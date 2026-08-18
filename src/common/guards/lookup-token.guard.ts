import * as crypto from "crypto";

import {
	BadRequestException,
	CanActivate,
	ExecutionContext,
	ForbiddenException,
	Injectable,
	Logger,
	UnauthorizedException,
} from "@nestjs/common";
import { Request } from "express";
import * as jwt from "jsonwebtoken";
import jwksRsa, { JwksClient } from "jwks-rsa";

import { normalizeFingerprint, SHA256_HEX } from "@/common/auth/cert-roles";

/**
 * LookupTokenGuard – verifies Token 2 (the gateway's cert-lookup JWT, minted
 * by policy_router.lua on every proxied request) against the header it
 * actually arrives on, `X-PQC-Lookup-Token` – NOT `Authorization`, which
 * keeps carrying Token 1 (backend attestation) unchanged.
 *
 * Mirrors JwtAuthGuard's issuer/audience pinning, plus two lookup-specific
 * checks:
 *   1. The token header's `kid` must be EXACTLY "lookup-v1". This is pinned
 *      before the JWKS key is even fetched, so a backend-v1 or admin-v1
 *      signed token is rejected outright rather than relying solely on the
 *      audience check that follows – two independent barriers, not one.
 *   2. The verified `fpr` claim must exactly match the `:fpr` path param
 *      (both normalized to lowercase, compared with crypto.timingSafeEqual –
 *      consistent with this codebase's existing HMAC-comparison convention)
 *      so a valid Token 2 for one certificate can't be replayed to fetch a
 *      different one.
 *
 * The `:fpr` path param is validated against SHA256_HEX here, independent of
 * FingerprintParamDto's own validation on the way to the handler. NestJS runs
 * guards before pipes (guards -> interceptors -> pipes -> handler), so this
 * guard sees the raw, unvalidated Express param – relying solely on the DTO
 * pipe, or on a malformed value simply failing to match a well-formed claim,
 * would make this guard's correctness depend on that ordering rather than on
 * anything it visibly checks itself.
 *
 * Do NOT reuse Token 1 here: its audience (pqc-backend) is stated for
 * request-attestation verifiers, and accepting it at this lookup route would
 * be JWT audience confusion (RFC 8725).
 */

const JWKS_URI =
	process.env.GATEWAY_JWKS_URI ?? "http://gateway:8081/.well-known/jwks.json";

const EXPECTED_ALGORITHMS: jwt.Algorithm[] = ["RS256"];
const EXPECTED_ISSUER = process.env.JWT_EXPECTED_ISSUER ?? "pqc-gateway";
const EXPECTED_LOOKUP_AUDIENCE =
	process.env.JWT_EXPECTED_LOOKUP_AUDIENCE ?? "pqc-cert-lookup";
const EXPECTED_LOOKUP_KID = "lookup-v1";

export type RequestWithLookupFpr = Request & { lookupFpr?: string };

@Injectable()
export class LookupTokenGuard implements CanActivate {
	private readonly logger = new Logger(LookupTokenGuard.name);

	private readonly jwksClient: JwksClient = jwksRsa({
		jwksUri: JWKS_URI,
		cache: true,
		cacheMaxEntries: 5,
		cacheMaxAge: 60 * 60 * 1000, // 1 hour
		timeout: 5_000,
		rateLimit: true,
		jwksRequestsPerMinute: 10,
	});

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request = context
			.switchToHttp()
			.getRequest<RequestWithLookupFpr>();

		// 1. Extract the lookup token from its own dedicated header.
		const tokenHeader = request.headers["x-pqc-lookup-token"];
		const token = Array.isArray(tokenHeader) ? tokenHeader[0] : tokenHeader;
		if (!token) {
			this.logger.warn("Missing X-PQC-Lookup-Token header");
			throw new UnauthorizedException(
				"Missing X-PQC-Lookup-Token header"
			);
		}

		// 2. Decode header (unverified) to obtain the kid for key lookup.
		let decodedHeader: jwt.JwtHeader;
		try {
			const decoded = jwt.decode(token, { complete: true });
			if (!decoded || typeof decoded !== "object" || !decoded.header) {
				throw new Error("malformed token structure");
			}
			decodedHeader = decoded.header;
		} catch (e) {
			this.logger.warn(
				`Lookup token decode failed: ${(e as Error).message}`
			);
			throw new UnauthorizedException("Invalid token format");
		}

		// 3. Pin kid to lookup-v1 specifically – reject backend-v1/admin-v1
		//    tokens outright instead of relying only on the audience check.
		if (decodedHeader.kid !== EXPECTED_LOOKUP_KID) {
			this.logger.warn(
				`Lookup token has wrong kid="${decodedHeader.kid ?? "missing"}" (expected "${EXPECTED_LOOKUP_KID}")`
			);
			throw new UnauthorizedException(
				"Token key ID is not valid for cert lookup"
			);
		}

		// 4. Fetch the matching public key from the gateway JWKS.
		let publicKey: string;
		try {
			const key = await this.jwksClient.getSigningKey(decodedHeader.kid);
			publicKey = key.getPublicKey();
		} catch (e) {
			this.logger.error(
				`Failed to fetch signing key kid=${decodedHeader.kid} from ${JWKS_URI}: ${(e as Error).message}`
			);
			throw new UnauthorizedException(
				"Unable to verify token – JWKS key not found"
			);
		}

		// 5. Verify signature, expiry, algorithm, issuer and audience.
		let payload: jwt.JwtPayload;
		try {
			const verified = jwt.verify(token, publicKey, {
				algorithms: EXPECTED_ALGORITHMS,
				issuer: EXPECTED_ISSUER,
				audience: EXPECTED_LOOKUP_AUDIENCE,
			});
			if (typeof verified === "string") {
				throw new Error("unexpected string payload");
			}
			payload = verified;
		} catch (e) {
			const msg = (e as Error).message;
			if (msg.includes("expired")) {
				this.logger.warn("Lookup token has expired");
				throw new UnauthorizedException("Token expired");
			}
			this.logger.warn(`Lookup token verification failed: ${msg}`);
			throw new UnauthorizedException("Token signature invalid");
		}

		// 6. Validate the path param's own shape before using it for anything.
		//    Guards run before pipes (see class docstring), so FingerprintParamDto
		//    hasn't validated this yet -- don't depend on that ordering, or on a
		//    malformed value merely failing to match the claim, for safety here.
		const pathFprRaw =
			typeof request.params?.fpr === "string" ? request.params.fpr : "";
		const pathFpr = normalizeFingerprint(pathFprRaw);
		if (!SHA256_HEX.test(pathFpr)) {
			this.logger.warn(
				`Malformed :fpr path param (length=${pathFprRaw.length})`
			);
			throw new BadRequestException(
				"Fingerprint must be exactly 64 hexadecimal characters"
			);
		}

		// 7. The token's own fpr claim must exactly match the :fpr path param –
		//    otherwise a valid Token 2 minted for one certificate could be used
		//    to fetch a different one. Normalize both sides, constant-time compare.
		const claimFpr =
			typeof payload["fpr"] === "string"
				? normalizeFingerprint(payload["fpr"] as string)
				: "";

		const claimBuf = Buffer.from(claimFpr, "utf8");
		const pathBuf = Buffer.from(pathFpr, "utf8");
		const matches =
			claimFpr.length > 0 &&
			claimBuf.length === pathBuf.length &&
			crypto.timingSafeEqual(claimBuf, pathBuf);

		if (!matches) {
			this.logger.warn(
				`Lookup token fpr does not match requested path (sub="${payload.sub ?? "?"}")`
			);
			throw new ForbiddenException("Fingerprint does not match token");
		}

		request.lookupFpr = claimFpr;
		return true;
	}
}
