import {
	CanActivate,
	ExecutionContext,
	ForbiddenException,
	Injectable,
	Logger,
	UnauthorizedException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Request } from "express";
import * as jwt from "jsonwebtoken";
import jwksRsa, { JwksClient } from "jwks-rsa";

import {
	AdminIdentity,
	buildCertRoleMap,
	CertRoleMap,
	normalizeFingerprint,
} from "@/common/auth/cert-roles";
import { IS_PUBLIC_KEY } from "@/common/decorators/public.decorator";

/**
 * JwtAuthGuard – verifies RS256 JWTs issued by the PQC OpenResty gateway and
 * authorizes the caller against an explicit admin allowlist.
 *
 * The gateway mints a short-lived RS256 JWT from the verified mTLS client
 * certificate.  This guard:
 *   1. Verifies the signature (RS256, key fetched from the gateway JWKS by kid).
 *   2. Verifies the token is not expired and matches the expected issuer/audience.
 *   3. AUTHORIZES by certificate FINGERPRINT against an explicit allowlist.
 *
 * Why fingerprint and not the `role`/OU claim:
 *   The cert subject (CN, OU) is chosen by the certificate requester in their
 *   CSR.  Deriving authorization from a requester-influenced field lets anyone
 *   who can obtain a CA-signed cert request `OU=admin`.  The certificate SHA-256
 *   fingerprint, by contrast, is bound to the exact issued cert and cannot be
 *   forged without the CA re-issuing that precise certificate.  Authorization
 *   is therefore a separate, operator-controlled allowlist – decoupled from any
 *   attacker-influenceable subject field.
 *
 * Security posture:
 *   - Algorithm is hardcoded to RS256 – the token "alg" header is never trusted.
 *   - issuer and audience are pinned (prevents token-confusion across services).
 *   - Authorization fails CLOSED: if no allowlist is configured, every request
 *     is denied (a misconfigured deployment is locked, not wide open).
 */

const JWKS_URI =
	process.env.GATEWAY_JWKS_URI ?? "http://gateway:8081/.well-known/jwks.json";

const EXPECTED_ALGORITHMS: jwt.Algorithm[] = ["RS256"];
const EXPECTED_ISSUER = process.env.JWT_EXPECTED_ISSUER ?? "pqc-gateway";
const EXPECTED_AUDIENCE =
	process.env.JWT_EXPECTED_AUDIENCE ?? "pqc-mtls-management-api";

@Injectable()
export class JwtAuthGuard implements CanActivate {
	private readonly logger = new Logger(JwtAuthGuard.name);
	private readonly roleMap: CertRoleMap;

	private readonly jwksClient: JwksClient = jwksRsa({
		jwksUri: JWKS_URI,
		cache: true,
		cacheMaxEntries: 5,
		cacheMaxAge: 60 * 60 * 1000, // 1 hour
		timeout: 5_000,
		rateLimit: true,
		jwksRequestsPerMinute: 10,
	});

	constructor(private readonly reflector: Reflector) {
		// Resolve roles from the ADMIN_/AUDITOR_ fingerprint allowlists. The
		// builder logs precise warnings for malformed (e.g. SHA-1) entries and
		// for an empty allowlist (fail-closed: deny all).
		this.roleMap = buildCertRoleMap(this.logger);
	}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		// Honour @Public() opt-out (checked at handler and controller level).
		const isPublic = this.reflector.getAllAndOverride<boolean>(
			IS_PUBLIC_KEY,
			[context.getHandler(), context.getClass()]
		);
		if (isPublic) {
			return true;
		}

		const request = context.switchToHttp().getRequest<Request>();

		// 1. Extract the Bearer token.
		const authHeader = request.headers["authorization"];
		if (!authHeader || !authHeader.startsWith("Bearer ")) {
			this.logger.warn("Missing or malformed Authorization header");
			throw new UnauthorizedException(
				"Missing Authorization Bearer token"
			);
		}
		const token = authHeader.slice(7);

		// 2. Decode header (unverified) to obtain the kid for key lookup.
		let decodedHeader: jwt.JwtHeader;
		try {
			const decoded = jwt.decode(token, { complete: true });
			if (!decoded || typeof decoded !== "object" || !decoded.header) {
				throw new Error("malformed token structure");
			}
			decodedHeader = decoded.header;
		} catch (e) {
			this.logger.warn(`Token decode failed: ${(e as Error).message}`);
			throw new UnauthorizedException("Invalid token format");
		}

		const kid = decodedHeader.kid;
		if (!kid) {
			this.logger.warn("Token header missing kid claim");
			throw new UnauthorizedException("Token missing key ID (kid)");
		}

		// 3. Fetch the matching public key from the gateway JWKS.
		let publicKey: string;
		try {
			const key = await this.jwksClient.getSigningKey(kid);
			publicKey = key.getPublicKey();
		} catch (e) {
			this.logger.error(
				`Failed to fetch signing key kid=${kid} from ${JWKS_URI}: ${(e as Error).message}`
			);
			throw new UnauthorizedException(
				"Unable to verify token – JWKS key not found"
			);
		}

		// 4. Verify signature, expiry, algorithm, issuer and audience.
		let payload: jwt.JwtPayload;
		try {
			const verified = jwt.verify(token, publicKey, {
				algorithms: EXPECTED_ALGORITHMS,
				issuer: EXPECTED_ISSUER,
				audience: EXPECTED_AUDIENCE,
			});
			if (typeof verified === "string") {
				throw new Error("unexpected string payload");
			}
			payload = verified;
		} catch (e) {
			const msg = (e as Error).message;
			if (msg.includes("expired")) {
				this.logger.warn("Token has expired");
				throw new UnauthorizedException("Token expired");
			}
			this.logger.warn(`Token verification failed: ${msg}`);
			throw new UnauthorizedException("Token signature invalid");
		}

		// 5. AUTHORIZE by certificate fingerprint and RESOLVE the caller's role
		//    from the operator-controlled allowlists (admin / auditor).
		//    Fails closed: a fingerprint in neither list denies everyone.
		//    The role is taken from the fpr→role map, NEVER from the JWT
		//    `role`/OU claim (which is requester-influenceable, weaker evidence).
		const fpr =
			typeof payload["fpr"] === "string"
				? normalizeFingerprint(payload["fpr"] as string)
				: "";
		const role = fpr ? this.roleMap.resolve(fpr) : null;
		if (!role) {
			this.logger.warn(
				`Access denied: cert fingerprint not on admin/auditor allowlist ` +
					`(sub="${payload.sub ?? "?"}", fpr="${fpr || "missing"}")`
			);
			throw new ForbiddenException(
				"Admin authorization denied – certificate is not on the admin allowlist"
			);
		}

		const identity: AdminIdentity = {
			sub: typeof payload.sub === "string" ? payload.sub : "",
			fpr,
			role,
		};
		(
			request as Request & {
				jwtPayload: jwt.JwtPayload;
				adminIdentity: AdminIdentity;
			}
		).jwtPayload = payload;
		(request as Request & { adminIdentity: AdminIdentity }).adminIdentity =
			identity;
		this.logger.debug(
			`JWT verified & authorized: sub=${identity.sub} fpr=${fpr} role=${role} exp=${payload.exp}`
		);
		return true;
	}
}
