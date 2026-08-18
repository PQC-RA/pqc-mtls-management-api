import * as crypto from "crypto";
import * as fs from "fs";

import {
	CanActivate,
	ExecutionContext,
	Injectable,
	Logger,
	RawBodyRequest,
	UnauthorizedException,
} from "@nestjs/common";
import { Request } from "express";

/**
 * EnrollHmacGuard, interim fix.
 *
 * `POST /admin/certs/sign` is @Public() (no gateway-minted JWT – it is
 * reached by the CSR submitter themselves via the gateway's public :8443
 * /enroll proxy hop). Without a signature on that specific hop, an on-path
 * attacker between the gateway and this service could substitute the
 * submitted CSR for their own (keeping the legitimate CN), causing the CA to
 * sign the attacker's key under someone else's identity.
 *
 * enroll_sign.lua (access phase, runs before proxy_pass) signs the exact
 * bytes it forwards with a dedicated HMAC-SHA256 secret. This guard
 * recomputes the same HMAC and rejects before signCsr() runs – before any
 * enrollment-token consumption or CA interaction.
 *
 * Signed string construction mirrors policy.service.ts's control-plane push
 * EXACTLY (same convention control_plane.lua already verifies for that
 * channel, in the other direction):
 *   timestamp + "\n" + method + "\n" + path + "\n" + rawBody
 *
 * Secret: a dedicated enroll-hmac secret – deliberately NOT
 * control-plane-hmac or custodian-hmac, same "don't cross trust domains"
 * reasoning already applied to those two.
 */
@Injectable()
export class EnrollHmacGuard implements CanActivate {
	private readonly logger = new Logger(EnrollHmacGuard.name);

	// Bounds replay: consistent with control_plane.lua's own window, scaled
	// down for this higher-frequency, more exposed public endpoint.
	private static readonly MAX_CLOCK_SKEW_SECONDS = 60;

	private getHmacSecret(): string {
		const secretFile = "/run/secrets/enroll-hmac";
		try {
			return fs.readFileSync(secretFile, "utf8").trim();
		} catch {
			return process.env.ENROLL_HMAC_SECRET ?? "";
		}
	}

	canActivate(context: ExecutionContext): boolean {
		const request = context
			.switchToHttp()
			.getRequest<RawBodyRequest<Request>>();

		const secret = this.getHmacSecret();
		if (!secret) {
			this.logger.error(
				"enroll-hmac secret not configured – refusing enrollment (fail closed)"
			);
			throw new UnauthorizedException(
				"Enrollment signing is not configured"
			);
		}

		const timestampHeader = request.headers["x-timestamp"];
		const timestamp = Array.isArray(timestampHeader)
			? timestampHeader[0]
			: timestampHeader;
		if (!timestamp || !/^\d+$/.test(timestamp)) {
			this.logger.warn(
				`Missing/invalid X-Timestamp from ${request.ip ?? "?"}`
			);
			throw new UnauthorizedException("X-Timestamp header required");
		}

		const nowSeconds = Math.floor(Date.now() / 1000);
		const skew = Math.abs(nowSeconds - parseInt(timestamp, 10));
		if (skew > EnrollHmacGuard.MAX_CLOCK_SKEW_SECONDS) {
			this.logger.warn(
				`Stale X-Timestamp from ${request.ip ?? "?"} (skew=${skew}s)`
			);
			throw new UnauthorizedException(
				`X-Timestamp is outside the ${EnrollHmacGuard.MAX_CLOCK_SKEW_SECONDS}-second window`
			);
		}

		const sigHeader = request.headers["x-hub-signature-256"];
		const signature = Array.isArray(sigHeader) ? sigHeader[0] : sigHeader;
		const match = signature
			? /^sha256=([0-9a-fA-F]+)$/.exec(signature)
			: null;
		if (!match) {
			this.logger.warn(
				`Missing/malformed X-Hub-Signature-256 from ${request.ip ?? "?"}`
			);
			throw new UnauthorizedException(
				"X-Hub-Signature-256 header required (format: sha256=<hex>)"
			);
		}

		// rawBody is populated by Nest's bootstrap { rawBody: true } option – the
		// exact bytes the gateway signed, before any JSON parsing/re-serialization.
		const rawBody = request.rawBody ?? Buffer.alloc(0);
		const method = request.method;
		const path = request.path;
		const signedString = `${timestamp}\n${method}\n${path}\n${rawBody.toString("utf8")}`;
		const expectedHex = crypto
			.createHmac("sha256", secret)
			.update(signedString)
			.digest("hex");

		const expectedBuf = Buffer.from(expectedHex, "hex");
		const providedBuf = Buffer.from(match[1], "hex");
		const valid =
			expectedBuf.length === providedBuf.length &&
			crypto.timingSafeEqual(expectedBuf, providedBuf);

		if (!valid) {
			this.logger.warn(
				`Enrollment HMAC verification failed from ${request.ip ?? "?"} (method=${method} path=${path})`
			);
			throw new UnauthorizedException(
				"Enrollment request signature is missing or invalid"
			);
		}

		return true;
	}
}
