import * as crypto from "crypto";
import * as fs from "fs";

import {
	CanActivate,
	ExecutionContext,
	Injectable,
	Logger,
	NotFoundException,
	RawBodyRequest,
	UnauthorizedException,
} from "@nestjs/common";
import { Request } from "express";

/**
 * The client identity the gateway attests for a renewal. The API takes the
 * renewing client's identity ONLY from these fields (ADR-015 decision 4),
 * never from the request body or from subject fields.
 */
export interface RenewAttestation {
	fingerprint: string; // SHA-256 of the presented client certificate (DER), 64 lowercase hex
	serial: string; // uppercase hex, as nginx reports $ssl_client_serial
	notAfter: string; // $ssl_client_v_end, as nginx reports it
}

export type RenewRequest = RawBodyRequest<Request> & {
	renewAttestation?: RenewAttestation;
};

export function renewalEnabled(): boolean {
	return process.env.RENEWAL_ENABLED === "1";
}

/**
 * RenewAttestGuard: verifies the gateway's attestation of the mTLS client on
 * the `/renew` hop (ADR-015 decision 4).
 *
 * renew_attest.lua signs, with the dedicated renew-hmac secret:
 *   renew-v1 \n method \n path \n timestamp \n nonce \n fingerprint \n serial \n notAfter \n sha256(body)
 *
 * Checked in this order: MAC, then timestamp (±30 s), then the nonce, which is
 * recorded only after the MAC is good so an unauthenticated caller cannot fill
 * the store. The nonce store is in this process's memory (ADR-019 cut: no Redis
 * password before the talk); a restart reopens a replay window of at most 30 s.
 */
@Injectable()
export class RenewAttestGuard implements CanActivate {
	private readonly logger = new Logger(RenewAttestGuard.name);
	static readonly MAX_SKEW_S = 30;
	static readonly NONCE_TTL_MS = 120_000;
	private readonly nonces = new Map<string, number>();

	private secret(): string {
		try {
			return fs.readFileSync("/run/secrets/renew-hmac", "utf8").trim();
		} catch {
			return process.env.RENEW_HMAC_SECRET ?? "";
		}
	}

	private header(req: Request, name: string): string {
		const v = req.headers[name];
		return (Array.isArray(v) ? v[0] : v) ?? "";
	}

	canActivate(context: ExecutionContext): boolean {
		// With the switch off the route does not exist (ADR-019 decision 1).
		if (!renewalEnabled()) throw new NotFoundException();
		const req = context.switchToHttp().getRequest<RenewRequest>();

		const secret = this.secret();
		if (secret.length < 16) {
			this.logger.error(
				"renew-hmac secret not configured; refusing renewal (fail closed)"
			);
			throw new UnauthorizedException(
				"Renewal attestation is not configured"
			);
		}

		const ts = this.header(req, "x-pqc-renew-timestamp");
		const nonce = this.header(req, "x-pqc-renew-nonce");
		const fingerprint = this.header(req, "x-pqc-renew-fpr");
		const serial = this.header(req, "x-pqc-renew-serial");
		const notAfter = this.header(req, "x-pqc-renew-notafter");
		const sig = /^sha256=([0-9a-f]{64})$/.exec(
			this.header(req, "x-pqc-renew-signature")
		);
		if (
			!/^\d{1,12}$/.test(ts) ||
			!/^[0-9a-f]{32}$/.test(nonce) ||
			!/^[0-9a-f]{64}$/.test(fingerprint) ||
			!/^[0-9A-F]{1,40}$/.test(serial) ||
			!notAfter ||
			notAfter.length > 64 ||
			!sig
		) {
			this.logger.warn(
				`Renewal without a well-formed gateway attestation from ${req.ip ?? "?"}`
			);
			throw new UnauthorizedException("Gateway attestation required");
		}

		const body = req.rawBody ?? Buffer.alloc(0);
		const bodyHash = crypto.createHash("sha256").update(body).digest("hex");
		const signed = `renew-v1\n${req.method}\n${req.path}\n${ts}\n${nonce}\n${fingerprint}\n${serial}\n${notAfter}\n${bodyHash}`;
		const expected = crypto
			.createHmac("sha256", secret)
			.update(signed)
			.digest();
		const provided = Buffer.from(sig[1], "hex");
		if (
			expected.length !== provided.length ||
			!crypto.timingSafeEqual(expected, provided)
		) {
			this.logger.warn(
				`Renewal attestation MAC mismatch from ${req.ip ?? "?"}`
			);
			throw new UnauthorizedException("Gateway attestation invalid");
		}

		const skew = Math.abs(Math.floor(Date.now() / 1000) - Number(ts));
		if (skew > RenewAttestGuard.MAX_SKEW_S) {
			throw new UnauthorizedException("Gateway attestation is stale");
		}

		const now = Date.now();
		for (const [n, exp] of this.nonces)
			if (exp <= now) this.nonces.delete(n);
		if (this.nonces.has(nonce)) {
			this.logger.warn(
				`Replayed renewal attestation nonce from ${req.ip ?? "?"}`
			);
			throw new UnauthorizedException("Gateway attestation replayed");
		}
		this.nonces.set(nonce, now + RenewAttestGuard.NONCE_TTL_MS);

		req.renewAttestation = { fingerprint, serial, notAfter };
		return true;
	}
}
