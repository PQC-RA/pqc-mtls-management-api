import * as crypto from "crypto";

import {
	ExecutionContext,
	NotFoundException,
	UnauthorizedException,
} from "@nestjs/common";

import { RenewAttestGuard, RenewRequest } from "@/renew/renew-attest.guard";

const SECRET = "renew-hmac-test-secret-0123456789";
const FPR = "ab".repeat(32);

function signedRequest(
	over: {
		ts?: number;
		nonce?: string;
		body?: string;
		sig?: string;
		serial?: string;
	} = {}
) {
	const ts = String(over.ts ?? Math.floor(Date.now() / 1000));
	const nonce = over.nonce ?? crypto.randomBytes(16).toString("hex");
	const body = Buffer.from(over.body ?? '{"csr":"x"}');
	const serial = over.serial ?? "10A0";
	const notAfter = "Nov  1 00:02:00 2026 GMT";
	const bodyHash = crypto.createHash("sha256").update(body).digest("hex");
	const mac = crypto
		.createHmac("sha256", SECRET)
		.update(
			`renew-v1\nPOST\n/api/renew\n${ts}\n${nonce}\n${FPR}\n${serial}\n${notAfter}\n${bodyHash}`
		)
		.digest("hex");
	return {
		method: "POST",
		path: "/api/renew",
		ip: "10.0.0.1",
		rawBody: body,
		headers: {
			"x-pqc-renew-timestamp": ts,
			"x-pqc-renew-nonce": nonce,
			"x-pqc-renew-fpr": FPR,
			"x-pqc-renew-serial": serial,
			"x-pqc-renew-notafter": notAfter,
			"x-pqc-renew-signature": over.sig ?? `sha256=${mac}`,
		},
	} as unknown as RenewRequest;
}

function ctx(req: RenewRequest): ExecutionContext {
	return {
		switchToHttp: () => ({ getRequest: () => req }),
	} as unknown as ExecutionContext;
}

describe("RenewAttestGuard", () => {
	let guard: RenewAttestGuard;
	beforeEach(() => {
		process.env.RENEWAL_ENABLED = "1";
		process.env.RENEW_HMAC_SECRET = SECRET;
		guard = new RenewAttestGuard();
	});
	afterAll(() => {
		delete process.env.RENEWAL_ENABLED;
		delete process.env.RENEW_HMAC_SECRET;
	});

	it("answers 404 when renewal is switched off", () => {
		delete process.env.RENEWAL_ENABLED;
		expect(() => guard.canActivate(ctx(signedRequest()))).toThrow(
			NotFoundException
		);
	});

	it("accepts a correct attestation and takes the identity only from it", () => {
		const req = signedRequest();
		expect(guard.canActivate(ctx(req))).toBe(true);
		expect(req.renewAttestation).toEqual({
			fingerprint: FPR,
			serial: "10A0",
			notAfter: "Nov  1 00:02:00 2026 GMT",
		});
	});

	it("refuses a body changed after signing", () => {
		const req = signedRequest();
		(req as { rawBody: Buffer }).rawBody = Buffer.from('{"csr":"y"}');
		expect(() => guard.canActivate(ctx(req))).toThrow(
			UnauthorizedException
		);
	});

	it("refuses a changed serial", () => {
		const req = signedRequest();
		req.headers["x-pqc-renew-serial"] = "10A1";
		expect(() => guard.canActivate(ctx(req))).toThrow(
			UnauthorizedException
		);
	});

	it("refuses a stale timestamp", () => {
		expect(() =>
			guard.canActivate(
				ctx(signedRequest({ ts: Math.floor(Date.now() / 1000) - 31 }))
			)
		).toThrow(UnauthorizedException);
	});

	it("refuses a replayed nonce", () => {
		const nonce = crypto.randomBytes(16).toString("hex");
		expect(guard.canActivate(ctx(signedRequest({ nonce })))).toBe(true);
		expect(() => guard.canActivate(ctx(signedRequest({ nonce })))).toThrow(
			UnauthorizedException
		);
	});

	it("does not record the nonce of a request with a bad MAC", () => {
		const nonce = crypto.randomBytes(16).toString("hex");
		expect(() =>
			guard.canActivate(
				ctx(signedRequest({ nonce, sig: "sha256=" + "0".repeat(64) }))
			)
		).toThrow(UnauthorizedException);
		expect(guard.canActivate(ctx(signedRequest({ nonce })))).toBe(true);
	});

	it("refuses a missing or malformed header", () => {
		const req = signedRequest();
		delete req.headers["x-pqc-renew-fpr"];
		expect(() => guard.canActivate(ctx(req))).toThrow(
			UnauthorizedException
		);
	});

	it("fails closed without a secret", () => {
		process.env.RENEW_HMAC_SECRET = "short";
		expect(() => guard.canActivate(ctx(signedRequest()))).toThrow(
			UnauthorizedException
		);
	});
});
