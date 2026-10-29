import * as crypto from "crypto";

import {
	ExecutionContext,
	ForbiddenException,
	UnauthorizedException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Test } from "@nestjs/testing";

import { JwtAuthGuard } from "@/common/guards/jwt-auth.guard";

import { b64u, MldsaFixtures } from "../../../test/support/mldsa-openssl";

// The guard fetches the JWKS through makeJwksFetcher(); serve it from memory.
let mockJwksBody = '{"keys":[]}';
let mockFetchCount = 0;
jest.mock("@/common/auth/admin-jwks.store", () => {
	const actual = jest.requireActual("@/common/auth/admin-jwks.store");
	return {
		...actual,
		makeJwksFetcher: () => async () => {
			mockFetchCount++;
			if (mockJwksBody === "FAIL") throw new Error("connection refused");
			return mockJwksBody;
		},
	};
});

jest.setTimeout(60_000);

const TEST_FPR =
	"1c2ba075293fcd68e241cfcedf337ff59bc8126b24c2af07c60f319a38e1a0d8";
// A 40-char value is a SHA-1 fingerprint – the historical lockout cause.
const SHA1_FPR = "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00";
const ISSUER = "pqc-gateway";
const AUDIENCE = "pqc-mtls-management-api";
const H_V2 = '{"alg":"ML-DSA-65","typ":"JWT","kid":"admin-v2"}';
const H_V1 = '{"alg":"RS256","typ":"JWT","kid":"admin-v1"}';

const fx = new MldsaFixtures();
let v2: { keyPath: string; pub: Buffer };
let pinHex: string;
const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const rsaJwk = rsa.publicKey.export({ format: "jwk" });

function claims(over: Record<string, unknown> = {}): string {
	const now = Math.floor(Date.now() / 1000);
	return JSON.stringify({
		iss: ISSUER,
		aud: AUDIENCE,
		sub: "test-client",
		role: "admin",
		fpr: TEST_FPR,
		iat: now,
		exp: now + 60,
		jti: crypto.randomBytes(16).toString("base64url"),
		htm: "GET",
		htu: "/api/admin/certs",
		...over,
	});
}

const v2Token = (over: Record<string, unknown> = {}, header = H_V2) =>
	fx.token(v2.keyPath, header, claims(over));

/** RS256 is signable in Node; the old gateway's admin-v1 shape has no jti/htm/htu. */
function v1Token(over: Record<string, unknown> = {}, header = H_V1): string {
	const input = `${b64u(header)}.${b64u(claims({ jti: undefined, htm: undefined, htu: undefined, ...over }))}`;
	return `${input}.${b64u(crypto.sign("sha256", Buffer.from(input), rsa.privateKey))}`;
}

function makeContext(
	authHeader?: string,
	method = "GET",
	url = "/api/admin/certs"
): ExecutionContext {
	return {
		getHandler: () => undefined,
		getClass: () => undefined,
		switchToHttp: () => ({
			getRequest: () => ({
				headers: authHeader ? { authorization: authHeader } : {},
				method,
				originalUrl: url,
				url,
			}),
		}),
	} as unknown as ExecutionContext;
}

let reflector: { getAllAndOverride: jest.Mock };

async function makeGuard(
	env: Record<string, string | undefined>
): Promise<JwtAuthGuard> {
	for (const [k, v] of Object.entries(env)) {
		if (v === undefined) delete process.env[k];
		else process.env[k] = v;
	}
	const module = await Test.createTestingModule({
		providers: [JwtAuthGuard, { provide: Reflector, useValue: reflector }],
	}).compile();
	return module.get<JwtAuthGuard>(JwtAuthGuard);
}

const END_STATE = () => ({
	JWT_EXPECTED_KID: "admin-v2",
	ADMIN_V2_PUB_SHA256: pinHex,
});
const DUAL = () => ({
	JWT_EXPECTED_KID: "admin-v1,admin-v2",
	ADMIN_V2_PUB_SHA256: pinHex,
});

beforeAll(async () => {
	v2 = await fx.genKey();
	pinHex = crypto.createHash("sha256").update(v2.pub).digest("hex");
});
afterAll(() => fx.cleanup());

beforeEach(() => {
	delete process.env.ADMIN_CERT_FINGERPRINTS_FILE;
	process.env.ADMIN_CERT_FINGERPRINTS = TEST_FPR;
	reflector = { getAllAndOverride: jest.fn().mockReturnValue(false) };
	mockJwksBody = JSON.stringify({
		keys: [
			{
				...rsaJwk,
				kty: "RSA",
				use: "sig",
				alg: "RS256",
				kid: "backend-v1",
			},
			{
				...rsaJwk,
				kty: "RSA",
				use: "sig",
				alg: "RS256",
				kid: "admin-v1",
			},
			{
				kty: "AKP",
				use: "sig",
				alg: "ML-DSA-65",
				kid: "admin-v2",
				pub: b64u(v2.pub),
			},
			{
				...rsaJwk,
				kty: "RSA",
				use: "sig",
				alg: "RS256",
				kid: "lookup-v1",
			},
		],
	});
});

describe("JwtAuthGuard, end state (admin-v2 only)", () => {
	let guard: JwtAuthGuard;
	beforeEach(async () => {
		guard = await makeGuard(END_STATE());
	});

	it("accepts a valid admin-v2 token whose fingerprint is on the allowlist", async () => {
		await expect(
			guard.canActivate(makeContext(`Bearer ${await v2Token()}`))
		).resolves.toBe(true);
	});

	it("refuses an admin-v1 token (RS256), however valid", async () => {
		await expect(
			guard.canActivate(makeContext(`Bearer ${v1Token()}`))
		).rejects.toThrow(UnauthorizedException);
	});

	it("refuses a replay inside the 60 s", async () => {
		const t = await v2Token();
		await expect(
			guard.canActivate(makeContext(`Bearer ${t}`))
		).resolves.toBe(true);
		await expect(
			guard.canActivate(makeContext(`Bearer ${t}`))
		).rejects.toThrow(UnauthorizedException);
	});

	it("a token that failed (wrong path) does not use up its jti", async () => {
		const t = await v2Token();
		await expect(
			guard.canActivate(
				makeContext(`Bearer ${t}`, "GET", "/api/admin/crl")
			)
		).rejects.toThrow(UnauthorizedException);
		await expect(
			guard.canActivate(makeContext(`Bearer ${t}`))
		).resolves.toBe(true);
	});

	it("binds htm and htu to the request (query string ignored)", async () => {
		const t = await v2Token({
			htm: "DELETE",
			htu: "/api/admin/certs/1060",
		});
		await expect(
			guard.canActivate(
				makeContext(`Bearer ${t}`, "GET", "/api/admin/certs/1060")
			)
		).rejects.toThrow(UnauthorizedException);
		await expect(
			guard.canActivate(
				makeContext(`Bearer ${t}`, "DELETE", "/api/admin/certs/1061")
			)
		).rejects.toThrow(UnauthorizedException);
		await expect(
			guard.canActivate(
				makeContext(
					`Bearer ${t}`,
					"DELETE",
					"/api/admin/certs/1060?force=1"
				)
			)
		).resolves.toBe(true);
	});

	it("refuses Token 1 and Token 2 shapes (kid backend-v1 / lookup-v1)", async () => {
		const t1 = v1Token(
			{ aud: "pqc-backend" },
			'{"alg":"RS256","typ":"JWT","kid":"backend-v1"}'
		);
		const t2 = v1Token(
			{ aud: "pqc-cert-lookup" },
			'{"alg":"RS256","typ":"JWT","kid":"lookup-v1"}'
		);
		await expect(
			guard.canActivate(makeContext(`Bearer ${t1}`))
		).rejects.toThrow(UnauthorizedException);
		await expect(
			guard.canActivate(makeContext(`Bearer ${t2}`))
		).rejects.toThrow(UnauthorizedException);
	});

	it("refuses when the JWKS cannot be fetched", async () => {
		mockJwksBody = "FAIL";
		const g = await makeGuard(END_STATE());
		await expect(
			g.canActivate(makeContext(`Bearer ${await v2Token()}`))
		).rejects.toThrow(UnauthorizedException);
	});

	it("refuses when the JWKS admin-v2 key is not the pinned one", async () => {
		const other = await fx.genKey();
		mockJwksBody = JSON.stringify({
			keys: [
				{
					kty: "AKP",
					alg: "ML-DSA-65",
					kid: "admin-v2",
					pub: b64u(other.pub),
				},
			],
		});
		const g = await makeGuard(END_STATE());
		const t = await fx.token(other.keyPath, H_V2, claims());
		await expect(g.canActivate(makeContext(`Bearer ${t}`))).rejects.toThrow(
			UnauthorizedException
		);
	});

	it("fetches the JWKS at most once per 10 s for an unusable kid", async () => {
		mockJwksBody = JSON.stringify({ keys: [] });
		const g = await makeGuard(END_STATE());
		mockFetchCount = 0;
		for (let i = 0; i < 5; i++) {
			await expect(
				g.canActivate(makeContext(`Bearer ${await v2Token()}`))
			).rejects.toThrow(UnauthorizedException);
		}
		expect(mockFetchCount).toBe(1);
	});

	it("throws ForbiddenException when the fingerprint is not on the allowlist", async () => {
		await expect(
			guard.canActivate(
				makeContext(`Bearer ${await v2Token({ fpr: "deadbeef" })}`)
			)
		).rejects.toThrow(ForbiddenException);
	});

	it("a token of a fingerprint not on the allowlist does not use up a jti (403 both times)", async () => {
		const t = await v2Token({ fpr: "deadbeef" });
		await expect(
			guard.canActivate(makeContext(`Bearer ${t}`))
		).rejects.toThrow(ForbiddenException);
		await expect(
			guard.canActivate(makeContext(`Bearer ${t}`))
		).rejects.toThrow(ForbiddenException);
	});

	it("refuses a token without fpr as invalid (401)", async () => {
		await expect(
			guard.canActivate(
				makeContext(`Bearer ${await v2Token({ fpr: undefined })}`)
			)
		).rejects.toThrow(UnauthorizedException);
	});

	it("matches the fingerprint case-insensitively and ignoring colons", async () => {
		const colonForm = TEST_FPR.toUpperCase().match(/.{2}/g)!.join(":");
		await expect(
			guard.canActivate(
				makeContext(`Bearer ${await v2Token({ fpr: colonForm })}`)
			)
		).resolves.toBe(true);
	});
});

describe("JwtAuthGuard, dual window (admin-v1,admin-v2)", () => {
	it("accepts both kids; admin-v1 from an old gateway without jti/htm/htu", async () => {
		const g = await makeGuard(DUAL());
		await expect(
			g.canActivate(makeContext(`Bearer ${v1Token()}`))
		).resolves.toBe(true);
		await expect(
			g.canActivate(makeContext(`Bearer ${await v2Token()}`))
		).resolves.toBe(true);
	});

	it("admin-v1 from the new gateway (with jti/htm/htu) is bound too", async () => {
		const g = await makeGuard(DUAL());
		const t = v1Token({
			jti: crypto.randomBytes(16).toString("base64url"),
			htm: "GET",
			htu: "/api/admin/certs",
		});
		await expect(g.canActivate(makeContext(`Bearer ${t}`))).resolves.toBe(
			true
		);
		await expect(g.canActivate(makeContext(`Bearer ${t}`))).rejects.toThrow(
			UnauthorizedException
		);
	});

	it("refuses an admin-v1 token valid for longer than 60 s", async () => {
		const g = await makeGuard(DUAL());
		const now = Math.floor(Date.now() / 1000);
		await expect(
			g.canActivate(
				makeContext(`Bearer ${v1Token({ iat: now, exp: now + 300 })}`)
			)
		).rejects.toThrow(UnauthorizedException);
	});
});

describe("JwtAuthGuard, configuration", () => {
	it("default (no JWT_EXPECTED_KID): admin-v1 only, as before ADR-022", async () => {
		const g = await makeGuard({
			JWT_EXPECTED_KID: undefined,
			ADMIN_V2_PUB_SHA256: pinHex,
		});
		await expect(
			g.canActivate(makeContext(`Bearer ${v1Token()}`))
		).resolves.toBe(true);
		await expect(
			g.canActivate(makeContext(`Bearer ${await v2Token()}`))
		).rejects.toThrow(UnauthorizedException);
	});

	it("admin-v2 accepted but no pin configured: admin-v2 refused (fail closed)", async () => {
		const g = await makeGuard({
			JWT_EXPECTED_KID: "admin-v2",
			ADMIN_V2_PUB_SHA256: undefined,
		});
		await expect(
			g.canActivate(makeContext(`Bearer ${await v2Token()}`))
		).rejects.toThrow(UnauthorizedException);
	});

	it("an unknown kid in JWT_EXPECTED_KID is ignored, not trusted", async () => {
		const g = await makeGuard({
			JWT_EXPECTED_KID: "backend-v1",
			ADMIN_V2_PUB_SHA256: pinHex,
		});
		const t1 = v1Token(
			{ aud: AUDIENCE },
			'{"alg":"RS256","typ":"JWT","kid":"backend-v1"}'
		);
		await expect(
			g.canActivate(makeContext(`Bearer ${t1}`))
		).rejects.toThrow(UnauthorizedException);
	});

	it("allows @Public routes without any token", async () => {
		const g = await makeGuard(END_STATE());
		reflector.getAllAndOverride.mockReturnValue(true);
		await expect(g.canActivate(makeContext())).resolves.toBe(true);
	});

	it("401 when the Authorization header is missing or not Bearer", async () => {
		const g = await makeGuard(END_STATE());
		await expect(g.canActivate(makeContext())).rejects.toThrow(
			UnauthorizedException
		);
		await expect(
			g.canActivate(makeContext(`Basic ${await v2Token()}`))
		).rejects.toThrow(UnauthorizedException);
	});

	// ── SHA-256 alignment (the admin-lockout fix) ─────────────────────────────

	it("rejects a SHA-1 (40-char) allowlist entry – fail-closed, never silent-accept", async () => {
		process.env.ADMIN_CERT_FINGERPRINTS = SHA1_FPR;
		const g = await makeGuard(END_STATE());
		await expect(
			g.canActivate(
				makeContext(`Bearer ${await v2Token({ fpr: SHA1_FPR })}`)
			)
		).rejects.toThrow(ForbiddenException);
	});

	it("accepts a valid SHA-256 fpr alongside a rejected SHA-1 entry (mixed allowlist)", async () => {
		process.env.ADMIN_CERT_FINGERPRINTS = `${SHA1_FPR}, ${TEST_FPR}`;
		const g = await makeGuard(END_STATE());
		await expect(
			g.canActivate(makeContext(`Bearer ${await v2Token()}`))
		).resolves.toBe(true);
	});

	it("loads the allowlist from ADMIN_CERT_FINGERPRINTS_FILE (Docker secret)", async () => {
		const fs = require("fs") as typeof import("fs");
		const os = require("os") as typeof import("os");
		const path = require("path") as typeof import("path");
		const secret = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), "fpr-")),
			"admin-cert-fingerprints"
		);
		fs.writeFileSync(secret, `# admin allowlist\n${TEST_FPR}\n`);
		delete process.env.ADMIN_CERT_FINGERPRINTS;
		process.env.ADMIN_CERT_FINGERPRINTS_FILE = secret;
		const g = await makeGuard(END_STATE());
		await expect(
			g.canActivate(makeContext(`Bearer ${await v2Token()}`))
		).resolves.toBe(true);
		fs.rmSync(path.dirname(secret), { recursive: true, force: true });
	});
});
