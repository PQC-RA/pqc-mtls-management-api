import { generateKeyPairSync } from "crypto";

import {
	ExecutionContext,
	ForbiddenException,
	UnauthorizedException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Test, TestingModule } from "@nestjs/testing";
import * as jwt from "jsonwebtoken";

import { JwtAuthGuard } from "@/common/guards/jwt-auth.guard";

// ---------------------------------------------------------------------------
// Helpers – generate a test RSA key pair in-process for the test suite.
// ---------------------------------------------------------------------------

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
	modulusLength: 2048,
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const TEST_KID = "gw-rs256-v1";
// SHA-256 certificate fingerprint = 64 lowercase hex chars (what the gateway
// emits as SHA-256(DER) and what ADMIN_CERT_FINGERPRINTS must contain).
const TEST_FPR =
	"1c2ba075293fcd68e241cfcedf337ff59bc8126b24c2af07c60f319a38e1a0d8";
// A 40-char value is a SHA-1 fingerprint – the historical lockout cause.
const SHA1_FPR = "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00";
const ISSUER = "pqc-gateway";
const AUDIENCE = "pqc-mtls-management-api";

function makeToken(
	overrides: Partial<{
		fpr: string;
		exp: number;
		alg: string;
		kid: string;
		iss: string;
		aud: string;
		privateKey: string;
		omitFpr: boolean;
	}> = {}
): string {
	const now = Math.floor(Date.now() / 1000);
	const claims: Record<string, unknown> = {
		sub: "test-client",
		role: "admin",
		iss: overrides.iss ?? ISSUER,
		aud: overrides.aud ?? AUDIENCE,
	};
	if (!overrides.omitFpr) {
		claims.fpr = overrides.fpr ?? TEST_FPR;
	}
	return jwt.sign(claims, overrides.privateKey ?? privateKey, {
		algorithm: (overrides.alg as jwt.Algorithm) ?? "RS256",
		expiresIn: overrides.exp !== undefined ? overrides.exp - now : 60,
		keyid: overrides.kid ?? TEST_KID,
	});
}

function makeContext(authHeader?: string): ExecutionContext {
	return {
		getHandler: () => undefined,
		getClass: () => undefined,
		switchToHttp: () => ({
			getRequest: () => ({
				headers: authHeader ? { authorization: authHeader } : {},
			}),
		}),
	} as unknown as ExecutionContext;
}

// Mock jwks-rsa so the guard uses our in-process test public key.
jest.mock("jwks-rsa", () => {
	return jest.fn().mockReturnValue({
		getSigningKey: jest.fn().mockImplementation((kid: string) => {
			if (kid !== TEST_KID) {
				return Promise.reject(new Error("Key not found"));
			}
			return Promise.resolve({ getPublicKey: () => publicKey });
		}),
	});
});

describe("JwtAuthGuard", () => {
	let guard: JwtAuthGuard;
	let reflector: { getAllAndOverride: jest.Mock };

	beforeEach(async () => {
		// The allowlist is read in the guard constructor – set it first.
		// Clear the _FILE override so tests are isolated from one another.
		delete process.env.ADMIN_CERT_FINGERPRINTS_FILE;
		process.env.ADMIN_CERT_FINGERPRINTS = TEST_FPR;
		reflector = { getAllAndOverride: jest.fn().mockReturnValue(false) };

		const module: TestingModule = await Test.createTestingModule({
			providers: [
				JwtAuthGuard,
				{ provide: Reflector, useValue: reflector },
			],
		}).compile();
		guard = module.get<JwtAuthGuard>(JwtAuthGuard);
	});

	it("should be defined", () => {
		expect(guard).toBeDefined();
	});

	it("allows a valid token whose cert fingerprint is on the allowlist", async () => {
		const ctx = makeContext(`Bearer ${makeToken()}`);
		await expect(guard.canActivate(ctx)).resolves.toBe(true);
	});

	it("allows @Public routes without any token", async () => {
		reflector.getAllAndOverride.mockReturnValue(true);
		const ctx = makeContext();
		await expect(guard.canActivate(ctx)).resolves.toBe(true);
	});

	it("throws UnauthorizedException when Authorization header is missing", async () => {
		await expect(guard.canActivate(makeContext())).rejects.toThrow(
			UnauthorizedException
		);
	});

	it("throws UnauthorizedException when header lacks 'Bearer ' prefix", async () => {
		const ctx = makeContext(`Basic ${makeToken()}`);
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			UnauthorizedException
		);
	});

	it("throws UnauthorizedException for an expired token", async () => {
		const now = Math.floor(Date.now() / 1000);
		const ctx = makeContext(`Bearer ${makeToken({ exp: now - 10 })}`);
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			UnauthorizedException
		);
	});

	it("throws UnauthorizedException for a tampered token", async () => {
		const parts = makeToken().split(".");
		parts[2] = "invalidsignatureXXXXXX";
		const ctx = makeContext(`Bearer ${parts.join(".")}`);
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			UnauthorizedException
		);
	});

	it("throws UnauthorizedException when kid is not in JWKS", async () => {
		const ctx = makeContext(`Bearer ${makeToken({ kid: "unknown-kid" })}`);
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			UnauthorizedException
		);
	});

	it("throws UnauthorizedException for a wrong issuer", async () => {
		const ctx = makeContext(`Bearer ${makeToken({ iss: "evil" })}`);
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			UnauthorizedException
		);
	});

	it("throws UnauthorizedException for a wrong audience", async () => {
		const ctx = makeContext(
			`Bearer ${makeToken({ aud: "other-service" })}`
		);
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			UnauthorizedException
		);
	});

	it("throws ForbiddenException when the fingerprint is not on the allowlist", async () => {
		const ctx = makeContext(`Bearer ${makeToken({ fpr: "deadbeef" })}`);
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			ForbiddenException
		);
	});

	it("throws ForbiddenException when the fpr claim is missing", async () => {
		const ctx = makeContext(`Bearer ${makeToken({ omitFpr: true })}`);
		await expect(guard.canActivate(ctx)).rejects.toThrow(
			ForbiddenException
		);
	});

	it("matches the fingerprint case-insensitively and ignoring colons", async () => {
		// Colon-delimited UPPERCASE form, exactly as `openssl x509 -fingerprint
		// -sha256` prints it – the guard must normalise this to match.
		const colonForm = TEST_FPR.toUpperCase().match(/.{2}/g)!.join(":");
		const ctx = makeContext(`Bearer ${makeToken({ fpr: colonForm })}`);
		await expect(guard.canActivate(ctx)).resolves.toBe(true);
	});

	// ── SHA-256 alignment (the admin-lockout fix) ─────────────────────────────

	it("rejects a SHA-1 (40-char) allowlist entry – fail-closed, never silent-accept", async () => {
		// Simulate the historical misconfiguration: an operator pastes a SHA-1
		// fingerprint into ADMIN_CERT_FINGERPRINTS. The guard must drop it as
		// malformed so the allowlist is empty (deny all) rather than honour a
		// non-SHA-256 value.
		process.env.ADMIN_CERT_FINGERPRINTS = SHA1_FPR;
		const module = await Test.createTestingModule({
			providers: [
				JwtAuthGuard,
				{ provide: Reflector, useValue: reflector },
			],
		}).compile();
		const g = module.get<JwtAuthGuard>(JwtAuthGuard);

		const ctx = makeContext(`Bearer ${makeToken({ fpr: SHA1_FPR })}`);
		await expect(g.canActivate(ctx)).rejects.toThrow(ForbiddenException);
	});

	it("accepts a valid SHA-256 fpr alongside a rejected SHA-1 entry (mixed allowlist)", async () => {
		// A good SHA-256 entry still works even if a bad SHA-1 entry is present.
		process.env.ADMIN_CERT_FINGERPRINTS = `${SHA1_FPR}, ${TEST_FPR}`;
		const module = await Test.createTestingModule({
			providers: [
				JwtAuthGuard,
				{ provide: Reflector, useValue: reflector },
			],
		}).compile();
		const g = module.get<JwtAuthGuard>(JwtAuthGuard);

		await expect(
			g.canActivate(makeContext(`Bearer ${makeToken({ fpr: TEST_FPR })}`))
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

		delete process.env.ADMIN_CERT_FINGERPRINTS; // ensure the FILE is the source
		process.env.ADMIN_CERT_FINGERPRINTS_FILE = secret;
		const module = await Test.createTestingModule({
			providers: [
				JwtAuthGuard,
				{ provide: Reflector, useValue: reflector },
			],
		}).compile();
		const g = module.get<JwtAuthGuard>(JwtAuthGuard);

		await expect(
			g.canActivate(makeContext(`Bearer ${makeToken({ fpr: TEST_FPR })}`))
		).resolves.toBe(true);

		fs.rmSync(path.dirname(secret), { recursive: true, force: true });
	});
});
