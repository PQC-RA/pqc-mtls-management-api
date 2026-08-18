// nestjs-otel tries to connect to an OTLP collector on startup – mock it so
// the module initialises synchronously without any network calls.
jest.mock("nestjs-otel", () => ({
	OpenTelemetryModule: {
		forRoot: () => ({
			module: class OpenTelemetryModuleMock {},
			imports: [],
			exports: [],
		}),
	},
}));

// jwks-rsa@4.x depends on jose which is pure ESM and cannot be loaded by
// jest's CommonJS runtime in pnpm's nested node_modules layout.
// Replace it with a lightweight CJS implementation that honours the same
// interface used by JwtAuthGuard: jwksClient.getSigningKey(kid).getPublicKey().
jest.mock("jwks-rsa", () => {
	const nodeHttp = require("http") as typeof import("http");
	const nodeHttps = require("https") as typeof import("https");
	const nodeCrypto = require("crypto") as typeof import("crypto");

	function fetchJson(url: string): Promise<Record<string, unknown>> {
		return new Promise((resolve, reject) => {
			const client = url.startsWith("https://") ? nodeHttps : nodeHttp;
			client
				.get(url, res => {
					let raw = "";
					res.on("data", (chunk: Buffer) => {
						raw += chunk.toString();
					});
					res.on("end", () => {
						try {
							resolve(JSON.parse(raw) as Record<string, unknown>);
						} catch (e) {
							reject(e);
						}
					});
				})
				.on("error", reject);
		});
	}

	return function jwksRsa(options: { jwksUri: string }) {
		return {
			getSigningKey: async (kid: string) => {
				const jwks = (await fetchJson(options.jwksUri)) as {
					keys: Array<Record<string, string>>;
				};
				const keyData = jwks.keys.find(k => k.kid === kid);
				if (!keyData) throw new Error(`Key not found in JWKS: ${kid}`);
				const keyObj = nodeCrypto.createPublicKey({
					key: keyData as unknown as crypto.JsonWebKeyInput["key"],
					format: "jwk",
				});
				const pem = keyObj.export({
					type: "spki",
					format: "pem",
				}) as string;
				return { getPublicKey: () => pem };
			},
		};
	};
});

/**
 * End-to-end tests for the PQC Management API.
 *
 * Auth model exercised end-to-end (no mocks on the auth path):
 *  1. A fresh RSA key pair + local JWKS server simulate the gateway's signer.
 *  2. JWTs are signed with the pinned issuer/audience and a `fpr` claim.
 *  3. ADMIN_/AUDITOR_CERT_FINGERPRINTS map those fingerprints to roles.
 *  4. CONSOLE_ORIGIN drives the anti-CSRF guard on mutating routes.
 */

import * as crypto from "crypto";
import * as http from "http";
import * as os from "os";
import * as path from "path";

import { INestApplication, ValidationPipe } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";
import * as jwt from "jsonwebtoken";
import request from "supertest";
import type { App } from "supertest/types";

function publicKeyToJwk(
	publicKey: crypto.KeyObject,
	kid: string
): Record<string, unknown> {
	const jwk = publicKey.export({ format: "jwk" }) as Record<string, string>;
	return {
		keys: [
			{ kty: "RSA", use: "sig", alg: "RS256", kid, n: jwk.n, e: jwk.e },
		],
	};
}

function startJwksServer(
	jwks: Record<string, unknown>
): Promise<{ server: http.Server; url: string }> {
	return new Promise((resolve, reject) => {
		const body = JSON.stringify(jwks);
		const server = http.createServer((_req, res) => {
			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(body);
		});
		server.listen(0, "127.0.0.1", () => {
			const addr = server.address() as { port: number };
			resolve({ server, url: `http://127.0.0.1:${addr.port}` });
		});
		server.on("error", reject);
	});
}

// ── Test fixtures ────────────────────────────────────────────────────────────

const KEY_ID = "test-pqc-rs256-v1";
const ISSUER = "pqc-gateway";
const AUDIENCE = "pqc-mtls-management-api";
const CONSOLE_ORIGIN = "https://console.test";
const ADMIN_FPR =
	"1c2ba075293fcd68e241cfcedf337ff59bc8126b24c2af07c60f319a38e1a0d8";
const AUDITOR_FPR =
	"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
const UNKNOWN_FPR =
	"9999999999999999999999999999999999999999999999999999999999999999";

let privateKey: crypto.KeyObject;
let jwksServer: http.Server;
let app: INestApplication<App>;
let adminToken: string;
let auditorToken: string;

/** Sign an RS256 JWT with the pinned issuer/audience and a fpr claim. */
function signJwt(
	overrides: { fpr?: string; sub?: string } & jwt.SignOptions = {}
): string {
	const { fpr, sub, ...signOpts } = overrides;
	const claims: Record<string, unknown> = { sub: sub ?? "test-service" };
	if (fpr !== undefined) claims.fpr = fpr;
	return jwt.sign(
		claims,
		privateKey.export({ type: "pkcs8", format: "pem" }) as string,
		{
			algorithm: "RS256",
			expiresIn: "5m",
			keyid: KEY_ID,
			issuer: ISSUER,
			audience: AUDIENCE,
			...signOpts,
		}
	);
}

/** A POST/PUT/DELETE request pre-loaded with a valid CSRF Origin + header. */
function mutating(
	method: "post" | "put" | "delete",
	url: string,
	token: string
) {
	return request(app.getHttpServer())
		[method](url)
		.set("Authorization", `Bearer ${token}`)
		.set("Origin", CONSOLE_ORIGIN)
		.set("X-PQC-CSRF", "1");
}

beforeAll(async () => {
	const pair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
	privateKey = pair.privateKey;

	const { server, url } = await startJwksServer(
		publicKeyToJwk(pair.publicKey, KEY_ID)
	);
	jwksServer = server;

	// Configure the guards BEFORE the app boots (they read env at construction).
	process.env.GATEWAY_JWKS_URI = url;
	process.env.ADMIN_CERT_FINGERPRINTS = ADMIN_FPR;
	process.env.AUDITOR_CERT_FINGERPRINTS = AUDITOR_FPR;
	process.env.CONSOLE_ORIGIN = CONSOLE_ORIGIN;
	process.env.ADMIN_AUDIT_LOG = path.join(
		os.tmpdir(),
		`e2e-admin-actions-${process.pid}.log`
	);

	const { AppModule } = require("../src/app.module");

	const moduleFixture: TestingModule = await Test.createTestingModule({
		imports: [AppModule],
	}).compile();

	app = moduleFixture.createNestApplication();
	app.useGlobalPipes(
		new ValidationPipe({
			whitelist: true,
			forbidNonWhitelisted: true,
			transform: true,
		})
	);
	app.setGlobalPrefix("api");
	await app.init();

	adminToken = signJwt({ fpr: ADMIN_FPR, sub: "ops-admin" });
	auditorToken = signJwt({ fpr: AUDITOR_FPR, sub: "ops-auditor" });
}, 30000);

afterAll(async () => {
	await app.close();
	await new Promise<void>((res, rej) =>
		jwksServer.close(err => (err ? rej(err) : res()))
	);
});

// ── Health ─────────────────────────────────────────────────────────────────────

describe("GET /api/admin/health", () => {
	it("requires authentication (401 without a token)", async () => {
		const res = await request(app.getHttpServer()).get("/api/admin/health");
		expect(res.status).toBe(401);
	});

	it("returns a health status (200 or 503) with a valid admin token", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/health")
			.set("Authorization", `Bearer ${adminToken}`);
		expect([200, 503]).toContain(res.status);
	});
});

// ── Auth gate ────────────────────────────────────────────────────────────────

describe("Admin API auth gate", () => {
	it("401 without Authorization header", async () => {
		const res = await request(app.getHttpServer()).get("/api/admin/certs");
		expect(res.status).toBe(401);
	});

	it("401 with a malformed token", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/certs")
			.set("Authorization", "Bearer not.a.jwt");
		expect(res.status).toBe(401);
	});

	it("401 with an expired token", async () => {
		const expired = signJwt({ fpr: ADMIN_FPR, expiresIn: "-1s" });
		const res = await request(app.getHttpServer())
			.get("/api/admin/certs")
			.set("Authorization", `Bearer ${expired}`);
		expect(res.status).toBe(401);
	});

	it("403 when the fpr is not on any allowlist", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/certs")
			.set("Authorization", `Bearer ${signJwt({ fpr: UNKNOWN_FPR })}`);
		expect(res.status).toBe(403);
	});

	it("403 when the token has no fpr claim", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/certs")
			.set("Authorization", `Bearer ${signJwt({})}`);
		expect(res.status).toBe(403);
	});

	it("401 with a token signed by the wrong key", async () => {
		const wrongPair = crypto.generateKeyPairSync("rsa", {
			modulusLength: 2048,
		});
		const wrongToken = jwt.sign(
			{ sub: "x", fpr: ADMIN_FPR },
			wrongPair.privateKey.export({
				type: "pkcs8",
				format: "pem",
			}) as string,
			{
				algorithm: "RS256",
				expiresIn: "5m",
				keyid: KEY_ID,
				issuer: ISSUER,
				audience: AUDIENCE,
			}
		);
		const res = await request(app.getHttpServer())
			.get("/api/admin/certs")
			.set("Authorization", `Bearer ${wrongToken}`);
		expect(res.status).toBe(401);
	});
});

// ── whoami ─────────────────────────────────────────────────────────────────────

describe("GET /api/admin/whoami", () => {
	it("returns the admin identity and role", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/whoami")
			.set("Authorization", `Bearer ${adminToken}`);
		expect(res.status).toBe(200);
		expect(res.body).toEqual({
			sub: "ops-admin",
			fpr: ADMIN_FPR,
			role: "admin",
		});
	});

	it("reports the auditor role for an auditor cert", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/whoami")
			.set("Authorization", `Bearer ${auditorToken}`);
		expect(res.status).toBe(200);
		expect(res.body.role).toBe("auditor");
	});

	it("401 without a token", async () => {
		const res = await request(app.getHttpServer()).get("/api/admin/whoami");
		expect(res.status).toBe(401);
	});
});

// ── Certs ──────────────────────────────────────────────────────────────────────

describe("GET /api/admin/certs", () => {
	it("admin passes auth (non-401/403)", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/certs")
			.set("Authorization", `Bearer ${adminToken}`);
		expect(res.status).not.toBe(401);
		expect(res.status).not.toBe(403);
	});

	it("auditor may read certs", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/certs")
			.set("Authorization", `Bearer ${auditorToken}`);
		expect(res.status).not.toBe(401);
		expect(res.status).not.toBe(403);
	});
});

// ── RBAC + CSRF on mutations ─────────────────────────────────────────────────────

describe("POST /api/admin/certs/enrollment-tokens (RBAC + CSRF)", () => {
	it("401 without a token", async () => {
		const res = await request(app.getHttpServer()).post(
			"/api/admin/certs/enrollment-tokens"
		);
		expect(res.status).toBe(401);
	});

	it("403 (CSRF) when Origin / X-PQC-CSRF are missing", async () => {
		const res = await request(app.getHttpServer())
			.post("/api/admin/certs/enrollment-tokens")
			.set("Authorization", `Bearer ${adminToken}`)
			.query({ cn: "svc", ttl: 3600 });
		expect(res.status).toBe(403);
	});

	it("403 (RBAC) for an auditor even with valid CSRF headers", async () => {
		const res = await mutating(
			"post",
			"/api/admin/certs/enrollment-tokens",
			auditorToken
		).query({ cn: "svc", ttl: 3600 });
		expect(res.status).toBe(403);
	});

	it("201 for an admin with valid CSRF headers", async () => {
		const res = await mutating(
			"post",
			"/api/admin/certs/enrollment-tokens",
			adminToken
		).query({ cn: "svc", ttl: 3600 });
		expect(res.status).toBe(201);
		expect(res.body.token).toMatch(/^enroll_[0-9a-f]+$/);
		expect(res.body.allowedCn).toBe("svc");
	});
});

describe("GET /api/admin/certs/enrollment-tokens", () => {
	it("auditor may read the token list", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/certs/enrollment-tokens")
			.set("Authorization", `Bearer ${auditorToken}`);
		expect(res.status).toBe(200);
		expect(Array.isArray(res.body)).toBe(true);
	});
});

// ── Audit endpoints ──────────────────────────────────────────────────────────────

describe("GET /api/admin/audit/logs", () => {
	it("401 without a token", async () => {
		const res = await request(app.getHttpServer()).get(
			"/api/admin/audit/logs"
		);
		expect(res.status).toBe(401);
	});

	it("admin passes auth", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/audit/logs")
			.set("Authorization", `Bearer ${adminToken}`);
		expect(res.status).not.toBe(401);
		expect(res.status).not.toBe(403);
	});

	it("400 for lines=0 (below minimum)", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/audit/logs")
			.set("Authorization", `Bearer ${adminToken}`)
			.query({ lines: 0 });
		expect(res.status).toBe(400);
	});

	it("400 for lines above the maximum", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/audit/logs")
			.set("Authorization", `Bearer ${adminToken}`)
			.query({ lines: 99999 });
		expect(res.status).toBe(400);
	});

	it("accepts a valid lines value", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/audit/logs")
			.set("Authorization", `Bearer ${adminToken}`)
			.query({ lines: 500 });
		expect(res.status).not.toBe(400);
	});
});

describe("GET /api/admin/audit/admin-actions", () => {
	it("401 without a token", async () => {
		const res = await request(app.getHttpServer()).get(
			"/api/admin/audit/admin-actions"
		);
		expect(res.status).toBe(401);
	});

	it("auditor may read the admin-action trail", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/audit/admin-actions")
			.set("Authorization", `Bearer ${auditorToken}`);
		expect(res.status).toBe(200);
		expect(Array.isArray(res.body)).toBe(true);
	});
});

// ── Policy ───────────────────────────────────────────────────────────────────────

describe("GET /api/admin/policy/routes", () => {
	it("401 without a token", async () => {
		const res = await request(app.getHttpServer()).get(
			"/api/admin/policy/routes"
		);
		expect(res.status).toBe(401);
	});

	it("admin passes auth", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/policy/routes")
			.set("Authorization", `Bearer ${adminToken}`);
		expect(res.status).not.toBe(401);
		expect(res.status).not.toBe(403);
	});
});

describe("GET /api/admin/policy/orgs", () => {
	it("401 without a token", async () => {
		const res = await request(app.getHttpServer()).get(
			"/api/admin/policy/orgs"
		);
		expect(res.status).toBe(401);
	});

	// Route-ordering check: "orgs" (literal) must resolve to listOrgs(), not
	// fall through to the "orgs/:orgId" handler with orgId="orgs" (which would
	// 404, since no org is ever actually named "orgs" here). A real HTTP
	// request against the fully-booted Nest router is the only way to prove
	// this – reasoning about Express/NestJS route-matching defaults isn't
	// enough given this codebase's history of routing/decorator surprises.
	it("resolves to listOrgs, not the orgs/:orgId route – returns an object, not a 404", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/policy/orgs")
			.set("Authorization", `Bearer ${adminToken}`);
		expect(res.status).toBe(200);
		expect(res.body).toEqual(expect.any(Object));
		expect(res.body).not.toHaveProperty("statusCode", 404);
	});
});

describe("GET /api/admin/policy/orgs/:orgId", () => {
	// Sibling check: the literal "orgs" route above must not swallow the
	// ":orgId" wildcard route for genuine org IDs.
	it("still 404s for an unknown org ID (the :orgId route still matches)", async () => {
		const res = await request(app.getHttpServer())
			.get("/api/admin/policy/orgs/no-such-org")
			.set("Authorization", `Bearer ${adminToken}`);
		expect(res.status).toBe(404);
	});
});

describe("POST /api/admin/policy/routes?dryRun=1", () => {
	const doc = {
		clients: { "svc-new": { backend: "http://svc:80" } },
		defaults: {
			rate_limit: { rps: 50, burst: 100 },
			deny_action: "reject",
		},
		policy: {
			unknown_cn_action: "reject",
			expired_cert_action: "reject",
			expiry_warning_days: 30,
			expiry_critical_days: 7,
			require_valid_verify: true,
		},
	};

	it("returns a validation+diff result without pushing", async () => {
		const res = await mutating(
			"post",
			"/api/admin/policy/routes",
			adminToken
		)
			.query({ dryRun: 1 })
			.send(doc);
		expect(res.status).toBe(200);
		expect(res.body).toHaveProperty("valid");
		expect(res.body).toHaveProperty("diff");
		expect(res.body.diff).toHaveProperty("addedClients");
	});
});
