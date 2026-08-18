jest.mock("fs");
import * as fs from "fs";

import { HttpStatus } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";

import { PolicyService } from "@/policy/policy.service";

const existsSync = jest.mocked(fs.existsSync);
const readFileSync = jest.mocked(fs.readFileSync);

const fetchMock = jest.fn();

const SAMPLE_ROUTES = {
	_meta: { version: "1" },
	clients: {
		"service-A": {
			backend: "http://localhost:8081",
			rate_limit: { rps: 100, burst: 200 },
		},
	},
	defaults: { rate_limit: { rps: 50, burst: 100 }, deny_action: "reject" },
	policy: {
		unknown_cn_action: "reject",
		expired_cert_action: "reject",
		expiry_warning_days: 30,
		expiry_critical_days: 7,
		require_valid_verify: true,
	},
};

// `fs.readFileSync` is also used internally to read the control-plane HMAC
// secret file; route it away from whatever the current test configured for
// the legacy routes file so pushes succeed regardless of test setup.
const HMAC_SECRET_FILE = "/run/secrets/control-plane-hmac";
function mockLegacyRoutesFile(exists: boolean, content?: string): void {
	existsSync.mockImplementation(
		(p: fs.PathLike) => exists && p !== HMAC_SECRET_FILE
	);
	readFileSync.mockImplementation((p: fs.PathLike) => {
		if (p === HMAC_SECRET_FILE) return "test-hmac-secret";
		return content as never;
	});
}

describe("PolicyService", () => {
	let service: PolicyService;

	beforeEach(async () => {
		jest.resetAllMocks();
		(global as typeof globalThis & { fetch: typeof fetch }).fetch =
			fetchMock as unknown as typeof fetch;
		readFileSync.mockImplementation((p: fs.PathLike) =>
			p === HMAC_SECRET_FILE ? "test-hmac-secret" : (undefined as never)
		);
		existsSync.mockReturnValue(false);

		const module: TestingModule = await Test.createTestingModule({
			providers: [PolicyService],
		}).compile();
		service = module.get<PolicyService>(PolicyService);
	});

	it("should be defined", () => {
		expect(service).toBeDefined();
	});

	// ── one-time legacy import + startup reconciliation ─────────────────────

	describe("importLegacyRoutesFileIfNeeded / republishOnStartup", () => {
		it("does NOT push to the gateway when Redis is empty and no legacy file exists", async () => {
			mockLegacyRoutesFile(false);

			await (
				service as unknown as {
					initializeAndRepublish(): Promise<void>;
				}
			).initializeAndRepublish();

			expect(fetchMock).not.toHaveBeenCalled();
		});

		it("imports the legacy routes file into Redis on first startup, then republishes", async () => {
			mockLegacyRoutesFile(true, JSON.stringify(SAMPLE_ROUTES));
			fetchMock.mockResolvedValue({
				ok: true,
				status: 200,
				text: async () => '{"ok":true}',
			});

			await (
				service as unknown as {
					initializeAndRepublish(): Promise<void>;
				}
			).initializeAndRepublish();

			expect(fetchMock).toHaveBeenCalledTimes(1);
			expect(fetchMock).toHaveBeenCalledWith(
				expect.stringContaining("/update-routes"),
				expect.objectContaining({ method: "POST" })
			);

			// Imported state is now readable back from Redis (in-memory fallback).
			const routes = await service.getRoutes();
			expect(routes).toMatchObject(SAMPLE_ROUTES);
		});

		it("does not re-import on a second call once Redis already holds state", async () => {
			mockLegacyRoutesFile(true, JSON.stringify(SAMPLE_ROUTES));
			fetchMock.mockResolvedValue({
				ok: true,
				status: 200,
				text: async () => '{"ok":true}',
			});

			await (
				service as unknown as {
					initializeAndRepublish(): Promise<void>;
				}
			).initializeAndRepublish();

			readFileSync.mockClear();
			existsSync.mockClear();

			await (
				service as unknown as {
					initializeAndRepublish(): Promise<void>;
				}
			).initializeAndRepublish();

			// Second run republishes again (fetch called) but never re-reads the
			// legacy file, since `policy:meta` already exists in Redis.
			expect(fetchMock).toHaveBeenCalledTimes(2);
			expect(existsSync).not.toHaveBeenCalledWith(
				expect.stringContaining("routes.json")
			);
		});

		it("republishes existing Redis state without touching the legacy file", async () => {
			mockLegacyRoutesFile(false);
			fetchMock.mockResolvedValue({
				ok: true,
				status: 200,
				text: async () => '{"ok":true}',
			});

			// Seed Redis (in-memory fallback) directly via a normal write path.
			await service.updateRoutes(SAMPLE_ROUTES as never);
			fetchMock.mockClear();

			await (
				service as unknown as { republishOnStartup(): Promise<void> }
			).republishOnStartup();

			expect(fetchMock).toHaveBeenCalledTimes(1);
		});
	});

	// ── getRoutes ────────────────────────────────────────────────────────────

	describe("getRoutes", () => {
		it("returns default routes when nothing has been persisted to Redis", async () => {
			const result = await service.getRoutes();
			expect(result).toMatchObject({
				clients: {},
				defaults: {
					rate_limit: { rps: 50, burst: 100 },
					deny_action: "reject",
				},
			});
		});

		it("reassembles the full routes document from meta + per-client keys", async () => {
			// Seed the underlying store directly (bypassing updateRoutes' cache
			// shortcut) to genuinely exercise the SCAN + reassembly path.
			const local = (service as unknown as { local: Map<string, string> })
				.local;
			local.set(
				"policy:meta",
				JSON.stringify({
					_meta: SAMPLE_ROUTES._meta,
					defaults: SAMPLE_ROUTES.defaults,
					policy: SAMPLE_ROUTES.policy,
				})
			);
			local.set(
				"policy:client:service-A",
				JSON.stringify(SAMPLE_ROUTES.clients["service-A"])
			);

			const result = await service.getRoutes();
			expect(result).toMatchObject(SAMPLE_ROUTES);
		});
	});

	// ── updateRoutes ─────────────────────────────────────────────────────────

	describe("updateRoutes", () => {
		it("pushes routes to gateway control plane on success", async () => {
			fetchMock.mockResolvedValue({
				ok: true,
				status: 200,
				text: async () => '{"ok":true}',
			});

			const result = await service.updateRoutes(SAMPLE_ROUTES as never);
			expect(fetchMock).toHaveBeenCalledTimes(1);
			expect(fetchMock).toHaveBeenCalledWith(
				expect.stringContaining("/update-routes"),
				expect.objectContaining({
					method: "POST",
					headers: expect.objectContaining({
						"Content-Type": "application/json",
					}),
				})
			);
			expect(result.message).toMatch(/updated/i);
		});

		it("throws 502 when gateway returns non-2xx", async () => {
			fetchMock.mockResolvedValue({
				ok: false,
				status: 500,
				text: async () => "gateway internal error",
			});

			await expect(
				service.updateRoutes(SAMPLE_ROUTES as never)
			).rejects.toMatchObject({
				status: HttpStatus.BAD_GATEWAY,
			});
		});

		it("throws 502 when gateway is unreachable", async () => {
			fetchMock.mockRejectedValue(new Error("connect ECONNREFUSED"));

			await expect(
				service.updateRoutes(SAMPLE_ROUTES as never)
			).rejects.toMatchObject({
				status: HttpStatus.BAD_GATEWAY,
			});
		});

		it("does not persist to Redis when the gateway push fails", async () => {
			fetchMock.mockResolvedValue({
				ok: false,
				status: 500,
				text: async () => "gateway internal error",
			});

			await expect(
				service.updateRoutes(SAMPLE_ROUTES as never)
			).rejects.toBeDefined();

			const result = await service.getRoutes();
			expect(result.clients).toEqual({});
		});
	});

	// ── dryRunRoutes ─────────────────────────────────────────────────────────

	describe("dryRunRoutes", () => {
		beforeEach(async () => {
			// Active config = SAMPLE_ROUTES (service-A only).
			fetchMock.mockResolvedValue({
				ok: true,
				status: 200,
				text: async () => '{"ok":true}',
			});
			await service.updateRoutes(SAMPLE_ROUTES as never);
			fetchMock.mockClear();
		});

		it("does NOT push to the gateway (no HMAC call)", async () => {
			const candidate = JSON.parse(JSON.stringify(SAMPLE_ROUTES));
			candidate.clients["service-B"] = { backend: "http://b:80" };

			await service.dryRunRoutes(candidate);
			expect(fetchMock).not.toHaveBeenCalled();
		});

		it("computes added / removed / changed client CNs", async () => {
			const candidate = JSON.parse(JSON.stringify(SAMPLE_ROUTES));
			candidate.clients["service-B"] = { backend: "http://b:80" }; // added
			candidate.clients["service-A"].backend = "http://changed:9090"; // changed

			const result = await service.dryRunRoutes(candidate);
			expect(result.valid).toBe(true);
			expect(result.diff.addedClients).toEqual(["service-B"]);
			expect(result.diff.changedClients).toEqual(["service-A"]);
			expect(result.diff.removedClients).toEqual([]);
		});

		it("detects removed clients", async () => {
			const candidate = JSON.parse(JSON.stringify(SAMPLE_ROUTES));
			delete candidate.clients["service-A"];

			const result = await service.dryRunRoutes(candidate);
			expect(result.diff.removedClients).toEqual(["service-A"]);
			expect(result.diff.addedClients).toEqual([]);
		});

		it("detects changed global fields", async () => {
			const candidate = JSON.parse(JSON.stringify(SAMPLE_ROUTES));
			candidate.policy.unknown_cn_action = "allow";
			candidate.defaults.deny_action = "drop";

			const result = await service.dryRunRoutes(candidate);
			expect(result.diff.changedGlobalFields).toEqual(
				expect.arrayContaining([
					"policy.unknown_cn_action",
					"defaults.deny_action",
				])
			);
		});

		it("reports an empty diff when the document is unchanged", async () => {
			const candidate = JSON.parse(JSON.stringify(SAMPLE_ROUTES));
			const result = await service.dryRunRoutes(candidate);
			expect(result.diff).toEqual({
				addedClients: [],
				removedClients: [],
				changedClients: [],
				changedGlobalFields: [],
			});
		});

		it("flags a semantic error for a route missing path/backend", async () => {
			const candidate = JSON.parse(JSON.stringify(SAMPLE_ROUTES));
			candidate.clients["service-C"] = {
				routes: [{ path: "", backend: "" }],
			};
			const result = await service.dryRunRoutes(candidate);
			expect(result.valid).toBe(false);
			expect(result.errors.length).toBeGreaterThan(0);
		});
	});

	// ── per-client CRUD (atomic single-key ops) ─────────────────────────────

	describe("getClientPolicy / updateClientPolicy / deleteClientPolicy", () => {
		beforeEach(async () => {
			fetchMock.mockResolvedValue({
				ok: true,
				status: 200,
				text: async () => '{"ok":true}',
			});
			await service.updateRoutes(SAMPLE_ROUTES as never);
			fetchMock.mockClear();
		});

		it("getClientPolicy returns the stored policy for a known CN", async () => {
			const result = await service.getClientPolicy("service-A");
			expect(result).toMatchObject(SAMPLE_ROUTES.clients["service-A"]);
		});

		it("getClientPolicy throws 404 for an unknown CN", async () => {
			await expect(
				service.getClientPolicy("no-such-client")
			).rejects.toMatchObject({ status: HttpStatus.NOT_FOUND });
		});

		it("updateClientPolicy pushes the full assembled document and stores only the changed client key", async () => {
			const newPolicy = { backend: "http://service-b:8080" };
			const result = await service.updateClientPolicy(
				"service-B",
				newPolicy as never
			);

			expect(result).toEqual({ cn: "service-B", policy: newPolicy });
			expect(fetchMock).toHaveBeenCalledTimes(1);
			const pushedBody = JSON.parse(
				(fetchMock.mock.calls[0][1] as { body: string }).body
			);
			expect(pushedBody.clients).toMatchObject({
				"service-A": SAMPLE_ROUTES.clients["service-A"],
				"service-B": newPolicy,
			});

			// service-A must be untouched – only service-B's key was written.
			const routes = await service.getRoutes();
			expect(routes.clients["service-A"]).toMatchObject(
				SAMPLE_ROUTES.clients["service-A"]
			);
			expect(routes.clients["service-B"]).toEqual(newPolicy);
		});

		it("stores only the changed client key, leaving other client keys byte-for-byte untouched", async () => {
			const local = (service as unknown as { local: Map<string, string> })
				.local;
			const serviceAValueBefore = local.get("policy:client:service-A");
			expect(serviceAValueBefore).toBeDefined();

			await service.updateClientPolicy("service-B", {
				backend: "http://service-b:8080",
			} as never);

			expect(local.get("policy:client:service-A")).toBe(
				serviceAValueBefore
			);
			expect(
				JSON.parse(local.get("policy:client:service-B") as string)
			).toEqual({ backend: "http://service-b:8080" });
		});

		it("updateClientPolicy throws 502 without storing the client key when the gateway push fails", async () => {
			fetchMock.mockResolvedValue({
				ok: false,
				status: 500,
				text: async () => "gateway internal error",
			});

			await expect(
				service.updateClientPolicy("service-B", {
					backend: "http://b:80",
				} as never)
			).rejects.toMatchObject({ status: HttpStatus.BAD_GATEWAY });

			await expect(
				service.getClientPolicy("service-B")
			).rejects.toMatchObject({ status: HttpStatus.NOT_FOUND });
		});

		it("deleteClientPolicy removes the client key and pushes the reduced document", async () => {
			const local = (service as unknown as { local: Map<string, string> })
				.local;

			const result = await service.deleteClientPolicy("service-A");
			expect(result.message).toMatch(/deleted/i);
			expect(fetchMock).toHaveBeenCalledTimes(1);

			await expect(
				service.getClientPolicy("service-A")
			).rejects.toMatchObject({ status: HttpStatus.NOT_FOUND });
			expect(local.has("policy:client:service-A")).toBe(false);
			expect(local.has("policy:meta")).toBe(true);
		});

		it("deleteClientPolicy throws 404 for an unknown CN without calling the gateway", async () => {
			await expect(
				service.deleteClientPolicy("no-such-client")
			).rejects.toMatchObject({ status: HttpStatus.NOT_FOUND });
			expect(fetchMock).not.toHaveBeenCalled();
		});
	});

	// ── organization CRUD ────────────────────────────────────────────────────

	describe("listOrgs / getOrgPolicy / updateOrgPolicy / deleteOrgPolicy", () => {
		beforeEach(async () => {
			fetchMock.mockResolvedValue({
				ok: true,
				status: 200,
				text: async () => '{"ok":true}',
			});
			await service.updateRoutes(SAMPLE_ROUTES as never);
			fetchMock.mockClear();
		});

		it("listOrgs returns {} when no organizations exist", async () => {
			await expect(service.listOrgs()).resolves.toEqual({});
		});

		it("listOrgs returns every created org keyed by ID", async () => {
			const acmePolicy = { backend: "http://acme-backend:8080" };
			const globexPolicy = { backend: "http://globex-backend:9090" };
			await service.updateOrgPolicy("org-acme", acmePolicy as never);
			await service.updateOrgPolicy("org-globex", globexPolicy as never);

			const orgs = await service.listOrgs();
			expect(orgs).toEqual({
				"org-acme": acmePolicy,
				"org-globex": globexPolicy,
			});
		});

		it("listOrgs omits an org after it is deleted", async () => {
			await service.updateOrgPolicy("org-acme", {
				backend: "http://acme-backend:8080",
			} as never);
			await service.updateOrgPolicy("org-globex", {
				backend: "http://globex-backend:9090",
			} as never);

			await service.deleteOrgPolicy("org-acme");

			const orgs = await service.listOrgs();
			expect(Object.keys(orgs)).toEqual(["org-globex"]);
		});

		it("getOrgPolicy throws 404 for an unknown org", async () => {
			await expect(
				service.getOrgPolicy("no-such-org")
			).rejects.toMatchObject({ status: HttpStatus.NOT_FOUND });
		});

		it("updateOrgPolicy creates the org and pushes the resolved routing document", async () => {
			const orgPolicy = { backend: "http://org-backend:8080" };
			const result = await service.updateOrgPolicy(
				"org-acme",
				orgPolicy as never
			);

			expect(result).toEqual({ orgId: "org-acme", policy: orgPolicy });
			expect(fetchMock).toHaveBeenCalledTimes(1);

			const fetched = await service.getOrgPolicy("org-acme");
			expect(fetched).toEqual(orgPolicy);
		});

		it("updateOrgPolicy throws 502 without persisting the org when the gateway push fails", async () => {
			fetchMock.mockResolvedValue({
				ok: false,
				status: 500,
				text: async () => "gateway internal error",
			});

			await expect(
				service.updateOrgPolicy("org-acme", {
					backend: "http://b:80",
				} as never)
			).rejects.toMatchObject({ status: HttpStatus.BAD_GATEWAY });

			// Redis must be untouched on a failed push – a never-persisted org
			// must not appear to exist afterward.
			await expect(
				service.getOrgPolicy("org-acme")
			).rejects.toMatchObject({ status: HttpStatus.NOT_FOUND });
		});

		it("updateOrgPolicy leaves an existing org's policy unchanged when the gateway push fails", async () => {
			const originalPolicy = { backend: "http://org-original:8080" };
			await service.updateOrgPolicy("org-acme", originalPolicy as never);

			fetchMock.mockResolvedValue({
				ok: false,
				status: 500,
				text: async () => "gateway internal error",
			});

			await expect(
				service.updateOrgPolicy("org-acme", {
					backend: "http://org-failed-update:9090",
				} as never)
			).rejects.toMatchObject({ status: HttpStatus.BAD_GATEWAY });

			// The failed candidate must not have overwritten the persisted value.
			const stillOriginal = await service.getOrgPolicy("org-acme");
			expect(stillOriginal).toEqual(originalPolicy);
		});

		it("deleteOrgPolicy does not delete the org when the gateway push fails", async () => {
			const orgPolicy = { backend: "http://org-backend:8080" };
			await service.updateOrgPolicy("org-acme", orgPolicy as never);

			fetchMock.mockResolvedValue({
				ok: false,
				status: 500,
				text: async () => "gateway internal error",
			});

			await expect(
				service.deleteOrgPolicy("org-acme")
			).rejects.toMatchObject({ status: HttpStatus.BAD_GATEWAY });

			// Redis must be untouched on a failed push – the org must survive.
			const stillThere = await service.getOrgPolicy("org-acme");
			expect(stillThere).toEqual(orgPolicy);
		});

		it("deleteOrgPolicy removes the org and pushes the routing document", async () => {
			await service.updateOrgPolicy("org-acme", {
				backend: "http://org-backend:8080",
			} as never);
			fetchMock.mockClear();

			const result = await service.deleteOrgPolicy("org-acme");
			expect(result.message).toMatch(/deleted/i);
			expect(fetchMock).toHaveBeenCalledTimes(1);

			await expect(
				service.getOrgPolicy("org-acme")
			).rejects.toMatchObject({ status: HttpStatus.NOT_FOUND });
		});

		it("deleteOrgPolicy throws 404 for an unknown org without calling the gateway", async () => {
			await expect(
				service.deleteOrgPolicy("no-such-org")
			).rejects.toMatchObject({ status: HttpStatus.NOT_FOUND });
			expect(fetchMock).not.toHaveBeenCalled();
		});

		it("deleteOrgPolicy refuses with 409, listing the referencing CNs, without calling the gateway", async () => {
			await service.updateOrgPolicy("org-acme", {
				backend: "http://org-backend:8080",
			} as never);
			await service.updateClientPolicy("service-C", {
				org: "org-acme",
			} as never);
			fetchMock.mockClear();

			await expect(
				service.deleteOrgPolicy("org-acme")
			).rejects.toMatchObject({
				status: HttpStatus.CONFLICT,
				message: expect.stringContaining("service-C"),
			});
			expect(fetchMock).not.toHaveBeenCalled();

			// The org must still exist – refusal must not have deleted it.
			const stillThere = await service.getOrgPolicy("org-acme");
			expect(stillThere).toEqual({ backend: "http://org-backend:8080" });
		});
	});

	// ── organization membership on client policies (validation + merge) ─────

	describe("client policy org membership", () => {
		beforeEach(async () => {
			fetchMock.mockResolvedValue({
				ok: true,
				status: 200,
				text: async () => '{"ok":true}',
			});
			await service.updateRoutes(SAMPLE_ROUTES as never);
			fetchMock.mockClear();
		});

		it("updateClientPolicy rejects a policy referencing a nonexistent org with 400", async () => {
			await expect(
				service.updateClientPolicy("service-C", {
					org: "no-such-org",
				} as never)
			).rejects.toMatchObject({ status: HttpStatus.BAD_REQUEST });
			expect(fetchMock).not.toHaveBeenCalled();
		});

		it("resolves org defaults into a member client's effective policy, with the client's own fields winning per-field", async () => {
			await service.updateOrgPolicy("org-acme", {
				backend: "http://org-default-backend:8080",
				rate_limit: { rps: 10, burst: 20 },
				description: "ACME org default",
			} as never);
			fetchMock.mockClear();

			await service.updateClientPolicy("service-C", {
				org: "org-acme",
				backend: "http://client-own-backend:9090",
			} as never);

			// The pushed (gateway-facing) document is fully resolved: client's
			// own backend wins, org's rate_limit/description fill the rest.
			const pushedBody = JSON.parse(
				(fetchMock.mock.calls[0][1] as { body: string }).body
			);
			expect(pushedBody.clients["service-C"]).toMatchObject({
				org: "org-acme",
				backend: "http://client-own-backend:9090",
				rate_limit: { rps: 10, burst: 20 },
				description: "ACME org default",
			});

			// A fresh (non-cached) getRoutes() read resolves the same way.
			const routes = await service.getRoutes();
			expect(routes.clients["service-C"]).toMatchObject({
				backend: "http://client-own-backend:9090",
				rate_limit: { rps: 10, burst: 20 },
				description: "ACME org default",
			});

			// The raw stored client record keeps only what was actually set –
			// org merging is re-derived on read, not baked into storage.
			const stored = await service.getClientPolicy("service-C");
			expect(stored).toEqual({
				org: "org-acme",
				backend: "http://client-own-backend:9090",
			});
		});

		it("other org members without their own override still get the org's default for that field", async () => {
			await service.updateOrgPolicy("org-acme", {
				rate_limit: { rps: 10, burst: 20 },
			} as never);
			await service.updateClientPolicy("service-C", {
				org: "org-acme",
				rate_limit: { rps: 42, burst: 84 },
			} as never);
			await service.updateClientPolicy("service-D", {
				org: "org-acme",
			} as never);

			const routes = await service.getRoutes();
			expect(routes.clients["service-C"].rate_limit).toEqual({
				rps: 42,
				burst: 84,
			});
			expect(routes.clients["service-D"].rate_limit).toEqual({
				rps: 10,
				burst: 20,
			});
		});

		it("updateOrgPolicy re-pushes the gateway with every member client's newly resolved policy, not just the org key", async () => {
			await service.updateOrgPolicy("org-acme", {
				rate_limit: { rps: 10, burst: 20 },
			} as never);
			await service.updateClientPolicy("service-C", {
				org: "org-acme",
			} as never);
			fetchMock.mockClear();

			await service.updateOrgPolicy("org-acme", {
				rate_limit: { rps: 99, burst: 199 },
			} as never);

			expect(fetchMock).toHaveBeenCalledTimes(1);
			const pushedBody = JSON.parse(
				(fetchMock.mock.calls[0][1] as { body: string }).body
			);
			expect(pushedBody.clients["service-C"].rate_limit).toEqual({
				rps: 99,
				burst: 199,
			});

			const routes = await service.getRoutes();
			expect(routes.clients["service-C"].rate_limit).toEqual({
				rps: 99,
				burst: 199,
			});
		});

		it("dryRunRoutes shows a member client as changed when its org's defaults moved (no separate org-diff category)", async () => {
			await service.updateOrgPolicy("org-acme", {
				rate_limit: { rps: 10, burst: 20 },
			} as never);
			await service.updateClientPolicy("service-C", {
				org: "org-acme",
			} as never);

			const snapshotBeforeOrgChange = JSON.parse(
				JSON.stringify(await service.getRoutes())
			);

			await service.updateOrgPolicy("org-acme", {
				rate_limit: { rps: 999, burst: 1999 },
			} as never);

			const result = await service.dryRunRoutes(snapshotBeforeOrgChange);
			expect(result.diff.changedClients).toContain("service-C");
		});
	});
});
