import * as crypto from "crypto";
import * as fs from "fs";

import {
	BadGatewayException,
	HttpException,
	HttpStatus,
	Injectable,
	Logger,
	OnModuleDestroy,
	OnModuleInit,
} from "@nestjs/common";
import Redis from "ioredis";

import { PKI_CONFIG } from "@/common/config/pki.config";
import {
	ClientPolicyDto,
	OrgPolicyDto,
	PolicyDryRunResultDto,
	RoutesFileDto,
} from "@/policy/dto/routes.dto";

/**
 * Redis data model:
 *   `policy:meta`         → JSON string of { _meta, defaults, policy }
 *   `policy:client:<cn>`  → JSON string of that client's ClientPolicyDto (as
 *                           admin-set – may reference an org via `.org` but
 *                           does NOT carry the org's merged-in defaults)
 *   `policy:org:<orgId>`  → JSON string of that org's OrgPolicyDto
 *
 * getRoutes() reassembles the RoutesFileDto shape on demand from these keys
 * AND resolves each client's effective policy by merging in its org's
 * defaults (client-set fields win); that resolved shape is what gets cached
 * and pushed to the gateway. getClientPolicy()/persistClientPolicy() read and
 * write the raw, unresolved per-client record directly – resolution happens
 * exactly once, in getRoutes().
 */
const META_KEY = "policy:meta";
const CLIENT_KEY_PREFIX = "policy:client:";
const ORG_KEY_PREFIX = "policy:org:";

type RoutesMeta = Omit<RoutesFileDto, "clients">;

@Injectable()
export class PolicyService implements OnModuleInit, OnModuleDestroy {
	private readonly logger = new Logger(PolicyService.name);
	private readonly routesFilePath = PKI_CONFIG.routesFilePath;
	private readonly gatewayControlUrl =
		process.env.GATEWAY_CONTROL_URL ?? "http://gateway:8081/update-routes";

	private readonly redis: Redis | null = null;
	/** In-process fallback store used when REDIS_URL is not configured. */
	private readonly local = new Map<string, string>();

	private routesCache: RoutesFileDto | null = null;

	constructor() {
		// Fail fast on a malformed GATEWAY_CONTROL_URL at startup, rather than
		// only discovering it the first time a route push actually happens
		// (pushRoutesToGateway's `new URL(this.gatewayControlUrl)` would throw
		// there instead – deep into an otherwise-successful-looking request).
		try {
			new URL(this.gatewayControlUrl);
		} catch {
			throw new Error(
				`GATEWAY_CONTROL_URL is not a valid URL: "${this.gatewayControlUrl}"`
			);
		}

		const redisUrl = process.env.REDIS_URL;
		if (redisUrl) {
			this.redis = new Redis(redisUrl, {
				// Do not reconnect forever on auth failures or misconfigs.
				maxRetriesPerRequest: 3,
				enableReadyCheck: true,
			});
			this.redis.on("connect", () =>
				this.logger.log("Connected to Redis routing policy store")
			);
			this.redis.on("error", (err: Error) =>
				this.logger.error(`Redis error: ${err.message}`)
			);
		} else {
			// Fail closed in production: an in-process policy store is not durable
			// (routes vanish on restart) and not shared across replicas.
			if (process.env.NODE_ENV === "production") {
				throw new Error(
					"REDIS_URL is required in production: the in-memory routing " +
						"policy store does not provide durable, cross-instance persistence."
				);
			}
			this.logger.warn(
				"REDIS_URL not set – routing policy stored in process memory. " +
					"This is only suitable for single-instance development deployments."
			);
		}
	}

	async onModuleDestroy(): Promise<void> {
		if (this.redis) {
			await this.redis.quit();
		}
	}

	/**
	 * On startup, one-time import any legacy routes.json into Redis, then
	 * re-push the persisted routing configuration to the gateway.
	 *
	 * The gateway keeps routes only in volatile shared memory, so after a
	 * gateway restart its table is empty until something re-pushes it. This
	 * reconciliation (plus the gateway's own startup reload from its persisted
	 * file) ensures routing self-heals after a restart of either component
	 * instead of failing closed until a human intervenes. Runs in the
	 * background with retries; never blocks or crashes app startup.
	 */
	onModuleInit(): void {
		void this.initializeAndRepublish();
	}

	private async initializeAndRepublish(): Promise<void> {
		await this.importLegacyRoutesFileIfNeeded();
		await this.republishOnStartup();
	}

	private clientKey(cn: string): string {
		return `${CLIENT_KEY_PREFIX}${cn}`;
	}

	private orgKey(orgId: string): string {
		return `${ORG_KEY_PREFIX}${orgId}`;
	}

	// ── Low-level Redis access (with in-memory fallback) ────────────────────

	private async redisGet(key: string): Promise<string | null> {
		if (this.redis) {
			return this.redis.get(key);
		}
		return this.local.has(key) ? (this.local.get(key) as string) : null;
	}

	private async redisSet(key: string, value: string): Promise<void> {
		if (this.redis) {
			await this.redis.set(key, value);
			return;
		}
		this.local.set(key, value);
	}

	private async redisDel(key: string): Promise<void> {
		if (this.redis) {
			await this.redis.del(key);
			return;
		}
		this.local.delete(key);
	}

	private async redisMGet(keys: string[]): Promise<Array<string | null>> {
		if (keys.length === 0) {
			return [];
		}
		if (this.redis) {
			return this.redis.mget(...keys);
		}
		return keys.map(k =>
			this.local.has(k) ? (this.local.get(k) as string) : null
		);
	}

	/** SCAN (not KEYS) so listing client policies never blocks Redis. */
	private async scanClientKeys(): Promise<string[]> {
		if (this.redis) {
			const keys: string[] = [];
			let cursor = "0";
			do {
				const [nextCursor, batch] = await this.redis.scan(
					cursor,
					"MATCH",
					`${CLIENT_KEY_PREFIX}*`,
					"COUNT",
					100
				);
				cursor = nextCursor;
				keys.push(...batch);
			} while (cursor !== "0");
			return keys;
		}
		return Array.from(this.local.keys()).filter(k =>
			k.startsWith(CLIENT_KEY_PREFIX)
		);
	}

	/** SCAN (not KEYS) so listing org policies never blocks Redis. */
	private async scanOrgKeys(): Promise<string[]> {
		if (this.redis) {
			const keys: string[] = [];
			let cursor = "0";
			do {
				const [nextCursor, batch] = await this.redis.scan(
					cursor,
					"MATCH",
					`${ORG_KEY_PREFIX}*`,
					"COUNT",
					100
				);
				cursor = nextCursor;
				keys.push(...batch);
			} while (cursor !== "0");
			return keys;
		}
		return Array.from(this.local.keys()).filter(k =>
			k.startsWith(ORG_KEY_PREFIX)
		);
	}

	private async hasPersistedState(): Promise<boolean> {
		return (await this.redisGet(META_KEY)) !== null;
	}

	/**
	 * Bulk-replace the meta key and every client key. Used by updateRoutes()
	 * (full-document editor) and the one-time legacy import. Wrapped in a
	 * Redis MULTI/EXEC so the multi-key write is atomic. Mirrors the previous
	 * persistRoutes()-to-disk step: failures are logged, not thrown, since a
	 * push that already reached the gateway should still be reported success.
	 */
	private async writeRoutesToRedis(routes: RoutesFileDto): Promise<void> {
		try {
			const meta: RoutesMeta = {
				_meta: routes._meta,
				defaults: routes.defaults,
				policy: routes.policy,
			};
			const clientEntries = Object.entries(routes.clients ?? {});

			if (this.redis) {
				const existingKeys = await this.scanClientKeys();
				const newKeySet = new Set(
					clientEntries.map(([cn]) => this.clientKey(cn))
				);
				const staleKeys = existingKeys.filter(k => !newKeySet.has(k));

				const multi = this.redis.multi();
				multi.set(META_KEY, JSON.stringify(meta));
				for (const key of staleKeys) {
					multi.del(key);
				}
				for (const [cn, policy] of clientEntries) {
					multi.set(this.clientKey(cn), JSON.stringify(policy));
				}
				await multi.exec();
			} else {
				for (const key of Array.from(this.local.keys())) {
					if (key.startsWith(CLIENT_KEY_PREFIX)) {
						this.local.delete(key);
					}
				}
				this.local.set(META_KEY, JSON.stringify(meta));
				for (const [cn, policy] of clientEntries) {
					this.local.set(this.clientKey(cn), JSON.stringify(policy));
				}
			}
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			this.logger.error(`Failed to persist routes to Redis: ${msg}`);
		}
	}

	private async persistClientPolicy(
		cn: string,
		policy: ClientPolicyDto
	): Promise<void> {
		try {
			await this.redisSet(this.clientKey(cn), JSON.stringify(policy));
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			this.logger.error(
				`Failed to persist client policy for CN '${cn}' to Redis: ${msg}`
			);
		}
	}

	private async removeClientPolicyKey(cn: string): Promise<void> {
		try {
			await this.redisDel(this.clientKey(cn));
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			this.logger.error(
				`Failed to delete client policy for CN '${cn}' from Redis: ${msg}`
			);
		}
	}

	private async persistOrgPolicy(
		orgId: string,
		policy: OrgPolicyDto
	): Promise<void> {
		try {
			await this.redisSet(this.orgKey(orgId), JSON.stringify(policy));
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			this.logger.error(
				`Failed to persist org policy for org '${orgId}' to Redis: ${msg}`
			);
		}
	}

	private async getOrgPolicyRaw(orgId: string): Promise<OrgPolicyDto | null> {
		const raw = await this.redisGet(this.orgKey(orgId));
		return raw === null ? null : (JSON.parse(raw) as OrgPolicyDto);
	}

	/**
	 * Merge an org's defaults into a client's own (raw, admin-set) policy.
	 * The client's own value wins per-field; `org` and `routes` are never
	 * inherited from the org (an org has neither field).
	 */
	private mergeOrgIntoClientPolicy(
		policy: ClientPolicyDto,
		org: OrgPolicyDto | null
	): ClientPolicyDto {
		if (!org) {
			return policy;
		}
		return {
			...policy,
			backend: policy.backend ?? org.backend,
			rate_limit: policy.rate_limit ?? org.rate_limit,
			allowed_paths: policy.allowed_paths ?? org.allowed_paths,
			description: policy.description ?? org.description,
		};
	}

	/** Raw (unresolved) client records straight off `policy:client:*`. */
	private async fetchRawClients(): Promise<Record<string, ClientPolicyDto>> {
		const clientKeys = await this.scanClientKeys();
		const clientValues = await this.redisMGet(clientKeys);

		const rawClients: Record<string, ClientPolicyDto> = {};
		clientKeys.forEach((key, i) => {
			const raw = clientValues[i];
			if (raw === null) {
				return;
			}
			const cn = key.slice(CLIENT_KEY_PREFIX.length);
			rawClients[cn] = JSON.parse(raw) as ClientPolicyDto;
		});
		return rawClients;
	}

	/**
	 * Resolve every client's effective policy by merging in its org's
	 * defaults. `orgOverrides` lets a caller (updateOrgPolicy) inject an
	 * org policy that hasn't been persisted to Redis yet, so the resolved
	 * push it computes reflects the candidate write before committing it.
	 */
	private async resolveClients(
		clients: Record<string, ClientPolicyDto>,
		orgOverrides?: Record<string, OrgPolicyDto>
	): Promise<Record<string, ClientPolicyDto>> {
		const orgIds = Array.from(
			new Set(
				Object.values(clients)
					.map(c => c.org)
					.filter((org): org is string => !!org)
			)
		);

		const orgMap = new Map<string, OrgPolicyDto>();
		const idsToFetch = orgIds.filter(id => !orgOverrides?.[id]);
		if (idsToFetch.length > 0) {
			const orgValues = await this.redisMGet(
				idsToFetch.map(id => this.orgKey(id))
			);
			idsToFetch.forEach((id, i) => {
				const raw = orgValues[i];
				if (raw !== null) {
					orgMap.set(id, JSON.parse(raw) as OrgPolicyDto);
				}
			});
		}
		for (const [id, org] of Object.entries(orgOverrides ?? {})) {
			orgMap.set(id, org);
		}

		const resolved: Record<string, ClientPolicyDto> = {};
		for (const [cn, policy] of Object.entries(clients)) {
			const org = policy.org ? (orgMap.get(policy.org) ?? null) : null;
			resolved[cn] = this.mergeOrgIntoClientPolicy(policy, org);
		}
		return resolved;
	}

	/**
	 * On first-ever startup after this migration, import the legacy
	 * routes.json (if present) into Redis so the transition doesn't silently
	 * drop the currently-live routing config. No-op once `policy:meta` exists.
	 */
	private async importLegacyRoutesFileIfNeeded(): Promise<void> {
		if (await this.hasPersistedState()) {
			return;
		}

		if (!fs.existsSync(this.routesFilePath)) {
			return;
		}

		this.logger.log(
			`No routing policy found in Redis; found legacy routes file at ` +
				`${this.routesFilePath} – running one-time import into Redis`
		);

		let legacy: RoutesFileDto;
		try {
			const content = fs.readFileSync(this.routesFilePath, "utf8");
			legacy = JSON.parse(content) as RoutesFileDto;
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			this.logger.error(
				`One-time legacy routes import failed to read/parse ${this.routesFilePath}: ${msg}`
			);
			return;
		}

		await this.writeRoutesToRedis(legacy);

		if (await this.hasPersistedState()) {
			const clientCns = Object.keys(legacy.clients ?? {});
			this.logger.log(
				`One-time import complete: migrated legacy routes file into Redis ` +
					`(${clientCns.length} client${clientCns.length === 1 ? "" : "s"}` +
					`${clientCns.length > 0 ? ": " + clientCns.join(", ") : ""})`
			);
		} else {
			this.logger.error(
				"One-time legacy routes import did not persist to Redis – see prior error"
			);
		}
	}

	private async republishOnStartup(): Promise<void> {
		// Only republish when we hold genuinely persisted state. If Redis has
		// no routing policy yet, getRoutes() would synthesise an empty default
		// set – pushing that to the gateway would WIPE its live routing table
		// (which it has already reloaded from its own persisted volume), turning
		// a restart into an outage. The gateway self-heals from its own store,
		// so when we have nothing authoritative to contribute we must stay silent.
		if (!(await this.hasPersistedState())) {
			this.logger.warn(
				`No routing policy persisted in Redis; skipping startup republish ` +
					`so the gateway keeps the routes it reloaded from its own store`
			);
			return;
		}

		let routes: RoutesFileDto;
		try {
			routes = await this.getRoutes();
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			this.logger.error(`Startup route reconciliation skipped: ${msg}`);
			return;
		}

		const maxAttempts = 10;
		for (let attempt = 1; attempt <= maxAttempts; attempt++) {
			try {
				await this.pushRoutesToGateway(routes);
				this.logger.log(
					`Startup route reconciliation succeeded (attempt ${attempt})`
				);
				return;
			} catch (e) {
				const msg = e instanceof Error ? e.message : String(e);
				const backoffMs = Math.min(1000 * attempt, 10_000);
				this.logger.warn(
					`Startup route reconciliation attempt ${attempt}/${maxAttempts} failed (${msg}); retrying in ${backoffMs}ms`
				);
				await new Promise(r => setTimeout(r, backoffMs));
			}
		}
		this.logger.error(
			"Startup route reconciliation gave up – gateway routing may be empty until the next update"
		);
	}

	private getDefaultRoutes(): RoutesFileDto {
		return {
			_meta: {
				version: "1.0.0",
				description: "PQC-GW Policy Routing Configuration",
				updated: new Date().toISOString(),
			},
			clients: {},
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
	}

	private getHmacSecret(): string {
		// Prefer Docker-secret file; fall back to env var for local dev.
		const secretFile = "/run/secrets/control-plane-hmac";
		try {
			return fs.readFileSync(secretFile, "utf8").trim();
		} catch {
			return process.env.GATEWAY_HMAC_SECRET ?? "";
		}
	}

	private async pushRoutesToGateway(routes: RoutesFileDto): Promise<void> {
		const body = JSON.stringify(routes);
		const secret = this.getHmacSecret();
		if (!secret) {
			this.logger.error(
				"control-plane-hmac secret not configured – refusing to push routes to the gateway"
			);
			throw new BadGatewayException(
				"Control-plane HMAC secret is not configured"
			);
		}

		// Replay protection: bind the HMAC to timestamp + method + path (not
		// just the body), matching control_plane.lua exactly. A captured
		// request can't be replayed later or against a different endpoint.
		const timestamp = Math.floor(Date.now() / 1000).toString();
		const method = "POST";
		const uri = new URL(this.gatewayControlUrl).pathname;
		const signedString = `${timestamp}\n${method}\n${uri}\n${body}`;
		const sig =
			"sha256=" +
			crypto
				.createHmac("sha256", secret)
				.update(signedString)
				.digest("hex");

		const response = await fetch(this.gatewayControlUrl, {
			method,
			headers: {
				"Content-Type": "application/json",
				"Accept": "application/json",
				"X-Timestamp": timestamp,
				"X-Hub-Signature-256": sig,
			},
			body,
			signal: AbortSignal.timeout(10_000),
		}).catch((error: unknown) => {
			const message =
				error instanceof Error ? error.message : String(error);
			this.logger.error(`Gateway control-plane call failed: ${message}`);
			throw new BadGatewayException(
				"Failed to contact gateway control plane"
			);
		});

		if (!response.ok) {
			const bodyText = await response.text().catch(() => "");
			this.logger.error(
				`Gateway rejected route update (${response.status}): ${bodyText}`
			);
			throw new BadGatewayException(
				`Gateway control-plane update failed with status ${response.status}`
			);
		}

		this.logger.log("Gateway control-plane route update applied");
	}

	/** Push to the gateway, mapping errors the same way for every call site. */
	private async pushOrThrow(routes: RoutesFileDto): Promise<void> {
		try {
			await this.pushRoutesToGateway(routes);
		} catch (error) {
			if (error instanceof BadGatewayException) {
				throw error;
			}
			const message =
				error instanceof Error ? error.message : String(error);
			this.logger.error(`Failed to update routes: ${message}`);
			throw new HttpException(
				"Failed to update routing configuration",
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	async getRoutes(): Promise<RoutesFileDto> {
		this.logger.log("Fetching current routing configuration");

		if (this.routesCache) {
			return this.routesCache;
		}

		const metaRaw = await this.redisGet(META_KEY);
		if (metaRaw === null) {
			this.logger.warn(
				"No routing policy found in Redis, using defaults"
			);
			this.routesCache = this.getDefaultRoutes();
			return this.routesCache;
		}

		try {
			const meta = JSON.parse(metaRaw) as RoutesMeta;
			const rawClients = await this.fetchRawClients();

			this.routesCache = {
				_meta: meta._meta,
				defaults: meta.defaults,
				policy: meta.policy,
				clients: await this.resolveClients(rawClients),
			};
			return this.routesCache;
		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			this.logger.error(
				`Error reading routing configuration from Redis: ${message}`
			);
			throw new HttpException(
				"Failed to read routing configuration",
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	async updateRoutes(routes: RoutesFileDto): Promise<{ message: string }> {
		this.logger.log("Updating routes via gateway control plane");
		await this.pushOrThrow(routes);
		// Persist so the configuration survives a restart of either the
		// management-api or the gateway.
		await this.writeRoutesToRedis(routes);
		// Invalidate rather than cache `routes` verbatim: this endpoint stores
		// each client's raw (possibly org-referencing) policy, and the cache
		// must hold the org-resolved view like every other getRoutes() read.
		this.routesCache = null;

		return {
			message: "Routes updated successfully via gateway control plane",
		};
	}

	/**
	 * Validate a candidate routing document and diff it against the active
	 * configuration WITHOUT pushing to the gateway control plane or persisting.
	 * Powers the console's confirm-before-apply step.
	 */
	async dryRunRoutes(routes: RoutesFileDto): Promise<PolicyDryRunResultDto> {
		this.logger.log("Policy dry-run: validating and diffing (no push)");

		const errors: string[] = [];
		if (!routes || typeof routes !== "object") {
			errors.push("routing document must be an object");
		} else if (routes.clients && typeof routes.clients !== "object") {
			errors.push("`clients` must be an object keyed by CN");
		}
		// Per-client structural sanity (the global ValidationPipe has already
		// enforced the DTO shape; this surfaces semantic issues to the console).
		for (const [cn, policy] of Object.entries(routes?.clients ?? {})) {
			if (!cn || cn.trim() === "") {
				errors.push("a client entry has an empty CN key");
			}
			for (const route of policy?.routes ?? []) {
				if (!route.path || !route.backend) {
					errors.push(
						`client "${cn}" has a route missing path or backend`
					);
				}
			}
		}

		// Read the active config WITHOUT mutating cache semantics.
		let active: RoutesFileDto;
		try {
			active = await this.getRoutes();
		} catch {
			active = this.getDefaultRoutes();
		}

		const oldClients = Object.keys(active.clients ?? {});
		const newClients = Object.keys(routes.clients ?? {});
		const oldSet = new Set(oldClients);
		const newSet = new Set(newClients);

		const addedClients = newClients.filter(cn => !oldSet.has(cn));
		const removedClients = oldClients.filter(cn => !newSet.has(cn));
		const changedClients = newClients.filter(
			cn =>
				oldSet.has(cn) &&
				JSON.stringify(active.clients?.[cn]) !==
					JSON.stringify(routes.clients?.[cn])
		);

		const changedGlobalFields: string[] = [];
		const compareSection = (
			section: "defaults" | "policy",
			oldObj: Record<string, unknown> | undefined,
			newObj: Record<string, unknown> | undefined
		) => {
			const keys = new Set([
				...Object.keys(oldObj ?? {}),
				...Object.keys(newObj ?? {}),
			]);
			for (const k of keys) {
				if (
					JSON.stringify(oldObj?.[k]) !== JSON.stringify(newObj?.[k])
				) {
					changedGlobalFields.push(`${section}.${k}`);
				}
			}
		};
		compareSection(
			"defaults",
			active.defaults as unknown as Record<string, unknown>,
			routes.defaults as unknown as Record<string, unknown>
		);
		compareSection(
			"policy",
			active.policy as unknown as Record<string, unknown>,
			routes.policy as unknown as Record<string, unknown>
		);

		return {
			valid: errors.length === 0,
			errors,
			diff: {
				addedClients,
				removedClients,
				changedClients,
				changedGlobalFields,
			},
		};
	}

	async getClientPolicy(cn: string): Promise<ClientPolicyDto> {
		this.logger.log(`Fetching route config for CN: ${cn}`);
		const raw = await this.redisGet(this.clientKey(cn));

		if (raw === null) {
			throw new HttpException(
				`Policy for CN '${cn}' not found`,
				HttpStatus.NOT_FOUND
			);
		}

		return JSON.parse(raw) as ClientPolicyDto;
	}

	async updateClientPolicy(
		cn: string,
		policy: ClientPolicyDto
	): Promise<{ cn: string; policy: ClientPolicyDto }> {
		this.logger.log(`Updating route config for CN: ${cn}`);

		let org: OrgPolicyDto | null = null;
		if (policy.org) {
			org = await this.getOrgPolicyRaw(policy.org);
			if (org === null) {
				throw new HttpException(
					`Organization '${policy.org}' not found`,
					HttpStatus.BAD_REQUEST
				);
			}
		}

		const routes = await this.getRoutes();
		const resolvedPolicy = this.mergeOrgIntoClientPolicy(policy, org);
		const candidateRoutes: RoutesFileDto = {
			...routes,
			clients: { ...(routes.clients ?? {}), [cn]: resolvedPolicy },
		};

		await this.pushOrThrow(candidateRoutes);
		// Persist the raw (unresolved) policy – org merging is re-derived by
		// getRoutes() on every read, not baked into the stored record.
		await this.persistClientPolicy(cn, policy);
		this.routesCache = candidateRoutes;

		return { cn, policy };
	}

	async deleteClientPolicy(cn: string): Promise<{ message: string }> {
		this.logger.log(`Deleting route config for CN: ${cn}`);
		const routes = await this.getRoutes();

		if (!routes.clients || !routes.clients[cn]) {
			throw new HttpException(
				`Policy for CN '${cn}' not found`,
				HttpStatus.NOT_FOUND
			);
		}

		const remainingClients = { ...routes.clients };
		delete remainingClients[cn];
		const candidateRoutes: RoutesFileDto = {
			...routes,
			clients: remainingClients,
		};

		await this.pushOrThrow(candidateRoutes);
		await this.removeClientPolicyKey(cn);
		this.routesCache = candidateRoutes;

		return {
			message: `Policy for CN '${cn}' deleted successfully`,
		};
	}

	// ── Organization CRUD (org-level defaults, merged into member clients) ──

	async listOrgs(): Promise<Record<string, OrgPolicyDto>> {
		this.logger.log("Listing all organizations");
		const orgKeys = await this.scanOrgKeys();
		const orgValues = await this.redisMGet(orgKeys);

		const orgs: Record<string, OrgPolicyDto> = {};
		orgKeys.forEach((key, i) => {
			const raw = orgValues[i];
			if (raw === null) {
				return;
			}
			const orgId = key.slice(ORG_KEY_PREFIX.length);
			orgs[orgId] = JSON.parse(raw) as OrgPolicyDto;
		});
		return orgs;
	}

	async getOrgPolicy(orgId: string): Promise<OrgPolicyDto> {
		this.logger.log(`Fetching org policy for org: ${orgId}`);
		const org = await this.getOrgPolicyRaw(orgId);

		if (org === null) {
			throw new HttpException(
				`Organization '${orgId}' not found`,
				HttpStatus.NOT_FOUND
			);
		}

		return org;
	}

	/**
	 * Create or replace an org's defaults, then re-push the full resolved
	 * routing document to the gateway – changing org defaults changes every
	 * member client's effective policy, so a silent key write is not enough.
	 * Push-then-persist, same as updateClientPolicy: the candidate org policy
	 * is resolved into every member client and pushed BEFORE anything is
	 * written to Redis, so a failed push leaves Redis untouched.
	 */
	async updateOrgPolicy(
		orgId: string,
		policy: OrgPolicyDto
	): Promise<{ orgId: string; policy: OrgPolicyDto }> {
		this.logger.log(`Updating org policy for org: ${orgId}`);

		const routes = await this.getRoutes();
		const rawClients = await this.fetchRawClients();
		const resolvedClients = await this.resolveClients(rawClients, {
			[orgId]: policy,
		});
		const candidateRoutes: RoutesFileDto = {
			...routes,
			clients: resolvedClients,
		};

		await this.pushOrThrow(candidateRoutes);
		await this.persistOrgPolicy(orgId, policy);
		this.routesCache = candidateRoutes;

		return { orgId, policy };
	}

	async deleteOrgPolicy(orgId: string): Promise<{ message: string }> {
		this.logger.log(`Deleting org policy for org: ${orgId}`);
		const org = await this.getOrgPolicyRaw(orgId);
		if (org === null) {
			throw new HttpException(
				`Organization '${orgId}' not found`,
				HttpStatus.NOT_FOUND
			);
		}

		const routes = await this.getRoutes();
		const referencingCns = Object.entries(routes.clients ?? {})
			.filter(([, clientPolicy]) => clientPolicy.org === orgId)
			.map(([cn]) => cn);
		if (referencingCns.length > 0) {
			throw new HttpException(
				`Cannot delete organization '${orgId}': still referenced by ` +
					`client(s) ${referencingCns.join(", ")}. Reassign or clear ` +
					`their 'org' field first.`,
				HttpStatus.CONFLICT
			);
		}

		// The 409 guard above already proved no client references this org, so
		// the resolved routing document is unchanged by removing it – push the
		// already-fetched `routes` to confirm the gateway is reachable BEFORE
		// committing the deletion (push-then-persist, same as updateClientPolicy).
		await this.pushOrThrow(routes);
		await this.redisDel(this.orgKey(orgId));
		this.routesCache = routes;

		return { message: `Organization '${orgId}' deleted successfully` };
	}
}
