/**
 * TokenStoreService – pluggable enrollment token store.
 *
 * Behaviour:
 *   - When REDIS_URL is set, stores tokens in Redis with TTL-based expiry and
 *     an atomic Lua-script-based single-use guarantee (including CN constraint).
 *   - When REDIS_URL is absent (development / unit tests), falls back to an
 *     in-process Map with identical semantics.
 *
 * Redis data model:
 *   Key  : `pqc:enroll:{token}`  → JSON string `{expiresAt:number, allowedCn:string, usedAt?:number}`
 *   TTL  : ceil((expiresAt - now) / 1000) seconds – Redis evicts expired tokens automatically.
 *   Index: sorted set `pqc:enroll:index`, score = expiresAt (ms), member = token.
 *          Used for listing; stale members are filtered when their key is absent.
 */

import { Injectable, Logger, OnModuleDestroy } from "@nestjs/common";
import Redis from "ioredis";

export interface TokenMeta {
	expiresAt: number;
	allowedCn: string; // CSR subject CN must match this exactly before the token is consumed
	usedAt?: number;
	/** Renewal profile the certificate is issued under; absent = the legacy 365-day path. */
	profile?: "client-30d" | "demo-120s";
	/** Set while a signing is in flight: only a commit or a release clears it. */
	reservation?: { id: string; until: number };
	/** Serial of the certificate issued under this token (set on commit). */
	serial?: string;
}

export type ReserveResult =
	| { result: "ok"; reservationId: string; meta: TokenMeta }
	| { result: "in_progress" }
	| { result: "stale_reservation"; reservationId: string; meta: TokenMeta }
	| { result: "already_used"; serial?: string }
	| { result: "not_found" | "expired" | "cn_mismatch" };

export type ConsumeResult =
	| "ok"
	| "not_found"
	| "already_used"
	| "expired"
	| "cn_mismatch";

/** Lua script executed atomically on the Redis server. */
const CONSUME_SCRIPT = `
local val = redis.call('GET', KEYS[1])
if not val then return 'not_found' end
local meta = cjson.decode(val)
if meta.usedAt then return 'already_used' end
local now = tonumber(ARGV[1])
if meta.expiresAt < now then
  redis.call('DEL', KEYS[1])
  return 'expired'
end
local requestedCn = ARGV[2] or ''
if meta.allowedCn ~= requestedCn then
  return 'cn_mismatch'
end
meta.usedAt = now
local pttl = redis.call('PTTL', KEYS[1])
if pttl > 0 then
  redis.call('SET', KEYS[1], cjson.encode(meta), 'PX', pttl)
else
  redis.call('SET', KEYS[1], cjson.encode(meta))
end
return 'ok'
`;

/**
 * Reserve (item 4): the same checks as CONSUME_SCRIPT, but instead of marking
 * the token used it records a reservation with a lease. A live reservation
 * blocks a second request (in_progress); an expired one is returned as
 * stale_reservation so the caller can reconcile it with the custodian before
 * anything else happens.
 */
const RESERVE_SCRIPT = `
local val = redis.call('GET', KEYS[1])
if not val then return cjson.encode({result='not_found'}) end
local meta = cjson.decode(val)
if meta.usedAt then return cjson.encode({result='already_used', serial=meta.serial}) end
local now = tonumber(ARGV[1])
if meta.expiresAt < now and not meta.reservation then
  redis.call('DEL', KEYS[1])
  return cjson.encode({result='expired'})
end
if meta.allowedCn ~= (ARGV[2] or '') then return cjson.encode({result='cn_mismatch'}) end
if meta.reservation then
  if meta.reservation['until'] > now then return cjson.encode({result='in_progress'}) end
  return cjson.encode({result='stale_reservation', reservationId=meta.reservation.id, meta=meta})
end
meta.reservation = {id=ARGV[3], ['until']=now + tonumber(ARGV[4])}
local pttl = redis.call('PTTL', KEYS[1])
local keep = math.max(pttl, tonumber(ARGV[4]) + 600000)
redis.call('SET', KEYS[1], cjson.encode(meta), 'PX', keep)
return cjson.encode({result='ok', reservationId=ARGV[3], meta=meta})
`;

/** Commit or release, conditional on the reservation id. ARGV: id, action, serial, now. */
const SETTLE_SCRIPT = `
local val = redis.call('GET', KEYS[1])
if not val then return 'not_found' end
local meta = cjson.decode(val)
if not meta.reservation or meta.reservation.id ~= ARGV[1] then return 'not_reserved_by_caller' end
meta.reservation = nil
if ARGV[2] == 'commit' then
  meta.usedAt = tonumber(ARGV[4])
  meta.serial = ARGV[3]
end
local pttl = redis.call('PTTL', KEYS[1])
if pttl > 0 then redis.call('SET', KEYS[1], cjson.encode(meta), 'PX', pttl) else redis.call('SET', KEYS[1], cjson.encode(meta)) end
return 'ok'
`;

const KEY_PREFIX = "pqc:enroll:";
const INDEX_KEY = "pqc:enroll:index";

@Injectable()
export class TokenStoreService implements OnModuleDestroy {
	private readonly logger = new Logger(TokenStoreService.name);
	private readonly redis: Redis | null = null;

	/** In-process fallback store used when REDIS_URL is not configured. */
	private readonly local = new Map<string, TokenMeta>();

	constructor() {
		const redisUrl = process.env.REDIS_URL;
		if (redisUrl) {
			this.redis = new Redis(redisUrl, {
				// Do not reconnect forever on auth failures or misconfigs.
				maxRetriesPerRequest: 3,
				enableReadyCheck: true,
			});
			this.redis.on("connect", () =>
				this.logger.log("Connected to Redis token store")
			);
			this.redis.on("error", (err: Error) =>
				this.logger.error(`Redis error: ${err.message}`)
			);
		} else {
			// Fail closed in production: an in-process token store is not durable
			// (tokens vanish on restart) and not shared (the single-use guarantee
			// is per-instance, so a replicated deployment could consume the same
			// token once per replica). Refuse to start rather than silently ship
			// a broken single-use guarantee.
			if (process.env.NODE_ENV === "production") {
				throw new Error(
					"REDIS_URL is required in production: the in-memory enrollment " +
						"token store does not provide a durable, cross-instance single-use guarantee."
				);
			}
			this.logger.warn(
				"REDIS_URL not set – enrollment tokens stored in process memory. " +
					"This is only suitable for single-instance development deployments."
			);
		}
	}

	async onModuleDestroy(): Promise<void> {
		if (this.redis) {
			await this.redis.quit();
		}
	}

	// ── Write ────────────────────────────────────────────────────────────────

	async set(token: string, meta: TokenMeta): Promise<void> {
		if (this.redis) {
			const ttlSeconds = Math.ceil((meta.expiresAt - Date.now()) / 1000);
			const pipeline = this.redis.pipeline();
			pipeline.set(
				KEY_PREFIX + token,
				JSON.stringify(meta),
				"EX",
				Math.max(ttlSeconds, 1)
			);
			pipeline.zadd(INDEX_KEY, meta.expiresAt, token);
			await pipeline.exec();
		} else {
			this.local.set(token, meta);
		}
	}

	async delete(token: string): Promise<boolean> {
		if (this.redis) {
			const pipeline = this.redis.pipeline();
			pipeline.del(KEY_PREFIX + token);
			pipeline.zrem(INDEX_KEY, token);
			const results = await pipeline.exec();
			// First result is [err, count] from DEL; count 1 = key existed
			return results !== null && (results[0][1] as number) === 1;
		} else {
			return this.local.delete(token);
		}
	}

	// ── Read ─────────────────────────────────────────────────────────────────

	async get(token: string): Promise<TokenMeta | null> {
		if (this.redis) {
			const raw = await this.redis.get(KEY_PREFIX + token);
			return raw ? (JSON.parse(raw) as TokenMeta) : null;
		} else {
			return this.local.get(token) ?? null;
		}
	}

	/**
	 * Atomically validate CN constraint, mark token as used (single-use guarantee).
	 * cn must match token's allowedCn exactly – returns "cn_mismatch" without consuming if not.
	 * Redis path uses an eval Lua script to prevent TOCTOU races.
	 * In-process path is safe because Node.js is single-threaded.
	 */
	async consume(token: string, cn: string): Promise<ConsumeResult> {
		const now = Date.now();

		if (this.redis) {
			const result = await this.redis.eval(
				CONSUME_SCRIPT,
				1,
				KEY_PREFIX + token,
				String(now),
				cn
			);
			return result as ConsumeResult;
		} else {
			const meta = this.local.get(token);
			if (!meta) return "not_found";
			if (now > meta.expiresAt) {
				this.local.delete(token);
				return "expired";
			}
			if (meta.usedAt !== undefined) return "already_used";
			if (meta.allowedCn !== cn) return "cn_mismatch";
			meta.usedAt = now;
			return "ok";
		}
	}

	// ── Reserve then commit (item 4) ─────────────────────────────────────────

	async reserve(
		token: string,
		cn: string,
		reservationId: string,
		leaseMs: number
	): Promise<ReserveResult> {
		const now = Date.now();
		if (this.redis) {
			const raw = await this.redis.eval(
				RESERVE_SCRIPT,
				1,
				KEY_PREFIX + token,
				String(now),
				cn,
				reservationId,
				String(leaseMs)
			);
			return JSON.parse(raw as string) as ReserveResult;
		}
		const meta = this.local.get(token);
		if (!meta) return { result: "not_found" };
		if (meta.usedAt !== undefined)
			return { result: "already_used", serial: meta.serial };
		if (now > meta.expiresAt && !meta.reservation) {
			this.local.delete(token);
			return { result: "expired" };
		}
		if (meta.allowedCn !== cn) return { result: "cn_mismatch" };
		if (meta.reservation) {
			if (meta.reservation.until > now) return { result: "in_progress" };
			return {
				result: "stale_reservation",
				reservationId: meta.reservation.id,
				meta,
			};
		}
		meta.reservation = { id: reservationId, until: now + leaseMs };
		return { result: "ok", reservationId, meta };
	}

	async commit(
		token: string,
		reservationId: string,
		serial: string
	): Promise<string> {
		return this.settle(token, reservationId, "commit", serial);
	}

	async release(token: string, reservationId: string): Promise<string> {
		return this.settle(token, reservationId, "release", "");
	}

	private async settle(
		token: string,
		reservationId: string,
		action: "commit" | "release",
		serial: string
	): Promise<string> {
		const now = Date.now();
		if (this.redis) {
			return (await this.redis.eval(
				SETTLE_SCRIPT,
				1,
				KEY_PREFIX + token,
				reservationId,
				action,
				serial,
				String(now)
			)) as string;
		}
		const meta = this.local.get(token);
		if (!meta) return "not_found";
		if (!meta.reservation || meta.reservation.id !== reservationId)
			return "not_reserved_by_caller";
		delete meta.reservation;
		if (action === "commit") {
			meta.usedAt = now;
			meta.serial = serial;
		}
		return "ok";
	}

	/** Tokens whose reservation lease has passed, for the periodic reconcile. */
	async staleReservations(): Promise<
		Array<{ token: string; reservationId: string; meta: TokenMeta }>
	> {
		const now = Date.now();
		const out: Array<{
			token: string;
			reservationId: string;
			meta: TokenMeta;
		}> = [];
		if (this.redis) {
			const tokens = await this.redis.zrange(INDEX_KEY, 0, -1);
			for (const t of tokens) {
				const raw = await this.redis.get(KEY_PREFIX + t);
				if (!raw) continue;
				const meta = JSON.parse(raw) as TokenMeta;
				if (meta.reservation && meta.reservation.until <= now)
					out.push({
						token: t,
						reservationId: meta.reservation.id,
						meta,
					});
			}
			return out;
		}
		for (const [t, meta] of this.local.entries()) {
			if (meta.reservation && meta.reservation.until <= now)
				out.push({
					token: t,
					reservationId: meta.reservation.id,
					meta,
				});
		}
		return out;
	}

	// ── List ─────────────────────────────────────────────────────────────────

	async list(): Promise<
		Array<{
			token: string;
			expiresAt: number;
			allowedCn: string;
			used: boolean;
		}>
	> {
		if (this.redis) {
			const tokens = await this.redis.zrange(INDEX_KEY, 0, -1);
			if (tokens.length === 0) return [];

			// Fetch all token values in one round-trip.
			const pipeline = this.redis.pipeline();
			for (const t of tokens) pipeline.get(KEY_PREFIX + t);
			const results = await pipeline.exec();

			const entries: Array<{
				token: string;
				expiresAt: number;
				allowedCn: string;
				used: boolean;
			}> = [];

			for (let i = 0; i < tokens.length; i++) {
				const raw = results?.[i]?.[1] as string | null;
				if (!raw) continue; // expired / evicted
				const meta = JSON.parse(raw) as TokenMeta;
				entries.push({
					token: tokens[i],
					expiresAt: meta.expiresAt,
					allowedCn: meta.allowedCn,
					used: meta.usedAt !== undefined,
				});
			}

			return entries;
		} else {
			const now = Date.now();
			return Array.from(this.local.entries())
				.filter(([, m]) => m.expiresAt > now || m.usedAt !== undefined)
				.map(([token, meta]) => ({
					token,
					expiresAt: meta.expiresAt,
					allowedCn: meta.allowedCn,
					used: meta.usedAt !== undefined,
				}));
		}
	}
}
