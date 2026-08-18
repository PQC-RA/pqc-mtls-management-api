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
}

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
