import * as crypto from "crypto";
import * as http from "http";
import * as https from "https";

import {
	AdminJwtError,
	AdminKid,
	assertKeyMatchesSpec,
	decodeCanonicalB64url,
	KID_TABLE,
	MLDSA65_PUB_LENGTH,
	MLDSA65_SPKI_PREFIX,
} from "@/common/auth/admin-jwt.verifier";
import {
	gatewayLeafCheck,
	SUPPORTED_LEAF_ALGS,
} from "@/common/auth/gateway-tls";
import {
	isJsonObject,
	JsonValue,
	parseStrictJson,
} from "@/common/auth/strict-json";

/**
 * Admin verification keys from the gateway's JWKS (ADR-022 decision 2).
 *
 * Only the kids of the fixed table that the API is configured to accept are
 * read; every other entry (backend-v1, lookup-v1, ...) is ignored here. For each
 * accepted kid the JWKS must hold exactly ONE entry whose kty and alg equal the
 * table's, without private members. admin-v2 additionally needs a raw `pub` of
 * exactly 1,952 bytes whose SHA-256 equals ADMIN_V2_PUB_SHA256 from the API's
 * own configuration, so a JWKS served by anyone who can impersonate the
 * gateway's :8081 cannot substitute the admin key.
 *
 * A broken entry disables only its own kid; the error is kept for the log.
 */

export const MAX_JWKS_BYTES = 64 * 1024;
const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"];

export type JwksFetcher = (uri: string, maxBytes: number) => Promise<string>;

export interface AdminKeyStoreOptions {
	jwksUri: string;
	acceptedKids: ReadonlySet<AdminKid>;
	/** SHA-256 of the admin-v2 raw public key, 32 bytes. Required for admin-v2. */
	v2PubSha256?: Buffer;
	fetchJwks?: JwksFetcher;
	ttlMs?: number;
	minRefetchMs?: number;
	now?: () => number;
}

export interface BuiltKeys {
	keys: Map<AdminKid, crypto.KeyObject>;
	errors: Map<AdminKid, string>;
}

export function parsePubPin(v: string | undefined): Buffer | undefined {
	if (!v) return undefined;
	const hex = v.trim().toLowerCase();
	if (!/^[0-9a-f]{64}$/.test(hex)) return undefined;
	return Buffer.from(hex, "hex");
}

/** Builds the admin key table from a JWKS body. Throws only if the whole body is unusable. */
export function buildAdminKeys(
	body: string,
	acceptedKids: ReadonlySet<AdminKid>,
	v2PubSha256?: Buffer
): BuiltKeys {
	if (Buffer.byteLength(body, "utf8") > MAX_JWKS_BYTES) {
		throw new AdminJwtError("jwks_oversized");
	}
	let doc: JsonValue;
	try {
		doc = parseStrictJson(body);
	} catch (e) {
		throw new AdminJwtError("jwks_json", `JWKS: ${(e as Error).message}`);
	}
	if (!isJsonObject(doc) || !Array.isArray(doc.keys)) {
		throw new AdminJwtError("jwks_json", "JWKS: no keys array");
	}
	const entries = doc.keys;
	const keys = new Map<AdminKid, crypto.KeyObject>();
	const errors = new Map<AdminKid, string>();

	for (const kid of acceptedKids) {
		const spec = KID_TABLE[kid];
		const found = entries.filter(
			(e): e is { [key: string]: JsonValue } =>
				isJsonObject(e) && e.kid === kid
		);
		try {
			if (found.length === 0) throw new Error("no entry");
			if (found.length > 1) throw new Error("duplicate kid");
			const e = found[0];
			if (e.kty !== spec.kty) throw new Error(`kty is not ${spec.kty}`);
			if (e.alg !== spec.alg) throw new Error(`alg is not ${spec.alg}`);
			if (e.use !== undefined && e.use !== "sig")
				throw new Error("use is not sig");
			if (PRIVATE_MEMBERS.some(m => m in e)) {
				throw new Error("entry carries private key members");
			}
			let key: crypto.KeyObject;
			if (spec.kty === "RSA") {
				if (typeof e.n !== "string" || typeof e.e !== "string") {
					throw new Error("n/e missing");
				}
				decodeCanonicalB64url(e.n, "n");
				decodeCanonicalB64url(e.e, "e");
				key = crypto.createPublicKey({
					key: { kty: "RSA", n: e.n, e: e.e },
					format: "jwk",
				});
				assertKeyMatchesSpec(key, spec);
			} else {
				if (typeof e.pub !== "string") throw new Error("pub missing");
				const pub = decodeCanonicalB64url(e.pub, "pub");
				if (pub.length !== MLDSA65_PUB_LENGTH) {
					throw new Error(
						`pub is ${pub.length} bytes, not ${MLDSA65_PUB_LENGTH}`
					);
				}
				if (!v2PubSha256 || v2PubSha256.length !== 32) {
					throw new Error("no ADMIN_V2_PUB_SHA256 pin configured");
				}
				const h = crypto.createHash("sha256").update(pub).digest();
				if (!crypto.timingSafeEqual(h, v2PubSha256)) {
					throw new Error("pub does not match the pinned SHA-256");
				}
				const spki = Buffer.concat([MLDSA65_SPKI_PREFIX, pub]);
				key = crypto.createPublicKey({
					key: spki,
					format: "der",
					type: "spki",
				});
				assertKeyMatchesSpec(key, spec, spki);
			}
			keys.set(kid, key);
		} catch (err) {
			errors.set(kid, (err as Error).message);
		}
	}
	return { keys, errors };
}

export interface JwksFetchOptions {
	/**
	 * "ML-DSA-65": the :8081 server certificate must carry an ML-DSA-65 key
	 * (GATEWAY_TLS_LEAF_ALG). Chain validation alone accepts any leaf the pinned
	 * internal CA signed, an RSA one included; this closes that.
	 */
	leafAlg?: string;
	/** Trust anchors replacing Node's (tests). Production: NODE_EXTRA_CA_CERTS. */
	ca?: string | Buffer;
}

/** GET with a timeout and a hard body cap; http or https (NODE_EXTRA_CA_CERTS applies). */
export function makeJwksFetcher(fo: JwksFetchOptions = {}): JwksFetcher {
	return (uri, maxBytes) =>
		new Promise((resolve, reject) => {
			const isHttps = uri.startsWith("https://");
			const options: https.RequestOptions = { timeout: 5_000 };
			if (isHttps) {
				if (fo.ca) options.ca = fo.ca;
				if (fo.leafAlg) {
					if (!SUPPORTED_LEAF_ALGS.includes(fo.leafAlg)) {
						reject(
							new Error(
								`unsupported GATEWAY_TLS_LEAF_ALG ${fo.leafAlg}`
							)
						);
						return;
					}
					options.checkServerIdentity = gatewayLeafCheck(fo.leafAlg);
				}
			} else if (fo.leafAlg) {
				reject(
					new Error(
						"GATEWAY_TLS_LEAF_ALG is set but the JWKS URI is not https"
					)
				);
				return;
			}
			const client = isHttps ? https : http;
			const req = client.get(uri, options, res => {
				if (res.statusCode !== 200) {
					res.resume();
					reject(new Error(`JWKS HTTP ${res.statusCode}`));
					return;
				}
				const chunks: Buffer[] = [];
				let size = 0;
				res.on("data", (c: Buffer) => {
					size += c.length;
					if (size > maxBytes) {
						req.destroy(new Error("JWKS body over the size cap"));
						return;
					}
					chunks.push(c);
				});
				res.on("end", () =>
					resolve(Buffer.concat(chunks).toString("utf8"))
				);
				res.on("error", reject);
			});
			req.on("timeout", () =>
				req.destroy(new Error("JWKS fetch timed out"))
			);
			req.on("error", reject);
		});
}

export class AdminKeyStore {
	private keys = new Map<AdminKid, crypto.KeyObject>();
	private errors = new Map<AdminKid, string>();
	private fetchedAt = 0;
	private lastAttempt = -Infinity;
	private inflight?: Promise<void>;
	private readonly fetchJwks: JwksFetcher;
	private readonly ttlMs: number;
	private readonly minRefetchMs: number;
	private readonly now: () => number;

	constructor(private readonly opts: AdminKeyStoreOptions) {
		this.fetchJwks = opts.fetchJwks ?? makeJwksFetcher();
		this.ttlMs = opts.ttlMs ?? 60 * 60 * 1000;
		this.minRefetchMs = opts.minRefetchMs ?? 10_000;
		this.now = opts.now ?? Date.now;
	}

	lastError(kid: AdminKid): string | undefined {
		return this.errors.get(kid);
	}

	async getKey(kid: AdminKid): Promise<crypto.KeyObject> {
		const t = this.now();
		const stale = this.fetchedAt === 0 || t - this.fetchedAt > this.ttlMs;
		// At most one fetch per minRefetchMs, whatever the reason: a stream of
		// tokens with an unusable kid must not turn into a stream of fetches.
		if (
			(stale || !this.keys.has(kid)) &&
			t - this.lastAttempt >= this.minRefetchMs
		) {
			await this.refresh().catch(() => undefined);
		} else if (this.inflight) {
			await this.inflight.catch(() => undefined);
		}
		const key = this.keys.get(kid);
		if (!key) {
			throw new AdminJwtError(
				"jwks",
				`no usable ${kid} key in the JWKS: ${this.errors.get(kid) ?? "not fetched"}`
			);
		}
		return key;
	}

	refresh(): Promise<void> {
		if (this.inflight) return this.inflight;
		this.lastAttempt = this.now();
		this.inflight = (async () => {
			try {
				const body = await this.fetchJwks(
					this.opts.jwksUri,
					MAX_JWKS_BYTES
				);
				const built = buildAdminKeys(
					body,
					this.opts.acceptedKids,
					this.opts.v2PubSha256
				);
				this.keys = built.keys;
				this.errors = built.errors;
				this.fetchedAt = this.now();
			} catch (e) {
				// A failed fetch keeps the keys already held (until the TTL makes
				// the next request try again); a malformed body is not a fetch
				// failure and replaces nothing either.
				for (const kid of this.opts.acceptedKids) {
					if (!this.keys.has(kid))
						this.errors.set(kid, (e as Error).message);
				}
				throw e;
			} finally {
				this.inflight = undefined;
			}
		})();
		return this.inflight;
	}
}
