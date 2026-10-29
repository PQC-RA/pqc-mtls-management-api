import * as crypto from "crypto";

import {
	isJsonObject,
	JsonValue,
	parseStrictJson,
	StrictJsonError,
} from "@/common/auth/strict-json";

/**
 * The admin token verifier of ADR-022 (decision 2), hand-rolled and narrow.
 *
 * No Node JOSE library implements RFC 9964 (ML-DSA for JOSE), and the one the
 * guard used before (jsonwebtoken + jwks-rsa) cannot carry a key-type check per
 * kid either, so the admin token is verified here, in exactly this order:
 *
 *   1. length cap, before any decoding;
 *   2. exactly three non-empty segments;
 *   3. canonical base64url only (decode, re-encode, compare);
 *   4. header and payload are JSON objects without duplicate members;
 *   5. the header has exactly alg, typ (= "JWT") and kid, all strings;
 *   6. the kid selects the algorithm from a FIXED server-side table, and the
 *      header's alg must equal the table entry exactly;
 *   7. the key for that kid (AdminKeyStore: kty/alg per table, admin-v2 pub
 *      pinned by SHA-256, no duplicate kid) and its KeyObject type checks;
 *   8. the signature (pure ML-DSA-65 with an empty context / RS256 with an
 *      explicit sha256);
 *   9. the claims (exp, exp - iat <= 60, iat <= now + 5 s, iss and aud exact
 *      strings, fpr, jti single use for 120 s, htm/htu = method and path).
 *
 * Which kids are accepted is configuration (JWT_EXPECTED_KID); what a kid MEANS
 * is not: the table below is code.
 */

export type AdminKid = "admin-v1" | "admin-v2";

export interface KidSpec {
	readonly alg: "RS256" | "ML-DSA-65";
	readonly kty: "RSA" | "AKP";
}

export const KID_TABLE: Readonly<Record<AdminKid, KidSpec>> = Object.freeze({
	"admin-v1": Object.freeze({ alg: "RS256", kty: "RSA" } as const),
	"admin-v2": Object.freeze({ alg: "ML-DSA-65", kty: "AKP" } as const),
});

export function isAdminKid(kid: string): kid is AdminKid {
	return Object.prototype.hasOwnProperty.call(KID_TABLE, kid);
}

/** An admin-v2 token is about 4.9 KB (signature alone 4,412 characters). */
export const MAX_TOKEN_LENGTH = 8192;
export const MLDSA65_PUB_LENGTH = 1952;
export const MLDSA65_SIG_LENGTH = 3309;
/** DER prefix of an ML-DSA-65 SubjectPublicKeyInfo (RFC 9881, no parameters). */
export const MLDSA65_SPKI_PREFIX = Buffer.from(
	"308207b2300b0609608648016503040312038207a100",
	"hex"
);
export const MAX_LIFETIME_S = 60;
export const IAT_SKEW_S = 5;
export const JTI_TTL_S = 120;
const JTI_RE = /^[A-Za-z0-9_-]{16,128}$/;

export class AdminJwtError extends Error {
	constructor(
		readonly reason: string,
		message?: string
	) {
		super(message ?? reason);
	}
}

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

/** Decode base64url, refusing anything that does not re-encode to itself. */
export function decodeCanonicalB64url(s: string, what: string): Buffer {
	if (!B64URL_RE.test(s) || s.length % 4 === 1) {
		throw new AdminJwtError(
			"non_canonical_b64url",
			`${what}: not base64url`
		);
	}
	const buf = Buffer.from(s, "base64url");
	if (buf.toString("base64url") !== s) {
		throw new AdminJwtError(
			"non_canonical_b64url",
			`${what}: non-canonical base64url`
		);
	}
	return buf;
}

const utf8 = new TextDecoder("utf-8", { fatal: true });

function decodeJsonObject(
	seg: string,
	what: string
): { [key: string]: JsonValue } {
	const bytes = decodeCanonicalB64url(seg, what);
	let text: string;
	try {
		text = utf8.decode(bytes);
	} catch {
		throw new AdminJwtError("bad_json", `${what}: not UTF-8`);
	}
	let v: JsonValue;
	try {
		v = parseStrictJson(text);
	} catch (e) {
		const msg = e instanceof StrictJsonError ? e.message : "parse error";
		throw new AdminJwtError("bad_json", `${what}: ${msg}`);
	}
	if (!isJsonObject(v)) {
		throw new AdminJwtError("bad_json", `${what}: not a JSON object`);
	}
	return v;
}

export interface ParsedToken {
	kid: AdminKid;
	spec: KidSpec;
	signingInput: Buffer;
	signature: Buffer;
	payload: { [key: string]: JsonValue };
}

/** Steps 1 to 6: everything that needs no key. */
export function parseAdminToken(
	token: string,
	acceptedKids: ReadonlySet<string>
): ParsedToken {
	if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH) {
		throw new AdminJwtError("too_long");
	}
	const parts = token.split(".");
	if (parts.length !== 3 || parts.some(p => p.length === 0)) {
		throw new AdminJwtError("segments");
	}
	const [h, p, s] = parts;
	const header = decodeJsonObject(h, "header");
	const payload = decodeJsonObject(p, "payload");
	const signature = decodeCanonicalB64url(s, "signature");

	const members = Object.keys(header).sort();
	if (
		members.length !== 3 ||
		members[0] !== "alg" ||
		members[1] !== "kid" ||
		members[2] !== "typ"
	) {
		throw new AdminJwtError(
			"header_members",
			`header members must be exactly alg, kid, typ (got ${members.slice(0, 8).join(",")})`
		);
	}
	const { alg, kid, typ } = header;
	if (
		typeof alg !== "string" ||
		typeof kid !== "string" ||
		typeof typ !== "string"
	) {
		throw new AdminJwtError("header_types");
	}
	if (typ !== "JWT") throw new AdminJwtError("typ");
	if (!isAdminKid(kid) || !acceptedKids.has(kid)) {
		throw new AdminJwtError("kid", `kid not accepted for admin tokens`);
	}
	const spec = KID_TABLE[kid];
	if (alg !== spec.alg) {
		throw new AdminJwtError(
			"alg",
			`alg does not match the table for ${kid}`
		);
	}
	return {
		kid,
		spec,
		signingInput: Buffer.from(`${h}.${p}`, "ascii"),
		signature,
		payload,
	};
}

/**
 * Asserts that a KeyObject really is the key type the table names. crypto.verify
 * takes its algorithm from the KeyObject, not from the token, so this is what
 * binds the table to the operation (ADR-022 review item 5).
 *
 * ML-DSA-65: Node 22 (bundled OpenSSL 3.5.x) imports and verifies ML-DSA keys
 * but reports `asymmetricKeyType` as undefined for them; 'ml-dsa-65' only
 * appears in later Node lines. The check therefore requires the KeyObject to
 * export EXACTLY the expected 1,974-byte ML-DSA-65 SPKI (OID 2.16.840.1.101.3.4.3.18,
 * the pinned pub), and accepts asymmetricKeyType 'ml-dsa-65' or undefined only.
 */
export function assertKeyMatchesSpec(
	key: crypto.KeyObject,
	spec: KidSpec,
	expectedSpki?: Buffer
): void {
	if (key.type !== "public") throw new AdminJwtError("key_type");
	if (spec.kty === "RSA") {
		if (key.asymmetricKeyType !== "rsa")
			throw new AdminJwtError("key_type");
		const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
		if (bits < 2048)
			throw new AdminJwtError("key_type", "RSA key below 2048 bits");
		return;
	}
	const t = key.asymmetricKeyType as string | undefined;
	if (t !== undefined && t !== "ml-dsa-65")
		throw new AdminJwtError("key_type");
	const spki = key.export({ format: "der", type: "spki" });
	if (
		!expectedSpki ||
		spki.length !== MLDSA65_SPKI_PREFIX.length + MLDSA65_PUB_LENGTH ||
		!spki.equals(expectedSpki)
	) {
		throw new AdminJwtError("key_type", "not the pinned ML-DSA-65 SPKI");
	}
}

/** Step 8. */
export function verifyAdminSignature(
	spec: KidSpec,
	key: crypto.KeyObject,
	signingInput: Buffer,
	signature: Buffer
): boolean {
	if (spec.alg === "ML-DSA-65") {
		if (signature.length !== MLDSA65_SIG_LENGTH) return false;
		// Pure ML-DSA, empty context (RFC 9964 section 5): Node passes no
		// context and has no pre-hash mode, so a HashML-DSA signature or one
		// over a non-empty context fails here.
		try {
			return crypto.verify(null, signingInput, key, signature);
		} catch {
			return false;
		}
	}
	const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
	if (signature.length !== Math.ceil(bits / 8)) return false;
	try {
		return crypto.verify(
			"sha256",
			signingInput,
			{ key, padding: crypto.constants.RSA_PKCS1_PADDING },
			signature
		);
	} catch {
		return false;
	}
}

export interface ClaimContext {
	now: number; // seconds
	issuer: string;
	audience: string;
	method: string;
	path: string;
	/** jti, htm and htu are required for this kid (admin-v2); optional (checked if present) otherwise. */
	requireBinding: boolean;
}

/** Step 9, except the jti cache (the caller marks it used last). */
export function checkAdminClaims(
	payload: { [key: string]: JsonValue },
	ctx: ClaimContext
): { jti?: string; exp: number; fpr: string; sub: string } {
	const { exp, iat, iss, aud, fpr, sub, jti, htm, htu } = payload;
	if (typeof exp !== "number" || !Number.isFinite(exp)) {
		throw new AdminJwtError("exp");
	}
	if (typeof iat !== "number" || !Number.isFinite(iat)) {
		throw new AdminJwtError("iat");
	}
	if (ctx.now >= exp) throw new AdminJwtError("expired", "Token expired");
	if (exp - iat > MAX_LIFETIME_S || exp <= iat) {
		throw new AdminJwtError("lifetime");
	}
	if (iat > ctx.now + IAT_SKEW_S) throw new AdminJwtError("iat_future");
	if (typeof iss !== "string" || iss !== ctx.issuer) {
		throw new AdminJwtError("iss");
	}
	if (typeof aud !== "string" || aud !== ctx.audience) {
		throw new AdminJwtError("aud");
	}
	if (typeof fpr !== "string" || fpr.length === 0) {
		throw new AdminJwtError("fpr");
	}
	if (sub !== undefined && typeof sub !== "string") {
		throw new AdminJwtError("sub");
	}
	const bound = jti !== undefined || htm !== undefined || htu !== undefined;
	if (ctx.requireBinding || bound) {
		if (typeof jti !== "string" || !JTI_RE.test(jti)) {
			throw new AdminJwtError("jti");
		}
		if (typeof htm !== "string" || htm !== ctx.method) {
			throw new AdminJwtError("htm");
		}
		if (typeof htu !== "string" || htu !== ctx.path) {
			throw new AdminJwtError("htu");
		}
	}
	return {
		jti: typeof jti === "string" ? jti : undefined,
		exp,
		fpr,
		sub: typeof sub === "string" ? sub : "",
	};
}

/**
 * Single-use cache for jti (one API instance, in memory, ADR-022 answer 3).
 * An entry lives JTI_TTL_S (120 s), twice the longest token lifetime, so a
 * token cannot outlive its entry. When the cache is full after pruning it
 * refuses (fails closed) instead of evicting live entries.
 */
export class JtiCache {
	private readonly seen = new Map<string, number>();
	private inserts = 0;

	constructor(
		private readonly ttlS = JTI_TTL_S,
		private readonly maxEntries = 100_000
	) {}

	/** Returns false if jti was already used (replay) or the cache is full. */
	useOnce(jti: string, nowS: number): boolean {
		const until = this.seen.get(jti);
		if (until !== undefined && until > nowS) return false;
		if (++this.inserts % 1024 === 0 || this.seen.size >= this.maxEntries) {
			this.prune(nowS);
		}
		if (this.seen.size >= this.maxEntries) return false;
		this.seen.set(jti, nowS + this.ttlS);
		return true;
	}

	prune(nowS: number): void {
		for (const [k, until] of this.seen) {
			if (until <= nowS) this.seen.delete(k);
		}
	}

	get size(): number {
		return this.seen.size;
	}
}
