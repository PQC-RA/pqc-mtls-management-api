/**
 * Sanitization helpers for the admin-action audit log.
 *
 * The audit log must NEVER contain private key material, full enrollment
 * tokens, or full JWTs. These helpers redact such values before persistence.
 */

/** Keys whose values must always be fully redacted. */
const FULLY_REDACT = /(?:private|secret|password|passphrase|csr|key|jwt)/i;

/** Keys that carry a token whose value is reduced to a non-secret id/prefix. */
const TOKEN_KEYS = /(?:^token$|enrollmenttoken|bearer|authorization)/i;

/**
 * Reduce a token to a non-secret, stable identifier: its prefix only.
 * `enroll_abc123def456...` → `enroll_abc123...`. Safe to log for correlation.
 */
export function tokenId(token: unknown): string {
	if (typeof token !== "string" || token.length === 0) return "";
	const prefix = token.slice(0, 14);
	return token.length > 14 ? `${prefix}...` : prefix;
}

/**
 * Recursively sanitize an arbitrary params object for audit logging.
 *  - private/secret/key/csr/jwt fields → "[REDACTED]"
 *  - token-bearing fields → truncated to a prefix id
 *  - long strings (> 256 chars, e.g. PEM blobs) → replaced with a length marker
 */
export function sanitizeParams(input: unknown, depth = 0): unknown {
	if (depth > 6) return "[...]";

	if (typeof input === "string") {
		return input.length > 256 ? `<string:${input.length} chars>` : input;
	}
	if (input === null || typeof input !== "object") {
		return input;
	}
	if (Array.isArray(input)) {
		return input.slice(0, 50).map(v => sanitizeParams(v, depth + 1));
	}

	const out: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(
		input as Record<string, unknown>
	)) {
		if (FULLY_REDACT.test(key)) {
			out[key] = "[REDACTED]";
		} else if (TOKEN_KEYS.test(key)) {
			out[key] = tokenId(value);
		} else {
			out[key] = sanitizeParams(value, depth + 1);
		}
	}
	return out;
}
