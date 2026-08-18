import * as fs from "fs";

import { Logger } from "@nestjs/common";

/**
 * Server-side certificate → role mapping.
 *
 * Authorization roles are derived from the caller's certificate SHA-256
 * fingerprint against operator-controlled allowlists – NEVER from a
 * requester-influenceable JWT claim (role / OU). Two roles exist:
 *
 *   - `admin`   (ADMIN_CERT_FINGERPRINTS)   – read + write (all routes)
 *   - `auditor` (AUDITOR_CERT_FINGERPRINTS) – read-only (GET routes only)
 *
 * A fingerprint present in neither list is denied (fail-closed). If a
 * fingerprint appears in both lists, `admin` wins (the stronger grant).
 *
 * Both env vars support the Docker-secret `_FILE` convention
 * (ADMIN_CERT_FINGERPRINTS_FILE / AUDITOR_CERT_FINGERPRINTS_FILE): a mounted
 * secret file takes precedence over the inline value, so the allowlist can be
 * delivered as a secret rather than baked into the process environment.
 */

export type AdminRole = "admin" | "auditor";

/** Normalise a fingerprint to lowercase hex with no colons/whitespace. */
export function normalizeFingerprint(fp: string): string {
	return fp.replace(/[:\s]/g, "").toLowerCase();
}

/**
 * A SHA-256 certificate fingerprint is exactly 64 lowercase hex characters
 * (32 bytes). The gateway derives the `fpr` claim as SHA-256(DER), so the
 * allowlist MUST be SHA-256 too. A 40-char value is a SHA-1 fingerprint and
 * would never match, so every admin request would return 403.
 */
export const SHA256_HEX = /^[0-9a-f]{64}$/;

/**
 * Read a raw allowlist value. A mounted `_FILE` secret takes precedence over
 * the inline env var. An unreadable secret yields an empty string (deny all),
 * never a fallback that could widen access.
 */
function readFingerprintSource(
	envName: string,
	fileEnvName: string,
	logger: Logger
): string {
	const file = process.env[fileEnvName];
	if (file) {
		try {
			return fs.readFileSync(file, "utf8");
		} catch (e) {
			logger.error(
				`Could not read ${fileEnvName}=${file}: ${(e as Error).message}`
			);
			return "";
		}
	}
	return process.env[envName] ?? "";
}

/**
 * Parse an allowlist (comma/whitespace/newline-separated, with optional
 * shell-style `#` comments) into a validated Set of SHA-256 fingerprints plus
 * any rejected (wrong-length) entries for precise misconfiguration warnings.
 */
export function parseFingerprints(raw: string): {
	valid: Set<string>;
	rejected: string[];
} {
	const stripped = raw
		.split(/\r?\n/)
		.map(line => line.replace(/#.*$/, ""))
		.join("\n");
	const valid = new Set<string>();
	const rejected: string[] = [];
	const entries = stripped
		.split(/[,\s]+/)
		.map(normalizeFingerprint)
		.filter(Boolean);
	for (const entry of entries) {
		if (SHA256_HEX.test(entry)) {
			valid.add(entry);
		} else {
			rejected.push(entry);
		}
	}
	return { valid, rejected };
}

export interface CertRoleMap {
	/** Resolve the role for a (raw or normalized) fingerprint, or null if unknown. */
	resolve(fpr: string): AdminRole | null;
	adminCount: number;
	auditorCount: number;
}

/**
 * Build the certificate→role map from the environment. Reads both the admin
 * and auditor allowlists and logs precise warnings for malformed entries.
 * `admin` precedence: a fingerprint in both lists resolves to `admin`.
 */
export function buildCertRoleMap(logger: Logger): CertRoleMap {
	const admin = parseFingerprints(
		readFingerprintSource(
			"ADMIN_CERT_FINGERPRINTS",
			"ADMIN_CERT_FINGERPRINTS_FILE",
			logger
		)
	);
	const auditor = parseFingerprints(
		readFingerprintSource(
			"AUDITOR_CERT_FINGERPRINTS",
			"AUDITOR_CERT_FINGERPRINTS_FILE",
			logger
		)
	);

	for (const fp of admin.rejected) {
		logger.error(
			`Ignoring malformed ADMIN_CERT_FINGERPRINTS entry "${fp}" ` +
				`(${fp.length} hex chars). Expected a SHA-256 fingerprint ` +
				`(64 hex chars, e.g. \`openssl x509 -fingerprint -sha256\`). ` +
				(fp.length === 40
					? "This looks like a SHA-1 fingerprint – the gateway authorizes by SHA-256."
					: "")
		);
	}
	for (const fp of auditor.rejected) {
		logger.error(
			`Ignoring malformed AUDITOR_CERT_FINGERPRINTS entry "${fp}" ` +
				`(${fp.length} hex chars). Expected a SHA-256 fingerprint (64 hex chars).`
		);
	}

	const map = new Map<string, AdminRole>();
	// Auditors first, then admins overwrite – so admin wins on overlap.
	for (const fp of auditor.valid) map.set(fp, "auditor");
	for (const fp of admin.valid) map.set(fp, "admin");

	if (map.size === 0) {
		logger.error(
			"No valid SHA-256 entries in ADMIN_CERT_FINGERPRINTS or " +
				"AUDITOR_CERT_FINGERPRINTS – ALL admin requests will be denied " +
				"(fail-closed). Configure at least one admin fingerprint."
		);
	}

	return {
		resolve(fpr: string): AdminRole | null {
			return map.get(normalizeFingerprint(fpr)) ?? null;
		},
		adminCount: admin.valid.size,
		auditorCount: auditor.valid.size,
	};
}

/** The authenticated, authorized caller identity attached to the request. */
export interface AdminIdentity {
	sub: string;
	fpr: string;
	role: AdminRole;
}
