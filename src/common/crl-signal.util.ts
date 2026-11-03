import { execFile } from "child_process";
import * as fs from "fs";
import { promisify } from "util";

import { Logger } from "@nestjs/common";

import type { CustodianRevokeResult } from "@/common/ca-custodian.util";
import { PKI_CONFIG } from "@/common/config/pki.config";

const execFileAsync = promisify(execFile);

export type CrlRegenMode = "signaled" | "regenerated";
export type CrlAfterRevocation = CrlRegenMode | "published" | "pending";

/**
 * After one or more revocations: who makes the CRL that carries them.
 *
 * ADR-024: when the custodian issues CRLs itself, its revoke answer says so
 * ("published", or "pending" while it retries), and nothing more is done here;
 * there is no sentinel to touch. When an answer carries no CRL status, the
 * custodian is not the CRL issuer (the renewer still is) and the existing path
 * runs. Decided per answer, not by a setting, so management-api is right in
 * either order of the migration and a mismatch cannot silently skip a CRL.
 */
export async function crlAfterRevocation(
	logger: Logger,
	results: CustodianRevokeResult[]
): Promise<CrlAfterRevocation> {
	if (results.length > 0 && results.every(r => r.crl !== undefined)) {
		const pending = results.some(r => r.crl === "pending");
		if (pending) {
			logger.warn(
				"Revocation recorded, but the custodian has not published its CRL yet; it keeps retrying"
			);
		}
		return pending ? "pending" : "published";
	}
	return triggerCrlRegeneration(logger);
}

/**
 * Propagate CA-database changes (a revocation, or a forced renewal) into a fresh
 * CRL – the single source of truth for how the control plane regenerates CRLs.
 *
 * Production (least privilege): when CRL_RENEW_SIGNAL_FILE is configured, merely
 * touch a sentinel on a shared volume. The dedicated crl-renewer container – the
 * ONLY component holding broad CA write access and the nginx-reload path –
 * regenerates and publishes the CRL. This is what lets the web-facing API worker
 * run unprivileged with a writable surface reduced to the CA database (db/) and
 * issued/ directories, and the signing key mounted read-only.
 *
 * Development / single-container: with no sentinel configured, regenerate
 * in-process by invoking the renew script directly.
 *
 * Read live from process.env so deployment mode is configurable without a
 * rebuild (and unit-testable without module re-import).
 */
export async function triggerCrlRegeneration(
	logger: Logger
): Promise<CrlRegenMode> {
	const signalFile =
		process.env.CRL_RENEW_SIGNAL_FILE ?? PKI_CONFIG.crlRenewSignalFile;

	if (signalFile) {
		// The DB change already succeeded and the gateway also enforces revocation
		// from its own CRL poller, so a failed signal is an operational alert – not
		// a reason to report the operation itself as failed.
		try {
			fs.writeFileSync(
				signalFile,
				`${new Date().toISOString()} renew\n`,
				{ flag: "w" }
			);
		} catch (err) {
			logger.error(
				`CA database updated, but failed to signal the CRL renewer at ` +
					`${signalFile}: ${(err as Error).message}. The periodic renewer ` +
					`will still pick it up; run pqc-crl-renew.sh manually to refresh now.`
			);
		}
		return "signaled";
	}

	// Dev fallback: regenerate in-process (requires broad CA write access).
	await execFileAsync("/bin/bash", [PKI_CONFIG.crlRenewScript]);
	return "regenerated";
}
