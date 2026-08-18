/**
 * Central PKI path configuration.
 * All hardcoded paths live here – update once and everything follows.
 */
export const PKI_CONFIG = {
	openssl: process.env.OPENSSL_BIN ?? "/opt/openssl-3.6.2/bin/openssl",

	// Internal-only pqc-pki-network address of the pqc-ca-custodian sidecar – the
	// only component with any access to the intermediate CA private key.
	// management-api holds no CA-tree mount at all; sign/revoke/index/issued
	// all go through this HTTP API instead of local `openssl ca` invocations.
	custodianUrl: process.env.CUSTODIAN_URL ?? "http://pqc-ca-custodian:8091",

	crlRenewScript:
		process.env.CRL_RENEW_SCRIPT ?? "/usr/local/bin/pqc-crl-renew.sh",

	// Least-privilege CRL regeneration. When set, the API does NOT run the CRL
	// renew script itself (which needs broad CA write access + nginx reload).
	// Instead it touches this sentinel; the dedicated crl-renewer container –
	// which legitimately holds the wide CA mount – regenerates and reloads.
	// This keeps the web-facing API worker's writable surface to db/ + issued/.
	// Leave unset for single-container/dev to regenerate in-process.
	crlRenewSignalFile: process.env.CRL_RENEW_SIGNAL_FILE ?? "",

	// Data-plane audit log, read by GET /audit and counted by the
	// audit_log_entries metric.
	//
	// Written by config/nginx/lua/enroll_audit.lua in the log phase of the public
	// /enroll endpoint, on the shared pqc-logs-audit volume, and shaped
	// (ts / event / level / client / tls / http) to be parsed by this reader.
	// Its scope is enrollment requests, not all data-plane traffic.
	auditLogPath:
		process.env.AUDIT_LOG_PATH ?? "/var/log/pqc-gw/enroll-audit.log",

	// Admin-action (control-plane mutation) audit log. MUST live on the writable
	// app volume (/var/lib/pqc-mgmt) – never under the read-only /var/log/pqc-gw
	// (the gateway's data-plane logs) or the read-only CA tree.
	adminAuditLogPath:
		process.env.ADMIN_AUDIT_LOG ?? "/var/lib/pqc-mgmt/admin-actions.log",

	// Routing document. compose sets ROUTES_FILE; this fallback applies only when
	// the service runs outside it.
	routesFilePath: process.env.ROUTES_FILE ?? "/var/lib/pqc-mgmt/routes.json",
} as const;
