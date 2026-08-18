import { SetMetadata } from "@nestjs/common";

export const AUDIT_ACTION_KEY = "auditAction";

/** Context passed to the target/params extractors of an @AuditAction. */
export interface AuditActionContext {
	params: Record<string, unknown>;
	query: Record<string, unknown>;
	body: Record<string, unknown>;
	/** The handler's resolved return value (undefined on error). */
	result: unknown;
}

export interface AuditActionMeta {
	/** Stable action key, e.g. "cert.revoke", "policy.update-routes". */
	action: string;
	/**
	 * Optional extractor for the human-meaningful target (serial / CN / token
	 * id). Receives request params/query/body and the handler result.
	 */
	target?: (ctx: AuditActionContext) => string | null | undefined;
	/**
	 * Optional extractor for the params to record. Defaults to a sanitized
	 * merge of route params + query string (body is NOT logged by default to
	 * avoid persisting CSRs / large documents). The returned object is itself
	 * passed through the sanitizer before persistence.
	 */
	params?: (ctx: AuditActionContext) => Record<string, unknown>;
}

/**
 * Mark a mutating route for the admin-action audit trail. The
 * AdminAuditInterceptor records an entry (actor, action, target, sanitized
 * params, result) for every annotated handler – success or failure.
 */
export const AuditAction = (meta: AuditActionMeta) =>
	SetMetadata(AUDIT_ACTION_KEY, meta);
