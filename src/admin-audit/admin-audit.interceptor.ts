import {
	CallHandler,
	ExecutionContext,
	HttpException,
	HttpStatus,
	Injectable,
	NestInterceptor,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Observable } from "rxjs";
import { tap } from "rxjs/operators";

import { AdminAuditService } from "@/admin-audit/admin-audit.service";
import {
	AUDIT_ACTION_KEY,
	AuditActionContext,
	AuditActionMeta,
} from "@/admin-audit/decorators/audit-action.decorator";
import { AdminActor } from "@/admin-audit/dto/admin-action.dto";
import { RequestWithIdentity } from "@/common/decorators/admin-identity.decorator";

/**
 * AdminAuditInterceptor – records control-plane mutations to the tamper-evident
 * admin-action log. Active only on handlers annotated with @AuditAction(); all
 * other routes pass straight through.
 *
 * The actor is taken from the verified req.adminIdentity (null for the public,
 * token-authorized enroll route, which records its own entries in the service
 * layer). Target/params come from the @AuditAction extractors, and params are
 * sanitized again by the service before persistence.
 */
@Injectable()
export class AdminAuditInterceptor implements NestInterceptor {
	constructor(
		private readonly reflector: Reflector,
		private readonly auditService: AdminAuditService
	) {}

	intercept(
		context: ExecutionContext,
		next: CallHandler
	): Observable<unknown> {
		const meta = this.reflector.getAllAndOverride<AuditActionMeta>(
			AUDIT_ACTION_KEY,
			[context.getHandler(), context.getClass()]
		);
		if (!meta) {
			return next.handle();
		}

		const req = context.switchToHttp().getRequest<RequestWithIdentity>();
		const identity = req.adminIdentity;
		const actor: AdminActor = identity
			? { sub: identity.sub, fpr: identity.fpr, role: identity.role }
			: { sub: null, fpr: null, role: null };

		const baseCtx: Omit<AuditActionContext, "result"> = {
			params: (req.params ?? {}) as Record<string, unknown>,
			query: (req.query ?? {}) as Record<string, unknown>,
			body: (req.body ?? {}) as Record<string, unknown>,
		};

		const extractParams = (result: unknown): Record<string, unknown> => {
			const ctx: AuditActionContext = { ...baseCtx, result };
			if (meta.params) return meta.params(ctx);
			// Default: route params + query (small identifiers); never the body.
			return { ...baseCtx.params, ...baseCtx.query };
		};
		const extractTarget = (result: unknown): string | null => {
			if (!meta.target) return null;
			const ctx: AuditActionContext = { ...baseCtx, result };
			return meta.target(ctx) ?? null;
		};

		return next.handle().pipe(
			tap({
				next: result => {
					const httpStatus =
						context
							.switchToHttp()
							.getResponse<{ statusCode?: number }>()
							.statusCode ?? HttpStatus.OK;
					void this.auditService.append({
						action: meta.action,
						actor,
						target: extractTarget(result),
						params: extractParams(result),
						result: { status: "ok", httpStatus },
					});
				},
				error: (err: unknown) => {
					const httpStatus =
						err instanceof HttpException
							? err.getStatus()
							: HttpStatus.INTERNAL_SERVER_ERROR;
					const message =
						err instanceof Error ? err.message : String(err);
					void this.auditService.append({
						action: meta.action,
						actor,
						target: extractTarget(undefined),
						params: extractParams(undefined),
						result: { status: "error", httpStatus, message },
					});
				},
			})
		);
	}
}
