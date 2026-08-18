import {
	CanActivate,
	ExecutionContext,
	ForbiddenException,
	Injectable,
	Logger,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";

import { AdminRole } from "@/common/auth/cert-roles";
import { RequestWithIdentity } from "@/common/decorators/admin-identity.decorator";
import { IS_PUBLIC_KEY } from "@/common/decorators/public.decorator";
import { ROLES_KEY } from "@/common/decorators/roles.decorator";

/**
 * RolesGuard – coarse-grained RBAC layered on top of JwtAuthGuard.
 *
 * Registered as a global guard AFTER JwtAuthGuard, so by the time it runs the
 * caller's identity ({ sub, fpr, role }) is already attached to the request.
 *
 * Policy:
 *   - @Public() routes are skipped (no identity, no role requirement).
 *   - A route with no @Roles() metadata is readable by any authenticated role
 *     (admin + auditor).
 *   - A route annotated @Roles('admin') requires the caller's resolved role to
 *     be 'admin'. Fails CLOSED: a missing identity (defensive) is denied.
 */
@Injectable()
export class RolesGuard implements CanActivate {
	private readonly logger = new Logger(RolesGuard.name);

	constructor(private readonly reflector: Reflector) {}

	canActivate(context: ExecutionContext): boolean {
		const isPublic = this.reflector.getAllAndOverride<boolean>(
			IS_PUBLIC_KEY,
			[context.getHandler(), context.getClass()]
		);
		if (isPublic) {
			return true;
		}

		const required = this.reflector.getAllAndOverride<AdminRole[]>(
			ROLES_KEY,
			[context.getHandler(), context.getClass()]
		);
		// No explicit role requirement → any authenticated caller may proceed.
		if (!required || required.length === 0) {
			return true;
		}

		const request = context
			.switchToHttp()
			.getRequest<RequestWithIdentity>();
		const role = request.adminIdentity?.role;

		if (!role || !required.includes(role)) {
			this.logger.warn(
				`RBAC denied: role="${role ?? "none"}" not in [${required.join(", ")}] ` +
					`(sub="${request.adminIdentity?.sub ?? "?"}")`
			);
			throw new ForbiddenException(
				`This action requires one of the following roles: ${required.join(", ")}`
			);
		}

		return true;
	}
}
