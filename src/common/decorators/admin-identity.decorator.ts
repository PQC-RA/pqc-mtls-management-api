import {
	createParamDecorator,
	ExecutionContext,
	InternalServerErrorException,
} from "@nestjs/common";
import { Request } from "express";

import { AdminIdentity } from "@/common/auth/cert-roles";

/**
 * Request augmentation: JwtAuthGuard attaches the verified, authorized caller
 * identity here after a successful auth+authz. Never the raw token.
 */
export type RequestWithIdentity = Request & {
	adminIdentity?: AdminIdentity;
};

/**
 * Controller param decorator that injects the authenticated admin identity
 * ({ sub, fpr, role }) resolved by JwtAuthGuard.
 *
 * Only usable on JWT-protected routes – on a @Public() route no identity is
 * attached and this throws (a programming error: never read identity on a
 * public handler).
 */
export const AdminIdentityParam = createParamDecorator(
	(_data: unknown, ctx: ExecutionContext): AdminIdentity => {
		const req = ctx.switchToHttp().getRequest<RequestWithIdentity>();
		if (!req.adminIdentity) {
			throw new InternalServerErrorException(
				"No admin identity on request – @AdminIdentity() used on a non-authenticated route"
			);
		}
		return req.adminIdentity;
	}
);
