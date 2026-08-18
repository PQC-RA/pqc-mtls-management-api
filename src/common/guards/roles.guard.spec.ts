import { ExecutionContext, ForbiddenException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";

import { AdminRole } from "@/common/auth/cert-roles";
import { IS_PUBLIC_KEY } from "@/common/decorators/public.decorator";
import { ROLES_KEY } from "@/common/decorators/roles.decorator";
import { RolesGuard } from "@/common/guards/roles.guard";

function makeContext(role?: AdminRole): ExecutionContext {
	return {
		getHandler: () => undefined,
		getClass: () => undefined,
		switchToHttp: () => ({
			getRequest: () => ({
				adminIdentity: role ? { sub: "x", fpr: "f", role } : undefined,
			}),
		}),
	} as unknown as ExecutionContext;
}

/** Build a guard whose reflector returns the given public flag + required roles. */
function makeGuard(opts: { isPublic?: boolean; required?: AdminRole[] }) {
	const reflector = {
		getAllAndOverride: jest.fn((key: string) => {
			if (key === IS_PUBLIC_KEY) return opts.isPublic ?? false;
			if (key === ROLES_KEY) return opts.required;
			return undefined;
		}),
	} as unknown as Reflector;
	return new RolesGuard(reflector);
}

describe("RolesGuard", () => {
	it("allows @Public routes regardless of role", () => {
		const guard = makeGuard({ isPublic: true, required: ["admin"] });
		expect(guard.canActivate(makeContext())).toBe(true);
	});

	it("allows any authenticated role when no @Roles is set (read routes)", () => {
		const guard = makeGuard({});
		expect(guard.canActivate(makeContext("auditor"))).toBe(true);
		expect(guard.canActivate(makeContext("admin"))).toBe(true);
	});

	it("allows admin on @Roles('admin') routes", () => {
		const guard = makeGuard({ required: ["admin"] });
		expect(guard.canActivate(makeContext("admin"))).toBe(true);
	});

	it("blocks auditor on @Roles('admin') routes", () => {
		const guard = makeGuard({ required: ["admin"] });
		expect(() => guard.canActivate(makeContext("auditor"))).toThrow(
			ForbiddenException
		);
	});

	it("denies when no identity is present and a role is required (fail closed)", () => {
		const guard = makeGuard({ required: ["admin"] });
		expect(() => guard.canActivate(makeContext())).toThrow(
			ForbiddenException
		);
	});
});
