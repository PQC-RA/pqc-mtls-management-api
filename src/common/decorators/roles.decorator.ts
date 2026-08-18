import { SetMetadata } from "@nestjs/common";

import { AdminRole } from "@/common/auth/cert-roles";

export const ROLES_KEY = "requiredRoles";

/**
 * Restrict a route (or controller) to the listed roles. Enforced by RolesGuard.
 *
 * Conventions in this API:
 *   - Mutating routes (POST/PUT/DELETE/PATCH) are annotated `@Roles('admin')`.
 *   - Read routes carry no @Roles decorator, which RolesGuard treats as
 *     "any authenticated role" – i.e. both `admin` and `auditor` may read.
 *
 * The caller's role is resolved by JwtAuthGuard from the certificate
 * fingerprint allowlists, never from a JWT claim.
 */
export const Roles = (...roles: AdminRole[]) => SetMetadata(ROLES_KEY, roles);
