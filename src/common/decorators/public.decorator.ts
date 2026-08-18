import { SetMetadata } from "@nestjs/common";

/**
 * Marks a route handler (or whole controller) as publicly accessible,
 * exempting it from the globally-registered JwtAuthGuard.
 *
 * Use sparingly – only for endpoints that MUST be reachable without a
 * gateway-minted JWT (e.g. an unauthenticated container liveness probe that
 * leaks no sensitive data).  Admin/management routes must never be @Public.
 */
export const IS_PUBLIC_KEY = "isPublic";
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
