import { applyDecorators } from "@nestjs/common";
import {
	ApiBearerAuth,
	ApiForbiddenResponse,
	ApiTags,
	ApiUnauthorizedResponse,
} from "@nestjs/swagger";

/**
 * Composite class-level decorator for admin-only controllers.
 *
 * This decorator now only carries Swagger documentation. Authentication and
 * authorization are enforced GLOBALLY by JwtAuthGuard (registered as an
 * APP_GUARD in AppModule), so every route is protected by default and a
 * forgotten decorator can no longer leave an admin route open. Public routes
 * must opt out explicitly with @Public().
 *
 * The guard fetches the gateway's public key from the JWKS endpoint, verifies
 * the RS256 signature, issuer and audience, and authorizes the caller against
 * an explicit certificate-fingerprint allowlist – never a cert subject field.
 */
export function AdminController(tag: string) {
	return applyDecorators(
		ApiTags(tag),
		ApiBearerAuth("GatewayJWT"),
		ApiUnauthorizedResponse({
			description:
				"Missing or invalid Authorization Bearer JWT (RS256, gateway-signed).",
		}),
		ApiForbiddenResponse({
			description:
				"Access denied – certificate is not on the admin allowlist.",
		})
	);
}
