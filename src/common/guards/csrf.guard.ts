import {
	CanActivate,
	ExecutionContext,
	ForbiddenException,
	Injectable,
	Logger,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Request } from "express";

import { IS_PUBLIC_KEY } from "@/common/decorators/public.decorator";

/** HTTP methods that mutate state and therefore require CSRF protection. */
const MUTATING_METHODS = new Set(["POST", "PUT", "DELETE", "PATCH"]);

/**
 * CSRF marker header a client sets on every state-changing request. The value
 * is irrelevant – presence is the whole signal: a cross-site browser cannot set
 * a custom header (its CORS preflight is rejected), so the header being present
 * proves the request was not forged cross-origin. Named generically (not
 * "console") because non-browser admin clients – e.g. the issue-cert.sh CLI –
 * set it too.
 */
export const CSRF_HEADER = "x-pqc-csrf";

/**
 * Parse the console-origin allowlist. CONSOLE_ORIGIN takes precedence; it
 * defaults to CORS_ALLOWED_ORIGINS so a single CORS configuration also governs
 * CSRF. Comma-separated; empty → no allowed origins (deny all mutations).
 */
function parseConsoleOrigins(): Set<string> {
	const raw = process.env.CONSOLE_ORIGIN ?? process.env.CORS_ALLOWED_ORIGINS;
	if (!raw) return new Set();
	return new Set(
		raw
			.split(",")
			.map(o => o.trim().replace(/\/+$/, "")) // tolerate a trailing slash
			.filter(Boolean)
	);
}

/**
 * CsrfGuard – defends JWT-protected, state-changing routes against
 * cross-site request forgery from a browser.
 *
 * The gateway mints the JWT from the mTLS certificate and injects it as a
 * Bearer header, so a browser session is effectively credentialed by ambient
 * authority. To stop a malicious page from driving mutations, every
 * POST/PUT/DELETE/PATCH on a JWT-protected route must carry a non-empty
 * `X-PQC-CSRF` header. This is the primary defense and is CSRF-complete on
 * its own: CORS is locked to an explicit allowlist (main.ts), so a cross-site
 * page cannot set this custom header – its preflight is rejected – and a simple
 * <form>/GET-style request cannot set custom headers at all.
 *
 * Origin is pinned only when PRESENT: browsers always send Origin on
 * state-changing requests, so a request that carries one must have it in the
 * console-origin allowlist. A request with NO Origin is a non-browser client
 * (e.g. the issue-cert.sh admin CLI, authenticated by its own mTLS cert) and is
 * authorized by the custom header alone – so the console is not the only
 * permitted caller, and CLI admin flows are not tied to a console origin.
 *
 * Fails CLOSED: missing header, or a present-but-unlisted Origin → 403.
 *
 * @Public() routes are EXEMPT – notably POST /admin/certs/sign, the
 * token-authorized self-enrollment endpoint reached cross-context from a
 * browser enrollment page or curl with no Origin and no console session.
 */
@Injectable()
export class CsrfGuard implements CanActivate {
	private readonly logger = new Logger(CsrfGuard.name);
	private readonly allowedOrigins = parseConsoleOrigins();

	constructor(private readonly reflector: Reflector) {
		if (this.allowedOrigins.size === 0) {
			this.logger.warn(
				"No CONSOLE_ORIGIN / CORS_ALLOWED_ORIGINS configured – browser " +
					"console mutations (which always carry an Origin) will be " +
					"rejected by the CSRF guard. Header-only non-browser clients " +
					"(e.g. the admin CLI) still work."
			);
		}
	}

	canActivate(context: ExecutionContext): boolean {
		const request = context.switchToHttp().getRequest<Request>();
		const method = (request.method ?? "").toUpperCase();

		// Only mutating methods need CSRF protection.
		if (!MUTATING_METHODS.has(method)) {
			return true;
		}

		// Exempt @Public() routes (e.g. token-authorized /certs/sign).
		const isPublic = this.reflector.getAllAndOverride<boolean>(
			IS_PUBLIC_KEY,
			[context.getHandler(), context.getClass()]
		);
		if (isPublic) {
			return true;
		}

		// Primary CSRF defense: the X-PQC-CSRF custom header. CORS is locked to
		// an explicit allowlist (main.ts), so a cross-site page cannot set it (its
		// preflight is rejected) and a simple <form> request cannot set custom
		// headers at all. A legitimate non-browser client (e.g. the issue-cert.sh
		// admin CLI, authenticated by its mTLS cert) sets it explicitly.
		const rawHeader = request.headers[CSRF_HEADER];
		const headerValue = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;
		if (!headerValue || headerValue.trim() === "") {
			this.logger.warn(
				`CSRF block: missing X-PQC-CSRF header (${method} ${request.url})`
			);
			throw new ForbiddenException("Missing required X-PQC-CSRF header");
		}

		// Origin pinning for BROWSER clients: browsers always send Origin on
		// state-changing requests, so when one is present it must be allowlisted.
		// A request with no Origin is a non-browser client and is authorized by
		// the header above alone (the console is not the only permitted caller).
		const origin = request.headers["origin"];
		if (typeof origin === "string" && origin !== "") {
			const normalizedOrigin = origin.replace(/\/+$/, "");
			if (!this.allowedOrigins.has(normalizedOrigin)) {
				this.logger.warn(
					`CSRF block: Origin "${origin}" not in console allowlist ` +
						`(${method} ${request.url})`
				);
				throw new ForbiddenException(
					"Cross-origin request rejected – Origin is not an allowed console origin"
				);
			}
		}

		return true;
	}
}
