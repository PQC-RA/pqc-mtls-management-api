import { applyDecorators, HttpCode, Type } from "@nestjs/common";
import {
	ApiBadRequestResponse,
	ApiForbiddenResponse,
	ApiInternalServerErrorResponse,
	ApiNotFoundResponse,
	ApiOperation,
	ApiResponse,
} from "@nestjs/swagger";

// ── Shared error responses ───────────────────────────────────────────────────

/**
 * Standard error envelopes applied to every endpoint:
 *  - 400 Bad Request
 *  - 403 Forbidden (admin guard)
 *  - 500 Internal Server Error
 */
export function ApiErrorResponses() {
	return applyDecorators(
		ApiBadRequestResponse({ description: "Validation failed" }),
		ApiForbiddenResponse({
			description:
				"Access denied – the caller's certificate SHA-256 fingerprint is " +
				"not on the admin allowlist (JwtAuthGuard authorizes by fingerprint, " +
				"not any subject/OU field).",
		}),
		ApiInternalServerErrorResponse({
			description: "Unexpected server error",
		})
	);
}

// ── Per-method decorators ────────────────────────────────────────────────────

interface ApiMethodOptions {
	summary: string;
	description?: string;
	/** Swagger response DTO class – `type` on the 2xx response */
	type?: Type<unknown> | [Type<unknown>];
	/** Custom status code (default: 200 for GET/PUT/DELETE, 201 for POST) */
	status?: number;
	/** Include 404 in error responses? */
	notFound?: string;
}

export function ApiGet(opts: ApiMethodOptions) {
	const decorators = [
		ApiOperation({ summary: opts.summary, description: opts.description }),
		ApiResponse({
			status: opts.status ?? 200,
			description: opts.summary,
			type: opts.type as Type<unknown>,
		}),
		ApiErrorResponses(),
	];
	if (opts.notFound) {
		decorators.push(ApiNotFoundResponse({ description: opts.notFound }));
	}
	return applyDecorators(...decorators);
}

export function ApiPost(opts: ApiMethodOptions) {
	const status = opts.status ?? 200;
	const decorators = [
		HttpCode(status),
		ApiOperation({ summary: opts.summary, description: opts.description }),
		ApiResponse({
			status,
			description: opts.summary,
			type: opts.type as Type<unknown>,
		}),
		ApiErrorResponses(),
	];
	if (opts.notFound) {
		decorators.push(ApiNotFoundResponse({ description: opts.notFound }));
	}
	return applyDecorators(...decorators);
}

export function ApiPut(opts: ApiMethodOptions) {
	const decorators = [
		HttpCode(opts.status ?? 200),
		ApiOperation({ summary: opts.summary, description: opts.description }),
		ApiResponse({
			status: opts.status ?? 200,
			description: opts.summary,
			type: opts.type as Type<unknown>,
		}),
		ApiErrorResponses(),
	];
	if (opts.notFound) {
		decorators.push(ApiNotFoundResponse({ description: opts.notFound }));
	}
	return applyDecorators(...decorators);
}

export function ApiDelete(opts: ApiMethodOptions) {
	const decorators = [
		HttpCode(opts.status ?? 200),
		ApiOperation({ summary: opts.summary, description: opts.description }),
		ApiResponse({
			status: opts.status ?? 200,
			description: opts.summary,
			type: opts.type as Type<unknown>,
		}),
		ApiErrorResponses(),
	];
	if (opts.notFound) {
		decorators.push(ApiNotFoundResponse({ description: opts.notFound }));
	}
	return applyDecorators(...decorators);
}
