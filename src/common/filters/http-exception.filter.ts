import {
	ArgumentsHost,
	Catch,
	ExceptionFilter,
	HttpException,
	HttpStatus,
	Logger,
} from "@nestjs/common";
import { Request, Response } from "express";

import { errorResponse } from "@/common/dto/api-response.dto";

/**
 * Catches all HttpExceptions (and raw Error fallbacks) and wraps them
 * in the uniform { ok: false, error: { code, message } } envelope.
 *
 * Internal error details (stack traces, raw OpenSSL output, file paths)
 * are never forwarded to the client – only a safe human-readable message.
 */
@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
	private readonly logger = new Logger(HttpExceptionFilter.name);

	catch(exception: unknown, host: ArgumentsHost): void {
		const ctx = host.switchToHttp();
		const response = ctx.getResponse<Response>();
		const request = ctx.getRequest<Request>();

		let status = HttpStatus.INTERNAL_SERVER_ERROR;
		let message = "An unexpected error occurred";

		if (exception instanceof HttpException) {
			status = exception.getStatus();
			const res = exception.getResponse();

			// NestJS can give back a string or an object with a `message` field
			if (typeof res === "string") {
				message = res;
			} else if (
				typeof res === "object" &&
				res !== null &&
				"message" in res
			) {
				const { message: raw } = res as { message: unknown };

				// ValidationPipe returns message as string[]
				message = Array.isArray(raw) ? raw.join("; ") : String(raw);
			}
		} else if (exception instanceof Error) {
			// Unhandled errors – log full detail, return generic message
			this.logger.error(
				`Unhandled exception on ${request.method} ${request.url}: ${exception.message}`,
				exception.stack
			);
		}

		response.status(status).json(errorResponse(status, message));
	}
}
