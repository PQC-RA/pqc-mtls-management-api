import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

/**
 * Uniform API envelope returned by every endpoint.
 *
 * Success:  { ok: true,  data: <T> }
 * Error:    { ok: false, error: { code, message, details? } }
 */
export class ApiErrorDto {
	@ApiProperty({ example: 404 })
	code: number;

	@ApiProperty({ example: "Certificate not found" })
	message: string;

	@ApiPropertyOptional({ example: null })
	details?: unknown;
}

export class ApiResponseDto<T> {
	@ApiProperty({ example: true })
	ok: boolean;

	@ApiPropertyOptional()
	data?: T;

	@ApiPropertyOptional({ type: () => ApiErrorDto })
	error?: ApiErrorDto;
}

/** Helper to build a success envelope */
export function successResponse<T>(data: T): ApiResponseDto<T> {
	return { ok: true, data };
}

/** Helper to build an error envelope */
export function errorResponse(
	code: number,
	message: string,
	details?: unknown
): ApiResponseDto<never> {
	return { ok: false, error: { code, message, details } };
}
