import { ApiPropertyOptional } from "@nestjs/swagger";
import { Type } from "class-transformer";
import {
	IsInt,
	IsISO8601,
	IsOptional,
	IsString,
	Max,
	Min,
} from "class-validator";

/**
 * Shared query/pagination parameters for the NDJSON audit endpoints
 * (`/admin/audit/logs` and `/admin/audit/admin-actions`).
 *
 * Filtering is applied server-side over the parsed NDJSON tail. `lines` is kept
 * for backward compatibility (return the last N entries); when `offset`/`limit`
 * are supplied they take precedence over `lines`.
 */
export class AuditQueryDto {
	@ApiPropertyOptional({
		description:
			"Number of most recent entries to scan/return (backward-compatible). " +
			"Ignored when offset/limit are provided.",
		minimum: 1,
		maximum: 10_000,
		default: 100,
	})
	@IsOptional()
	@Type(() => Number)
	@IsInt()
	@Min(1)
	@Max(10_000)
	lines?: number;

	@ApiPropertyOptional({
		description:
			"Filter by client Common Name (exact match; data-plane entries only).",
	})
	@IsOptional()
	@IsString()
	cn?: string;

	@ApiPropertyOptional({
		description:
			"Filter by event/action type (exact match). For the data-plane log this is " +
			"the `event` field; for admin-actions it is the `action` field.",
	})
	@IsOptional()
	@IsString()
	event?: string;

	@ApiPropertyOptional({
		description:
			"Filter by level (data-plane log) / result status (admin-actions), exact match.",
	})
	@IsOptional()
	@IsString()
	level?: string;

	@ApiPropertyOptional({
		description: "Only entries at/after this ISO-8601 timestamp.",
		example: "2026-06-01T00:00:00.000Z",
	})
	@IsOptional()
	@IsISO8601()
	since?: string;

	@ApiPropertyOptional({
		description: "Only entries at/before this ISO-8601 timestamp.",
		example: "2026-06-30T23:59:59.000Z",
	})
	@IsOptional()
	@IsISO8601()
	until?: string;

	@ApiPropertyOptional({
		description: "Pagination offset over the filtered result (0-based).",
		minimum: 0,
	})
	@IsOptional()
	@Type(() => Number)
	@IsInt()
	@Min(0)
	offset?: number;

	@ApiPropertyOptional({
		description: "Pagination page size over the filtered result.",
		minimum: 1,
		maximum: 10_000,
	})
	@IsOptional()
	@Type(() => Number)
	@IsInt()
	@Min(1)
	@Max(10_000)
	limit?: number;
}
