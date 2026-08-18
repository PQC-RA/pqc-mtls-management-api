import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

export class HealthIndicatorResultDto {
	@ApiProperty({
		description: "Status of this specific health indicator",
		enum: ["up", "down"],
		example: "up",
	})
	status: "up" | "down";

	@ApiPropertyOptional({
		description: "Additional detail about the indicator's state",
		example: { caIndexFile: true, crlFile: true, renewScript: true },
	})
	details?: Record<string, unknown>;
}

export class HealthCheckResponseDto {
	@ApiProperty({
		description: "Overall system health status",
		enum: ["ok", "error", "shutting_down"],
		example: "ok",
	})
	status: "ok" | "error" | "shutting_down";

	@ApiProperty({
		description: "Per-indicator health results",
		example: {
			pki_infrastructure: { status: "up" },
		},
		type: "object",
		additionalProperties: {
			$ref: "#/components/schemas/HealthIndicatorResultDto",
		},
	})
	info: Record<string, HealthIndicatorResultDto>;

	@ApiPropertyOptional({
		description: "Details only for failing indicators",
		type: "object",
		additionalProperties: {
			$ref: "#/components/schemas/HealthIndicatorResultDto",
		},
	})
	error?: Record<string, HealthIndicatorResultDto>;

	@ApiProperty({
		description:
			"Full details for all indicators (same as info when all are up)",
		type: "object",
		additionalProperties: {
			$ref: "#/components/schemas/HealthIndicatorResultDto",
		},
	})
	details: Record<string, HealthIndicatorResultDto>;
}
