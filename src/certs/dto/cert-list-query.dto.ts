import { ApiPropertyOptional } from "@nestjs/swagger";
import { Type } from "class-transformer";
import { IsIn, IsInt, IsOptional, IsString, Min } from "class-validator";

/**
 * Optional filter/pagination params for the certificate list endpoint. With no
 * params the endpoint behaves exactly as before (returns all entries).
 */
export class CertListQueryDto {
	@ApiPropertyOptional({
		description: "Filter by status: V (valid), R (revoked), E (expired).",
		enum: ["V", "R", "E"],
	})
	@IsOptional()
	@IsIn(["V", "R", "E"])
	status?: "V" | "R" | "E";

	@ApiPropertyOptional({
		description:
			"Case-insensitive substring match against the certificate subject DN.",
		example: "service",
	})
	@IsOptional()
	@IsString()
	cnContains?: string;

	@ApiPropertyOptional({
		description: "Pagination page size.",
		minimum: 1,
	})
	@IsOptional()
	@Type(() => Number)
	@IsInt()
	@Min(1)
	limit?: number;

	@ApiPropertyOptional({
		description: "Pagination offset (0-based).",
		minimum: 0,
	})
	@IsOptional()
	@Type(() => Number)
	@IsInt()
	@Min(0)
	offset?: number;
}
