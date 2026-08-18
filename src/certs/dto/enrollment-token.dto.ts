import { ApiProperty } from "@nestjs/swagger";

/**
 * Response of `POST /admin/certs/enrollment-tokens`.
 *
 * NOTE: `expiresAt` is a **Unix epoch in milliseconds (number)**, not an ISO
 * date string – this is the field whose missing schema caused the console to
 * guess it as a string. Typed explicitly here so the generated client treats it
 * as a number.
 */
export class EnrollmentTokenDto {
	@ApiProperty({
		description:
			"Single-use, CN-constrained enrollment token. Hand to the operator out-of-band.",
		example: "enroll_abc123xyz",
	})
	token: string;

	@ApiProperty({
		description:
			"Token expiry as a Unix epoch timestamp in MILLISECONDS (e.g. Date.now() + ttl*1000). Not an ISO string.",
		type: Number,
		format: "int64",
		example: 1741600000000,
	})
	expiresAt: number;

	@ApiProperty({
		description:
			"CN the CSR subject must match exactly before the token is consumed.",
		example: "my-service",
	})
	allowedCn: string;
}

/**
 * One entry of `GET /admin/certs/enrollment-tokens`.
 * Same shape as {@link EnrollmentTokenDto} plus the `used` flag.
 */
export class EnrollmentTokenListItemDto {
	@ApiProperty({
		description: "The enrollment token value.",
		example: "enroll_abc123xyz",
	})
	token: string;

	@ApiProperty({
		description:
			"Token expiry as a Unix epoch timestamp in MILLISECONDS (number, not ISO).",
		type: Number,
		format: "int64",
		example: 1741600000000,
	})
	expiresAt: number;

	@ApiProperty({
		description: "CN the CSR subject must match exactly.",
		example: "my-service",
	})
	allowedCn: string;

	@ApiProperty({
		description:
			"Whether the token has already been consumed by a successful enrollment.",
		type: Boolean,
		example: false,
	})
	used: boolean;
}
