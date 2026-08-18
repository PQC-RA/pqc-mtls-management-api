import { ApiProperty } from "@nestjs/swagger";
import { IsString, Matches } from "class-validator";

/**
 * Validates the :fpr path parameter. The global ValidationPipe applies
 * class-validator decorators to @Param() objects – mirrors certs.controller's
 * SerialParamDto convention.
 */
export class FingerprintParamDto {
	@IsString()
	@Matches(/^[0-9A-Fa-f]{64}$/, {
		message:
			"fpr must be a 64-character hexadecimal SHA-256 certificate fingerprint",
	})
	fpr: string;
}

export class CertLookupResultDto {
	@ApiProperty({
		description: "PEM-encoded certificate content (as issued).",
	})
	certificate: string;

	@ApiProperty({
		description: "CA serial number of the issued certificate.",
		example: "1018",
	})
	serialNumber: string;

	@ApiProperty({
		description: "Validity end (ISO-8601).",
		example: "2027-07-16T11:32:00.000Z",
	})
	expiresAt: string;
}
