import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { IsNotEmpty, IsString, Matches } from "class-validator";

/** Request body for the CSR pre-flight check. */
export class ValidateCsrDto {
	@ApiProperty({
		description:
			"PEM-encoded Certificate Signing Request to validate (no token spent).",
		example:
			"-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----\n",
	})
	@IsString()
	@IsNotEmpty()
	@Matches(
		/-----BEGIN CERTIFICATE REQUEST-----[\s\S]+-----END CERTIFICATE REQUEST-----/,
		{
			message:
				"csr must be a valid PEM-encoded Certificate Signing Request",
		}
	)
	csr: string;
}

export class ValidateCsrResponseDto {
	@ApiProperty({
		description:
			"True only if the CSR self-signature verifies AND the key algorithm " +
			"is the permitted ML-DSA-65.",
		example: true,
	})
	valid: boolean;

	@ApiPropertyOptional({
		description: "Subject CN extracted from the CSR (if present).",
		example: "my-service",
	})
	cn?: string;

	@ApiPropertyOptional({
		description:
			"Public-key algorithm reported by OpenSSL (if determinable).",
		example: "ML-DSA-65",
	})
	publicKeyAlgorithm?: string;

	@ApiPropertyOptional({
		description: "Why the CSR is not valid (omitted when valid).",
		example:
			'Unsupported client key algorithm "rsaEncryption": only ML-DSA-65 is permitted.',
	})
	reason?: string;
}
