import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

import { CertEntryDto } from "@/certs/dto/cert-entry.dto";

/**
 * Enriched single-certificate view. Extends the lean index-derived entry with
 * fields parsed from the issued PEM via the PQ OpenSSL toolchain.
 */
export class CertDetailDto extends CertEntryDto {
	@ApiProperty({
		description:
			"SHA-256 certificate fingerprint, lowercase hex with no colons – the " +
			"exact form an operator pastes into ADMIN_CERT_FINGERPRINTS.",
		example:
			"1c2ba075293fcd68e241cfcedf337ff59bc8126b24c2af07c60f319a38e1a0d8",
	})
	fingerprintSha256: string;

	@ApiProperty({
		description: "Public-key algorithm reported by OpenSSL.",
		example: "ML-DSA-65",
	})
	publicKeyAlgorithm: string;

	@ApiPropertyOptional({
		description:
			"Subject Alternative Name extension value (omitted if the cert has none).",
		example: "DNS:my-service, DNS:my-service.internal",
	})
	subjectAltName?: string;

	@ApiProperty({
		description: "Validity start (ISO-8601).",
		example: "2026-06-30T00:00:00.000Z",
	})
	notBefore: string;

	@ApiProperty({
		description: "Validity end (ISO-8601).",
		example: "2027-06-30T00:00:00.000Z",
	})
	notAfter: string;

	@ApiProperty({
		description: "Full PEM-encoded certificate.",
		example:
			"-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n",
	})
	pem: string;
}
