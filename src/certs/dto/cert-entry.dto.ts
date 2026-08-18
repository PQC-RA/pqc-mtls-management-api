import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

export class CertEntryDto {
	@ApiProperty({
		description: "Certificate status",
		enum: ["V", "R", "E"],
		example: "V",
	})
	status: "V" | "R" | "E";

	@ApiProperty({
		description:
			"Certificate expiration date (parsed from OpenSSL YYMMDDHHMMSSZ format)",
		type: String,
		format: "date-time",
		example: "2036-03-09T15:48:49.000Z",
	})
	expirationDate: Date;

	@ApiPropertyOptional({
		description:
			"Date the certificate was revoked (only present if status is R)",
		type: String,
		format: "date-time",
		example: "2026-03-09T15:48:49.000Z",
	})
	revocationDate?: Date;

	@ApiProperty({
		description:
			"Hex serial number as stored in the OpenSSL index.txt (uppercase, even-length hex)",
		example: "1006",
	})
	serialNumber: string;

	@ApiPropertyOptional({
		description:
			"Path to the certificate file on disk (omitted if unknown)",
		example: "/etc/pki/pqc-ca/intermediate/issued/1006.pem",
	})
	filename?: string;

	@ApiProperty({
		description: "Distinguished Name (DN) of the certificate subject",
		example: "/CN=service-A/O=Enterprise",
	})
	subject: string;
}
