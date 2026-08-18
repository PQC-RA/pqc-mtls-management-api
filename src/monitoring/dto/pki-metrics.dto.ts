import { ApiProperty } from "@nestjs/swagger";

/** Certificate counts by OpenSSL index status. */
export class CertsTotalDto {
	@ApiProperty({
		description: "Valid (V) certificates.",
		type: Number,
		example: 6,
	})
	valid: number;

	@ApiProperty({
		description: "Revoked (R) certificates.",
		type: Number,
		example: 0,
	})
	revoked: number;

	@ApiProperty({
		description: "Expired (E) certificates.",
		type: Number,
		example: 0,
	})
	expired: number;

	@ApiProperty({
		description: "Total certificates in the CA database.",
		type: Number,
		example: 6,
	})
	total: number;
}

/** One soon-to-expire certificate in the metrics detail list. */
export class ExpiringCertDetailDto {
	@ApiProperty({ description: "Hex serial number.", example: "1006" })
	serial: string;

	@ApiProperty({
		description: "Subject DN.",
		example: "/CN=service-A/O=Enterprise",
	})
	subject: string;

	@ApiProperty({
		description: "Whole days until expiry (ceil).",
		type: Number,
		example: 12,
	})
	daysLeft: number;
}

/** Certificate expiry buckets plus the within-30-day detail list. */
export class CertsExpiringDto {
	@ApiProperty({
		description: "Valid certs expiring within 30 days.",
		type: Number,
		example: 1,
	})
	within_30d: number;

	@ApiProperty({
		description: "Valid certs expiring within 14 days (CRITICAL).",
		type: Number,
		example: 0,
	})
	within_14d: number;

	@ApiProperty({
		description: "Valid certs expiring within 7 days (URGENT).",
		type: Number,
		example: 0,
	})
	within_7d: number;

	@ApiProperty({
		description:
			"Per-certificate details for those expiring within 30 days.",
		type: [ExpiringCertDetailDto],
	})
	details_30d: ExpiringCertDetailDto[];
}

/**
 * `GET /admin/metrics` response (NIS2 Art. 21(2)(g)). Property names are
 * snake_case exactly as the API emits them.
 */
export class PkiMetricsDto {
	@ApiProperty({
		description: "Compliance tag.",
		example: "NIS2 Art. 21(2)(g)",
	})
	compliance: string;

	@ApiProperty({
		description: "Generation time (ISO-8601 string).",
		type: String,
		format: "date-time",
		example: "2026-06-30T11:25:38.994Z",
	})
	timestamp: string;

	@ApiProperty({
		description: "Certificate counts by status.",
		type: CertsTotalDto,
	})
	certs_total: CertsTotalDto;

	@ApiProperty({
		description: "Expiry buckets and 30-day detail.",
		type: CertsExpiringDto,
	})
	certs_expiring: CertsExpiringDto;

	@ApiProperty({
		description:
			"Seconds since the combined CRL was last modified, or null if the CRL file is missing/unreadable.",
		type: Number,
		nullable: true,
		example: 1680,
	})
	crl_age_seconds: number | null;

	@ApiProperty({
		description:
			"CRL freshness: 'ok' (< 48h), 'stale' (>= 48h), or 'unknown' (age undeterminable).",
		enum: ["ok", "stale", "unknown"],
		example: "ok",
	})
	crl_status: "ok" | "stale" | "unknown";

	@ApiProperty({
		description:
			"Total non-blank lines in the data-plane audit log, or null if unreadable.",
		type: Number,
		nullable: true,
		example: 0,
	})
	audit_log_entries: number | null;
}
