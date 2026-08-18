import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

// ── Nested sub-objects matching the NJS audit log format ─────────────────────

export class AuditClientDto {
	@ApiProperty({ example: "service-A" })
	cn: string;

	@ApiProperty({ example: "M2M-Client" })
	org: string;

	@ApiPropertyOptional({ example: "AB:CD:12:34:..." })
	serial?: string;

	@ApiPropertyOptional({ example: "sha256:abcdef..." })
	fingerprint?: string;

	@ApiProperty({
		description: "Nginx ssl_client_verify result",
		example: "SUCCESS",
	})
	verify: string;
}

export class AuditTlsDto {
	@ApiProperty({ example: "TLSv1.3" })
	version: string;

	@ApiProperty({ example: "TLS_AES_256_GCM_SHA384" })
	cipher: string;
}

export class AuditHttpDto {
	@ApiProperty({ example: "POST" })
	method: string;

	@ApiProperty({ example: "/api/v1/payments" })
	uri: string;

	@ApiProperty({ example: 200 })
	status: number;

	@ApiPropertyOptional({ example: "203.0.113.10" })
	remote_addr?: string;
}

export class AuditDetailsDto {
	@ApiPropertyOptional({ example: "http://backend:8080" })
	backend?: string;

	@ApiPropertyOptional({ example: true })
	allowed?: boolean;

	@ApiPropertyOptional({ example: "Rate limit: 100 req/s" })
	note?: string;
}

// ── Top-level audit log entry ────────────────────────────────────────────────

export class AuditLogEntryDto {
	@ApiProperty({
		description:
			"Sequence number within the log (monotonically increasing)",
		example: 42,
	})
	seq: number;

	@ApiProperty({
		description: "ISO 8601 timestamp of the request",
		example: "2026-03-09T15:48:49.000Z",
	})
	ts: string;

	@ApiProperty({
		description: "Event type",
		example: "access",
		enum: ["access", "block", "error"],
	})
	event: string;

	@ApiProperty({
		description: "Log level",
		example: "info",
		enum: ["info", "warn", "error"],
	})
	level: string;

	@ApiProperty({ description: "Client identity from mTLS certificate" })
	client: AuditClientDto;

	@ApiProperty({ description: "TLS session details" })
	tls: AuditTlsDto;

	@ApiProperty({ description: "HTTP request/response details" })
	http: AuditHttpDto;

	@ApiPropertyOptional({ description: "Policy enforcement details" })
	details?: AuditDetailsDto;

	@ApiProperty({
		description:
			"SHA-256 hash of the previous log entry (blockchain-style integrity)",
		example:
			"0000000000000000000000000000000000000000000000000000000000000000",
	})
	prev_hash: string;

	@ApiProperty({
		description:
			"SHA-256 hash of this entry (covers all fields except hash itself)",
		example: "a1b2c3d4e5f6...",
	})
	hash: string;
}
