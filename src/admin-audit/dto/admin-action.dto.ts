import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

/** The authenticated actor that performed a control-plane action. */
export interface AdminActor {
	/** JWT subject (client CN), or null for the token-authorized public enroll. */
	sub: string | null;
	/** Certificate SHA-256 fingerprint, or null when there is no admin identity. */
	fpr: string | null;
	/** Resolved role, or null for anonymous/public actions. */
	role: string | null;
}

export interface AdminActionResult {
	status: "ok" | "error";
	httpStatus: number;
	message?: string;
}

/** A single tamper-evident admin-action audit entry (as persisted as NDJSON). */
export interface AdminActionEntry {
	seq: number;
	ts: string;
	actor: AdminActor;
	action: string;
	target: string | null;
	params: Record<string, unknown>;
	result: AdminActionResult;
	prev_hash: string;
	hash: string;
}

// ── Swagger DTOs ─────────────────────────────────────────────────────────────

export class AdminActorDto implements AdminActor {
	@ApiPropertyOptional({
		type: String,
		description:
			"JWT subject (client CN), or null for token-authorized public enroll.",
		example: "ops-admin",
		nullable: true,
	})
	sub: string | null;

	@ApiPropertyOptional({
		type: String,
		description:
			"Certificate SHA-256 fingerprint, or null when there is no admin identity.",
		example:
			"1c2ba075293fcd68e241cfcedf337ff59bc8126b24c2af07c60f319a38e1a0d8",
		nullable: true,
	})
	fpr: string | null;

	@ApiPropertyOptional({
		enum: ["admin", "auditor"],
		description: "Resolved role, or null for anonymous/public actions.",
		example: "admin",
		nullable: true,
	})
	role: string | null;
}

export class AdminActionResultDto implements AdminActionResult {
	@ApiProperty({ enum: ["ok", "error"], example: "ok" })
	status: "ok" | "error";

	@ApiProperty({ example: 201 })
	httpStatus: number;

	@ApiPropertyOptional({ example: "Certificate not found" })
	message?: string;
}

export class AdminActionEntryDto implements AdminActionEntry {
	@ApiProperty({ description: "Monotonic sequence number", example: 42 })
	seq: number;

	@ApiProperty({ example: "2026-06-30T09:35:12.000Z" })
	ts: string;

	@ApiProperty({ type: AdminActorDto })
	actor: AdminActor;

	@ApiProperty({
		description: "Action key",
		example: "cert.revoke",
	})
	action: string;

	@ApiPropertyOptional({
		type: String,
		description: "Action target (serial / CN / token id)",
		example: "serial=1006",
		nullable: true,
	})
	target: string | null;

	@ApiProperty({
		description:
			"Sanitized parameters – never full private material or full tokens " +
			"(token ids are truncated to a prefix).",
		type: "object",
		additionalProperties: true,
		example: { serial: "1006", reason: "keyCompromise" },
	})
	params: Record<string, unknown>;

	@ApiProperty({ type: AdminActionResultDto })
	result: AdminActionResult;

	@ApiProperty({
		description: "SHA-256 hash of the previous entry (hash chain).",
		example:
			"0000000000000000000000000000000000000000000000000000000000000000",
	})
	prev_hash: string;

	@ApiProperty({
		description:
			"SHA-256 hash of this entry (covers all fields except hash).",
		example: "a1b2c3...",
	})
	hash: string;
}
