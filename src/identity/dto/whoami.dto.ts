import { ApiProperty } from "@nestjs/swagger";

import type { AdminRole } from "@/common/auth/cert-roles";

export class WhoamiDto {
	@ApiProperty({
		description: "JWT subject – the authenticated client's certificate CN.",
		example: "ops-admin",
	})
	sub: string;

	@ApiProperty({
		description:
			"Certificate SHA-256 fingerprint (lowercase hex, no colons) – the " +
			"exact form pasted into ADMIN_CERT_FINGERPRINTS.",
		example:
			"1c2ba075293fcd68e241cfcedf337ff59bc8126b24c2af07c60f319a38e1a0d8",
	})
	fpr: string;

	@ApiProperty({
		description:
			"Server-resolved role from the fingerprint allowlists (NOT a JWT claim).",
		enum: ["admin", "auditor"],
		example: "admin",
	})
	role: AdminRole;
}
