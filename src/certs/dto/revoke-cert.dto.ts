import { ApiProperty } from "@nestjs/swagger";
import { IsEnum, IsNotEmpty, IsString, Matches } from "class-validator";

/**
 * Allowed CRLReason codes for TLS end-entity certificates.
 *
 * Per Mozilla Root Store Policy §6.1.1 and CA/B Forum Baseline Requirements §7.2.2,
 * only the reasons below may appear in the CRL reasonCode extension.
 * Listed in priority order – if multiple apply, use the highest.
 *
 * Banned for TLS end-entity certs (MUST NOT appear in CRL reasonCode):
 *   CACompromise (#2)     – CA/intermediate certs only
 *   certificateHold (#6)  – BR §7.2.2 explicitly bans it
 *   removeFromCRL (#8)    – delta-CRL only; N/A since certificateHold is banned
 *   aACompromise (#10)    – attribute certificates only
 *
 * When reason is `unspecified`, the CRL reasonCode extension MUST be omitted
 * (RFC 5280 §5.3.1, BR §7.2.2).
 */
export enum RevocationReason {
	/** CRLReason #0 – no specific reason; reasonCode extension omitted from CRL */
	Unspecified = "unspecified",
	/** CRLReason #1 – private key compromise (highest priority) */
	KeyCompromise = "keyCompromise",
	/** CRLReason #3 – subject name or org info changed */
	AffiliationChanged = "affiliationChanged",
	/** CRLReason #4 – certificate replaced (re-key, compliance, domain re-validation) */
	Superseded = "superseded",
	/** CRLReason #5 – domain no longer owned or site shut down */
	CessationOfOperation = "cessationOfOperation",
	/** CRLReason #9 – subscriber infraction (CA-operator use only, not subscriber-facing) */
	PrivilegeWithdrawn = "privilegeWithdrawn",
}

export class RevokeCertDto {
	@ApiProperty({
		description:
			"Hex serial number of the certificate to revoke. Use the value as it appears in GET /admin/certs (e.g. '1006'). Also accepts 0x-prefixed hex (0x1006) or decimal with prefix (dec:4102).",
		example: "1006",
	})
	@IsString()
	@IsNotEmpty()
	@Matches(/^(0x)?[0-9A-Fa-f]{1,40}$|^dec:\d{1,13}$/, {
		message:
			"serial must be hexadecimal (e.g. '1006', '0x1006') or decimal-prefixed (e.g. 'dec:4102')",
	})
	serial: string;

	@ApiProperty({
		description:
			"RFC 5280 CRLReason code per Mozilla Root Store Policy §6.1.1. " +
			"Priority order: keyCompromise > privilegeWithdrawn > cessationOfOperation > affiliationChanged > superseded. " +
			"When `unspecified`, the CRL reasonCode extension is omitted as required by BR §7.2.2.",
		enum: RevocationReason,
		enumName: "RevocationReason",
		example: RevocationReason.KeyCompromise,
	})
	@IsEnum(RevocationReason)
	reason: RevocationReason;
}

export class RevokeCertResponseDto {
	@ApiProperty({
		description: "Human-readable confirmation message",
		example: "Certificate 1006 revoked successfully and CRL regenerated.",
	})
	message: string;
}
