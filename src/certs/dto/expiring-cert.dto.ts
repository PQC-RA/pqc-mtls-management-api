import { ApiProperty } from "@nestjs/swagger";

import { CertEntryDto } from "@/certs/dto/cert-entry.dto";

/**
 * A certificate from `GET /admin/certs/expiring` – a lean index entry enriched
 * with the whole number of days remaining until expiry.
 */
export class ExpiringCertDto extends CertEntryDto {
	@ApiProperty({
		description:
			"Whole days until expiry (ceil of the remaining interval). May be 0 or negative for already-expired-but-still-valid-flagged entries.",
		type: Number,
		example: 12,
	})
	daysLeft: number;
}
