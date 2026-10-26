import { ApiProperty } from "@nestjs/swagger";
import { Type } from "class-transformer";
import {
	IsInt,
	IsNotEmpty,
	IsString,
	Matches,
	MaxLength,
	Min,
	ValidateNested,
} from "class-validator";

export class ProofOfPossessionDto {
	@ApiProperty({
		description:
			"Unix time in seconds at which the proof was made (±120 s)",
	})
	@IsInt()
	@Min(0)
	timestamp: number;

	@ApiProperty({
		description:
			"Base64 ML-DSA-65 signature by the CURRENT private key over the UTF-8 string " +
			"`pqc-renew-v1\\n<sha256 hex of the CSR DER>\\n<current serial, uppercase hex>\\n<timestamp>`",
	})
	@IsString()
	@IsNotEmpty()
	@MaxLength(8192)
	@Matches(/^[A-Za-z0-9+/]+={0,2}$/)
	signature: string;
}

export class RenewDto {
	@ApiProperty({
		description:
			"PEM CSR signed by the NEW ML-DSA-65 key; subject equal to the current certificate's",
	})
	@IsString()
	@IsNotEmpty()
	@MaxLength(32768)
	@Matches(
		/-----BEGIN CERTIFICATE REQUEST-----[\s\S]+-----END CERTIFICATE REQUEST-----/
	)
	csr: string;

	@ApiProperty({ type: ProofOfPossessionDto })
	@ValidateNested()
	@Type(() => ProofOfPossessionDto)
	pop: ProofOfPossessionDto;
}

export class RenewResponseDto {
	@ApiProperty() certificate: string;
	@ApiProperty() serialNumber: string;
	@ApiProperty() notBefore: string;
	@ApiProperty() expiresAt: string;
	@ApiProperty({ required: false }) replay?: boolean;
}
