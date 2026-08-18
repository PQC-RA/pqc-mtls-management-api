import { ApiProperty } from "@nestjs/swagger";

export class CrlResponseDto {
	@ApiProperty({
		description:
			"PEM-encoded hybrid combined CRL containing all 4 CA chains: ML-DSA-65 intermediate, ML-DSA-65 root, Ed25519 intermediate, Ed25519 root",
		example:
			"-----BEGIN X509 CRL-----\nMIIB...base64...\n-----END X509 CRL-----\n-----BEGIN X509 CRL-----\nMIIB...base64...\n-----END X509 CRL-----\n",
	})
	crl: string;
}

export class CrlRenewResponseDto {
	@ApiProperty({
		description: "Confirmation message from the CRL renewal script",
		example: "CRL renewed successfully",
	})
	message: string;
}
