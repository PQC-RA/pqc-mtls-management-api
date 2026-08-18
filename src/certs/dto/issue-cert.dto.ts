import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString, Matches } from "class-validator";

/**
 * Request body for signing a CSR.
 * The client generates their own ML-DSA-65 key pair and CSR, then submits only the CSR.
 * The private key never leaves the client device.
 */
export class SignCsrDto {
	@ApiProperty({
		description:
			"PEM-encoded Certificate Signing Request (CSR). " +
			"Generate with: `openssl genpkey -algorithm ML-DSA-65 -out client.key && " +
			"openssl req -new -key client.key -out client.csr -subj '/CN=my-service/O=MyOrg'`",
		example:
			"-----BEGIN CERTIFICATE REQUEST-----\nMIIB...base64...\n-----END CERTIFICATE REQUEST-----\n",
	})
	@IsString()
	@IsNotEmpty()
	@Matches(
		/-----BEGIN CERTIFICATE REQUEST-----[\s\S]+-----END CERTIFICATE REQUEST-----/,
		{
			message:
				"csr must be a valid PEM-encoded Certificate Signing Request",
		}
	)
	csr: string;

	@ApiProperty({
		description:
			"Single-use enrollment token issued by an admin via POST /admin/certs/enrollment-tokens. " +
			"Always required. The token carries a CN constraint – the CSR subject CN must match " +
			"the CN the admin specified when creating the token. A mismatched CN returns 403 " +
			"without consuming the token.",
		example: "enroll_abc123xyz",
	})
	@IsString()
	@IsNotEmpty()
	enrollmentToken: string;
}

export class SignCsrResponseDto {
	@ApiProperty({
		description:
			"PEM-encoded ML-DSA-65 certificate signed by the intermediate CA",
		example:
			"-----BEGIN CERTIFICATE-----\nMIIF...base64...\n-----END CERTIFICATE-----\n",
	})
	certificate: string;

	@ApiProperty({
		description:
			"Certificate serial number (uppercase hex, as stored in CA index)",
		example: "1007",
	})
	serialNumber: string;

	@ApiProperty({
		description: "Certificate expiry date (ISO 8601)",
		example: "2027-03-10T06:00:00.000Z",
	})
	expiresAt: string;
}
