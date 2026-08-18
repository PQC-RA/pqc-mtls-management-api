import { Controller, Get, Param, UseGuards } from "@nestjs/common";
import {
	ApiForbiddenResponse,
	ApiParam,
	ApiTags,
	ApiUnauthorizedResponse,
} from "@nestjs/swagger";

import { CertLookupService } from "@/cert-lookup/cert-lookup.service";
import {
	CertLookupResultDto,
	FingerprintParamDto,
} from "@/cert-lookup/dto/cert-lookup-result.dto";
import { ApiGet } from "@/common/decorators/api-responses.decorator";
import { Public } from "@/common/decorators/public.decorator";
import { LookupTokenGuard } from "@/common/guards/lookup-token.guard";

/**
 * Certificate-by-fingerprint lookup – a backend-facing route, deliberately
 * NOT under /admin/* (that prefix is gated by the ADMIN_CERT_FINGERPRINTS
 * console allowlist, the wrong trust model for arbitrary backends calling in
 * with their own per-request Token 2).
 *
 * @Public() opts this controller out of the GLOBAL JwtAuthGuard (which
 * expects an admin-allowlisted Authorization Bearer token); LookupTokenGuard
 * is the real gate here, verifying the dedicated X-PQC-Lookup-Token header
 * instead. See the end-to-end token acquisition flow.
 */
@ApiTags("cert-lookup")
@Controller("certs")
export class CertLookupController {
	constructor(private readonly certLookupService: CertLookupService) {}

	@Public()
	@UseGuards(LookupTokenGuard)
	@Get("by-fingerprint/:fpr")
	@ApiForbiddenResponse({
		description:
			"Token's fpr claim does not match the requested :fpr path parameter.",
	})
	@ApiUnauthorizedResponse({
		description:
			"Missing/invalid/expired X-PQC-Lookup-Token, or wrong kid/audience.",
	})
	@ApiParam({
		name: "fpr",
		description:
			"SHA-256 fingerprint (64 hex characters) of the certificate to retrieve.",
		example:
			"ec8f048a93ca3a24448727644366e6afe7b56f03fc62340bd3b9dbfd55673e7f",
	})
	@ApiGet({
		summary: "Fetch an issued certificate by its SHA-256 fingerprint",
		description:
			"Backend-facing lookup, authorized by Token 2 (`X-PQC-Lookup-Token`, " +
			"aud=pqc-cert-lookup, kid=lookup-v1) – a gateway-minted JWT distinct " +
			"from the per-request attestation token (Authorization / Token 1). " +
			"The token's own `fpr` claim must match the requested `:fpr` exactly.",
		type: CertLookupResultDto,
		notFound: "No certificate found for the given fingerprint",
	})
	async getByFingerprint(
		@Param() params: FingerprintParamDto
	): Promise<CertLookupResultDto> {
		return this.certLookupService.getByFingerprint(params.fpr);
	}
}
