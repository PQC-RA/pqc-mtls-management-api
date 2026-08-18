import { Controller, Get, Post } from "@nestjs/common";
import {
	ApiNotFoundResponse,
	ApiOperation,
	ApiProduces,
	ApiResponse,
} from "@nestjs/swagger";

import { AuditAction } from "@/admin-audit/decorators/audit-action.decorator";
import { AdminController } from "@/common/decorators/admin-controller.decorator";
import {
	ApiErrorResponses,
	ApiPost,
} from "@/common/decorators/api-responses.decorator";
import { Roles } from "@/common/decorators/roles.decorator";
import { CrlService } from "@/crl/crl.service";
import { CrlRenewResponseDto } from "@/crl/dto/crl.dto";

@AdminController("crl")
@Controller("admin/crl")
export class CrlController {
	constructor(private readonly crlService: CrlService) {}

	@Get()
	@ApiProduces("text/plain")
	@ApiOperation({
		summary:
			"Retrieve the current combined Certificate Revocation List (CRL)",
		description:
			"Returns the raw PEM content of `/etc/pki/pqc-ca/hybrid-combined-crl.pem`, which contains CRLs from all 4 CA chains:\n\n" +
			"1. ML-DSA-65 (PQ) Intermediate CA\n" +
			"2. ML-DSA-65 (PQ) Root CA\n" +
			"3. Ed25519 Intermediate CA\n" +
			"4. Ed25519 Root CA\n\n" +
			"The CRL is regenerated daily by cron via `/usr/local/bin/pqc-crl-renew.sh`. Use `POST /admin/crl/renew` to force immediate renewal.",
	})
	// Raw decorators (not the ApiGet composite) so the 200 carries an explicit
	// text/plain string schema – the composite emits a typeless application/json
	// 200 that would clobber this.
	@ApiResponse({
		status: 200,
		description: "CRL PEM content (4 concatenated X.509 CRL blocks)",
		content: {
			"text/plain": {
				schema: {
					type: "string",
					example:
						"-----BEGIN X509 CRL-----\nMIIB...base64...\n-----END X509 CRL-----\n" +
						"-----BEGIN X509 CRL-----\nMIIB...base64...\n-----END X509 CRL-----\n",
				},
			},
		},
	})
	@ApiNotFoundResponse({
		description:
			"hybrid-combined-crl.pem not found – run POST /admin/crl/renew first",
	})
	@ApiErrorResponses()
	async getCrl(): Promise<string> {
		return this.crlService.getCrl();
	}

	@Post("renew")
	@Roles("admin")
	@AuditAction({ action: "crl.renew" })
	@ApiPost({
		summary: "Force immediate CRL renewal",
		description:
			"Executes `/usr/local/bin/pqc-crl-renew.sh`, which:\n\n" +
			"1. Generates fresh intermediate CRLs (daily schedule, validity 7 days)\n" +
			"2. Generates fresh root CRLs if expired (every 90 days, validity 180 days)\n" +
			"3. Combines all 4 CRLs into the hybrid PEM file\n" +
			"4. Syncs CRL files to `/var/www/pki/` for HTTP distribution\n" +
			"5. Reloads Nginx\n\n" +
			"Compliant with eIDAS Art. 24(2)(h) and ETSI EN 319 411-1 §6.2.4.",
		type: CrlRenewResponseDto,
	})
	async renewCrl(): Promise<CrlRenewResponseDto> {
		return this.crlService.renewCrl();
	}
}
