import {
	Body,
	Controller,
	HttpCode,
	HttpStatus,
	Ip,
	Post,
	Req,
	UseGuards,
} from "@nestjs/common";
import { ApiBody, ApiOperation, ApiTags } from "@nestjs/swagger";

import { Public } from "@/common/decorators/public.decorator";
import { RenewAttestGuard } from "@/renew/renew-attest.guard";
import type { RenewRequest } from "@/renew/renew-attest.guard";
import { RenewDto, RenewResponseDto } from "@/renew/renew.dto";
import { RenewService } from "@/renew/renew.service";

/**
 * POST /api/renew: reached only through the gateway's `location = /renew` on
 * the mTLS listener, which attests the client certificate (RenewAttestGuard).
 * Outside /api/admin/ and accepts no JWT: the client is not an admin.
 * With RENEWAL_ENABLED unset the guard answers 404.
 */
@ApiTags("renewal")
@Controller("renew")
export class RenewController {
	constructor(private readonly renewService: RenewService) {}

	@Public()
	@UseGuards(RenewAttestGuard)
	@Post()
	@HttpCode(HttpStatus.CREATED)
	@ApiOperation({
		summary:
			"Renew the presented client certificate with a new key (mTLS, EST-style re-enrollment)",
	})
	@ApiBody({ type: RenewDto })
	async renew(
		@Req() req: RenewRequest,
		@Body() dto: RenewDto,
		@Ip() ip: string
	): Promise<RenewResponseDto> {
		return this.renewService.renew(req.renewAttestation!, dto, ip);
	}
}
