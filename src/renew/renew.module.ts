import { Module } from "@nestjs/common";

import { CertsModule } from "@/certs/certs.module";
import { RenewAttestGuard } from "@/renew/renew-attest.guard";
import { RenewController } from "@/renew/renew.controller";
import { RenewService } from "@/renew/renew.service";

@Module({
	imports: [CertsModule],
	controllers: [RenewController],
	providers: [RenewService, RenewAttestGuard],
	exports: [RenewService],
})
export class RenewModule {}
