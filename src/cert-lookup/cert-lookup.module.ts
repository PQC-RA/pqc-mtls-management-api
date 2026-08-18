import { Module } from "@nestjs/common";

import { CertLookupController } from "@/cert-lookup/cert-lookup.controller";
import { CertLookupService } from "@/cert-lookup/cert-lookup.service";
import { LookupTokenGuard } from "@/common/guards/lookup-token.guard";

@Module({
	controllers: [CertLookupController],
	providers: [CertLookupService, LookupTokenGuard],
})
export class CertLookupModule {}
