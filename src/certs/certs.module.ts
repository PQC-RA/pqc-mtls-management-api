import { Module } from "@nestjs/common";

import { CertsController } from "@/certs/certs.controller";
import { CertsService } from "@/certs/certs.service";
import { IndexParserService } from "@/certs/index-parser.service";
import { TokenStoreService } from "@/certs/token-store.service";
import { EnrollHmacGuard } from "@/common/guards/enroll-hmac.guard";

@Module({
	controllers: [CertsController],
	providers: [
		CertsService,
		IndexParserService,
		TokenStoreService,
		EnrollHmacGuard,
	],
	exports: [CertsService],
})
export class CertsModule {}
