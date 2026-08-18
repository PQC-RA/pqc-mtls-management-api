import { Module } from "@nestjs/common";

import { CrlController } from "@/crl/crl.controller";
import { CrlService } from "@/crl/crl.service";

@Module({
	controllers: [CrlController],
	providers: [CrlService],
})
export class CrlModule {}
