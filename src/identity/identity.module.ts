import { Module } from "@nestjs/common";

import { WhoamiController } from "@/identity/whoami.controller";

@Module({
	controllers: [WhoamiController],
})
export class IdentityModule {}
