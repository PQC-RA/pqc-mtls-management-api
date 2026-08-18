import { Module } from "@nestjs/common";

import { PolicyController } from "@/policy/policy.controller";
import { PolicyService } from "@/policy/policy.service";

@Module({
	controllers: [PolicyController],
	providers: [PolicyService],
})
export class PolicyModule {}
