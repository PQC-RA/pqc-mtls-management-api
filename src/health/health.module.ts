import { Module } from "@nestjs/common";
import { TerminusModule } from "@nestjs/terminus";

import { HealthController } from "@/health/health.controller";
import { HealthService } from "@/health/health.service.indicator";

@Module({
	imports: [TerminusModule],
	controllers: [HealthController],
	providers: [HealthService],
})
export class HealthModule {}
