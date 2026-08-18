import { Module } from "@nestjs/common";

import { CertsModule } from "@/certs/certs.module";
import { MonitoringController } from "@/monitoring/monitoring.controller";
import { MonitoringService } from "@/monitoring/monitoring.service";

@Module({
	imports: [CertsModule],
	controllers: [MonitoringController],
	providers: [MonitoringService],
})
export class MonitoringModule {}
