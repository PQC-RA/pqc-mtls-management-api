import { Module } from "@nestjs/common";

import { AuditController } from "@/audit/audit.controller";
import { AuditService } from "@/audit/audit.service";

@Module({
	controllers: [AuditController],
	providers: [AuditService],
})
export class AuditModule {}
