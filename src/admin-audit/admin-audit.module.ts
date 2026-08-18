import { Global, Module } from "@nestjs/common";

import { AdminAuditController } from "@/admin-audit/admin-audit.controller";
import { AdminAuditService } from "@/admin-audit/admin-audit.service";

/**
 * Global so AdminAuditService can be injected anywhere (e.g. CertsService
 * records the public enroll directly) without re-importing the module, and so
 * the global AdminAuditInterceptor can resolve it.
 */
@Global()
@Module({
	controllers: [AdminAuditController],
	providers: [AdminAuditService],
	exports: [AdminAuditService],
})
export class AdminAuditModule {}
