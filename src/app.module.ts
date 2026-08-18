import { Module } from "@nestjs/common";
import { APP_GUARD, APP_INTERCEPTOR } from "@nestjs/core";
import { OpenTelemetryModule } from "nestjs-otel";

import { AdminAuditInterceptor } from "@/admin-audit/admin-audit.interceptor";
import { AdminAuditModule } from "@/admin-audit/admin-audit.module";
import { AuditModule } from "@/audit/audit.module";
import { CertLookupModule } from "@/cert-lookup/cert-lookup.module";
import { CertsModule } from "@/certs/certs.module";
import { CsrfGuard } from "@/common/guards/csrf.guard";
import { JwtAuthGuard } from "@/common/guards/jwt-auth.guard";
import { RolesGuard } from "@/common/guards/roles.guard";
import { CrlModule } from "@/crl/crl.module";
import { HealthModule } from "@/health/health.module";
import { IdentityModule } from "@/identity/identity.module";
import { MonitoringModule } from "@/monitoring/monitoring.module";
import { PolicyModule } from "@/policy/policy.module";

@Module({
	imports: [
		OpenTelemetryModule.forRoot(),
		CertsModule,
		CrlModule,
		HealthModule,
		PolicyModule,
		AuditModule,
		MonitoringModule,
		AdminAuditModule,
		IdentityModule,
		CertLookupModule,
	],
	providers: [
		// Global guards run in registration order. The chain is:
		//   1. JwtAuthGuard  – authenticate + attach req.adminIdentity, or @Public.
		//   2. RolesGuard    – coarse RBAC (admin vs auditor) from the resolved role.
		//   3. CsrfGuard     – anti-CSRF on mutating JWT-protected routes.
		// Every route is protected by default; opt out explicitly with @Public().
		// This makes "unauthenticated by accident" impossible.
		{
			provide: APP_GUARD,
			useClass: JwtAuthGuard,
		},
		{
			provide: APP_GUARD,
			useClass: RolesGuard,
		},
		{
			provide: APP_GUARD,
			useClass: CsrfGuard,
		},
		// Global interceptor that records control-plane mutations to the
		// tamper-evident admin-action audit log (keyed off @AuditAction()).
		{
			provide: APP_INTERCEPTOR,
			useClass: AdminAuditInterceptor,
		},
	],
})
export class AppModule {}
