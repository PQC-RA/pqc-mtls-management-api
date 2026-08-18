import { Controller, Get } from "@nestjs/common";

import { AdminController } from "@/common/decorators/admin-controller.decorator";
import { ApiGet } from "@/common/decorators/api-responses.decorator";
import { PkiMetricsDto } from "@/monitoring/dto/pki-metrics.dto";
import { MonitoringService, PkiMetrics } from "@/monitoring/monitoring.service";

@AdminController("metrics")
@Controller("admin/metrics")
export class MonitoringController {
	constructor(private readonly monitoringService: MonitoringService) {}

	@Get()
	@ApiGet({
		summary: "Prometheus-compatible PKI metrics (NIS2 Art. 21(2)(g))",
		description:
			"Returns PKI infrastructure metrics for monitoring and security effectiveness assessment.\n\n" +
			"**Metrics included:**\n" +
			"- `certs_total` – total certificates by status (V/R/E)\n" +
			"- `certs_expiring_30d` – valid certs expiring within 30 days\n" +
			"- `certs_expiring_14d` – valid certs expiring within 14 days (CRITICAL)\n" +
			"- `certs_expiring_7d` – valid certs expiring within 7 days (URGENT)\n" +
			"- `crl_age_seconds` – seconds since the CRL was last modified\n" +
			"- `audit_log_entries` – total lines in the data-plane audit log\n\n" +
			"Compliant with NIS2 Art. 21(2)(g) – assessing effectiveness of cybersecurity measures.",
		type: PkiMetricsDto,
	})
	async getMetrics(): Promise<PkiMetrics> {
		return this.monitoringService.getMetrics();
	}
}
