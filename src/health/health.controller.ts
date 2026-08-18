import { Controller, Get } from "@nestjs/common";
import {
	ApiOperation,
	ApiResponse,
	ApiServiceUnavailableResponse,
	ApiTags,
} from "@nestjs/swagger";
import { HealthCheck, HealthCheckService } from "@nestjs/terminus";

import { HealthCheckResponseDto } from "@/health/dto/health.dto";
import { HealthService } from "@/health/health.service.indicator";

@ApiTags("health")
@Controller("admin/health")
export class HealthController {
	constructor(
		private health: HealthCheckService,
		private healthService: HealthService
	) {}

	@Get()
	@HealthCheck()
	@ApiOperation({
		summary: "Check PKI system health",
		description:
			"Runs health checks on the PKI infrastructure components and returns a @nestjs/terminus-shaped response.\n\n" +
			"**Checks performed by `pki_infrastructure`:**\n" +
			"- CA index database is readable\n" +
			"- Hybrid CRL file exists and is non-empty\n" +
			"- CRL renewal script exists\n\n" +
			"Returns HTTP 200 when all checks pass, HTTP 503 when any check fails.",
	})
	@ApiResponse({
		status: 200,
		description: "All PKI health checks passed",
		type: HealthCheckResponseDto,
	})
	@ApiServiceUnavailableResponse({
		description:
			"One or more PKI health checks failed – system may be degraded",
		type: HealthCheckResponseDto,
	})
	check() {
		return this.health.check([
			() => this.healthService.isHealthy("pki_infrastructure"),
		]);
	}
}
