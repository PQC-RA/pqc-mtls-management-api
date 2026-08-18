jest.mock("@/common/guards/jwt-auth.guard", () => ({
	JwtAuthGuard: class MockJwtAuthGuard {
		canActivate() {
			return true;
		}
	},
}));

import { Test, TestingModule } from "@nestjs/testing";

import { JwtAuthGuard } from "@/common/guards/jwt-auth.guard";
import { MonitoringController } from "@/monitoring/monitoring.controller";
import { MonitoringService } from "@/monitoring/monitoring.service";

describe("MonitoringController", () => {
	let controller: MonitoringController;
	let monitoringService: jest.Mocked<MonitoringService>;

	beforeEach(async () => {
		monitoringService = { getMetrics: jest.fn() } as any;

		const module: TestingModule = await Test.createTestingModule({
			controllers: [MonitoringController],
			providers: [
				{ provide: MonitoringService, useValue: monitoringService },
			],
		})
			.overrideGuard(JwtAuthGuard)
			.useValue({ canActivate: () => true })
			.compile();

		controller = module.get<MonitoringController>(MonitoringController);
	});

	it("should be defined", () => {
		expect(controller).toBeDefined();
	});

	it("getMetrics delegates entirely to MonitoringService", async () => {
		const fakeMetrics = {
			compliance: "NIS2 Art. 21(2)(g)",
			timestamp: new Date().toISOString(),
			certs_total: { valid: 3, revoked: 1, expired: 0, total: 4 },
			certs_expiring: {
				within_30d: 1,
				within_14d: 0,
				within_7d: 0,
				details_30d: [],
			},
			crl_age_seconds: 3600,
			crl_status: "ok" as const,
			audit_log_entries: 42,
		};
		monitoringService.getMetrics.mockResolvedValue(fakeMetrics);

		const result = await controller.getMetrics();
		expect(result).toBe(fakeMetrics);
		expect(monitoringService.getMetrics).toHaveBeenCalledTimes(1);
	});
});
