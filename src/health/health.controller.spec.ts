import { HealthCheckService } from "@nestjs/terminus";
import { Test, TestingModule } from "@nestjs/testing";

import { HealthController } from "@/health/health.controller";
import { HealthService } from "@/health/health.service.indicator";

describe("HealthController", () => {
	let controller: HealthController;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			controllers: [HealthController],
			providers: [
				{
					provide: HealthCheckService,
					useValue: { check: jest.fn() },
				},
				{
					provide: HealthService,
					useValue: { isHealthy: jest.fn() },
				},
			],
		}).compile();

		controller = module.get<HealthController>(HealthController);
	});

	it("should be defined", () => {
		expect(controller).toBeDefined();
	});
});
