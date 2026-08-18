jest.mock("@/common/guards/jwt-auth.guard", () => ({
	JwtAuthGuard: class MockJwtAuthGuard {
		canActivate() {
			return true;
		}
	},
}));

import { Test, TestingModule } from "@nestjs/testing";

import { AuditController } from "@/audit/audit.controller";
import { AuditService } from "@/audit/audit.service";
import { JwtAuthGuard } from "@/common/guards/jwt-auth.guard";

describe("AuditController", () => {
	let controller: AuditController;
	let auditService: jest.Mocked<AuditService>;

	beforeEach(async () => {
		auditService = { getAuditLogs: jest.fn() } as any;

		const module: TestingModule = await Test.createTestingModule({
			controllers: [AuditController],
			providers: [{ provide: AuditService, useValue: auditService }],
		})
			.overrideGuard(JwtAuthGuard)
			.useValue({ canActivate: () => true })
			.compile();

		controller = module.get<AuditController>(AuditController);
	});

	it("should be defined", () => {
		expect(controller).toBeDefined();
	});

	it("getAuditLogs delegates to service with the provided query", async () => {
		const entries = [
			{ timestamp: "2026-03-10T00:00:00Z", status: 200 },
		] as any;
		auditService.getAuditLogs.mockResolvedValue(entries);

		const query = { lines: 50 };
		const result = await controller.getAuditLogs(query);
		expect(result).toEqual(entries);
		expect(auditService.getAuditLogs).toHaveBeenCalledWith(query);
	});

	it("passes filter params through to the service", async () => {
		auditService.getAuditLogs.mockResolvedValue([]);
		const query = { event: "block", cn: "service-A", offset: 0, limit: 20 };
		await controller.getAuditLogs(query);
		expect(auditService.getAuditLogs).toHaveBeenCalledWith(query);
	});
});
