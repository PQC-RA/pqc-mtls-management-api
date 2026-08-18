jest.mock("@/common/guards/jwt-auth.guard", () => ({
	JwtAuthGuard: class {
		canActivate() {
			return true;
		}
	},
}));

import { Test, TestingModule } from "@nestjs/testing";

import { AdminAuditController } from "@/admin-audit/admin-audit.controller";
import { AdminAuditService } from "@/admin-audit/admin-audit.service";
import { JwtAuthGuard } from "@/common/guards/jwt-auth.guard";

describe("AdminAuditController", () => {
	let controller: AdminAuditController;
	let service: jest.Mocked<AdminAuditService>;

	beforeEach(async () => {
		service = { query: jest.fn(), append: jest.fn() } as any;
		const module: TestingModule = await Test.createTestingModule({
			controllers: [AdminAuditController],
			providers: [{ provide: AdminAuditService, useValue: service }],
		})
			.overrideGuard(JwtAuthGuard)
			.useValue({ canActivate: () => true })
			.compile();
		controller = module.get(AdminAuditController);
	});

	it("delegates the query through to the service", async () => {
		const entries = [{ seq: 1 }] as any;
		service.query.mockResolvedValue(entries);
		const query = { event: "cert.revoke", limit: 10 };
		const result = await controller.getAdminActions(query);
		expect(result).toBe(entries);
		expect(service.query).toHaveBeenCalledWith(query);
	});
});
