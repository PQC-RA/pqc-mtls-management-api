jest.mock("@/common/guards/jwt-auth.guard", () => ({
	JwtAuthGuard: class MockJwtAuthGuard {
		canActivate() {
			return true;
		}
	},
}));

import { Test, TestingModule } from "@nestjs/testing";

import { JwtAuthGuard } from "@/common/guards/jwt-auth.guard";
import { PolicyController } from "@/policy/policy.controller";
import { PolicyService } from "@/policy/policy.service";

const SAMPLE_ROUTES = {
	clients: {
		"service-A": {
			backend: "http://localhost:8081",
			rate_limit: { rps: 100, burst: 200 },
		},
	},
	defaults: { rate_limit: { rps: 50, burst: 100 }, deny_action: "reject" },
	policy: {
		unknown_cn_action: "reject",
		expired_cert_action: "reject",
		expiry_warning_days: 30,
		expiry_critical_days: 7,
		require_valid_verify: true,
	},
};

describe("PolicyController", () => {
	let controller: PolicyController;
	let policyService: jest.Mocked<PolicyService>;

	beforeEach(async () => {
		policyService = {
			getRoutes: jest.fn(),
			updateRoutes: jest.fn(),
			getClientPolicy: jest.fn(),
			updateClientPolicy: jest.fn(),
			deleteClientPolicy: jest.fn(),
		} as any;

		const module: TestingModule = await Test.createTestingModule({
			controllers: [PolicyController],
			providers: [{ provide: PolicyService, useValue: policyService }],
		})
			.overrideGuard(JwtAuthGuard)
			.useValue({ canActivate: () => true })
			.compile();

		controller = module.get<PolicyController>(PolicyController);
	});

	it("should be defined", () => {
		expect(controller).toBeDefined();
	});

	it("getRoutes delegates to service", async () => {
		policyService.getRoutes.mockResolvedValue(SAMPLE_ROUTES as never);
		const result = await controller.getRoutes();
		expect(result).toMatchObject(SAMPLE_ROUTES);
	});

	it("updateRoutes passes body to service and returns response", async () => {
		policyService.updateRoutes.mockResolvedValue({
			message: "Routes updated and Nginx reloaded successfully",
		});
		const result = await controller.updateRoutes(SAMPLE_ROUTES as never);
		// updateRoutes returns a union – the apply confirmation, or the dry-run
		// result when ?dryRun is set. Narrow on the discriminant rather than
		// casting: this asserts the no-dryRun call really produced the apply
		// shape, so a controller that returned the wrong one would fail here
		// instead of being silently cast past.
		if (!("message" in result)) {
			throw new Error(
				"expected the apply-confirmation shape from updateRoutes() without ?dryRun, " +
					`got the dry-run shape: ${JSON.stringify(result)}`
			);
		}
		expect(result.message).toMatch(/updated/i);
		expect(policyService.updateRoutes).toHaveBeenCalledWith(SAMPLE_ROUTES);
	});

	it("getClientPolicy delegates to service with CN", async () => {
		const fakePolicy = { backend: "http://localhost:8081" };
		policyService.getClientPolicy.mockResolvedValue(fakePolicy as never);
		const result = await controller.getClientPolicy("service-A");
		expect(result).toBe(fakePolicy);
		expect(policyService.getClientPolicy).toHaveBeenCalledWith("service-A");
	});

	it("updateClientPolicy passes CN and body to service", async () => {
		const policy = { backend: "http://localhost:9090" };
		policyService.updateClientPolicy.mockResolvedValue({
			cn: "service-B",
			policy,
		} as never);
		const result = await controller.updateClientPolicy(
			"service-B",
			policy as never
		);
		expect(result.cn).toBe("service-B");
		expect(policyService.updateClientPolicy).toHaveBeenCalledWith(
			"service-B",
			policy
		);
	});

	it("deleteClientPolicy delegates to service with CN", async () => {
		policyService.deleteClientPolicy.mockResolvedValue({
			message: "Policy deleted",
		});
		const result = await controller.deleteClientPolicy("service-A");
		expect(result.message).toMatch(/deleted/i);
		expect(policyService.deleteClientPolicy).toHaveBeenCalledWith(
			"service-A"
		);
	});
});
