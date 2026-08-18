jest.mock("@/common/guards/jwt-auth.guard", () => ({
	JwtAuthGuard: class MockJwtAuthGuard {
		canActivate() {
			return true;
		}
	},
}));

import { Test, TestingModule } from "@nestjs/testing";

import { JwtAuthGuard } from "@/common/guards/jwt-auth.guard";
import { CrlController } from "@/crl/crl.controller";
import { CrlService } from "@/crl/crl.service";

const FAKE_CRL = "-----BEGIN X509 CRL-----\nMIIB...\n-----END X509 CRL-----\n";

describe("CrlController", () => {
	let controller: CrlController;
	let crlService: jest.Mocked<CrlService>;

	beforeEach(async () => {
		crlService = { getCrl: jest.fn(), renewCrl: jest.fn() } as any;

		const module: TestingModule = await Test.createTestingModule({
			controllers: [CrlController],
			providers: [{ provide: CrlService, useValue: crlService }],
		})
			.overrideGuard(JwtAuthGuard)
			.useValue({ canActivate: () => true })
			.compile();

		controller = module.get<CrlController>(CrlController);
	});

	it("should be defined", () => {
		expect(controller).toBeDefined();
	});

	it("getCrl delegates to service", async () => {
		crlService.getCrl.mockResolvedValue(FAKE_CRL);
		const result = await controller.getCrl();
		expect(result).toBe(FAKE_CRL);
	});

	it("renewCrl delegates to service", async () => {
		crlService.renewCrl.mockResolvedValue({ message: "CRL renewed" });
		const result = await controller.renewCrl();
		expect(result.message).toMatch(/renewed/i);
	});
});
