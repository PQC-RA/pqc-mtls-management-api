jest.mock("fs");
// The index database and combined CRL are no longer visible to this process –
// it stopped mounting the CA tree and asks the pqc-ca-custodian sidecar instead.
// Only the CRL-renew script is still an fs check, so the fs mock stays for that.
jest.mock("@/common/ca-custodian.util");
import * as fs from "fs";

import { HealthIndicatorService } from "@nestjs/terminus";
import { Test, TestingModule } from "@nestjs/testing";

import { checkCustodianHealth } from "@/common/ca-custodian.util";
import { HealthService } from "@/health/health.service.indicator";

const existsSync = jest.mocked(fs.existsSync);
const custodianHealth = jest.mocked(checkCustodianHealth);

const mockIndicator = {
	up: jest.fn((info?) => ({ pki_infrastructure: { status: "up", ...info } })),
	down: jest.fn((info?) => ({
		pki_infrastructure: { status: "down", ...info },
	})),
};

const mockHealthIndicatorService = {
	check: jest.fn(() => mockIndicator),
};

describe("HealthService", () => {
	let service: HealthService;

	beforeEach(async () => {
		jest.resetAllMocks();

		// Re-assign implementations after resetAllMocks clears them
		mockIndicator.up.mockImplementation((info?) => ({
			pki_infrastructure: { status: "up", ...info },
		}));
		mockIndicator.down.mockImplementation((info?) => ({
			pki_infrastructure: { status: "down", ...info },
		}));
		mockHealthIndicatorService.check.mockReturnValue(mockIndicator);

		const module: TestingModule = await Test.createTestingModule({
			providers: [
				HealthService,
				{
					provide: HealthIndicatorService,
					useValue: mockHealthIndicatorService,
				},
			],
		}).compile();
		service = module.get<HealthService>(HealthService);
	});

	it("should be defined", () => {
		expect(service).toBeDefined();
	});

	it("reports up when the custodian is healthy and the renew script exists", async () => {
		custodianHealth.mockResolvedValue({
			ok: true,
			indexOk: true,
			crlOk: true,
		});
		existsSync.mockReturnValue(true);

		const result = await service.isHealthy("pki_infrastructure");
		expect(result.pki_infrastructure.status).toBe("up");
	});

	it("reports down when the custodian says the CA index is unreachable", async () => {
		custodianHealth.mockResolvedValue({ ok: false, indexOk: false });
		existsSync.mockReturnValue(true);

		await service.isHealthy("pki_infrastructure");
		expect(mockIndicator.down).toHaveBeenCalledWith(
			expect.objectContaining({ caDatabase: expect.any(String) })
		);
	});

	it("reports down when the custodian says the CRL is unreachable", async () => {
		custodianHealth.mockResolvedValue({ ok: false, crlOk: false });
		existsSync.mockReturnValue(true);

		await service.isHealthy("pki_infrastructure");
		expect(mockIndicator.down).toHaveBeenCalledWith(
			expect.objectContaining({ crl: expect.any(String) })
		);
	});

	it("returns down status when renewal script is missing", async () => {
		custodianHealth.mockResolvedValue({
			ok: true,
			indexOk: true,
			crlOk: true,
		});
		existsSync.mockImplementation((p: fs.PathLike) => {
			return !String(p).includes("pqc-crl-renew.sh");
		});

		await service.isHealthy("pki_infrastructure");
		expect(mockIndicator.down).toHaveBeenCalledWith(
			expect.objectContaining({ renewScript: expect.any(String) })
		);
	});

	it("returns down on unexpected errors", async () => {
		existsSync.mockImplementation(() => {
			throw new Error("filesystem exploded");
		});

		await service.isHealthy("pki_infrastructure");
		expect(mockIndicator.down).toHaveBeenCalledWith(
			expect.objectContaining({ error: expect.any(String) })
		);
	});
});
