jest.mock("fs");
// CRL age comes from the pqc-ca-custodian sidecar's mtimeMs, not statSync – this
// process no longer mounts the CA tree. The audit log is still a local read, so
// the fs mock stays for that.
jest.mock("@/common/ca-custodian.util");
import * as fs from "fs";

import { Test, TestingModule } from "@nestjs/testing";

import { CertsService } from "@/certs/certs.service";
import { fetchCrlViaCustodian } from "@/common/ca-custodian.util";
import { MonitoringService } from "@/monitoring/monitoring.service";

const fetchCrl = jest.mocked(fetchCrlViaCustodian);
const readFileSync = jest.mocked(fs.readFileSync);

const now = Date.now();
const msPerDay = 24 * 60 * 60 * 1000;

function makeCert(status: "V" | "R" | "E", daysFromNow: number) {
	return {
		status,
		serialNumber: "1000",
		subject: "/CN=test",
		expirationDate: new Date(now + daysFromNow * msPerDay),
	};
}

describe("MonitoringService", () => {
	let service: MonitoringService;
	let certsService: jest.Mocked<Pick<CertsService, "getAllCertificates">>;

	beforeEach(async () => {
		jest.resetAllMocks();
		certsService = { getAllCertificates: jest.fn() };

		const module: TestingModule = await Test.createTestingModule({
			providers: [
				MonitoringService,
				{ provide: CertsService, useValue: certsService },
			],
		}).compile();
		service = module.get<MonitoringService>(MonitoringService);
	});

	it("should be defined", () => {
		expect(service).toBeDefined();
	});

	// ── getMetrics ───────────────────────────────────────────────────────────────

	describe("getMetrics", () => {
		it("returns correct cert totals and expiry buckets", async () => {
			certsService.getAllCertificates.mockResolvedValue([
				makeCert("V", 5), // within 7d
				makeCert("V", 10), // within 14d
				makeCert("V", 25), // within 30d
				makeCert("V", 60), // healthy
				makeCert("R", -1), // revoked
				makeCert("E", -1), // expired
			] as never);

			fetchCrl.mockResolvedValue({
				content: "",
				mtimeMs: now - 3600_000,
			});
			readFileSync.mockReturnValue("line1\nline2\n" as never);

			const metrics = await service.getMetrics();

			expect(metrics.certs_total.total).toBe(6);
			expect(metrics.certs_total.valid).toBe(4);
			expect(metrics.certs_total.revoked).toBe(1);
			expect(metrics.certs_total.expired).toBe(1);
			expect(metrics.certs_expiring.within_7d).toBe(1);
			expect(metrics.certs_expiring.within_14d).toBe(2);
			expect(metrics.certs_expiring.within_30d).toBe(3);
			expect(metrics.certs_expiring.details_30d).toHaveLength(3);
		});

		it("marks CRL as ok when age < 48h", async () => {
			certsService.getAllCertificates.mockResolvedValue([]);
			fetchCrl.mockResolvedValue({
				content: "",
				mtimeMs: now - 3600_000,
			});
			readFileSync.mockReturnValue("" as never);

			const metrics = await service.getMetrics();
			expect(metrics.crl_status).toBe("ok");
		});

		it("marks CRL as stale when age > 48h", async () => {
			certsService.getAllCertificates.mockResolvedValue([]);
			fetchCrl.mockResolvedValue({
				content: "",
				mtimeMs: now - 3 * 24 * 3600_000,
			});
			readFileSync.mockReturnValue("" as never);

			const metrics = await service.getMetrics();
			expect(metrics.crl_status).toBe("stale");
		});

		it("marks CRL as unknown when the custodian is unreachable", async () => {
			certsService.getAllCertificates.mockResolvedValue([]);
			fetchCrl.mockRejectedValue(new Error("CA custodian unreachable"));
			readFileSync.mockReturnValue("log\n" as never);

			const metrics = await service.getMetrics();
			expect(metrics.crl_status).toBe("unknown");
			expect(metrics.crl_age_seconds).toBeNull();
		});

		it("counts audit log entries correctly", async () => {
			certsService.getAllCertificates.mockResolvedValue([]);
			readFileSync.mockReturnValue("a\nb\nc\n" as never);

			const metrics = await service.getMetrics();
			expect(metrics.audit_log_entries).toBe(3);
		});

		it("sets audit_log_entries to null when readFileSync throws", async () => {
			certsService.getAllCertificates.mockResolvedValue([]);
			readFileSync.mockImplementation(() => {
				throw new Error("no log");
			});

			const metrics = await service.getMetrics();
			expect(metrics.audit_log_entries).toBeNull();
		});
	});

	// ── handleCertificateExpiryCheck ────────────────────────────────────────────

	describe("handleCertificateExpiryCheck", () => {
		it("logs expired certificates as errors", async () => {
			certsService.getAllCertificates.mockResolvedValue([
				makeCert("V", -1), // expired
			] as never);
			const errorSpy = jest
				.spyOn((service as any).logger, "error")
				.mockImplementation(() => {});

			await service.handleCertificateExpiryCheck();
			expect(errorSpy).toHaveBeenCalledWith(
				expect.stringContaining("expired")
			);
		});

		it("logs 7-day certs as critical warnings", async () => {
			certsService.getAllCertificates.mockResolvedValue([
				makeCert("V", 5),
			] as never);
			const warnSpy = jest
				.spyOn((service as any).logger, "warn")
				.mockImplementation(() => {});

			await service.handleCertificateExpiryCheck();
			expect(warnSpy).toHaveBeenCalledWith(
				expect.stringContaining("CRITICAL")
			);
		});

		it("logs 30-day certs as informational", async () => {
			certsService.getAllCertificates.mockResolvedValue([
				makeCert("V", 25),
			] as never);
			const logSpy = jest
				.spyOn((service as any).logger, "log")
				.mockImplementation(() => {});

			await service.handleCertificateExpiryCheck();
			expect(logSpy).toHaveBeenCalledWith(
				expect.stringContaining("INFO")
			);
		});

		it("handles service errors gracefully", async () => {
			certsService.getAllCertificates.mockRejectedValue(
				new Error("db error")
			);
			const errorSpy = jest
				.spyOn((service as any).logger, "error")
				.mockImplementation(() => {});

			await expect(
				service.handleCertificateExpiryCheck()
			).resolves.toBeUndefined();
			expect(errorSpy).toHaveBeenCalled();
		});
	});
});
