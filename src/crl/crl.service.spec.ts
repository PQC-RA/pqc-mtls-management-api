jest.mock("fs");
// getCrl() no longer touches the filesystem: this process stopped mounting the
// CA tree and now reads through the pqc-ca-custodian sidecar. Mock that seam, or
// the tests drive fs mocks the code never consults and fall through to a REAL
// fetch to the custodian. renewCrl() still uses fs, so the fs mock stays.
jest.mock("@/common/ca-custodian.util");
import * as fs from "fs";

import { HttpException, HttpStatus } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";

import { fetchCrlViaCustodian } from "@/common/ca-custodian.util";
import { CrlService } from "@/crl/crl.service";

const existsSync = jest.mocked(fs.existsSync);
const readFileSync = jest.mocked(fs.readFileSync);
const fetchCrl = jest.mocked(fetchCrlViaCustodian);

const FAKE_CRL =
	"-----BEGIN X509 CRL-----\nMIIB...base64...\n-----END X509 CRL-----\n";

// Mock child_process.execFile so we never shell out in tests
jest.mock("child_process", () => ({
	execFile: jest.fn((...callArgs: any[]) => {
		const cb = callArgs[callArgs.length - 1];
		cb(null, { stdout: "", stderr: "" });
	}),
}));

describe("CrlService", () => {
	let service: CrlService;

	beforeEach(async () => {
		jest.resetAllMocks();
		const module: TestingModule = await Test.createTestingModule({
			providers: [CrlService],
		}).compile();
		service = module.get<CrlService>(CrlService);
	});

	// ── getCrl ──────────────────────────────────────────────────────────────────

	describe("getCrl", () => {
		it("returns the CRL PEM the custodian serves", async () => {
			fetchCrl.mockResolvedValue({
				content: FAKE_CRL,
				mtimeMs: 1_700_000_000,
			});

			const result = await service.getCrl();
			expect(result).toBe(FAKE_CRL);
			expect(fetchCrl).toHaveBeenCalledTimes(1);
		});

		it("does not read the CRL from the filesystem", async () => {
			// Guards the refactor itself. Before the custodian move this method
			// read the CA tree directly; a regression to that would still pass the
			// test above (the mock would go unused) but fail here.
			fetchCrl.mockResolvedValue({ content: FAKE_CRL, mtimeMs: 1 });

			await service.getCrl();
			expect(readFileSync).not.toHaveBeenCalled();
		});

		it("propagates a custodian 404 as 404", async () => {
			fetchCrl.mockRejectedValue(
				new HttpException("CRL not found", HttpStatus.NOT_FOUND)
			);

			await expect(service.getCrl()).rejects.toMatchObject({
				status: HttpStatus.NOT_FOUND,
			});
		});

		it("propagates a custodian failure as 500 rather than swallowing it", async () => {
			fetchCrl.mockRejectedValue(
				new HttpException(
					"CA custodian unreachable",
					HttpStatus.INTERNAL_SERVER_ERROR
				)
			);

			await expect(service.getCrl()).rejects.toMatchObject({
				status: HttpStatus.INTERNAL_SERVER_ERROR,
			});
		});
	});

	// ── renewCrl ────────────────────────────────────────────────────────────────

	describe("renewCrl", () => {
		it("returns success message when script exists and succeeds", async () => {
			existsSync.mockReturnValue(true);
			const { execFile } = require("child_process");
			execFile.mockImplementation((...callArgs: any[]) => {
				const cb = callArgs[callArgs.length - 1];
				cb(null, { stdout: "", stderr: "" });
			});

			const result = await service.renewCrl();
			expect(result.message).toMatch(/renewed successfully/i);
		});

		it("returns dry-run message when script does not exist", async () => {
			existsSync.mockReturnValue(false);

			const result = await service.renewCrl();
			expect(result.message).toMatch(/dry run/i);
		});

		it("throws 500 when script execution fails", async () => {
			existsSync.mockReturnValue(true);
			const { execFile } = require("child_process");
			execFile.mockImplementation((...callArgs: any[]) => {
				const cb = callArgs[callArgs.length - 1];
				cb(new Error("bash error"));
			});

			await expect(service.renewCrl()).rejects.toMatchObject({
				status: HttpStatus.INTERNAL_SERVER_ERROR,
			});
		});
	});
});
