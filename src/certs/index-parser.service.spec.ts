jest.mock("fs");
import * as fs from "fs";

import { Test, TestingModule } from "@nestjs/testing";

import { IndexParserService } from "@/certs/index-parser.service";

const existsSync = jest.mocked(fs.existsSync);
const createReadStream = jest.mocked(fs.createReadStream);

// ─── Minimal valid index.txt lines ───────────────────────────────────────────
const VALID_ENTRY_V =
	"V\t360309154849Z\t\t1006\tunknown\t/C=BG/O=Enterprise/CN=service-A";
const VALID_ENTRY_R =
	"R\t360309154849Z\t260310060000Z,keyCompromise\t1007\tunknown\t/CN=service-B";
const VALID_ENTRY_E = "E\t200101000000Z\t\t1000\tunknown\t/CN=old-service";

describe("IndexParserService", () => {
	let service: IndexParserService;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [IndexParserService],
		}).compile();
		service = module.get<IndexParserService>(IndexParserService);
	});

	it("should be defined", () => {
		expect(service).toBeDefined();
	});

	it("returns empty array when file does not exist", async () => {
		existsSync.mockReturnValueOnce(false);
		const result = await service.parseIndexFile("/nonexistent/path");
		expect(result).toEqual([]);
	});

	it("parses a valid V entry", async () => {
		existsSync.mockReturnValue(true);
		// createReadStream → mock with an async iterable
		const lines = [VALID_ENTRY_V];
		mockReadStream(lines);

		const result = await service.parseIndexFile("/fake/index.txt");
		expect(result).toHaveLength(1);
		expect(result[0].status).toBe("V");
		expect(result[0].serialNumber).toBe("1006");
		expect(result[0].subject).toBe("/C=BG/O=Enterprise/CN=service-A");
		expect(result[0].filename).toBeUndefined(); // "unknown" → undefined
		expect(result[0].expirationDate).toBeInstanceOf(Date);
		expect(result[0].revocationDate).toBeUndefined();
	});

	it("parses a valid R entry with revocation date and reason", async () => {
		existsSync.mockReturnValue(true);
		mockReadStream([VALID_ENTRY_R]);

		const result = await service.parseIndexFile("/fake/index.txt");
		expect(result[0].status).toBe("R");
		expect(result[0].revocationDate).toBeInstanceOf(Date);
	});

	it("parses a valid E entry", async () => {
		existsSync.mockReturnValue(true);
		mockReadStream([VALID_ENTRY_E]);

		const result = await service.parseIndexFile("/fake/index.txt");
		expect(result[0].status).toBe("E");
	});

	it("skips blank lines", async () => {
		existsSync.mockReturnValue(true);
		mockReadStream(["", "   ", VALID_ENTRY_V]);

		const result = await service.parseIndexFile("/fake/index.txt");
		expect(result).toHaveLength(1);
	});

	it("skips lines with fewer than 6 tab-separated fields", async () => {
		existsSync.mockReturnValue(true);
		mockReadStream(["V\t360309154849Z\t\t1006"]);

		const result = await service.parseIndexFile("/fake/index.txt");
		expect(result).toHaveLength(0);
	});

	it("parses multiple entries correctly", async () => {
		existsSync.mockReturnValue(true);
		mockReadStream([VALID_ENTRY_V, VALID_ENTRY_R, VALID_ENTRY_E]);

		const result = await service.parseIndexFile("/fake/index.txt");
		expect(result).toHaveLength(3);
	});
});

// ─── Helper: mock fs.createReadStream with in-memory lines ───────────────────
function mockReadStream(lines: string[]): void {
	const { Readable } = require("stream");

	createReadStream.mockReturnValueOnce(
		Readable.from(lines.join("\n")) as never
	);
}
