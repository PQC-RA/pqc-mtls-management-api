jest.mock("fs");
import * as fs from "fs";

import { HttpStatus } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";

import { AuditService } from "@/audit/audit.service";

const existsSync = jest.mocked(fs.existsSync);
const readFileSync = jest.mocked(fs.readFileSync);

const SAMPLE_ENTRY = JSON.stringify({
	seq: 1,
	ts: "2026-03-10T06:00:00Z",
	event: "access",
	level: "info",
	client: { cn: "service-A", org: "M2M-Client", verify: "SUCCESS" },
	tls: { version: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384" },
	http: { method: "GET", uri: "/api/data", status: 200 },
	prev_hash: "0".repeat(64),
	hash: "a".repeat(64),
});

describe("AuditService", () => {
	let service: AuditService;

	beforeEach(async () => {
		jest.resetAllMocks();
		const module: TestingModule = await Test.createTestingModule({
			providers: [AuditService],
		}).compile();
		service = module.get<AuditService>(AuditService);
	});

	it("should be defined", () => {
		expect(service).toBeDefined();
	});

	describe("getAuditLogs", () => {
		it("returns empty array when log file does not exist", async () => {
			existsSync.mockReturnValue(false);
			const result = await service.getAuditLogs({ lines: 100 });
			expect(result).toEqual([]);
		});

		it("parses NDJSON lines and returns the last N", async () => {
			const lines = Array.from({ length: 5 }, (_, i) =>
				JSON.stringify({ id: i })
			).join("\n");
			existsSync.mockReturnValue(true);
			readFileSync.mockReturnValue(lines as never);

			const result = await service.getAuditLogs({ lines: 3 });
			expect(result).toHaveLength(3);
			expect(result[0]).toEqual({ id: 2 });
			expect(result[2]).toEqual({ id: 4 });
		});

		it("returns all lines when N is larger than log size", async () => {
			const content = [SAMPLE_ENTRY, SAMPLE_ENTRY].join("\n");
			existsSync.mockReturnValue(true);
			readFileSync.mockReturnValue(content as never);

			const result = await service.getAuditLogs({ lines: 100 });
			expect(result).toHaveLength(2);
		});

		it("ignores blank lines in log file", async () => {
			const content = `${SAMPLE_ENTRY}\n\n${SAMPLE_ENTRY}\n`;
			existsSync.mockReturnValue(true);
			readFileSync.mockReturnValue(content as never);

			const result = await service.getAuditLogs({ lines: 100 });
			expect(result).toHaveLength(2);
		});

		it("filters by event, level and cn", async () => {
			const a = JSON.stringify({
				ts: "2026-03-10T06:00:00Z",
				event: "access",
				level: "info",
				client: { cn: "service-A" },
			});
			const b = JSON.stringify({
				ts: "2026-03-10T06:00:01Z",
				event: "block",
				level: "warn",
				client: { cn: "service-B" },
			});
			existsSync.mockReturnValue(true);
			readFileSync.mockReturnValue([a, b].join("\n") as never);

			const blocked = await service.getAuditLogs({ event: "block" });
			expect(blocked).toHaveLength(1);
			expect((blocked[0] as any).client.cn).toBe("service-B");

			const byCn = await service.getAuditLogs({ cn: "service-A" });
			expect(byCn).toHaveLength(1);
			expect((byCn[0] as any).event).toBe("access");
		});

		it("paginates with offset/limit over the filtered set", async () => {
			const content = Array.from({ length: 5 }, (_, i) =>
				JSON.stringify({ ts: "2026-03-10T06:00:00Z", id: i })
			).join("\n");
			existsSync.mockReturnValue(true);
			readFileSync.mockReturnValue(content as never);

			const page = await service.getAuditLogs({ offset: 1, limit: 2 });
			expect(page.map((e: any) => e.id)).toEqual([1, 2]);
		});

		it("filters by since/until window", async () => {
			const content = [
				JSON.stringify({ ts: "2026-03-09T00:00:00Z", id: 0 }),
				JSON.stringify({ ts: "2026-03-10T00:00:00Z", id: 1 }),
				JSON.stringify({ ts: "2026-03-11T00:00:00Z", id: 2 }),
			].join("\n");
			existsSync.mockReturnValue(true);
			readFileSync.mockReturnValue(content as never);

			const win = await service.getAuditLogs({
				since: "2026-03-10T00:00:00Z",
				until: "2026-03-10T23:59:59Z",
			});
			expect(win.map((e: any) => e.id)).toEqual([1]);
		});

		it("throws 500 when readFileSync fails", async () => {
			existsSync.mockReturnValue(true);
			readFileSync.mockImplementation(() => {
				throw new Error("disk error");
			});

			await expect(service.getAuditLogs()).rejects.toMatchObject({
				status: HttpStatus.INTERNAL_SERVER_ERROR,
			});
		});
	});
});
