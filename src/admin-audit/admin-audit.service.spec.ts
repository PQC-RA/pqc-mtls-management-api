import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { AdminAuditService } from "@/admin-audit/admin-audit.service";
import { AdminActionEntry } from "@/admin-audit/dto/admin-action.dto";

function readEntries(logPath: string): AdminActionEntry[] {
	return fs
		.readFileSync(logPath, "utf8")
		.split("\n")
		.filter(l => l.trim())
		.map(l => JSON.parse(l) as AdminActionEntry);
}

/** Build a service writing to an isolated temp file (a writable, non-root path). */
function makeService(): { service: AdminAuditService; logPath: string } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "admin-audit-"));
	const logPath = path.join(dir, "admin-actions.log");
	const service = new AdminAuditService();
	(service as unknown as { logPath: string }).logPath = logPath;
	return { service, logPath };
}

describe("AdminAuditService", () => {
	it("appends a tamper-evident hash chain (continuity)", async () => {
		const { service, logPath } = makeService();

		await service.append({
			action: "cert.revoke",
			actor: { sub: "admin1", fpr: "f1", role: "admin" },
			target: "serial=1006",
			result: { status: "ok", httpStatus: 200 },
		});
		await service.append({
			action: "crl.renew",
			actor: { sub: "admin1", fpr: "f1", role: "admin" },
			result: { status: "ok", httpStatus: 200 },
		});

		const entries = readEntries(logPath);
		expect(entries).toHaveLength(2);
		expect(entries[0].seq).toBe(1);
		expect(entries[1].seq).toBe(2);
		// Genesis prev_hash is all zeros; each entry links to the previous hash.
		expect(entries[0].prev_hash).toBe("0".repeat(64));
		expect(entries[1].prev_hash).toBe(entries[0].hash);
		expect(entries[0].hash).toMatch(/^[0-9a-f]{64}$/);
	});

	it("never logs secrets – sanitizes csr / tokens / private material", async () => {
		const { service, logPath } = makeService();

		await service.append({
			action: "cert.enroll",
			actor: null,
			target: "cn=svc",
			params: {
				csr: "-----BEGIN CERTIFICATE REQUEST-----\nSECRET\n-----END...",
				enrollmentToken: "enroll_supersecrettokenvalue1234567890",
				privateKey: "TOPSECRET",
				cn: "svc",
			},
			result: { status: "ok", httpStatus: 201 },
		});

		const [entry] = readEntries(logPath);
		const raw = JSON.stringify(entry);
		expect(raw).not.toContain("SECRET");
		expect(raw).not.toContain("supersecrettokenvalue");
		expect(entry.params.csr).toBe("[REDACTED]");
		expect(entry.params.privateKey).toBe("[REDACTED]");
		expect(String(entry.params.enrollmentToken)).toMatch(
			/^enroll_.{0,8}...?$/
		);
		expect(entry.params.cn).toBe("svc");
	});

	it("records an anonymous actor for the public enroll", async () => {
		const { service, logPath } = makeService();
		await service.append({
			action: "cert.enroll",
			actor: null,
			result: { status: "error", httpStatus: 403, message: "bad token" },
		});
		const [entry] = readEntries(logPath);
		expect(entry.actor).toEqual({ sub: null, fpr: null, role: null });
		expect(entry.result.status).toBe("error");
		expect(entry.result.httpStatus).toBe(403);
	});

	it("recovers the chain head across instances (seq continues after restart)", async () => {
		const { service, logPath } = makeService();
		await service.append({
			action: "cert.revoke",
			actor: { sub: "a", fpr: "f", role: "admin" },
			result: { status: "ok", httpStatus: 200 },
		});

		// New instance over the same file – must continue the chain, not reset it.
		const next = new AdminAuditService();
		(next as unknown as { logPath: string }).logPath = logPath;
		await next.append({
			action: "crl.renew",
			actor: { sub: "a", fpr: "f", role: "admin" },
			result: { status: "ok", httpStatus: 200 },
		});

		const entries = readEntries(logPath);
		expect(entries.map(e => e.seq)).toEqual([1, 2]);
		expect(entries[1].prev_hash).toBe(entries[0].hash);
	});

	it("query() filters by action (event) and result status (level)", async () => {
		const { service } = makeService();
		await service.append({
			action: "cert.revoke",
			actor: { sub: "a", fpr: "f", role: "admin" },
			result: { status: "ok", httpStatus: 200 },
		});
		await service.append({
			action: "crl.renew",
			actor: { sub: "a", fpr: "f", role: "admin" },
			result: { status: "error", httpStatus: 500 },
		});

		const revokes = await service.query({ event: "cert.revoke" });
		expect(revokes).toHaveLength(1);
		expect(revokes[0].action).toBe("cert.revoke");

		const errors = await service.query({ level: "error" });
		expect(errors).toHaveLength(1);
		expect(errors[0].action).toBe("crl.renew");
	});
});
