import { Logger } from "@nestjs/common";

import { buildCertRoleMap } from "@/common/auth/cert-roles";

const ADMIN_FPR =
	"1c2ba075293fcd68e241cfcedf337ff59bc8126b24c2af07c60f319a38e1a0d8";
const AUDITOR_FPR =
	"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
const SHA1_FPR = "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00"; // 40 chars – invalid

describe("buildCertRoleMap", () => {
	const logger = new Logger("test");

	beforeEach(() => {
		delete process.env.ADMIN_CERT_FINGERPRINTS;
		delete process.env.ADMIN_CERT_FINGERPRINTS_FILE;
		delete process.env.AUDITOR_CERT_FINGERPRINTS;
		delete process.env.AUDITOR_CERT_FINGERPRINTS_FILE;
	});

	it("resolves an admin fingerprint to role admin", () => {
		process.env.ADMIN_CERT_FINGERPRINTS = ADMIN_FPR;
		const map = buildCertRoleMap(logger);
		expect(map.resolve(ADMIN_FPR)).toBe("admin");
		expect(map.adminCount).toBe(1);
	});

	it("resolves an auditor fingerprint to role auditor", () => {
		process.env.AUDITOR_CERT_FINGERPRINTS = AUDITOR_FPR;
		const map = buildCertRoleMap(logger);
		expect(map.resolve(AUDITOR_FPR)).toBe("auditor");
		expect(map.auditorCount).toBe(1);
	});

	it("denies (null) an unknown fingerprint – fail closed", () => {
		process.env.ADMIN_CERT_FINGERPRINTS = ADMIN_FPR;
		const map = buildCertRoleMap(logger);
		expect(map.resolve("deadbeef")).toBeNull();
	});

	it("returns an empty map when nothing is configured (deny all)", () => {
		const map = buildCertRoleMap(logger);
		expect(map.resolve(ADMIN_FPR)).toBeNull();
		expect(map.adminCount).toBe(0);
		expect(map.auditorCount).toBe(0);
	});

	it("gives admin precedence over auditor on overlap", () => {
		process.env.ADMIN_CERT_FINGERPRINTS = ADMIN_FPR;
		process.env.AUDITOR_CERT_FINGERPRINTS = ADMIN_FPR;
		const map = buildCertRoleMap(logger);
		expect(map.resolve(ADMIN_FPR)).toBe("admin");
	});

	it("normalises colon/case forms before matching", () => {
		process.env.ADMIN_CERT_FINGERPRINTS = ADMIN_FPR;
		const map = buildCertRoleMap(logger);
		const colonUpper = ADMIN_FPR.toUpperCase().match(/.{2}/g)!.join(":");
		expect(map.resolve(colonUpper)).toBe("admin");
	});

	it("drops malformed (SHA-1) entries – never silently accepts", () => {
		process.env.ADMIN_CERT_FINGERPRINTS = `${SHA1_FPR}, ${ADMIN_FPR}`;
		const map = buildCertRoleMap(logger);
		expect(map.resolve(SHA1_FPR)).toBeNull();
		expect(map.resolve(ADMIN_FPR)).toBe("admin");
		expect(map.adminCount).toBe(1);
	});
});
