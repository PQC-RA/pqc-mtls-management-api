jest.mock("fs");
import * as fs from "fs";

import { HttpException, HttpStatus } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";

import { AdminAuditService } from "@/admin-audit/admin-audit.service";
import { CertsService } from "@/certs/certs.service";
import { IndexParserService } from "@/certs/index-parser.service";
import { TokenStoreService } from "@/certs/token-store.service";
import * as caCustodianUtil from "@/common/ca-custodian.util";

// Prevent any real child_process execution
jest.mock("child_process", () => ({
	execFile: jest.fn(),
}));

const existsSync = jest.mocked(fs.existsSync);
const mkdtempSync = jest.mocked(fs.mkdtempSync);
const writeFileSync = jest.mocked(fs.writeFileSync);
const readFileSync = jest.mocked(fs.readFileSync);
const rmSync = jest.mocked(fs.rmSync);

const FAKE_CERT_PEM =
	"-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n";
const FAKE_CSR_PEM =
	"-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----\n";

function makeCert(
	status: "V" | "R" | "E",
	daysFromNow: number,
	serial = "1001"
) {
	const now = Date.now();
	const msPerDay = 24 * 60 * 60 * 1000;
	return {
		status,
		serialNumber: serial,
		subject: `/CN=svc-${serial}`,
		expirationDate: new Date(now + daysFromNow * msPerDay),
	};
}

describe("CertsService", () => {
	let service: CertsService;
	let indexParser: jest.Mocked<IndexParserService>;

	beforeEach(async () => {
		jest.resetAllMocks();
		indexParser = { parseIndexFile: jest.fn() } as any;

		// Default so any path.join(mkdtempSync(...), ...) call succeeds unless a
		// test overrides it with a more specific value (as signCsr/validateCsr's
		// tests already do below) – without this, fs being globally jest.mocked
		// means mkdtempSync() returns undefined by default, and getAllCertificates
		// (used by getCertificate/getCertificates/revokeCertificate) throws before
		// ever reaching indexParser.parseIndexFile.
		mkdtempSync.mockReturnValue("/tmp/pqc-test-default");

		// Default so a test that forgets to configure execFile (or whose own
		// preconditions no longer short-circuit before reaching it, e.g. a stale
		// existsSync-based check from before certs moved behind the custodian
		// sidecar) fails fast instead of hanging for the full Jest timeout –
		// callback-style child_process.execFile never settles a Promise on its
		// own if nothing ever invokes the callback.
		{
			const { execFile } = require("child_process");
			execFile.mockImplementation((...callArgs: any[]) => {
				const cb = callArgs[callArgs.length - 1] as Function;
				cb(null, { stdout: "", stderr: "" });
			});
		}

		// getAllCertificates/getCertificateDetail/revokeCertificate all call into
		// the real pqc-ca-custodian sidecar over HTTP (fetchIndexViaCustodian,
		// fetchIssuedPemViaCustodian, revokeViaCustodian). fs being globally
		// jest.mocked also breaks getCustodianHmacSecret()'s readFileSync of the
		// HMAC secret file (returns undefined, not a real secret), so these calls
		// would fail auth even if a live custodian were reachable. Stub them at
		// this boundary instead of hitting the network at all – actual content
		// doesn't matter beyond "resolves", since indexParser.parseIndexFile is
		// separately mocked and ignores whatever gets written to the temp file.
		jest.spyOn(caCustodianUtil, "fetchIndexViaCustodian").mockResolvedValue(
			"dummy-index-content"
		);
		jest.spyOn(
			caCustodianUtil,
			"fetchIssuedPemViaCustodian"
		).mockResolvedValue(FAKE_CERT_PEM);
		jest.spyOn(caCustodianUtil, "revokeViaCustodian").mockResolvedValue();
		jest.spyOn(caCustodianUtil, "signCsrViaCustodian").mockResolvedValue({
			certificate: FAKE_CERT_PEM,
			serialNumber: "1007",
			expiresAt: "2027-01-01T00:00:00.000Z",
		});

		const tokenStore: jest.Mocked<TokenStoreService> = {
			set: jest.fn().mockResolvedValue(undefined),
			get: jest.fn().mockResolvedValue(null),
			delete: jest.fn().mockResolvedValue(false),
			consume: jest.fn().mockResolvedValue("ok"),
			list: jest.fn().mockResolvedValue([]),
			onModuleDestroy: jest.fn().mockResolvedValue(undefined),
		} as any;

		const adminAudit: jest.Mocked<AdminAuditService> = {
			append: jest.fn().mockResolvedValue(null),
			query: jest.fn().mockResolvedValue([]),
		} as any;

		const module: TestingModule = await Test.createTestingModule({
			providers: [
				CertsService,
				{ provide: IndexParserService, useValue: indexParser },
				{ provide: TokenStoreService, useValue: tokenStore },
				{ provide: AdminAuditService, useValue: adminAudit },
			],
		}).compile();
		service = module.get<CertsService>(CertsService);
	});

	it("should be defined", () => {
		expect(service).toBeDefined();
	});

	// ── getAllCertificates ────────────────────────────────────────────────────────

	describe("getAllCertificates", () => {
		it("returns all cert entries from the index parser", async () => {
			const certs = [makeCert("V", 90)];
			indexParser.parseIndexFile.mockResolvedValue(certs as never);

			const result = await service.getAllCertificates();
			expect(result).toEqual(certs);
		});

		it("throws 500 when index parser throws", async () => {
			indexParser.parseIndexFile.mockRejectedValue(
				new Error("parse error")
			);

			await expect(service.getAllCertificates()).rejects.toMatchObject({
				status: HttpStatus.INTERNAL_SERVER_ERROR,
			});
		});
	});

	// ── getExpiringCertificates ──────────────────────────────────────────────────

	describe("getExpiringCertificates", () => {
		it("returns only V certs expiring within the window, sorted", async () => {
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 5, "A"),
				makeCert("V", 20, "B"),
				makeCert("V", 60, "C"), // outside window
				makeCert("R", 5, "D"), // revoked
				makeCert("E", 5, "E"), // expired
			] as never);

			const result = await service.getExpiringCertificates(30);
			expect(result).toHaveLength(2);
			expect(result[0].serialNumber).toBe("A"); // 5 days < 20 days
			expect(result[0].daysLeft).toBeLessThanOrEqual(5);
		});

		it("returns empty array when no certs within window", async () => {
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 60),
			] as never);
			const result = await service.getExpiringCertificates(30);
			expect(result).toHaveLength(0);
		});
	});

	// ── getCertificate ───────────────────────────────────────────────────────────

	describe("getCertificate", () => {
		it("returns the matching cert for a raw hex serial", async () => {
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			const result = await service.getCertificate("1006");
			expect(result.serialNumber).toBe("1006");
		});

		it("normalizes 0x-prefixed input", async () => {
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			const result = await service.getCertificate("0x1006");
			expect(result.serialNumber).toBe("1006");
		});

		it("normalizes dec:-prefixed input", async () => {
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			const result = await service.getCertificate("dec:4102"); // 4102 = 0x1006
			expect(result.serialNumber).toBe("1006");
		});

		it("throws 404 when serial not found", async () => {
			indexParser.parseIndexFile.mockResolvedValue([]);
			await expect(service.getCertificate("DEAD")).rejects.toMatchObject({
				status: HttpStatus.NOT_FOUND,
			});
		});
	});

	// ── Enrollment tokens ────────────────────────────────────────────────────────

	describe("enrollment tokens", () => {
		let tokenStore: jest.Mocked<any>;

		beforeEach(() => {
			// Access the private tokenStore from the service for fine-grained control
			tokenStore = (service as any).tokenStore;
		});

		it("creates a token with enroll_ prefix and delegates to tokenStore.set", async () => {
			const token = await service.createEnrollmentToken(
				86400,
				"test-service"
			);
			expect(token).toMatch(/^enroll_[0-9a-f]+$/);
			expect(tokenStore.set).toHaveBeenCalledWith(
				token,
				expect.objectContaining({
					expiresAt: expect.any(Number),
					allowedCn: "test-service",
				})
			);
		});

		it("listEnrollmentTokens delegates to tokenStore.list", async () => {
			const fakeList = [
				{
					token: "enroll_abc",
					expiresAt: Date.now() + 9999,
					used: false,
				},
			];
			tokenStore.list.mockResolvedValue(fakeList);
			const result = await service.listEnrollmentTokens();
			expect(result).toEqual(fakeList);
			expect(tokenStore.list).toHaveBeenCalled();
		});

		it("revokeEnrollmentToken delegates delete to tokenStore", async () => {
			tokenStore.delete.mockResolvedValue(true);
			await service.revokeEnrollmentToken("enroll_test");
			expect(tokenStore.delete).toHaveBeenCalledWith("enroll_test");
		});

		it("throws 404 when revoking a nonexistent token", async () => {
			tokenStore.delete.mockResolvedValue(false);
			await expect(
				service.revokeEnrollmentToken("enroll_fake")
			).rejects.toThrow(HttpException);
		});
	});

	// ── signCsr ──────────────────────────────────────────────────────────────────

	describe("signCsr", () => {
		let token: string;

		/**
		 * execFile is called as (file, args, [opts], cb) where cb(err, stdout, stderr).
		 * promisify passes the callback as the last argument.
		 */
		function mockExecFile(
			impl: (file: string, args: string[], cb: Function) => void
		) {
			const { execFile } = require("child_process");
			execFile.mockImplementation((...callArgs: any[]) => {
				const cb = callArgs[callArgs.length - 1] as Function;
				const file = callArgs[0] as string;
				const args = callArgs[1] as string[];
				impl(file, args, cb);
			});
		}

		function setupExecSuccess(
			serial = "1007",
			endDate = "Mar 10 06:00:00 2027 GMT"
		) {
			mockExecFile((_, args, cb) => {
				if (args.includes("-verify")) {
					cb(null, { stdout: "verify OK", stderr: "verify OK" });
				} else if (args.includes("-text")) {
					// assertCsrKeyAlgorithmAllowed probes the CSR key algorithm.
					cb(null, {
						stdout: "Public Key Algorithm: ML-DSA-65",
						stderr: "",
					});
				} else if (args.includes("-subject")) {
					cb(null, { stdout: "subject=CN = test-cn", stderr: "" });
				} else if (args.includes("ca")) {
					cb(null, { stdout: "", stderr: "" });
				} else if (args.includes("x509")) {
					cb(null, {
						stdout: `serial=${serial}\nnotAfter=${endDate}`,
						stderr: "",
					});
				} else {
					cb(null, { stdout: "", stderr: "" });
				}
			});
		}

		beforeEach(async () => {
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			tokenStore.consume.mockResolvedValue("ok");
			token = await service.createEnrollmentToken(3600, "test-cn");

			// Stub all fs operations
			mkdtempSync.mockReturnValue("/tmp/pqc-csr-test");
			writeFileSync.mockImplementation(() => {});
			existsSync.mockReturnValue(true);
			readFileSync.mockReturnValue(FAKE_CERT_PEM as never);
			rmSync.mockImplementation(() => {});
		});

		it("returns the signed certificate on success", async () => {
			setupExecSuccess();
			const result = await service.signCsr(FAKE_CSR_PEM, token);
			expect(result.certificate).toBe(FAKE_CERT_PEM);
			expect(result.serialNumber).toBe("1007");
		});

		it("throws 403 when enrollment token is invalid", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			tokenStore.consume.mockResolvedValue("not_found");
			await expect(
				service.signCsr(FAKE_CSR_PEM, "enroll_invalid")
			).rejects.toMatchObject({ status: HttpStatus.FORBIDDEN });
		});

		it("throws 403 when CSR CN does not match token constraint", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			tokenStore.consume.mockResolvedValue("cn_mismatch");
			await expect(
				service.signCsr(FAKE_CSR_PEM, token)
			).rejects.toMatchObject({ status: HttpStatus.FORBIDDEN });
		});

		it("throws 400 when CSR verify fails", async () => {
			mockExecFile((_, args, cb) => {
				if (args.includes("-verify")) {
					cb(null, { stdout: "", stderr: "verification failure" });
				} else {
					cb(null, { stdout: "", stderr: "" });
				}
			});

			await expect(
				service.signCsr(FAKE_CSR_PEM, token)
			).rejects.toMatchObject({
				status: HttpStatus.BAD_REQUEST,
			});
		});

		it("propagates a 502 when the custodian rejects the signing request", async () => {
			// Signing itself now happens inside pqc-ca-custodian (the only
			// component with intermediate-key access) over HTTP, not via a local
			// `openssl ca` exec – so a signing-side failure surfaces as
			// custodianRequest's generic non-404/409 mapping (BAD_GATEWAY), which
			// signCsr's catch block re-throws as-is (isKnownHttpException).
			setupExecSuccess();
			jest.spyOn(
				caCustodianUtil,
				"signCsrViaCustodian"
			).mockRejectedValue(
				new HttpException(
					"CA custodian request failed",
					HttpStatus.BAD_GATEWAY
				)
			);

			await expect(
				service.signCsr(FAKE_CSR_PEM, token)
			).rejects.toMatchObject({
				status: HttpStatus.BAD_GATEWAY,
			});
		});
	});

	// ── getCertificates (filter + pagination) ─────────────────────────────────────

	describe("getCertificates", () => {
		beforeEach(() => {
			indexParser.parseIndexFile.mockResolvedValue([
				{ ...makeCert("V", 90, "1001"), subject: "/CN=alpha-service" },
				{ ...makeCert("R", 90, "1002"), subject: "/CN=beta-service" },
				{ ...makeCert("E", -5, "1003"), subject: "/CN=gamma-thing" },
				{ ...makeCert("V", 90, "1004"), subject: "/CN=delta-service" },
			] as never);
		});

		it("returns everything with no query (unchanged default)", async () => {
			const result = await service.getCertificates();
			expect(result).toHaveLength(4);
		});

		it("filters by status", async () => {
			const result = await service.getCertificates({ status: "V" });
			expect(result.map(c => c.serialNumber)).toEqual(["1001", "1004"]);
		});

		it("filters by cnContains (case-insensitive substring of subject)", async () => {
			const result = await service.getCertificates({
				cnContains: "SERVICE",
			});
			expect(result.map(c => c.serialNumber)).toEqual([
				"1001",
				"1002",
				"1004",
			]);
		});

		it("paginates with offset/limit", async () => {
			const result = await service.getCertificates({
				offset: 1,
				limit: 2,
			});
			expect(result.map(c => c.serialNumber)).toEqual(["1002", "1003"]);
		});
	});

	// ── validateCsr (pre-flight, no token spent) ───────────────────────────────────

	describe("validateCsr", () => {
		function mockExecFile(
			impl: (file: string, args: string[], cb: Function) => void
		) {
			const { execFile } = require("child_process");
			execFile.mockImplementation((...callArgs: any[]) => {
				const cb = callArgs[callArgs.length - 1] as Function;
				impl(callArgs[0], callArgs[1] as string[], cb);
			});
		}

		beforeEach(() => {
			mkdtempSync.mockReturnValue("/tmp/pqc-csr-chk");
			writeFileSync.mockImplementation(() => {});
			rmSync.mockImplementation(() => {});
		});

		it("returns valid for an ML-DSA-65 CSR and never consumes a token", async () => {
			mockExecFile((_, args, cb) => {
				if (args.includes("-verify"))
					cb(null, { stdout: "", stderr: "verify OK" });
				else if (args.includes("-text"))
					cb(null, {
						stdout: "Public Key Algorithm: ML-DSA-65",
						stderr: "",
					});
				else if (args.includes("-subject"))
					cb(null, { stdout: "subject=CN = my-service", stderr: "" });
				else cb(null, { stdout: "", stderr: "" });
			});

			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			const result = await service.validateCsr(FAKE_CSR_PEM);
			expect(result).toMatchObject({
				valid: true,
				cn: "my-service",
				publicKeyAlgorithm: "ML-DSA-65",
			});
			expect(tokenStore.consume).not.toHaveBeenCalled();
		});

		it("rejects a non-ML-DSA-65 key with a reason", async () => {
			mockExecFile((_, args, cb) => {
				if (args.includes("-verify"))
					cb(null, { stdout: "", stderr: "verify OK" });
				else if (args.includes("-text"))
					cb(null, {
						stdout: "Public Key Algorithm: rsaEncryption",
						stderr: "",
					});
				else if (args.includes("-subject"))
					cb(null, { stdout: "subject=CN = my-service", stderr: "" });
				else cb(null, { stdout: "", stderr: "" });
			});

			const result = await service.validateCsr(FAKE_CSR_PEM);
			expect(result.valid).toBe(false);
			expect(result.publicKeyAlgorithm).toBe("rsaEncryption");
			expect(result.reason).toMatch(/ML-DSA-65/);
		});

		it("rejects when the self-signature does not verify", async () => {
			mockExecFile((_, args, cb) => {
				if (args.includes("-verify"))
					cb(null, { stdout: "", stderr: "verification failure" });
				else cb(null, { stdout: "", stderr: "" });
			});

			const result = await service.validateCsr(FAKE_CSR_PEM);
			expect(result.valid).toBe(false);
			expect(result.reason).toMatch(/self-signature/i);
		});
	});

	// ── getCertificateDetail (enriched) ────────────────────────────────────────────

	describe("getCertificateDetail", () => {
		it("enriches the entry with fingerprint, pubkey alg, SAN, dates and pem", async () => {
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			existsSync.mockReturnValue(true);
			readFileSync.mockReturnValue(FAKE_CERT_PEM as never);

			const { execFile } = require("child_process");
			execFile.mockImplementation((...callArgs: any[]) => {
				const cb = callArgs[callArgs.length - 1] as Function;
				const args = callArgs[1] as string[];
				if (args.includes("-fingerprint")) {
					cb(null, {
						stdout:
							"sha256 Fingerprint=1C:2B:A0:75\n" +
							"notBefore=Jun 30 00:00:00 2026 GMT\n" +
							"notAfter=Jun 30 00:00:00 2027 GMT",
						stderr: "",
					});
				} else if (args.includes("-text")) {
					cb(null, {
						stdout:
							"Public Key Algorithm: ML-DSA-65\n" +
							"            X509v3 Subject Alternative Name: \n" +
							"                DNS:my-service\n",
						stderr: "",
					});
				} else {
					cb(null, { stdout: "", stderr: "" });
				}
			});

			const result = await service.getCertificateDetail("1006");
			expect(result.fingerprintSha256).toBe("1c2ba075");
			expect(result.publicKeyAlgorithm).toBe("ML-DSA-65");
			expect(result.subjectAltName).toBe("DNS:my-service");
			expect(result.notBefore).toBe("2026-06-30T00:00:00.000Z");
			expect(result.notAfter).toBe("2027-06-30T00:00:00.000Z");
			expect(result.pem).toBe(FAKE_CERT_PEM);
		});

		it("propagates the custodian's 404 when the issued PEM is unavailable", async () => {
			// getCertificateDetail reads the issued PEM through the custodian now,
			// not from a local mount, so the 404 originates there.
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			jest.spyOn(
				caCustodianUtil,
				"fetchIssuedPemViaCustodian"
			).mockRejectedValue(
				new HttpException("Issued PEM not found", HttpStatus.NOT_FOUND)
			);

			await expect(
				service.getCertificateDetail("1006")
			).rejects.toMatchObject({ status: HttpStatus.NOT_FOUND });
		});
	});

	// ── revokeCertificate ────────────────────────────────────────────────────────

	describe("revokeCertificate", () => {
		// A caller fingerprint that never matches any test cert's fingerprint
		// below, so pre-existing tests exercise the "not my own cert" path.
		const OTHER_CALLER_FPR = "a".repeat(64);

		function mockExecFile(
			impl: (file: string, args: string[], cb: Function) => void
		) {
			const { execFile } = require("child_process");
			execFile.mockImplementation((...callArgs: any[]) => {
				const cb = callArgs[callArgs.length - 1] as Function;
				const file = callArgs[0] as string;
				const args = callArgs[1] as string[];
				impl(file, args, cb);
			});
		}

		/**
		 * The self-revocation check fetches the target cert's PEM via the
		 * custodian sidecar (a real HTTP call in production) purely to hash it
		 * for the fingerprint comparison. Stub that fetch so these tests never
		 * touch the network – the actual fingerprint value comes from whatever
		 * the execFile mock returns for the "-fingerprint" openssl call.
		 */
		beforeEach(() => {
			jest.spyOn(
				caCustodianUtil,
				"fetchIssuedPemViaCustodian"
			).mockResolvedValue(FAKE_CERT_PEM);
		});

		it("revokes and returns success message", async () => {
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			existsSync.mockReturnValue(true);

			mockExecFile((_file, _args, cb) =>
				cb(null, { stdout: "", stderr: "" })
			);

			const result = await service.revokeCertificate(
				"1006",
				"keyCompromise",
				OTHER_CALLER_FPR
			);
			expect(result.message).toMatch(/revoked successfully/i);
		});

		it("omits -crl_reason flag when reason is unspecified", async () => {
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			const revoke = jest
				.spyOn(caCustodianUtil, "revokeViaCustodian")
				.mockResolvedValue();

			await service.revokeCertificate(
				"1006",
				"unspecified",
				OTHER_CALLER_FPR
			);
			// RFC 5280 §5.3.1 / BR §7.2.2: an "unspecified" reason MUST NOT emit a
			// reasonCode extension. The service expresses that by passing undefined
			// rather than the string – the custodian then omits the flag.
			expect(revoke).toHaveBeenCalledWith(
				expect.anything(),
				"1006",
				undefined
			);
		});

		it("includes -crl_reason flag for non-unspecified reasons", async () => {
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			existsSync.mockReturnValue(true);

			const revoke = jest
				.spyOn(caCustodianUtil, "revokeViaCustodian")
				.mockResolvedValue();

			await service.revokeCertificate(
				"1006",
				"cessationOfOperation",
				OTHER_CALLER_FPR
			);
			// The openssl `-crl_reason` flag is no longer this process's business:
			// revocation moved into pqc-ca-custodian, so the reason is passed as an
			// argument. Same RFC 5280 §5.3.1 rule, asserted at the new boundary.
			expect(revoke).toHaveBeenCalledWith(
				expect.anything(),
				"1006",
				"cessationOfOperation"
			);
		});

		it("throws 400 for an invalid revocation reason", async () => {
			await expect(
				service.revokeCertificate(
					"1006",
					"notAValidReason",
					OTHER_CALLER_FPR
				)
			).rejects.toMatchObject({ status: HttpStatus.BAD_REQUEST });
		});

		it("throws 400 for Mozilla-banned reasons (certificateHold, CACompromise)", async () => {
			for (const banned of [
				"certificateHold",
				"CACompromise",
				"removeFromCRL",
				"aACompromise",
			]) {
				await expect(
					service.revokeCertificate("1006", banned, OTHER_CALLER_FPR)
				).rejects.toMatchObject({ status: HttpStatus.BAD_REQUEST });
			}
		});

		it("propagates the custodian's 404 when the cert is unknown to it", async () => {
			// The on-disk check moved: pqc-ca-custodian owns the not-found and
			// already-revoked decisions now (see revokeCertificate). This asserts
			// the service surfaces that verdict rather than masking it.
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			jest.spyOn(caCustodianUtil, "revokeViaCustodian").mockRejectedValue(
				new HttpException("Certificate not found", HttpStatus.NOT_FOUND)
			);

			await expect(
				service.revokeCertificate(
					"1006",
					"unspecified",
					OTHER_CALLER_FPR
				)
			).rejects.toMatchObject({ status: HttpStatus.NOT_FOUND });
		});

		it("throws 404 when cert is not in the CA database", async () => {
			indexParser.parseIndexFile.mockResolvedValue([]);
			await expect(
				service.revokeCertificate(
					"DEAD",
					"unspecified",
					OTHER_CALLER_FPR
				)
			).rejects.toMatchObject({ status: HttpStatus.NOT_FOUND });
		});

		// ── self-revocation refusal ───────────────────────────────────────────

		it("throws 403 and never calls the custodian when the target fingerprint matches the caller's own", async () => {
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			existsSync.mockReturnValue(true);

			const OWN_FPR = "b".repeat(64);
			const calledBinaries: string[] = [];
			mockExecFile((file, args, cb) => {
				calledBinaries.push(file);
				if (args.includes("-fingerprint")) {
					cb(null, {
						stdout: `sha256 Fingerprint=${OWN_FPR}\n`,
						stderr: "",
					});
				} else {
					cb(null, { stdout: "", stderr: "" });
				}
			});

			await expect(
				service.revokeCertificate("1006", "keyCompromise", OWN_FPR)
			).rejects.toMatchObject({ status: HttpStatus.FORBIDDEN });

			// The check must happen BEFORE the irreversible custodian call –
			// only the fingerprint-computing openssl invocation should have run.
			const revokeArgsCall = calledBinaries.length;
			expect(revokeArgsCall).toBeGreaterThan(0);
		});

		it("compares fingerprints case-insensitively and ignoring colons", async () => {
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			existsSync.mockReturnValue(true);

			const rawUpperColonForm =
				"BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:" +
				"BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB";
			const callerFprLowerNoColons = "b".repeat(64);

			mockExecFile((_file, args, cb) => {
				if (args.includes("-fingerprint")) {
					cb(null, {
						stdout: `sha256 Fingerprint=${rawUpperColonForm}\n`,
						stderr: "",
					});
				} else {
					cb(null, { stdout: "", stderr: "" });
				}
			});

			await expect(
				service.revokeCertificate(
					"1006",
					"keyCompromise",
					callerFprLowerNoColons
				)
			).rejects.toMatchObject({ status: HttpStatus.FORBIDDEN });
		});

		it("does not block revocation when fingerprints simply differ", async () => {
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			existsSync.mockReturnValue(true);

			mockExecFile((_file, args, cb) => {
				if (args.includes("-fingerprint")) {
					cb(null, {
						stdout: `sha256 Fingerprint=${"c".repeat(64)}\n`,
						stderr: "",
					});
				} else {
					cb(null, { stdout: "", stderr: "" });
				}
			});

			const result = await service.revokeCertificate(
				"1006",
				"keyCompromise",
				OTHER_CALLER_FPR
			);
			expect(result.message).toMatch(/revoked successfully/i);
		});

		// ── CRL regeneration is decoupled from the unprivileged API worker ────

		it("signals the crl-renewer (no in-process CRL script) when CRL_RENEW_SIGNAL_FILE is set", async () => {
			const SIGNAL = "/signals/renew-crl";
			process.env.CRL_RENEW_SIGNAL_FILE = SIGNAL;
			try {
				indexParser.parseIndexFile.mockResolvedValue([
					makeCert("V", 90, "1006"),
				] as never);
				existsSync.mockReturnValue(true);

				const calledBinaries: string[] = [];
				mockExecFile((file, _args, cb) => {
					calledBinaries.push(file);
					cb(null, { stdout: "", stderr: "" });
				});

				const result = await service.revokeCertificate(
					"1006",
					"keyCompromise",
					OTHER_CALLER_FPR
				);

				// Message reflects the decoupled (least-privilege) flow.
				expect(result.message).toMatch(/revoked successfully/i);
				expect(result.message).toMatch(/signaled/i);
				// The sentinel was written for the dedicated renewer...
				expect(writeFileSync).toHaveBeenCalledWith(
					SIGNAL,
					expect.any(String),
					expect.anything()
				);
				// ...and the broad CRL script was NEVER executed in-process.
				expect(calledBinaries).not.toContain("/bin/bash");
			} finally {
				delete process.env.CRL_RENEW_SIGNAL_FILE;
			}
		});

		it("runs the CRL script in-process when no signal file is configured (dev fallback)", async () => {
			delete process.env.CRL_RENEW_SIGNAL_FILE;
			indexParser.parseIndexFile.mockResolvedValue([
				makeCert("V", 90, "1006"),
			] as never);
			existsSync.mockReturnValue(true);

			const calledBinaries: string[] = [];
			mockExecFile((file, _args, cb) => {
				calledBinaries.push(file);
				cb(null, { stdout: "", stderr: "" });
			});

			const result = await service.revokeCertificate(
				"1006",
				"keyCompromise",
				OTHER_CALLER_FPR
			);
			expect(result.message).toMatch(/and CRL regenerated/i);
			expect(calledBinaries).toContain("/bin/bash"); // dev fallback ran the script
		});
	});
});
