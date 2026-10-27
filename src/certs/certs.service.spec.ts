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
			reserve: jest.fn((_t: string, cn: string, id: string) =>
				Promise.resolve({
					result: "ok",
					reservationId: id,
					meta: { expiresAt: Date.now() + 60_000, allowedCn: cn },
				})
			),
			commit: jest.fn().mockResolvedValue("ok"),
			release: jest.fn().mockResolvedValue("ok"),
			staleReservations: jest.fn().mockResolvedValue([]),
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
					cb(null, { stdout: "subject=CN=test-cn", stderr: "" });
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
			tokenStore.reserve.mockResolvedValueOnce({ result: "not_found" });
			await expect(
				service.signCsr(FAKE_CSR_PEM, "enroll_invalid")
			).rejects.toMatchObject({ status: HttpStatus.FORBIDDEN });
		});

		it("throws 403 when CSR CN does not match token constraint", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			tokenStore.reserve.mockResolvedValueOnce({ result: "cn_mismatch" });
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

		it("returns the signed certificate and commits the reservation", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			await service.signCsr(FAKE_CSR_PEM, token);
			expect(tokenStore.commit).toHaveBeenCalledWith(
				token,
				expect.any(String),
				"1007"
			);
			expect(tokenStore.release).not.toHaveBeenCalled();
		});

		it("releases the token when the custodian refuses before signing", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			jest.spyOn(
				caCustodianUtil,
				"signCsrViaCustodian"
			).mockRejectedValueOnce(
				new caCustodianUtil.CustodianHttpException(
					"refused",
					HttpStatus.CONFLICT,
					"refused",
					"cn_already_active"
				)
			);
			await expect(
				service.signCsr(FAKE_CSR_PEM, token)
			).rejects.toMatchObject({ status: HttpStatus.CONFLICT });
			expect(tokenStore.release).toHaveBeenCalled();
			expect(tokenStore.commit).not.toHaveBeenCalled();
		});

		it("releases the token when the request never reached the custodian (custodian stopped)", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			jest.spyOn(
				caCustodianUtil,
				"signCsrViaCustodian"
			).mockRejectedValueOnce(
				new caCustodianUtil.CustodianHttpException(
					"down",
					HttpStatus.BAD_GATEWAY,
					"not_sent",
					"ENOTFOUND"
				)
			);
			await expect(
				service.signCsr(FAKE_CSR_PEM, token)
			).rejects.toMatchObject({ status: HttpStatus.BAD_GATEWAY });
			expect(tokenStore.release).toHaveBeenCalled();
		});

		it("on an ambiguous failure, commits if the custodian did issue", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			jest.spyOn(
				caCustodianUtil,
				"signCsrViaCustodian"
			).mockRejectedValueOnce(
				new caCustodianUtil.CustodianHttpException(
					"timeout",
					HttpStatus.BAD_GATEWAY,
					"ambiguous"
				)
			);
			jest.spyOn(
				caCustodianUtil,
				"fetchSignResultViaCustodian"
			).mockResolvedValueOnce({
				state: "issued",
				certificate: FAKE_CERT_PEM,
				serialNumber: "1008",
				expiresAt: "2027-01-01T00:00:00.000Z",
			});
			const result = await service.signCsr(FAKE_CSR_PEM, token);
			expect(result.serialNumber).toBe("1008");
			expect(tokenStore.commit).toHaveBeenCalledWith(
				token,
				expect.any(String),
				"1008"
			);
			expect(tokenStore.release).not.toHaveBeenCalled();
		});

		it("on an ambiguous failure, releases if the custodian has no certificate", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			jest.spyOn(
				caCustodianUtil,
				"signCsrViaCustodian"
			).mockRejectedValueOnce(
				new caCustodianUtil.CustodianHttpException(
					"timeout",
					HttpStatus.BAD_GATEWAY,
					"ambiguous"
				)
			);
			jest.spyOn(
				caCustodianUtil,
				"fetchSignResultViaCustodian"
			).mockResolvedValueOnce({ state: "none" });
			await expect(
				service.signCsr(FAKE_CSR_PEM, token)
			).rejects.toMatchObject({ status: HttpStatus.BAD_GATEWAY });
			expect(tokenStore.release).toHaveBeenCalled();
			expect(tokenStore.commit).not.toHaveBeenCalled();
		});

		it("keeps the reservation when the custodian cannot be asked after an ambiguous failure", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			jest.spyOn(
				caCustodianUtil,
				"signCsrViaCustodian"
			).mockRejectedValueOnce(
				new caCustodianUtil.CustodianHttpException(
					"timeout",
					HttpStatus.BAD_GATEWAY,
					"ambiguous"
				)
			);
			jest.spyOn(
				caCustodianUtil,
				"fetchSignResultViaCustodian"
			).mockRejectedValueOnce(new Error("still down"));
			await expect(
				service.signCsr(FAKE_CSR_PEM, token)
			).rejects.toMatchObject({ status: HttpStatus.BAD_GATEWAY });
			expect(tokenStore.release).not.toHaveBeenCalled();
			expect(tokenStore.commit).not.toHaveBeenCalled();
		});

		it("answers 409 while another enrollment with the token is in progress", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			tokenStore.reserve.mockResolvedValueOnce({ result: "in_progress" });
			await expect(
				service.signCsr(FAKE_CSR_PEM, token)
			).rejects.toMatchObject({ status: HttpStatus.CONFLICT });
		});

		it("names the reason of a token failure in a machine-readable code", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			for (const [result, status, reason] of [
				["in_progress", HttpStatus.CONFLICT, "in_progress"],
				["already_used", HttpStatus.FORBIDDEN, "token_already_used"],
				["expired", HttpStatus.FORBIDDEN, "token_expired"],
				["cn_mismatch", HttpStatus.FORBIDDEN, "cn_mismatch"],
				["not_found", HttpStatus.FORBIDDEN, "token_invalid"],
			] as const) {
				tokenStore.reserve.mockResolvedValueOnce({ result });
				const err = await service
					.signCsr(FAKE_CSR_PEM, token)
					.catch(e => e);
				expect(err.getStatus()).toBe(status);
				expect(err.getResponse()).toMatchObject({ error: reason });
			}
		});

		describe("enrollment replay with the same key (R5)", () => {
			const realFs = jest.requireActual("fs") as typeof fs;
			const fx = (n: string) =>
				realFs.readFileSync(
					require("path").join(__dirname, "__fixtures__", n),
					"utf8"
				);
			const crypto = require("crypto");
			const spkiOf = (pem: string) =>
				crypto
					.createHash("sha256")
					.update(
						new crypto.X509Certificate(pem).publicKey.export({
							type: "spki",
							format: "der",
						})
					)
					.digest("hex");
			function arrange(
				issuedPem: string,
				indexStatus = "V",
				csrKeyOf = "enroll.crt"
			) {
				setupExecSuccess();
				const tokenStore = (service as any)
					.tokenStore as jest.Mocked<any>;
				tokenStore.reserve.mockResolvedValueOnce({
					result: "already_used",
					serial: "10C6",
				});
				jest.spyOn(
					service as any,
					"extractCsrCn"
				).mockResolvedValueOnce("replay-fixture");
				// the CSR in the request carries key A, as enroll.crt does
				jest.spyOn(
					service as any,
					"spkiSha256OfCsrFile"
				).mockResolvedValueOnce(spkiOf(fx(csrKeyOf)));
				jest.spyOn(
					caCustodianUtil,
					"fetchIssuedPemViaCustodian"
				).mockResolvedValueOnce(
					"Certificate:\n    text dump\n" + issuedPem
				);
				jest.spyOn(
					caCustodianUtil,
					"fetchIndexViaCustodian"
				).mockResolvedValueOnce(
					`${indexStatus}\t361026000000Z\t${indexStatus === "R" ? "261025000000Z,keyCompromise" : ""}\t10C6\tunknown\t/CN=replay-fixture\n`
				);
			}
			it("gives the committed certificate back to a retry with the same key", async () => {
				arrange(fx("enroll.crt"));
				const r: any = await service.signCsr(fx("enroll.csr"), token);
				expect(r.replay).toBe(true);
				expect(r.serialNumber).toBe("10C6");
				expect(r.certificate).toContain("BEGIN CERTIFICATE");
			});
			it("refuses a retry with a different key (403 token_already_used)", async () => {
				arrange(fx("other-key.crt"));
				const err = await service
					.signCsr(fx("enroll.csr"), token)
					.catch(e => e);
				expect(err.getStatus()).toBe(HttpStatus.FORBIDDEN);
				expect(err.getResponse()).toMatchObject({
					error: "token_already_used",
				});
			});
			it("refuses when the committed certificate names another CN", async () => {
				arrange(fx("other-cn.crt"));
				const err = await service
					.signCsr(fx("enroll.csr"), token)
					.catch(e => e);
				expect(err.getStatus()).toBe(HttpStatus.FORBIDDEN);
			});
			it("audits a used token tried with another key apart (token.replay_mismatch)", async () => {
				arrange(fx("other-key.crt"));
				await service
					.signCsr(fx("enroll.csr"), token)
					.catch(() => undefined);
				expect((service as any).adminAudit.append).toHaveBeenCalledWith(
					expect.objectContaining({
						action: "token.replay_mismatch",
						params: expect.objectContaining({
							reason: "replay_key_mismatch",
						}),
					})
				);
			});
			it("audits a replay as cert.enroll.replay, not as a new issuance", async () => {
				arrange(fx("enroll.crt"));
				await service.signCsr(fx("enroll.csr"), token);
				expect((service as any).adminAudit.append).toHaveBeenCalledWith(
					expect.objectContaining({ action: "cert.enroll.replay" })
				);
			});
			it("answers 503 replay_unavailable (retry) when the custodian cannot be asked", async () => {
				setupExecSuccess();
				const tokenStore = (service as any)
					.tokenStore as jest.Mocked<any>;
				tokenStore.reserve.mockResolvedValueOnce({
					result: "already_used",
					serial: "10C6",
				});
				jest.spyOn(
					service as any,
					"extractCsrCn"
				).mockResolvedValueOnce("replay-fixture");
				jest.spyOn(
					caCustodianUtil,
					"fetchIssuedPemViaCustodian"
				).mockRejectedValueOnce(new Error("custodian down"));
				const err = await service
					.signCsr(fx("enroll.csr"), token)
					.catch(e => e);
				expect(err.getStatus()).toBe(HttpStatus.SERVICE_UNAVAILABLE);
				expect(err.getResponse()).toMatchObject({
					error: "replay_unavailable",
					retryAfterSeconds: 30,
				});
			});
			it("refuses a revoked committed certificate (403 certificate_revoked)", async () => {
				arrange(fx("enroll.crt"), "R");
				const err = await service
					.signCsr(fx("enroll.csr"), token)
					.catch(e => e);
				expect(err.getStatus()).toBe(HttpStatus.FORBIDDEN);
				expect(err.getResponse()).toMatchObject({
					error: "certificate_revoked",
				});
			});
			it("refuses an expired committed certificate (403 certificate_expired)", async () => {
				arrange(fx("expired.crt"), "V", "expired.crt");
				const err = await service
					.signCsr(fx("enroll.csr"), token)
					.catch(e => e);
				expect(err.getStatus()).toBe(HttpStatus.FORBIDDEN);
				expect(err.getResponse()).toMatchObject({
					error: "certificate_expired",
				});
			});
			it("replays on the stale-reservation path too, when the reconcile finds the certificate", async () => {
				setupExecSuccess();
				const tokenStore = (service as any)
					.tokenStore as jest.Mocked<any>;
				tokenStore.reserve.mockResolvedValueOnce({
					result: "stale_reservation",
					reservationId: "old",
					meta: { expiresAt: 0, allowedCn: "replay-fixture" },
				});
				jest.spyOn(
					service as any,
					"extractCsrCn"
				).mockResolvedValueOnce("replay-fixture");
				jest.spyOn(
					service as any,
					"spkiSha256OfCsrFile"
				).mockResolvedValueOnce(spkiOf(fx("enroll.crt")));
				jest.spyOn(
					caCustodianUtil,
					"fetchSignResultViaCustodian"
				).mockResolvedValueOnce({
					state: "issued",
					certificate: fx("enroll.crt"),
					serialNumber: "10C6",
					expiresAt: "",
				});
				jest.spyOn(
					caCustodianUtil,
					"fetchIndexViaCustodian"
				).mockResolvedValueOnce(
					"V\t361026000000Z\t\t10C6\tunknown\t/CN=replay-fixture\n"
				);
				const r: any = await service.signCsr(fx("enroll.csr"), token);
				expect(r.replay).toBe(true);
				expect(tokenStore.commit).toHaveBeenCalledWith(
					token,
					"old",
					"10C6"
				);
			});
		});

		it("names the CN in the audit entry of a reconcile release", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			const audit = (service as any).adminAudit;
			tokenStore.staleReservations = jest.fn().mockResolvedValue([
				{
					token,
					reservationId: "r1",
					meta: { expiresAt: 0, allowedCn: "lost-cn" },
				},
			]);
			jest.spyOn(
				caCustodianUtil,
				"fetchSignResultViaCustodian"
			).mockResolvedValueOnce({ state: "none" });
			await service.reconcileStaleReservations();
			expect(audit.append).toHaveBeenCalledWith(
				expect.objectContaining({
					action: "token.release",
					target: "cn=lost-cn",
				})
			);
		});

		it("treats a stale reservation the custodian completed as an already-used token", async () => {
			setupExecSuccess();
			const tokenStore = (service as any).tokenStore as jest.Mocked<any>;
			tokenStore.reserve.mockResolvedValueOnce({
				result: "stale_reservation",
				reservationId: "old",
				meta: { expiresAt: 0, allowedCn: "test-cn" },
			});
			jest.spyOn(
				caCustodianUtil,
				"fetchSignResultViaCustodian"
			).mockResolvedValueOnce({
				state: "issued",
				certificate: FAKE_CERT_PEM,
				serialNumber: "1009",
				expiresAt: "",
			});
			await expect(
				service.signCsr(FAKE_CSR_PEM, token)
			).rejects.toMatchObject({ status: HttpStatus.FORBIDDEN });
			expect(tokenStore.commit).toHaveBeenCalledWith(
				token,
				"old",
				"1009"
			);
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
					cb(null, { stdout: "subject=CN=my-service", stderr: "" });
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
					cb(null, { stdout: "subject=CN=my-service", stderr: "" });
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
				// The sentinel was written for the dedicated renewer…
				expect(writeFileSync).toHaveBeenCalledWith(
					SIGNAL,
					expect.any(String),
					expect.anything()
				);
				// …and the broad CRL script was NEVER executed in-process.
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
