jest.mock("@/common/guards/jwt-auth.guard", () => ({
	JwtAuthGuard: class MockJwtAuthGuard {
		canActivate() {
			return true;
		}
	},
}));

import { Test, TestingModule } from "@nestjs/testing";

import { CertsController } from "@/certs/certs.controller";
import { CertsService } from "@/certs/certs.service";
import { RevocationReason } from "@/certs/dto/revoke-cert.dto";
import { JwtAuthGuard } from "@/common/guards/jwt-auth.guard";

const FAKE_CERT =
	"-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n";
const FAKE_CSR =
	"-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----\n";

describe("CertsController", () => {
	let controller: CertsController;
	let certsService: jest.Mocked<CertsService>;

	beforeEach(async () => {
		certsService = {
			getAllCertificates: jest.fn(),
			getCertificates: jest.fn(),
			getExpiringCertificates: jest.fn(),
			getCertificate: jest.fn(),
			getCertificateDetail: jest.fn(),
			signCsr: jest.fn(),
			validateCsr: jest.fn(),
			revokeCertificate: jest.fn(),
			createEnrollmentToken: jest.fn(),
			listEnrollmentTokens: jest.fn(),
			revokeEnrollmentToken: jest.fn(),
		} as any;

		const module: TestingModule = await Test.createTestingModule({
			controllers: [CertsController],
			providers: [{ provide: CertsService, useValue: certsService }],
		})
			.overrideGuard(JwtAuthGuard)
			.useValue({ canActivate: () => true })
			.compile();

		controller = module.get<CertsController>(CertsController);
	});

	it("should be defined", () => {
		expect(controller).toBeDefined();
	});

	it("getAllCertificates delegates to service", async () => {
		certsService.getCertificates.mockResolvedValue([]);
		const result = await controller.getAllCertificates({});
		expect(result).toEqual([]);
		expect(certsService.getCertificates).toHaveBeenCalledWith({});
	});

	it("getAllCertificates passes filter/pagination query through", async () => {
		certsService.getCertificates.mockResolvedValue([]);
		await controller.getAllCertificates({ status: "V", limit: 10 } as any);
		expect(certsService.getCertificates).toHaveBeenCalledWith({
			status: "V",
			limit: 10,
		});
	});

	it("getExpiringCertificates passes days to service", async () => {
		certsService.getExpiringCertificates.mockResolvedValue([]);
		await controller.getExpiringCertificates(14);
		expect(certsService.getExpiringCertificates).toHaveBeenCalledWith(14);
	});

	it("getCertificateBySerial delegates to the enriched detail service", async () => {
		const cert = { serialNumber: "1006", status: "V" } as any;
		certsService.getCertificateDetail.mockResolvedValue(cert);
		const result = await controller.getCertificateBySerial({
			serial: "1006",
		} as any);
		expect(result).toBe(cert);
		expect(certsService.getCertificateDetail).toHaveBeenCalledWith("1006");
	});

	it("signCsr delegates to service with csr, token, and source ip", async () => {
		certsService.signCsr.mockResolvedValue({
			certificate: FAKE_CERT,
			serialNumber: "1007",
			expiresAt: "2027-03-10T06:00:00.000Z",
		});
		const result = await controller.signCsr(
			{ csr: FAKE_CSR, enrollmentToken: "enroll_abc" },
			"203.0.113.5"
		);
		expect(result.certificate).toBe(FAKE_CERT);
		expect(certsService.signCsr).toHaveBeenCalledWith(
			FAKE_CSR,
			"enroll_abc",
			"203.0.113.5"
		);
	});

	it("validateCsr delegates to service without signing", async () => {
		certsService.validateCsr.mockResolvedValue({
			valid: true,
			cn: "my-service",
			publicKeyAlgorithm: "ML-DSA-65",
		});
		const result = await controller.validateCsr({ csr: FAKE_CSR });
		expect(result.valid).toBe(true);
		expect(certsService.validateCsr).toHaveBeenCalledWith(FAKE_CSR);
	});

	it("createEnrollmentToken returns token, expiresAt, and allowedCn", async () => {
		certsService.createEnrollmentToken.mockResolvedValue("enroll_xyz");
		const result = await controller.createEnrollmentToken(
			"my-service",
			3600
		);
		expect(result.token).toBe("enroll_xyz");
		expect(result.expiresAt).toBeGreaterThan(Date.now());
		expect(result.allowedCn).toBe("my-service");
		expect(certsService.createEnrollmentToken).toHaveBeenCalledWith(
			3600,
			"my-service"
		);
	});

	it("createEnrollmentToken throws 400 when cn is missing", async () => {
		await expect(
			controller.createEnrollmentToken("", 3600)
		).rejects.toMatchObject({
			status: 400,
		});
	});

	it("listEnrollmentTokens delegates to service", async () => {
		certsService.listEnrollmentTokens.mockResolvedValue([]);
		const result = await controller.listEnrollmentTokens();
		expect(result).toEqual([]);
	});

	it("revokeEnrollmentToken delegates to service", async () => {
		await controller.revokeEnrollmentToken("enroll_abc");
		expect(certsService.revokeEnrollmentToken).toHaveBeenCalledWith(
			"enroll_abc"
		);
	});

	it("revokeCertificate delegates to service, passing the caller's own fingerprint", async () => {
		certsService.revokeCertificate.mockResolvedValue({
			message:
				"Certificate 1006 revoked successfully and CRL regenerated.",
		});
		const identity = {
			sub: "some-other-admin",
			fpr: "f".repeat(64),
			role: "admin" as const,
		};
		const result = await controller.revokeCertificate(
			{ serial: "1006", reason: RevocationReason.KeyCompromise },
			identity
		);
		expect(result.message).toMatch(/revoked/i);
		expect(certsService.revokeCertificate).toHaveBeenCalledWith(
			"1006",
			RevocationReason.KeyCompromise,
			identity.fpr
		);
	});
});
