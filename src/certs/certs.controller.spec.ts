jest.mock("@/common/guards/jwt-auth.guard", () => ({
	JwtAuthGuard: class MockJwtAuthGuard {
		canActivate() {
			return true;
		}
	},
}));

import { Test, TestingModule } from "@nestjs/testing";

import {
	CertsController,
	checkEnrollmentProfileConfig,
} from "@/certs/certs.controller";
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
			"my-service",
			undefined
		);
	});

	describe("enrollment token profile (DEFAULT_ENROLLMENT_PROFILE)", () => {
		const saved = { ...process.env };
		afterEach(() => {
			process.env = { ...saved };
		});
		const created = async (profile?: string) => {
			certsService.createEnrollmentToken.mockResolvedValue("enroll_xyz");
			await controller.createEnrollmentToken("my-service", 3600, profile);
			return certsService.createEnrollmentToken.mock.calls.at(-1)?.[2];
		};

		it("no default configured: an omitted profile stays legacy", async () => {
			delete process.env.DEFAULT_ENROLLMENT_PROFILE;
			process.env.RENEWAL_ENABLED = "1";
			expect(await created()).toBeUndefined();
		});

		it("default client-30d with renewal on: an omitted profile becomes client-30d", async () => {
			process.env.DEFAULT_ENROLLMENT_PROFILE = "client-30d";
			process.env.RENEWAL_ENABLED = "1";
			expect(await created()).toBe("client-30d");
		});

		it("default client-30d with renewal off: an omitted profile stays legacy", async () => {
			process.env.DEFAULT_ENROLLMENT_PROFILE = "client-30d";
			delete process.env.RENEWAL_ENABLED;
			expect(await created()).toBeUndefined();
		});

		it("explicit legacy overrides the default (clients that cannot renew)", async () => {
			process.env.DEFAULT_ENROLLMENT_PROFILE = "client-30d";
			process.env.RENEWAL_ENABLED = "1";
			expect(await created("legacy")).toBeUndefined();
		});

		it("explicit demo-120s overrides the default", async () => {
			process.env.DEFAULT_ENROLLMENT_PROFILE = "client-30d";
			process.env.RENEWAL_ENABLED = "1";
			expect(await created("demo-120s")).toBe("demo-120s");
		});

		it("an unknown profile is refused with 400", async () => {
			await expect(
				controller.createEnrollmentToken(
					"my-service",
					3600,
					"client-90d"
				)
			).rejects.toMatchObject({ status: 400 });
		});

		it("the response names the effective profile", async () => {
			process.env.DEFAULT_ENROLLMENT_PROFILE = "client-30d";
			process.env.RENEWAL_ENABLED = "1";
			certsService.createEnrollmentToken.mockResolvedValue("enroll_xyz");
			const a = await controller.createEnrollmentToken(
				"my-service",
				3600
			);
			expect(a.profile).toBe("client-30d");
			const b = await controller.createEnrollmentToken(
				"my-service",
				3600,
				"legacy"
			);
			expect(b.profile).toBe("legacy");
		});

		it("a whitespace or legacy default stays legacy", async () => {
			process.env.RENEWAL_ENABLED = "1";
			process.env.DEFAULT_ENROLLMENT_PROFILE = "  ";
			expect(await created()).toBeUndefined();
			process.env.DEFAULT_ENROLLMENT_PROFILE = "legacy";
			expect(await created()).toBeUndefined();
		});

		it("explicit client-30d with renewal off reaches the service (which refuses), no silent downgrade", async () => {
			process.env.DEFAULT_ENROLLMENT_PROFILE = "client-30d";
			delete process.env.RENEWAL_ENABLED;
			expect(await created("client-30d")).toBe("client-30d");
		});

		it("a missing cn is still a 400 even with an invalid default", async () => {
			process.env.DEFAULT_ENROLLMENT_PROFILE = "bogus";
			await expect(
				controller.createEnrollmentToken("", 3600)
			).rejects.toMatchObject({ status: 400 });
		});

		it("startup check: invalid default throws, client-30d without renewal warns", () => {
			process.env.DEFAULT_ENROLLMENT_PROFILE = "client-30D";
			expect(() => checkEnrollmentProfileConfig()).toThrow(/invalid/);
			process.env.DEFAULT_ENROLLMENT_PROFILE = "client-30d";
			delete process.env.RENEWAL_ENABLED;
			expect(checkEnrollmentProfileConfig()).toMatch(/no effect/);
			process.env.RENEWAL_ENABLED = "1";
			expect(checkEnrollmentProfileConfig()).toBeUndefined();
		});

		it("an invalid default is a loud 500, never a silent fallback", async () => {
			process.env.DEFAULT_ENROLLMENT_PROFILE = "demo-120s";
			process.env.RENEWAL_ENABLED = "1";
			await expect(
				controller.createEnrollmentToken("my-service", 3600)
			).rejects.toMatchObject({ status: 500 });
		});
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
