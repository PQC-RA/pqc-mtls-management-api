import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { HttpException, HttpStatus } from "@nestjs/common";

import { AdminAuditService } from "@/admin-audit/admin-audit.service";
import { CertsService } from "@/certs/certs.service";
import * as custodian from "@/common/ca-custodian.util";
import { CustodianHttpException } from "@/common/ca-custodian.util";
import { RenewService } from "@/renew/renew.service";

jest.mock("@/common/ca-custodian.util", () => {
	const actual = jest.requireActual("@/common/ca-custodian.util");
	return {
		...actual,
		fetchIssuedPemViaCustodian: jest.fn(),
		fetchLineageViaCustodian: jest.fn(),
		fetchSignResultViaCustodian: jest.fn(),
		freezeLineageViaCustodian: jest.fn(),
		revokeViaCustodian: jest.fn(),
		signCsrViaCustodian: jest.fn(),
	};
});
jest.mock("@/common/crl-signal.util", () => ({
	triggerCrlRegeneration: jest.fn().mockResolvedValue("signaled"),
}));

// Real ML-DSA-65 material made offline with OpenSSL 3.6.2 (see __fixtures__/README.txt):
// the predecessor is a 120 s leaf issued 2026-11-01T00:00:00Z (notBefore backdated 60 s).
const FX = path.join(__dirname, "__fixtures__");
const predPem = fs.readFileSync(path.join(FX, "pred.crt"), "utf8");
const newCsr = fs.readFileSync(path.join(FX, "new.csr"), "utf8");
const meta = JSON.parse(fs.readFileSync(path.join(FX, "meta.json"), "utf8"));
const T0 = Date.UTC(2026, 10, 1, 0, 0, 0);

const mocked = custodian as jest.Mocked<typeof custodian>;

function attestation(
	over: Partial<{ fingerprint: string; serial: string }> = {}
) {
	return {
		fingerprint: meta.fingerprint,
		serial: meta.serial,
		notAfter: "Nov  1 00:02:00 2026 GMT",
		...over,
	};
}
function dto(
	over: Partial<{ csr: string; timestamp: number; signature: string }> = {}
) {
	return {
		csr: over.csr ?? newCsr,
		pop: {
			timestamp: over.timestamp ?? meta.popTimestamp,
			signature: over.signature ?? meta.popSignature,
		},
	};
}
async function expectRefusal(
	p: Promise<unknown>,
	status: HttpStatus,
	error: string
) {
	try {
		await p;
	} catch (e) {
		expect(e).toBeInstanceOf(HttpException);
		expect((e as HttpException).getStatus()).toBe(status);
		expect(
			((e as HttpException).getResponse() as { error: string }).error
		).toBe(error);
		return;
	}
	throw new Error(`expected ${status} ${error}`);
}

describe("RenewService", () => {
	let service: RenewService;
	let audit: { append: jest.Mock };
	let alerts: string;

	beforeEach(() => {
		jest.clearAllMocks();
		jest.spyOn(Date, "now").mockReturnValue(T0 + 90_000);
		audit = { append: jest.fn().mockResolvedValue(null) };
		const certs = {
			checkCsrForIssuance: jest
				.fn()
				.mockResolvedValue("renew-fixture-client"),
		};
		service = new RenewService(
			certs as unknown as CertsService,
			audit as unknown as AdminAuditService
		);
		jest.spyOn(
			service as unknown as { spkiSha256OfCsr: () => Promise<string> },
			"spkiSha256OfCsr"
		).mockResolvedValue(meta.newSpkiSha256);
		alerts = path.join(
			fs.mkdtempSync(path.join(os.tmpdir(), "renew-spec-")),
			"renew-alerts.log"
		);
		process.env.RENEW_ALERTS_LOG = alerts;
		mocked.fetchIssuedPemViaCustodian.mockResolvedValue(predPem);
		mocked.fetchLineageViaCustodian.mockResolvedValue({
			serial: meta.serial,
			lineageId: meta.serial,
			bootstrapAt: T0,
			profile: "demo-120s",
			predecessor: null,
			capAt: "",
		});
		mocked.signCsrViaCustodian.mockResolvedValue({
			certificate: "PEM",
			serialNumber: "10A1",
			expiresAt: "2026-11-01T00:03:30.000Z",
		});
	});

	afterEach(() => jest.restoreAllMocks());

	it("renews: the CSR goes to the custodian with the predecessor and a server-computed idempotency key", async () => {
		const r = await service.renew(attestation(), dto());
		expect(r.serialNumber).toBe("10A1");
		expect(mocked.signCsrViaCustodian).toHaveBeenCalledWith(
			expect.anything(),
			newCsr,
			{
				renewsSerial: meta.serial,
				idempotencyKey: `renew:${meta.serial}:${meta.newSpkiSha256}`,
			}
		);
		expect(audit.append).toHaveBeenCalledWith(
			expect.objectContaining({
				action: "cert.renew",
				result: expect.objectContaining({ status: "ok" }),
			})
		);
	});

	it("refuses a presented certificate that is not the issued one for its serial", async () => {
		await expectRefusal(
			service.renew(attestation({ fingerprint: "0".repeat(64) }), dto()),
			HttpStatus.FORBIDDEN,
			"certificate_mismatch"
		);
		expect(mocked.signCsrViaCustodian).not.toHaveBeenCalled();
	});

	it("refuses before half of the lifetime", async () => {
		jest.spyOn(Date, "now").mockReturnValue(T0 + 30_000);
		await expectRefusal(
			service.renew(
				attestation(),
				dto({ timestamp: Math.floor((T0 + 30_000) / 1000) })
			),
			HttpStatus.CONFLICT,
			"too_early"
		);
	});

	it("refuses an expired predecessor", async () => {
		jest.spyOn(Date, "now").mockReturnValue(T0 + 130_000);
		await expectRefusal(
			service.renew(attestation(), dto()),
			HttpStatus.FORBIDDEN,
			"not_valid"
		);
	});

	it("refuses a proof made by any key other than the current one", async () => {
		await expectRefusal(
			service.renew(
				attestation(),
				dto({ signature: meta.wrongPopSignature })
			),
			HttpStatus.FORBIDDEN,
			"pop_invalid"
		);
		expect(mocked.signCsrViaCustodian).not.toHaveBeenCalled();
	});

	it("refuses a valid proof for a different CSR", async () => {
		const other = newCsr
			.replace(/(\n[A-Za-z0-9+/]{10})A/, "$1B")
			.replace(/(\n[A-Za-z0-9+/]{10})[^A\n]/, "$1A");
		expect(other).not.toBe(newCsr);
		await expectRefusal(
			service.renew(attestation(), dto({ csr: other })),
			HttpStatus.FORBIDDEN,
			"pop_invalid"
		);
	});

	it("refuses a stale proof timestamp", async () => {
		await expectRefusal(
			service.renew(
				attestation(),
				dto({ timestamp: meta.popTimestamp - 300 })
			),
			HttpStatus.BAD_REQUEST,
			"pop_stale"
		);
	});

	it("refuses a certificate with no lineage (not issued under a renewal profile)", async () => {
		mocked.fetchLineageViaCustodian.mockRejectedValue(
			new CustodianHttpException(
				"nf",
				HttpStatus.NOT_FOUND,
				"refused",
				"not_found"
			)
		);
		await expectRefusal(
			service.renew(attestation(), dto()),
			HttpStatus.FORBIDDEN,
			"not_renewable"
		);
	});

	it("refuses a frozen identity", async () => {
		mocked.fetchLineageViaCustodian.mockResolvedValue({
			serial: meta.serial,
			lineageId: meta.serial,
			bootstrapAt: T0,
			profile: "demo-120s",
			predecessor: null,
			frozen: true,
			capAt: "",
		});
		await expectRefusal(
			service.renew(attestation(), dto()),
			HttpStatus.FORBIDDEN,
			"lineage_frozen"
		);
	});

	it("conflict rule: a second key for one predecessor freezes, revokes both, alerts", async () => {
		mocked.signCsrViaCustodian.mockRejectedValue(
			new CustodianHttpException(
				"exists",
				HttpStatus.CONFLICT,
				"refused",
				"successor_exists",
				{ successorSerial: "10A1" }
			)
		);
		await expectRefusal(
			service.renew(attestation(), dto()),
			HttpStatus.CONFLICT,
			"renewal_conflict"
		);
		expect(mocked.freezeLineageViaCustodian).toHaveBeenCalledWith(
			expect.anything(),
			meta.serial
		);
		expect(mocked.revokeViaCustodian).toHaveBeenCalledWith(
			expect.anything(),
			meta.serial,
			"keyCompromise"
		);
		expect(mocked.revokeViaCustodian).toHaveBeenCalledWith(
			expect.anything(),
			"10A1",
			"keyCompromise"
		);
		expect(service.conflicts).toBe(1);
		expect(fs.readFileSync(alerts, "utf8")).toContain(
			'"event":"renew.conflict"'
		);
		expect(audit.append).toHaveBeenCalledWith(
			expect.objectContaining({ action: "renew.conflict" })
		);
	});

	it("an ambiguous custodian failure is settled from the idempotency record", async () => {
		mocked.signCsrViaCustodian.mockRejectedValue(
			new CustodianHttpException("x", HttpStatus.BAD_GATEWAY, "ambiguous")
		);
		mocked.fetchSignResultViaCustodian.mockResolvedValue({
			state: "issued",
			certificate: "PEM",
			serialNumber: "10A1",
			expiresAt: "x",
		});
		const r = await service.renew(attestation(), dto());
		expect(r).toEqual(
			expect.objectContaining({ serialNumber: "10A1", replay: true })
		);
	});

	it("an ambiguous failure with nothing issued asks the client to retry with the same key", async () => {
		mocked.signCsrViaCustodian.mockRejectedValue(
			new CustodianHttpException("x", HttpStatus.BAD_GATEWAY, "ambiguous")
		);
		mocked.fetchSignResultViaCustodian.mockResolvedValue({ state: "none" });
		await expectRefusal(
			service.renew(attestation(), dto()),
			HttpStatus.SERVICE_UNAVAILABLE,
			"retry"
		);
	});

	it("passes a custodian refusal through (for example the lineage cap)", async () => {
		mocked.signCsrViaCustodian.mockRejectedValue(
			new CustodianHttpException(
				"cap",
				HttpStatus.CONFLICT,
				"refused",
				"lineage_cap_reached"
			)
		);
		await expectRefusal(
			service.renew(attestation(), dto()),
			HttpStatus.CONFLICT,
			"lineage_cap_reached"
		);
	});
});
