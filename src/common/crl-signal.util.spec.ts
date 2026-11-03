jest.mock("fs");
import * as fs from "fs";

import { Logger } from "@nestjs/common";

import { crlAfterRevocation } from "@/common/crl-signal.util";

const writeFileSync = jest.mocked(fs.writeFileSync);

describe("crlAfterRevocation (ADR-024)", () => {
	const logger = new Logger("test");
	beforeAll(() => {
		jest.spyOn(logger, "warn").mockImplementation(() => undefined);
		jest.spyOn(logger, "error").mockImplementation(() => undefined);
	});
	beforeEach(() => {
		writeFileSync.mockReset();
		process.env.CRL_RENEW_SIGNAL_FILE = "/signals/renew-crl";
	});
	afterAll(() => {
		delete process.env.CRL_RENEW_SIGNAL_FILE;
	});

	it("the custodian published the CRL: nothing more, no sentinel", async () => {
		await expect(
			crlAfterRevocation(logger, [
				{ crl: "published", crlNumber: "0x10" },
			])
		).resolves.toBe("published");
		expect(writeFileSync).not.toHaveBeenCalled();
	});

	it("the custodian is retrying its CRL: pending, still no sentinel", async () => {
		await expect(
			crlAfterRevocation(logger, [
				{ crl: "published" },
				{ crl: "pending" },
			])
		).resolves.toBe("pending");
		expect(writeFileSync).not.toHaveBeenCalled();
		expect(logger.warn).toHaveBeenCalled();
	});

	it("an answer without a CRL status: the custodian is not the CRL issuer, so the renewer is signalled", async () => {
		await expect(crlAfterRevocation(logger, [{}])).resolves.toBe(
			"signaled"
		);
		expect(writeFileSync).toHaveBeenCalledWith(
			"/signals/renew-crl",
			expect.any(String),
			{ flag: "w" }
		);
	});

	it("no successful revocation at all: the renewer is still asked, as before", async () => {
		await expect(crlAfterRevocation(logger, [])).resolves.toBe("signaled");
		expect(writeFileSync).toHaveBeenCalled();
	});
});
