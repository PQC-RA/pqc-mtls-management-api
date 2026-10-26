import { Logger } from "@nestjs/common";

import {
	CustodianHttpException,
	signCsrViaCustodian,
} from "@/common/ca-custodian.util";

describe("ca-custodian.util", () => {
	const logger = new Logger("test");
	const realFetch = global.fetch;
	beforeAll(() => {
		process.env.CUSTODIAN_HMAC_SECRET = "0123456789abcdef0123456789abcdef";
		jest.spyOn(logger, "error").mockImplementation(() => undefined);
	});
	afterEach(() => {
		global.fetch = realFetch;
	});

	it("turns an answer whose body is cut off into an ambiguous custodian error, not a bare abort", async () => {
		global.fetch = jest.fn().mockResolvedValue({
			ok: true,
			status: 201,
			headers: new Headers(),
			arrayBuffer: () =>
				Promise.reject(
					Object.assign(
						new Error("The operation was aborted due to timeout"),
						{ name: "TimeoutError" }
					)
				),
		}) as unknown as typeof fetch;
		const err = await signCsrViaCustodian(logger, "csr").catch(e => e);
		expect(err).toBeInstanceOf(CustodianHttpException);
		expect((err as CustodianHttpException).kind).toBe("ambiguous");
	});

	it("treats a refused connection as not sent", async () => {
		global.fetch = jest.fn().mockRejectedValue(
			Object.assign(new TypeError("fetch failed"), {
				cause: { code: "ECONNREFUSED" },
			})
		) as unknown as typeof fetch;
		const err = await signCsrViaCustodian(logger, "csr").catch(e => e);
		expect((err as CustodianHttpException).kind).toBe("not_sent");
	});
});
