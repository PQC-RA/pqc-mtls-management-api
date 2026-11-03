import * as crypto from "crypto";

import { HttpStatus, Logger } from "@nestjs/common";

import {
	CustodianHttpException,
	issueCrlViaCustodian,
	revokeViaCustodian,
	signCsrViaCustodian,
} from "@/common/ca-custodian.util";

const SECRET = "0123456789abcdef0123456789abcdef";

// A custodian answer signed the way custodian.js signs it (v2r, bound to the
// request's nonce), so the client accepts it as authentic.
function custodianAnswer(status: number, body: unknown) {
	return jest.fn((_url: string, init: RequestInit) => {
		const raw = Buffer.from(JSON.stringify(body));
		const nonce = (init.headers as Record<string, string>)[
			"X-Custodian-Nonce"
		];
		const sig = crypto
			.createHmac("sha256", SECRET)
			.update(
				`v2r\n${status}\n${nonce}\n${crypto.createHash("sha256").update(raw).digest("hex")}`
			)
			.digest("hex");
		return Promise.resolve({
			ok: status >= 200 && status < 300,
			status,
			headers: new Headers({
				"x-custodian-response-signature": `sha256=${sig}`,
			}),
			arrayBuffer: () => Promise.resolve(raw),
		});
	}) as unknown as typeof fetch;
}

describe("ca-custodian.util", () => {
	const logger = new Logger("test");
	const realFetch = global.fetch;
	beforeAll(() => {
		process.env.CUSTODIAN_HMAC_SECRET = SECRET;
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
		// The custodian is down: a retryable 503, not a 502 or a 500.
		expect((err as CustodianHttpException).getStatus()).toBe(
			HttpStatus.SERVICE_UNAVAILABLE
		);
	});

	it("keeps 502 for a call that may have reached the custodian", async () => {
		global.fetch = jest.fn().mockRejectedValue(
			Object.assign(new TypeError("fetch failed"), {
				cause: { code: "ECONNRESET" },
			})
		) as unknown as typeof fetch;
		const err = await signCsrViaCustodian(logger, "csr").catch(e => e);
		expect((err as CustodianHttpException).kind).toBe("ambiguous");
		expect((err as CustodianHttpException).getStatus()).toBe(
			HttpStatus.BAD_GATEWAY
		);
	});

	it.each(["not_ready", "stopping"])(
		"turns the custodian's 503 %s into a retryable 503, nothing sent",
		async code => {
			global.fetch = custodianAnswer(503, {
				error: code,
				message: "retry",
			});
			const err = await revokeViaCustodian(logger, "10A1").catch(e => e);
			expect(err).toBeInstanceOf(CustodianHttpException);
			expect((err as CustodianHttpException).kind).toBe("not_sent");
			expect((err as CustodianHttpException).getStatus()).toBe(
				HttpStatus.SERVICE_UNAVAILABLE
			);
		}
	);

	describe("revoke and the CRL (ADR-024)", () => {
		it("a custodian that is not the CRL issuer answers {ok:true}: no CRL status", async () => {
			global.fetch = custodianAnswer(200, { ok: true });
			await expect(revokeViaCustodian(logger, "10A1")).resolves.toEqual({
				crl: undefined,
				crlNumber: undefined,
			});
		});

		it("200 published carries the CRL number", async () => {
			global.fetch = custodianAnswer(200, {
				ok: true,
				crl: "published",
				crlNumber: "0x10F9",
			});
			await expect(revokeViaCustodian(logger, "10A1")).resolves.toEqual({
				crl: "published",
				crlNumber: "0x10F9",
			});
		});

		it("202 pending is a recorded revocation, not an error", async () => {
			global.fetch = custodianAnswer(202, { ok: true, crl: "pending" });
			await expect(revokeViaCustodian(logger, "10A1")).resolves.toEqual({
				crl: "pending",
				crlNumber: undefined,
			});
		});

		it("an unknown crl value is ignored, so the renewer path is taken", async () => {
			global.fetch = custodianAnswer(200, { ok: true, crl: "maybe" });
			await expect(revokeViaCustodian(logger, "10A1")).resolves.toEqual({
				crl: undefined,
				crlNumber: undefined,
			});
		});

		it("issueCrlViaCustodian returns the new CRL number", async () => {
			global.fetch = custodianAnswer(200, {
				ok: true,
				crl: "published",
				crlNumber: "0x10FA",
			});
			await expect(issueCrlViaCustodian(logger)).resolves.toEqual({
				crlNumber: "0x10FA",
			});
		});

		it("issueCrlViaCustodian returns null when the custodian is not the CRL issuer (404)", async () => {
			global.fetch = custodianAnswer(404, {
				error: "not_crl_issuer",
				message: "no",
			});
			await expect(issueCrlViaCustodian(logger)).resolves.toBeNull();
		});

		it("issueCrlViaCustodian does not hide other errors", async () => {
			global.fetch = custodianAnswer(500, {
				error: "crl_failed",
				message: "no",
			});
			await expect(issueCrlViaCustodian(logger)).rejects.toBeInstanceOf(
				CustodianHttpException
			);
		});
	});
});
