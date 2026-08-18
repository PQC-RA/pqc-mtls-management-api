import { ExecutionContext, ForbiddenException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";

import { IS_PUBLIC_KEY } from "@/common/decorators/public.decorator";
import { CsrfGuard } from "@/common/guards/csrf.guard";

const ORIGIN = "https://console.example.com";

function makeContext(opts: {
	method: string;
	origin?: string;
	csrfHeader?: string;
}): ExecutionContext {
	const headers: Record<string, string> = {};
	if (opts.origin !== undefined) headers["origin"] = opts.origin;
	if (opts.csrfHeader !== undefined) headers["x-pqc-csrf"] = opts.csrfHeader;
	return {
		getHandler: () => undefined,
		getClass: () => undefined,
		switchToHttp: () => ({
			getRequest: () => ({
				method: opts.method,
				url: "/api/admin/x",
				headers,
			}),
		}),
	} as unknown as ExecutionContext;
}

function makeGuard(isPublic = false) {
	const getAllAndOverride = jest.fn(() => isPublic);
	const reflector = { getAllAndOverride } as unknown as Reflector;
	return { guard: new CsrfGuard(reflector), getAllAndOverride };
}

describe("CsrfGuard", () => {
	beforeEach(() => {
		process.env.CONSOLE_ORIGIN = ORIGIN;
		delete process.env.CORS_ALLOWED_ORIGINS;
	});

	it("allows non-mutating methods without Origin/header", () => {
		const { guard } = makeGuard();
		expect(guard.canActivate(makeContext({ method: "GET" }))).toBe(true);
	});

	it("allows a mutating request with allowed Origin + CSRF header", () => {
		const { guard } = makeGuard();
		expect(
			guard.canActivate(
				makeContext({
					method: "POST",
					origin: ORIGIN,
					csrfHeader: "1",
				})
			)
		).toBe(true);
	});

	it("allows a mutating request with no Origin when the CSRF header is present (non-browser CLI)", () => {
		const { guard } = makeGuard();
		expect(
			guard.canActivate(makeContext({ method: "POST", csrfHeader: "1" }))
		).toBe(true);
	});

	it("rejects a mutating request with no Origin AND no CSRF header", () => {
		const { guard } = makeGuard();
		expect(() =>
			guard.canActivate(makeContext({ method: "POST" }))
		).toThrow(ForbiddenException);
	});

	it("rejects a mutating request with a disallowed Origin", () => {
		const { guard } = makeGuard();
		expect(() =>
			guard.canActivate(
				makeContext({
					method: "POST",
					origin: "https://evil.example.com",
					csrfHeader: "1",
				})
			)
		).toThrow(ForbiddenException);
	});

	it("rejects a mutating request missing the X-PQC-CSRF header", () => {
		const { guard } = makeGuard();
		expect(() =>
			guard.canActivate(makeContext({ method: "POST", origin: ORIGIN }))
		).toThrow(ForbiddenException);
	});

	it("exempts @Public() routes (e.g. /certs/sign) from CSRF checks", () => {
		const { guard, getAllAndOverride } = makeGuard(true);
		expect(guard.canActivate(makeContext({ method: "POST" }))).toBe(true);
		// Assert the guard asked for the RIGHT metadata key, not merely that it
		// honoured a truthy reflector result. The stub answers any key, so without
		// this a guard reading a mistyped or wrong key would still pass here – while
		// in production every @Public() route silently lost its exemption.
		expect(getAllAndOverride).toHaveBeenCalledWith(
			IS_PUBLIC_KEY,
			expect.anything()
		);
	});

	it("tolerates a trailing slash on the Origin", () => {
		const { guard } = makeGuard();
		expect(
			guard.canActivate(
				makeContext({
					method: "PUT",
					origin: `${ORIGIN}/`,
					csrfHeader: "yes",
				})
			)
		).toBe(true);
	});
});
