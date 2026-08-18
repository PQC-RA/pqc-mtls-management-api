import { CallHandler, ExecutionContext, HttpException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { lastValueFrom, of, throwError } from "rxjs";

import { AdminAuditInterceptor } from "@/admin-audit/admin-audit.interceptor";
import { AdminAuditService } from "@/admin-audit/admin-audit.service";
import { AuditActionMeta } from "@/admin-audit/decorators/audit-action.decorator";

function makeContext(req: Record<string, unknown>): ExecutionContext {
	return {
		getHandler: () => undefined,
		getClass: () => undefined,
		switchToHttp: () => ({
			getRequest: () => req,
			getResponse: () => ({ statusCode: 201 }),
		}),
	} as unknown as ExecutionContext;
}

describe("AdminAuditInterceptor", () => {
	let append: jest.Mock;
	let service: AdminAuditService;

	beforeEach(() => {
		append = jest.fn().mockResolvedValue(null);
		service = { append } as unknown as AdminAuditService;
	});

	function makeInterceptor(meta?: AuditActionMeta) {
		const reflector = {
			getAllAndOverride: jest.fn(() => meta),
		} as unknown as Reflector;
		return new AdminAuditInterceptor(reflector, service);
	}

	it("passes through unannotated handlers without recording", async () => {
		const interceptor = makeInterceptor(undefined);
		const handler: CallHandler = { handle: () => of("ok") };
		await lastValueFrom(interceptor.intercept(makeContext({}), handler));
		expect(append).not.toHaveBeenCalled();
	});

	it("records an ok entry with actor, action and target on success", async () => {
		const interceptor = makeInterceptor({
			action: "cert.revoke",
			target: c => `serial=${(c.body as any).serial}`,
		});
		const req = {
			adminIdentity: { sub: "admin1", fpr: "f1", role: "admin" },
			params: {},
			query: {},
			body: { serial: "1006", reason: "keyCompromise" },
		};
		const handler: CallHandler = {
			handle: () => of({ message: "revoked" }),
		};

		await lastValueFrom(interceptor.intercept(makeContext(req), handler));

		expect(append).toHaveBeenCalledTimes(1);
		const entry = append.mock.calls[0][0];
		expect(entry.action).toBe("cert.revoke");
		expect(entry.actor).toEqual({
			sub: "admin1",
			fpr: "f1",
			role: "admin",
		});
		expect(entry.target).toBe("serial=1006");
		expect(entry.result).toEqual({ status: "ok", httpStatus: 201 });
	});

	it("records an error entry (with status) when the handler throws", async () => {
		const interceptor = makeInterceptor({ action: "cert.revoke" });
		const req = {
			adminIdentity: { sub: "admin1", fpr: "f1", role: "admin" },
			params: {},
			query: {},
			body: {},
		};
		const handler: CallHandler = {
			handle: () => throwError(() => new HttpException("not found", 404)),
		};

		await expect(
			lastValueFrom(interceptor.intercept(makeContext(req), handler))
		).rejects.toBeInstanceOf(HttpException);

		expect(append).toHaveBeenCalledTimes(1);
		const entry = append.mock.calls[0][0];
		expect(entry.result.status).toBe("error");
		expect(entry.result.httpStatus).toBe(404);
	});

	it("defaults the actor to anonymous when there is no admin identity", async () => {
		const interceptor = makeInterceptor({ action: "cert.enroll" });
		const handler: CallHandler = { handle: () => of("x") };
		await lastValueFrom(
			interceptor.intercept(
				makeContext({ params: {}, query: {}, body: {} }),
				handler
			)
		);
		const entry = append.mock.calls[0][0];
		expect(entry.actor).toEqual({ sub: null, fpr: null, role: null });
	});
});
