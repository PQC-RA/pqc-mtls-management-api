import { ArgumentsHost, HttpException, HttpStatus } from "@nestjs/common";

import { HttpExceptionFilter } from "@/common/filters/http-exception.filter";

function makeHost(method = "GET", url = "/test"): ArgumentsHost {
	const json = jest.fn();
	const status = jest.fn().mockReturnValue({ json });
	return {
		switchToHttp: () => ({
			getResponse: () => ({ status, json }), // return json here so we can assert on it later if we spy on the chained mock
			getRequest: () => ({ method, url }),
		}),
	} as unknown as ArgumentsHost;
}

describe("HttpExceptionFilter", () => {
	let filter: HttpExceptionFilter;

	beforeEach(() => {
		filter = new HttpExceptionFilter();
	});

	it("serializes an HttpException with a string response", () => {
		const host = makeHost();
		const response = host.switchToHttp().getResponse() as any;

		filter.catch(
			new HttpException("Not Found", HttpStatus.NOT_FOUND),
			host
		);

		expect(response.status).toHaveBeenCalledWith(404);
		// Check that json was called by inspecting the return value of status() since it's chained
		const jsonMock = response.status.mock.results[0].value.json;
		expect(jsonMock).toHaveBeenCalledWith(
			expect.objectContaining({
				ok: false,
				error: expect.objectContaining({
					code: 404,
					message: "Not Found",
				}),
			})
		);
	});

	it("serializes an HttpException with an object response", () => {
		const host = makeHost();
		const response = host.switchToHttp().getResponse() as any;

		filter.catch(
			new HttpException(
				{ message: "Validation failed" },
				HttpStatus.BAD_REQUEST
			),
			host
		);

		expect(response.status).toHaveBeenCalledWith(400);
		const jsonMock = response.status.mock.results[0].value.json;
		expect(jsonMock).toHaveBeenCalledWith(
			expect.objectContaining({
				ok: false,
				error: expect.objectContaining({
					message: "Validation failed",
				}),
			})
		);
	});

	it("joins array messages from ValidationPipe", () => {
		const host = makeHost();
		const response = host.switchToHttp().getResponse() as any;

		filter.catch(
			new HttpException(
				{ message: ["field1 error", "field2 error"] },
				HttpStatus.BAD_REQUEST
			),
			host
		);

		const jsonMock = response.status.mock.results[0].value.json;
		expect(jsonMock).toHaveBeenCalledWith(
			expect.objectContaining({
				error: expect.objectContaining({
					message: "field1 error; field2 error",
				}),
			})
		);
	});

	it("returns 500 with a generic message for non-HttpException errors", () => {
		const host = makeHost();
		const response = host.switchToHttp().getResponse() as any;

		filter.catch(new Error("something broke internally"), host);

		expect(response.status).toHaveBeenCalledWith(500);
		const jsonMock = response.status.mock.results[0].value.json;
		expect(jsonMock).toHaveBeenCalledWith(
			expect.objectContaining({
				ok: false,
				error: expect.objectContaining({ code: 500 }),
			})
		);
		// Must NOT leak the raw error message
		const call = jsonMock.mock.calls[0][0];
		expect(call.error.message).not.toContain("something broke internally");
	});
});
