import { singleCommonName, SubjectDnError } from "./subject-dn.util";

describe("singleCommonName (RFC 2253 subject, strict)", () => {
	it("returns the one CN", () => {
		expect(singleCommonName("subject=CN=svc-a,OU=M2M,O=ACME,C=BG")).toBe(
			"svc-a"
		);
		expect(singleCommonName("C=BG,O=ACME,CN=svc-b")).toBe("svc-b");
	});
	it("unescapes RFC 2253 values", () => {
		expect(singleCommonName("CN=a\\,b,O=ACME")).toBe("a,b");
		expect(singleCommonName("CN=x\\+y")).toBe("x+y");
		expect(singleCommonName("CN=caf\\C3\\A9")).toBe("café");
	});
	it("refuses two CN attributes (the token-binding bypass)", () => {
		expect(() => singleCommonName("CN=victim,CN=allowed")).toThrow(
			SubjectDnError
		);
		expect(() => singleCommonName("CN=victim,O=X,CN=allowed")).toThrow(
			/more than one CN/
		);
	});
	it("refuses a CN given by OID next to one by name", () => {
		expect(() => singleCommonName("2.5.4.3=victim,CN=allowed")).toThrow(
			SubjectDnError
		);
	});
	it("refuses multi-valued RDNs", () => {
		expect(() => singleCommonName("CN=allowed+CN=victim")).toThrow(
			/multi-valued/
		);
		expect(() => singleCommonName("CN=svc,O=A+OU=B")).toThrow(
			/multi-valued/
		);
	});
	it("refuses a subject without CN, an empty CN or an empty subject", () => {
		expect(() => singleCommonName("O=ACME,C=BG")).toThrow(/no CN/);
		expect(() => singleCommonName("CN=,O=ACME")).toThrow(/empty CN/);
		expect(() => singleCommonName("subject=")).toThrow(/empty subject/);
	});
});
