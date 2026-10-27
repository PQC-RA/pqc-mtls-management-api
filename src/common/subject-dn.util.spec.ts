import { singleCommonName, SubjectDnError } from "./subject-dn.util";

describe("singleCommonName (RFC 2253 subject, strict)", () => {
	it("returns the one CN", () => {
		expect(singleCommonName("subject=CN=svc-a,OU=M2M,O=ACME,C=BG")).toBe(
			"svc-a"
		);
		expect(singleCommonName("C=BG,O=ACME,CN=svc.b_2")).toBe("svc.b_2");
	});
	it("accepts other attributes with RFC 2253 escapes", () => {
		expect(singleCommonName("CN=svc,O=ACME\\, Inc.,C=BG")).toBe("svc");
		expect(singleCommonName("CN=svc,OU=R\\+D")).toBe("svc");
	});
	it("refuses two CN attributes (the token-binding bypass)", () => {
		expect(() => singleCommonName("CN=victim,CN=allowed")).toThrow(
			SubjectDnError
		);
		expect(() => singleCommonName("CN=victim,O=X,CN=allowed")).toThrow(
			/more than one CN/
		);
	});
	it("refuses a value that a regular expression could read as a CN", () => {
		expect(() =>
			singleCommonName("emailAddress=xCN=victim,CN=allowed")
		).toThrow(/CN=/);
		expect(() => singleCommonName("OU=xcn=victim,CN=allowed")).toThrow(
			/CN=/
		);
		expect(() => singleCommonName("CN=allowed,O=a/CN=victim")).toThrow(
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
	it("refuses a CN outside the CN alphabet", () => {
		expect(() => singleCommonName("CN=a\\,b,O=ACME")).toThrow(/outside/);
		expect(() => singleCommonName("CN=caf\\C3\\A9")).toThrow(/outside/);
		expect(() => singleCommonName("CN=two words")).toThrow(/outside/);
		expect(() => singleCommonName("CN=" + "a".repeat(65))).toThrow(
			/outside/
		);
	});
	it("refuses a subject without CN, an empty CN or an empty subject", () => {
		expect(() => singleCommonName("O=ACME,C=BG")).toThrow(/no CN/);
		expect(() => singleCommonName("CN=,O=ACME")).toThrow(/empty CN/);
		expect(() => singleCommonName("subject=")).toThrow(/empty subject/);
	});
});
