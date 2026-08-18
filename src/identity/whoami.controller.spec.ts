import { AdminIdentity } from "@/common/auth/cert-roles";
import { WhoamiController } from "@/identity/whoami.controller";

describe("WhoamiController", () => {
	const controller = new WhoamiController();

	it("echoes the resolved identity (sub, fpr, role)", () => {
		const identity: AdminIdentity = {
			sub: "ops-admin",
			fpr: "1c2ba075293fcd68e241cfcedf337ff59bc8126b24c2af07c60f319a38e1a0d8",
			role: "admin",
		};
		expect(controller.whoami(identity)).toEqual(identity);
	});

	it("reports the auditor role for a read-only caller", () => {
		const identity: AdminIdentity = {
			sub: "auditor1",
			fpr: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
			role: "auditor",
		};
		expect(controller.whoami(identity).role).toBe("auditor");
	});
});
