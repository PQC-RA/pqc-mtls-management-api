import { Controller, Get } from "@nestjs/common";

import type { AdminIdentity } from "@/common/auth/cert-roles";
import { AdminController } from "@/common/decorators/admin-controller.decorator";
import { AdminIdentityParam } from "@/common/decorators/admin-identity.decorator";
import { ApiGet } from "@/common/decorators/api-responses.decorator";
import { WhoamiDto } from "@/identity/dto/whoami.dto";

@AdminController("identity")
@Controller("admin")
export class WhoamiController {
	@Get("whoami")
	@ApiGet({
		summary: "Return the authenticated caller's identity and privilege",
		description:
			"Echoes the validated JWT subject, the certificate SHA-256 fingerprint, " +
			"and the server-resolved role (admin / auditor). Powers the console's " +
			"unlock screen and the 'connected as / privilege' display. Requires a " +
			"valid gateway JWT (not @Public); readable by both admin and auditor.",
		type: WhoamiDto,
	})
	whoami(@AdminIdentityParam() identity: AdminIdentity): WhoamiDto {
		return { sub: identity.sub, fpr: identity.fpr, role: identity.role };
	}
}
