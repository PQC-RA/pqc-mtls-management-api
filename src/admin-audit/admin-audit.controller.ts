import { Controller, Get, Query } from "@nestjs/common";
import { ApiQuery } from "@nestjs/swagger";

import { AdminAuditService } from "@/admin-audit/admin-audit.service";
import { AdminActionEntryDto } from "@/admin-audit/dto/admin-action.dto";
import { AuditQueryDto } from "@/common/audit/audit-query.dto";
import { AdminController } from "@/common/decorators/admin-controller.decorator";
import { ApiGet } from "@/common/decorators/api-responses.decorator";

@AdminController("audit")
@Controller("admin/audit")
export class AdminAuditController {
	constructor(private readonly adminAuditService: AdminAuditService) {}

	@Get("admin-actions")
	@ApiGet({
		summary: "Retrieve the control-plane admin-action audit trail",
		description:
			"Returns tamper-evident NDJSON records of who performed control-plane " +
			"mutations (enrollment-token create/revoke, CSR enroll, cert revoke, " +
			"policy create/update/delete, CRL renew). Each entry carries a SHA-256 " +
			"hash chain (`prev_hash` → `hash`) for integrity verification.\n\n" +
			"Readable by `admin` and `auditor` roles. Supports the same filters and " +
			"pagination as `/admin/audit/logs` (`event` matches the `action` field, " +
			"`level` matches the result status).\n\n" +
			"Returns an empty array if no actions have been recorded yet.",
		type: [AdminActionEntryDto],
	})
	@ApiQuery({ name: "lines", required: false, type: Number, example: 100 })
	@ApiQuery({
		name: "event",
		required: false,
		type: String,
		example: "cert.revoke",
	})
	@ApiQuery({ name: "level", required: false, type: String, example: "ok" })
	@ApiQuery({ name: "since", required: false, type: String })
	@ApiQuery({ name: "until", required: false, type: String })
	@ApiQuery({ name: "offset", required: false, type: Number })
	@ApiQuery({ name: "limit", required: false, type: Number })
	async getAdminActions(
		@Query() query: AuditQueryDto
	): Promise<AdminActionEntryDto[]> {
		return this.adminAuditService.query(query);
	}
}
