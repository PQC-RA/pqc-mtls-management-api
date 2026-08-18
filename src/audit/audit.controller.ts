import { Controller, Get, Query } from "@nestjs/common";
import { ApiQuery } from "@nestjs/swagger";

import { AuditService } from "@/audit/audit.service";
import { AuditLogEntryDto } from "@/audit/dto/audit-log.dto";
import { AuditQueryDto } from "@/common/audit/audit-query.dto";
import { AdminController } from "@/common/decorators/admin-controller.decorator";
import { ApiGet } from "@/common/decorators/api-responses.decorator";

@AdminController("audit")
@Controller("admin/audit")
export class AuditController {
	constructor(private readonly auditService: AuditService) {}

	@Get("logs")
	@ApiGet({
		summary: "Retrieve recent NDJSON audit log entries",
		description:
			"Tails the gateway data-plane audit log (`/var/log/pqc-gw/enroll-audit.log`, " +
			"written by the /enroll log-phase handler) and returns entries " +
			"parsed from NDJSON format. Each entry represents a single proxied request through the PQC-GW, " +
			"including the client's mTLS identity (CN, OU), the target URI, response code, and whether " +
			"the request was blocked by policy.\n\n" +
			"Optional server-side filters: `cn`, `event`, `level`, `since`/`until` (ISO-8601). " +
			"Pagination via `offset`/`limit`; `lines` is retained for backward compatibility.\n\n" +
			"Returns an empty array if the log file does not yet exist.",
		type: [AuditLogEntryDto],
	})
	@ApiQuery({
		name: "lines",
		required: false,
		type: Number,
		description:
			"Number of most recent log entries to return (default: 100, min: 1, max: 10000). Ignored when offset/limit are set.",
		example: 100,
	})
	@ApiQuery({ name: "cn", required: false, type: String })
	@ApiQuery({
		name: "event",
		required: false,
		type: String,
		example: "block",
	})
	@ApiQuery({ name: "level", required: false, type: String, example: "warn" })
	@ApiQuery({ name: "since", required: false, type: String })
	@ApiQuery({ name: "until", required: false, type: String })
	@ApiQuery({ name: "offset", required: false, type: Number })
	@ApiQuery({ name: "limit", required: false, type: Number })
	async getAuditLogs(
		@Query() query: AuditQueryDto
	): Promise<AuditLogEntryDto[]> {
		return this.auditService.getAuditLogs(query);
	}
}
