import * as fs from "fs";

import { HttpException, HttpStatus, Injectable, Logger } from "@nestjs/common";

import { AuditLogEntryDto } from "@/audit/dto/audit-log.dto";
import { AuditQueryDto } from "@/common/audit/audit-query.dto";
import {
	parseNdjson,
	queryAuditEntries,
} from "@/common/audit/audit-query.util";
import { PKI_CONFIG } from "@/common/config/pki.config";

@Injectable()
export class AuditService {
	private readonly logger = new Logger(AuditService.name);
	private readonly auditLogPath = PKI_CONFIG.auditLogPath;

	/**
	 * Read, filter, and paginate the gateway's data-plane NDJSON audit log.
	 * Supports `cn`/`event`/`level`/`since`/`until` filters and `offset`/`limit`
	 * pagination, with `lines` kept for backward compatibility.
	 */
	async getAuditLogs(query: AuditQueryDto = {}): Promise<AuditLogEntryDto[]> {
		this.logger.log(`Fetching audit logs (query=${JSON.stringify(query)})`);

		if (!fs.existsSync(this.auditLogPath)) {
			this.logger.warn(
				`Audit log file not found at ${this.auditLogPath}`
			);
			return [];
		}

		try {
			const content = fs.readFileSync(this.auditLogPath, "utf8");
			const all = parseNdjson<AuditLogEntryDto>(content);
			return queryAuditEntries(all, query, {
				ts: e => e.ts,
				cn: e => e.client?.cn,
				event: e => e.event,
				level: e => e.level,
			});
		} catch (e) {
			this.logger.error(`Error reading audit logs: ${e.message}`);
			throw new HttpException(
				"Failed to read audit logs",
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}
}
