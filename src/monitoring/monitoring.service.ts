import * as fs from "fs";

import { Injectable, Logger } from "@nestjs/common";
import { Cron, CronExpression } from "@nestjs/schedule";

import { CertsService } from "@/certs/certs.service";
import { fetchCrlViaCustodian } from "@/common/ca-custodian.util";
import { PKI_CONFIG } from "@/common/config/pki.config";

export interface PkiMetrics {
	compliance: string;
	timestamp: string;
	certs_total: {
		valid: number;
		revoked: number;
		expired: number;
		total: number;
	};
	certs_expiring: {
		within_30d: number;
		within_14d: number;
		within_7d: number;
		details_30d: Array<{
			serial: string;
			subject: string;
			daysLeft: number;
		}>;
	};
	crl_age_seconds: number | null;
	crl_status: "ok" | "stale" | "unknown";
	audit_log_entries: number | null;
}

@Injectable()
export class MonitoringService {
	private readonly logger = new Logger(MonitoringService.name);
	private readonly auditLogPath = PKI_CONFIG.auditLogPath;

	constructor(private readonly certsService: CertsService) {}

	async getMetrics(): Promise<PkiMetrics> {
		const certs = await this.certsService.getAllCertificates();
		const now = Date.now();
		const msPerDay = 24 * 60 * 60 * 1000;

		const valid = certs.filter(c => c.status === "V");
		const revoked = certs.filter(c => c.status === "R");
		const expired = certs.filter(c => c.status === "E");

		const expiring30 = valid.filter(
			c => c.expirationDate.getTime() - now <= 30 * msPerDay
		);
		const expiring14 = valid.filter(
			c => c.expirationDate.getTime() - now <= 14 * msPerDay
		);
		const expiring7 = valid.filter(
			c => c.expirationDate.getTime() - now <= 7 * msPerDay
		);

		let crlAgeSeconds: number | null = null;
		try {
			// CRL lives under the CA tree, which this process no longer mounts –
			// only mtimeMs is needed here, but the sidecar's /crl route returns
			// content + mtimeMs together (see crl.service.ts for the content use).
			const { mtimeMs } = await fetchCrlViaCustodian(this.logger);
			crlAgeSeconds = Math.floor((now - mtimeMs) / 1000);
		} catch (_) {}

		let auditLogEntries: number | null = null;
		try {
			const content = fs.readFileSync(this.auditLogPath, "utf8");
			auditLogEntries = content
				.split("\n")
				.filter(l => l.trim().length > 0).length;
		} catch (_) {}

		return {
			compliance: "NIS2 Art. 21(2)(g)",
			timestamp: new Date().toISOString(),
			certs_total: {
				valid: valid.length,
				revoked: revoked.length,
				expired: expired.length,
				total: certs.length,
			},
			certs_expiring: {
				within_30d: expiring30.length,
				within_14d: expiring14.length,
				within_7d: expiring7.length,
				details_30d: expiring30.map(c => ({
					serial: c.serialNumber,
					subject: c.subject,
					daysLeft: Math.ceil(
						(c.expirationDate.getTime() - now) / msPerDay
					),
				})),
			},
			crl_age_seconds: crlAgeSeconds,
			crl_status:
				crlAgeSeconds !== null
					? crlAgeSeconds < 48 * 3600
						? "ok"
						: "stale"
					: "unknown",
			audit_log_entries: auditLogEntries,
		};
	}

	// Run every day at 02:00
	@Cron(CronExpression.EVERY_DAY_AT_2AM)
	async handleCertificateExpiryCheck() {
		this.logger.log(
			"Running daily Certificate Expiry check (NIS2 Art. 21(2)(d))"
		);
		try {
			const certs = await this.certsService.getAllCertificates();
			const validCerts = certs.filter(c => c.status === "V");
			const now = new Date();

			for (const cert of validCerts) {
				if (!cert.expirationDate) continue;
				const diffDays = Math.ceil(
					(cert.expirationDate.getTime() - now.getTime()) /
						(1000 * 60 * 60 * 24)
				);

				if (diffDays <= 0) {
					this.logger.error(
						`Certificate expired! Serial: ${cert.serialNumber}, Subject: ${cert.subject}`
					);
				} else if (diffDays <= 7) {
					this.logger.warn(
						`CRITICAL: Certificate expiring in ${diffDays} days! Serial: ${cert.serialNumber}`
					);
				} else if (diffDays <= 14) {
					this.logger.warn(
						`WARNING: Certificate expiring in ${diffDays} days. Serial: ${cert.serialNumber}`
					);
				} else if (diffDays <= 30) {
					this.logger.log(
						`INFO: Certificate expiring in ${diffDays} days. Serial: ${cert.serialNumber}`
					);
				}
			}
		} catch (error) {
			this.logger.error(
				`Failed to execute certificate expiry check: ${error.message}`
			);
		}
	}
}
