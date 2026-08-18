import * as fs from "fs";

import { Injectable, Logger } from "@nestjs/common";
import {
	HealthIndicatorResult,
	HealthIndicatorService,
} from "@nestjs/terminus";

import { checkCustodianHealth } from "@/common/ca-custodian.util";
import { PKI_CONFIG } from "@/common/config/pki.config";

@Injectable()
export class HealthService {
	private readonly logger = new Logger(HealthService.name);

	constructor(
		private readonly healthIndicatorService: HealthIndicatorService
	) {}

	async isHealthy(key: string): Promise<HealthIndicatorResult> {
		const indicator = this.healthIndicatorService.check(key);

		try {
			const errors: Record<string, string> = {};

			// This process holds no CA-tree mount; ask the pqc-ca-custodian sidecar
			// (the only component that does) whether its index database and
			// combined CRL are reachable.
			const custodian = await checkCustodianHealth(this.logger);
			if (!custodian.ok) {
				if (custodian.indexOk === false)
					errors.caDatabase =
						"pqc-ca-custodian reports the CA index is unreachable";
				if (custodian.crlOk === false)
					errors.crl =
						"pqc-ca-custodian reports the combined CRL is unreachable";
				if (
					custodian.indexOk === undefined &&
					custodian.crlOk === undefined
				) {
					errors.custodian = "pqc-ca-custodian is unreachable";
				}
			}

			// Skip script check in signal-file mode: when CRL_RENEW_SIGNAL_FILE is
			// set the API touches a sentinel instead of running the script, so the
			// script need not exist inside the container.
			if (
				!PKI_CONFIG.crlRenewSignalFile &&
				!fs.existsSync(PKI_CONFIG.crlRenewScript)
			) {
				errors.renewScript = `${PKI_CONFIG.crlRenewScript} does not exist`;
			}

			if (Object.keys(errors).length > 0) {
				return indicator.down(errors);
			}

			return indicator.up({
				caDatabase: "OK",
				crl: "OK",
				renewScript: "OK",
			});
		} catch (e: unknown) {
			const msg = e instanceof Error ? e.message : String(e);
			this.logger.error(`PKI health check threw unexpectedly: ${msg}`);

			return indicator.down({ error: "Internal check error" });
		}
	}
}
