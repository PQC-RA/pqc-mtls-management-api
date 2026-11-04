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

			// Who issues the CRLs decides what is checked, and the custodian's
			// own answer says which (crlIssuerOk is sent only when it is the
			// issuer, ADR-024), as crlAfterRevocation decides per revoke answer.
			// No setting is involved, so a deployment on either side of the
			// migration reports its real state.
			let crlIssuer: "pqc-ca-custodian" | "crl-renewer" | undefined;
			if (custodian.crlIssuerOk !== undefined) {
				crlIssuer = "pqc-ca-custodian";
				if (!custodian.crlIssuerOk)
					errors.crlIssuer =
						"pqc-ca-custodian has not published its first CRL, or its CRL schedule is overdue";
			} else if (
				custodian.indexOk !== undefined ||
				custodian.crlOk !== undefined
			) {
				// The renewer issues the CRLs. Skip the script check in
				// signal-file mode: the API touches a sentinel instead of
				// running the script, so the script need not exist here.
				crlIssuer = "crl-renewer";
				const signalFile =
					process.env.CRL_RENEW_SIGNAL_FILE ??
					PKI_CONFIG.crlRenewSignalFile;
				if (!signalFile && !fs.existsSync(PKI_CONFIG.crlRenewScript)) {
					errors.renewScript = `${PKI_CONFIG.crlRenewScript} does not exist`;
				}
			}
			// With the custodian unreachable the issuer is unknown: only
			// errors.custodian is reported, nothing is guessed.

			if (Object.keys(errors).length > 0) {
				return indicator.down(errors);
			}

			return indicator.up({
				caDatabase: "OK",
				crl: "OK",
				crlIssuer,
			});
		} catch (e: unknown) {
			const msg = e instanceof Error ? e.message : String(e);
			this.logger.error(`PKI health check threw unexpectedly: ${msg}`);

			return indicator.down({ error: "Internal check error" });
		}
	}
}
