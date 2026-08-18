import * as fs from "fs";

import { HttpException, HttpStatus, Injectable, Logger } from "@nestjs/common";

import { fetchCrlViaCustodian } from "@/common/ca-custodian.util";
import { PKI_CONFIG } from "@/common/config/pki.config";
import { triggerCrlRegeneration } from "@/common/crl-signal.util";

@Injectable()
export class CrlService {
	private readonly logger = new Logger(CrlService.name);
	private readonly renewScriptPath = PKI_CONFIG.crlRenewScript;

	async getCrl(): Promise<string> {
		this.logger.log("Fetching current CRL");

		// The combined CRL lives under the CA tree, which this process no
		// longer mounts – read via the pqc-ca-custodian sidecar instead (public
		// data, but served through the same narrow fixed-path surface as the
		// index and issued certs).
		const { content } = await fetchCrlViaCustodian(this.logger);
		return content;
	}

	async renewCrl(): Promise<{ message: string }> {
		this.logger.log("Executing forced CRL renewal");

		try {
			// Production: signal the dedicated crl-renewer (least privilege).
			// Dev/single-container: regenerate in-process. The in-process branch
			// short-circuits to a dry-run message when the script is absent.
			const signalConfigured = !!(
				process.env.CRL_RENEW_SIGNAL_FILE ??
				PKI_CONFIG.crlRenewSignalFile
			);
			if (!signalConfigured && !fs.existsSync(this.renewScriptPath)) {
				this.logger.warn(
					`CRL renewal script not found at ${this.renewScriptPath}. Mock execution.`
				);
				return {
					message:
						"CRL renewal script not found, assuming success for dry run.",
				};
			}

			const mode = await triggerCrlRegeneration(this.logger);
			return {
				message:
					mode === "signaled"
						? "CRL renewal signaled to the renewer"
						: "CRL renewed successfully",
			};
		} catch (error) {
			this.logger.error(`Failed to renew CRL: ${error.message}`);
			throw new HttpException(
				"CRL renewal failed",
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}
}
