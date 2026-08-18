import { Injectable, Logger } from "@nestjs/common";

import { CertLookupResultDto } from "@/cert-lookup/dto/cert-lookup-result.dto";
import { fetchCertByFingerprintViaCustodian } from "@/common/ca-custodian.util";

@Injectable()
export class CertLookupService {
	private readonly logger = new Logger(CertLookupService.name);

	async getByFingerprint(fpr: string): Promise<CertLookupResultDto> {
		return fetchCertByFingerprintViaCustodian(this.logger, fpr);
	}
}
