import {
	Body,
	Controller,
	DefaultValuePipe,
	Delete,
	Get,
	HttpException,
	HttpStatus,
	Ip,
	Param,
	ParseIntPipe,
	Post,
	Query,
	UseGuards,
} from "@nestjs/common";
import {
	ApiBadRequestResponse,
	ApiBody,
	ApiForbiddenResponse,
	ApiParam,
	ApiQuery,
	ApiUnauthorizedResponse,
} from "@nestjs/swagger";
import { IsString, Matches } from "class-validator";

import { AuditAction } from "@/admin-audit/decorators/audit-action.decorator";
import { tokenId } from "@/admin-audit/sanitize.util";
import { CertsService } from "@/certs/certs.service";
import { CertDetailDto } from "@/certs/dto/cert-detail.dto";
import { CertEntryDto } from "@/certs/dto/cert-entry.dto";
import { CertListQueryDto } from "@/certs/dto/cert-list-query.dto";
import {
	EnrollmentTokenDto,
	EnrollmentTokenListItemDto,
} from "@/certs/dto/enrollment-token.dto";
import { ExpiringCertDto } from "@/certs/dto/expiring-cert.dto";
import { SignCsrDto, SignCsrResponseDto } from "@/certs/dto/issue-cert.dto";
import {
	RevokeCertDto,
	RevokeCertResponseDto,
} from "@/certs/dto/revoke-cert.dto";
import {
	ValidateCsrDto,
	ValidateCsrResponseDto,
} from "@/certs/dto/validate-csr.dto";
import { CertEntry } from "@/certs/index-parser.service";
import type { AdminIdentity } from "@/common/auth/cert-roles";
import { AdminController } from "@/common/decorators/admin-controller.decorator";
import { AdminIdentityParam } from "@/common/decorators/admin-identity.decorator";
import {
	ApiDelete,
	ApiGet,
	ApiPost,
} from "@/common/decorators/api-responses.decorator";
import { Public } from "@/common/decorators/public.decorator";
import { Roles } from "@/common/decorators/roles.decorator";
import { EnrollHmacGuard } from "@/common/guards/enroll-hmac.guard";

/**
 * DTO for validating the :serial path parameter.
 * The global ValidationPipe applies class-validator decorators to @Param() objects.
 */
class SerialParamDto {
	@IsString()
	@Matches(/^(0x)?[0-9A-Fa-f]{1,40}$|^dec:\d{1,13}$/, {
		message:
			"serial must be hexadecimal (e.g. '1006', '0x1006') or decimal-prefixed (e.g. 'dec:4102')",
	})
	serial: string;
}

@AdminController("certs")
@Controller("admin/certs")
export class CertsController {
	constructor(private readonly certsService: CertsService) {}

	// ──────────────────────────────────────────────
	// Certificate queries
	// ──────────────────────────────────────────────

	@Get()
	@ApiGet({
		summary: "List all certificates in the intermediate CA database",
		description:
			"Parses the CA index database and returns certificate entries – valid (V), revoked (R), and expired (E). " +
			"Serial numbers are in uppercase hex format as stored by OpenSSL.\n\n" +
			"Optional server-side filtering/pagination: `status`, `cnContains`, `limit`, `offset`. " +
			"With no params the full list is returned (default behaviour unchanged).",
		type: [CertEntryDto],
	})
	@ApiQuery({ name: "status", required: false, enum: ["V", "R", "E"] })
	@ApiQuery({
		name: "cnContains",
		required: false,
		type: String,
		example: "service",
	})
	@ApiQuery({ name: "limit", required: false, type: Number })
	@ApiQuery({ name: "offset", required: false, type: Number })
	async getAllCertificates(
		@Query() query: CertListQueryDto
	): Promise<CertEntryDto[]> {
		return this.certsService.getCertificates(query);
	}

	@Get("expiring")
	@ApiGet({
		summary: "List certificates expiring soon (NIS2 Art. 21(2)(d))",
		description:
			"Returns all valid certificates expiring within the next N days, sorted by days remaining. " +
			"Thresholds: ≤30 days = WARNING, ≤14 days = CRITICAL, ≤7 days = URGENT.",
		type: [ExpiringCertDto],
	})
	@ApiQuery({
		name: "days",
		required: false,
		example: 30,
		description: "Expiry window in days (default: 30)",
	})
	async getExpiringCertificates(
		@Query("days", new DefaultValuePipe(30), ParseIntPipe) days: number
	): Promise<(CertEntry & { daysLeft: number })[]> {
		return this.certsService.getExpiringCertificates(days);
	}

	// ──────────────────────────────────────────────
	// Enrollment tokens (must be before :serial param route)
	// ──────────────────────────────────────────────

	@Post("enrollment-tokens")
	@Roles("admin")
	@AuditAction({
		action: "enrollment-token.create",
		target: c => `cn=${c.query.cn}`,
		params: c => ({
			cn: c.query.cn,
			ttl: c.query.ttl,
			tokenId: tokenId(
				(c.result as { token?: string } | undefined)?.token
			),
		}),
	})
	@ApiPost({
		summary: "Issue a single-use CN-constrained enrollment token",
		description:
			"Creates a short-lived, single-use token that authorizes exactly one CSR submission. " +
			"The token is bound to a specific CN – the CSR subject CN must match exactly or the signing is rejected.\n\n" +
			"Hand this token to the service operator out-of-band (e.g. over a secure channel). " +
			"The operator generates their own key pair and submits the CSR + token to " +
			"`POST /admin/certs/sign` (no admin credential required there).\n\n" +
			"Default TTL: 24 hours. The token is immediately invalidated after first use.",
		status: HttpStatus.CREATED,
		type: EnrollmentTokenDto,
	})
	@ApiQuery({
		name: "cn",
		required: true,
		example: "my-service",
		description:
			"CN (Common Name) the CSR must contain. Rejected if the CSR subject CN does not match exactly.",
	})
	@ApiQuery({
		name: "ttl",
		required: false,
		example: 86400,
		description: "Token TTL in seconds (default: 86400 = 24 h)",
	})
	async createEnrollmentToken(
		@Query("cn") cn: string,
		@Query("ttl", new DefaultValuePipe(86400), ParseIntPipe) ttl: number
	): Promise<EnrollmentTokenDto> {
		if (!cn || cn.trim() === "") {
			throw new HttpException(
				"cn query parameter is required – specify the CN the CSR must contain",
				HttpStatus.BAD_REQUEST
			);
		}
		const allowedCn = cn.trim();
		const expiresAt = Date.now() + ttl * 1000;
		const token = await this.certsService.createEnrollmentToken(
			ttl,
			allowedCn
		);
		return { token, expiresAt, allowedCn };
	}

	@Get("enrollment-tokens")
	@ApiGet({
		summary: "List outstanding enrollment tokens",
		description:
			"Returns all active (and recently used/expired) enrollment tokens for audit purposes.",
		type: [EnrollmentTokenListItemDto],
	})
	async listEnrollmentTokens(): Promise<EnrollmentTokenListItemDto[]> {
		return this.certsService.listEnrollmentTokens();
	}

	@Delete("enrollment-tokens/:token")
	@Roles("admin")
	@AuditAction({
		action: "enrollment-token.revoke",
		target: c => tokenId(c.params.token),
		params: c => ({ tokenId: tokenId(c.params.token) }),
	})
	@ApiDelete({
		summary: "Revoke an enrollment token",
		description:
			"Immediately invalidates an enrollment token before it is used or expires.",
		status: HttpStatus.NO_CONTENT,
		notFound: "Token not found",
	})
	@ApiParam({
		name: "token",
		description: "The enrollment token to revoke",
		example: "enroll_abc123xyz",
	})
	async revokeEnrollmentToken(@Param("token") token: string): Promise<void> {
		await this.certsService.revokeEnrollmentToken(token);
	}

	// ──────────────────────────────────────────────
	// Certificate by serial (param route – must be last GET)
	// ──────────────────────────────────────────────

	@Get(":serial")
	@ApiGet({
		summary:
			"Get an enriched view of a specific certificate by serial number",
		description:
			"Looks up a single certificate and enriches it from the issued PEM: " +
			"`fingerprintSha256` (the exact ADMIN_CERT_FINGERPRINTS paste form), " +
			"`publicKeyAlgorithm` (ML-DSA-65), `subjectAltName`, `notBefore`, " +
			"`notAfter`, and the full `pem`. " +
			"Accepts hex (`1006`), 0x-prefixed (`0x1006`), or decimal-prefixed (`dec:4102`) formats.",
		type: CertDetailDto,
		notFound:
			"No certificate with the given serial exists in the CA database",
	})
	@ApiParam({
		name: "serial",
		description: "Certificate serial number",
		example: "1006",
	})
	async getCertificateBySerial(
		@Param() { serial }: SerialParamDto
	): Promise<CertDetailDto> {
		return this.certsService.getCertificateDetail(serial);
	}

	// ──────────────────────────────────────────────
	// CSR Signing
	// ──────────────────────────────────────────────

	@Post("validate-csr")
	@Roles("admin")
	@ApiPost({
		summary: "Pre-flight a CSR without signing or consuming a token",
		description:
			"Runs the same self-signature and ML-DSA-65 key-algorithm checks as " +
			"enrollment and returns `{ valid, cn, publicKeyAlgorithm, reason? }` – " +
			"without signing or spending a single-use token. Lets the console (and " +
			"the 'issue on behalf' flow) validate before committing a token.",
		status: HttpStatus.OK,
		type: ValidateCsrResponseDto,
	})
	@ApiBody({ type: ValidateCsrDto })
	async validateCsr(
		@Body() dto: ValidateCsrDto
	): Promise<ValidateCsrResponseDto> {
		return this.certsService.validateCsr(dto.csr);
	}

	@Public()
	@UseGuards(EnrollHmacGuard)
	@Post("sign")
	@ApiPost({
		summary: "Sign a client-generated CSR (self-enrollment via token)",
		description:
			"**Self-enrollment flow – no admin credential required here:**\n\n" +
			"1. An admin pre-authorizes the enrollment by creating a CN-constrained token:\n" +
			"   ```\n" +
			"   POST /admin/certs/enrollment-tokens?cn=my-service\n" +
			"   → { token: 'enroll_...', allowedCn: 'my-service' }\n" +
			"   ```\n" +
			"2. The admin hands the token to the service operator out-of-band.\n" +
			"3. The operator generates their key pair locally (private key never leaves their device):\n" +
			"   ```\n" +
			"   openssl genpkey -algorithm ML-DSA-65 -out client.key\n" +
			"   openssl req -new -key client.key -out client.csr -subj '/CN=my-service/O=MyOrg'\n" +
			"   ```\n" +
			"4. The operator submits the CSR + token here (no admin JWT needed).\n\n" +
			"The API verifies the CSR self-signature, checks the token's CN constraint " +
			"(CSR subject CN must match `allowedCn` exactly), and signs with the CA.\n\n" +
			"⚠️ Each token is single-use and CN-bound. A stolen token cannot be used for a different CN.\n\n" +
			"🔒 This route is only reachable through the gateway's public `/enroll` proxy hop, " +
			"which signs the forwarded request with a dedicated HMAC (`X-Timestamp` + " +
			"`X-Hub-Signature-256`, `EnrollHmacGuard`) – a direct call to this API without " +
			"those headers is rejected before the CSR/token are ever inspected.",
		status: HttpStatus.CREATED,
		type: SignCsrResponseDto,
	})
	@ApiBody({ type: SignCsrDto })
	@ApiBadRequestResponse({
		description:
			"CSR is malformed, self-signature is invalid, or subject has no CN",
	})
	@ApiForbiddenResponse({
		description:
			"Enrollment token is invalid, expired, already used, or CSR CN does not match token constraint",
	})
	@ApiUnauthorizedResponse({
		description:
			"Missing/invalid/stale enrollment HMAC signature (X-Timestamp / X-Hub-Signature-256) – only the gateway can produce a valid one",
	})
	async signCsr(
		@Body() dto: SignCsrDto,
		@Ip() ip: string
	): Promise<SignCsrResponseDto> {
		return this.certsService.signCsr(dto.csr, dto.enrollmentToken, ip);
	}

	// ──────────────────────────────────────────────
	// Revocation
	// ──────────────────────────────────────────────

	@Post("revoke")
	@Roles("admin")
	@AuditAction({
		action: "cert.revoke",
		target: c => `serial=${(c.body as { serial?: string }).serial}`,
		params: c => ({
			serial: (c.body as { serial?: string }).serial,
			reason: (c.body as { reason?: string }).reason,
		}),
	})
	@ApiForbiddenResponse({
		description:
			"Access denied (not 'admin'), or the target certificate's fingerprint " +
			"matches the caller's own authenticated certificate – self-revocation " +
			"is refused so an admin can't lock themselves out of the console. Ask " +
			"another admin to revoke it instead.",
	})
	@ApiPost({
		summary: "Revoke an active certificate and regenerate the CRL",
		description:
			"Marks the certificate as revoked in the CA database and triggers CRL regeneration.\n\n" +
			"**Allowed CRLReason codes** (Mozilla Root Store Policy §6.1.1, priority order):\n" +
			"1. `keyCompromise` – private key compromise\n" +
			"2. `privilegeWithdrawn` – subscriber infraction (CA-operator only)\n" +
			"3. `cessationOfOperation` – domain no longer owned or site shut down\n" +
			"4. `affiliationChanged` – subject name or org info changed\n" +
			"5. `superseded` – certificate replaced\n" +
			"6. `unspecified` – no specific reason (CRL reasonCode extension omitted)\n\n" +
			"⚠️ Revocation is **irreversible**. If multiple reasons apply, use the highest-priority one.\n\n" +
			"⛔ You cannot revoke the certificate you're currently authenticated with – " +
			"ask another admin to revoke it instead.",
		type: RevokeCertResponseDto,
		notFound: "Certificate not found in the CA database",
	})
	@ApiBody({ type: RevokeCertDto })
	async revokeCertificate(
		@Body() dto: RevokeCertDto,
		@AdminIdentityParam() identity: AdminIdentity
	): Promise<RevokeCertResponseDto> {
		return this.certsService.revokeCertificate(
			dto.serial,
			dto.reason,
			identity.fpr
		);
	}
}
