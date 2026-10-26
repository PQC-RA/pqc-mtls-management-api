import { execFile } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { promisify } from "util";

import {
	HttpException,
	HttpStatus,
	Injectable,
	Logger,
	OnModuleDestroy,
	OnModuleInit,
} from "@nestjs/common";

import { AdminAuditService } from "@/admin-audit/admin-audit.service";
import { tokenId } from "@/admin-audit/sanitize.util";
import { CertDetailDto } from "@/certs/dto/cert-detail.dto";
import { CertListQueryDto } from "@/certs/dto/cert-list-query.dto";
import { SignCsrResponseDto } from "@/certs/dto/issue-cert.dto";
import { RevocationReason } from "@/certs/dto/revoke-cert.dto";
import { ValidateCsrResponseDto } from "@/certs/dto/validate-csr.dto";
import { CertEntry, IndexParserService } from "@/certs/index-parser.service";
import { TokenStoreService } from "@/certs/token-store.service";
import { normalizeFingerprint } from "@/common/auth/cert-roles";
import {
	CustodianHttpException,
	fetchIndexViaCustodian,
	fetchIssuedPemViaCustodian,
	fetchSignResultViaCustodian,
	revokeViaCustodian,
	signCsrViaCustodian,
} from "@/common/ca-custodian.util";
import { PKI_CONFIG } from "@/common/config/pki.config";
import { triggerCrlRegeneration } from "@/common/crl-signal.util";

const execFileAsync = promisify(execFile);

/**
 * The ONLY client public-key algorithm permitted for enrollment.
 *
 * This is the issuance-side half of a defense-in-depth control: the gateway
 * already restricts client auth at the TLS handshake via
 * `ssl_conf_command ClientSignatureAlgorithms ML-DSA-65`. Here we additionally
 * refuse to MINT a certificate for any non-ML-DSA-65 key, so a classical client
 * cert can never be issued via enrollment in the first place.
 *
 * Matched exactly against the "Public Key Algorithm:" field reported by
 * OpenSSL 3.6.2 `req -text`. ML-DSA-44/87 and RSA (rsaEncryption) / EC
 * (id-ecPublicKey) all report distinct strings and are therefore rejected.
 */
const ALLOWED_CSR_KEY_ALGORITHM = "ML-DSA-65";

@Injectable()
export class CertsService implements OnModuleInit, OnModuleDestroy {
	private readonly logger = new Logger(CertsService.name);
	// Used only for parsing/verifying the client-supplied CSR itself (never CA
	// material) – see verifyCsr/extractCsrCn/readCsrKeyAlgorithm below. All CA
	// tree access (signing key, index, issued certs) goes through the
	// pqc-ca-custodian sidecar; this process holds no CA-tree mount at all.
	private readonly openssl = PKI_CONFIG.openssl;

	constructor(
		private readonly indexParser: IndexParserService,
		private readonly tokenStore: TokenStoreService,
		private readonly adminAudit: AdminAuditService
	) {}

	// ──────────────────────────────────────────────
	// Enrollment Token management
	// ──────────────────────────────────────────────

	/**
	 * Issue a single-use enrollment token an admin hands to a service operator.
	 * The token is bound to allowedCn – the CSR subject CN must match exactly.
	 * Default TTL: 24 hours.
	 */
	async createEnrollmentToken(
		ttlSeconds = 86_400,
		allowedCn: string,
		profile?: "client-30d" | "demo-120s"
	): Promise<string> {
		if (profile && process.env.RENEWAL_ENABLED !== "1") {
			throw new HttpException(
				"Renewal profiles are disabled on this deployment",
				HttpStatus.BAD_REQUEST
			);
		}
		const token = "enroll_" + crypto.randomBytes(18).toString("hex");
		const expiresAt = Date.now() + ttlSeconds * 1000;
		await this.tokenStore.set(token, {
			expiresAt,
			allowedCn,
			...(profile ? { profile } : {}),
		});
		this.logger.log(
			`Created enrollment token (ttl=${ttlSeconds}s, allowedCn=${allowedCn}, profile=${profile ?? "legacy"})`
		);
		return token;
	}

	async listEnrollmentTokens(): Promise<
		Array<{
			token: string;
			expiresAt: number;
			allowedCn: string;
			used: boolean;
		}>
	> {
		return this.tokenStore.list();
	}

	async revokeEnrollmentToken(token: string): Promise<void> {
		const existed = await this.tokenStore.delete(token);
		if (!existed) {
			throw new HttpException(
				"Enrollment token not found",
				HttpStatus.NOT_FOUND
			);
		}
	}

	/** Lease on a reservation: well above the 15 s custodian timeout (R2). */
	private static readonly LEASE_MS = 60_000;
	private reconcileTimer?: NodeJS.Timeout;

	onModuleInit(): void {
		// Periodic reconcile of reservations whose lease passed (R6): never an
		// implicit release, always a lookup with the custodian first.
		this.reconcileTimer = setInterval(() => {
			void this.reconcileStaleReservations().catch(err =>
				this.logger.error(
					`Reconcile pass failed: ${(err as Error).message}`
				)
			);
		}, 30_000);
		this.reconcileTimer.unref();
	}

	onModuleDestroy(): void {
		if (this.reconcileTimer) clearInterval(this.reconcileTimer);
	}

	/**
	 * Token failures carry a snake_case reason (error.details.reason, through
	 * the exception filter) beside the human message, as /renew does, so a
	 * client can tell "retry shortly" (in_progress) from "get a new token".
	 */
	private tokenFailure(result: string): HttpException {
		const fail = (status: HttpStatus, reason: string, message: string) =>
			new HttpException(
				{ statusCode: status, error: reason, message },
				status
			);
		switch (result) {
			case "expired":
				return fail(
					HttpStatus.FORBIDDEN,
					"token_expired",
					"Enrollment token has expired"
				);
			case "already_used":
				return fail(
					HttpStatus.FORBIDDEN,
					"token_already_used",
					"Enrollment token has already been used"
				);
			case "cn_mismatch":
				return fail(
					HttpStatus.FORBIDDEN,
					"cn_mismatch",
					"CSR subject CN does not match the CN constraint on this enrollment token"
				);
			case "in_progress":
				return fail(
					HttpStatus.CONFLICT,
					"in_progress",
					"An enrollment with this token is in progress; retry shortly"
				);
			default:
				return fail(
					HttpStatus.FORBIDDEN,
					"token_invalid",
					"Invalid or already-used enrollment token"
				);
		}
	}

	/** SHA-256 of the SubjectPublicKeyInfo (DER) of a CSR file. */
	private async spkiSha256OfCsrFile(csrPath: string): Promise<string> {
		const { stdout } = await execFileAsync(this.openssl, [
			"req",
			"-in",
			csrPath,
			"-noout",
			"-pubkey",
		]);
		const der = crypto
			.createPublicKey(stdout)
			.export({ type: "spki", format: "der" }) as Buffer;
		return crypto.createHash("sha256").update(der).digest("hex");
	}

	private async auditReplay(
		token: string,
		cn: string,
		r: { certificate: string; serialNumber: string; expiresAt: string },
		source?: string
	): Promise<{
		certificate: string;
		serialNumber: string;
		expiresAt: string;
		replay: true;
	}> {
		this.logger.log(
			`Enrollment replay: serial=${r.serialNumber} cn=${cn} (same key, response had been lost)`
		);
		await this.adminAudit.append({
			action: "cert.enroll.replay",
			actor: null,
			target: `cn=${cn} serial=${r.serialNumber}`,
			params: { cn, tokenId: tokenId(token), source },
			result: { status: "ok", httpStatus: HttpStatus.CREATED },
		});
		return { ...r, replay: true };
	}

	/** A used token tried with another key or CN: the stolen-token signal, audited apart. */
	private async auditKeyMismatch(
		token: string,
		cn: string,
		why: string,
		source?: string
	): Promise<void> {
		this.logger.warn(
			`Enrollment with a used token and a different ${why === "cn" ? "CN" : "key"}: cn=${cn}`
		);
		await this.adminAudit.append({
			action: "token.replay_mismatch",
			actor: null,
			target: `cn=${cn}`,
			params: {
				cn,
				tokenId: tokenId(token),
				reason: `replay_${why}_mismatch`,
				source,
			},
			result: { status: "error", httpStatus: HttpStatus.FORBIDDEN },
		});
	}

	/**
	 * Enrollment replay (requirement R5, measured 2026-10-25): when the token
	 * was committed to a certificate whose public key is the key of THIS CSR,
	 * the client lost the response (gateway timeout, a killed API, a reconcile
	 * after the lease) and retries with the same key. The CSR's self-signature
	 * was verified, so the caller holds that key: give the certificate back
	 * instead of "already used", which would need an admin.
	 *
	 *   replay                the certificate, still valid and not revoked
	 *   mismatch              another key or CN: the caller gets "already used"
	 *   none                  nothing committed to compare with
	 *   throws 503 replay_unavailable  the custodian could not be asked; retry
	 *   throws 403 certificate_revoked / certificate_expired  it is dead; a new
	 *                         bootstrap is needed (after an admin revokes, if so)
	 */
	private async replayIfSameKey(
		csrPath: string,
		cn: string,
		serial: string | undefined,
		certificate?: string
	): Promise<
		| {
				kind: "replay";
				r: {
					certificate: string;
					serialNumber: string;
					expiresAt: string;
				};
		  }
		| { kind: "mismatch"; why: string }
		| { kind: "none" }
	> {
		if (!serial && !certificate) return { kind: "none" };
		const unavailable = (why: string) => {
			this.logger.warn(
				`Enrollment replay unavailable for serial ${serial ?? "?"}: ${why}`
			);
			return new HttpException(
				{
					statusCode: HttpStatus.SERVICE_UNAVAILABLE,
					error: "replay_unavailable",
					message:
						"The issued certificate cannot be looked up right now; retry with the same key",
					retryAfterSeconds: 30,
				},
				HttpStatus.SERVICE_UNAVAILABLE
			);
		};
		let pem = certificate;
		if (!pem && serial) {
			try {
				pem = await fetchIssuedPemViaCustodian(this.logger, serial);
			} catch (err) {
				throw unavailable((err as Error).message);
			}
		}
		if (!pem) return { kind: "none" };
		let x: crypto.X509Certificate;
		try {
			const block = pem.match(
				/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/
			);
			if (!block)
				return { kind: "mismatch", why: "no certificate block" };
			x = new crypto.X509Certificate(block[0]);
			const issued = crypto
				.createHash("sha256")
				.update(
					x.publicKey.export({
						type: "spki",
						format: "der",
					}) as Buffer
				)
				.digest("hex");
			const asked = await this.spkiSha256OfCsrFile(csrPath);
			if (issued !== asked) return { kind: "mismatch", why: "key" };
			const subjectCn = x.subject
				.split("\n")
				.find(l => l.startsWith("CN="))
				?.slice(3);
			if (subjectCn !== cn) return { kind: "mismatch", why: "cn" };
		} catch (err) {
			// Anything unreadable is not a replay: the caller answers "already used".
			this.logger.warn(
				`Enrollment replay check failed: ${(err as Error).message}`
			);
			return { kind: "mismatch", why: "unreadable" };
		}
		const ser = (serial ?? x.serialNumber).toUpperCase();
		const dead = (reason: string, message: string) =>
			new HttpException(
				{ statusCode: HttpStatus.FORBIDDEN, error: reason, message },
				HttpStatus.FORBIDDEN
			);
		if (Date.parse(x.validTo) <= Date.now())
			throw dead(
				"certificate_expired",
				"The certificate issued under this token has expired; a new bootstrap enrollment is required"
			);
		let index: string;
		try {
			index = await fetchIndexViaCustodian(this.logger);
		} catch (err) {
			throw unavailable((err as Error).message);
		}
		const row = index
			.split("\n")
			.map(l => l.split("\t"))
			.find(f => f.length > 3 && f[3].toUpperCase() === ser);
		if (row && row[0] !== "V")
			throw dead(
				"certificate_revoked",
				"The certificate issued under this token is revoked; a new bootstrap enrollment is required"
			);
		return {
			kind: "replay",
			r: {
				certificate: pem,
				serialNumber: ser,
				expiresAt: new Date(x.validTo).toISOString(),
			},
		};
	}

	/**
	 * Settle one reservation from the custodian's record: commit if a
	 * certificate exists for it, release if the custodian has none. Returns the
	 * issued result when committed. Leaves the reservation alone when the
	 * custodian cannot be asked.
	 */
	private async reconcileReservation(
		token: string,
		reservationId: string,
		cn?: string
	): Promise<{
		certificate: string;
		serialNumber: string;
		expiresAt: string;
	} | null> {
		const r = await fetchSignResultViaCustodian(
			this.logger,
			`enroll:${reservationId}`
		);
		if (r.state === "issued" && r.serialNumber && r.certificate) {
			await this.tokenStore.commit(token, reservationId, r.serialNumber);
			await this.adminAudit.append({
				action: "token.commit",
				actor: null,
				target: `serial=${r.serialNumber}`,
				params: {
					tokenId: tokenId(token),
					reservationId,
					via: "reconcile",
					...(cn ? { cn } : {}),
				},
				result: { status: "ok", httpStatus: HttpStatus.OK },
			});
			return {
				certificate: r.certificate,
				serialNumber: r.serialNumber,
				expiresAt: r.expiresAt ?? "",
			};
		}
		await this.tokenStore.release(token, reservationId);
		await this.adminAudit.append({
			action: "token.release",
			actor: null,
			target: cn ? `cn=${cn}` : null,
			params: {
				tokenId: tokenId(token),
				reservationId,
				reason: `reconcile:${r.state}`,
			},
			result: { status: "ok", httpStatus: HttpStatus.OK },
		});
		return null;
	}

	async reconcileStaleReservations(): Promise<void> {
		for (const s of await this.tokenStore.staleReservations()) {
			try {
				await this.reconcileReservation(
					s.token,
					s.reservationId,
					s.meta.allowedCn
				);
			} catch (err) {
				this.logger.warn(
					`Reconcile of reservation ${s.reservationId} deferred: ${(err as Error).message}`
				);
			}
		}
	}

	// ──────────────────────────────────────────────
	// Certificate queries
	// ──────────────────────────────────────────────

	async getAllCertificates(): Promise<CertEntry[]> {
		this.logger.log("Fetching all certificates");
		let tmpDir: string | undefined;
		try {
			const content = await fetchIndexViaCustodian(this.logger);
			tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pqc-index-"));
			const tmpPath = path.join(tmpDir, "index.txt");
			fs.writeFileSync(tmpPath, content, { mode: 0o600 });
			return await this.indexParser.parseIndexFile(tmpPath);
		} catch (error) {
			this.logger.error(`Failed to parse index file: ${error.message}`);
			throw new HttpException(
				"Internal Server Error while parsing PKI database",
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		} finally {
			if (tmpDir) {
				try {
					fs.rmSync(tmpDir, { recursive: true, force: true });
				} catch (_) {}
			}
		}
	}

	/**
	 * List certificates with optional server-side filtering and pagination.
	 * With an empty query this returns every entry (unchanged default behaviour).
	 */
	async getCertificates(query: CertListQueryDto = {}): Promise<CertEntry[]> {
		let entries = await this.getAllCertificates();

		if (query.status) {
			entries = entries.filter(c => c.status === query.status);
		}
		if (query.cnContains) {
			const needle = query.cnContains.toLowerCase();
			entries = entries.filter(c =>
				(c.subject ?? "").toLowerCase().includes(needle)
			);
		}
		if (query.offset !== undefined || query.limit !== undefined) {
			const offset = query.offset ?? 0;
			const limit = query.limit ?? entries.length;
			entries = entries.slice(offset, offset + limit);
		}
		return entries;
	}

	async getExpiringCertificates(
		days: number = 30
	): Promise<(CertEntry & { daysLeft: number })[]> {
		this.logger.log(`Fetching certificates expiring within ${days} days`);
		const all = await this.getAllCertificates();
		const now = Date.now();
		const thresholdMs = days * 24 * 60 * 60 * 1000;
		return all
			.filter(
				c =>
					c.status === "V" &&
					c.expirationDate.getTime() - now <= thresholdMs
			)
			.map(c => ({
				...c,
				daysLeft: Math.ceil(
					(c.expirationDate.getTime() - now) / (1000 * 60 * 60 * 24)
				),
			}))
			.sort((a, b) => a.daysLeft - b.daysLeft);
	}

	async getCertificate(serial: string): Promise<CertEntry> {
		const normalized = this.normalizeSerial(serial);
		this.logger.log(
			`Fetching certificate with serial: ${serial} (normalized: ${normalized})`
		);
		const certs = await this.getAllCertificates();
		const cert = certs.find(
			c => c.serialNumber.toUpperCase() === normalized
		);

		if (!cert) {
			throw new HttpException(
				`Certificate with serial ${serial} not found`,
				HttpStatus.NOT_FOUND
			);
		}

		return cert;
	}

	/**
	 * Enriched single-certificate view: parses the issued PEM via the PQ
	 * OpenSSL toolchain (OPENSSL_CONF must be set) to add the SHA-256
	 * fingerprint (allowlist-paste form), public-key algorithm, SAN, validity
	 * window, and the full PEM. The lean list endpoint is unaffected.
	 */
	async getCertificateDetail(serial: string): Promise<CertDetailDto> {
		const entry = await this.getCertificate(serial);
		const normalizedSerial = this.normalizeSerial(serial);
		const pem = await fetchIssuedPemViaCustodian(
			this.logger,
			normalizedSerial
		);

		const tmpDir = fs.mkdtempSync(
			path.join(os.tmpdir(), "pqc-cert-detail-")
		);
		const certPath = path.join(tmpDir, "cert.pem");
		fs.writeFileSync(certPath, pem, { mode: 0o600 });

		try {
			// Fingerprint + validity window in one call.
			const { stdout: fpOut } = await execFileAsync(this.openssl, [
				"x509",
				"-in",
				certPath,
				"-noout",
				"-fingerprint",
				"-sha256",
				"-startdate",
				"-enddate",
			]);
			const fprMatch = fpOut.match(/Fingerprint=([0-9A-Fa-f:]+)/);
			const notBeforeMatch = fpOut.match(/notBefore=(.+)/);
			const notAfterMatch = fpOut.match(/notAfter=(.+)/);

			// Public-key algorithm + SAN from the text dump.
			const { stdout: textOut } = await execFileAsync(this.openssl, [
				"x509",
				"-in",
				certPath,
				"-noout",
				"-text",
			]);
			const algMatch = textOut.match(/Public Key Algorithm:\s*(.+)/);
			const sanMatch = textOut.match(
				/X509v3 Subject Alternative Name:\s*\n\s*(.+)/
			);

			const toIso = (raw?: string): string => {
				if (!raw) return "";
				const d = new Date(raw.trim());
				return Number.isNaN(d.getTime()) ? "" : d.toISOString();
			};

			return {
				...entry,
				fingerprintSha256: fprMatch
					? normalizeFingerprint(fprMatch[1])
					: "",
				publicKeyAlgorithm: algMatch ? algMatch[1].trim() : "",
				subjectAltName: sanMatch ? sanMatch[1].trim() : undefined,
				notBefore: toIso(notBeforeMatch?.[1]),
				notAfter: toIso(notAfterMatch?.[1]),
				pem,
			};
		} catch (error) {
			this.logger.error(
				`Failed to parse issued certificate ${normalizedSerial}: ${(error as Error).message}`
			);
			throw new HttpException(
				"Failed to read certificate details",
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		} finally {
			try {
				fs.rmSync(tmpDir, { recursive: true, force: true });
			} catch (_) {}
		}
	}

	// ──────────────────────────────────────────────
	// CSR signing (replaces server-side key generation)
	// ──────────────────────────────────────────────

	/**
	 * Sign a client-submitted CSR with the intermediate CA.
	 *
	 * Security model:
	 *  - The client generates their ML-DSA-65 key pair locally.
	 *  - Only the CSR (public key + subject) is sent to this API.
	 *  - The CSR self-signature is verified before signing.
	 *  - A single-use enrollment token pre-issued by an admin authorizes the request.
	 *  - The token carries an allowedCn constraint; the CSR subject CN must match exactly.
	 */
	async signCsr(
		csrPem: string,
		enrollmentToken: string,
		source?: string
	): Promise<SignCsrResponseDto> {
		this.logger.log("Received CSR signing request");

		// Write the CSR to a temp file under /tmp
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pqc-csr-"));
		const csrPath = path.join(tmpDir, "client.csr");

		// Tracked for the admin-action audit trail. The /sign route is @Public()
		// (no admin identity), so we record the enroll explicitly here where the
		// token id and CSR CN are known. Never logs the full token or CSR.
		let csrCn: string | undefined;

		try {
			fs.writeFileSync(csrPath, csrPem, { mode: 0o600 });

			// 1. Verify CSR self-signature
			await this.verifyCsr(csrPath);

			// 2. Enforce PQC-only issuance: refuse to mint a certificate for any
			//    key that is not ML-DSA-65. Runs BEFORE token consumption and any
			//    CA-DB mutation, so a rejected request neither burns the
			//    single-use enrollment token nor touches the CA database.
			await this.assertCsrKeyAlgorithmAllowed(csrPath);

			// 3. Extract CN from CSR subject for token constraint check
			csrCn = await this.extractCsrCn(csrPath);

			// 4. Reserve the enrollment token (item 4): CN, TTL and single-use
			//    are checked atomically, but the token is only marked used once a
			//    certificate exists (commit). A definite failure releases it; an
			//    ambiguous one is reconciled with the custodian first.
			let reservationId = crypto.randomUUID();
			let reserved = await this.tokenStore.reserve(
				enrollmentToken,
				csrCn,
				reservationId,
				CertsService.LEASE_MS
			);
			if (reserved.result === "stale_reservation") {
				const settled = await this.reconcileReservation(
					enrollmentToken,
					reserved.reservationId,
					csrCn
				);
				if (settled) {
					const replay = await this.replayIfSameKey(
						csrPath,
						csrCn,
						settled.serialNumber,
						settled.certificate
					);
					if (replay.kind === "replay")
						return await this.auditReplay(
							enrollmentToken,
							csrCn,
							replay.r,
							source
						);
					if (replay.kind === "mismatch")
						await this.auditKeyMismatch(
							enrollmentToken,
							csrCn,
							replay.why,
							source
						);
					throw this.tokenFailure("already_used");
				}
				reservationId = crypto.randomUUID();
				reserved = await this.tokenStore.reserve(
					enrollmentToken,
					csrCn,
					reservationId,
					CertsService.LEASE_MS
				);
			}
			if (reserved.result === "already_used") {
				const replay = await this.replayIfSameKey(
					csrPath,
					csrCn,
					reserved.serial
				);
				if (replay.kind === "replay")
					return await this.auditReplay(
						enrollmentToken,
						csrCn,
						replay.r,
						source
					);
				if (replay.kind === "mismatch")
					await this.auditKeyMismatch(
						enrollmentToken,
						csrCn,
						replay.why,
						source
					);
			}
			if (reserved.result !== "ok")
				throw this.tokenFailure(reserved.result);
			const profile = reserved.meta.profile;
			await this.adminAudit.append({
				action: "token.reserve",
				actor: null,
				target: `cn=${csrCn}`,
				params: {
					tokenId: tokenId(enrollmentToken),
					reservationId,
					profile: profile ?? "legacy",
				},
				result: { status: "ok", httpStatus: HttpStatus.OK },
			});

			// 5. Sign with the intermediate CA – the ONLY component that touches
			//    the private key is the pqc-ca-custodian sidecar.
			let signed: {
				certificate: string;
				serialNumber: string;
				expiresAt: string;
			};
			try {
				signed = await signCsrViaCustodian(this.logger, csrPem, {
					idempotencyKey: `enroll:${reservationId}`,
					...(profile ? { profile } : {}),
				});
			} catch (err) {
				const kind =
					err instanceof CustodianHttpException
						? err.kind
						: "ambiguous";
				if (kind === "ambiguous") {
					let settled: {
						certificate: string;
						serialNumber: string;
						expiresAt: string;
					} | null = null;
					try {
						settled = await this.reconcileReservation(
							enrollmentToken,
							reservationId,
							csrCn
						);
					} catch (e) {
						this.logger.warn(
							`Reservation ${reservationId} left for the periodic reconcile: ${(e as Error).message}`
						);
						throw err;
					}
					if (!settled) throw err;
					signed = settled;
				} else {
					await this.tokenStore.release(
						enrollmentToken,
						reservationId
					);
					await this.adminAudit.append({
						action: "token.release",
						actor: null,
						target: `cn=${csrCn}`,
						params: {
							tokenId: tokenId(enrollmentToken),
							reservationId,
							reason: kind,
						},
						result: { status: "ok", httpStatus: HttpStatus.OK },
					});
					throw err;
				}
			}
			const { certificate: certPem, serialNumber, expiresAt } = signed;
			const commit = await this.tokenStore.commit(
				enrollmentToken,
				reservationId,
				serialNumber
			);
			if (commit !== "ok")
				this.logger.warn(
					`Commit of reservation ${reservationId} returned ${commit}`
				);

			this.logger.log(
				`Certificate signed: serial=${serialNumber}, expires=${expiresAt}`
			);

			await this.adminAudit.append({
				action: "cert.enroll",
				actor: null, // public, token-authorized enrollment – no admin identity
				target: `cn=${csrCn} serial=${serialNumber}`,
				params: {
					cn: csrCn,
					tokenId: tokenId(enrollmentToken),
					reservationId,
					profile: profile ?? "legacy",
					source,
				},
				result: { status: "ok", httpStatus: HttpStatus.CREATED },
			});

			return { certificate: certPem, serialNumber, expiresAt };
		} catch (error) {
			this.logger.error(`Failed to sign CSR: ${error.message}`);

			const isKnownHttpException = error instanceof HttpException;
			const httpStatus = isKnownHttpException
				? (error as HttpException).getStatus()
				: HttpStatus.INTERNAL_SERVER_ERROR;
			await this.adminAudit.append({
				action: "cert.enroll",
				actor: null,
				target: csrCn ? `cn=${csrCn}` : null,
				params: {
					cn: csrCn,
					tokenId: tokenId(enrollmentToken),
					source,
				},
				result: {
					status: "error",
					httpStatus,
					message: (error as Error).message,
				},
			});

			// Don't leak internal details (paths, OpenSSL stderr) to the client
			if (isKnownHttpException) throw error;

			throw new HttpException(
				"Certificate signing failed. Ensure your CSR is valid and the subject DN is correct.",
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		} finally {
			// Always clean up temp files
			try {
				fs.rmSync(tmpDir, { recursive: true, force: true });
			} catch (_) {}
		}
	}

	/**
	 * Pre-flight a CSR WITHOUT signing or consuming a token. Reuses the same
	 * self-signature and ML-DSA-65 key-algorithm checks as enrollment, but
	 * returns a structured verdict instead of throwing, so the console can
	 * validate before spending a single-use token.
	 */
	async validateCsr(csrPem: string): Promise<ValidateCsrResponseDto> {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pqc-csr-chk-"));
		const csrPath = path.join(tmpDir, "client.csr");
		try {
			fs.writeFileSync(csrPath, csrPem, { mode: 0o600 });

			let selfSignatureValid = true;
			try {
				await this.verifyCsr(csrPath);
			} catch {
				selfSignatureValid = false;
			}
			if (!selfSignatureValid) {
				return {
					valid: false,
					reason: "CSR self-signature verification failed. The CSR may be malformed or tampered with.",
				};
			}

			const algorithm = await this.readCsrKeyAlgorithm(csrPath);
			let cn: string | undefined;
			try {
				cn = await this.extractCsrCn(csrPath);
			} catch {
				cn = undefined;
			}

			if (algorithm === null) {
				return {
					valid: false,
					cn,
					reason: "Unable to determine the CSR public-key algorithm; refusing to issue.",
				};
			}
			if (algorithm !== ALLOWED_CSR_KEY_ALGORITHM) {
				return {
					valid: false,
					cn,
					publicKeyAlgorithm: algorithm,
					reason:
						`Unsupported client key algorithm "${algorithm}": only ` +
						`${ALLOWED_CSR_KEY_ALGORITHM} is permitted for enrollment.`,
				};
			}

			return { valid: true, cn, publicKeyAlgorithm: algorithm };
		} finally {
			try {
				fs.rmSync(tmpDir, { recursive: true, force: true });
			} catch {
				/* best-effort cleanup */
			}
		}
	}

	/**
	 * The issuance checks renewal shares with enrollment: CSR self-signature and
	 * ML-DSA-65 key (both required enforcement points), then the CN.
	 */
	async checkCsrForIssuance(csrPath: string): Promise<string> {
		await this.verifyCsr(csrPath);
		await this.assertCsrKeyAlgorithmAllowed(csrPath);
		return this.extractCsrCn(csrPath);
	}

	private async extractCsrCn(csrPath: string): Promise<string> {
		const { stdout } = await execFileAsync(this.openssl, [
			"req",
			"-in",
			csrPath,
			"-noout",
			"-subject",
		]);
		// Modern OpenSSL: "subject=C = BG, O = ACME Corp, CN = my-service"
		// Legacy OpenSSL: "subject= /C=BG/O=ACME/CN=my-service"
		const m = stdout.match(/\bCN\s*=\s*([^,\/\n]+)/);
		if (!m) {
			throw new HttpException(
				"CSR subject does not contain a CN (Common Name) field",
				HttpStatus.BAD_REQUEST
			);
		}
		return m[1].trim();
	}

	private async verifyCsr(csrPath: string): Promise<void> {
		try {
			const { stdout, stderr } = await execFileAsync(this.openssl, [
				"req",
				"-verify",
				"-in",
				csrPath,
				"-noout",
			]);
			const output = stdout + stderr;
			// "verify OK" is printed to stderr on success
			if (!output.includes("verify OK")) {
				throw new Error("Self-signature verification failed");
			}
		} catch (_error) {
			throw new HttpException(
				"CSR self-signature verification failed. The CSR may be malformed or tampered with.",
				HttpStatus.BAD_REQUEST
			);
		}
	}

	/**
	 * Defense-in-depth, issuance side: refuse to sign any CSR whose public-key
	 * algorithm is not ML-DSA-65. Reads the algorithm via OpenSSL 3.6.2
	 * `req -text` ("Public Key Algorithm:" field) and compares it exactly.
	 *
	 * Fails CLOSED: if the algorithm cannot be parsed for any reason, the request
	 * is rejected rather than signed. Rejections are HTTP 400 with a descriptive
	 * message and must occur before any CA-DB mutation or token consumption.
	 */
	/**
	 * Read the CSR's public-key algorithm string via OpenSSL `req -text`.
	 * Returns null if it cannot be determined (caller decides fail-closed).
	 */
	private async readCsrKeyAlgorithm(csrPath: string): Promise<string | null> {
		try {
			const { stdout } = await execFileAsync(this.openssl, [
				"req",
				"-in",
				csrPath,
				"-noout",
				"-text",
			]);
			const m = stdout.match(/Public Key Algorithm:\s*(.+)/);
			return m ? m[1].trim() : null;
		} catch (error) {
			this.logger.error(
				`Failed to determine CSR public-key algorithm: ${error.message}`
			);
			return null;
		}
	}

	private async assertCsrKeyAlgorithmAllowed(csrPath: string): Promise<void> {
		const algorithm = await this.readCsrKeyAlgorithm(csrPath);

		if (algorithm === null) {
			throw new HttpException(
				"Unable to determine the CSR public-key algorithm; refusing to issue. " +
					`Only ${ALLOWED_CSR_KEY_ALGORITHM} client keys are permitted.`,
				HttpStatus.BAD_REQUEST
			);
		}

		if (algorithm !== ALLOWED_CSR_KEY_ALGORITHM) {
			this.logger.warn(
				`Rejected enrollment CSR with disallowed key algorithm "${algorithm}" ` +
					`(only ${ALLOWED_CSR_KEY_ALGORITHM} is permitted)`
			);
			throw new HttpException(
				`Unsupported client key algorithm "${algorithm}": only ` +
					`${ALLOWED_CSR_KEY_ALGORITHM} is permitted for enrollment.`,
				HttpStatus.BAD_REQUEST
			);
		}

		this.logger.log(`CSR key algorithm accepted: ${algorithm}`);
	}

	// ──────────────────────────────────────────────
	// Revocation
	// ──────────────────────────────────────────────

	/**
	 * SHA-256 fingerprint of an issued certificate, computed the same way
	 * getCertificateDetail does (fetch the PEM via the custodian, hash it
	 * locally) but without that method's extra SAN/pubkey-alg/validity-date
	 * parsing – this is only ever used for the self-revocation identity check.
	 */
	private async getCertificateFingerprint(
		normalizedSerial: string
	): Promise<string> {
		const pem = await fetchIssuedPemViaCustodian(
			this.logger,
			normalizedSerial
		);

		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pqc-cert-fpr-"));
		const certPath = path.join(tmpDir, "cert.pem");
		fs.writeFileSync(certPath, pem, { mode: 0o600 });

		try {
			const { stdout } = await execFileAsync(this.openssl, [
				"x509",
				"-in",
				certPath,
				"-noout",
				"-fingerprint",
				"-sha256",
			]);
			const match = stdout.match(/Fingerprint=([0-9A-Fa-f:]+)/);
			return match ? normalizeFingerprint(match[1]) : "";
		} finally {
			try {
				fs.rmSync(tmpDir, { recursive: true, force: true });
			} catch (_) {}
		}
	}

	async revokeCertificate(
		serial: string,
		reason: string,
		callerFingerprint: string
	): Promise<{ message: string }> {
		// Normalise and strictly validate the serial before it touches any file path
		// or shell argument.  normalizeSerial throws 400 for non-hex input.
		const normalizedSerial = this.normalizeSerial(serial);
		this.logger.log(
			`Revoking certificate with serial: ${normalizedSerial}, reason: ${reason}`
		);

		// Single source of truth: RevocationReason (revoke-cert.dto.ts) already
		// enforces this same Mozilla Root Store Policy §6.1.1 set at the DTO
		// boundary via @IsEnum – derive from it rather than a hand-maintained
		// duplicate list that could silently drift out of sync.
		const validReasons: string[] = Object.values(RevocationReason);
		if (!validReasons.includes(reason)) {
			throw new HttpException(
				`Invalid revocation reason: ${reason}. ` +
					`Allowed per Mozilla Root Store Policy §6.1.1: ${validReasons.join(", ")}`,
				HttpStatus.BAD_REQUEST
			);
		}

		try {
			// Verify the certificate exists in the CA database before attempting revocation
			await this.getCertificate(normalizedSerial);

			// Refuse self-revocation: compare by fingerprint (the same forgery-proof
			// identity primitive JwtAuthGuard itself authorizes on – see its own
			// docstring), never by CN/subject. Revoking the certificate currently
			// authenticating this very request would lock the caller out of the
			// console mid-session; ask another admin to do it instead. Deliberately
			// unconditional (no reason-based override, e.g. for keyCompromise) –
			// `reason` is self-reported by the caller, so trusting it to bypass this
			// check would defeat the point.
			const targetFingerprint =
				await this.getCertificateFingerprint(normalizedSerial);
			if (normalizeFingerprint(callerFingerprint) === targetFingerprint) {
				throw new HttpException(
					"You cannot revoke your own certificate – this would immediately " +
						"invalidate the session you're using to make this request, " +
						"locking you out of the admin console. Ask another admin to " +
						"revoke it instead.",
					HttpStatus.FORBIDDEN
				);
			}

			// RFC 5280 §5.3.1 / BR §7.2.2: when reason is unspecified, the CRL
			// reasonCode extension MUST be omitted. Revocation itself – the only
			// step that touches the private key – happens in the pqc-ca-custodian
			// sidecar; it also owns the not-found/already-revoked checks now.
			await revokeViaCustodian(
				this.logger,
				normalizedSerial,
				reason !== "unspecified" ? reason : undefined
			);

			// Propagate the revocation into a fresh CRL. In production this is
			// delegated to the dedicated crl-renewer (least privilege); in dev it
			// runs in-process. See triggerCrlRegeneration for the rationale.
			const mode = await triggerCrlRegeneration(this.logger);

			return {
				message:
					mode === "signaled"
						? `Certificate ${normalizedSerial} revoked successfully; CRL regeneration signaled to the renewer.`
						: `Certificate ${normalizedSerial} revoked successfully and CRL regenerated.`,
			};
		} catch (error) {
			this.logger.error(`Failed to revoke certificate: ${error.message}`);
			if (error instanceof HttpException) throw error;
			throw new HttpException(
				"Certificate revocation failed",
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	// ──────────────────────────────────────────────
	// Helpers
	// ──────────────────────────────────────────────

	/**
	 * Normalizes a serial number to the format OpenSSL uses in index.txt:
	 * uppercase hex, even number of digits (e.g. "1006", "0A", "10E4").
	 *
	 * Accepts:
	 *   - Raw hex (default): "1006", "1001", "0A3F"  → upper-cased, even-length
	 *   - 0x-prefixed:       "0x1006"                → strips prefix, normalizes
	 *   - Explicit decimal:  "dec:4102"              → converts to hex "1006"
	 */
	private normalizeSerial(serial: string): string {
		const trimmed = serial.trim();

		if (trimmed.toLowerCase().startsWith("dec:")) {
			const n = parseInt(trimmed.slice(4), 10);
			if (isNaN(n) || n < 0) {
				throw new HttpException(
					"Invalid serial number: dec: prefix must be followed by a non-negative integer",
					HttpStatus.BAD_REQUEST
				);
			}
			const hex = n.toString(16).toUpperCase();
			return hex.length % 2 === 0 ? hex : "0" + hex;
		}

		const rawHex = trimmed.toLowerCase().startsWith("0x")
			? trimmed.slice(2)
			: trimmed;

		if (!/^[0-9A-Fa-f]{1,40}$/.test(rawHex)) {
			throw new HttpException(
				"Invalid serial number: must be hexadecimal (1–40 characters), 0x-prefixed hex, or dec:-prefixed decimal",
				HttpStatus.BAD_REQUEST
			);
		}

		const hex = rawHex.toUpperCase();
		return hex.length % 2 === 0 ? hex : "0" + hex;
	}
}
