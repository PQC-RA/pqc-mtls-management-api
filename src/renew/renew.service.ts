import { execFile } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { promisify } from "util";

import { HttpException, HttpStatus, Injectable, Logger } from "@nestjs/common";

import { AdminAuditService } from "@/admin-audit/admin-audit.service";
import { CertsService } from "@/certs/certs.service";
import {
	CustodianHttpException,
	fetchIssuedPemViaCustodian,
	fetchLineageViaCustodian,
	fetchSignResultViaCustodian,
	freezeLineageViaCustodian,
	LineageRecord,
	revokeViaCustodian,
	signCsrViaCustodian,
} from "@/common/ca-custodian.util";
import { PKI_CONFIG } from "@/common/config/pki.config";
import { triggerCrlRegeneration } from "@/common/crl-signal.util";
import { RenewAttestation } from "@/renew/renew-attest.guard";
import { RenewDto, RenewResponseDto } from "@/renew/renew.dto";

const execFileAsync = promisify(execFile);

/** DER prefix of a SubjectPublicKeyInfo for ML-DSA-65 (OID 2.16.840.1.101.3.4.3.18, 1,952-byte key). */
const MLDSA65_SPKI_PREFIX = Buffer.from(
	"308207b2300b0609608648016503040312038207a100",
	"hex"
);
const MLDSA65_SPKI_LENGTH = MLDSA65_SPKI_PREFIX.length + 1952;

function sha256Hex(data: Buffer | string): string {
	return crypto.createHash("sha256").update(data).digest("hex");
}

function refuse(
	status: HttpStatus,
	error: string,
	message: string,
	extra: Record<string, unknown> = {}
): HttpException {
	return new HttpException(
		{ statusCode: status, error, message, ...extra },
		status
	);
}

function isMlDsa65Spki(der: Buffer): boolean {
	return (
		der.length === MLDSA65_SPKI_LENGTH &&
		der.subarray(0, MLDSA65_SPKI_PREFIX.length).equals(MLDSA65_SPKI_PREFIX)
	);
}

/** The exact bytes the current key signs to prove possession (ADR-015 decision 3). */
export function popMessage(
	csrDerSha256Hex: string,
	serial: string,
	timestamp: number
): Buffer {
	return Buffer.from(
		`pqc-renew-v1\n${csrDerSha256Hex}\n${serial}\n${timestamp}`,
		"utf8"
	);
}

export function pemBodyToDer(pem: string, label: string): Buffer {
	const m = new RegExp(
		`-----BEGIN ${label}-----([\\s\\S]+?)-----END ${label}-----`
	).exec(pem);
	if (!m)
		throw refuse(
			HttpStatus.BAD_REQUEST,
			"invalid_csr",
			`Not a PEM ${label}`
		);
	return Buffer.from(m[1].replace(/\s+/g, ""), "base64");
}

/**
 * Renewal over mTLS (item 4, ADR-015). The client proves who it is twice: by
 * the mTLS handshake, attested by the gateway (RenewAttestGuard), and by a
 * signature of its CURRENT key over the new CSR's hash, so a compromised
 * gateway cannot obtain a successor for a client whose key it does not hold.
 * The custodian then enforces subject equality, the new-key rule, one
 * successor per certificate and the lineage cap inside its CA lock.
 */
@Injectable()
export class RenewService {
	private readonly logger = new Logger(RenewService.name);
	private readonly openssl = PKI_CONFIG.openssl;
	static readonly POP_SKEW_S = 120;
	static readonly BACKDATE_S = 60; // the custodian backdates notBefore by this much
	/** Renewal conflicts since start; exported by the metrics endpoint. */
	conflicts = 0;

	constructor(
		private readonly certs: CertsService,
		private readonly adminAudit: AdminAuditService
	) {}

	private alertsLogPath(): string {
		return (
			process.env.RENEW_ALERTS_LOG ??
			path.join(
				path.dirname(PKI_CONFIG.adminAuditLogPath),
				"renew-alerts.log"
			)
		);
	}

	private async spkiSha256OfCsr(csrPath: string): Promise<string> {
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
		if (!isMlDsa65Spki(der))
			throw refuse(
				HttpStatus.BAD_REQUEST,
				"invalid_csr",
				"Only ML-DSA-65 keys can be renewed"
			);
		return sha256Hex(der);
	}

	async renew(
		att: RenewAttestation,
		dto: RenewDto,
		source?: string
	): Promise<RenewResponseDto> {
		const serial = att.serial;
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pqc-renew-"));
		const csrPath = path.join(tmpDir, "renew.csr");
		let cn: string | undefined;
		try {
			fs.writeFileSync(csrPath, dto.csr, { mode: 0o600 });
			// Both required enforcement points: self-signature and ML-DSA-65 only.
			cn = await this.certs.checkCsrForIssuance(csrPath);
			const csrHash = sha256Hex(
				pemBodyToDer(dto.csr, "CERTIFICATE REQUEST")
			);
			const newSpki = await this.spkiSha256OfCsr(csrPath);

			// The presented certificate must be the one the CA issued for that serial.
			let predPem: string;
			try {
				predPem = await fetchIssuedPemViaCustodian(this.logger, serial);
			} catch (err) {
				if (
					err instanceof CustodianHttpException &&
					err.kind === "refused"
				) {
					throw refuse(
						HttpStatus.FORBIDDEN,
						"not_renewable",
						"No issued certificate for this serial"
					);
				}
				throw err;
			}
			const pred = new crypto.X509Certificate(predPem);
			if (
				pred.fingerprint256.replace(/:/g, "").toLowerCase() !==
				att.fingerprint
			) {
				this.logger.warn(
					`Renewal: presented certificate does not match the issued certificate for serial ${serial}`
				);
				throw refuse(
					HttpStatus.FORBIDDEN,
					"certificate_mismatch",
					"The presented certificate is not the issued certificate for its serial"
				);
			}
			const now = Date.now();
			const validFrom = Date.parse(pred.validFrom);
			const validTo = Date.parse(pred.validTo);
			if (!(now < validTo) || !(now >= validFrom))
				throw refuse(
					HttpStatus.FORBIDDEN,
					"not_valid",
					"The presented certificate is not currently valid"
				);
			const predKey = pred.publicKey;
			if (
				!isMlDsa65Spki(
					predKey.export({ type: "spki", format: "der" }) as Buffer
				)
			) {
				throw refuse(
					HttpStatus.FORBIDDEN,
					"not_renewable",
					"Only ML-DSA-65 certificates can be renewed"
				);
			}

			// Only certificates issued under a renewal profile have a lineage.
			let lineage: LineageRecord;
			try {
				lineage = await fetchLineageViaCustodian(this.logger, serial);
			} catch (err) {
				if (
					err instanceof CustodianHttpException &&
					err.kind === "refused"
				) {
					throw refuse(
						HttpStatus.FORBIDDEN,
						"not_renewable",
						"This certificate was not issued under a renewal profile"
					);
				}
				throw err;
			}
			if (lineage.frozen)
				throw refuse(
					HttpStatus.FORBIDDEN,
					"lineage_frozen",
					"This identity is frozen; a new bootstrap enrollment is required"
				);

			// Window (ADR-014): the client renews at 2/3; the server refuses before 1/2.
			const issuedAt = validFrom + RenewService.BACKDATE_S * 1000;
			const earliest = issuedAt + (validTo - issuedAt) / 2;
			if (now < earliest) {
				throw refuse(
					HttpStatus.CONFLICT,
					"too_early",
					"Renewal opens at half of the certificate's lifetime",
					{
						retryAfterSeconds: Math.ceil((earliest - now) / 1000),
					}
				);
			}

			// Proof of possession of the CURRENT key.
			const popTs = dto.pop.timestamp;
			if (
				Math.abs(Math.floor(now / 1000) - popTs) >
				RenewService.POP_SKEW_S
			) {
				throw refuse(
					HttpStatus.BAD_REQUEST,
					"pop_stale",
					`The proof timestamp must be within ${RenewService.POP_SKEW_S} s`
				);
			}
			const popSig = Buffer.from(dto.pop.signature, "base64");
			let popOk = false;
			try {
				popOk = crypto.verify(
					null,
					popMessage(csrHash, serial, popTs),
					predKey,
					popSig
				);
			} catch {
				popOk = false;
			}
			if (!popOk) {
				this.logger.warn(
					`Renewal: proof of possession failed for serial ${serial}`
				);
				throw refuse(
					HttpStatus.FORBIDDEN,
					"pop_invalid",
					"The proof of possession of the current key is invalid"
				);
			}

			// Server-computed idempotency (ADR-015 decision 8): a retry with the same
			// new key returns the same successor.
			const idempotencyKey = `renew:${serial}:${newSpki}`;
			let signed: {
				certificate: string;
				serialNumber: string;
				expiresAt: string;
				notBefore?: string;
				replay?: boolean;
			};
			try {
				signed = await signCsrViaCustodian(this.logger, dto.csr, {
					renewsSerial: serial,
					idempotencyKey,
				});
			} catch (err) {
				if (
					err instanceof CustodianHttpException &&
					err.code === "successor_exists"
				) {
					const successor =
						typeof err.details?.successorSerial === "string"
							? err.details.successorSerial
							: undefined;
					await this.handleConflict(serial, successor, cn, source);
					throw refuse(
						HttpStatus.CONFLICT,
						"renewal_conflict",
						"This identity was renewed with a different key; it is frozen and both certificates are revoked"
					);
				}
				if (
					err instanceof CustodianHttpException &&
					err.kind === "ambiguous"
				) {
					let r: Awaited<
						ReturnType<typeof fetchSignResultViaCustodian>
					> | null = null;
					try {
						r = await fetchSignResultViaCustodian(
							this.logger,
							idempotencyKey
						);
					} catch {
						r = null;
					}
					if (
						r &&
						r.state === "issued" &&
						r.certificate &&
						r.serialNumber
					) {
						signed = {
							certificate: r.certificate,
							serialNumber: r.serialNumber,
							expiresAt: r.expiresAt ?? "",
							replay: true,
						};
					} else {
						throw refuse(
							HttpStatus.SERVICE_UNAVAILABLE,
							"retry",
							"The CA did not confirm; retry with the same key"
						);
					}
				} else if (
					err instanceof CustodianHttpException &&
					err.kind === "refused"
				) {
					throw refuse(
						err.getStatus(),
						err.code ?? "refused",
						err.message
					);
				} else {
					throw err;
				}
			}

			await this.adminAudit.append({
				action: "cert.renew",
				actor: null,
				target: `cn=${cn} serial=${signed.serialNumber}`,
				params: {
					cn,
					predecessor: serial,
					lineageId: lineage.lineageId,
					replay: signed.replay === true,
					source,
				},
				result: { status: "ok", httpStatus: HttpStatus.CREATED },
			});
			this.logger.log(
				`Renewed serial=${serial} -> ${signed.serialNumber} cn=${cn}${signed.replay ? " (replay)" : ""}`
			);
			return {
				certificate: signed.certificate,
				serialNumber: signed.serialNumber,
				notBefore: signed.notBefore ?? "",
				expiresAt: signed.expiresAt,
				...(signed.replay ? { replay: true } : {}),
			};
		} catch (error) {
			const status =
				error instanceof HttpException
					? error.getStatus()
					: HttpStatus.INTERNAL_SERVER_ERROR;
			await this.adminAudit.append({
				action: "cert.renew",
				actor: null,
				target: cn ? `cn=${cn} serial=${serial}` : `serial=${serial}`,
				params: { cn, predecessor: serial, source },
				result: {
					status: "error",
					httpStatus: status,
					message: (error as Error).message,
				},
			});
			if (error instanceof HttpException) throw error;
			this.logger.error(
				`Renewal failed for serial ${serial}: ${(error as Error).message}`
			);
			throw refuse(
				HttpStatus.INTERNAL_SERVER_ERROR,
				"renewal_failed",
				"Renewal failed"
			);
		} finally {
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	}

	/**
	 * Conflict rule (ADR-015 decision 9): a second, different key for one
	 * predecessor means one of the two holders is not the legitimate client.
	 * Freeze the identity, revoke both certificates, raise an alert. Recovery is
	 * a bootstrap enrollment.
	 */
	private async handleConflict(
		predecessor: string,
		successor: string | undefined,
		cn: string | undefined,
		source?: string
	): Promise<void> {
		this.conflicts++;
		this.logger.error(
			`RENEWAL CONFLICT cn=${cn} predecessor=${predecessor} successor=${successor ?? "?"}: freezing and revoking`
		);
		const errors: string[] = [];
		// Each step is attempted even if an earlier one fails; failures go into the alert.
		const attempt = async (label: string, step: () => Promise<unknown>) => {
			try {
				await step();
			} catch (e) {
				errors.push(`${label}: ${(e as Error).message}`);
			}
		};
		await attempt("freeze", () =>
			freezeLineageViaCustodian(this.logger, predecessor)
		);
		for (const s of [predecessor, successor]) {
			if (s)
				await attempt(`revoke ${s}`, () =>
					revokeViaCustodian(this.logger, s, "keyCompromise")
				);
		}
		await attempt("crl", () => triggerCrlRegeneration(this.logger));
		const line = JSON.stringify({
			ts: new Date().toISOString(),
			event: "renew.conflict",
			cn,
			predecessor,
			successor,
			source,
			errors,
		});
		try {
			fs.appendFileSync(this.alertsLogPath(), line + "\n", {
				mode: 0o640,
			});
		} catch (e) {
			this.logger.error(
				`Could not write the renewal alert log: ${(e as Error).message}`
			);
		}
		await this.adminAudit.append({
			action: "renew.conflict",
			actor: null,
			target: `cn=${cn} serial=${predecessor}`,
			params: { cn, predecessor, successor, source, errors },
			result: {
				status: errors.length ? "error" : "ok",
				httpStatus: HttpStatus.CONFLICT,
			},
		});
	}
}
