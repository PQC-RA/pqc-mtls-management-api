import * as crypto from "crypto";
import * as fs from "fs";

import { HttpException, HttpStatus, Logger } from "@nestjs/common";

import { PKI_CONFIG } from "@/common/config/pki.config";

/**
 * Client for the pqc-ca-custodian sidecar – the ONLY component with any access
 * to the intermediate CA private key. management-api holds no CA-tree mount
 * at all; every CA-subsystem operation (sign, revoke, list, read an issued
 * cert, read the CRL) goes through this HTTP client instead of a local
 * `openssl ca` invocation or a direct file read.
 *
 * Auth mirrors the existing gateway control-plane convention (see
 * policy.service.ts / control_plane.lua): HMAC-SHA256 over the raw request
 * body, secret loaded from a Docker-secret-style file. This uses a DEDICATED
 * secret (custodian-hmac, separate from control-plane-hmac) so a leaked secret
 * here can only reach the CA custodian, not the gateway's route-push endpoint,
 * and vice versa.
 */

interface CustodianErrorBody {
	error?: string;
	message?: string;
}

function getCustodianHmacSecret(): string {
	const secretFile = "/run/secrets/custodian-hmac";
	try {
		return fs.readFileSync(secretFile, "utf8").trim();
	} catch {
		return process.env.CUSTODIAN_HMAC_SECRET ?? "";
	}
}

/**
 * How a failed custodian call must be treated by a caller that holds a
 * reservation:
 *   refused   the custodian answered and did not sign (safe to release)
 *   not_sent  the request never reached the custodian (safe to release)
 *   ambiguous the custodian may have signed (reconcile before releasing)
 */
export type CustodianErrorKind = "refused" | "not_sent" | "ambiguous";

export class CustodianHttpException extends HttpException {
	constructor(
		message: string,
		status: HttpStatus,
		readonly kind: CustodianErrorKind,
		readonly code?: string,
		readonly details?: Record<string, unknown>
	) {
		super(message, status);
	}
}

const NOT_SENT_CODES = new Set([
	"ENOTFOUND",
	"EAI_AGAIN",
	"ECONNREFUSED",
	"EHOSTUNREACH",
	"ENETUNREACH",
]);

function sha256Hex(data: string | Buffer): string {
	return crypto.createHash("sha256").update(data).digest("hex");
}

async function custodianRequest<T>(
	logger: Logger,
	method: "GET" | "POST",
	pathSegment: string,
	body?: unknown,
	timeoutMs = 15_000
): Promise<T> {
	const secret = getCustodianHmacSecret();
	if (!secret) {
		logger.error(
			"custodian-hmac secret not configured – refusing to call pqc-ca-custodian"
		);
		throw new CustodianHttpException(
			"CA custodian is not configured",
			HttpStatus.INTERNAL_SERVER_ERROR,
			"not_sent"
		);
	}

	// Request authentication v2: method, path, timestamp, nonce and the body
	// hash are all covered, so a captured request cannot be replayed.
	const bodyStr = body !== undefined ? JSON.stringify(body) : "";
	const ts = String(Date.now());
	const nonce = crypto.randomBytes(16).toString("hex");
	const mac = (data: string) =>
		crypto.createHmac("sha256", secret).update(data).digest("hex");
	const sig =
		"sha256=" +
		mac(
			`v2\n${method}\n${pathSegment}\n${ts}\n${nonce}\n${sha256Hex(bodyStr)}`
		);

	let response: Response;
	try {
		response = await fetch(`${PKI_CONFIG.custodianUrl}${pathSegment}`, {
			method,
			headers: {
				"Content-Type": "application/json",
				"X-Hub-Signature-256": sig,
				"X-Custodian-Timestamp": ts,
				"X-Custodian-Nonce": nonce,
			},
			body: body !== undefined ? bodyStr : undefined,
			signal: AbortSignal.timeout(timeoutMs),
		});
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		const code = (error as { cause?: { code?: string } })?.cause?.code;
		const kind: CustodianErrorKind =
			code && NOT_SENT_CODES.has(code) ? "not_sent" : "ambiguous";
		logger.error(
			`CA custodian call failed (${method} ${pathSegment}): ${message} [${code ?? "no code"}, ${kind}]`
		);
		throw new CustodianHttpException(
			"Failed to contact CA custodian",
			HttpStatus.BAD_GATEWAY,
			kind,
			code
		);
	}

	// Responses are signed by the custodian, bound to our nonce; an unsigned
	// or wrongly signed response is not trusted, and is ambiguous for a sign.
	// The body can be lost after the status line arrived (a connection dropped
	// mid-answer, or the timeout firing while it is read). The custodian may have
	// signed: that is an ambiguous outcome, never a bare AbortError (which the
	// renewal path turned into a 500 the client would not retry; measured on the
	// stand 2026-10-26).
	let raw: Buffer;
	try {
		raw = Buffer.from(await response.arrayBuffer());
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		logger.error(
			`CA custodian answer for ${method} ${pathSegment} was cut off: ${message} [ambiguous]`
		);
		throw new CustodianHttpException(
			"CA custodian answer was cut off",
			HttpStatus.BAD_GATEWAY,
			"ambiguous"
		);
	}
	const respSig = response.headers.get("x-custodian-response-signature");
	const expected =
		"sha256=" + mac(`v2r\n${response.status}\n${nonce}\n${sha256Hex(raw)}`);
	if (
		!respSig ||
		respSig.length !== expected.length ||
		!crypto.timingSafeEqual(Buffer.from(respSig), Buffer.from(expected))
	) {
		logger.error(
			`CA custodian response for ${method} ${pathSegment} is not authenticated`
		);
		throw new CustodianHttpException(
			"CA custodian response could not be authenticated",
			HttpStatus.BAD_GATEWAY,
			"ambiguous",
			"response_unauthenticated"
		);
	}
	let payload: CustodianErrorBody & Record<string, unknown> = {};
	try {
		payload = raw.length ? JSON.parse(raw.toString("utf8")) : {};
	} catch {
		payload = {};
	}

	if (!response.ok) {
		const code =
			typeof payload.error === "string" ? payload.error : undefined;
		const mayHaveIssued = payload.mayHaveIssued === true;
		if (response.status >= 400 && response.status < 500 && !mayHaveIssued) {
			const status =
				response.status === 404
					? HttpStatus.NOT_FOUND
					: response.status === 409
						? HttpStatus.CONFLICT
						: response.status === 403
							? HttpStatus.FORBIDDEN
							: HttpStatus.BAD_REQUEST;
			throw new CustodianHttpException(
				payload.message ?? "CA custodian refused the request",
				status,
				"refused",
				code,
				payload
			);
		}
		logger.error(
			`CA custodian returned ${response.status} for ${method} ${pathSegment}: ${payload.error ?? "unknown"} – ${payload.message ?? ""}`
		);
		throw new CustodianHttpException(
			"CA custodian request failed",
			HttpStatus.BAD_GATEWAY,
			"ambiguous",
			code
		);
	}

	return payload as T;
}

export interface CustodianSignResult {
	certificate: string;
	serialNumber: string;
	expiresAt: string;
}

export interface SignOptions {
	profile?: "client-30d" | "demo-120s";
	renewsSerial?: string;
	idempotencyKey?: string;
}

export async function signCsrViaCustodian(
	logger: Logger,
	csrPem: string,
	options: SignOptions = {}
): Promise<
	CustodianSignResult & {
		replay?: boolean;
		lineageId?: string;
		notBefore?: string;
	}
> {
	return custodianRequest(logger, "POST", "/sign", {
		csrPem,
		...options,
	});
}

/**
 * The custodian's record for one idempotency key. Runs inline after an
 * ambiguous sign (15 s), so it gets a short timeout of its own: 15 + 5 s stays
 * well inside the gateway's 30 s proxy_read_timeout. With 15 s here the API
 * could answer at the same second nginx gives up, and a certificate committed
 * then would reach nobody (measured on the stand 2026-10-25, T3).
 */
export async function fetchSignResultViaCustodian(
	logger: Logger,
	idempotencyKey: string,
	timeoutMs = 5_000
): Promise<
	{
		state: "none" | "intent_without_certificate" | "issued";
	} & Partial<CustodianSignResult>
> {
	return custodianRequest(
		logger,
		"GET",
		`/sign-result/${encodeURIComponent(idempotencyKey)}`,
		undefined,
		timeoutMs
	);
}

export interface LineageRecord {
	serial: string;
	lineageId: string;
	bootstrapAt: number;
	profile: string;
	predecessor: string | null;
	successor?: string;
	frozen?: boolean;
	capAt: string;
}

export async function fetchLineageViaCustodian(
	logger: Logger,
	serial: string
): Promise<LineageRecord> {
	return custodianRequest(
		logger,
		"GET",
		`/lineage/${encodeURIComponent(serial)}`
	);
}

export async function freezeLineageViaCustodian(
	logger: Logger,
	serialNumber: string
): Promise<void> {
	await custodianRequest(logger, "POST", "/lineage/freeze", { serialNumber });
}

export async function revokeViaCustodian(
	logger: Logger,
	serialNumber: string,
	reason?: string
): Promise<void> {
	await custodianRequest<{ ok: true }>(logger, "POST", "/revoke", {
		serialNumber,
		reason,
	});
}

export async function fetchIndexViaCustodian(logger: Logger): Promise<string> {
	const { content } = await custodianRequest<{ content: string }>(
		logger,
		"GET",
		"/index"
	);
	return content;
}

export async function fetchIssuedPemViaCustodian(
	logger: Logger,
	serialNumber: string
): Promise<string> {
	const { content } = await custodianRequest<{ content: string }>(
		logger,
		"GET",
		`/issued/${encodeURIComponent(serialNumber)}`
	);
	return content;
}

export async function fetchCertByFingerprintViaCustodian(
	logger: Logger,
	fingerprint: string
): Promise<CustodianSignResult> {
	return custodianRequest<CustodianSignResult>(
		logger,
		"GET",
		`/cert/by-fingerprint/${encodeURIComponent(fingerprint)}`
	);
}

export async function fetchCrlViaCustodian(
	logger: Logger
): Promise<{ content: string; mtimeMs: number }> {
	return custodianRequest<{ content: string; mtimeMs: number }>(
		logger,
		"GET",
		"/crl"
	);
}

/**
 * Unauthenticated liveness check (no HMAC – /healthz carries no CA data,
 * just booleans). Used by health.service.indicator.ts in place of the local
 * CA-tree file checks it ran before this process stopped mounting the tree.
 */
export async function checkCustodianHealth(
	logger: Logger
): Promise<{ ok: boolean; indexOk?: boolean; crlOk?: boolean }> {
	try {
		const response = await fetch(`${PKI_CONFIG.custodianUrl}/healthz`, {
			signal: AbortSignal.timeout(5_000),
		});
		const payload = (await response.json().catch(() => ({}))) as {
			ok?: boolean;
			indexOk?: boolean;
			crlOk?: boolean;
		};
		return {
			ok: response.ok && payload.ok === true,
			indexOk: payload.indexOk,
			crlOk: payload.crlOk,
		};
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		logger.error(`CA custodian health check failed: ${message}`);
		return { ok: false };
	}
}
