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

async function custodianRequest<T>(
	logger: Logger,
	method: "GET" | "POST",
	pathSegment: string,
	body?: unknown
): Promise<T> {
	const secret = getCustodianHmacSecret();
	if (!secret) {
		logger.error(
			"custodian-hmac secret not configured – refusing to call pqc-ca-custodian"
		);
		throw new HttpException(
			"CA custodian is not configured",
			HttpStatus.INTERNAL_SERVER_ERROR
		);
	}

	const bodyStr = body !== undefined ? JSON.stringify(body) : "";
	const sig =
		"sha256=" +
		crypto.createHmac("sha256", secret).update(bodyStr).digest("hex");

	let response: Response;
	try {
		response = await fetch(`${PKI_CONFIG.custodianUrl}${pathSegment}`, {
			method,
			headers: {
				"Content-Type": "application/json",
				"X-Hub-Signature-256": sig,
			},
			body: body !== undefined ? bodyStr : undefined,
			signal: AbortSignal.timeout(15_000),
		});
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		logger.error(
			`CA custodian call failed (${method} ${pathSegment}): ${message}`
		);
		throw new HttpException(
			"Failed to contact CA custodian",
			HttpStatus.BAD_GATEWAY
		);
	}

	const payload = (await response
		.json()
		.catch(() => ({}))) as CustodianErrorBody & Record<string, unknown>;

	if (!response.ok) {
		if (response.status === 404) {
			throw new HttpException(
				payload.message ?? "Not found",
				HttpStatus.NOT_FOUND
			);
		}
		if (response.status === 409) {
			throw new HttpException(
				payload.message ?? "Conflict",
				HttpStatus.CONFLICT
			);
		}
		if (response.status === 400) {
			throw new HttpException(
				payload.message ?? "Bad request",
				HttpStatus.BAD_REQUEST
			);
		}
		logger.error(
			`CA custodian returned ${response.status} for ${method} ${pathSegment}: ${payload.error ?? "unknown"} – ${payload.message ?? ""}`
		);
		throw new HttpException(
			"CA custodian request failed",
			HttpStatus.BAD_GATEWAY
		);
	}

	return payload as T;
}

export interface CustodianSignResult {
	certificate: string;
	serialNumber: string;
	expiresAt: string;
}

export async function signCsrViaCustodian(
	logger: Logger,
	csrPem: string
): Promise<CustodianSignResult> {
	return custodianRequest<CustodianSignResult>(logger, "POST", "/sign", {
		csrPem,
	});
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
