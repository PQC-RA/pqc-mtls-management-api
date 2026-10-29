import * as crypto from "crypto";
import * as https from "https";
import * as tls from "tls";

import {
	MLDSA65_PUB_LENGTH,
	MLDSA65_SPKI_PREFIX,
} from "@/common/auth/admin-jwt.verifier";

/**
 * The gateway's :8081 control plane as seen from this API (ADR-022): the JWKS
 * fetch (admin token and LookupTokenGuard) and the route push.
 *
 * The chain is pinned by NODE_EXTRA_CA_CERTS (the internal TLS CA, or during
 * the ADR-022 transition a bundle of the ML-DSA-65 and the RSA internal CA).
 * Chain validation alone accepts any leaf a pinned CA signed, an RSA one
 * included. GATEWAY_TLS_LEAF_ALG=ML-DSA-65 additionally requires the :8081
 * leaf to carry an ML-DSA-65 key, on every one of the three channels.
 */

export const SUPPORTED_LEAF_ALGS: readonly string[] = ["ML-DSA-65"];

/** True if a DER certificate's public key is an ML-DSA-65 key. */
export function isMldsa65Certificate(raw: Buffer): boolean {
	try {
		const spki = new crypto.X509Certificate(raw).publicKey.export({
			format: "der",
			type: "spki",
		});
		return (
			spki.length === MLDSA65_SPKI_PREFIX.length + MLDSA65_PUB_LENGTH &&
			spki
				.subarray(0, MLDSA65_SPKI_PREFIX.length)
				.equals(MLDSA65_SPKI_PREFIX)
		);
	} catch {
		return false;
	}
}

export type ServerIdentityCheck = (
	host: string,
	cert: tls.PeerCertificate
) => Error | undefined;

/**
 * checkServerIdentity for the :8081 leaf. undefined when no leaf type is
 * required (chain and name checks only, Node's default). An unsupported value
 * refuses every connection (fail closed) rather than being ignored.
 */
export function gatewayLeafCheck(
	leafAlg: string | undefined
): ServerIdentityCheck | undefined {
	if (!leafAlg) return undefined;
	if (!SUPPORTED_LEAF_ALGS.includes(leafAlg)) {
		return () => new Error(`unsupported GATEWAY_TLS_LEAF_ALG ${leafAlg}`);
	}
	return (host, cert) => {
		const err = tls.checkServerIdentity(host, cert);
		if (err) return err;
		if (!isMldsa65Certificate(cert.raw)) {
			return new Error(
				"the :8081 certificate is not an ML-DSA-65 certificate"
			);
		}
		return undefined;
	};
}

/**
 * An https.Agent that applies gatewayLeafCheck (for jwks-rsa's requestAgent
 * and the route push). undefined when no leaf type is required.
 * `ca` replaces Node's trust anchors (tests); production: NODE_EXTRA_CA_CERTS.
 */
export function gatewayHttpsAgent(
	leafAlg: string | undefined,
	ca?: string | Buffer
): https.Agent | undefined {
	const check = gatewayLeafCheck(leafAlg);
	if (!check) return undefined;
	return new https.Agent({
		checkServerIdentity: check,
		...(ca ? { ca } : {}),
	});
}

export interface SimpleResponse {
	ok: boolean;
	status: number;
	text(): Promise<string>;
}

/**
 * POST over https through `agent` (fetch cannot take an https.Agent). The
 * response body is capped at 64 KiB; the whole call at timeoutMs.
 */
export function gatewayHttpsPost(
	url: string,
	headers: Record<string, string>,
	body: string,
	agent: https.Agent,
	timeoutMs = 10_000
): Promise<SimpleResponse> {
	return new Promise((resolve, reject) => {
		const req = https.request(
			url,
			{
				method: "POST",
				agent,
				headers: {
					...headers,
					"Content-Length": Buffer.byteLength(body).toString(),
				},
				timeout: timeoutMs,
			},
			res => {
				const chunks: Buffer[] = [];
				let size = 0;
				res.on("data", (c: Buffer) => {
					size += c.length;
					if (size <= 64 * 1024) chunks.push(c);
				});
				res.on("end", () => {
					const status = res.statusCode ?? 0;
					const text = Buffer.concat(chunks).toString("utf8");
					resolve({
						ok: status >= 200 && status < 300,
						status,
						text: async () => text,
					});
				});
				res.on("error", reject);
			}
		);
		req.on("timeout", () =>
			req.destroy(new Error("gateway control-plane call timed out"))
		);
		req.on("error", reject);
		req.end(body);
	});
}
