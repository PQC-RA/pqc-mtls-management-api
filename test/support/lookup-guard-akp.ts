/**
 * Child-process half of lookup-token.akp.spec.ts (ADR-022 decision 6:
 * "LookupTokenGuard still working with an AKP entry in the shared JWKS").
 *
 * Runs the REAL LookupTokenGuard with the REAL jwks-rsa (jest cannot load its
 * ESM dependency, so this runs under plain Node + ts-node) against a loopback
 * JWKS that holds the gateway's three RSA entries AND the ML-DSA-65 AKP entry
 * admin-v2, as the gateway publishes it. Prints one RESULT line.
 */
import * as crypto from "crypto";
import * as fs from "fs";
import * as http from "http";
import * as https from "https";
import * as path from "path";

import * as jwt from "jsonwebtoken";

async function main(): Promise<void> {
	const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
	const j = rsa.publicKey.export({ format: "jwk" });
	const entry = (kid: string) => ({
		...j,
		kty: "RSA",
		use: "sig",
		alg: "RS256",
		kid,
	});
	const jwks = JSON.stringify({
		keys: [
			entry("backend-v1"),
			entry("admin-v1"),
			{
				kty: "AKP",
				use: "sig",
				alg: "ML-DSA-65",
				kid: "admin-v2",
				pub: crypto.randomBytes(1952).toString("base64url"),
			},
			entry("lookup-v1"),
		],
	});
	// LOOKUP_TLS (ADR-022 L2, the :8081 leaf check on this channel):
	//   unset                 plain http JWKS on loopback (default)
	//   node:<crt>:<key>      Node https server with this (RSA) certificate
	//   docroot:<dir>:<url>   the JWKS written to <dir>/jwks.json, fetched from
	//                         <url> (an OpenSSL s_server -WWW with an ML-DSA-65
	//                         certificate, started by the spec: Node cannot sign
	//                         ML-DSA)
	// Trust comes from NODE_EXTRA_CA_CERTS, as in production.
	const mode = (process.env.LOOKUP_TLS ?? "").split(":");
	const handler: http.RequestListener = (_q, r) => {
		r.writeHead(200, { "content-type": "application/json" });
		r.end(jwks);
	};
	let server: http.Server | https.Server | undefined;
	if (mode[0] === "docroot") {
		fs.writeFileSync(path.join(mode[1], "jwks.json"), jwks);
		process.env.GATEWAY_JWKS_URI = mode.slice(2).join(":");
	} else {
		server =
			mode[0] === "node"
				? https.createServer(
						{
							cert: fs.readFileSync(mode[1]),
							key: fs.readFileSync(mode[2]),
						},
						handler
					)
				: http.createServer(handler);
		const s = server;
		await new Promise<void>(res => s.listen(0, "127.0.0.1", () => res()));
		const scheme = mode[0] === "node" ? "https" : "http";
		process.env.GATEWAY_JWKS_URI = `${scheme}://127.0.0.1:${(s.address() as { port: number }).port}/jwks.json`;
	}

	// Loaded only now: the guard reads GATEWAY_JWKS_URI at module load.
	// eslint-disable-next-line @typescript-eslint/no-require-imports
	const { LookupTokenGuard } = require("@/common/guards/lookup-token.guard");
	const guard = new LookupTokenGuard();
	const fpr = crypto.randomBytes(32).toString("hex");
	const token = jwt.sign({ sub: "svc", fpr }, rsa.privateKey, {
		algorithm: "RS256",
		keyid: "lookup-v1",
		issuer: "pqc-gateway",
		audience: "pqc-cert-lookup",
		expiresIn: 60,
	});
	const ctx = {
		switchToHttp: () => ({
			getRequest: () => ({
				headers: { "x-pqc-lookup-token": token },
				params: { fpr },
			}),
		}),
	};
	let lookup = "FAIL";
	try {
		lookup = (await guard.canActivate(ctx)) === true ? "OK" : "FAIL";
	} catch (e) {
		lookup = `FAIL ${(e as Error).message}`;
	}
	server?.close();
	console.log(`RESULT lookup=${lookup}`);
}

main().then(
	() => process.exit(0),
	e => {
		console.log(`RESULT lookup=FAIL ${(e as Error).message}`);
		process.exit(1);
	}
);
