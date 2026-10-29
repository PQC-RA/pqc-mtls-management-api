/**
 * ADR-022 decision 6: LookupTokenGuard (Token 2, jwks-rsa 4.x) must keep
 * working once the shared JWKS also carries the ML-DSA-65 AKP entry admin-v2.
 * If jwks-rsa failed on the unknown key type, every cert lookup would fail.
 *
 * And the :8081 leaf check (GATEWAY_TLS_LEAF_ALG) on this channel too, with
 * NODE_EXTRA_CA_CERTS holding the transition bundle (ML-DSA-65 and RSA
 * internal CA) as in production: an RSA leaf passes the chain check alone and
 * is refused with GATEWAY_TLS_LEAF_ALG=ML-DSA-65; an ML-DSA-65 leaf passes.
 *
 * jest cannot load the real jwks-rsa (its jose dependency is ESM), so the
 * real guard runs in a child Node process (test/support/lookup-guard-akp.ts).
 */
import { execFile } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { promisify } from "util";

import { MldsaFixtures } from "../../../test/support/mldsa-openssl";

jest.setTimeout(180_000);

const root = path.resolve(__dirname, "../../..");
const fx = new MldsaFixtures();
const SAN = "DNS:gateway,IP:127.0.0.1";
const stops: Array<() => void> = [];
let bundle: string;
let rsaLeaf: { key: string; crt: string };
let mldsaLeaf: { key: string; crt: string };

async function runGuard(env: Record<string, string>): Promise<string> {
	const { stdout } = await promisify(execFile)(
		process.execPath,
		[
			"-r",
			"ts-node/register/transpile-only",
			"-r",
			"tsconfig-paths/register",
			path.join(root, "test/support/lookup-guard-akp.ts"),
		],
		{
			cwd: root,
			timeout: 110_000,
			env: {
				...process.env,
				TS_NODE_PROJECT: path.join(root, "tsconfig.json"),
				GATEWAY_TLS_LEAF_ALG: "",
				...env,
			},
		}
	).catch((e: { stdout?: string }) => ({ stdout: e.stdout ?? "" }));
	return stdout;
}

beforeAll(async () => {
	const mlCa = await fx.ca("ML-DSA-65", "PQC-GW Internal TLS CA ML-DSA-65");
	const rsaCa = await fx.ca("RSA", "PQC-GW Internal TLS CA");
	bundle = path.join(fx.dir, "internal-tls-ca.crt");
	fs.writeFileSync(
		bundle,
		Buffer.concat([fs.readFileSync(mlCa.crt), fs.readFileSync(rsaCa.crt)])
	);
	rsaLeaf = await fx.leaf("RSA", rsaCa, SAN);
	mldsaLeaf = await fx.leaf("ML-DSA-65", mlCa, SAN);
});
afterAll(() => {
	stops.forEach(s => s());
	fx.cleanup();
});

it("LookupTokenGuard verifies a lookup-v1 token with an AKP entry in the JWKS (real jwks-rsa)", async () => {
	expect(await runGuard({})).toMatch(/RESULT lookup=OK/);
});

it("RSA :8081 leaf from the bundled RSA CA: accepted without a leaf type, refused with GATEWAY_TLS_LEAF_ALG=ML-DSA-65", async () => {
	const tlsEnv = {
		LOOKUP_TLS: `node:${rsaLeaf.crt}:${rsaLeaf.key}`,
		NODE_EXTRA_CA_CERTS: bundle,
	};
	expect(await runGuard(tlsEnv)).toMatch(/RESULT lookup=OK/);
	expect(
		await runGuard({ ...tlsEnv, GATEWAY_TLS_LEAF_ALG: "ML-DSA-65" })
	).toMatch(/RESULT lookup=FAIL/);
});

it("ML-DSA-65 :8081 leaf from the bundled ML-DSA-65 CA: accepted with GATEWAY_TLS_LEAF_ALG=ML-DSA-65", async () => {
	const docroot = path.join(fx.dir, "www-lookup");
	fs.mkdirSync(docroot);
	const s = await fx.sServer(mldsaLeaf, docroot);
	stops.push(s.stop);
	expect(
		await runGuard({
			LOOKUP_TLS: `docroot:${docroot}:https://127.0.0.1:${s.port}/jwks.json`,
			NODE_EXTRA_CA_CERTS: bundle,
			GATEWAY_TLS_LEAF_ALG: "ML-DSA-65",
		})
	).toMatch(/RESULT lookup=OK/);
});

it("GATEWAY_TLS_LEAF_ALG with a plain-http JWKS URI refuses every lookup", async () => {
	expect(await runGuard({ GATEWAY_TLS_LEAF_ALG: "ML-DSA-65" })).toMatch(
		/RESULT lookup=FAIL/
	);
});
