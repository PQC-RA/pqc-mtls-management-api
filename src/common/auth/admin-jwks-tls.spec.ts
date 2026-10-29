/**
 * ADR-022 decision 6, the :8081 cases: the JWKS fetch against an OpenSSL
 * s_server configured like the gateway's control plane (TLS 1.3 only,
 * X25519MLKEM768 only), with certificates made by the OpenSSL CLI.
 *
 *   - ML-DSA-65 leaf from the pinned ML-DSA-65 internal CA: fetched
 *   - leaf from another CA: refused (chain)
 *   - RSA leaf from the pinned CA: accepted by chain validation alone, refused
 *     with GATEWAY_TLS_LEAF_ALG=ML-DSA-65 (what the end state sets)
 */
import * as fs from "fs";
import * as path from "path";

import {
	makeJwksFetcher,
	MAX_JWKS_BYTES,
} from "@/common/auth/admin-jwks.store";

import { MldsaFixtures } from "../../../test/support/mldsa-openssl";

jest.setTimeout(60_000);

const fx = new MldsaFixtures();
const BODY =
	'{"keys":[{"kty":"AKP","alg":"ML-DSA-65","kid":"admin-v2","pub":"x"}]}';
const SAN = "DNS:gateway,IP:127.0.0.1";
let docroot: string;
let pinnedCa: { key: string; crt: string };
const servers: Array<() => void> = [];

async function serve(cert: { key: string; crt: string }): Promise<string> {
	const s = await fx.sServer(cert, docroot);
	servers.push(s.stop);
	return `https://127.0.0.1:${s.port}/jwks.json`;
}

beforeAll(async () => {
	docroot = path.join(fx.dir, "www");
	fs.mkdirSync(docroot);
	fs.writeFileSync(path.join(docroot, "jwks.json"), BODY);
	pinnedCa = await fx.ca("ML-DSA-65", "PQC-GW Internal TLS CA ML-DSA-65");
});
afterAll(() => {
	servers.forEach(stop => stop());
	fx.cleanup();
});

const pinned = () => fs.readFileSync(pinnedCa.crt);

it("fetches the JWKS from an ML-DSA-65 leaf of the pinned ML-DSA-65 CA (leaf type enforced)", async () => {
	const url = await serve(await fx.leaf("ML-DSA-65", pinnedCa, SAN));
	await expect(
		makeJwksFetcher({ ca: pinned(), leafAlg: "ML-DSA-65" })(
			url,
			MAX_JWKS_BYTES
		)
	).resolves.toBe(BODY);
	await expect(
		makeJwksFetcher({ ca: pinned() })(url, MAX_JWKS_BYTES)
	).resolves.toBe(BODY);
});

it("refuses an ML-DSA-65 leaf from another CA", async () => {
	const other = await fx.ca("ML-DSA-65", "Someone Else CA");
	const url = await serve(await fx.leaf("ML-DSA-65", other, SAN));
	await expect(
		makeJwksFetcher({ ca: pinned() })(url, MAX_JWKS_BYTES)
	).rejects.toThrow();
	await expect(
		makeJwksFetcher({ ca: pinned(), leafAlg: "ML-DSA-65" })(
			url,
			MAX_JWKS_BYTES
		)
	).rejects.toThrow();
});

it("refuses an RSA leaf from another (RSA) CA", async () => {
	const other = await fx.ca("RSA", "Old RSA CA");
	const url = await serve(await fx.leaf("RSA", other, SAN));
	await expect(
		makeJwksFetcher({ ca: pinned() })(url, MAX_JWKS_BYTES)
	).rejects.toThrow();
});

it("an RSA leaf from the pinned CA passes chain validation, and is refused by the leaf-type check", async () => {
	const url = await serve(await fx.leaf("RSA", pinnedCa, SAN));
	await expect(
		makeJwksFetcher({ ca: pinned() })(url, MAX_JWKS_BYTES)
	).resolves.toBe(BODY);
	await expect(
		makeJwksFetcher({ ca: pinned(), leafAlg: "ML-DSA-65" })(
			url,
			MAX_JWKS_BYTES
		)
	).rejects.toThrow(/not an ML-DSA-65 certificate/);
});

it("refuses a leaf whose name is not the one asked for", async () => {
	const url = await serve(
		await fx.leaf("ML-DSA-65", pinnedCa, "DNS:not-the-gateway")
	);
	await expect(
		makeJwksFetcher({ ca: pinned(), leafAlg: "ML-DSA-65" })(
			url,
			MAX_JWKS_BYTES
		)
	).rejects.toThrow();
});

it("refuses a body over the cap", async () => {
	const url = await serve(await fx.leaf("ML-DSA-65", pinnedCa, SAN));
	await expect(makeJwksFetcher({ ca: pinned() })(url, 16)).rejects.toThrow(
		/size cap/
	);
});

it("refuses the leaf-type requirement over plain http", async () => {
	await expect(
		makeJwksFetcher({ leafAlg: "ML-DSA-65" })(
			"http://127.0.0.1:9/jwks.json",
			MAX_JWKS_BYTES
		)
	).rejects.toThrow(/not https/);
});
