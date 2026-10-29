/**
 * ADR-022, the :8081 leaf check shared by the JWKS fetch, LookupTokenGuard and
 * the route push (gateway-tls.ts), and the transition trust file: a BUNDLE of
 * the ML-DSA-65 and the RSA internal CA, so that management-api, started once
 * on it, accepts either leaf while the gateway switches between them.
 */
import * as fs from "fs";
import * as https from "https";
import * as path from "path";

import {
	makeJwksFetcher,
	MAX_JWKS_BYTES,
} from "@/common/auth/admin-jwks.store";
import {
	gatewayHttpsAgent,
	gatewayHttpsPost,
	gatewayLeafCheck,
} from "@/common/auth/gateway-tls";

import { MldsaFixtures } from "../../../test/support/mldsa-openssl";

jest.setTimeout(60_000);

const fx = new MldsaFixtures();
const SAN = "DNS:gateway,IP:127.0.0.1";
const BODY = '{"keys":[]}';
const stops: Array<() => void> = [];
let docroot: string;
let mlCa: { key: string; crt: string };
let rsaCa: { key: string; crt: string };
let bundle: Buffer;

async function sServe(cert: { key: string; crt: string }): Promise<string> {
	const s = await fx.sServer(cert, docroot);
	stops.push(s.stop);
	return `https://127.0.0.1:${s.port}/jwks.json`;
}

/** A Node https server (RSA leaf: Node cannot sign ML-DSA) recording POSTs. */
async function nodeServe(
	cert: { key: string; crt: string },
	seen: Array<{ headers: Record<string, unknown>; body: string }>
): Promise<string> {
	const server = https.createServer(
		{ cert: fs.readFileSync(cert.crt), key: fs.readFileSync(cert.key) },
		(q, r) => {
			let b = "";
			q.on("data", c => (b += c));
			q.on("end", () => {
				seen.push({ headers: q.headers, body: b });
				r.writeHead(200, { "content-type": "application/json" });
				r.end('{"ok":true}');
			});
		}
	);
	await new Promise<void>(res => server.listen(0, "127.0.0.1", () => res()));
	stops.push(() => server.close());
	return `https://127.0.0.1:${(server.address() as { port: number }).port}/update-routes`;
}

function get(url: string, agent: https.Agent): Promise<number> {
	return new Promise((resolve, reject) => {
		https
			.get(url, { agent }, res => {
				res.resume();
				resolve(res.statusCode ?? 0);
			})
			.on("error", reject);
	});
}

beforeAll(async () => {
	docroot = path.join(fx.dir, "www-gwtls");
	fs.mkdirSync(docroot);
	fs.writeFileSync(path.join(docroot, "jwks.json"), BODY);
	mlCa = await fx.ca("ML-DSA-65", "PQC-GW Internal TLS CA ML-DSA-65");
	rsaCa = await fx.ca("RSA", "PQC-GW Internal TLS CA");
	bundle = Buffer.concat([
		fs.readFileSync(mlCa.crt),
		fs.readFileSync(rsaCa.crt),
	]);
});
afterAll(() => {
	stops.forEach(s => s());
	fx.cleanup();
});

describe("gatewayLeafCheck", () => {
	it("is off without a leaf type, and fails closed on an unsupported one", () => {
		expect(gatewayLeafCheck(undefined)).toBeUndefined();
		expect(gatewayLeafCheck("")).toBeUndefined();
		expect(gatewayHttpsAgent(undefined)).toBeUndefined();
		const odd = gatewayLeafCheck("ml-dsa-65");
		expect(odd).toBeDefined();
		expect(odd?.("gateway", {} as never)?.message).toMatch(
			/unsupported GATEWAY_TLS_LEAF_ALG/
		);
	});
});

describe("the transition bundle (ML-DSA-65 CA + RSA CA) as the pinned trust file", () => {
	it("JWKS fetch: an ML-DSA-65 leaf and an RSA leaf both verify against the bundle", async () => {
		const ml = await sServe(await fx.leaf("ML-DSA-65", mlCa, SAN));
		const rsa = await sServe(await fx.leaf("RSA", rsaCa, SAN));
		await expect(
			makeJwksFetcher({ ca: bundle })(ml, MAX_JWKS_BYTES)
		).resolves.toBe(BODY);
		await expect(
			makeJwksFetcher({ ca: bundle })(rsa, MAX_JWKS_BYTES)
		).resolves.toBe(BODY);
		// The end state's leaf check still refuses the RSA leaf.
		await expect(
			makeJwksFetcher({ ca: bundle, leafAlg: "ML-DSA-65" })(
				ml,
				MAX_JWKS_BYTES
			)
		).resolves.toBe(BODY);
		await expect(
			makeJwksFetcher({ ca: bundle, leafAlg: "ML-DSA-65" })(
				rsa,
				MAX_JWKS_BYTES
			)
		).rejects.toThrow(/not an ML-DSA-65 certificate/);
	});

	it("a leaf from a CA outside the bundle is refused", async () => {
		const other = await fx.ca("ML-DSA-65", "Someone Else CA");
		const url = await sServe(await fx.leaf("ML-DSA-65", other, SAN));
		await expect(
			makeJwksFetcher({ ca: bundle })(url, MAX_JWKS_BYTES)
		).rejects.toMatchObject({ code: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" });
	});
});

describe("gatewayHttpsAgent (jwks-rsa requestAgent, route push)", () => {
	it("accepts an ML-DSA-65 leaf and refuses an RSA leaf from the same bundle", async () => {
		const ml = await sServe(await fx.leaf("ML-DSA-65", mlCa, SAN));
		const rsa = await sServe(await fx.leaf("RSA", rsaCa, SAN));
		const agent = gatewayHttpsAgent("ML-DSA-65", bundle);
		expect(agent).toBeInstanceOf(https.Agent);
		await expect(get(ml, agent as https.Agent)).resolves.toBe(200);
		await expect(get(rsa, agent as https.Agent)).rejects.toThrow(
			/not an ML-DSA-65 certificate/
		);
	});

	it("still checks the name", async () => {
		const url = await sServe(
			await fx.leaf("ML-DSA-65", mlCa, "DNS:not-the-gateway")
		);
		await expect(
			get(url, gatewayHttpsAgent("ML-DSA-65", bundle) as https.Agent)
		).rejects.toMatchObject({ code: "ERR_TLS_CERT_ALTNAME_INVALID" });
	});
});

describe("gatewayHttpsPost (route push with a leaf type)", () => {
	it("POSTs headers and body through the agent and returns status and text", async () => {
		const seen: Array<{ headers: Record<string, unknown>; body: string }> =
			[];
		const url = await nodeServe(await fx.leaf("RSA", rsaCa, SAN), seen);
		const res = await gatewayHttpsPost(
			url,
			{ "Content-Type": "application/json", "X-Timestamp": "1" },
			'{"a":1}',
			new https.Agent({ ca: bundle })
		);
		expect(res.ok).toBe(true);
		expect(res.status).toBe(200);
		await expect(res.text()).resolves.toBe('{"ok":true}');
		expect(seen).toHaveLength(1);
		expect(seen[0].body).toBe('{"a":1}');
		expect(seen[0].headers["x-timestamp"]).toBe("1");
	});

	it("refuses an RSA :8081 leaf with GATEWAY_TLS_LEAF_ALG=ML-DSA-65, before sending anything", async () => {
		const seen: Array<{ headers: Record<string, unknown>; body: string }> =
			[];
		const url = await nodeServe(await fx.leaf("RSA", rsaCa, SAN), seen);
		await expect(
			gatewayHttpsPost(
				url,
				{},
				'{"a":1}',
				gatewayHttpsAgent("ML-DSA-65", bundle) as https.Agent
			)
		).rejects.toThrow(/not an ML-DSA-65 certificate/);
		expect(seen).toHaveLength(0);
	});
});
