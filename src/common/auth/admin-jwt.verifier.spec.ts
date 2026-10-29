/**
 * ADR-022 decision 6: the admin-v2 (ML-DSA-65) verifier suite.
 *
 * Every ML-DSA signature here is made by the OpenSSL CLI through execFile
 * (test/support/mldsa-openssl.ts): Node 22 cannot sign ML-DSA. The RFC 9964
 * Appendix A.1 ML-DSA-65 example is verified as a known answer.
 */
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

import {
	buildAdminKeys,
	MAX_JWKS_BYTES,
	parsePubPin,
} from "@/common/auth/admin-jwks.store";
import {
	AdminJwtError,
	AdminKid,
	assertKeyMatchesSpec,
	checkAdminClaims,
	decodeCanonicalB64url,
	JtiCache,
	KID_TABLE,
	MAX_TOKEN_LENGTH,
	MLDSA65_SPKI_PREFIX,
	parseAdminToken,
	verifyAdminSignature,
} from "@/common/auth/admin-jwt.verifier";

import { b64u, MldsaFixtures } from "../../../test/support/mldsa-openssl";

jest.setTimeout(60_000);

const V2 = new Set<AdminKid>(["admin-v2"]);
const BOTH = new Set<AdminKid>(["admin-v1", "admin-v2"]);
const H_V2 = '{"alg":"ML-DSA-65","typ":"JWT","kid":"admin-v2"}';
const ISS = "pqc-gateway";
const AUD = "pqc-mtls-management-api";
const FPR = "1c2ba075293fcd68e241cfcedf337ff59bc8126b24c2af07c60f319a38e1a0d8";

const fx = new MldsaFixtures();
let key: { keyPath: string; spki: Buffer; pub: Buffer };
let pin: Buffer;
let jwks: string;
let v2Key: crypto.KeyObject;

function claims(
	over: Record<string, unknown> = {},
	now = Math.floor(Date.now() / 1000)
) {
	return JSON.stringify({
		iss: ISS,
		aud: AUD,
		sub: "ops-admin",
		role: "admin",
		fpr: FPR,
		iat: now,
		exp: now + 60,
		jti: crypto.randomBytes(16).toString("base64url"),
		htm: "GET",
		htu: "/api/admin/certs",
		...over,
	});
}

function ctx(now = Math.floor(Date.now() / 1000)) {
	return {
		now,
		issuer: ISS,
		audience: AUD,
		method: "GET",
		path: "/api/admin/certs",
		requireBinding: true,
	};
}

/** Full verify of one token, as JwtAuthGuard runs it (minus the jti cache). */
async function verify(
	token: string,
	accepted = V2,
	keys = buildAdminKeys(jwks, accepted, pin).keys
) {
	const p = parseAdminToken(token, accepted);
	const k = keys.get(p.kid);
	if (!k) throw new AdminJwtError("jwks");
	if (!verifyAdminSignature(p.spec, k, p.signingInput, p.signature)) {
		throw new AdminJwtError("signature");
	}
	return checkAdminClaims(p.payload, {
		...ctx(),
		requireBinding: p.kid === "admin-v2",
	});
}

async function reason(fn: () => unknown): Promise<string> {
	try {
		await fn();
	} catch (e) {
		if (e instanceof AdminJwtError) return e.reason;
		throw e;
	}
	return "ACCEPTED";
}

function jwksWith(entries: unknown[]): string {
	return JSON.stringify({ keys: entries });
}
function akp(pub: Buffer, over: Record<string, unknown> = {}) {
	return {
		kty: "AKP",
		use: "sig",
		alg: "ML-DSA-65",
		kid: "admin-v2",
		pub: b64u(pub),
		...over,
	};
}

beforeAll(async () => {
	key = await fx.genKey();
	pin = crypto.createHash("sha256").update(key.pub).digest();
	jwks = jwksWith([akp(key.pub)]);
	v2Key = buildAdminKeys(jwks, V2, pin).keys.get("admin-v2")!;
});
afterAll(() => fx.cleanup());

describe("RFC 9964 Appendix A.1 (ML-DSA-65) known answer", () => {
	const kat = JSON.parse(
		fs.readFileSync(
			path.join(
				__dirname,
				"../../../test/fixtures/rfc9964-a1-ml-dsa-65.json"
			),
			"utf8"
		)
	) as {
		jwk: { pub: string; alg: string; kty: string };
		jws: string;
		raw_public_key: string;
	};

	it("the example's pub is 1,952 bytes and is the public key of the all-zero seed (OpenSSL CLI)", async () => {
		const pub = decodeCanonicalB64url(kat.jwk.pub, "pub");
		expect(pub.length).toBe(1952);
		expect(pub.toString("hex")).toBe(kat.raw_public_key);
		const seed0 = await fx.genKey("ML-DSA-65", "00".repeat(32));
		expect(seed0.pub.equals(pub)).toBe(true);
	});

	it("verifies the example JWS through the same key path and signature check as admin-v2", () => {
		const pub = decodeCanonicalB64url(kat.jwk.pub, "pub");
		const body = jwksWith([{ ...kat.jwk, kid: "admin-v2" }]);
		const built = buildAdminKeys(
			body,
			V2,
			crypto.createHash("sha256").update(pub).digest()
		);
		expect(built.errors.size).toBe(0);
		const k = built.keys.get("admin-v2")!;
		const [h, p, s] = kat.jws.split(".");
		const sig = decodeCanonicalB64url(s, "sig");
		expect(
			verifyAdminSignature(
				KID_TABLE["admin-v2"],
				k,
				Buffer.from(`${h}.${p}`),
				sig
			)
		).toBe(true);
		const flipped = Buffer.from(sig);
		flipped[100] ^= 0x01;
		expect(
			verifyAdminSignature(
				KID_TABLE["admin-v2"],
				k,
				Buffer.from(`${h}.${p}`),
				flipped
			)
		).toBe(false);
		expect(
			verifyAdminSignature(
				KID_TABLE["admin-v2"],
				k,
				Buffer.from(`${h}.${p}x`),
				sig
			)
		).toBe(false);
	});

	it("the example's deterministic signature is reproduced by the OpenSSL CLI from the zero seed", async () => {
		const seed0 = await fx.genKey("ML-DSA-65", "00".repeat(32));
		const [h, p, s] = kat.jws.split(".");
		const sig = await fx.sign(seed0.keyPath, `${h}.${p}`, {
			deterministic: true,
		});
		expect(b64u(sig)).toBe(s);
	});

	it("the example token itself is not an admin token (no typ, foreign kid): refused before any key", () => {
		expect(() => parseAdminToken(kat.jws, V2)).toThrow(AdminJwtError);
	});
});

describe("admin-v2 accepted", () => {
	it("accepts a valid token signed by the OpenSSL CLI (pure ML-DSA-65, empty context)", async () => {
		const t = await fx.token(key.keyPath, H_V2, claims());
		await expect(verify(t)).resolves.toMatchObject({ fpr: FPR });
		expect(t.split(".")[2].length).toBe(4412);
	});

	it("KeyObject check: the pinned SPKI only (Node 22 reports no asymmetricKeyType for ML-DSA)", () => {
		expect(v2Key.type).toBe("public");
		expect(() =>
			assertKeyMatchesSpec(
				v2Key,
				KID_TABLE["admin-v2"],
				Buffer.concat([MLDSA65_SPKI_PREFIX, key.pub])
			)
		).not.toThrow();
		const rsa = crypto.generateKeyPairSync("rsa", {
			modulusLength: 2048,
		}).publicKey;
		expect(() =>
			assertKeyMatchesSpec(
				rsa,
				KID_TABLE["admin-v2"],
				Buffer.concat([MLDSA65_SPKI_PREFIX, key.pub])
			)
		).toThrow(AdminJwtError);
		expect(() =>
			assertKeyMatchesSpec(v2Key, KID_TABLE["admin-v1"])
		).toThrow(AdminJwtError);
	});
});

describe("header and algorithm confusion", () => {
	it("refuses alg none (with and without a signature segment)", async () => {
		const h = '{"alg":"none","typ":"JWT","kid":"admin-v2"}';
		expect(
			await reason(() => verify(`${b64u(h)}.${b64u(claims())}.`))
		).toBe("segments");
		expect(
			await reason(() =>
				verify(`${b64u(h)}.${b64u(claims())}.${b64u("x")}`)
			)
		).toBe("alg");
	});

	it("refuses HS256 with the public key as the HMAC secret", async () => {
		for (const kid of ["admin-v2", "admin-v1"]) {
			const h = `{"alg":"HS256","typ":"JWT","kid":"${kid}"}`;
			const input = `${b64u(h)}.${b64u(claims())}`;
			const secret =
				kid === "admin-v2"
					? key.spki
					: Buffer.from("-----BEGIN PUBLIC KEY-----");
			const t = `${input}.${b64u(crypto.createHmac("sha256", secret).update(input).digest())}`;
			expect(await reason(() => verify(t, BOTH))).toBe("alg");
		}
	});

	it("refuses each kid with the other kid's alg", async () => {
		const rsa = await fx.genRsaKey();
		const t1 = await fx.rs256Token(
			rsa,
			'{"alg":"RS256","typ":"JWT","kid":"admin-v2"}',
			claims()
		);
		expect(await reason(() => verify(t1, BOTH))).toBe("alg");
		const t2 = await fx.token(
			key.keyPath,
			'{"alg":"ML-DSA-65","typ":"JWT","kid":"admin-v1"}',
			claims()
		);
		expect(await reason(() => verify(t2, BOTH))).toBe("alg");
	});

	it.each([
		"ml-dsa-65",
		"Ml-Dsa-65",
		"ML-DSA-65 ",
		"MLDSA65",
		"ML_DSA_65",
		"ML-DSA-44",
		"ML-DSA-87",
	])("refuses alg variant %j", async alg => {
		const t = await fx.token(
			key.keyPath,
			`{"alg":${JSON.stringify(alg)},"typ":"JWT","kid":"admin-v2"}`,
			claims()
		);
		expect(await reason(() => verify(t))).toBe("alg");
	});

	it.each([
		"admin-v3",
		"Admin-v2",
		"admin-v2 ",
		"../admin-v2",
		"admin-v2/../x",
		"https://evil/admin-v2",
		"admin-v2?x",
		"backend-v1",
		"lookup-v1",
		"__proto__",
		"toString",
	])("refuses kid %j", async kid => {
		const t = await fx.token(
			key.keyPath,
			`{"alg":"ML-DSA-65","typ":"JWT","kid":${JSON.stringify(kid)}}`,
			claims()
		);
		expect(await reason(() => verify(t, BOTH))).toBe("kid");
	});

	it("refuses admin-v1 when only admin-v2 is accepted (end state)", async () => {
		const rsa = await fx.genRsaKey();
		const t = await fx.rs256Token(
			rsa,
			'{"alg":"RS256","typ":"JWT","kid":"admin-v1"}',
			claims()
		);
		expect(await reason(() => verify(t, V2))).toBe("kid");
	});

	it.each([
		[
			'{"alg":"ML-DSA-65","typ":"JWT","kid":"admin-v2","crit":["b64"],"b64":false}',
			"header_members",
		],
		[
			'{"alg":"ML-DSA-65","typ":"JWT","kid":"admin-v2","crit":["exp"]}',
			"header_members",
		],
		[
			'{"alg":"ML-DSA-65","typ":"JWT","kid":"admin-v2","b64":false}',
			"header_members",
		],
		[
			'{"alg":"ML-DSA-65","typ":"JWT","kid":"admin-v2","jku":"https://evil/jwks"}',
			"header_members",
		],
		[
			'{"alg":"ML-DSA-65","typ":"JWT","kid":"admin-v2","x5u":"https://evil/c"}',
			"header_members",
		],
		[
			'{"alg":"ML-DSA-65","typ":"JWT","kid":"admin-v2","jwk":{}}',
			"header_members",
		],
		['{"alg":"ML-DSA-65","kid":"admin-v2"}', "header_members"],
		['{"alg":"ML-DSA-65","typ":"jwt","kid":"admin-v2"}', "typ"],
		['{"alg":"ML-DSA-65","typ":"JOSE","kid":"admin-v2"}', "typ"],
		['{"alg":"ML-DSA-65","typ":"at+jwt","kid":"admin-v2"}', "typ"],
		['{"alg":"ML-DSA-65","typ":"JWT","kid":2}', "header_types"],
		['{"alg":"ML-DSA-65","typ":"JWT","kid":["admin-v2"]}', "header_types"],
		['{"alg":"ML-DSA-65","typ":"JWT","kid":null}', "header_types"],
		['{"alg":["ML-DSA-65"],"typ":"JWT","kid":"admin-v2"}', "header_types"],
		['{"alg":"ML-DSA-65","typ":true,"kid":"admin-v2"}', "header_types"],
		[
			'{"alg":"ML-DSA-65","typ":"JWT","kid":"admin-v2","kid":"admin-v1"}',
			"bad_json",
		],
		[
			'{"alg":"ML-DSA-65","alg":"RS256","typ":"JWT","kid":"admin-v2"}',
			"bad_json",
		],
		['["ML-DSA-65","JWT","admin-v2"]', "bad_json"],
		['"admin-v2"', "bad_json"],
		['{"alg":"ML-DSA-65","typ":"JWT","kid":"admin-v2"} ', "ACCEPTED"],
		['{"alg":"ML-DSA-65","typ":"JWT","kid":"admin-v2"}x', "bad_json"],
	])("header %s -> %s", async (header, expected) => {
		const t = await fx.token(key.keyPath, header, claims());
		expect(await reason(() => verify(t))).toBe(expected);
	});

	it("refuses duplicate members in the payload and a payload that is not an object", async () => {
		const now = Math.floor(Date.now() / 1000);
		const dup = claims().replace(/}$/, `,"exp":${now + 3600}}`);
		expect(
			await reason(async () =>
				verify(await fx.token(key.keyPath, H_V2, dup))
			)
		).toBe("bad_json");
		const dupFpr = claims().replace(/}$/, ',"fpr":"aa"}');
		expect(
			await reason(async () =>
				verify(await fx.token(key.keyPath, H_V2, dupFpr))
			)
		).toBe("bad_json");
		expect(
			await reason(async () =>
				verify(await fx.token(key.keyPath, H_V2, "[1,2]"))
			)
		).toBe("bad_json");
		expect(
			await reason(async () =>
				verify(await fx.token(key.keyPath, H_V2, "null"))
			)
		).toBe("bad_json");
	});
});

describe("segments, encoding, length", () => {
	let good: string;
	beforeAll(async () => {
		good = await fx.token(key.keyPath, H_V2, claims());
	});

	it.each([
		["2 segments", (t: string) => t.split(".").slice(0, 2).join(".")],
		["4 segments", (t: string) => `${t}.${b64u("x")}`],
		["5 segments", (t: string) => `${t}.${b64u("x")}.${b64u("y")}`],
		[
			"empty header",
			(t: string) => `.${t.split(".")[1]}.${t.split(".")[2]}`,
		],
		[
			"empty payload",
			(t: string) => `${t.split(".")[0]}..${t.split(".")[2]}`,
		],
		[
			"empty signature",
			(t: string) => `${t.split(".")[0]}.${t.split(".")[1]}.`,
		],
		["only dots", () => ".."],
		["empty", () => ""],
	])("refuses %s", async (_n, mut) => {
		expect(await reason(() => verify(mut(good)))).toBe("segments");
	});

	it.each([
		["padding on the signature", (t: string) => `${t}=`],
		[
			"padding on the header",
			(t: string) => {
				const [h, p, s] = t.split(".");
				return `${h}==.${p}.${s}`;
			},
		],
		[
			"'+' in the signature",
			(t: string) => t.slice(0, -10) + "+" + t.slice(-9),
		],
		[
			"'/' in the payload",
			(t: string) => {
				const [h, p, s] = t.split(".");
				return `${h}.${p.slice(0, -1)}/.${s}`;
			},
		],
		[
			"whitespace",
			(t: string) => {
				const [h, p, s] = t.split(".");
				return `${h}.${p} .${s}`;
			},
		],
	])("refuses non-canonical base64url: %s", async (_n, mut) => {
		expect(await reason(() => verify(mut(good)))).toBe(
			"non_canonical_b64url"
		);
	});

	it("refuses base64url whose unused trailing bits are not zero (decodes to the same bytes)", () => {
		// "QQ" and "QR" both decode to "A"; only "QQ" is canonical.
		expect(decodeCanonicalB64url("QQ", "x").toString()).toBe("A");
		expect(() => decodeCanonicalB64url("QR", "x")).toThrow(AdminJwtError);
		expect(() => decodeCanonicalB64url("QUJD=", "x")).toThrow(
			AdminJwtError
		);
		expect(() => decodeCanonicalB64url("Q", "x")).toThrow(AdminJwtError);
	});

	it("refuses a header segment with altered unused trailing bits", async () => {
		// A 52-byte header (H_V2 plus one space, valid JSON) ends in a
		// 2-character group whose last character carries 4 unused bits, so
		// index ^ 1 decodes to the same bytes.
		const hdr = `${H_V2} `;
		expect(Buffer.from(hdr).length % 3).toBe(1);
		const t = await fx.token(key.keyPath, hdr, claims());
		await expect(verify(t)).resolves.toBeDefined();
		const [h, p, s] = t.split(".");
		const alphabet =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		const h2 =
			h.slice(0, -1) + alphabet[alphabet.indexOf(h[h.length - 1]) ^ 1];
		expect(
			Buffer.from(h2, "base64url").equals(Buffer.from(h, "base64url"))
		).toBe(true);
		expect(await reason(() => verify(`${h2}.${p}.${s}`))).toBe(
			"non_canonical_b64url"
		);
	});

	it("caps the length before decoding anything", async () => {
		expect(
			await reason(() => verify("A".repeat(MAX_TOKEN_LENGTH + 1)))
		).toBe("too_long");
		const padded = `${good.split(".")[0]}.${b64u(claims({ pad: "x".repeat(MAX_TOKEN_LENGTH) }))}.${good.split(".")[2]}`;
		expect(await reason(() => verify(padded))).toBe("too_long");
		expect(good.length).toBeLessThan(MAX_TOKEN_LENGTH);
	});
});

describe("signature mutations", () => {
	let input: string;
	let sig: Buffer;
	beforeAll(async () => {
		input = `${b64u(H_V2)}.${b64u(claims())}`;
		sig = await fx.sign(key.keyPath, input);
		expect(sig.length).toBe(3309);
	});
	const tok = (s: Buffer) => `${input}.${b64u(s)}`;

	it("the unmutated control verifies", async () => {
		await expect(verify(tok(sig))).resolves.toBeDefined();
	});
	it("refuses a truncated signature", async () => {
		expect(await reason(() => verify(tok(sig.subarray(0, 3308))))).toBe(
			"signature"
		);
		expect(await reason(() => verify(tok(sig.subarray(0, 2420))))).toBe(
			"signature"
		);
	});
	it("refuses an extended signature", async () => {
		expect(
			await reason(() =>
				verify(tok(Buffer.concat([sig, Buffer.from([0])])))
			)
		).toBe("signature");
	});
	it.each([0, 1, 1000, 3308])(
		"refuses one flipped bit at byte %d",
		async i => {
			const s = Buffer.from(sig);
			s[i] ^= 0x10;
			expect(await reason(() => verify(tok(s)))).toBe("signature");
		}
	);
	it("refuses a valid signature by another ML-DSA-65 key", async () => {
		const other = await fx.genKey();
		expect(
			await reason(async () =>
				verify(tok(await fx.sign(other.keyPath, input)))
			)
		).toBe("signature");
	});
	it("refuses a signature with a non-empty context string", async () => {
		const s = await fx.sign(key.keyPath, input, { context: "pqc-gateway" });
		expect(s.length).toBe(3309);
		expect(await reason(() => verify(tok(s)))).toBe("signature");
	});
	it("refuses a HashML-DSA (SHA-256) signature", async () => {
		const s = await fx.signHashMlDsa(key.keyPath, input);
		expect(s.length).toBe(3309);
		expect(await reason(() => verify(tok(s)))).toBe("signature");
	});
	it("refuses an ML-DSA-44 signature under admin-v2 (2,420 bytes: refused by the length check)", async () => {
		const k44 = await fx.genKey("ML-DSA-44");
		expect(
			await reason(async () =>
				verify(tok(await fx.sign(k44.keyPath, input)))
			)
		).toBe("signature");
	});
});

describe("claims", () => {
	const now = Math.floor(Date.now() / 1000);
	const run = async (over: Record<string, unknown>, c = {}) => {
		const p = parseAdminToken(
			await fx.token(key.keyPath, H_V2, claims(over, now)),
			V2
		);
		return reason(() => checkAdminClaims(p.payload, { ...ctx(now), ...c }));
	};

	it("accepts the gateway's shape", async () => {
		expect(await run({})).toBe("ACCEPTED");
	});
	it("refuses an expired token, and one at exp exactly", async () => {
		expect(await run({ iat: now - 70, exp: now - 10 })).toBe("expired");
		expect(await run({ iat: now - 60, exp: now })).toBe("expired");
	});
	it("refuses a missing or non-numeric exp / iat", async () => {
		expect(await run({ exp: undefined })).toBe("exp");
		expect(await run({ exp: String(now + 60) })).toBe("exp");
		expect(await run({ iat: undefined })).toBe("iat");
		expect(await run({ iat: null })).toBe("iat");
	});
	it("refuses exp - iat > 60 and exp <= iat", async () => {
		expect(await run({ iat: now, exp: now + 61 })).toBe("lifetime");
		expect(await run({ iat: now - 1, exp: now + 3600 })).toBe("lifetime");
		expect(await run({ iat: now + 2, exp: now + 1 })).toBe("lifetime");
	});
	it("allows iat up to now + 5 s, refuses later", async () => {
		expect(await run({ iat: now + 5, exp: now + 60 })).toBe("ACCEPTED");
		expect(await run({ iat: now + 6, exp: now + 60 })).toBe("iat_future");
	});
	it("refuses iss / aud that are not the exact strings (arrays included)", async () => {
		expect(await run({ iss: "pqc-gateway2" })).toBe("iss");
		expect(await run({ iss: [ISS] })).toBe("iss");
		expect(await run({ aud: [AUD] })).toBe("aud");
		expect(await run({ aud: [AUD, "x"] })).toBe("aud");
		expect(await run({ aud: "pqc-backend" })).toBe("aud");
		expect(await run({ aud: "pqc-cert-lookup" })).toBe("aud");
	});
	it("refuses a missing fpr", async () => {
		expect(await run({ fpr: undefined })).toBe("fpr");
		expect(await run({ fpr: "" })).toBe("fpr");
	});
	it("requires jti, htm, htu for admin-v2 and matches htm/htu to the request", async () => {
		expect(await run({ jti: undefined })).toBe("jti");
		expect(await run({ jti: "short" })).toBe("jti");
		expect(await run({ htm: undefined })).toBe("htm");
		expect(await run({ htm: "POST" })).toBe("htm");
		expect(await run({ htm: "get" })).toBe("htm");
		expect(await run({ htu: undefined })).toBe("htu");
		expect(await run({ htu: "/api/admin/certs/x" })).toBe("htu");
		expect(await run({ htu: "/api/admin/certs?x=1" })).toBe("htu");
		expect(await run({}, { method: "DELETE" })).toBe("htm");
		expect(await run({}, { path: "/api/admin/crl" })).toBe("htu");
	});
	it("admin-v1 without jti/htm/htu passes (old gateways, dual window); with them they are checked", async () => {
		expect(
			await run(
				{ jti: undefined, htm: undefined, htu: undefined },
				{ requireBinding: false }
			)
		).toBe("ACCEPTED");
		expect(
			await run({ htu: "/api/admin/other" }, { requireBinding: false })
		).toBe("htu");
	});
});

describe("jti single use", () => {
	it("refuses a replay inside the 60 s and forgets after 120 s", () => {
		const c = new JtiCache();
		expect(c.useOnce("a".repeat(22), 1000)).toBe(true);
		expect(c.useOnce("a".repeat(22), 1001)).toBe(false);
		expect(c.useOnce("a".repeat(22), 1059)).toBe(false);
		expect(c.useOnce("a".repeat(22), 1119)).toBe(false);
		expect(c.useOnce("a".repeat(22), 1120)).toBe(true);
	});
	it("fails closed when full of live entries", () => {
		const c = new JtiCache(120, 3);
		expect(
			c.useOnce("j1", 0) && c.useOnce("j2", 0) && c.useOnce("j3", 0)
		).toBe(true);
		expect(c.useOnce("j4", 1)).toBe(false);
		expect(c.useOnce("j4", 121)).toBe(true);
	});
});

describe("Token 1 and Token 2 presented to /admin/", () => {
	it("refuses the backend and lookup tokens (RS256, kid backend-v1 / lookup-v1)", async () => {
		const rsa = await fx.genRsaKey();
		for (const [kid, aud] of [
			["backend-v1", "pqc-backend"],
			["lookup-v1", "pqc-cert-lookup"],
		]) {
			const t = await fx.rs256Token(
				rsa,
				`{"alg":"RS256","typ":"JWT","kid":"${kid}"}`,
				claims({ aud })
			);
			expect(await reason(() => verify(t, BOTH))).toBe("kid");
		}
	});
});

describe("JWKS", () => {
	const keysOf = (body: string, accepted = V2, p: Buffer | undefined = pin) =>
		buildAdminKeys(body, accepted, p);

	it("builds admin-v2 from the gateway's AKP entry beside RSA entries", () => {
		const rsa = crypto
			.generateKeyPairSync("rsa", { modulusLength: 2048 })
			.publicKey.export({ format: "jwk" });
		const b = keysOf(
			jwksWith([
				{
					...rsa,
					kty: "RSA",
					use: "sig",
					alg: "RS256",
					kid: "backend-v1",
				},
				{
					...rsa,
					kty: "RSA",
					use: "sig",
					alg: "RS256",
					kid: "admin-v1",
				},
				akp(key.pub),
				{
					...rsa,
					kty: "RSA",
					use: "sig",
					alg: "RS256",
					kid: "lookup-v1",
				},
			]),
			BOTH
		);
		expect(b.errors.size).toBe(0);
		expect([...b.keys.keys()].sort()).toEqual(["admin-v1", "admin-v2"]);
	});
	it.each([
		[
			"a pub of the wrong length",
			() => jwksWith([akp(key.pub.subarray(0, 1951))]),
			/1951 bytes/,
		],
		[
			"an ML-DSA-44-length pub",
			() => jwksWith([akp(Buffer.alloc(1312, 7))]),
			/1312 bytes/,
		],
		[
			"kty RSA under admin-v2",
			() => jwksWith([{ ...akp(key.pub), kty: "RSA" }]),
			/kty/,
		],
		[
			"alg RS256 under admin-v2",
			() => jwksWith([{ ...akp(key.pub), alg: "RS256" }]),
			/alg/,
		],
		[
			"alg in another case",
			() => jwksWith([{ ...akp(key.pub), alg: "ml-dsa-65" }]),
			/alg/,
		],
		[
			"a duplicate kid",
			() => jwksWith([akp(key.pub), akp(key.pub)]),
			/duplicate kid/,
		],
		[
			"a pub that does not match the pin",
			() => jwksWith([akp(Buffer.alloc(1952, 1))]),
			/pinned/,
		],
		[
			"private members",
			() => jwksWith([akp(key.pub, { priv: "AAAA" })]),
			/private/,
		],
		["use enc", () => jwksWith([akp(key.pub, { use: "enc" })]), /use/],
		[
			"a non-canonical pub",
			() => jwksWith([akp(key.pub, { pub: b64u(key.pub) + "=" })]),
			/base64url/,
		],
		["no entry", () => jwksWith([]), /no entry/],
	])("refuses %s", (_n, body, msg) => {
		const b = keysOf(body());
		expect(b.keys.has("admin-v2")).toBe(false);
		expect(b.errors.get("admin-v2")).toMatch(msg);
	});
	it("refuses admin-v2 when no pin is configured", () => {
		expect(
			buildAdminKeys(jwks, V2, undefined).errors.get("admin-v2")
		).toMatch(/ADMIN_V2_PUB_SHA256/);
		expect(parsePubPin("xyz")).toBeUndefined();
		expect(
			parsePubPin(pin.toString("hex").toUpperCase())?.equals(pin)
		).toBe(true);
	});
	it("refuses an oversized body and a body with duplicate members", () => {
		const big = jwksWith([
			akp(key.pub),
			{ pad: "x".repeat(MAX_JWKS_BYTES) },
		]);
		expect(() => keysOf(big)).toThrow(AdminJwtError);
		expect(() => keysOf('{"keys":[],"keys":[]}')).toThrow(AdminJwtError);
		expect(() => keysOf('{"keys":{}}')).toThrow(AdminJwtError);
	});
	it("admin-v1: refuses RSA below 2048 bits and kty/alg off the table", () => {
		const small = crypto
			.generateKeyPairSync("rsa", { modulusLength: 1024 })
			.publicKey.export({ format: "jwk" });
		const b = keysOf(
			jwksWith([{ ...small, kty: "RSA", alg: "RS256", kid: "admin-v1" }]),
			new Set<AdminKid>(["admin-v1"])
		);
		expect(b.errors.get("admin-v1")).toMatch(/2048/);
		const b2 = keysOf(
			jwksWith([akp(key.pub, { kid: "admin-v1" })]),
			new Set<AdminKid>(["admin-v1"])
		);
		expect(b2.errors.get("admin-v1")).toMatch(/kty/);
	});
});
