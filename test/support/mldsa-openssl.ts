/**
 * ML-DSA-65 test fixtures made with the OpenSSL CLI (ADR-022 decision 6).
 *
 * Node 22 verifies ML-DSA but cannot generate or sign it ("provider signature
 * not supported"), so every admin-v2 token, mutated signature, context-string
 * and HashML-DSA signature in the suites is produced here by an OpenSSL 3.5+
 * binary through execFile. No key material leaves the per-run temp directory,
 * which is removed by cleanup().
 *
 * The binary: $PQC_TEST_OPENSSL, $OPENSSL_BIN, /opt/openssl/bin/openssl or
 * /opt/openssl-* /bin/openssl, the first that is 3.5 or later. No such binary
 * is a test FAILURE, never a skip: an ML-DSA suite that silently skips would
 * pass CI while testing nothing (checks.yml provides one).
 */
import { ChildProcess, execFile, execFileSync, spawn } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as net from "net";
import * as os from "os";
import * as path from "path";
import { promisify } from "util";

const execFileP = promisify(execFile);

export const MLDSA65_SPKI_PREFIX = Buffer.from(
	"308207b2300b0609608648016503040312038207a100",
	"hex"
);

export interface PqOpenssl {
	bin: string;
	env: NodeJS.ProcessEnv;
}

let cached: PqOpenssl | undefined;

export function findPqOpenssl(): PqOpenssl {
	if (cached) return cached;
	const candidates: string[] = [];
	for (const v of [process.env.PQC_TEST_OPENSSL, process.env.OPENSSL_BIN]) {
		if (v) candidates.push(v);
	}
	candidates.push("/opt/openssl/bin/openssl");
	try {
		for (const d of fs.readdirSync("/opt").sort().reverse()) {
			if (d.startsWith("openssl-"))
				candidates.push(`/opt/${d}/bin/openssl`);
		}
	} catch {
		/* no /opt */
	}
	for (const bin of candidates) {
		if (!fs.existsSync(bin)) continue;
		const root = path.dirname(path.dirname(bin));
		const env = {
			PATH: process.env.PATH ?? "/usr/bin:/bin",
			LD_LIBRARY_PATH: `${root}/lib64:${root}/lib`,
			OPENSSL_CONF: "/dev/null",
		};
		try {
			const v = execFileSync(bin, ["version"], { env }).toString();
			const m = /OpenSSL (\d+)\.(\d+)/.exec(v);
			if (
				m &&
				(Number(m[1]) > 3 || (Number(m[1]) === 3 && Number(m[2]) >= 5))
			) {
				cached = { bin, env };
				return cached;
			}
		} catch {
			/* try the next one */
		}
	}
	throw new Error(
		"No OpenSSL 3.5+ CLI found for the ML-DSA-65 fixtures. Set PQC_TEST_OPENSSL " +
			"to one (e.g. /opt/openssl-3.6.5/bin/openssl). This is a failure, not a skip."
	);
}

export async function openssl(args: string[]): Promise<Buffer> {
	const o = findPqOpenssl();
	const { stdout } = await execFileP(o.bin, args, {
		env: o.env,
		encoding: "buffer",
		maxBuffer: 16 * 1024 * 1024,
	});
	return stdout as unknown as Buffer;
}

export const b64u = (b: Buffer | string): string =>
	(typeof b === "string" ? Buffer.from(b, "utf8") : b).toString("base64url");

export class MldsaFixtures {
	readonly dir: string;
	private n = 0;

	constructor() {
		this.dir = fs.mkdtempSync(path.join(os.tmpdir(), "adr022-"));
		fs.chmodSync(this.dir, 0o700);
	}

	cleanup(): void {
		fs.rmSync(this.dir, { recursive: true, force: true });
	}

	private file(name: string): string {
		return path.join(this.dir, `${++this.n}-${name}`);
	}

	/** A fresh ML-DSA-65 key (or one from a 32-byte hex seed, e.g. RFC 9964 A.1's). */
	async genKey(
		alg = "ML-DSA-65",
		hexSeed?: string
	): Promise<{
		keyPath: string;
		spki: Buffer;
		pub: Buffer;
	}> {
		const keyPath = this.file("key.pem");
		const args = ["genpkey", "-algorithm", alg, "-out", keyPath];
		if (hexSeed) args.push("-pkeyopt", `hexseed:${hexSeed}`);
		await openssl(args);
		const spki = await openssl([
			"pkey",
			"-in",
			keyPath,
			"-pubout",
			"-outform",
			"DER",
		]);
		const prefixLen = alg === "ML-DSA-65" ? MLDSA65_SPKI_PREFIX.length : 22;
		return { keyPath, spki, pub: spki.subarray(prefixLen) };
	}

	async genRsaKey(): Promise<string> {
		const keyPath = this.file("rsa.pem");
		await openssl([
			"genpkey",
			"-algorithm",
			"RSA",
			"-pkeyopt",
			"rsa_keygen_bits:2048",
			"-out",
			keyPath,
		]);
		return keyPath;
	}

	/**
	 * ML-DSA signature over `data` by the OpenSSL CLI. Default: pure ML-DSA,
	 * empty context (what RFC 9964 and jwt_mldsa.lua use). `context` sets a
	 * context string; `rawMessage` signs `data` as the internal message M'
	 * (message-encoding:0), which is how a HashML-DSA signature is built here.
	 */
	async sign(
		keyPath: string,
		data: Buffer | string,
		opts: {
			context?: string;
			rawMessage?: boolean;
			deterministic?: boolean;
		} = {}
	): Promise<Buffer> {
		const inPath = this.file("tbs");
		const outPath = this.file("sig");
		fs.writeFileSync(inPath, data);
		const args = [
			"pkeyutl",
			"-sign",
			"-rawin",
			"-inkey",
			keyPath,
			"-in",
			inPath,
			"-out",
			outPath,
		];
		if (opts.context !== undefined)
			args.push("-pkeyopt", `context-string:${opts.context}`);
		if (opts.rawMessage) args.push("-pkeyopt", "message-encoding:0");
		if (opts.deterministic) args.push("-pkeyopt", "deterministic:1");
		await openssl(args);
		return fs.readFileSync(outPath);
	}

	/**
	 * HashML-DSA-65 with SHA-256 and an empty context (FIPS 204 algorithm 4):
	 * M' = 0x01 || 0x00 || DER(OID sha256) || SHA-256(M), signed with the
	 * internal ML-DSA.Sign. RFC 9964 does not specify HashML-DSA for JOSE.
	 */
	async signHashMlDsa(
		keyPath: string,
		data: Buffer | string
	): Promise<Buffer> {
		const oid = Buffer.from("0609608648016503040201", "hex");
		const ph = crypto.createHash("sha256").update(data).digest();
		const mPrime = Buffer.concat([Buffer.from([0x01, 0x00]), oid, ph]);
		return this.sign(keyPath, mPrime, { rawMessage: true });
	}

	/** header.payload.signature with the header exactly as given (JSON text). */
	async token(
		keyPath: string,
		headerJson: string,
		payloadJson: string,
		opts: Parameters<MldsaFixtures["sign"]>[2] = {}
	): Promise<string> {
		const input = `${b64u(headerJson)}.${b64u(payloadJson)}`;
		const sig = await this.sign(keyPath, input, opts);
		return `${input}.${b64u(sig)}`;
	}

	/** token() without a promise, for per-request tokens inside supertest chains. */
	tokenSync(
		keyPath: string,
		headerJson: string,
		payloadJson: string
	): string {
		const o = findPqOpenssl();
		const input = `${b64u(headerJson)}.${b64u(payloadJson)}`;
		const inPath = this.file("tbs");
		const outPath = this.file("sig");
		fs.writeFileSync(inPath, input);
		execFileSync(
			o.bin,
			[
				"pkeyutl",
				"-sign",
				"-rawin",
				"-inkey",
				keyPath,
				"-in",
				inPath,
				"-out",
				outPath,
			],
			{ env: o.env }
		);
		return `${input}.${b64u(fs.readFileSync(outPath))}`;
	}

	/** RS256 token by the OpenSSL CLI (sha256 + PKCS#1 v1.5). */
	async rs256Token(
		keyPath: string,
		headerJson: string,
		payloadJson: string
	): Promise<string> {
		const input = `${b64u(headerJson)}.${b64u(payloadJson)}`;
		const inPath = this.file("tbs");
		fs.writeFileSync(inPath, input);
		const sig = await openssl([
			"dgst",
			"-sha256",
			"-sign",
			keyPath,
			inPath,
		]);
		return `${input}.${b64u(sig)}`;
	}

	/** Self-signed CA, and a leaf signed by it, for the :8081 TLS cases. */
	async ca(alg: string, cn: string): Promise<{ key: string; crt: string }> {
		const key = this.file("ca.key");
		const crt = this.file("ca.crt");
		const cnf = this.file("ca.cnf");
		fs.writeFileSync(
			cnf,
			"[req]\ndistinguished_name=dn\nprompt=no\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
		);
		await openssl(
			alg === "RSA"
				? [
						"genpkey",
						"-algorithm",
						"RSA",
						"-pkeyopt",
						"rsa_keygen_bits:2048",
						"-out",
						key,
					]
				: ["genpkey", "-algorithm", alg, "-out", key]
		);
		await openssl([
			"req",
			"-config",
			cnf,
			"-new",
			"-x509",
			"-days",
			"2",
			"-extensions",
			"v3_ca",
			"-key",
			key,
			"-subj",
			`/CN=${cn}`,
			"-out",
			crt,
		]);
		return { key, crt };
	}

	async leaf(
		alg: string,
		ca: { key: string; crt: string },
		san = "DNS:gateway"
	): Promise<{ key: string; crt: string }> {
		const key = this.file("leaf.key");
		const csr = this.file("leaf.csr");
		const crt = this.file("leaf.crt");
		const cnf = this.file("leaf.cnf");
		fs.writeFileSync(
			cnf,
			`[req]\ndistinguished_name=dn\nprompt=no\n[dn]\n[v3]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=${san}\n`
		);
		await openssl(
			alg === "RSA"
				? [
						"genpkey",
						"-algorithm",
						"RSA",
						"-pkeyopt",
						"rsa_keygen_bits:2048",
						"-out",
						key,
					]
				: ["genpkey", "-algorithm", alg, "-out", key]
		);
		await openssl([
			"req",
			"-config",
			cnf,
			"-new",
			"-key",
			key,
			"-subj",
			"/CN=gateway",
			"-out",
			csr,
		]);
		await openssl([
			"x509",
			"-req",
			"-days",
			"2",
			"-in",
			csr,
			"-CA",
			ca.crt,
			"-CAkey",
			ca.key,
			"-set_serial",
			"0x" + crypto.randomBytes(8).toString("hex"),
			"-extfile",
			cnf,
			"-extensions",
			"v3",
			"-out",
			crt,
		]);
		return { key, crt };
	}

	/**
	 * openssl s_server -WWW on a loopback port, TLS 1.3 and X25519MLKEM768 only
	 * (the :8081 settings), serving files from `docroot`.
	 */
	async sServer(
		cert: { key: string; crt: string },
		docroot: string
	): Promise<{ port: number; stop: () => void }> {
		const port = await freePort();
		const o = findPqOpenssl();
		const child: ChildProcess = spawn(
			o.bin,
			[
				"s_server",
				"-accept",
				`127.0.0.1:${port}`,
				"-cert",
				cert.crt,
				"-key",
				cert.key,
				"-tls1_3",
				"-groups",
				"X25519MLKEM768",
				"-WWW",
				"-quiet",
			],
			{ env: o.env, cwd: docroot, stdio: ["ignore", "ignore", "pipe"] }
		);
		const stop = () => child.kill("SIGKILL");
		for (let i = 0; i < 100; i++) {
			if (await canConnect(port)) return { port, stop };
			await new Promise(r => setTimeout(r, 50));
		}
		stop();
		throw new Error("s_server did not start");
	}
}

function freePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const s = net.createServer();
		s.listen(0, "127.0.0.1", () => {
			const p = (s.address() as net.AddressInfo).port;
			s.close(() => resolve(p));
		});
		s.on("error", reject);
	});
}

function canConnect(port: number): Promise<boolean> {
	return new Promise(resolve => {
		const c = net.connect(port, "127.0.0.1");
		c.on("connect", () => {
			c.destroy();
			resolve(true);
		});
		c.on("error", () => resolve(false));
	});
}
