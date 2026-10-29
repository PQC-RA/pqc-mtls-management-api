/**
 * ADR-022 decision 6: LookupTokenGuard (Token 2, jwks-rsa 4.x) must keep
 * working once the shared JWKS also carries the ML-DSA-65 AKP entry admin-v2.
 * If jwks-rsa failed on the unknown key type, every cert lookup would fail.
 *
 * jest cannot load the real jwks-rsa (its jose dependency is ESM), so the
 * real guard runs in a child Node process (test/support/lookup-guard-akp.ts).
 */
import { execFile } from "child_process";
import * as path from "path";
import { promisify } from "util";

jest.setTimeout(120_000);

it("LookupTokenGuard verifies a lookup-v1 token with an AKP entry in the JWKS (real jwks-rsa)", async () => {
	const root = path.resolve(__dirname, "../../..");
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
			},
		}
	);
	expect(stdout).toMatch(/RESULT lookup=OK/);
});
