/**
 * Fail any unit test that reaches the network.
 *
 * Four suites (crl, certs, health, monitoring) were left behind by the move of
 * CA-tree access into the pqc-ca-custodian sidecar: they still mocked `fs`, which
 * the code no longer consults for those paths, so every run fell through to a
 * REAL fetch to http://pqc-ca-custodian:8091. It failed, the assertions saw the
 * wrong outcome, and 11 tests were red for a reason that looked like flakiness.
 *
 * A mocked seam that has moved is invisible: the mock simply goes unused. This
 * makes it loud instead – the next time a boundary shifts, the failure names the
 * cause on the first line rather than after an afternoon of reading diffs.
 *
 * It also removes a CI hazard: on a runner with catch-all DNS or an HTTP proxy
 * these calls do not fail cleanly, they hang or return something arbitrary.
 *
 * A test that genuinely needs fetch should mock it explicitly
 * (`global.fetch = jest.fn()`), which overwrites this and is self-documenting.
 */
const blocked = ((input: unknown) => {
	const target =
		typeof input === "string"
			? input
			: input instanceof URL
				? input.toString()
				: ((input as { url?: string })?.url ?? "unknown");

	const message =
		`Unit test attempted a real network call to ${target}.\n` +
		"Unit tests must not touch the network. Mock the boundary instead:\n" +
		'  jest.mock("@/common/ca-custodian.util");   // for CA-tree access\n' +
		"  global.fetch = jest.fn();                  // if fetch itself is the subject\n" +
		"If a mock looks correct but this still fires, the code has probably stopped\n" +
		"using the seam you mocked – check what it actually calls now.";

	// Log before throwing. Service code routinely wraps fetch failures in its own
	// HttpException (see custodianRequest), which would otherwise swallow this
	// message and leave only a generic "custodian unreachable" – the exact
	// ambiguity that made the original 11 failures look like flakiness.
	console.error(`\n[jest] NETWORK BLOCKED\n${message}\n`);
	throw new Error(message);
}) as unknown as typeof fetch;

global.fetch = blocked;
