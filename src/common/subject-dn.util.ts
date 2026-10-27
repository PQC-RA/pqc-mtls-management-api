/**
 * Strict reading of a certificate or CSR subject printed by OpenSSL with
 * `-nameopt RFC2253`.
 *
 * Why strict: the components of this system read the CN differently. OpenSSL's
 * default print is in forward order, RFC 2253 (the custodian, the gateway's
 * $ssl_client_s_dn) in reverse order, so a subject with two CN attributes
 * ("/CN=allowed/CN=victim") is "allowed" to one and "victim" to the others. A
 * token bound to one CN could then yield a certificate the gateway routes as
 * another. So a subject is accepted only with exactly one CN and no
 * multi-valued RDN, and every component agrees on it.
 */

export class SubjectDnError extends Error {}

/** Split on separators that are not escaped with a backslash. */
function splitUnescaped(s: string, sep: string): string[] {
	const out: string[] = [];
	let cur = "";
	for (let i = 0; i < s.length; i++) {
		const c = s[i];
		if (c === "\\" && i + 1 < s.length) {
			cur += c + s[i + 1];
			i++;
			continue;
		}
		if (c === sep) {
			out.push(cur);
			cur = "";
			continue;
		}
		cur += c;
	}
	out.push(cur);
	return out;
}

/** Undo RFC 2253 escaping: "\," "\+" "\\" ... and "\XX" hex pairs. */
function unescapeValue(v: string): string {
	const bytes: number[] = [];
	for (let i = 0; i < v.length; i++) {
		const c = v[i];
		if (c === "\\" && i + 1 < v.length) {
			const hex = v.slice(i + 1, i + 3);
			if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
				bytes.push(parseInt(hex, 16));
				i += 2;
				continue;
			}
			bytes.push(...Buffer.from(v[i + 1], "utf8"));
			i++;
			continue;
		}
		bytes.push(...Buffer.from(c, "utf8"));
	}
	return Buffer.from(bytes).toString("utf8");
}

/**
 * The one CN of an RFC 2253 subject ("CN=svc,O=ACME,C=BG", with or without a
 * leading "subject="). Throws SubjectDnError unless the subject has exactly one
 * CN attribute and every RDN has exactly one attribute.
 */
export function singleCommonName(rfc2253: string): string {
	const s = rfc2253.replace(/^\s*subject\s*=\s*/i, "").trim();
	if (!s) throw new SubjectDnError("empty subject");
	const cns: string[] = [];
	for (const rdn of splitUnescaped(s, ",")) {
		const attrs = splitUnescaped(rdn, "+");
		if (attrs.length !== 1) {
			throw new SubjectDnError("multi-valued RDN in subject");
		}
		const eq = attrs[0].indexOf("=");
		if (eq < 1) throw new SubjectDnError("malformed RDN in subject");
		const type = attrs[0].slice(0, eq).trim();
		if (type.toUpperCase() === "CN" || type === "2.5.4.3") {
			cns.push(unescapeValue(attrs[0].slice(eq + 1).trim()));
		}
	}
	if (cns.length !== 1) {
		throw new SubjectDnError(
			cns.length === 0
				? "subject has no CN"
				: "subject has more than one CN"
		);
	}
	if (!cns[0]) throw new SubjectDnError("empty CN");
	return cns[0];
}
