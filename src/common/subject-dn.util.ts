/**
 * Strict reading of a certificate or CSR subject printed by OpenSSL with
 * `-nameopt RFC2253`.
 *
 * Why strict: the components of this system read the CN differently. OpenSSL's
 * default print is in forward order, RFC 2253 (the custodian, the gateway's
 * $ssl_client_s_dn) in reverse order, and the custodian and the gateway find the
 * CN with a regular expression over the printed DN. So a subject is accepted
 * only if every reader must agree on its CN:
 *   - exactly one CN attribute, and one attribute per RDN;
 *   - the CN within [A-Za-z0-9._-]{1,64};
 *   - no attribute value containing "CN=" (any case) or "/", which a regular
 *     expression could take for a CN ("emailAddress=xCN=victim").
 */

export class SubjectDnError extends Error {}

/** The CN alphabet. Every CN issued so far fits it. */
export const CN_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

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

/**
 * The one CN of an RFC 2253 subject ("CN=svc,O=ACME,C=BG", with or without a
 * leading "subject="). Throws SubjectDnError otherwise.
 */
export function singleCommonName(rfc2253: string): string {
	const s = rfc2253
		.replace(/^\s*subject\s*=\s*/i, "")
		.replace(/[\r\n]+$/, "");
	if (!s.trim()) throw new SubjectDnError("empty subject");
	// Exactly one "CN=" anywhere in the subject: a regular expression reading the
	// DN must find only the CN attribute (an attribute type such as ISO-CN, OID
	// 1.2.156, prints as "ISO-CN=victim").
	if ((s.match(/cn\s*=/gi) ?? []).length > 1) {
		throw new SubjectDnError('"CN=" occurs more than once in the subject');
	}
	const cns: string[] = [];
	for (const rdn of splitUnescaped(s, ",")) {
		const attrs = splitUnescaped(rdn, "+");
		if (attrs.length !== 1) {
			throw new SubjectDnError("multi-valued RDN in subject");
		}
		const eq = attrs[0].indexOf("=");
		if (eq < 1) throw new SubjectDnError("malformed RDN in subject");
		const type = attrs[0].slice(0, eq);
		const value = attrs[0].slice(eq + 1);
		if (/cn\s*=/i.test(value) || value.includes("/")) {
			throw new SubjectDnError(
				'an attribute value contains "CN=" or "/"'
			);
		}
		if (type.toUpperCase() === "CN") cns.push(value);
	}
	if (cns.length !== 1) {
		throw new SubjectDnError(
			cns.length === 0
				? "subject has no CN"
				: "subject has more than one CN"
		);
	}
	if (!cns[0]) throw new SubjectDnError("empty CN");
	// The pattern has no escapable character, so the printed value is the CN.
	if (!CN_PATTERN.test(cns[0])) {
		throw new SubjectDnError("CN outside [A-Za-z0-9._-]{1,64}");
	}
	return cns[0];
}
