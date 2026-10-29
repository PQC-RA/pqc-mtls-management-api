/**
 * A strict JSON (RFC 8259) parser for security decisions.
 *
 * JSON.parse keeps the LAST of two members with the same name, so
 * `{"kid":"admin-v2","kid":"admin-v1"}` is read differently by two parsers that
 * resolve duplicates differently. RFC 7515 section 5.2 and RFC 8725 section 3.6
 * say a JWS with duplicate header members must be rejected; this parser does
 * that for the JWT header, the claims and the JWKS (ADR-022 decision 2).
 *
 * Objects are created without a prototype, so a member named `__proto__` or
 * `constructor` is plain data. Depth and size are capped. Anything that is not
 * exactly one JSON value (leading/trailing garbage, NaN, comments, single
 * quotes, unescaped control characters, bad escapes) throws. Lone surrogates
 * from \u escapes are kept as data; the callers compare strings exactly.
 */

export class StrictJsonError extends Error {}

export type JsonValue =
	| null
	| boolean
	| number
	| string
	| JsonValue[]
	| { [key: string]: JsonValue };

const MAX_DEPTH = 16;

export function parseStrictJson(text: string): JsonValue {
	let i = 0;
	const n = text.length;

	const fail = (msg: string): never => {
		throw new StrictJsonError(`${msg} at offset ${i}`);
	};
	const ws = () => {
		while (i < n) {
			const c = text.charCodeAt(i);
			if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
			else break;
		}
	};

	const parseString = (): string => {
		if (text[i] !== '"') fail("expected string");
		i++;
		let out = "";
		for (;;) {
			if (i >= n) fail("unterminated string");
			const c = text.charCodeAt(i);
			if (c === 0x22) {
				i++;
				return out;
			}
			if (c < 0x20) fail("control character in string");
			if (c === 0x5c) {
				i++;
				const e = text[i];
				i++;
				switch (e) {
					case '"':
						out += '"';
						break;
					case "\\":
						out += "\\";
						break;
					case "/":
						out += "/";
						break;
					case "b":
						out += "\b";
						break;
					case "f":
						out += "\f";
						break;
					case "n":
						out += "\n";
						break;
					case "r":
						out += "\r";
						break;
					case "t":
						out += "\t";
						break;
					case "u": {
						const hex = text.slice(i, i + 4);
						if (!/^[0-9a-fA-F]{4}$/.test(hex))
							fail("bad \\u escape");
						i += 4;
						out += String.fromCharCode(parseInt(hex, 16));
						break;
					}
					default:
						fail("bad escape");
				}
				continue;
			}
			out += text[i];
			i++;
		}
	};

	const parseNumber = (): number => {
		const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(
			text.slice(i, i + 64)
		);
		if (!m) fail("bad number");
		i += m![0].length;
		const v = Number(m![0]);
		if (!Number.isFinite(v)) fail("number out of range");
		return v;
	};

	const parseValue = (depth: number): JsonValue => {
		if (depth > MAX_DEPTH) fail("nesting too deep");
		ws();
		const c = text[i];
		if (c === "{") {
			i++;
			const obj = Object.create(null) as { [key: string]: JsonValue };
			ws();
			if (text[i] === "}") {
				i++;
				return obj;
			}
			for (;;) {
				ws();
				const key = parseString();
				if (Object.prototype.hasOwnProperty.call(obj, key)) {
					fail(`duplicate member "${key.slice(0, 32)}"`);
				}
				ws();
				if (text[i] !== ":") fail("expected ':'");
				i++;
				obj[key] = parseValue(depth + 1);
				ws();
				if (text[i] === ",") {
					i++;
					continue;
				}
				if (text[i] === "}") {
					i++;
					return obj;
				}
				fail("expected ',' or '}'");
			}
		}
		if (c === "[") {
			i++;
			const arr: JsonValue[] = [];
			ws();
			if (text[i] === "]") {
				i++;
				return arr;
			}
			for (;;) {
				arr.push(parseValue(depth + 1));
				ws();
				if (text[i] === ",") {
					i++;
					continue;
				}
				if (text[i] === "]") {
					i++;
					return arr;
				}
				fail("expected ',' or ']'");
			}
		}
		if (c === '"') return parseString();
		if (text.startsWith("true", i)) {
			i += 4;
			return true;
		}
		if (text.startsWith("false", i)) {
			i += 5;
			return false;
		}
		if (text.startsWith("null", i)) {
			i += 4;
			return null;
		}
		if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) {
			return parseNumber();
		}
		return fail("unexpected token");
	};

	const v = parseValue(0);
	ws();
	if (i !== n) fail("trailing data");
	return v;
}

export function isJsonObject(v: JsonValue): v is { [key: string]: JsonValue } {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}
