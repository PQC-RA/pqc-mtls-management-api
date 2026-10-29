import {
	CanActivate,
	ExecutionContext,
	ForbiddenException,
	Injectable,
	Logger,
	UnauthorizedException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Request } from "express";

import {
	AdminKeyStore,
	makeJwksFetcher,
	parsePubPin,
} from "@/common/auth/admin-jwks.store";
import {
	AdminJwtError,
	AdminKid,
	checkAdminClaims,
	isAdminKid,
	JtiCache,
	parseAdminToken,
	verifyAdminSignature,
} from "@/common/auth/admin-jwt.verifier";
import {
	AdminIdentity,
	buildCertRoleMap,
	CertRoleMap,
	normalizeFingerprint,
} from "@/common/auth/cert-roles";
import { IS_PUBLIC_KEY } from "@/common/decorators/public.decorator";

/**
 * JwtAuthGuard – verifies the admin JWT the PQC OpenResty gateway mints for
 * /admin/ and authorizes the caller against an explicit admin allowlist.
 *
 * The gateway mints a short-lived JWT from the verified mTLS client
 * certificate.  This guard:
 *   1. Verifies the token with the narrow verifier of ADR-022
 *      (common/auth/admin-jwt.verifier.ts): kid -> algorithm from a fixed
 *      table (admin-v1 = RS256, admin-v2 = ML-DSA-65), key from the gateway
 *      JWKS with the admin-v2 key pinned by SHA-256, exact header, claims,
 *      jti single use, htm/htu bound to this request.
 *   2. AUTHORIZES by certificate FINGERPRINT against an explicit allowlist.
 *
 * Why fingerprint and not the `role`/OU claim:
 *   The cert subject (CN, OU) is chosen by the certificate requester in their
 *   CSR.  Deriving authorization from a requester-influenced field lets anyone
 *   who can obtain a CA-signed cert request `OU=admin`.  The certificate SHA-256
 *   fingerprint, by contrast, is bound to the exact issued cert and cannot be
 *   forged without the CA re-issuing that precise certificate.  Authorization
 *   is therefore a separate, operator-controlled allowlist – decoupled from any
 *   attacker-influenceable subject field.
 *
 * Configuration (read when the guard is constructed):
 *   JWT_EXPECTED_KID      admin kids accepted, comma-separated, from the table
 *                         (default "admin-v1"; the ADR-022 dual window is
 *                         "admin-v1,admin-v2", the end state "admin-v2").
 *   ADMIN_V2_PUB_SHA256   SHA-256 (hex) of the admin-v2 raw public key; without
 *                         it admin-v2 tokens are refused (fail closed).
 *   GATEWAY_TLS_LEAF_ALG  "ML-DSA-65": the JWKS is fetched only from a :8081
 *                         presenting an ML-DSA-65 certificate (unset: any leaf
 *                         that chains to NODE_EXTRA_CA_CERTS, for the cut-over).
 *                         LookupTokenGuard and the route push apply the same
 *                         check (common/auth/gateway-tls.ts).
 *   JWT_EXPECTED_ISSUER / JWT_EXPECTED_AUDIENCE, GATEWAY_JWKS_URI.
 *
 * Security posture:
 *   - The token "alg" header is never trusted: the kid selects it, the header
 *     must agree, and the key object must be of that type.
 *   - issuer and audience are pinned exact strings.
 *   - Authorization fails CLOSED: if no allowlist is configured, every request
 *     is denied (a misconfigured deployment is locked, not wide open).
 */

const DEFAULT_JWKS_URI = "http://gateway:8081/.well-known/jwks.json";

@Injectable()
export class JwtAuthGuard implements CanActivate {
	private readonly logger = new Logger(JwtAuthGuard.name);
	private readonly roleMap: CertRoleMap;
	private readonly acceptedKids: ReadonlySet<AdminKid>;
	private readonly keyStore: AdminKeyStore;
	private readonly jtiCache = new JtiCache();
	private readonly issuer: string;
	private readonly audience: string;

	constructor(private readonly reflector: Reflector) {
		// Resolve roles from the ADMIN_/AUDITOR_ fingerprint allowlists. The
		// builder logs precise warnings for malformed (e.g. SHA-1) entries and
		// for an empty allowlist (fail-closed: deny all).
		this.roleMap = buildCertRoleMap(this.logger);

		this.issuer = process.env.JWT_EXPECTED_ISSUER ?? "pqc-gateway";
		this.audience =
			process.env.JWT_EXPECTED_AUDIENCE ?? "pqc-mtls-management-api";

		const kids = new Set<AdminKid>();
		for (const raw of (process.env.JWT_EXPECTED_KID ?? "admin-v1").split(
			","
		)) {
			const k = raw.trim();
			if (!k) continue;
			if (isAdminKid(k)) kids.add(k);
			else
				this.logger.error(
					`JWT_EXPECTED_KID: "${k}" is not an admin kid of the fixed table (admin-v1, admin-v2), ignored`
				);
		}
		const pin = parsePubPin(process.env.ADMIN_V2_PUB_SHA256);
		if (kids.has("admin-v2") && !pin) {
			this.logger.error(
				"admin-v2 is accepted but ADMIN_V2_PUB_SHA256 is missing or not 64 hex characters: every admin-v2 token will be refused"
			);
		}
		if (kids.size === 0) {
			this.logger.error(
				"No admin kid is accepted: every admin request will be refused"
			);
		}
		this.acceptedKids = kids;
		this.keyStore = new AdminKeyStore({
			jwksUri: process.env.GATEWAY_JWKS_URI ?? DEFAULT_JWKS_URI,
			acceptedKids: kids,
			v2PubSha256: pin,
			fetchJwks: makeJwksFetcher({
				leafAlg: process.env.GATEWAY_TLS_LEAF_ALG || undefined,
			}),
		});
		this.logger.log(
			`Admin token kids accepted: ${[...kids].join(",") || "none"}`
		);
	}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		// Honour @Public() opt-out (checked at handler and controller level).
		const isPublic = this.reflector.getAllAndOverride<boolean>(
			IS_PUBLIC_KEY,
			[context.getHandler(), context.getClass()]
		);
		if (isPublic) {
			return true;
		}

		const request = context.switchToHttp().getRequest<Request>();

		// 1. Extract the Bearer token.
		const authHeader = request.headers["authorization"];
		if (!authHeader || !authHeader.startsWith("Bearer ")) {
			this.logger.warn("Missing or malformed Authorization header");
			throw new UnauthorizedException(
				"Missing Authorization Bearer token"
			);
		}
		const token = authHeader.slice(7);

		// 2. Verify (ADR-022 decision 2, in its order).
		let claims: ReturnType<typeof checkAdminClaims>;
		let kid: AdminKid;
		try {
			const parsed = parseAdminToken(token, this.acceptedKids);
			kid = parsed.kid;
			const key = await this.keyStore.getKey(kid);
			if (
				!verifyAdminSignature(
					parsed.spec,
					key,
					parsed.signingInput,
					parsed.signature
				)
			) {
				throw new AdminJwtError("signature");
			}
			const nowS = Math.floor(Date.now() / 1000);
			claims = checkAdminClaims(parsed.payload, {
				now: nowS,
				issuer: this.issuer,
				audience: this.audience,
				method: request.method,
				path: requestPath(request),
				requireBinding: kid === "admin-v2",
			});
		} catch (e) {
			if (e instanceof AdminJwtError) {
				// The message can quote unauthenticated token content: printable ASCII only.
				this.logger.warn(
					`Admin token refused: ${e.reason} (${e.message.replace(/[^\x20-\x7e]/g, "?").slice(0, 200)})`
				);
				throw new UnauthorizedException(
					e.reason === "expired"
						? "Token expired"
						: "Invalid admin token"
				);
			}
			this.logger.error(
				`Admin token verification error: ${(e as Error).message}`
			);
			throw new UnauthorizedException("Invalid admin token");
		}

		// 3. AUTHORIZE by certificate fingerprint and RESOLVE the caller's role
		//    from the operator-controlled allowlists (admin / auditor).
		//    Fails closed: a fingerprint in neither list denies everyone.
		//    The role is taken from the fpr→role map, NEVER from the JWT
		//    `role`/OU claim (which is requester-influenceable, weaker evidence).
		const fpr = normalizeFingerprint(claims.fpr);
		const role = fpr ? this.roleMap.resolve(fpr) : null;
		if (!role) {
			this.logger.warn(
				`Access denied: cert fingerprint not on admin/auditor allowlist ` +
					`(sub="${claims.sub || "?"}", fpr="${fpr || "missing"}")`
			);
			throw new ForbiddenException(
				"Admin authorization denied – certificate is not on the admin allowlist"
			);
		}

		// 4. jti, last: only a token that passed everything else, including the
		//    allowlist, uses up a cache entry. Otherwise any CA-verified client
		//    (the gateway mints for every verified certificate) could fill the
		//    cache and lock the admins out.
		if (
			claims.jti !== undefined &&
			!this.jtiCache.useOnce(claims.jti, Math.floor(Date.now() / 1000))
		) {
			this.logger.warn(
				"Admin token refused: replay (jti already used, or the jti cache is full)"
			);
			throw new UnauthorizedException("Invalid admin token");
		}

		const identity: AdminIdentity = { sub: claims.sub, fpr, role };
		(
			request as Request & {
				adminIdentity: AdminIdentity;
				adminTokenKid: AdminKid;
			}
		).adminIdentity = identity;
		(request as Request & { adminTokenKid: AdminKid }).adminTokenKid = kid;
		this.logger.debug(
			`Admin token verified & authorized: kid=${kid} sub=${identity.sub} fpr=${fpr} role=${role} exp=${claims.exp}`
		);
		return true;
	}
}

/**
 * The request path as this process received it, without the query string:
 * what the gateway binds in htu ("/api/admin/..." after its proxy_pass rewrite).
 */
export function requestPath(request: Request): string {
	const raw = request.originalUrl ?? request.url ?? "";
	const q = raw.indexOf("?");
	return q === -1 ? raw : raw.slice(0, q);
}
