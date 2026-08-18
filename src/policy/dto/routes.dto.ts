import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { Type } from "class-transformer";
import {
	IsArray,
	IsBoolean,
	IsInt,
	IsObject,
	IsOptional,
	IsPositive,
	IsString,
	IsUrl,
	ValidateNested,
} from "class-validator";

export class ClientRouteDto {
	@ApiProperty({
		description: "URI prefix matched against the incoming request path",
		example: "/api/v1/status",
	})
	@IsString()
	path: string;

	@ApiProperty({
		description: "Upstream backend URL for this route",
		example: "http://shadow-mock:80",
	})
	@IsUrl({ require_tld: false })
	backend: string;

	@ApiPropertyOptional({
		description:
			"Narrow, per-route opt-in that forwards the client's raw certificate " +
			"to this specific backend via X-Client-Cert (policy_router.lua), for " +
			"backends that can't do fingerprint-based lookup. Overrides the " +
			"client-level setting for this route. Security-sensitive – logged " +
			"(WARN) whenever it fires. Default false.",
		default: false,
	})
	@IsOptional()
	@IsBoolean()
	sendRawCert?: boolean;
}

export class RateLimitDto {
	@ApiProperty({ description: "Requests per second limit", example: 100 })
	@IsInt()
	@IsPositive()
	rps: number;

	@ApiProperty({ description: "Burst allowance", example: 200 })
	@IsInt()
	@IsPositive()
	burst: number;
}

export class OrgPolicyDto {
	@ApiPropertyOptional({
		description:
			"Default upstream backend URL for member clients that don't set their own",
		example: "http://127.0.0.1:8081",
	})
	@IsOptional()
	@IsUrl({ require_tld: false })
	backend?: string;

	@ApiPropertyOptional({
		description:
			"Default rate limits for member clients that don't set their own",
	})
	@IsOptional()
	@ValidateNested()
	@Type(() => RateLimitDto)
	rate_limit?: RateLimitDto;

	@ApiPropertyOptional({
		description:
			"Default list of allowed URI prefixes for member clients that don't set their own",
		example: ["/api/", "/data/"],
	})
	@IsOptional()
	@IsArray()
	@IsString({ each: true })
	allowed_paths?: string[];

	@ApiPropertyOptional({
		description: "Human-readable description of the organization",
	})
	@IsOptional()
	@IsString()
	description?: string;
}

export class ClientPolicyDto {
	@ApiPropertyOptional({
		description:
			"Organization ID this client belongs to. Must reference an existing " +
			"organization (see /admin/policy/orgs/:orgId). For any of " +
			"backend/rate_limit/allowed_paths/description the client does not set " +
			"itself, the organization's default is used instead.",
		example: "org-acme",
	})
	@IsOptional()
	@IsString()
	org?: string;

	@ApiPropertyOptional({
		description: "Upstream backend URL",
		example: "http://127.0.0.1:8081",
	})
	@IsOptional()
	@IsUrl({ require_tld: false })
	backend?: string;

	@ApiPropertyOptional({
		description: "Per-path upstream routes for the client",
		type: [ClientRouteDto],
		example: [
			{
				path: "/api/v1/status",
				backend: "http://shadow-mock:80",
			},
			{
				path: "/api/admin/health",
				backend: "http://management-api:3000",
			},
		],
	})
	@IsOptional()
	@IsArray()
	@ValidateNested({ each: true })
	@Type(() => ClientRouteDto)
	routes?: ClientRouteDto[];

	@ApiPropertyOptional({ description: "Per-client rate limits" })
	@IsOptional()
	@ValidateNested()
	@Type(() => RateLimitDto)
	rate_limit?: RateLimitDto;

	@ApiPropertyOptional({
		description: "List of allowed URI prefixes",
		example: ["/api/", "/data/"],
	})
	@IsOptional()
	@IsArray()
	@IsString({ each: true })
	allowed_paths?: string[];

	@ApiPropertyOptional({ description: "Human-readable description" })
	@IsOptional()
	@IsString()
	description?: string;

	@ApiPropertyOptional({
		description:
			"Narrow, client-level opt-in that forwards this client's raw " +
			"certificate to its backend via X-Client-Cert (policy_router.lua), " +
			"for backends that can't do fingerprint-based lookup. A matching " +
			"route's own sendRawCert overrides this for that route. " +
			"Security-sensitive – logged (WARN) whenever it fires. Default false.",
		default: false,
	})
	@IsOptional()
	@IsBoolean()
	sendRawCert?: boolean;
}

export class PolicyDefaultsDto {
	@ApiProperty({ description: "Global default rate limits" })
	rate_limit: RateLimitDto;

	@ApiProperty({
		description: "Action to take when denied",
		example: "reject",
	})
	deny_action: string;
}

export class GlobalPolicyDto {
	@ApiProperty({ description: "Action for unknown CNs", example: "reject" })
	unknown_cn_action: string;

	@ApiProperty({ description: "Action for expired certs", example: "reject" })
	expired_cert_action: string;

	@ApiProperty({ description: "Days before expiry to warn", example: 30 })
	expiry_warning_days: number;

	@ApiProperty({
		description: "Days before expiry to mark critical",
		example: 7,
	})
	expiry_critical_days: number;

	@ApiProperty({
		description: "Whether to require valid SSL verification",
		example: true,
	})
	require_valid_verify: boolean;
}

export class RoutesFileDto {
	@ApiPropertyOptional({ description: "Metadata about the policy file" })
	@IsOptional()
	@IsObject()
	_meta?: Record<string, string>;

	@ApiProperty({
		description:
			"Map of allowed clients by their Certificate Common Name (CN)",
		type: "object",
		additionalProperties: { $ref: "#/components/schemas/ClientPolicyDto" },
	})
	@IsObject()
	clients: Record<string, ClientPolicyDto>;

	@ApiProperty({ description: "Default fallback values" })
	@IsObject()
	defaults: PolicyDefaultsDto;

	@ApiProperty({ description: "Global gateway policy settings" })
	@IsObject()
	policy: GlobalPolicyDto;
}

export class UpdateRoutesResponseDto {
	@ApiProperty({
		description: "Confirmation message",
		example: "Routes updated and Nginx reloaded successfully",
	})
	message: string;
}

export class UpdateClientPolicyResponseDto {
	@ApiProperty({
		description: "Confirmation message",
		example: "Client policy updated and Nginx reloaded successfully",
	})
	message: string;
}

/** Response of `PUT /admin/policy/routes/:cn` – the CN plus its stored policy. */
export class UpdateClientPolicyResultDto {
	@ApiProperty({
		description: "The CN that was created or updated.",
		example: "client-112653",
	})
	cn: string;

	@ApiProperty({
		description: "The stored policy for the CN after the update.",
		type: ClientPolicyDto,
	})
	policy: ClientPolicyDto;
}

export class PolicyDiffDto {
	@ApiProperty({
		description:
			"Client CNs present in the new document but not the active one",
		type: [String],
		example: ["client-new"],
	})
	addedClients: string[];

	@ApiProperty({
		description:
			"Client CNs present in the active document but not the new one",
		type: [String],
		example: ["client-gone"],
	})
	removedClients: string[];

	@ApiProperty({
		description: "Client CNs present in both but whose policy differs",
		type: [String],
		example: ["client-112653"],
	})
	changedClients: string[];

	@ApiProperty({
		description:
			"Dotted paths of global fields (defaults.*, policy.*) that differ",
		type: [String],
		example: ["policy.unknown_cn_action", "defaults.deny_action"],
	})
	changedGlobalFields: string[];
}

export class UpdateOrgPolicyResponseDto {
	@ApiProperty({
		description: "Confirmation message",
		example: "Organization policy updated and pushed to the gateway",
	})
	message: string;
}

/** Response of `PUT /admin/policy/orgs/:orgId` – the org ID plus its stored policy. */
export class UpdateOrgPolicyResultDto {
	@ApiProperty({
		description: "The organization ID that was created or updated.",
		example: "org-acme",
	})
	orgId: string;

	@ApiProperty({
		description: "The stored policy for the organization after the update.",
		type: OrgPolicyDto,
	})
	policy: OrgPolicyDto;
}

export class PolicyDryRunResultDto {
	@ApiProperty({
		description: "Whether the submitted document is valid",
		example: true,
	})
	valid: boolean;

	@ApiProperty({
		description: "Validation error messages (empty when valid)",
		type: [String],
		example: [],
	})
	errors: string[];

	@ApiProperty({
		description:
			"Diff of the submitted document vs the active configuration",
		type: PolicyDiffDto,
	})
	diff: PolicyDiffDto;
}
