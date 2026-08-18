import {
	Body,
	Controller,
	Delete,
	Get,
	HttpCode,
	Param,
	Post,
	Put,
	Query,
} from "@nestjs/common";
import {
	ApiBody,
	ApiExtraModels,
	ApiOperation,
	ApiQuery,
	ApiResponse,
	getSchemaPath,
} from "@nestjs/swagger";

import { AuditAction } from "@/admin-audit/decorators/audit-action.decorator";
import { AdminController } from "@/common/decorators/admin-controller.decorator";
import {
	ApiDelete,
	ApiErrorResponses,
	ApiGet,
	ApiPut,
} from "@/common/decorators/api-responses.decorator";
import { Roles } from "@/common/decorators/roles.decorator";
import {
	ClientPolicyDto,
	OrgPolicyDto,
	PolicyDryRunResultDto,
	RoutesFileDto,
	UpdateClientPolicyResponseDto,
	UpdateClientPolicyResultDto,
	UpdateOrgPolicyResponseDto,
	UpdateOrgPolicyResultDto,
	UpdateRoutesResponseDto,
} from "@/policy/dto/routes.dto";
import { PolicyService } from "@/policy/policy.service";

/** Recognise the dry-run flag in a tolerant way (`1`, `true`, present). */
function isDryRun(value: unknown): boolean {
	if (value === undefined || value === null) return false;
	const v = String(value).toLowerCase();
	return v === "1" || v === "true" || v === "";
}

@AdminController("policy")
@Controller("admin/policy")
export class PolicyController {
	constructor(private readonly policyService: PolicyService) {}

	@Get("routes")
	@ApiGet({
		summary: "Get the active routing configuration",
		description:
			"Returns the current in-memory routing document managed by the Policy service. " +
			"Updates are pushed to the gateway control plane over HTTP, without Nginx reload.",
		type: RoutesFileDto,
		notFound: "Routing configuration not found",
	})
	async getRoutes(): Promise<RoutesFileDto> {
		return this.policyService.getRoutes();
	}

	@Post("routes")
	@Roles("admin")
	@AuditAction({
		action: "policy.update-routes",
		target: c =>
			`clients=${Object.keys((c.body as unknown as RoutesFileDto)?.clients ?? {}).length}`,
		params: c => ({
			dryRun: isDryRun(c.query.dryRun),
			clientCount: Object.keys(
				(c.body as unknown as RoutesFileDto)?.clients ?? {}
			).length,
		}),
	})
	@HttpCode(200)
	@ApiOperation({
		summary: "Update routing policy via gateway control plane",
		description:
			"Sends the full routing document to the gateway internal control plane endpoint. " +
			"No shell execution and no Nginx reload are performed.\n\n" +
			"Pass `?dryRun=1` to preview: returns `{ valid, errors, diff }` describing the " +
			"added/removed/changed CNs and global fields vs the active config, without applying.",
	})
	@ApiQuery({
		name: "dryRun",
		required: false,
		description:
			"When set (`1`/`true`), validate the document and return a diff vs the " +
			"active config WITHOUT pushing to the gateway control plane. No HMAC " +
			"push or persistence occurs.",
		example: "1",
	})
	// Two distinct 200 shapes depending on ?dryRun: the apply confirmation
	// (UpdateRoutesResponseDto) or the dry-run preview (PolicyDryRunResultDto).
	@ApiExtraModels(UpdateRoutesResponseDto, PolicyDryRunResultDto)
	@ApiResponse({
		status: 200,
		description:
			"Apply confirmation `{ message }`, or – when `?dryRun=1` – a " +
			"`{ valid, errors, diff }` preview without applying.",
		schema: {
			oneOf: [
				{ $ref: getSchemaPath(UpdateRoutesResponseDto) },
				{ $ref: getSchemaPath(PolicyDryRunResultDto) },
			],
		},
	})
	@ApiErrorResponses()
	@ApiBody({
		type: RoutesFileDto,
		description:
			"Complete routes configuration to apply. This fully replaces the existing active document.",
		examples: {
			perPathBackends: {
				summary: "Client with multiple per-path backends",
				value: {
					"client-112653": {
						org: "client-112653",
						routes: [
							{
								path: "/api/v1/status",
								backend: "http://shadow-mock:80",
							},
							{
								path: "/api/admin/health",
								backend: "http://management-api:3000",
							},
						],
					},
				},
			},
		},
	})
	async updateRoutes(
		@Body() routes: RoutesFileDto,
		@Query("dryRun") dryRun?: string
	): Promise<UpdateRoutesResponseDto | PolicyDryRunResultDto> {
		if (isDryRun(dryRun)) {
			return this.policyService.dryRunRoutes(routes);
		}
		return this.policyService.updateRoutes(routes);
	}

	@Get("routes/:cn")
	@ApiGet({
		summary: "Get the routing configuration for a specific client CN",
		description:
			"Returns the policy configuration for a specific Common Name (CN).",
		type: ClientPolicyDto,
		notFound: "Policy for the given CN not found",
	})
	async getClientPolicy(@Param("cn") cn: string): Promise<ClientPolicyDto> {
		return this.policyService.getClientPolicy(cn);
	}

	@Put("routes/:cn")
	@Roles("admin")
	@AuditAction({
		action: "policy.update-client",
		target: c => `cn=${c.params.cn}`,
	})
	@ApiPut({
		summary:
			"Create or update the routing configuration for a specific client CN",
		description:
			"Updates the policy for a single Common Name (CN) and pushes the updated full routing document " +
			"to the gateway control plane. If the CN does not exist, it will be created.",
		type: UpdateClientPolicyResultDto,
	})
	@ApiBody({ type: ClientPolicyDto })
	async updateClientPolicy(
		@Param("cn") cn: string,
		@Body() policy: ClientPolicyDto
	): Promise<UpdateClientPolicyResultDto> {
		return this.policyService.updateClientPolicy(cn, policy);
	}

	@Delete("routes/:cn")
	@Roles("admin")
	@AuditAction({
		action: "policy.delete-client",
		target: c => `cn=${c.params.cn}`,
	})
	@ApiDelete({
		summary: "Delete the routing configuration for a specific client CN",
		description:
			"Removes the policy for a single Common Name (CN) and pushes the updated full routing document " +
			"to the gateway control plane.",
		type: UpdateClientPolicyResponseDto,
		notFound: "Policy for the given CN not found",
	})
	async deleteClientPolicy(
		@Param("cn") cn: string
	): Promise<UpdateClientPolicyResponseDto> {
		return this.policyService.deleteClientPolicy(cn);
	}

	// Registered ABOVE "orgs/:orgId" – a literal path segment must be matched
	// before the ":orgId" wildcard can swallow it (verified empirically
	// against this route table, not just assumed from framework defaults).
	@Get("orgs")
	@ApiOperation({
		summary: "List all organizations and their default policies",
		description:
			"Returns every organization's defaults, keyed by org ID. Use this to populate an " +
			"org picker or a full organization-management view – GET .../orgs/:orgId alone " +
			"cannot be used to discover which orgs exist.",
	})
	@ApiExtraModels(OrgPolicyDto)
	@ApiResponse({
		status: 200,
		description: "Every organization's defaults, keyed by org ID.",
		schema: {
			type: "object",
			additionalProperties: { $ref: getSchemaPath(OrgPolicyDto) },
		},
	})
	@ApiErrorResponses()
	async listOrgs(): Promise<Record<string, OrgPolicyDto>> {
		return this.policyService.listOrgs();
	}

	@Get("orgs/:orgId")
	@ApiGet({
		summary: "Get the default policy for a specific organization",
		description:
			"Returns the org-level defaults (backend, rate_limit, allowed_paths, description) " +
			"for a specific organization ID. These defaults are merged into every member " +
			"client's effective policy for fields the client does not set itself.",
		type: OrgPolicyDto,
		notFound: "Policy for the given organization not found",
	})
	async getOrgPolicy(@Param("orgId") orgId: string): Promise<OrgPolicyDto> {
		return this.policyService.getOrgPolicy(orgId);
	}

	@Put("orgs/:orgId")
	@Roles("admin")
	@AuditAction({
		action: "policy.update-org",
		target: c => `orgId=${c.params.orgId}`,
	})
	@ApiPut({
		summary:
			"Create or update the default policy for a specific organization",
		description:
			"Updates the org-level defaults for a specific organization ID and re-pushes the " +
			"full resolved routing document to the gateway control plane, since every member " +
			"client's effective policy changes with the org's defaults. If the organization " +
			"does not exist, it will be created.",
		type: UpdateOrgPolicyResultDto,
	})
	@ApiBody({ type: OrgPolicyDto })
	async updateOrgPolicy(
		@Param("orgId") orgId: string,
		@Body() policy: OrgPolicyDto
	): Promise<UpdateOrgPolicyResultDto> {
		return this.policyService.updateOrgPolicy(orgId, policy);
	}

	@Delete("orgs/:orgId")
	@Roles("admin")
	@AuditAction({
		action: "policy.delete-org",
		target: c => `orgId=${c.params.orgId}`,
	})
	@ApiDelete({
		summary: "Delete the default policy for a specific organization",
		description:
			"Removes the organization's defaults and re-pushes the full resolved routing " +
			"document to the gateway control plane. Refuses with 409 if any client still " +
			"references this organization.",
		type: UpdateOrgPolicyResponseDto,
		notFound: "Policy for the given organization not found",
	})
	async deleteOrgPolicy(
		@Param("orgId") orgId: string
	): Promise<UpdateOrgPolicyResponseDto> {
		return this.policyService.deleteOrgPolicy(orgId);
	}
}
