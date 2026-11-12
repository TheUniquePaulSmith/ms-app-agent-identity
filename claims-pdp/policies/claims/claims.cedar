// Claims domain policies, owned by the Claims team.
//
// Evaluated together with the platform guardrails (policies/platform). Default
// deny: nothing is allowed unless a permit matches, and any matching forbid
// (here or in the platform layer) beats every permit. Each policy carries:
//   @id      the policy id returned to PEPs in context.policyIds
//   @reason  the user-facing explanation returned in context.reason_user

// =========================================================================
// Who may use the Claims domain at all
// =========================================================================

@id("user-must-be-adjuster")
@reason("You are not a member of a POC Claims adjuster group in Entra.")
forbid (principal, action, resource)
when {
  context has onBehalfOf &&
  !(context.onBehalfOf in Platform::Group::"adjusters-eu" ||
    context.onBehalfOf in Platform::Group::"adjusters-us")
};

// =========================================================================
// Layer 4, coarse: mirror the Entra permissions (never wider than Entra)
// =========================================================================

@id("gateway-mcp-access")
@reason("The token carries no permission on the MCP server.")
permit (principal, action == Claims::Action::"mcp_request", resource)
when {
  context.permissions.containsAny(["Mcp.Analyze", "Mcp.Analyze.All", "Mcp.Archive", "Mcp.Archive.All"])
};

@id("read-claim")
@reason("Any caller with a claims permission may read a claim summary.")
permit (principal, action == Claims::Action::"get_claim", resource)
when {
  context.permissions.containsAny([
    "Mcp.Analyze", "Mcp.Analyze.All", "Mcp.Archive", "Mcp.Archive.All",
    "Claims.Analyze", "Claims.Analyze.All", "Claims.Archive", "Claims.Archive.All"])
};

@id("agent-analyze")
@reason("Agents may analyze claims when Entra granted Mcp.Analyze.")
permit (
  principal is Platform::Agent,
  action in [Claims::Action::"analyze_claim", Claims::Action::"get_claim_evidence"],
  resource
)
when { context.permissions.containsAny(["Mcp.Analyze", "Mcp.Analyze.All"]) };

@id("host-archive")
@reason("The host application may archive claims when Entra granted Mcp.Archive.")
permit (
  principal is Platform::Application,
  action == Claims::Action::"archive_claim",
  resource
)
when {
  !principal.isMcpServer &&
  context.permissions.containsAny(["Mcp.Archive", "Mcp.Archive.All"])
};

// Proposal 5.8 option A: after the token exchange the Claims API sees the MCP
// server as the caller. The per-agent decision was made at PEP 2; here the PDP
// trusts the MCP server for agent attribution but still applies every
// record-level forbid below (status, hold, amount, user groups, user kill).
@id("mcp-server-intermediary")
@reason("The MCP server may call the Claims API for a caller it already authorized.")
permit (
  principal is Platform::Application,
  action in [Claims::Action::"get_claim_evidence", Claims::Action::"analyze_claim", Claims::Action::"archive_claim"],
  resource
)
when {
  principal.isMcpServer && context.pep == "claims-api" &&
  ((action == Claims::Action::"archive_claim" &&
    context.permissions.containsAny(["Claims.Archive", "Claims.Archive.All"])) ||
   (action != Claims::Action::"archive_claim" &&
    context.permissions.containsAny(["Claims.Analyze", "Claims.Analyze.All"])))
};

// =========================================================================
// Layer 4, fine-grained: what Entra roles and scopes cannot express
// =========================================================================

@id("claim-must-exist")
@reason("There is no claim with that id.")
forbid (principal, action, resource)
when { resource is Claims::Claim && !resource.exists };

@id("agent-same-region-as-user")
@reason("The claim belongs to a region whose adjuster group you are not in.")
forbid (principal is Platform::Agent, action, resource)
when {
  resource is Claims::Claim && context has onBehalfOf &&
  !(context.onBehalfOf in resource.adjusterGroup)
};

// A missing limit counts as 0 (the PDP always sets it for agents).
@id("agent-autonomous-limit")
@reason("This claim is above the agent's autonomous limit; a signed-in adjuster must be in the loop.")
forbid (principal is Platform::Agent, action, resource)
when {
  resource is Claims::Claim && !(context has onBehalfOf) &&
  !(context has agentAutonomousLimit && resource.amount <= context.agentAutonomousLimit)
};

@id("no-agent-on-litigation-hold")
@reason("Claims on litigation hold may not be touched by agents.")
forbid (principal is Platform::Agent, action, resource)
when { resource is Claims::Claim && resource.litigationHold };

@id("no-archive-on-litigation-hold")
@reason("Claims on litigation hold may not be archived.")
forbid (principal, action == Claims::Action::"archive_claim", resource)
when { resource is Claims::Claim && resource.litigationHold };

@id("no-archive-twice")
@reason("The claim is already archived.")
forbid (principal, action == Claims::Action::"archive_claim", resource)
when { resource is Claims::Claim && resource.status == "archived" };

@id("no-analyze-archived")
@reason("Archived claims are closed and cannot be analyzed.")
forbid (principal, action == Claims::Action::"analyze_claim", resource)
when { resource is Claims::Claim && resource.status == "archived" };

@id("archive-own-region")
@reason("You may only archive claims in the region of your adjuster group.")
forbid (principal, action == Claims::Action::"archive_claim", resource)
when {
  resource is Claims::Claim && context has onBehalfOf &&
  !(context.onBehalfOf in resource.adjusterGroup)
};

@id("archive-over-5000-needs-senior")
@reason("Archiving a claim above 5,000 requires the POC Claims Senior Adjusters group.")
forbid (principal, action == Claims::Action::"archive_claim", resource)
when {
  resource is Claims::Claim && context has onBehalfOf && resource.amount > 5000 &&
  !(context.onBehalfOf in Platform::Group::"senior-adjusters")
};

@id("archive-over-25000-needs-user")
@reason("Archiving a claim above 25,000 requires a signed-in adjuster; app-only archive is not allowed.")
forbid (principal, action == Claims::Action::"archive_claim", resource)
when {
  resource is Claims::Claim && !(context has onBehalfOf) && resource.amount > 25000
};
