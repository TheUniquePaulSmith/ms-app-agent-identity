// Platform guardrails: loaded into every domain PDP, owned centrally.
//
// The loader accepts only forbid policies in this layer. Platform rules can take
// access away from every domain but never grant it; granting is the domain's job.
// Because a matching forbid beats every permit, no domain policy can override
// these. Policies name no domain action or resource type, so they apply to
// every action the domain schema declares.
//
//   @id      the policy id returned to PEPs in context.policyIds
//   @reason  the user-facing explanation returned in context.reason_user

// =========================================================================
// Layer 5: kill switch (kill list read from Redis on every evaluation)
// =========================================================================

@id("kill-switch-principal")
@reason("This agent or application has been disabled by an administrator.")
forbid (principal, action, resource)
when { principal.killed };

@id("kill-switch-blueprint")
@reason("Every agent created from this blueprint has been disabled by an administrator.")
forbid (principal is Platform::Agent, action, resource)
when { principal.blueprint.killed };

@id("kill-switch-user")
@reason("Agents and applications may not act on behalf of this user right now.")
forbid (principal, action, resource)
when { context has onBehalfOf && context.onBehalfOf.killed };

// =========================================================================
// Layer 1 as seen by the PDP: only identities in the registry
// =========================================================================

@id("agent-must-be-registered")
@reason("This agent identity is not registered with the policy decision point.")
forbid (principal is Platform::Agent, action, resource)
when { !principal.registered };

// Also catches an agent whose token carried no agent claims (it then looks like
// an application, and an unknown one).
@id("application-must-be-registered")
@reason("This application is not registered with the policy decision point.")
forbid (principal is Platform::Application, action, resource)
when { !principal.registered };
