# Emerging standards and layers

Agent governance is not one control. It splits into five layers, each answering a different
question, and each has its own standards and products. This POC covers layers 3 to 5; layers 1
and 2 are created by script and left at that.

| Layer | Question | Fully local mock | Cloud-hosted mock (APIM + Cedar) |
| --- | --- | --- | --- |
| 1. Registry and lifecycle | Which agents exist, who owns them? | Entra Agent ID objects created by script | unchanged (Agent 365 / ID Governance are out of scope here) |
| 2. Entitlement governance | Which permissions may it hold? | `appRoleAssignments` / `oauth2PermissionGrants` via Graph script | unchanged |
| 3. Token-time authorization | May it get a token at all? | Entra app roles and scopes | unchanged, still required |
| **4. Per-call authorization** | May it do *this action* on *this record* for *this user* now? | `hasPermission()` string match in two services | **AuthZEN PDP + Cedar**, called by the gateway, MCP server and Claims API |
| **5. Signals and revocation** | Stop it now | Entra disable (new tokens only) | **Kill switch workflow + Event Grid + kill list**, read on every call; Entra disable as backstop |

Layer 3 stays the coarse gate. Layer 4 refines it and never widens it: a call needs both an
Entra permission **and** a PDP `permit`. The design behind layers 4 and 5 is in
[Proposal.md](Proposal.md).

## Frameworks and solutions by layer

| Layer | Standards | Products and open source | In this repo |
| --- | --- | --- | --- |
| 1. Registry and lifecycle | SCIM agent resource ([draft-wzdk-scim-agent-resource](https://datatracker.ietf.org/doc/draft-wzdk-scim-agent-resource/)); [A2A](https://a2a-protocol.org/latest/) signed Agent Cards for discovery; SPIFFE IDs for workloads | [Microsoft Entra Agent ID](https://learn.microsoft.com/entra/agent-id/whats-new-agent-id) (identity: blueprints, agent identities, owners and sponsors); Microsoft Agent 365 (the registry, now hosted there instead of in Entra); Amazon Bedrock AgentCore Identity; Okta for AI Agents | Blueprint and Agent1-4 from `Configure/Configure-Entra.ps1` |
| 2. Entitlement governance | OAuth scopes and app roles; Rich Authorization Requests (RFC 9396) for finer-grained grants | [Entra ID Governance for agents](https://learn.microsoft.com/entra/id-governance/agent-id-governance-overview): access packages requested by sponsors, access reviews, expiry; IGA vendors (SailPoint, Saviynt and others) adding agent identities | Grants and admin consent by Graph script |
| 3. Token-time authorization | OAuth 2.x; [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (Protected Resource Metadata RFC 9728, resource indicators RFC 8707, Client ID Metadata Documents); Token Exchange (RFC 8693); ID-JAG for enterprise-managed MCP access; WIMSE workload credentials | Entra app roles, scopes, on-behalf-of and Conditional Access for agents; Okta Cross App Access (ID-JAG); AgentCore Identity and Auth0 Token Vault for outbound credentials | Entra tokens checked by the MCP server and Claims API; OBO in the MCP server ([details](mcp-server.md)) |
| 4. Per-call authorization | [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0-final.html) plus its MCP tool (COAZ) and access request (AARP) profiles; OAuth Transaction Tokens to carry agent and user context across hops | [Cedar](https://www.cncf.io/projects/cedar/) (Amazon Verified Permissions, [AgentCore Policy](https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available)); OPA / Rego; Zanzibar-style ReBAC (OpenFGA, SpiceDB); Cerbos, Topaz and other AuthZEN PDPs; API Management or another MCP gateway as the PEP | `claims-pdp/` (AuthZEN + `cedar-wasm`), called from `mcp-policy.xml`, `claims-mcp-azure/` and `claims-api-azure/` |
| 5. Signals and revocation | [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html) with [CAEP 1.0](https://openid.net/specs/openid-caep-1_0-final.html) and RISC 1.0; CloudEvents 1.0 | [Entra continuous access evaluation](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation) (built on CAEP, Microsoft resources only); Entra disable agent identity; Okta Identity Threat Protection (SSF receiver); Azure Event Grid | `claims-killswitch/`, Logic App + Event Grid, Redis kill list |

## Standards status (November 2026)

| Standard | Status | Used here |
| --- | --- | --- |
| [OpenID AuthZEN Authorization API 1.0](https://openid.net/wg/authzen/specifications/) | Final (January 2026). The MCP tool authorization profile (COAZ) and the Access Request and Approval Profile (AARP) became working-group drafts in June 2026 | Yes, PEP ↔ PDP contract |
| [Cedar](https://www.cncf.io/projects/cedar/) | Open source; CNCF Sandbox since October 2025. Used by Amazon Verified Permissions and AgentCore Policy (GA March 2026) | Yes, policy language and engine |
| [CloudEvents 1.0](https://cloudevents.io/) | CNCF graduated; native on Event Grid | Yes, kill / restore events |
| [OpenID Shared Signals Framework / CAEP / RISC 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html) | Final (published September 2025). Entra's CAE uses CAEP for Microsoft resources but sends no events to custom APIs | No. The Event Grid design fills the same role; the kill switch service could later act as an SSF transmitter |
| [OAuth Transaction Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) | IETF OAuth working-group draft (-11, July 2026), past working-group consensus and waiting for write-up; no Entra support | Listed only as [Proposal.md section 5.8](Proposal.md#58-carrying-the-agent-across-hop-2) option C |
| [ID-JAG](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) (Identity Assertion JWT Authorization Grant) | IETF OAuth working-group draft (-06, October 2026). Used by the MCP Enterprise-Managed Authorization extension; Okta ships it as Cross App Access. No Entra support announced | No |
| [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Part of MCP revision 2026-07-28: Protected Resource Metadata required, Client ID Metadata Documents preferred over dynamic registration | Partly: the MCP server is its own OAuth resource with audience binding ([details](mcp-server.md)) |
| [IETF WIMSE AI agent work](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/) | `draft-ietf-wimse-aims` (AI Identity Management System, -01, November 2026) is a WIMSE working-group document that replaces the individual `draft-klrc-aiagent-auth`; further individual drafts on agent identity and delegation | No |
| [SCIM for agents](https://datatracker.ietf.org/doc/draft-wzdk-scim-agent-resource/) | Individual draft (-00, June 2026, authors from Microsoft and Okta) adding an `Agent` resource type and `/Agents` endpoint to SCIM; a governance extension draft (`draft-kushwaha-scim-agent-governance`) builds on it | No |
| [A2A protocol](https://a2a-protocol.org/latest/) | Version 1.0 (2026) under the Linux Foundation; adds signed Agent Cards | No |
| [NIST NCCoE agent identity concept paper](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd) | Concept paper (February 2026, comments closed April 2026); proposes applying OAuth, OpenID Connect, SCIM and SPIFFE to agents | Background only |
