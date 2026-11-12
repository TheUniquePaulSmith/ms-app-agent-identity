# Agent Identity vs Application Identity

This POC simulates a design around a Claims application and backend API using Agent & User identities.
It uses real Microsoft Entra tokens to show the difference between an
**application identity** (a normal App Registration / service principal) and a
**Microsoft Entra Agent Identity** when either one calls a downstream API, directly or through
an MCP server.

It is a teaching aid, not a production pattern. Secrets live in a local, git-ignored
`appsettings.json`. The downstream API is a mock (it validates tokens for real, but its business
logic is stubbed). Bearer tokens are handed out through a browser endpoint.

## What it demonstrates

> **Where the code runs does not pick the identity. The logical actor performing the operation
> picks the identity.**

- **Same operation, different actor.** One host process mints tokens either as the host app or
  as an agent identity, and the downstream API sees a different `azp`/`oid` for each.
- **The permission kind follows the user, not the code.** `roles` when no user is present,
  `scp` plus the user's `oid` when one is.
- **The MCP server is a resource, not a relay.** It validates tokens issued for it, decides on its
  own `Mcp.*` permissions, and exchanges the token (on-behalf-of or client credentials) instead of
  passing it through.
- **Per-call authorization and a kill switch** (optional, in Azure): API Management, an AuthZEN
  + Cedar PDP, and an Event Grid driven kill list.

The six direct scenarios, the four agent-loop chat modes and the permissions behind each are on
one page: [Scenarios at a glance](docs/scenarios.md).

## Pieces

The repo holds two versions of the same Claims API + MCP server, used by different tabs of the
same host app. Both use the same Entra tenant and registrations.

### Fully local mock (the core POC)

Everything runs on your machine; Azure isn't needed. Web UI tabs: *Application runtime* and
*Agent runtime loop*.

| Piece | Path | Address |
| --- | --- | --- |
| Host application (ASP.NET Core minimal API + web UI) | `Program.cs`, `*Service.cs`, `wwwroot/` | `http://localhost:5094` |
| Mock downstream "POC Claims API" (Node, `jose`) | `claims-api/` | `http://localhost:5001` |
| MCP server in front of the Claims API (own Entra registration) | `claims-mcp/` | `http://localhost:5002/mcp` |
| Local LLM (vLLM, OpenAI-compatible) or the fake stand-in | `fake-llm/` | `http://localhost:8000/v1` |
| Scenario test driver | `Tests/Invoke-ClaimsIdentityTests.ps1` | PowerShell 7 |

### Cloud-hosted mock (the gateway extension in [Proposal.md](docs/Proposal.md))

One Azure resource group, deployed by `Configure/Deploy-GatewayPoc.ps1`. The host app and the LLM
stay local; tool calls go out to Azure. Web UI tab: *Local LLM & Gateway MCP*. Details:
[Local LLM & Gateway MCP](docs/gateway.md).

| Piece | Path | Runs on | Role |
| --- | --- | --- | --- |
| MCP gateway (PEP 1) | `Configure/Bicep/apim/mcp-policy.xml` | API Management (Consumption) | Validates the Entra token, rate limit per `azp`, kill list check, AuthZEN decision per MCP method |
| Hosted MCP server (PEP 2) | `claims-mcp-azure/` | App Service | Asks the PDP before each tool call; filters `tools/list`; adds `list_claims` |
| Hosted Claims API (PEP 3) | `claims-api-azure/` | App Service | Asks the PDP per record, then changes the record |
| Policy decision point (PDP) | `claims-pdp/` | App Service | AuthZEN 1.0 + Cedar policies; looks up agent registrations, groups and the kill list |
| Kill switch | `claims-killswitch/` | App Service | Only writer of the kill list; Event Grid webhook, audit log, Entra drift sync |
| Kill / restore workflow | `Configure/Bicep/logicapp/` | Logic App + Event Grid | Publishes a kill event; can also disable the agent identity in Entra |
| Kill list and gateway cache | (deployed by Bicep) | Azure Managed Redis | Fast lookup for the gateway and the PDP |
| Claims, kill audit, PDP registry | (deployed by Bicep) | Storage tables | `Claims`, `KillAudit`, `PdpEntities` |
| Infrastructure and Entra setup | `Configure/Bicep/main.bicep`, `Configure/*.ps1` | PowerShell 7 + Azure CLI | Deploys everything above and writes the URLs and keys into `appsettings.json` |

### How the two differ

| | Fully local mock | Cloud-hosted mock |
| --- | --- | --- |
| Who decides | Entra permissions only: `roles` / `scp` checked by the MCP server and the Claims API | Entra permissions, **plus** a per-call AuthZEN + Cedar decision at three points (gateway, MCP server, Claims API) |
| Agent identity used for tool calls | Agent1, with application and delegated permissions | Agents 2-4 from the same blueprint: limited, greater access, and an unregistered "rogue" agent ([Test identities](docs/test-identities.md)) |
| What the policies can see | Token claims | Token claims plus the claim record (region, amount, hold, status), the user's Entra groups and the agent registry |
| Stopping an agent | Disable it in Entra; existing tokens keep working until they expire | Kill switch: the gateway refuses the agent, its blueprint or a user within seconds |
| Claim data | Stubbed responses, nothing stored | Records in an Azure Table that analyze and archive actually change |
| Configuration | `appsettings.json`, `claims-api/config.json`, `claims-mcp/config.json` | App Service settings set by Bicep; the deploy script writes the URLs and keys back into `appsettings.json` |
| Cost and setup | Free, starts in minutes | Pay-as-you-go Azure resources (Redis and the App Service plan cost money while deployed); one deploy script |

## Prerequisites

| Tool | Version | Used for | Install (Windows) | Other platforms |
| --- | --- | --- | --- | --- |
| .NET SDK | 10.0 | Host application (`dotnet run`) | `winget install Microsoft.DotNet.SDK.10` | [Download .NET 10](https://dotnet.microsoft.com/download/dotnet/10.0) |
| Node.js | 22 or later (LTS) | Claims API, MCP servers, PDP, kill switch, fake LLM | `winget install OpenJS.NodeJS.LTS` | [nodejs.org](https://nodejs.org/en/download) |
| PowerShell | 7.x | Test driver and the scripts in `Configure/` (they require 7.0, so Windows PowerShell 5.1 won't work) | `winget install Microsoft.PowerShell` | [Install PowerShell](https://learn.microsoft.com/powershell/scripting/install/installing-powershell) |
| Microsoft Graph PowerShell SDK | current | Entra setup scripts (app registrations, agent identities, grants, groups) | `Install-Module Microsoft.Graph -Scope CurrentUser` (run in `pwsh`) | [Install the Graph SDK](https://learn.microsoft.com/powershell/microsoftgraph/installation) |
| Azure CLI with Bicep | current | Only for the cloud-hosted mock (`Deploy-GatewayPoc.ps1`) | `winget install Microsoft.AzureCLI`, then `az bicep install` | [Install the Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) |

Open a new PowerShell 7 (`pwsh`) window after installing, then check that everything is there:

```powershell
dotnet --version                                    # 10.0.x
node --version                                      # v22.x or later
$PSVersionTable.PSVersion                           # 7.x
Get-Module Microsoft.Graph.Authentication -ListAvailable | Select-Object Name, Version
az version                                          # only for the cloud-hosted mock
```

You also need a Microsoft Entra tenant and an account with these roles (or Global Administrator):

| Role | Needed for |
| --- | --- |
| Agent ID Administrator | Creating the agent blueprint, its secret and agent identities |
| Cloud Application Administrator | App registrations, app roles, admin consent and application permissions |
| User Administrator and Groups Administrator | Only for the test users and the PDP's groups (`Configure-Entra.ps1 -TestUsers`) |
| Owner or User Access Administrator on a subscription | Only for the cloud-hosted mock (the Bicep template creates role assignments) |

A model is optional: the agent loop runs against the bundled `fake-llm/`, or any
OpenAI-compatible endpoint with tool calling (for example vLLM).

## Quick start

Check the [prerequisites](#prerequisites) first.

1. Create the Entra objects: [Entra setup](docs/entra-setup.md). The test users and agents
   (User1-4, Agent1-4) come from one script, `.\Configure\Configure-Entra.ps1 -TestAgents -TestUsers`
   ([Test identities](docs/test-identities.md)).
2. Create your local settings from the templates and fill in every `<placeholder>`
   ([details](docs/run-locally.md)):
   ```powershell
   Copy-Item appsettings.sample.json appsettings.json
   Copy-Item claims-api/config.sample.json claims-api/config.json
   ```
3. Start the mock Claims API and the host app:
   ```bash
   cd claims-api && npm install && node server.js
   ```
   ```bash
   dotnet run
   ```
4. Sign in at `http://localhost:5094/auth/sign-in`, then run the scenarios with the tokens it
   returns:
   ```powershell
   .\Tests\Invoke-ClaimsIdentityTests.ps1 -HostToken '<hostToken>' -AgentToken '<agentToken>'
   ```
5. Optional: the [agent runtime loop](docs/agent-loop.md) (LLM + MCP server) and the
   [gateway extension](docs/gateway.md) in Azure.

No tenant, app or object id is hard-coded: the scripts read them from your `appsettings.json` or
take them as parameters, and the Node servers stop if theirs are missing.

## Documentation

**Walkthrough**, in reading order:

| Page | What it covers |
| --- | --- |
| [Scenarios at a glance](docs/scenarios.md) | Every scenario and the API permission behind it, on one page |
| [Identity concepts](docs/concepts.md) | Agent vs application identity, claims cheat sheet, app roles vs "Expose an API", identity inventory |
| [Entra setup](docs/entra-setup.md) | Portal and Graph steps for the Claims API, host app, blueprint and agent identity |
| [Test identities](docs/test-identities.md) | The four test users and four agents: roles, groups, permissions, PDP access and expected decisions |
| [Run it locally](docs/run-locally.md) | Local settings, starting the pieces, expected test results |
| [Troubleshooting](docs/troubleshooting.md) | Symptoms, causes and fixes (AADSTS errors, 401/403s, MCP token exchange) |
| [Agent runtime loop](docs/agent-loop.md) | LLM + MCP chat, the web UI, where governance plugs in |
| [MCP server as an OAuth resource](docs/mcp-server.md) | Own registration, audience binding, no token passthrough, on-behalf-of |
| [Local LLM & Gateway MCP](docs/gateway.md) | The Azure deployment: API Management, AuthZEN + Cedar PDP, kill switch |

**Background and reference:**

| Page | What it covers |
| --- | --- |
| [Architecture](docs/ARCHITECTURE.md) | Mermaid diagrams: components, Entra object model, flows, code structure |
| [Proposal](docs/Proposal.md) | The design behind the gateway extension: per-call authorization and an agent kill switch |
| [References](docs/references.md) | Microsoft Learn and MCP specification links |

## Emerging standards and layers

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
[Proposal.md](docs/Proposal.md).

### Frameworks and solutions by layer

| Layer | Standards | Products and open source | In this repo |
| --- | --- | --- | --- |
| 1. Registry and lifecycle | SCIM agent resource ([draft-wzdk-scim-agent-resource](https://datatracker.ietf.org/doc/draft-wzdk-scim-agent-resource/)); [A2A](https://a2a-protocol.org/latest/) signed Agent Cards for discovery; SPIFFE IDs for workloads | [Microsoft Entra Agent ID](https://learn.microsoft.com/entra/agent-id/whats-new-agent-id) (identity: blueprints, agent identities, owners and sponsors); Microsoft Agent 365 (the registry, now hosted there instead of in Entra); Amazon Bedrock AgentCore Identity; Okta for AI Agents | Blueprint and Agent1-4 from `Configure/Configure-Entra.ps1` |
| 2. Entitlement governance | OAuth scopes and app roles; Rich Authorization Requests (RFC 9396) for finer-grained grants | [Entra ID Governance for agents](https://learn.microsoft.com/entra/id-governance/agent-id-governance-overview): access packages requested by sponsors, access reviews, expiry; IGA vendors (SailPoint, Saviynt and others) adding agent identities | Grants and admin consent by Graph script |
| 3. Token-time authorization | OAuth 2.x; [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (Protected Resource Metadata RFC 9728, resource indicators RFC 8707, Client ID Metadata Documents); Token Exchange (RFC 8693); ID-JAG for enterprise-managed MCP access; WIMSE workload credentials | Entra app roles, scopes, on-behalf-of and Conditional Access for agents; Okta Cross App Access (ID-JAG); AgentCore Identity and Auth0 Token Vault for outbound credentials | Entra tokens checked by the MCP server and Claims API; OBO in the MCP server ([details](docs/mcp-server.md)) |
| 4. Per-call authorization | [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0-final.html) plus its MCP tool (COAZ) and access request (AARP) profiles; OAuth Transaction Tokens to carry agent and user context across hops | [Cedar](https://www.cncf.io/projects/cedar/) (Amazon Verified Permissions, [AgentCore Policy](https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available)); OPA / Rego; Zanzibar-style ReBAC (OpenFGA, SpiceDB); Cerbos, Topaz and other AuthZEN PDPs; API Management or another MCP gateway as the PEP | `claims-pdp/` (AuthZEN + `cedar-wasm`), called from `mcp-policy.xml`, `claims-mcp-azure/` and `claims-api-azure/` |
| 5. Signals and revocation | [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html) with [CAEP 1.0](https://openid.net/specs/openid-caep-1_0-final.html) and RISC 1.0; CloudEvents 1.0 | [Entra continuous access evaluation](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation) (built on CAEP, Microsoft resources only); Entra disable agent identity; Okta Identity Threat Protection (SSF receiver); Azure Event Grid | `claims-killswitch/`, Logic App + Event Grid, Redis kill list |

### Standards status (November 2026)

| Standard | Status | Used here |
| --- | --- | --- |
| [OpenID AuthZEN Authorization API 1.0](https://openid.net/wg/authzen/specifications/) | Final (January 2026). The MCP tool authorization profile (COAZ) and the Access Request and Approval Profile (AARP) became working-group drafts in June 2026 | Yes, PEP ↔ PDP contract |
| [Cedar](https://www.cncf.io/projects/cedar/) | Open source; CNCF Sandbox since October 2025. Used by Amazon Verified Permissions and AgentCore Policy (GA March 2026) | Yes, policy language and engine |
| [CloudEvents 1.0](https://cloudevents.io/) | CNCF graduated; native on Event Grid | Yes, kill / restore events |
| [OpenID Shared Signals Framework / CAEP / RISC 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html) | Final (published September 2025). Entra's CAE uses CAEP for Microsoft resources but sends no events to custom APIs | No. The Event Grid design fills the same role; the kill switch service could later act as an SSF transmitter |
| [OAuth Transaction Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) | IETF OAuth working-group draft (-11, July 2026), past working-group consensus and waiting for write-up; no Entra support | Listed only as [Proposal.md section 5.8](docs/Proposal.md#58-carrying-the-agent-across-hop-2) option C |
| [ID-JAG](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) (Identity Assertion JWT Authorization Grant) | IETF OAuth working-group draft (-06, October 2026). Used by the MCP Enterprise-Managed Authorization extension; Okta ships it as Cross App Access. No Entra support announced | No |
| [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Part of MCP revision 2026-07-28: Protected Resource Metadata required, Client ID Metadata Documents preferred over dynamic registration | Partly: the MCP server is its own OAuth resource with audience binding ([details](docs/mcp-server.md)) |
| [IETF WIMSE AI agent work](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/) | `draft-ietf-wimse-aims` (AI Identity Management System, -01, November 2026) is a WIMSE working-group document that replaces the individual `draft-klrc-aiagent-auth`; further individual drafts on agent identity and delegation | No |
| [SCIM for agents](https://datatracker.ietf.org/doc/draft-wzdk-scim-agent-resource/) | Individual draft (-00, June 2026, authors from Microsoft and Okta) adding an `Agent` resource type and `/Agents` endpoint to SCIM; a governance extension draft (`draft-kushwaha-scim-agent-governance`) builds on it | No |
| [A2A protocol](https://a2a-protocol.org/latest/) | Version 1.0 (2026) under the Linux Foundation; adds signed Agent Cards | No |
| [NIST NCCoE agent identity concept paper](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd) | Concept paper (February 2026, comments closed April 2026); proposes applying OAuth, OpenID Connect, SCIM and SPIFFE to agents | Background only |
