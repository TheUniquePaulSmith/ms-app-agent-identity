# 9. Local LLM & Gateway MCP (Proposal.md implemented in Azure)

[← Back to README](../README.md)

The web UI's **Local LLM & Gateway MCP** tab implements [Proposal.md](Proposal.md) layers 4 and 5.
The LLM still runs locally. The MCP server, the Claims API, the PDP and the kill switch run in Azure
behind API Management. Tool calls run as one of the **gateway agents** from the same blueprint
(Agent2-4 in [Test identities](test-identities.md)), so the PDP can treat agents differently. The original tab and
`claims-mcp/` are unchanged.

```
Host app (localhost:5094, local LLM)
  │ Bearer aud = MCP server (gateway agent / host app, app-only or for the user)
  ▼
API Management (Consumption)  PEP 1: validate-azure-ad-token → rate limit per azp → kill list → AuthZEN "mcp:<method>"
  ▼
claims-mcp-azure (App Service) PEP 2: AuthZEN per tool + claim; tools/list and list_claims filtered by batch evaluation
  │ OBO / client credentials (MCP server's own credential, as in section 8)
  ▼
claims-api-azure (App Service) PEP 3: AuthZEN per record (subject = MCP server, Proposal 5.8 option A), then changes the record
  ▼
Azure Table "Claims"

claims-pdp (App Service): AuthZEN 1.0 + Cedar. Registry: Azure Table "PdpEntities". PIPs: Redis kill list, Claims table, Entra groups (Graph checkMemberGroups)
Kill: web UI → Logic App → Event Grid (CloudEvents) → claims-killswitch → Redis kill list (+ Entra disable as backstop)
```

## 9A. Components

| Path | Role |
| --- | --- |
| `claims-pdp/` | PDP. `POST /access/v1/evaluation`, `/access/v1/evaluations`, `/.well-known/authzen-configuration`. Cedar policies and schema in two layers: `policies/platform/` (guardrails every domain PDP would share: kill switch, registration; forbid only) and `policies/claims/` (the Claims domain, namespace `Claims`; identity types are `Platform::Agent`, `Platform::User`, ...). Registry (blueprints, agents, applications, groups, local members) in the `PdpEntities` table, re-read every 30 s and on `POST /admin/reload`. `npm test` runs a 20-case decision matrix |
| `claims-killswitch/` | Single writer of the kill list. Event Grid webhook (CloudEvents handshake, idempotent on event id), audit to the `KillAudit` table, `/kills`, `/kills/check`, and Entra drift sync (`accountEnabled`) every 60 s |
| `claims-api-azure/` | Hosted Claims API: jose validation (as `claims-api/`), PDP per record, analyze/archive change the record in the `Claims` table (seeded from `seed-claims.json`) |
| `claims-mcp-azure/` | Hosted MCP server: PDP per tool, filtered `tools/list`, new `list_claims` tool, gateway decision echoed into the tool result |
| `Configure/Bicep/main.bicep` | Every Azure resource (one resource group) |
| `Configure/Bicep/apim/mcp-policy.xml` | The gateway policy (PEP 1) |
| `Configure/Bicep/logicapp/killswitch-workflow.json` | Kill / restore workflow (order as Proposal 6.2 / 6.4) |
| `Configure/Bicep/eventgrid-subscription.bicep` | Topic → kill switch webhook, dead-letter to blob |
| `Configure/Configure-Entra.ps1 -SetupAll` | App registrations (`-TestAppRegs`); test agents Agent1-4, test users User1-4, the PDP groups and user assignments (`-TestAgents -TestUsers`). Writes them into `appsettings.json` and (once deployed) the PDP registry |
| `Configure/Configure-GatewayEntra.ps1` | MCP optional claims, managed identity Graph permissions |
| `Configure/Deploy-GatewayPoc.ps1` | Bicep, code deployment, Event Grid subscription, writes `appsettings.json` `GatewayMcp` |
| `GatewayEndpoints.cs`, `wwwroot/gateway.js` | The tab: chat via `/gw/chat/*`, trace per PEP, kill switch, claims table, PDP playground |
| `PdpEntityEndpoints.cs` | The tab's *PDP entities* sub-tab: lists, adds, edits and deletes registry rows straight in the storage account (`GatewayMcp:StorageConnectionString`), then asks the PDP to reload |

## 9B. Azure resources and SKUs (cheapest that works)

| Resource | SKU | Why this one |
| --- | --- | --- |
| API Management | Consumption | Internet facing, pay per call. Supports `validate-azure-ad-token`, `send-request` and the external cache. It has **no `rate-limit-by-key`**, so the per-`azp` limit is a one-minute counter in the external cache |
| Azure Managed Redis | Balanced_B0, high availability off | Kill list and APIM external cache. Azure Cache for Redis Basic/Standard is closed to new customers since April 2026. APIM can't read raw Redis keys, so it asks the kill switch (`/kills/check`) and caches the answer for 5 s |
| App Service plan | Linux B1, 4 web apps | PDP, kill switch, Claims API, MCP server on one plan (cheaper than 4 container instances) |
| Storage account | Standard_LRS | Tables `Claims`, `KillAudit`, `PdpEntities`; container `deadletter` |
| Event Grid | Custom topic (CloudEvents 1.0) | Pay per operation; a namespace topic would add an hourly charge |
| Logic App | Consumption | Managed identity for Event Grid (Data Sender role) and Microsoft Graph |

Not deployed (deliberately): private endpoints, VNet, Key Vault, Application Insights, a PDP app
registration. Internal calls use a shared key (`x-pdp-key`, `?code=` for the webhook); that is
the POC simplification of Proposal section 8.

## 9C. Deploy

From a PowerShell 7 prompt at the repo root (Azure CLI signed in, Microsoft.Graph module):

```powershell
.\Configure\Configure-Entra.ps1 -SetupAll                                              # app registrations, test agents, users, groups, ids into appsettings.json
.\Configure\Deploy-GatewayPoc.ps1 -NamePrefix <prefix> -PublisherEmail you@contoso.com   # Azure + code + appsettings.json
.\Configure\Configure-Entra.ps1 -TestAgents -TestUsers                                   # again: agents, groups, members into the PDP registry
.\Configure\Configure-GatewayEntra.ps1                                                   # MCP optional claims, managed identity Graph permissions
```

`Deploy-GatewayPoc.ps1` takes `-ResourceGroup` (default `rg-poc-agent-gateway`), `-Location`
(`eastus2`) and `-NamePrefix` (required the first time: 3-11 lowercase letters and digits, unique
enough for `<prefix>-apim.azure-api.net` and `<prefix>-pdp.azurewebsites.net`; later runs read it
back from `appsettings.json` `GatewayMcp:PdpUrl`). Tenant and Claims API ids come from
`appsettings.json`, the MCP server id and secret from `claims-mcp/config.json`. Redeploy code only with `-SkipInfra -Apps claims-pdp` (for example after editing a
policy).

**PDP registry.** Blueprints, agents, applications, groups and local members live in the
`PdpEntities` table of the same storage account (PartitionKey = kind, RowKey = id; columns in
`claims-pdp/pdp-core.mjs`). `Deploy-GatewayPoc.ps1` adds the missing baseline rows and writes the
account's connection string into `GatewayMcp:StorageConnectionString`; `Configure-Entra.ps1
-TestAgents -TestUsers` (second run) writes the test agents, the group object ids and the local members. After that,
add or change rows on the gateway tab's **PDP entities** sub-tab: the web app writes the table
directly and calls the PDP's `POST /admin/reload`, so the next decision uses the change (the PDP
also re-reads the table every 30 s and keeps the last good registry if storage is unreachable).
Without storage (a local `node server.mjs` with neither `STORAGE_TABLE_ENDPOINT` nor
`STORAGE_CONNECTION_STRING`) the registry is empty and every agent is unregistered.

**More agents.** The chat's *Agent identity* drop-down lists `appsettings.json`
`GatewayAgentIdentities`, all from the same blueprint: Agents 1-4 from
[Test identities](test-identities.md), with Agent2 as the default. Create more with:

```powershell
.\Configure\Configure-Entra.ps1 -NewAgent "POC Claims Agent 5" [-AutonomousLimit 2000] [-NotInPdp]
```

Each new agent gets `Mcp.Analyze.All` and delegated `Mcp.Analyze` on the MCP server, a drop-down
entry, and (unless `-NotInPdp`) a `PdpEntities` row with its own autonomous limit, which the PDP
picks up within 30 s. Restart the web app to see it in the drop-down. An agent left out of the
registry can be registered later with the *Register* button on the PDP entities sub-tab.

## 9D. The policies (Cedar) and the test users

Users are represented by **Entra groups**. The PDP resolves membership live through Microsoft
Graph `checkMemberGroups` with its managed identity, cached for 60 s. The users, groups and agents
are described in [Test identities](test-identities.md).

| Group | Members |
| --- | --- |
| POC Claims Adjusters EU | User1 (EU Adjuster) |
| POC Claims Adjusters US | User2 (US Senior Adjuster) |
| POC Claims Senior Adjusters | User2 (US Senior Adjuster) |

| Claim | Region | Status | Amount | Hold |
| --- | --- | --- | --- | --- |
| CLAIM-1001 | EU | open | 1,250 | |
| CLAIM-1002 | US | open | 3,400 | |
| CLAIM-1003 | EU | open | 18,500 | yes |
| CLAIM-1004 | EU | archived | 900 | |
| CLAIM-1005 | US | open | 42,000 | |
| CLAIM-1006 | EU | open | 12,000 | |
| CLAIM-2002 | US | open | 7,800 | |

| Try (mode → prompt) | Expected | Decided by (policy) |
| --- | --- | --- |
| Agent2 app-only → Analyze 1001 | ALLOW, record becomes `analyzed` | PEP 2 `agent-analyze`, PEP 3 `mcp-server-intermediary` |
| Agent2 app-only → Analyze 1005 or 1006 | DENY | PEP 2 `agent-autonomous-limit` (10,000) |
| Agent3 app-only → Analyze 1005 or 1006 | ALLOW | `agent-analyze` (limit 50,000) |
| Agent2 or Agent3 app-only → Analyze 1003 | DENY | PEP 2 `no-agent-on-litigation-hold` |
| Agent2 or Agent3 app-only → "Archive" | no archive tool offered | `tools/list` filtered (no permit for agents) |
| Agent4 → anything | DENY at the gateway | `agent-must-be-registered` (Entra granted it `Mcp.Analyze.All`; *Register* it on the PDP entities sub-tab and it is allowed) |
| Agent2 for User1 → Analyze 1002 | DENY | `agent-same-region-as-user` (not in the US group) |
| Agent2 for User2 → Analyze 1005 | ALLOW (a human is in the loop) | `agent-analyze` |
| Agent2 for User3 → anything | DENY at the gateway | `user-must-be-adjuster` |
| Host app for User1 → Archive 1006 | DENY | `archive-over-5000-needs-senior` |
| Host app for User2 → Archive 2002 | ALLOW | `host-archive` (Senior Adjusters) |
| Host app for User2 → Archive 1006 | DENY | `archive-own-region` |
| Host app app-only → Archive 1005 | DENY | `archive-over-25000-needs-user` |
| Any → Archive 1004, or Archive 1001 twice | DENY | `no-archive-twice` (PEP 2, or PEP 3 when the record changed in between) |
| Agent1 (the local agent) through the gateway | DENY at the gateway | `agent-must-be-registered` |
| Kill the selected agent, then any call | 403 at the gateway within ~5 s | kill list (`kill-switch-principal` at PEP 2/3 too) |
| Kill the blueprint / the signed-in user | every agent of the blueprint / every call for that user refused | `kill-switch-blueprint` / `kill-switch-user` |
| More than 30 MCP requests a minute from one `azp` | 429 at the gateway | rate-limit counter |

Sign in as User1, User2 or User3 (sign out first), refresh tokens on the Profile tab, then use the
*on behalf of signed-in user* modes. `Configure-Entra.ps1 -TestUsers` assigns User1-3 to the
blueprint and every agent; with the user gate on (`Set-AgentUserAccess.ps1 -RequireAssignment $true`)
User4 cannot get an agent token at all.
The **Reset sample data** button restores the table.

## 9E. Differences from Proposal.md

- **Kill list at the gateway:** APIM reads it through the kill switch's `/kills/check` (cached in
  the external Redis cache), not with a raw Redis `GET`.
- **Rate limit:** an approximate fixed-window counter in the external cache (Consumption tier).
- **Hop 2:** option A. The Claims API asks the PDP about the MCP server and the user, and still
  applies every record-level `forbid`.
- **Agent detection:** the MCP registration did not emit `xms_par_app_azp`, so
  `Configure-GatewayEntra.ps1` adds it as an optional claim. The PDP also treats any id in its agent
  registry as an agent. An unknown caller of any kind is refused (`*-must-be-registered`).
- **Blueprint kill:** kill list only; the blueprint is not disabled in Entra (Proposal open
  question 4). Agent kills can also disable the agent identity in Entra (checkbox), using
  `AgentIdentity.EnableDisable.All` on the Logic App's managed identity.
- **Drift sync** polls `accountEnabled` of the watched agent ids instead of `servicePrincipals/delta`.
