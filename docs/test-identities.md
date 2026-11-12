# Test identities: users, groups and agents

[← Back to README](../README.md)

The POC uses four test users and four agent identities. Each one shows a different combination of
**what Entra allows** (app roles, scopes, user assignment) and **what the PDP allows** (registry,
groups, Cedar policies). One script creates them all:

```powershell
.\Configure\Configure-Entra.ps1 -TestAgents -TestUsers
```

Run it again after `Deploy-GatewayPoc.ps1`: the PDP registry (Azure Table `PdpEntities`) only exists
once the gateway is deployed, and the second run writes the agents, group object ids and local
members into it. Every step is idempotent.

## Users

| User | Display name (role) | Sign-in name | Entra groups (PDP) | Assigned to blueprint + agents (`Agent.Invoke`) | What it shows |
| --- | --- | --- | --- | --- | --- |
| **User1** | POC Claims EU Adjuster (User1) | `poc-claims-user1@<domain>` | POC Claims Adjusters EU | yes | An EU adjuster: may work on EU claims, may not archive above 5,000 |
| **User2** | POC Claims US Senior Adjuster (User2) | `poc-claims-user2@<domain>` | POC Claims Adjusters US, POC Claims Senior Adjusters | yes | A US adjuster with higher privilege: may work on US claims and archive above 5,000 |
| **User3** | POC Claims Agent User, No Adjuster Group (User3) | `poc-claims-user3@<domain>` | none | yes | Entra says yes, the PDP says no: gets agent tokens, but every gateway call is refused (`user-must-be-adjuster`) |
| **User4** | POC Claims Unassigned User (User4) | `poc-claims-user4@<domain>` | none | **no** | Entra says no: with the user gate on, Entra refuses to issue an agent token (`AADSTS50105`) |

- The display name says the role; the sign-in name stays short. `<domain>` is the tenant's
  default verified domain, or `-UserDomain`. Re-running the script restores the display names of
  these accounts.
- New users get a random one-time password, printed once, which must be changed at first sign-in.
- To use existing accounts instead, pass `-User1` … `-User4` with a UPN or object id. Their
  display names are left as they are.
- The script makes group membership match this table for these four users. It adds missing
  memberships and removes memberships that shouldn't be there, and leaves other members of the
  groups alone.

**The user gate.** Assignment to the blueprint only blocks anyone once the blueprint principal
requires it. Turn the gate on to see User4 refused, and off again afterwards:

```powershell
.\Configure\Set-AgentUserAccess.ps1 -RequireAssignment $true    # User4 now gets AADSTS50105
.\Configure\Set-AgentUserAccess.ps1 -RequireAssignment $false   # back to open
```

With the gate on, the account you use for the local demo also needs the assignment
(`.\Configure\Set-AgentUserAccess.ps1 -Grant -User <you> -AgentIdentityId <ids>`). With the gate
off, User4 behaves like User3 at the PDP.

## Groups

The Cedar policies in `claims-pdp/policies/claims/claims.cedar` refer to groups by these ids. The
PDP maps them to Entra object ids through its registry.

| Entra group | PDP id | Region | Members | Used by policies |
| --- | --- | --- | --- | --- |
| POC Claims Adjusters EU | `adjusters-eu` | EU | User1 | `user-must-be-adjuster`, `agent-same-region-as-user`, `archive-own-region` |
| POC Claims Adjusters US | `adjusters-us` | US | User2 | same |
| POC Claims Senior Adjusters | `senior-adjusters` | | User2 | `archive-over-5000-needs-senior` |

## Agents

All four are agent identities from the same blueprint. Agent1 is for the local tabs; Agents 2-4
are for the **Local LLM & Gateway MCP** tab, where the agent drop-down lists them.

| Agent | Display name | Entra permissions | PDP registry | What it shows |
| --- | --- | --- | --- | --- |
| **Agent1** | POC Claims Local Analysis Agent (Agent1), id in `AgentIdentity:ClientId` | Claims API: `Claims.Analyze.All` (application) + `Claims.Analyze` (delegated). MCP server: `Mcp.Analyze.All` + `Mcp.Analyze` | not registered | Local mode: the same agent with an application permission (scenario 3, no user) and a delegated permission (scenario 4, user present) |
| **Agent2** | POC Claims Limited Gateway Agent (Agent2) | MCP server: `Mcp.Analyze.All` + `Mcp.Analyze` | registered, autonomous limit **10,000** | PDP, limited access: app-only analysis only up to 10,000 |
| **Agent3** | POC Claims Senior Gateway Agent (Agent3) | MCP server: `Mcp.Analyze.All` + `Mcp.Analyze` | registered, autonomous limit **50,000** | PDP, greater access: the same Entra permissions as Agent2, but the PDP lets it analyze high-value claims on its own |
| **Agent4** | POC Claims Rogue Agent, Unregistered (Agent4) | MCP server: `Mcp.Analyze.All` + `Mcp.Analyze` | **not registered** | A bad agent: Entra grants it the permissions, but the gateway refuses every call (`agent-must-be-registered`) |

- No agent holds an archive permission, and the Cedar policies have no archive permit for agents.
  Archiving is the host app's job.
- Agent2 is the drop-down's default (`GatewayMcp:AgentIdentityClientId`).
- The display name says the role. The script finds an agent under its role name or an older name
  (for example *POC Claims Gateway Agent*) and renames it.
- The script resets the autonomous limits of Agents 2 and 3 on every run. It also removes registry
  rows for Agents 1 and 4, which undoes a *Register* click on the PDP entities sub-tab.
- More agents: `.\Configure\Configure-Entra.ps1 -NewAgent "POC Claims Agent 5" [-AutonomousLimit 2000] [-NotInPdp]`.

## What to expect

Claim amounts and regions are listed in [9D](gateway.md#9d-the-policies-cedar-and-the-test-users).

**Local tabs (no PDP):** Agent1 with application vs delegated permission. These are scenarios 3 and
4 in [Run it locally](run-locally.md). Any user can be the signed-in user for scenario 4, except
User4 while the user gate is on.

**Gateway tab, agent app-only (no user):** the PDP compares the claim amount with the agent's
autonomous limit.

| Prompt | Agent2 (limit 10,000) | Agent3 (limit 50,000) | Agent4 (unregistered) |
| --- | --- | --- | --- |
| Analyze CLAIM-1001 (EU, 1,250) | ALLOW | ALLOW | DENY `agent-must-be-registered` |
| Analyze CLAIM-1006 (EU, 12,000) | DENY `agent-autonomous-limit` | ALLOW | DENY |
| Analyze CLAIM-1005 (US, 42,000) | DENY `agent-autonomous-limit` | ALLOW | DENY |
| Analyze CLAIM-1003 (litigation hold) | DENY `no-agent-on-litigation-hold` | DENY | DENY |

**Gateway tab, on behalf of a signed-in user:** the user's groups decide; the autonomous limit does
not apply because a human is in the loop. These outcomes hold for Agent2 and Agent3 (Agent4 is
refused for everyone).

| Prompt | User1 (EU) | User2 (US + Senior) | User3 (no group) | User4 |
| --- | --- | --- | --- | --- |
| Agent: analyze CLAIM-1001 (EU) | ALLOW | DENY `agent-same-region-as-user` | DENY `user-must-be-adjuster` | gate on: no agent token (`AADSTS50105`); gate off: as User3 |
| Agent: analyze CLAIM-1005 (US, 42,000) | DENY `agent-same-region-as-user` | ALLOW | DENY `user-must-be-adjuster` | as above |
| Host app: archive CLAIM-1001 (EU, 1,250) | ALLOW | DENY `archive-own-region` | DENY `user-must-be-adjuster` | DENY `user-must-be-adjuster` (the host app token is not gated) |
| Host app: archive CLAIM-2002 (US, 7,800) | DENY `archive-own-region` | ALLOW | DENY | DENY |
| Host app: archive CLAIM-1006 (EU, 12,000) | DENY `archive-over-5000-needs-senior` | DENY `archive-own-region` | DENY | DENY |

To switch users, sign out, sign in as the user, and refresh the tokens on the Profile tab. The PDP
playground sub-tab has presets for User1-3 and Agent4; their object ids come from
`GatewayMcp:User1ObjectId`..`User3ObjectId`, which the script writes.

## What the script writes

| Where | What |
| --- | --- |
| `appsettings.json` | `AgentIdentity:ClientId` (Agent1, only when it creates it), `GatewayMcp:AgentIdentityClientId` (Agent2), `GatewayAgentIdentities` (Agents 1-4), `GatewayMcp:User1ObjectId`..`User3ObjectId` |
| Entra | the users, groups and memberships; `Agent.Invoke` assignments for User1-3 on the blueprint and every agent (removed for User4); the agent grants above |
| PDP registry (once deployed) | `agent` rows for Agents 2 and 3; `group` rows with Entra object ids; `member` rows for User1 and User2 (used only with `GROUP_SOURCE=local`) |

Restart the web app after the script so it picks up `appsettings.json`.

## Clean up

The script doesn't delete anything from Entra. To remove the test objects, delete the users
`poc-claims-user1`..`4`, the three *POC Claims Adjusters* groups, and the agent identities ending in
*(Agent2)*, *(Agent3)* and *(Agent4)* in the Entra admin center. Agent1 is the agent from
[4D](entra-setup.md#4d-poc-claims-analysis-agent-the-agent-identity), so keep it for the local tabs.
