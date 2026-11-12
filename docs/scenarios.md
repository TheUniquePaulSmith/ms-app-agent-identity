# Scenarios at a glance (API permissions)

[← Back to README](../README.md)

One page to read before the detail. Two resources define permissions, two callers hold them, and
the MCP server sits in between holding its own set.

**What each resource defines**

| Resource (App Registration) | Delegated scopes (`scp`, user present) | Application app roles (`roles`, no user) |
| --- | --- | --- |
| POC Claims API | `Claims.Archive`, `Claims.Analyze` | `Claims.Archive.All`, `Claims.Analyze.All` |
| POC Claims MCP Server | `Mcp.Archive`, `Mcp.Analyze` | `Mcp.Archive.All`, `Mcp.Analyze.All` |

**Who holds what** (rule of thumb: the host app archives, the agent analyzes, nobody gets the other side)

| Caller | On the Claims API | On the MCP server |
| --- | --- | --- |
| Host app `POC Claims Web` | `Claims.Archive` + `Claims.Archive.All` | `Mcp.Archive` + `Mcp.Archive.All` |
| Agent identity `POC Claims Analysis Agent` | `Claims.Analyze` + `Claims.Analyze.All` | `Mcp.Analyze` + `Mcp.Analyze.All` |
| MCP server `POC Claims MCP Server` | all four `Claims.*` (it calls the API for everyone) | it is the resource |

**A. Direct calls: host app → Claims API** (UI tab *Application runtime*; [concepts](concepts.md), [Entra setup](entra-setup.md), [run it](run-locally.md))

One hop, one check. The Claims API reads `roles` or `scp` on the token it receives.

1. **Host app, no user** → token `roles: Claims.Archive.All` → archive **ALLOW**
2. **Host app for the signed-in user** (on-behalf-of) → `scp: Claims.Archive` → archive **ALLOW**
3. **Agent identity, no user** → `roles: Claims.Analyze.All` → analyze **ALLOW**
4. **Agent identity for the signed-in user** (on-behalf-of) → `scp: Claims.Analyze` → analyze **ALLOW**
5. **Negative: agent tries to archive** → holds `Claims.Analyze.All` only → **403**
6. **Negative: host app tries to analyze** → holds `Claims.Archive.All` only → **403**

**B. Agent loop: host app → MCP server → Claims API** (UI tab *Agent runtime loop*; [agent loop](agent-loop.md), [MCP server](mcp-server.md))

Two hops, two checks. Hop 1: the MCP server checks `Mcp.*` on the token minted for it. Hop 2: the
MCP server exchanges that token for its own Claims API token (on-behalf-of when a user is present,
client credentials otherwise) and the Claims API checks `Claims.*` on that. A refusal at hop 1
never reaches the Claims API.

| Chat mode | Token the MCP server checks | analyze_claim | archive_claim | Claims API sees on hop 2 |
| --- | --- | --- | --- | --- |
| Agent identity, app-only | `roles: Mcp.Analyze.All` | ALLOW | DENY at MCP server | MCP server (client credentials) |
| Agent identity on behalf of user | `scp: Mcp.Analyze`, `oid` = user | ALLOW | DENY at MCP server | MCP server as actor, user as subject (OBO) |
| Host app on behalf of user | `scp: Mcp.Archive`, `oid` = user | DENY at MCP server | ALLOW | MCP server as actor, user as subject (OBO) |
| Host app, app-only | `roles: Mcp.Archive.All` | DENY at MCP server | ALLOW | MCP server (client credentials) |

Three things to point at when presenting:

- **Same operation, different actor.** Scenarios 1 and 3 both succeed, but the Claims API logs a
  different `azp`/`oid`: the host app in one, the agent identity in the other.
- **The permission kind follows the user, not the code.** `roles` when no user is present,
  `scp` plus the user's `oid` when one is. The same identity can hold both.
- **The MCP server is a resource, not a relay.** It holds its own permissions, decides on them
  first, and never forwards the token it received, so the Claims API sees the MCP server as actor.
