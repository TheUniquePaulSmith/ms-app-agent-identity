# 7. The agent runtime loop (LLM + MCP)

[← Back to README](../README.md)

The second half of the POC runs the same four identities through a real agent loop: a local
OpenAI-compatible model (vLLM) proposes tool calls, the host app decides **which identity**
performs each call, and the Claims API is reached through an **MCP server**.

## Pieces

| Piece | Path | Port | Role |
| --- | --- | --- | --- |
| MCP server | `claims-mcp/server.mjs` | 5002 | Exposes the Claims API as MCP tools `get_claim`, `get_claim_evidence`, `analyze_claim`, `archive_claim` and the resource `claims://{claimId}` (Streamable HTTP, stateless). An OAuth **resource server with its own Entra registration**: validates that the bearer token was issued for it, authorizes on its own `Mcp.*` scopes and app roles, then **exchanges** it (on-behalf-of or client credentials) for a Claims API token. Never forwards the inbound token. Publishes `/.well-known/oauth-protected-resource`. See [section 8](mcp-server.md). |
| Agent loop | `AgentLoopService.cs` | | Mints the token for the chosen identity, connects an MCP client with it, discovers tools, runs the model loop, records a per-tool-call trace. |
| Chat endpoints | `Program.cs` `/chat/{mode}` | 5094 | `host-app`, `agent-app` (anonymous), `host-user`, `agent-user` (bearer, same policies as the direct endpoints). |
| Web UI | `wwwroot/` | 5094 | Tabs: Profile & tokens, LLM connection, Application runtime (direct API), Agent runtime loop (chat + trace). |
| Fake LLM | `fake-llm/server.mjs` | 8000 | Optional OpenAI-compatible stand-in for demos without a GPU: maps the prompt to one tool call, then summarises the tool result. |

The model never chooses the identity. The route (`/chat/agent-app` etc.) fixes the
`IdentityMode`, `AgentLoopService.AcquireMcpAuthorizationHeaderAsync` mints exactly one token
for it **with the MCP server as audience** (`api://<mcp-client-id>/.default`), and every MCP
`tools/call` in that turn carries that token. The MCP server validates it, decides on its own
`Mcp.Analyze`/`Mcp.Archive` permissions, and exchanges it for a Claims API token minted with the
MCP server's credential. The Claims API therefore sees the **MCP server** as actor (`azp`); the
agent identity is visible at the MCP server, which is where the agent-vs-host decision now happens.

```
user prompt ─► model ─► tool call proposed ─► host app: identity = IdentityMode ─► token minted (aud = MCP server)
            ◄─ answer ◄─ tool result ◄─ Claims API (roles/scp on the EXCHANGED token) ◄─ MCP server: validate, authorize Mcp.*, exchange (OBO / client credentials) ◄─ MCP client + token
```

Packages: `Microsoft.Extensions.AI` + `Microsoft.Extensions.AI.OpenAI` (any OpenAI-compatible
endpoint via `OpenAIClientOptions.Endpoint`), `ModelContextProtocol` (MCP C# client),
`@modelcontextprotocol/sdk` + `express` + `zod` + `jose` (token validation) + `@azure/msal-node`
(on-behalf-of and client-credential exchanges) for the MCP server.

## Run the full demo

```bash
cd claims-api && npm install && node server.js
```
```bash
cd claims-mcp && npm install && node server.mjs
```
(the MCP server needs its own registration first: [section 8](mcp-server.md), then `claims-mcp/config.json`
(copy `config.sample.json`; `TENANT_ID`, `CLAIMS_API_APP_ID`, `MCP_CLIENT_ID`, `MCP_CLIENT_SECRET`)
or env vars of the same names, and `McpServer:ClientId` in `appsettings.json`)
```bash
dotnet run
```
Then either start vLLM with tool calling enabled (for example
`--enable-auto-tool-choice --tool-call-parser hermes`) on `http://localhost:8000/v1`, or use the stand-in:
```bash
cd fake-llm && node server.mjs
```

Open `http://localhost:5094/`:

1. **Profile & tokens**: sign in, then *Get / refresh tokens*. Both tokens decoded side by side.
2. **LLM connection**: base URL, key, *List models* (fills the model picker from `/v1/models`),
   *Test tool calling* (asks the model to call a `get_server_time` tool and reports whether it did).
3. **Application runtime (direct API)**: the six buttons call the same endpoints as the
   PowerShell script; the panel shows the HTTP status and the claims the Claims API saw.
4. **Agent runtime loop**: pick the identity for tool calls, chat. The trace panel shows, per tool
   call, the tool and arguments, the identity the host app chose, the permission kind, and **two
   hops**: what the MCP server validated (`azp` = chosen identity, `Mcp.*` roles/scp, its ALLOW or
   DENY) and, after the exchange, what the Claims API received (`azp` = MCP server, `Claims.*`
   roles/scp). A DENY is labelled with who refused (`decidedBy`). *Discover via MCP* lists the
   tools the MCP server advertises.

Observed on 22 Oct 2026 with the fake LLM and real tenant tokens, **before** the MCP server got
its own registration (it forwarded the token then):

| Chat mode | "Analyze CLAIM-1001" | "Archive CLAIM-1001" | Claims API saw |
| --- | --- | --- | --- |
| Agent identity, app-only | ALLOW | DENY 403 | `azp` = agent identity, `roles: Claims.Analyze.All` |
| Host application, app-only | DENY 403 | ALLOW | `azp` = host app, `roles: Claims.Archive.All` |

Observed on 23 Oct 2026 after [section 8](mcp-server.md), all rows verified against the tenant with the fake LLM (app-only through /chat/agent-app and /chat/host-app, user-delegated through the signed-in UI; the on-behalf-of hop keeps the user as `oid` and makes the MCP server the `azp`):

| Chat mode | "Analyze CLAIM-1001" | "Archive CLAIM-1001" | MCP server saw | Claims API saw |
| --- | --- | --- | --- | --- |
| Agent identity, app-only | ALLOW | DENY 403 **at the MCP server** | `azp` = agent identity (labelled through the `KNOWN_AGENT_APP_IDS` fallback), `roles: Mcp.Analyze.All` | `azp` = MCP server, `roles: Claims.Analyze.All Claims.Archive.All` |
| Host application, app-only | DENY 403 **at the MCP server** | ALLOW | `azp` = host app, `roles: Mcp.Archive.All` | `azp` = MCP server, same roles |
| Agent identity, user-delegated | ALLOW | DENY 403 at the MCP server | `azp` = agent identity, `oid` = user, `scp: Mcp.Analyze` | `azp` = MCP server, `oid` = user, `scp: Claims.Analyze Claims.Archive` |
| Host application, user-delegated | DENY 403 at the MCP server | ALLOW | `azp` = host app, `oid` = user, `scp: Mcp.Archive` | `azp` = MCP server, `oid` = user, same scp |

The model's answer in the DENY case explains which permission is missing and who refused, because
the MCP tool result carries `decidedBy`, the `required` list and both hops' token summaries.

## Where governance plugs in

The only agent-specific line of code in the host app is
`options.WithAgentIdentity(...)` (in `AgentRuntimeService.cs` for the direct path and in
`AgentLoopService.AcquireMcpAuthorizationHeaderAsync` for the loop). In a production
runtime a policy layer (for example the Agent Governance Toolkit's `GovernanceKernel`) sits between
"model proposed a tool call" and "mint the token" in `AgentLoopService.RunTurnAsync`, allowing or
denying the call before any token exists. The resource enforces OAuth permissions or Azure RBAC on
its own, independently of the policy layer. Two controls, two questions:

- Entra: *can* this agent identity reach this resource? (app roles / scopes / Azure RBAC)
- Runtime policy: *should* this agent run this tool with these arguments right now?

Design notes carried over from Microsoft's guidance:

- One agent identity per logical agent; share a blueprint only among agents that can share a
  credential and a permission baseline.
- Azure RBAC (Key Vault, Storage) is assigned directly to the agent identity at the narrowest
  scope; it is not inherited from the blueprint.
- Use application permissions for autonomous agents and delegated permissions for agents acting
  for a signed-in user. Say "agent identity + application permission" or "agent identity +
  user-delegated permission" rather than "agent delegated permission".
- An MCP server that fronts the Claims API is a resource of its own: it validates tokens issued
  **for it**, reads `azp`, `oid`, `roles`/`scp` and `xms_par_app_azp`, holds its own scopes and
  app roles, and obtains its own token for the next hop. [Section 8](mcp-server.md) implements exactly that.
