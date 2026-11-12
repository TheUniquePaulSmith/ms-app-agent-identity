# 8. The MCP server as its own OAuth resource (no token passthrough)

[← Back to README](../README.md)

The MCP authorization specification (revision 2026-07-28) makes four things mandatory for an HTTP
MCP server, and the first version of this POC met only the first:

| Requirement | Spec wording | How the POC does it now |
| --- | --- | --- |
| Discovery | Servers **MUST** serve RFC 9728 protected resource metadata and point to it from the 401 `WWW-Authenticate` header | `GET /.well-known/oauth-protected-resource` names the tenant's v2.0 issuer and the `Mcp.*` scopes; every 401 carries `resource_metadata` and `scope` |
| Audience binding | Servers **MUST** validate that the token was issued for them (RFC 8707); invalid tokens get 401 | `jose` verifies signature (tenant JWKS), issuer, tenant, `aud` = the MCP server's client id, expiry |
| No passthrough | "The MCP server **MUST NOT** pass through the token it received from the MCP client" | The inbound token never leaves the MCP server. `@azure/msal-node` obtains a Claims API token with the MCP server's own credential |
| Client identity | Dynamic Client Registration is deprecated; pre-registration is a supported option | Entra supports neither DCR nor Client ID Metadata Documents, so the host app and the agent blueprint stay pre-registered confidential clients |

## 8A. Entra objects

`Configure/Configure-McpEntra.ps1` creates and wires everything (idempotent; run it from a normal
PowerShell 7 prompt):

| Object | What the script does |
| --- | --- |
| App registration **POC Claims MCP Server** | `requestedAccessTokenVersion = 2`; identifier URI `api://<mcp-app-id>` (plus `-PublicUrl https://...` when the server has an HTTPS address); delegated scopes `Mcp.Analyze`, `Mcp.Archive`; app roles `Mcp.Analyze.All`, `Mcp.Archive.All` (Applications); a client secret |
| MCP server principal → Claims API | app roles `Claims.Analyze.All` + `Claims.Archive.All` (for the app-only path) and delegated `Claims.Analyze` + `Claims.Archive` for all users (for the on-behalf-of path) |
| Agent identity → MCP server | app role `Mcp.Analyze.All` + delegated `Mcp.Analyze` |
| Host app → MCP server | app role `Mcp.Archive.All` + delegated `Mcp.Archive` |

The script prints the values to paste into `claims-mcp/config.json` (git-ignored; copy
`config.sample.json`) or
the `MCP_CLIENT_ID` / `MCP_CLIENT_SECRET` environment variables, into `McpServer:ClientId` in
`appsettings.json`, and optionally into `KNOWN_MCP_APP_IDS` for the mock Claims API so its console
labels the MCP server as an intermediary.

## 8B. What changes in the tokens

| Hop | Token audience | Actor (`azp`) | Subject (`oid`) | Permission claim |
| --- | --- | --- | --- | --- |
| Host app → MCP server (app-only) | MCP server | agent identity or host app | the same principal | `roles: Mcp.Analyze.All` or `Mcp.Archive.All` |
| Host app → MCP server (delegated) | MCP server | agent identity or host app | user | `scp: Mcp.Analyze` or `Mcp.Archive` |
| MCP server → Claims API (from app-only) | Claims API | **MCP server** (client credentials) | MCP server | `roles: Claims.Analyze.All Claims.Archive.All` |
| MCP server → Claims API (from delegated) | Claims API | **MCP server** (on-behalf-of) | user | `scp: Claims.Analyze Claims.Archive` |

Two consequences worth saying out loud when presenting:

- The **agent-vs-host decision moves to the MCP server.** The Claims API cannot tell whether an
  agent or the host app asked, because the MCP server is the actor on every exchanged token. The
  MCP server enforces `Mcp.*` per tool before it exchanges anything, so "agent cannot archive" and
  "host cannot analyze" still hold, and the trace shows the 403 with `decidedBy: mcp-server`.
- Entra has **no app-only on-behalf-of**. A delegated inbound token keeps the user as subject
  through the OBO exchange; an app-only inbound token cannot be exchanged for "the agent at the
  Claims API", so the MCP server calls the Claims API as itself. If the downstream API must know
  the original agent, the MCP server has to be the resource that authorizes it (as here), or the
  MCP server and the API must share one registration and one trust boundary.

## 8C. Localhost limitation

Entra will not register `http://localhost:5002/mcp` as an identifier URI, so the `resource`
value in the metadata document (the server URL, as RFC 9728 requires) does not match any
identifier URI in Entra. The host app side-steps this by requesting the scope
`api://<mcp-app-id>/.default`, which is how Entra identifies the resource; a third-party MCP
client that sends `resource=http://localhost:5002/mcp` would get `AADSTS9010010`. Give the server
an HTTPS address and re-run the script with `-PublicUrl` to remove the mismatch.

## 8D. Verification

| Check | Command or place | Expect |
| --- | --- | --- |
| Metadata | `curl http://localhost:5002/.well-known/oauth-protected-resource` | `resource`, `authorization_servers` = tenant v2.0 issuer, `scopes_supported: [Mcp.Analyze, Mcp.Archive]` |
| Challenge | `curl -i -X POST http://localhost:5002/mcp` without a token | 401 with `WWW-Authenticate: Bearer resource_metadata=..., scope=...` |
| Audience | call `/mcp` with a **Claims API** token (the old behaviour) | 401 `invalid_token` naming the wrong `aud` |
| Grants | `Configure/Configure-McpEntra.ps1` output, steps [2] and [3] | all "already" or "created" lines |
| Two hops | UI → Agent runtime loop → "Analyze CLAIM-1001" as agent, app-only | Hop 1 `azp` = agent identity, Hop 2 `azp` = MCP server, ALLOW |
| Decision at the MCP server | same mode, "Archive CLAIM-1001" | DENY 403 from mcp-server, exchange row "denied before exchange" |
