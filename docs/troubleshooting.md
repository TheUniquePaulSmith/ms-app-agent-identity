# 6. Troubleshooting

[← Back to README](../README.md)

| Symptom | Cause | Fix |
| --- | --- | --- |
| 403 from the mock with `tokenType: APP-ONLY (no roles claim ...)` | the Claims API defines no app roles, or the client has no app role assignment | [4A step 2](entra-setup.md#4a-poc-claims-api-the-resource), then [4B](entra-setup.md#4b-poc-claims-web-the-host-application) (host) or [4D](entra-setup.md#4d-poc-claims-analysis-agent-the-agent-identity) (agent) |
| `AADSTS500011` resource principal not found | Claims API has no Application ID URI or no service principal in the tenant | [4A step 1](entra-setup.md#4a-poc-claims-api-the-resource); open the registration's Enterprise application once |
| `AADSTS65001` / `MsalUiRequiredException` on scenario 2 or 4 | delegated permission not consented for that client | [4B](entra-setup.md#4b-poc-claims-web-the-host-application) admin consent (host), [4D](entra-setup.md#4d-poc-claims-analysis-agent-the-agent-identity) grant (agent) |
| `AADSTS82014` | you tried interactive consent with the agent identity as client | use the admin-consent URL or the Graph grant in [4D](entra-setup.md#4d-poc-claims-analysis-agent-the-agent-identity), or blueprint inheritance in [4C](entra-setup.md#4c-poc-claims-analysis-agent-blueprint) |
| `agentToken.error` on `/auth/token` | host app not granted `access_agent` on the blueprint, or blueprint has no `access_agent` scope | [4C step 3](entra-setup.md#4c-poc-claims-analysis-agent-blueprint), then [4B](entra-setup.md#4b-poc-claims-web-the-host-application) |
| 401 on `/claims/{id}/agent-analyze-as-user` | the token's audience is the host app, not the blueprint | pass `agentToken`, not `hostToken` |
| 401 on `/claims/{id}/archive-as-user` | token expired, wrong audience, or missing `access_as_user` scope | sign in again at `/auth/sign-in` |
| scenario 3 fails inside token acquisition (FIC / invalid_client) | blueprint secret wrong, or the agent identity was not created from this blueprint | [4C step 2](entra-setup.md#4c-poc-claims-analysis-agent-blueprint); check `AgentIdentity:ClientId` belongs to `AgentBlueprint:ClientId` |
| `callerKind` says host-application for the agent | token has no `xms_par_app_azp` and the agent id is not in `KNOWN_AGENT_APP_IDS` | [4A step 5](entra-setup.md#4a-poc-claims-api-the-resource), or set `KNOWN_AGENT_APP_IDS` when starting the mock |
| `azp` missing, `appid` present, issuer `sts.windows.net` | Claims API issues v1 tokens | [4A step 3](entra-setup.md#4a-poc-claims-api-the-resource) |
| MCP server answers 401 `invalid_token` with `token aud=<claims-api-id>` | the host app still requests a Claims API token for the MCP server | set `McpServer:ClientId` ([section 8A](mcp-server.md#8a-entra-objects)) and restart the host app |
| MCP server answers 401 `invalid_token` "no applicable key" / signature | wrong `TENANT_ID` or `MCP_CLIENT_ID` on the MCP server | match the values printed by `Configure-McpEntra.ps1` |
| tool result `httpStatus: 502, stage: token-exchange` with `AADSTS65001` | MCP server principal not granted `Claims.*` on the Claims API | re-run `Configure-McpEntra.ps1` (step [2]) |
| tool result `httpStatus: 502, stage: token-exchange` with `AADSTS7000215` / `invalid_client` | MCP server secret wrong or expired | `Configure-McpEntra.ps1 -NewSecret` |
| `AADSTS9010010` from a third-party MCP client | it sent `resource=http://localhost:5002/mcp`, which is not an identifier URI | [section 8C](mcp-server.md#8c-localhost-limitation) |
