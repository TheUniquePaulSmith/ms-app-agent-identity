# 5. Run it locally

[← Back to README](../README.md)

1. Create your local settings (both files are git-ignored; nothing in the repo names a tenant):
   ```powershell
   Copy-Item appsettings.sample.json appsettings.json
   Copy-Item claims-api/config.sample.json claims-api/config.json
   ```
   (Or skip this step: `.\Configure\Configure-Entra.ps1 -SetupAll` creates both files, plus
   `claims-mcp/config.json`, and writes every id and secret into them. See [Entra setup](entra-setup.md).)
   Fill every `<placeholder>` in `appsettings.json`: tenant id, the three client ids, the agent
   identity client id, both secrets, and the Claims API app id inside the two `DownstreamApis`
   scopes (the gateway values are written later by the [section 9](gateway.md) scripts). In
   `claims-api/config.json` set `TENANT_ID` and `CLAIMS_API_APP_ID`.
   The `Configure/*.ps1` scripts read the tenant and app ids from `appsettings.json`; pass
   `-TenantId`, `-BlueprintAppId` and so on to override. They have no built-in ids and stop
   with the name of the missing parameter.
   `DownstreamApis:*:AcquireTokenOptions:AuthenticationOptionsName` is what selects **whose
   credential** mints the downstream token: `Bearer` = host application, `AgentBlueprint` =
   blueprint. The code never names a credential; it only names the actor via `WithAgentIdentity`.
2. Start the mock Claims API (it validates every token against the tenant's signing keys:
   signature, issuer `.../<tenant>/v2.0`, `tid`, `aud` = its client id or `api://<client id>`,
   expiry; `TENANT_ID` and `CLAIMS_API_APP_ID` come from `claims-api/config.json`, and
   environment variables of the same name override it; it stops if either is missing):
   ```bash
   cd claims-api
   npm install
   node server.js
   ```
3. Start the host app:
   ```bash
   dotnet run
   ```
4. Get the two user tokens: open `http://localhost:5094/auth/sign-in`, sign in, and you land on
   `/auth/token`, which returns `hostToken`, `agentToken` and a ready-to-paste `powerShell` line.
   If `agentToken.error` is set, the host app has not been granted `access_agent` on the
   blueprint; the response includes the admin-consent URL to fix it.
5. Run the scenarios:
   ```powershell
   .\Tests\Invoke-ClaimsIdentityTests.ps1 -HostToken '<hostToken>' -AgentToken '<agentToken>'
   ```
   Scenarios 1, 3 and both negative cases need no token at all, so you can run the script with
   any placeholder `-HostToken` to check the app-only paths first.

Expected summary once Entra is configured:

| Test | Expected | Result | CallerKind | CallerAppId | Roles | Scp | ParentBlueprint |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1. Host app + application | 200 | PASS | host-application (app-only) | `<host-app-id>` | `Claims.Archive.All` | | |
| 2. Host app + user-delegated | 200 | PASS | user via host-application (delegated) | `<host-app-id>` | | `Claims.Archive` | |
| 3. Agent identity + application | 200 | PASS | agent-identity (app-only) | `<agent-identity-id>` | `Claims.Analyze.All` | | `<blueprint-id>` |
| 4. Agent identity + user-delegated | 200 | PASS | user via agent-identity (delegated) | `<agent-identity-id>` | | `Claims.Analyze` | `<blueprint-id>` |
| Negative: agent tries to archive | 403 | PASS | agent-identity (app-only) | `<agent-identity-id>` | `Claims.Analyze.All` | | `<blueprint-id>` |
| Negative: host tries to analyze | 403 | PASS | host-application (app-only) | `<host-app-id>` | `Claims.Archive.All` | | |

Observed on 21 Oct 2026 after [section 4](entra-setup.md) was applied: **all six cases pass** against the test
tenant, with exactly the rows above. Two details worth pointing out when presenting:

- Scenario 3 and scenario 4 tokens carry the agent identity (`<agent-identity-id>`) as `azp`; scenario 4
  additionally carries the user as `oid` and `scp: Claims.Analyze`. Same actor, different subject.
- The `xms_par_app_azp` parent-blueprint claim was **not** emitted for this custom API even with
  v2 tokens, so the mock labelled the agent through its `KNOWN_AGENT_APP_IDS` fallback
  (`agentDetectedBy` says so). Whether the agent facet claims can be requested as optional
  claims on a custom API is still an open question ([4A](entra-setup.md#4a-poc-claims-api-the-resource) step 5).

Before [section 4](entra-setup.md) (Claims API with no scopes or roles) the same code produced 403s for
scenarios 1 and 3 with `tokenType: APP-ONLY (no roles claim ...)`: the tokens were issued, the
callers were correctly identified, but no permission was present. That is the "before" picture
and a useful contrast for the audience.

The mock prints the full decoded token for every call in its console, which is the most useful
view when presenting: compare the `azp`/`oid` of scenario 1 with scenario 3 side by side.
