# 4. Entra setup, step by step

[← Back to README](../README.md)

Portal where the portal can do it, Microsoft Graph PowerShell where it cannot.

Shortcut: `Configure/Configure-Entra.ps1` performs the Graph-only parts ([4C](#4c-poc-claims-analysis-agent-blueprint).3 blueprint URI and
scope, [4B](#4b-poc-claims-web-the-host-application) host-app grant on the blueprint, [4D](#4d-poc-claims-analysis-agent-the-agent-identity) direct agent grants with `-AssignAgentPermissions`)
and prints every grant the agent identity, blueprint principal and host app currently hold.
Run it from a normal PowerShell 7 prompt, not through nested `pwsh -Command` quoting.
It reads the tenant and app ids from your local `appsettings.json` (create it first: [section 5](run-locally.md),
step 1), or takes them as parameters (`-TenantId`, `-HostAppId`, `-BlueprintAppId`,
`-AgentIdentityId`, `-ClaimsApiAppId`). With `-TestAgents -TestUsers` it also creates the test
agents, users and groups of [4F](#4f-test-users-and-agents).

For the manual PowerShell steps:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -TenantId {Agent Tenant ID} -Scopes "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All","DelegatedPermissionGrant.ReadWrite.All","AgentIdentityBlueprint.UpdateAuthProperties.All","AgentIdentityBlueprint.AddRemoveCreds.All"
```

Variables used below:

```powershell
$tenantId      = "{Agent Tenant ID}"
$claimsApiAppId = "{Client API GUID}"
$hostAppId      = "{Host App Client GUID}"
$blueprintAppId = "{Agent Blueprint Client GUID}"
$blueprintObjId = "{Agent Blueprint Client GUID}"   # blueprint APPLICATION object id == its app id
$blueprintSpId  = "{Agent Blueprint Principal GUID}"   # blueprint PRINCIPAL (service principal) object id
$agentId        = "{Agent Identity Client GUID}"   # agent identity (app id == object id)

$claimsApiSp  = Get-MgServicePrincipal -Filter "appId eq '$claimsApiAppId'"
$hostSp       = Get-MgServicePrincipal -Filter "appId eq '$hostAppId'"
$blueprintSp  = Get-MgServicePrincipal -Filter "appId eq '$blueprintAppId'"   # .Id == $blueprintSpId
$graphHeaders = @{ "OData-Version" = "4.0" }   # required on agent blueprint requests
```

## 4A. POC Claims API (the resource)

Portal → App registrations → POC Claims API:

1. **Expose an API**
   - Application ID URI: `api://{Client API GUID}` (accept the default).
   - Add a scope `Claims.Archive`: who can consent *Admins and users*, display name "Archive claims as the signed-in user".
   - Add a scope `Claims.Analyze`: same, "Analyze claims as the signed-in user".
2. **App roles** → Create app role, twice:
   - Display name `Claims.Archive.All`, allowed member types **Applications**, value `Claims.Archive.All`.
   - Display name `Claims.Analyze.All`, allowed member types **Applications**, value `Claims.Analyze.All`.
3. **Manifest**: set `"requestedAccessTokenVersion": 2` (Microsoft Graph manifest format; the
   older format calls it `accessTokenAcceptedVersion`). This switches issued tokens from v1
   (`appid`, `iss = sts.windows.net`) to v2 (`azp`, `iss = login.microsoftonline.com/.../v2.0`).
4. **Token configuration** → Add optional claim → token type *Access* → `idtyp`. This makes
   app-only tokens carry `idtyp: app`.
5. Agent facet claims (`xms_par_app_azp`, `xms_act_fct`, `xms_sub_fct`) are documented as
   optional claims for agent tokens. If the Token configuration picker does not list them,
   try adding them through the manifest:
   ```json
   "optionalClaims": { "accessToken": [ { "name": "idtyp" }, { "name": "xms_par_app_azp" }, { "name": "xms_act_fct" }, { "name": "xms_sub_fct" } ] }
   ```
   If Entra rejects a name, remove it. The mock API still labels the agent correctly through
   its `KNOWN_AGENT_APP_IDS` fallback and reports `agentDetectedBy` so you can see which signal it used.
6. Optional hardening demo: Enterprise applications → POC Claims API → Properties →
   **Assignment required = Yes**. Entra then refuses to issue app-only tokens to any client that
   has no app role on this API (`AADSTS501051`) instead of issuing a token with no `roles`.

## 4B. POC Claims Web (the host application)

Portal → App registrations → POC Claims Web:

1. **Authentication**: platform *Web*, redirect URIs `http://localhost:5094/signin-oidc` and
   `https://localhost:7221/signin-oidc`. ID tokens are not required (auth-code flow with secret).
2. **Certificates & secrets**: a client secret; its value goes in `HostApplication:ClientCredentials[0]:ClientSecret`.
3. **Expose an API**: Application ID URI `api://{Host App Client GUID}`, scope
   `access_as_user` (Admins and users). The app requests this scope for itself at sign-in
   (token-to-self, no consent needed) and `/auth/token` returns it as `hostToken`.
4. **API permissions** → Add a permission → *APIs my organization uses*:
   - POC Claims API → **Delegated** → `Claims.Archive` (scenario 2).
   - POC Claims API → **Application** → `Claims.Archive.All` (scenario 1).
   - POC Claims Analysis Agent Blueprint → **Delegated** → `access_agent` (scenario 4).
     If the blueprint is not listed in the picker, grant it with Graph or the consent URL below.
   - Click **Grant admin consent for <tenant>**.

   Graph equivalent for the blueprint scope (the host app's `/auth/token` page also prints the admin-consent URL):
   ```powershell
   New-MgOauth2PermissionGrant -ClientId $hostSp.Id -ConsentType "AllPrincipals" -ResourceId $blueprintSp.Id -Scope "access_agent"
   # or: https://login.microsoftonline.com/$tenantId/v2.0/adminconsent?client_id=$hostAppId&scope=api://$blueprintAppId/access_agent
   ```

## 4C. POC Claims Analysis Agent Blueprint

1. Create: Entra admin center → **Entra ID → Agents → Agent blueprints → New agent blueprint**.
   Set a sponsor (required) and an owner. The wizard also creates the blueprint principal.
   (Programmatic: `POST /v1.0/applications/microsoft.graph.agentIdentityBlueprint` then
   `POST /v1.0/serviceprincipals/microsoft.graph.agentIdentityBlueprintPrincipal`.)
2. Credential (requires the *Agent ID Administrator* role for a secret):
   ```powershell
   $secret = Add-MgApplicationPassword -ApplicationId $blueprintObjId -PasswordCredential @{ displayName = "poc"; endDateTime = (Get-Date).AddMonths(6) }
   $secret.SecretText   # -> AgentBlueprint:ClientCredentials[0]:ClientSecret
   ```
   Production guidance is a federated managed identity or certificate, not a secret.
3. Expose the `access_agent` scope (needed only for scenario 4). Use the blueprint's
   **application** object id (equal to its app id), not the principal id, and send the
   `OData-Version` header as the docs do:
   ```powershell
   $body = @{
     identifierUris = @("api://$blueprintAppId")
     api = @{ oauth2PermissionScopes = @(@{
       id = [guid]::NewGuid().ToString(); value = "access_agent"; type = "User"; isEnabled = $true
       adminConsentDisplayName = "Access agent"
       adminConsentDescription = "Allow the application to access the agent on behalf of the signed-in user." }) }
   } | ConvertTo-Json -Depth 6
   Invoke-MgGraphRequest -Method PATCH -Headers $graphHeaders -ContentType "application/json" -Body $body `
     -Uri "https://graph.microsoft.com/v1.0/applications/$blueprintObjId"
   # verify:
   (Invoke-MgGraphRequest -Method GET -Headers $graphHeaders -Uri "https://graph.microsoft.com/v1.0/applications/$blueprintObjId`?`$select=identifierUris,api").identifierUris
   ```
   Symptom of the wrong id: `Request_ResourceNotFound` for `e1dd3704-…`, which is the principal.
4. Permissions for the agent: pick **one** of the two models below (both exist in this tenant
   today; to see which one is in effect, remove one and read the token).

   **Direct grants on the agent identity (recommended for this POC: one agent, inspectable):** see [4D](#4d-poc-claims-analysis-agent-the-agent-identity).

   **Inherited from the blueprint (fleet model: approve once, every agent identity gets it):**
   ```powershell
   # a) declare the Claims API as inheritable (scopes and roles)
   $body = @{ resourceAppId = $claimsApiAppId
              inheritableScopes = @{ "@odata.type" = "#microsoft.graph.allAllowedScopes"; kind = "allAllowed" }
              inheritableRoles  = @{ "@odata.type" = "#microsoft.graph.allAllowedRoles";  kind = "allAllowed" } } | ConvertTo-Json -Depth 5
   Invoke-MgGraphRequest -Method POST -Headers $graphHeaders -ContentType "application/json" -Body $body `
     -Uri "https://graph.microsoft.com/v1.0/applications/microsoft.graph.agentIdentityBlueprint/$blueprintObjId/inheritablePermissions"
   # b) an admin consents on the BLUEPRINT PRINCIPAL (opens a browser)
   Start-Process "https://login.microsoftonline.com/$tenantId/v2.0/adminconsent?client_id=$blueprintAppId&scope=api://$claimsApiAppId/Claims.Analyze&role=api://$claimsApiAppId/Claims.Analyze.All"
   ```
   Both conditions are required: the resource must be listed as inheritable **and** the
   permission must be granted on the blueprint principal.

## 4D. POC Claims Analysis Agent (the agent identity)

1. Create: **Entra ID → Agents → Agent identities → New agent identity**, pick the blueprint,
   set sponsor/owner. Put its app (client) id in `AgentIdentity:ClientId`. (Or leave the
   placeholder and let `Configure-Entra.ps1 -TestAgents` create it as Agent1 and write the id.
   The test setup gives it the role-based name *POC Claims Local Analysis Agent (Agent1)*.)
2. Direct grants:
   ```powershell
   # Application permission (scenario 3): app role assignment on the agent identity SP
   $role = $claimsApiSp.AppRoles | Where-Object Value -eq "Claims.Analyze.All"
   New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $agentId -PrincipalId $agentId -ResourceId $claimsApiSp.Id -AppRoleId $role.Id

   # Delegated permission (scenario 4): tenant-wide grant with the agent identity as client
   New-MgOauth2PermissionGrant -ClientId $agentId -ConsentType "AllPrincipals" -ResourceId $claimsApiSp.Id -Scope "Claims.Analyze"
   # or the admin-consent URL with the AGENT IDENTITY as client_id:
   # https://login.microsoftonline.com/$tenantId/v2.0/adminconsent?client_id=$agentId&scope=api://$claimsApiAppId/Claims.Analyze&role=api://$claimsApiAppId/Claims.Analyze.All
   ```
3. Deliberately do **not** grant `Claims.Archive.All` to the agent, and do not grant
   `Claims.Analyze.All` to the host app. The two negative tests depend on that.

## 4E. Verification checklist

| Check | Where | Expect |
| --- | --- | --- |
| Claims API exposes 2 scopes and 2 app roles | App registrations → POC Claims API → Expose an API / App roles | `Claims.Archive`, `Claims.Analyze` / `Claims.Archive.All`, `Claims.Analyze.All` |
| Host app grants | Enterprise applications → POC Claims Web → Permissions | `Claims.Archive` (delegated), `Claims.Archive.All` (application), `access_agent` (delegated) |
| Agent direct grants | `Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $agentId` and `Get-MgOauth2PermissionGrant -Filter "clientId eq '$agentId'"` | one role assignment to the Claims API, one grant with scope `Claims.Analyze` |
| Blueprint inheritance (if used) | `GET /v1.0/applications/microsoft.graph.agentIdentityBlueprint/$blueprintObjId/inheritablePermissions` (with `OData-Version: 4.0`) | an entry for `$claimsApiAppId` |
| Blueprint exposes `access_agent` | `GET /v1.0/applications/$blueprintObjId?$select=identifierUris,api` | `api://$blueprintAppId` and one scope `access_agent` |
| Token content | run the script ([section 5](run-locally.md)) | see the expected rows below |
| Test users and agents (if created) | output of `Configure-Entra.ps1 -TestAgents -TestUsers` | every line "found", "already" or "created"; User1-3 assigned, User4 not |

## 4F. Test users and agents

The demo uses four test users and four agents. Each one shows a different mix of Entra
permissions and PDP access:

| | Display name | Purpose |
| --- | --- | --- |
| User1 | POC Claims EU Adjuster (User1) | EU adjuster (group *POC Claims Adjusters EU*) |
| User2 | POC Claims US Senior Adjuster (User2) | US adjuster with higher privilege (*POC Claims Adjusters US* + *POC Claims Senior Adjusters*) |
| User3 | POC Claims Agent User, No Adjuster Group (User3) | Assigned to the blueprint and agents, but in no adjuster group: no PDP access |
| User4 | POC Claims Unassigned User (User4) | Not assigned to any agent or the blueprint |
| Agent1 | POC Claims Local Analysis Agent (Agent1) | Local mode: application vs delegated permission on the Claims API |
| Agent2 | POC Claims Limited Gateway Agent (Agent2) | Gateway, registered in the PDP with limited access (autonomous limit 10,000) |
| Agent3 | POC Claims Senior Gateway Agent (Agent3) | Gateway, registered in the PDP with greater access (autonomous limit 50,000) |
| Agent4 | POC Claims Rogue Agent, Unregistered (Agent4) | Bad agent: has the API permissions but is not registered in the PDP |

Users sign in with short names (`poc-claims-user1@<domain>` … `user4`); the display names carry the role.

Create them all (needs User Administrator and Groups Administrator in addition to the roles above):

```powershell
.\Configure\Configure-Entra.ps1 -TestAgents -TestUsers
```

The local tabs only need Agent1 and one signed-in user; the groups and Agents 2-4 matter for the
[gateway](gateway.md). Every permission, group membership and expected decision is listed in
[Test identities](test-identities.md).
