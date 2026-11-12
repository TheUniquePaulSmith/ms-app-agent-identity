#requires -Version 7.0
<#
.SYNOPSIS
    Creates and wires up the "POC Claims MCP Server" app registration (docs/mcp-server.md).

.DESCRIPTION
    The MCP server is an OAuth resource server (clients get tokens FOR it) and an OAuth client of
    the Claims API (it exchanges those tokens with its own credential). Each step is idempotent:

      1. App registration: v2 access tokens, identifier URI api://<app-id> (plus -PublicUrl when
         given), delegated scopes Mcp.Analyze / Mcp.Archive, app roles Mcp.Analyze.All /
         Mcp.Archive.All, a service principal, and a client secret (printed once; -NewSecret mints another).
      2. MCP server -> Claims API: app roles Claims.Analyze.All and Claims.Archive.All assigned to the
         MCP server principal (app-only path), delegated Claims.Analyze + Claims.Archive granted for
         all users (on-behalf-of path).
      3. Callers -> MCP server: agent identity gets Mcp.Analyze.All + Mcp.Analyze; host app gets
         Mcp.Archive.All + Mcp.Archive. The agent still cannot archive and the host still cannot
         analyze, but the decision now happens at the MCP server.
      4. Prints the values for claims-mcp/config.json and the McpServer section of appsettings.json.

    Run it in a normal PowerShell 7 prompt:  .\Configure\Configure-McpEntra.ps1 [-PublicUrl https://mcp.contoso.com] [-NewSecret]

.NOTES
    Needs the Microsoft.Graph PowerShell module and a user who can create app registrations and
    grant application permissions (for example Cloud Application Administrator).
#>
[CmdletBinding()]
param(
    # Ids default to the values in appsettings.json; pass them to override (nothing is hard-coded).
    [string] $TenantId,
    [string] $ClaimsApiAppId,
    [string] $HostAppId,
    [string] $AgentIdentityId,
    [string] $DisplayName     = "POC Claims MCP Server",
    [string] $PublicUrl       = "",
    [switch] $NewSecret
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$graph = "https://graph.microsoft.com/v1.0"
$appsPath = Join-Path (Split-Path -Parent $PSScriptRoot) "appsettings.json"

# Read-JsonWithComments, Resolve-Setting
. (Join-Path $PSScriptRoot "GatewayConfigFiles.ps1")

$TenantId        = Resolve-Setting $TenantId        "TenantId"        $appsPath "HostApplication:TenantId", "AgentBlueprint:TenantId"
$ClaimsApiAppId  = Resolve-Setting $ClaimsApiAppId  "ClaimsApiAppId"  $appsPath "DownstreamApis:ClaimsApiAsAgent:Scopes:0"
$HostAppId       = Resolve-Setting $HostAppId       "HostAppId"       $appsPath "HostApplication:ClientId"
$AgentIdentityId = Resolve-Setting $AgentIdentityId "AgentIdentityId" $appsPath "AgentIdentity:ClientId"

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All"
)

$claimsApiSp = Get-MgServicePrincipal -Filter "appId eq '$ClaimsApiAppId'"
$hostSp      = Get-MgServicePrincipal -Filter "appId eq '$HostAppId'"
if (-not $claimsApiSp) { throw "No service principal for Claims API $ClaimsApiAppId." }
if (-not $hostSp)      { throw "No service principal for host app $HostAppId." }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Ensure-AppRoleAssignment([string] $Label, [string] $PrincipalId, $ResourceSp, [string] $RoleValue) {
    $role = $ResourceSp.AppRoles | Where-Object Value -eq $RoleValue | Select-Object -First 1
    if (-not $role) { throw "$($ResourceSp.DisplayName) has no app role '$RoleValue'." }
    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -ErrorAction SilentlyContinue |
        Where-Object { $_.AppRoleId -eq $role.Id -and $_.ResourceId -eq $ResourceSp.Id }
    if ($existing) {
        Write-Host "    $Label already has app role $RoleValue on $($ResourceSp.DisplayName)" -ForegroundColor Green
    }
    else {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -PrincipalId $PrincipalId -ResourceId $ResourceSp.Id -AppRoleId $role.Id | Out-Null
        Write-Host "    assigned app role $RoleValue on $($ResourceSp.DisplayName) to $Label" -ForegroundColor Green
    }
}

function Ensure-DelegatedGrant([string] $Label, [string] $ClientSpId, $ResourceSp, [string[]] $Scopes) {
    foreach ($s in $Scopes) {
        if (-not ($ResourceSp.Oauth2PermissionScopes | Where-Object Value -eq $s)) { throw "$($ResourceSp.DisplayName) has no delegated scope '$s'." }
    }
    # Plain Graph calls (Microsoft.Graph.Authentication only): the *-MgOauth2PermissionGrant cmdlets
    # live in Microsoft.Graph.Identity.SignIns, which does not always auto-load.
    $grant = @((Invoke-MgGraphRequest -Method GET `
        -Uri "$graph/oauth2PermissionGrants?`$filter=clientId eq '$ClientSpId' and resourceId eq '$($ResourceSp.Id)'").value) |
        Select-Object -First 1
    if ($grant) {
        $have = @($grant.scope -split " " | Where-Object { $_ })
        $missing = @($Scopes | Where-Object { $have -notcontains $_ })
        if ($missing.Count -eq 0) {
            Write-Host "    $Label already granted '$($grant.scope)' on $($ResourceSp.DisplayName)" -ForegroundColor Green
        }
        else {
            Invoke-MgGraphRequest -Method PATCH -ContentType "application/json" -Uri "$graph/oauth2PermissionGrants/$($grant.id)" `
                -Body (@{ scope = (($have + $missing) -join " ") } | ConvertTo-Json) | Out-Null
            Write-Host "    added '$($missing -join ' ')' to the $Label grant on $($ResourceSp.DisplayName)" -ForegroundColor Green
        }
    }
    else {
        $body = @{ clientId = $ClientSpId; consentType = "AllPrincipals"; resourceId = $ResourceSp.Id; scope = ($Scopes -join " ") } | ConvertTo-Json
        Invoke-MgGraphRequest -Method POST -ContentType "application/json" -Uri "$graph/oauth2PermissionGrants" -Body $body | Out-Null
        Write-Host "    created grant: $Label -> '$($Scopes -join ' ')' on $($ResourceSp.DisplayName)" -ForegroundColor Green
    }
}

function New-Scope([string] $Value, [string] $Verb) {
    @{
        id                      = [guid]::NewGuid().ToString()
        value                   = $Value
        type                    = "User"
        isEnabled               = $true
        adminConsentDisplayName = "$Verb claims through the MCP server as the signed-in user"
        adminConsentDescription = "Allows the application to $($Verb.ToLower()) claims through the POC Claims MCP Server on behalf of the signed-in user."
        userConsentDisplayName  = "$Verb claims through the MCP server on your behalf"
        userConsentDescription  = "Allows the application to $($Verb.ToLower()) claims through the POC Claims MCP Server on your behalf."
    }
}

function New-Role([string] $Value, [string] $Verb) {
    @{
        id                 = [guid]::NewGuid().ToString()
        value              = $Value
        displayName        = $Value
        description        = "Allows the application to $($Verb.ToLower()) claims through the POC Claims MCP Server without a signed-in user."
        allowedMemberTypes = @("Application")
        isEnabled          = $true
    }
}

# ---------------------------------------------------------------------------
# 1. App registration for the MCP server
# ---------------------------------------------------------------------------
Write-Host "`n[1] App registration '$DisplayName'" -ForegroundColor Cyan
$app = Get-MgApplication -Filter "displayName eq '$DisplayName'" | Select-Object -First 1
if ($app) {
    Write-Host "    found: appId $($app.AppId), object $($app.Id)"
}
else {
    $app = New-MgApplication -DisplayName $DisplayName -SignInAudience "AzureADMyOrg"
    Write-Host "    created: appId $($app.AppId), object $($app.Id)" -ForegroundColor Green
}
$mcpAppId = $app.AppId

# v2 tokens first (an https identifier URI is only allowed once this is set).
Invoke-MgGraphRequest -Method PATCH -ContentType "application/json" -Uri "$graph/applications/$($app.Id)" `
    -Body (@{ api = @{ requestedAccessTokenVersion = 2 } } | ConvertTo-Json -Depth 5) | Out-Null

$current = Invoke-MgGraphRequest -Method GET -Uri "$graph/applications/$($app.Id)`?`$select=identifierUris,api,appRoles,requiredResourceAccess"

$uris = @("api://$mcpAppId")
if ($PublicUrl) { $uris += $PublicUrl.TrimEnd("/") }
foreach ($u in @($current.identifierUris)) { if ($uris -notcontains $u) { $uris += $u } }

$scopes = @($current.api.oauth2PermissionScopes | ForEach-Object { $_ })
if (-not ($scopes | Where-Object { $_.value -eq "Mcp.Analyze" })) { $scopes += New-Scope "Mcp.Analyze" "Analyze" }
if (-not ($scopes | Where-Object { $_.value -eq "Mcp.Archive" })) { $scopes += New-Scope "Mcp.Archive" "Archive" }

$roles = @($current.appRoles | ForEach-Object { $_ })
if (-not ($roles | Where-Object { $_.value -eq "Mcp.Analyze.All" })) { $roles += New-Role "Mcp.Analyze.All" "Analyze" }
if (-not ($roles | Where-Object { $_.value -eq "Mcp.Archive.All" })) { $roles += New-Role "Mcp.Archive.All" "Archive" }

# API permissions the MCP server consumes on the Claims API (portal display; the grants below are what matter).
$claimsScopeIds = @("Claims.Analyze", "Claims.Archive") | ForEach-Object {
    $def = $claimsApiSp.Oauth2PermissionScopes | Where-Object Value -eq $_ | Select-Object -First 1
    if (-not $def) { throw "Claims API has no delegated scope '$_' (docs/entra-setup.md 4A.1)." }
    @{ id = $def.Id; type = "Scope" }
}
$claimsRoleIds = @("Claims.Analyze.All", "Claims.Archive.All") | ForEach-Object {
    $def = $claimsApiSp.AppRoles | Where-Object Value -eq $_ | Select-Object -First 1
    if (-not $def) { throw "Claims API has no app role '$_' (docs/entra-setup.md 4A.2)." }
    @{ id = $def.Id; type = "Role" }
}

$body = @{
    identifierUris         = $uris
    api                    = @{ requestedAccessTokenVersion = 2; oauth2PermissionScopes = $scopes }
    appRoles               = $roles
    requiredResourceAccess = @(@{ resourceAppId = $ClaimsApiAppId; resourceAccess = @($claimsScopeIds + $claimsRoleIds) })
} | ConvertTo-Json -Depth 8
Invoke-MgGraphRequest -Method PATCH -ContentType "application/json" -Uri "$graph/applications/$($app.Id)" -Body $body | Out-Null
Write-Host ("    identifier URIs: {0}" -f ($uris -join ", ")) -ForegroundColor Green
Write-Host ("    scopes: {0} | app roles: {1}" -f (($scopes | ForEach-Object value) -join ", "), (($roles | ForEach-Object value) -join ", ")) -ForegroundColor Green

$mcpSp = Get-MgServicePrincipal -Filter "appId eq '$mcpAppId'"
if (-not $mcpSp) {
    $mcpSp = New-MgServicePrincipal -AppId $mcpAppId
    Write-Host "    created service principal $($mcpSp.Id)" -ForegroundColor Green
}
else {
    Write-Host "    service principal $($mcpSp.Id)"
}
# Re-read so AppRoles / Oauth2PermissionScopes reflect the PATCH.
$mcpSp = Get-MgServicePrincipal -ServicePrincipalId $mcpSp.Id

$secretText = $null
$app = Get-MgApplication -ApplicationId $app.Id
if ($NewSecret -or -not $app.PasswordCredentials) {
    $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{ displayName = "poc-mcp"; endDateTime = (Get-Date).AddMonths(6) }
    $secretText = $secret.SecretText
    Write-Host "    minted client secret (shown once below)" -ForegroundColor Green
}
else {
    Write-Host "    existing client secret kept (use -NewSecret to mint another)"
}

# ---------------------------------------------------------------------------
# 2. MCP server -> Claims API (what the exchanged token can carry)
# ---------------------------------------------------------------------------
Write-Host "`n[2] MCP server permissions on the Claims API" -ForegroundColor Cyan
Ensure-AppRoleAssignment "MCP server" $mcpSp.Id $claimsApiSp "Claims.Analyze.All"
Ensure-AppRoleAssignment "MCP server" $mcpSp.Id $claimsApiSp "Claims.Archive.All"
Ensure-DelegatedGrant    "MCP server" $mcpSp.Id $claimsApiSp @("Claims.Analyze", "Claims.Archive")

# ---------------------------------------------------------------------------
# 3. Callers -> MCP server (what the inbound token can carry)
# ---------------------------------------------------------------------------
Write-Host "`n[3] Caller permissions on the MCP server" -ForegroundColor Cyan
Ensure-AppRoleAssignment "agent identity" $AgentIdentityId $mcpSp "Mcp.Analyze.All"
Ensure-DelegatedGrant    "agent identity" $AgentIdentityId $mcpSp @("Mcp.Analyze")
Ensure-AppRoleAssignment "host app"       $hostSp.Id       $mcpSp "Mcp.Archive.All"
Ensure-DelegatedGrant    "host app"       $hostSp.Id       $mcpSp @("Mcp.Archive")

# ---------------------------------------------------------------------------
# 4. Values to paste
# ---------------------------------------------------------------------------
Write-Host "`n[4] Configuration" -ForegroundColor Cyan
Write-Host "    claims-mcp/config.json (or env vars):"
Write-Host "      MCP_CLIENT_ID     = $mcpAppId"
Write-Host ("      MCP_CLIENT_SECRET = {0}" -f ($(if ($secretText) { $secretText } else { "<existing secret>" })))
Write-Host "      TENANT_ID         = $TenantId"
Write-Host "      CLAIMS_API_APP_ID = $ClaimsApiAppId"
Write-Host "    appsettings.json:"
Write-Host "      McpServer:ClientId = $mcpAppId   (scope defaults to api://$mcpAppId/.default)"
Write-Host "    claims-api (optional, labels the MCP server in its console):"
Write-Host "      KNOWN_MCP_APP_IDS = $mcpAppId"
if (-not $PublicUrl) {
    Write-Host "`n    Note: Entra cannot register http://localhost as an identifier URI, so third-party MCP clients that send" -ForegroundColor DarkGray
    Write-Host "    resource=http://localhost:5002/mcp will get AADSTS9010010. The host app requests api://$mcpAppId/.default" -ForegroundColor DarkGray
    Write-Host "    instead. Re-run with -PublicUrl https://<your-host> once the server has an HTTPS address." -ForegroundColor DarkGray
}
Write-Host "`nDone. Grants can take a minute or two to show up in new tokens." -ForegroundColor Cyan
