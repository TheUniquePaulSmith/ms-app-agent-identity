#requires -Version 7.0
<#
.SYNOPSIS
    Gateway-only Entra setup for the "Local LLM & Gateway MCP" scenario (docs/gateway.md). Run it after
    Deploy-GatewayPoc.ps1; every step is idempotent.

.DESCRIPTION
    The test agents, test users and PDP groups come from Configure-Entra.ps1 -TestAgents -TestUsers
    (docs/test-identities.md). This script adds what only the gateway needs:

      1. MCP server registration: accessToken optional claims xms_par_app_azp, xms_act_fct and
         xms_sub_fct, so tokens for the MCP server say "this caller is an agent of blueprint X".
      2. Microsoft Graph application permissions for the deployed managed identities
           <prefix>-killswitch-workflow  AgentIdentity.EnableDisable.All  (disable/enable in Entra)
           <prefix>-killswitch           Application.Read.All             (drift sync)
           <prefix>-pdp                  GroupMember.Read.All +
                                         User.ReadBasic.All               (group membership PIP)

    Run in a normal PowerShell 7 prompt:   .\Configure\Configure-GatewayEntra.ps1
    Tenant and MCP server ids come from appsettings.json, the name prefix from GatewayMcp:PdpUrl
    (written by Deploy-GatewayPoc.ps1), unless passed as parameters.

.NOTES
    Needs the Microsoft.Graph PowerShell module and an admin who can grant application permissions
    (Cloud Application Administrator or Privileged Role Administrator, or Global Admin).
#>
[CmdletBinding()]
param(
    # Ids default to the values in appsettings.json; pass them to override (nothing is hard-coded).
    [string] $TenantId,
    [string] $McpAppId,
    # Same -NamePrefix as Deploy-GatewayPoc.ps1. Defaults to the prefix in appsettings.json GatewayMcp:PdpUrl.
    [string] $NamePrefix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root      = Split-Path -Parent $PSScriptRoot
$graph     = "https://graph.microsoft.com/v1.0"
$appsPath  = Join-Path $root "appsettings.json"

# Read-JsonWithComments, Resolve-Setting
. (Join-Path $PSScriptRoot "GatewayConfigFiles.ps1")

$TenantId   = Resolve-Setting $TenantId "TenantId" $appsPath "HostApplication:TenantId", "AgentBlueprint:TenantId"
$McpAppId   = Resolve-Setting $McpAppId "McpAppId" $appsPath "McpServer:ClientId"
$NamePrefix = try { Resolve-Setting $NamePrefix "NamePrefix" $appsPath "GatewayMcp:PdpUrl" -Pattern '^https://([a-z0-9]+)-pdp\.' } catch { "" }

$requiredScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All"
)
# Reuse the current Graph session when it already holds every scope. Otherwise sign in; on Windows
# that is a WAM prompt, plus a consent page the first time these scopes are requested.
$context = Get-MgContext
$sameTenant = $context -and (-not ($TenantId -as [guid]) -or $context.TenantId -eq $TenantId)
# Outer @(): an if statement that yields an empty array assigns $null, and StrictMode throws on $null.Count.
$missingScopes = @(if ($context) { $requiredScopes | Where-Object { @($context.Scopes) -notcontains $_ } } else { $requiredScopes })
if ($sameTenant -and $missingScopes.Count -eq 0) {
    Write-Host "Reusing Microsoft Graph session ($($context.Account))" -ForegroundColor Cyan
}
else {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes $requiredScopes
}

# ---------------------------------------------------------------------------
# 1. Optional claims on the MCP server registration
# ---------------------------------------------------------------------------
Write-Host "`n[1] MCP server registration: agent optional claims in access tokens" -ForegroundColor Cyan
$mcpApp = Invoke-MgGraphRequest -Method GET -Uri "$graph/applications(appId='$McpAppId')?`$select=id,optionalClaims"
# optionalClaims is null on a registration that never had any (StrictMode would throw on .accessToken).
$existingOptional = if ($mcpApp.optionalClaims) { $mcpApp.optionalClaims } else { @{} }
# Leading comma: return the array itself, so an empty list stays [] instead of becoming $null.
$claimsOf = { param($kind) if ($existingOptional.ContainsKey($kind) -and $existingOptional[$kind]) { , @($existingOptional[$kind]) } else { , @() } }
$accessClaims = & $claimsOf "accessToken"
$wanted = @("xms_par_app_azp", "xms_act_fct", "xms_sub_fct")
$missing = @($wanted | Where-Object { $n = $_; -not ($accessClaims | Where-Object { $_.name -eq $n }) })
if ($missing.Count -eq 0) {
    Write-Host "    already emitted: $($wanted -join ', ')" -ForegroundColor Green
}
else {
    $newClaims = @($accessClaims) + @($missing | ForEach-Object { @{ name = $_; essential = $false; additionalProperties = @() } })
    $optional = @{
        accessToken = $newClaims
        idToken     = & $claimsOf "idToken"
        saml2Token  = & $claimsOf "saml2Token"
    }
    Invoke-MgGraphRequest -Method PATCH -ContentType "application/json" -Uri "$graph/applications/$($mcpApp.id)" `
        -Body (@{ optionalClaims = $optional } | ConvertTo-Json -Depth 6) | Out-Null
    Write-Host "    added: $($missing -join ', ')" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 2. Graph application permissions for the managed identities (after deployment)
# ---------------------------------------------------------------------------
Write-Host "`n[2] Managed identities -> Microsoft Graph application permissions" -ForegroundColor Cyan
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$miPlan = @(
    @{ name = "$NamePrefix-killswitch-workflow"; permission = "AgentIdentity.EnableDisable.All"; why = "disable / enable the agent in Entra" }
    @{ name = "$NamePrefix-killswitch";          permission = "Application.Read.All";            why = "drift sync (accountEnabled)" }
    @{ name = "$NamePrefix-pdp";                 permission = "GroupMember.Read.All";            why = "group membership (checkMemberGroups)" }
    # /users/{id}/checkMemberGroups (app-only) needs User.ReadBasic.All AND GroupMember.Read.All.
    @{ name = "$NamePrefix-pdp";                 permission = "User.ReadBasic.All";              why = "checkMemberGroups on a user object" }
)
$pending = 0
if (-not $NamePrefix) {
    Write-Host "    skipped: pass -NamePrefix (the one given to Deploy-GatewayPoc.ps1), or re-run after deployment" -ForegroundColor Yellow
    $pending++
    $miPlan = @()
}
foreach ($mi in $miPlan) {
    $sp = Get-MgServicePrincipal -Filter "displayName eq '$($mi.name)' and servicePrincipalType eq 'ManagedIdentity'" | Select-Object -First 1
    if (-not $sp) {
        Write-Host "    $($mi.name): not deployed yet (re-run after Deploy-GatewayPoc.ps1)" -ForegroundColor Yellow
        $pending++
        continue
    }
    $appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq $mi.permission -and $_.AllowedMemberTypes -contains "Application" } | Select-Object -First 1
    if (-not $appRole) { throw "Microsoft Graph has no application permission $($mi.permission) in this tenant." }
    $has = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id | Where-Object { $_.AppRoleId -eq $appRole.Id -and $_.ResourceId -eq $graphSp.Id }
    if ($has) { Write-Host "    $($mi.name): $($mi.permission) already granted" -ForegroundColor Green }
    else {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $appRole.Id | Out-Null
        Write-Host "    $($mi.name): granted $($mi.permission) ($($mi.why))" -ForegroundColor Green
    }
}

Write-Host ""
if ($pending) {
    Write-Host "Next: run .\Configure\Deploy-GatewayPoc.ps1, then run this script again for step 2." -ForegroundColor Cyan
}
else {
    Write-Host "Done. Test agents, users and the PDP registry: .\Configure\Configure-Entra.ps1 -TestAgents -TestUsers (docs/test-identities.md)." -ForegroundColor Cyan
}
