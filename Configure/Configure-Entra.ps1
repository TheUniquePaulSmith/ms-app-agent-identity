#requires -Version 7.0
<#
.SYNOPSIS
    Applies the Graph-only parts of docs/entra-setup.md for the agent blueprint and agent identity,
    and optionally creates the POC's app registrations, its test agents (Agent1-4) and test users
    (User1-4) with the Entra groups the PDP policies use.

.DESCRIPTION
    Steps (each is idempotent and prints what it found or changed):

      0. With -TestAppRegs: the app registrations of docs/entra-setup.md 4A-4C, each found by the app
         id in appsettings.json or by display name, created when missing:
           POC Claims API                       v2 tokens, api://<id>, scopes Claims.Archive / Claims.Analyze,
                                                app roles Claims.Archive.All / Claims.Analyze.All, optional
                                                claims idtyp + agent facet claims (4A)
           POC Claims Analysis Agent Blueprint  blueprint + blueprint principal, sponsor and owner the
                                                signed-in admin, a client secret (4C.1-2)
           POC Claims Web                       v2 tokens, redirect URIs http://localhost:5094/signin-oidc and
                                                https://localhost:7221/signin-oidc, api://<id> with scope
                                                access_as_user, a client secret (4B.1-3)
         Writes the tenant id, client ids, scopes and new secrets into appsettings.json (created from
         appsettings.sample.json when missing) and claims-api/config.json. A secret is minted for a new
         registration, when appsettings.json has none, or with -NewSecrets; otherwise it is kept.
      1. Blueprint: set identifier URI api://<blueprint-app-id> and expose the access_agent scope (docs/entra-setup.md 4C.3).
      2. Host app: grant the delegated access_agent scope on the blueprint principal (docs/entra-setup.md 4B).
         With -TestAppRegs also Claims.Archive (delegated) and Claims.Archive.All (application) on the
         Claims API, sign-in consent (openid, profile, offline_access, User.Read) and the API
         permissions list; then the MCP server registration (Configure-McpEntra.ps1 -WriteConfig).
      3. With -TestAgents: the four test agents of docs/test-identities.md, all from the same blueprint:
           Agent1  "POC Claims Local Analysis Agent (Agent1)"       AgentIdentity:ClientId (created when not set yet);
                   direct Claims API grants + MCP grants; the local tabs' agent; not in the PDP
           Agent2  "POC Claims Limited Gateway Agent (Agent2)"      MCP grants; PDP autonomous limit 10,000
           Agent3  "POC Claims Senior Gateway Agent (Agent3)"       MCP grants; PDP autonomous limit 50,000
           Agent4  "POC Claims Rogue Agent, Unregistered (Agent4)"  MCP grants; NOT in the PDP
         Display names describe the role; agents found under an older name are renamed.
         Writes AgentIdentity:ClientId, GatewayMcp:AgentIdentityClientId (Agent2) and
         GatewayAgentIdentities in appsettings.json, and the agent rows of the PDP registry once deployed.
      4. With -TestUsers: the four test users and the PDP groups:
           User1  "POC Claims EU Adjuster (User1)"          Adjusters EU                    assigned to blueprint + agents
           User2  "POC Claims US Senior Adjuster (User2)"   Adjusters US + Senior Adjusters assigned to blueprint + agents
           User3  "POC Claims Agent User, No Adjuster Group (User3)"   no group              assigned to blueprint + agents
           User4  "POC Claims Unassigned User (User4)"      no group                        not assigned to anything
         Users sign in as poc-claims-user<n>@<default domain>; they are created with a one-time
         password unless -User1..-User4 name existing ones (whose display names are left alone). Group membership is made to match the plan for these four
         users (other members are left alone). Writes GatewayMcp:User1ObjectId..User3ObjectId and the
         group and member rows of the PDP registry once deployed.
      5. With -AssignAgentPermissions: the direct Claims API grants on Agent1 only (docs/entra-setup.md 4D).
      6. With -NewAgent "<name>"[, ...]: more agent identities from the same blueprint (MCP grants,
         drop-down entry, PDP registration unless -NotInPdp).
      7. Report the grants held by Agent1, the blueprint principal and the host app.

    Run it in a normal PowerShell 7 prompt:
      .\Configure\Configure-Entra.ps1                                    # steps 1, 2, 7
      .\Configure\Configure-Entra.ps1 -SetupAll                          # everything: same as -TestAppRegs -TestAgents -TestUsers
      .\Configure\Configure-Entra.ps1 -SetupAll -TenantId <tenant id>    # a new tenant, before appsettings.json exists
      .\Configure\Configure-Entra.ps1 -TestAgents -TestUsers             # test identities on existing registrations
      .\Configure\Configure-Entra.ps1 -TestUsers -User1 alice@contoso.com -User2 bob@contoso.com
      .\Configure\Configure-Entra.ps1 -NewAgent "POC Claims Agent 5" -AutonomousLimit 2000

    Run it again after Deploy-GatewayPoc.ps1 to write the test agents, groups and members into the
    PDP registry (the table exists only once deployed).

.NOTES
    Needs: Microsoft.Graph PowerShell module and a user with Agent ID Administrator (or owner of the
    blueprint) plus rights to grant application permissions (for example Cloud Application Administrator).
    -TestAppRegs also needs rights to create app registrations and blueprints (Cloud Application
    Administrator plus Agent ID Administrator, which is required to add the blueprint's secret).
    -TestUsers also needs User Administrator (create users) and Groups Administrator, or Global Admin.
    Creating agents uses the blueprint's client secret from appsettings.json (AgentBlueprint).
    The PDP picks up registry changes within 30 s (it re-reads the PdpEntities table).
#>
[CmdletBinding()]
param(
    # Ids default to the values in appsettings.json; pass them to override (nothing is hard-coded).
    [string]   $TenantId,
    [string]   $ClaimsApiAppId,
    [string]   $HostAppId,
    [string]   $BlueprintAppId,
    [string]   $AgentIdentityId,
    [string]   $McpAppId,
    # Create / update the app registrations (Claims API, blueprint, host app, MCP server).
    [switch]   $TestAppRegs,
    [switch]   $TestAgents,
    [switch]   $TestUsers,
    # Everything: -TestAppRegs -TestAgents -TestUsers.
    [switch]   $SetupAll,
    # With -TestAppRegs: mint new client secrets even where appsettings.json already holds one.
    [switch]   $NewSecrets,
    # Existing users (UPN or object id) to use instead of creating poc-claims-user<n>@<domain>.
    [string]   $User1,
    [string]   $User2,
    [string]   $User3,
    [string]   $User4,
    # Domain for created test users; defaults to the tenant's default verified domain.
    [string]   $UserDomain,
    [switch]   $AssignAgentPermissions,
    [string[]] $NewAgent        = @(),
    [int]      $AutonomousLimit = 10000,
    [switch]   $NotInPdp,
    [switch]   $SkipMcpPermissions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$graphHeaders = @{ "OData-Version" = "4.0" }
$graph = "https://graph.microsoft.com/v1.0"
$root       = Split-Path -Parent $PSScriptRoot
$appsPath   = Join-Path $root "appsettings.json"

# Read-JsonWithComments, Resolve-Setting, Set-AppSetting, Set-GatewayAgentIdentity, Get-PdpTable,
# Set-PdpAgent, Set-PdpEntity, Remove-PdpEntity
. (Join-Path $PSScriptRoot "GatewayConfigFiles.ps1")

if ($SetupAll) { $TestAppRegs = $true; $TestAgents = $true; $TestUsers = $true }

# -TestAppRegs starts from nothing: appsettings.json is created from the sample, and every app id
# that is still a placeholder is created (step 0) instead of being required here.
if ($TestAppRegs -and (Initialize-AppSettings $appsPath)) {
    Write-Host "Created appsettings.json from appsettings.sample.json" -ForegroundColor Green
}
function Resolve-Optional([string] $Value, [string] $Parameter, [string[]] $Keys) {
    try { Resolve-Setting $Value $Parameter $appsPath $Keys } catch { "" }
}
if ($TestAppRegs) {
    # Without a tenant id the signed-in account's tenant is used (and written to appsettings.json).
    $TenantId       = Resolve-Optional $TenantId       "TenantId"       "HostApplication:TenantId", "AgentBlueprint:TenantId"
    $ClaimsApiAppId = Resolve-Optional $ClaimsApiAppId "ClaimsApiAppId" "DownstreamApis:ClaimsApiAsAgent:Scopes:0"
    $HostAppId      = Resolve-Optional $HostAppId      "HostAppId"      "HostApplication:ClientId"
    $BlueprintAppId = Resolve-Optional $BlueprintAppId "BlueprintAppId" "AgentBlueprint:ClientId"
}
else {
    $TenantId       = Resolve-Setting $TenantId       "TenantId"       $appsPath "HostApplication:TenantId", "AgentBlueprint:TenantId"
    $ClaimsApiAppId = Resolve-Setting $ClaimsApiAppId "ClaimsApiAppId" $appsPath "DownstreamApis:ClaimsApiAsAgent:Scopes:0"
    $HostAppId      = Resolve-Setting $HostAppId      "HostAppId"      $appsPath "HostApplication:ClientId"
    $BlueprintAppId = Resolve-Setting $BlueprintAppId "BlueprintAppId" $appsPath "AgentBlueprint:ClientId"
}
# -TestAgents creates Agent1 when AgentIdentity:ClientId is still a placeholder; -TestAppRegs alone
# may run before any agent exists.
$AgentIdentityId = if ($TestAgents -or $TestAppRegs) { Resolve-Optional $AgentIdentityId "AgentIdentityId" "AgentIdentity:ClientId" }
else { Resolve-Setting $AgentIdentityId "AgentIdentityId" $appsPath "AgentIdentity:ClientId" }
# The MCP server (created by Configure-McpEntra.ps1, or by -TestAppRegs after step 2) is needed only
# for agent grants on it.
$needsMcp = ($TestAgents -or $NewAgent.Count -gt 0) -and -not $SkipMcpPermissions
if ($needsMcp -and -not $TestAppRegs) {
    $McpAppId = Resolve-Setting $McpAppId "McpAppId" $appsPath "McpServer:ClientId"
}

$scopes = @(
    "Application.Read.All",
    "AgentIdentityBlueprint.UpdateAuthProperties.All",
    "DelegatedPermissionGrant.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "User.Read"
)
if ($TestAppRegs) {
    # App registrations, the blueprint, its principal and secret (docs: "Create an agent identity blueprint").
    $scopes += @("Application.ReadWrite.All", "AgentIdentityBlueprint.Create", "AgentIdentityBlueprint.Read.All",
                 "AgentIdentityBlueprint.AddRemoveCreds.All", "AgentIdentityBlueprintPrincipal.Create")
}
if ($TestUsers) {
    # Users, groups, and the blueprint / agent user assignments (Set-AgentUserAccess.ps1).
    $scopes += @("User.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.ReadWrite.All",
                 "AgentIdentityBlueprintPrincipal.ReadWrite.All", "User.ReadBasic.All", "GroupMember.Read.All")
}
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
$connect = @{ NoWelcome = $true; Scopes = $scopes }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect
if (-not $TenantId) {
    $TenantId = (Get-MgContext).TenantId
    Write-Host "Tenant (from the signed-in account): $TenantId" -ForegroundColor Green
}

# Delegated grants go through Invoke-MgGraphRequest (Microsoft.Graph.Authentication), so the script
# does not depend on the Identity.SignIns module auto-loading.
function Get-DelegatedGrants([string] $ClientId, [string] $ResourceId) {
    $filter = "clientId eq '$ClientId'" + $(if ($ResourceId) { " and resourceId eq '$ResourceId'" } else { "" })
    @((Invoke-MgGraphRequest -Method GET -Uri "$graph/oauth2PermissionGrants?`$filter=$filter").value)
}

# Adds $Scope to the AllPrincipals grant from $ClientId to $ResourceId (creating it if needed).
function Set-DelegatedGrant([string] $ClientId, [string] $ResourceId, [string] $Scope, [string] $Label) {
    $grant = Get-DelegatedGrants $ClientId $ResourceId | Select-Object -First 1
    if ($grant -and ($grant.scope -split " ") -contains $Scope) {
        Write-Host "    delegated $Scope already granted ($Label)" -ForegroundColor Green
    }
    elseif ($grant) {
        Invoke-MgGraphRequest -Method PATCH -ContentType "application/json" -Uri "$graph/oauth2PermissionGrants/$($grant.id)" `
            -Body (@{ scope = (($grant.scope + " $Scope").Trim()) } | ConvertTo-Json) | Out-Null
        Write-Host "    added $Scope to the existing grant ($Label)" -ForegroundColor Green
    }
    else {
        $body = @{ clientId = $ClientId; consentType = "AllPrincipals"; resourceId = $ResourceId; scope = $Scope } | ConvertTo-Json
        Invoke-MgGraphRequest -Method POST -ContentType "application/json" -Uri "$graph/oauth2PermissionGrants" -Body $body | Out-Null
        Write-Host "    granted delegated $Scope ($Label)" -ForegroundColor Green
    }
}

# Assigns app role $RoleValue of $ResourceSp to $PrincipalId. -ErrorAction Stop is explicit because
# the Graph module cmdlets do not inherit this script's $ErrorActionPreference: without it a 404 is
# only printed and the "assigned" line below would be a lie.
function Set-AppRole([string] $PrincipalId, $ResourceSp, [string] $RoleValue, [string] $Label) {
    $role = $ResourceSp.AppRoles | Where-Object Value -eq $RoleValue | Select-Object -First 1
    if (-not $role) { throw "$($ResourceSp.DisplayName) has no app role '$RoleValue'." }
    $has = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -ErrorAction Stop |
        Where-Object { $_.AppRoleId -eq $role.Id -and $_.ResourceId -eq $ResourceSp.Id }
    if ($has) { Write-Host "    app role $RoleValue already assigned ($Label)" -ForegroundColor Green; return }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -PrincipalId $PrincipalId `
        -ResourceId $ResourceSp.Id -AppRoleId $role.Id -ErrorAction Stop | Out-Null
    Write-Host "    assigned app role $RoleValue ($Label)" -ForegroundColor Green
}

# A just-created agent identity (or app registration) takes a while to replicate in the directory:
# until then Graph answers 404 Request_ResourceNotFound for it (or, creating a service principal,
# "does not reference a valid application object"), and even once one read succeeds another replica
# may still 404. Runs $Action, retrying those every 10 s for up to 2 minutes.
function Invoke-WhenReplicated([string] $PrincipalId, [scriptblock] $Action) {
    for ($attempt = 1; ; $attempt++) {
        try { & $Action; return }
        catch {
            $message = "$($_.Exception.Message) $($_.ErrorDetails)"
            if ($attempt -ge 12 -or $message -notmatch "Request_ResourceNotFound|does not exist|valid application object|404") { throw }
            Write-Host "    $PrincipalId not replicated yet, retrying in 10 s ($attempt/12)" -ForegroundColor DarkGray
            Start-Sleep -Seconds 10
        }
    }
}

# Agent identities are created by the blueprint itself (client credentials, AgentIdentity.CreateAsManager),
# with its client secret from appsettings.json. The token is fetched once, on first use.
$script:bpHeaders = $null
function Get-BlueprintHeaders {
    if (-not $script:bpHeaders) {
        $blueprintSecret = (Read-JsonWithComments $appsPath).AgentBlueprint.ClientCredentials[0].ClientSecret
        if (-not (Test-ConfiguredId $blueprintSecret)) { throw "AgentBlueprint:ClientCredentials[0]:ClientSecret is not set in appsettings.json." }
        # A blueprint or secret created moments ago (-TestAppRegs) is not known to the token service
        # yet (AADSTS700016 / AADSTS7000215): retry every 10 s for up to 2 minutes.
        for ($attempt = 1; ; $attempt++) {
            try {
                $tokenResponse = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body @{
                    grant_type    = "client_credentials"
                    client_id     = $BlueprintAppId
                    client_secret = $blueprintSecret
                    scope         = "https://graph.microsoft.com/.default"
                }
                break
            }
            catch {
                if ($attempt -ge 12 -or "$($_.Exception.Message) $($_.ErrorDetails)" -notmatch "AADSTS700016|AADSTS7000215|invalid_client|unauthorized_client") { throw }
                Write-Host "    blueprint credential not active yet, retrying in 10 s ($attempt/12)" -ForegroundColor DarkGray
                Start-Sleep -Seconds 10
            }
        }
        $script:bpHeaders = @{ Authorization = "Bearer $($tokenResponse.access_token)"; "OData-Version" = "4.0" }
    }
    $script:bpHeaders
}

# Renames an agent identity (the blueprint manages its own agents). A failure is only a warning:
# the name is cosmetic, the id is what everything else uses.
function Rename-AgentIdentity([string] $Id, [string] $From, [string] $To) {
    if ($From -eq $To) { return }
    try {
        Invoke-RestMethod -Method PATCH -Headers (Get-BlueprintHeaders) -ContentType "application/json" `
            -Uri "$graph/servicePrincipals/$Id/microsoft.graph.agentIdentity" -Body (@{ displayName = $To } | ConvertTo-Json) | Out-Null
        Write-Host "    renamed: '$From' -> '$To'" -ForegroundColor Green
    }
    catch { Write-Host "    could not rename '$From' to '$To' (rename it in the Entra admin center): $($_.Exception.Message)" -ForegroundColor Yellow }
}

# The signed-in admin (sponsor of created agents and of the blueprint).
$script:me = $null
function Get-Me {
    if (-not $script:me) { $script:me = Invoke-MgGraphRequest -Method GET -Uri "$graph/me?`$select=id,userPrincipalName" }
    $script:me
}

# Finds the agent identity with this display name (or one of its older names) under the blueprint,
# or creates it (sponsor: the signed-in admin). Returns its id (for agent identities the app id
# equals the object id).
function Use-AgentIdentity([string] $Name, [string[]] $OldNames = @()) {
    $all = @((Invoke-RestMethod -Headers (Get-BlueprintHeaders) `
        -Uri ("$graph/servicePrincipals/microsoft.graph.agentIdentity?`$filter=agentIdentityBlueprintId eq '$BlueprintAppId'&`$select=id,appId,displayName,accountEnabled")).value)
    $existing = $all | Where-Object { $_.displayName -eq $Name } | Select-Object -First 1
    if (-not $existing) { $existing = $all | Where-Object { $OldNames -contains $_.displayName } | Select-Object -First 1 }
    if ($existing) {
        Write-Host "    found: $($existing.id) (accountEnabled=$($existing.accountEnabled))" -ForegroundColor Green
        Rename-AgentIdentity $existing.id $existing.displayName $Name
        return $existing.id
    }
    $me = Get-Me
    $body = @{
        displayName              = $Name
        agentIdentityBlueprintId = $BlueprintAppId
        "sponsors@odata.bind"    = @("$graph/users/$($me.id)")
    } | ConvertTo-Json
    $new = Invoke-RestMethod -Method POST -Headers (Get-BlueprintHeaders) -ContentType "application/json" `
        -Uri "$graph/servicePrincipals/microsoft.graph.agentIdentity" -Body $body
    Write-Host "    created: $($new.id) (sponsor $($me.userPrincipalName))" -ForegroundColor Green
    return $new.id
}

function Set-McpAgentGrants([string] $AgentId) {
    if (-not $mcpSp) { return }
    Invoke-WhenReplicated $AgentId { Set-AppRole $AgentId $mcpSp "Mcp.Analyze.All" "-> MCP server" }
    Invoke-WhenReplicated $AgentId { Set-DelegatedGrant $AgentId $mcpSp.Id "Mcp.Analyze" "-> MCP server" }
}

# ---------------------------------------------------------------------------
# 0. App registrations (-TestAppRegs): POC Claims API, the agent identity blueprint, POC Claims Web
#    (docs/entra-setup.md 4A-4C). The MCP server follows after step 2, once the host app holds its grants.
# ---------------------------------------------------------------------------
# The blueprint's application object id equals its app id in the tenants this was built on; step 0
# replaces it with the id Graph returns.
$blueprintObjectId = $BlueprintAppId
$claimsApiName = "POC Claims API"
$blueprintName = "POC Claims Analysis Agent Blueprint"
$hostAppName   = "POC Claims Web"
$hostRedirectUris = @("http://localhost:5094/signin-oidc", "https://localhost:7221/signin-oidc")   # Properties/launchSettings.json

# The registration with the configured app id, or else the first one named $Name in $ListUri (or $null).
function Find-Application([string] $Label, [string] $AppId, [string] $Name, [string] $ListUri) {
    if (Test-ConfiguredId $AppId) {
        try { return Invoke-MgGraphRequest -Method GET -Headers $graphHeaders -Uri "$graph/applications(appId='$AppId')" }
        catch {
            if ("$($_.Exception.Message) $($_.ErrorDetails)" -notmatch "Request_ResourceNotFound|does not exist|404") { throw }
            throw "$Label $AppId (from appsettings.json or the parameter) does not exist in tenant $TenantId. Put its <placeholder> back to have '$Name' created."
        }
    }
    @((Invoke-MgGraphRequest -Method GET -Headers $graphHeaders -Uri "$ListUri`?`$filter=displayName eq '$Name'").value) | Select-Object -First 1
}

function New-AppRegistration([string] $Name) {
    $app = Invoke-MgGraphRequest -Method POST -ContentType "application/json" -Uri "$graph/applications" `
        -Body (@{ displayName = $Name; signInAudience = "AzureADMyOrg" } | ConvertTo-Json)
    Write-Host "    created: appId $($app.appId)" -ForegroundColor Green
    $app
}

# Creates the service principal of $AppId when missing ($CreateUri differs for a blueprint principal).
function Use-ServicePrincipal([string] $AppId, [string] $CreateUri = "$graph/servicePrincipals") {
    $sp = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/servicePrincipals?`$filter=appId eq '$AppId'&`$select=id").value) | Select-Object -First 1
    if ($sp) { Write-Host "    service principal $($sp.id)"; return }
    Invoke-WhenReplicated $AppId {
        $new = Invoke-MgGraphRequest -Method POST -Headers $graphHeaders -ContentType "application/json" -Uri $CreateUri `
            -Body (@{ appId = $AppId } | ConvertTo-Json)
        Write-Host "    created service principal $($new.id)" -ForegroundColor Green
    }
}

# $Existing plus the entries of $Wanted whose value it lacks (existing scopes and roles keep their ids).
function Merge-ByValue($Existing, $Wanted) {
    $list = @($Existing | Where-Object { $_ })
    foreach ($w in $Wanted) { if (-not ($list | Where-Object { $_.value -eq $w.value })) { $list += $w } }
    , $list
}

function New-ApiScope([string] $Value, [string] $Title, [string] $Description) {
    @{
        id = [guid]::NewGuid().ToString(); value = $Value; type = "User"; isEnabled = $true
        adminConsentDisplayName = $Title; adminConsentDescription = $Description
        userConsentDisplayName  = $Title; userConsentDescription  = $Description
    }
}

function New-AppRoleDefinition([string] $Value, [string] $Description) {
    @{ id = [guid]::NewGuid().ToString(); value = $Value; displayName = $Value; description = $Description
       allowedMemberTypes = @("Application"); isEnabled = $true }
}

# v2 access tokens, api://<app id> first among the identifier URIs, and the given scopes / app roles
# added to whatever the registration already has.
function Set-ApiShape($App, [object[]] $Scopes, [object[]] $Roles = @(), [hashtable] $Extra = @{}) {
    $uri = "$graph/applications/$($App.id)"
    # v2 first: some identifier URI forms are only accepted once it is set.
    Invoke-WhenReplicated $App.appId {
        Invoke-MgGraphRequest -Method PATCH -ContentType "application/json" -Uri $uri `
            -Body (@{ api = @{ requestedAccessTokenVersion = 2 } } | ConvertTo-Json -Depth 4) | Out-Null
    }
    $current = Invoke-MgGraphRequest -Method GET -Uri "$uri`?`$select=identifierUris,api,appRoles"
    $idUri = "api://$($App.appId)"
    $body = @{
        identifierUris = @($idUri) + @(@($current.identifierUris) | Where-Object { $_ -and $_ -ne $idUri })
        api            = @{ requestedAccessTokenVersion = 2; oauth2PermissionScopes = (Merge-ByValue $current.api.oauth2PermissionScopes $Scopes) }
    }
    if ($Roles.Count) { $body.appRoles = Merge-ByValue $current.appRoles $Roles }
    foreach ($k in $Extra.Keys) { $body[$k] = $Extra[$k] }
    Invoke-MgGraphRequest -Method PATCH -ContentType "application/json" -Uri $uri -Body ($body | ConvertTo-Json -Depth 8) | Out-Null
    $check = Invoke-MgGraphRequest -Method GET -Uri "$uri`?`$select=identifierUris,api,appRoles"
    Write-Host ("    v2 tokens; {0}; scopes: {1}{2}" -f ($check.identifierUris -join ", "),
        (($check.api.oauth2PermissionScopes | ForEach-Object value) -join ", "),
        $(if ($Roles.Count) { "; app roles: " + (($check.appRoles | ForEach-Object value) -join ", ") } else { "" })) -ForegroundColor Green
}

# Adds the missing names to the registration's access-token optional claims (other token types kept).
function Add-AccessTokenClaims($App, [string[]] $Names) {
    $optional = (Invoke-MgGraphRequest -Method GET -Uri "$graph/applications/$($App.id)?`$select=optionalClaims").optionalClaims
    $existing = if ($optional) { $optional } else { @{} }
    # Leading comma: return the array itself, so an empty list stays [] instead of becoming $null.
    $claimsOf = { param($kind) if ($existing.ContainsKey($kind) -and $existing[$kind]) { , @($existing[$kind]) } else { , @() } }
    $access = & $claimsOf "accessToken"
    $missing = @($Names | Where-Object { $n = $_; -not ($access | Where-Object { $_.name -eq $n }) })
    if ($missing.Count -eq 0) { Write-Host "    optional claims already in access tokens: $($Names -join ', ')" -ForegroundColor Green; return }
    $body = @{ optionalClaims = @{
        accessToken = @($access) + @($missing | ForEach-Object { @{ name = $_; essential = $false; additionalProperties = @() } })
        idToken     = & $claimsOf "idToken"
        saml2Token  = & $claimsOf "saml2Token"
    } } | ConvertTo-Json -Depth 6
    Invoke-MgGraphRequest -Method PATCH -ContentType "application/json" -Uri "$graph/applications/$($App.id)" -Body $body | Out-Null
    Write-Host "    optional claims added to access tokens: $($missing -join ', ')" -ForegroundColor Green
}

# A client secret is minted for a new registration, with -NewSecrets, when appsettings.json does not
# hold one (it cannot be read back from Entra), or when the registration has none. Returns the new
# secret text, or $null when the existing one is kept.
function Use-ClientSecret($App, [bool] $Created, [string] $SettingPath, [string] $Label) {
    $local = Resolve-Optional "" "x" $SettingPath
    $hasCredentials = [bool] $App["passwordCredentials"]   # index access: StrictMode throws on a missing key with dot access
    if (-not ($Created -or $NewSecrets -or -not (Test-ConfiguredId $local) -or -not $hasCredentials)) {
        Write-Host "    client secret kept (appsettings.json has one; -NewSecrets mints another)"
        return $null
    }
    $body = @{ passwordCredential = @{ displayName = $Label; endDateTime = (Get-Date).ToUniversalTime().AddMonths(6).ToString("o") } } | ConvertTo-Json
    $secret = Invoke-WhenReplicated $App.appId {
        (Invoke-MgGraphRequest -Method POST -Headers $graphHeaders -ContentType "application/json" `
            -Uri "$graph/applications/$($App.id)/addPassword" -Body $body).secretText
    }
    Write-Host "    minted a client secret (6 months), written to appsettings.json" -ForegroundColor Green
    $secret
}

if ($TestAppRegs) {
    Write-Host "`n[0] App registrations" -ForegroundColor Cyan
    $me = Get-Me

    # 4A. The resource: scopes for the delegated scenarios, app roles for the app-only ones.
    Write-Host "`n    $claimsApiName (docs/entra-setup.md 4A)" -ForegroundColor Yellow
    $app = Find-Application "Claims API" $ClaimsApiAppId $claimsApiName "$graph/applications"
    if ($app) { Write-Host "    found: appId $($app.appId)" -ForegroundColor Green } else { $app = New-AppRegistration $claimsApiName }
    $ClaimsApiAppId = $app.appId
    Set-ApiShape $app -Scopes @(
        New-ApiScope "Claims.Archive" "Archive claims as the signed-in user" "Allows the application to archive claims on behalf of the signed-in user."
        New-ApiScope "Claims.Analyze" "Analyze claims as the signed-in user" "Allows the application to analyze claims on behalf of the signed-in user."
    ) -Roles @(
        New-AppRoleDefinition "Claims.Archive.All" "Allows the application to archive claims without a signed-in user."
        New-AppRoleDefinition "Claims.Analyze.All" "Allows the application to analyze claims without a signed-in user."
    )
    # idtyp marks app-only tokens; the agent facet claims say "this caller is an agent of blueprint X" (4A.4-5).
    try { Add-AccessTokenClaims $app @("idtyp", "xms_par_app_azp", "xms_act_fct", "xms_sub_fct") }
    catch {
        Write-Host "    Entra refused the agent facet claims, adding idtyp only (4A.5): $($_.Exception.Message)" -ForegroundColor Yellow
        Add-AccessTokenClaims $app @("idtyp")
    }
    Use-ServicePrincipal $ClaimsApiAppId
    Set-AppSettingList $appsPath "DownstreamApis" "Scopes" @("api://$ClaimsApiAppId/.default")
    Set-JsonConfig (Join-Path $root "claims-api/config.json") @{ TENANT_ID = $TenantId; CLAIMS_API_APP_ID = $ClaimsApiAppId }
    Write-Host "    appsettings.json DownstreamApis:*:Scopes, claims-api/config.json TENANT_ID + CLAIMS_API_APP_ID" -ForegroundColor Green

    # 4C.1-2. The blueprint: the only agent object with a credential. Its URI and scope are step 1.
    Write-Host "`n    $blueprintName (docs/entra-setup.md 4C.1-2)" -ForegroundColor Yellow
    $bp = Find-Application "Blueprint" $BlueprintAppId $blueprintName "$graph/applications/microsoft.graph.agentIdentityBlueprint"
    $bpCreated = -not $bp
    if ($bp) { Write-Host "    found: appId $($bp.appId)" -ForegroundColor Green }
    else {
        $body = @{
            "@odata.type"         = "Microsoft.Graph.AgentIdentityBlueprint"
            displayName           = $blueprintName
            "sponsors@odata.bind" = @("$graph/users/$($me.id)")
            "owners@odata.bind"   = @("$graph/users/$($me.id)")
        } | ConvertTo-Json
        $bp = Invoke-MgGraphRequest -Method POST -Headers $graphHeaders -ContentType "application/json" `
            -Uri "$graph/applications/microsoft.graph.agentIdentityBlueprint" -Body $body
        Write-Host "    created: appId $($bp.appId) (sponsor and owner $($me.userPrincipalName))" -ForegroundColor Green
    }
    $BlueprintAppId = $bp.appId
    $blueprintObjectId = $bp.id
    Use-ServicePrincipal $BlueprintAppId "$graph/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal"
    $secret = Use-ClientSecret $bp $bpCreated "AgentBlueprint:ClientCredentials:0:ClientSecret" "poc"
    Set-AppSetting $appsPath "AgentBlueprint" "TenantId" $TenantId
    Set-AppSetting $appsPath "AgentBlueprint" "ClientId" $BlueprintAppId
    Set-AppSetting $appsPath "AgentBlueprint" "ApiScope" "api://$BlueprintAppId/access_agent"
    if ($secret) { Set-AppSetting $appsPath "AgentBlueprint" "ClientSecret" $secret; $script:bpHeaders = $null }
    Write-Host "    appsettings.json AgentBlueprint:TenantId, ClientId, ApiScope$(if ($secret) { ', ClientSecret' })" -ForegroundColor Green

    # 4B.1-3. The host app: browser sign-in (auth code + secret) and its own access_as_user scope.
    # Its grants on the Claims API and the blueprint are step 2.
    Write-Host "`n    $hostAppName (docs/entra-setup.md 4B.1-3)" -ForegroundColor Yellow
    $app = Find-Application "Host app" $HostAppId $hostAppName "$graph/applications"
    $hostCreated = -not $app
    if ($app) { Write-Host "    found: appId $($app.appId)" -ForegroundColor Green } else { $app = New-AppRegistration $hostAppName }
    $HostAppId = $app.appId
    $redirects = @($hostRedirectUris) + @(@($app.web.redirectUris) | Where-Object { $_ -and $hostRedirectUris -notcontains $_ })
    Set-ApiShape $app -Scopes @(
        New-ApiScope "access_as_user" "Access POC Claims Web as the signed-in user" "Allows the application to call POC Claims Web on behalf of the signed-in user."
    ) -Extra @{ web = @{ redirectUris = $redirects } }
    Write-Host "    redirect URIs: $($redirects -join ', ')" -ForegroundColor Green
    Use-ServicePrincipal $HostAppId
    $secret = Use-ClientSecret $app $hostCreated "HostApplication:ClientCredentials:0:ClientSecret" "poc-web"
    Set-AppSetting $appsPath "HostApplication" "TenantId" $TenantId
    Set-AppSetting $appsPath "HostApplication" "ClientId" $HostAppId
    Set-AppSetting $appsPath "HostApplication" "ApiScope" "api://$HostAppId/access_as_user"
    if ($secret) { Set-AppSetting $appsPath "HostApplication" "ClientSecret" $secret }
    Write-Host "    appsettings.json HostApplication:TenantId, ClientId, ApiScope$(if ($secret) { ', ClientSecret' })" -ForegroundColor Green
}

# Service principals. Right after -TestAppRegs created or changed them they may not be readable (or
# not show the new scopes and roles) yet, so they are polled for up to 2 minutes.
function Get-ReadyServicePrincipal([string] $AppId, [string[]] $Roles = @(), [string[]] $Scopes = @()) {
    $attempts = if ($TestAppRegs) { 12 } else { 1 }
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction Stop | Select-Object -First 1
        $ready = [bool] $sp
        if ($sp) {
            $haveRoles  = @($sp.AppRoles | ForEach-Object { $_.Value })
            $haveScopes = @($sp.Oauth2PermissionScopes | ForEach-Object { $_.Value })
            $ready = -not ($Roles | Where-Object { $haveRoles -notcontains $_ }) -and
                     -not ($Scopes | Where-Object { $haveScopes -notcontains $_ })
        }
        if ($ready -or $attempt -eq $attempts) { return $sp }
        Write-Host "    service principal of $AppId not up to date yet, retrying in 10 s ($attempt/$attempts)" -ForegroundColor DarkGray
        Start-Sleep -Seconds 10
    }
}

$claimsRoles  = if ($TestAppRegs) { @("Claims.Archive.All", "Claims.Analyze.All") } else { @() }
$claimsScopes = if ($TestAppRegs) { @("Claims.Archive", "Claims.Analyze") } else { @() }
$claimsApiSp = Get-ReadyServicePrincipal $ClaimsApiAppId $claimsRoles $claimsScopes
$hostSp      = Get-ReadyServicePrincipal $HostAppId
$blueprintSp = Get-ReadyServicePrincipal $BlueprintAppId
if (-not $claimsApiSp) { throw "No service principal for Claims API $ClaimsApiAppId. Open its Enterprise application once." }
if (-not $hostSp)      { throw "No service principal for host app $HostAppId." }
if (-not $blueprintSp) { throw "No blueprint principal for $BlueprintAppId (docs/entra-setup.md 4C.1)." }
$mcpSp = $null
if ($needsMcp -and -not $TestAppRegs) {
    $mcpSp = Get-MgServicePrincipal -Filter "appId eq '$McpAppId'"
    if (-not $mcpSp) { throw "No service principal for the MCP server $McpAppId (run Configure-McpEntra.ps1 first)." }
}

Write-Host ("`nClaims API SP  : {0}  ({1})" -f $claimsApiSp.Id, $claimsApiSp.DisplayName)
Write-Host ("Host app SP    : {0}  ({1})" -f $hostSp.Id, $hostSp.DisplayName)
Write-Host ("Blueprint SP   : {0}  ({1})" -f $blueprintSp.Id, $blueprintSp.DisplayName)
Write-Host ("Agent identity : {0}" -f $(if ($AgentIdentityId) { $AgentIdentityId } else { "(not set; -TestAgents creates it)" }))

$pdpTable = Get-PdpTable $appsPath
$pdpPending ="    PDP registry: storage not deployed yet (GatewayMcp:StorageConnectionString empty); run this script again after Deploy-GatewayPoc.ps1"

# ---------------------------------------------------------------------------
# 1. Blueprint identifier URI + access_agent scope
# ---------------------------------------------------------------------------
Write-Host "`n[1] Blueprint identifier URI and access_agent scope" -ForegroundColor Cyan
$bpApp = Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
    -Uri "$graph/applications/$blueprintObjectId`?`$select=id,appId,displayName,identifierUris,api"

$expectedUri = "api://$BlueprintAppId"
$existingScopes = @($bpApp.api.oauth2PermissionScopes)
$hasUri   = @($bpApp.identifierUris) -contains $expectedUri
$hasScope = $existingScopes | Where-Object { $_.value -eq "access_agent" }

if ($hasUri -and $hasScope) {
    Write-Host "    already configured: $expectedUri with scope access_agent" -ForegroundColor Green
}
else {
    $scopeList = @($existingScopes | ForEach-Object { $_ })
    if (-not $hasScope) {
        $scopeList += @{
            id                      = [guid]::NewGuid().ToString()
            value                   = "access_agent"
            type                    = "User"
            isEnabled               = $true
            adminConsentDisplayName = "Access agent"
            adminConsentDescription = "Allow the application to access the agent on behalf of the signed-in user."
            userConsentDisplayName  = "Access agent"
            userConsentDescription  = "Allow the application to access the agent on your behalf."
        }
    }
    $body = @{
        identifierUris = @($expectedUri)
        api            = @{ oauth2PermissionScopes = $scopeList }
    } | ConvertTo-Json -Depth 8

    Invoke-MgGraphRequest -Method PATCH -Headers $graphHeaders -ContentType "application/json" `
        -Uri "$graph/applications/$blueprintObjectId" -Body $body | Out-Null

    $check = Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
        -Uri "$graph/applications/$blueprintObjectId`?`$select=identifierUris,api"
    Write-Host ("    set: {0}; scopes: {1}" -f ($check.identifierUris -join ", "), (($check.api.oauth2PermissionScopes | ForEach-Object value) -join ", ")) -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 2. Host app -> delegated access_agent on the blueprint principal
# ---------------------------------------------------------------------------
Write-Host "`n[2] Host app delegated grant: access_agent on the blueprint" -ForegroundColor Cyan
Set-DelegatedGrant $hostSp.Id $blueprintSp.Id "access_agent" "host app -> blueprint"

if ($TestAppRegs) {
    # docs/entra-setup.md 4B.4: scenario 1 (application) and 2 (delegated) on the Claims API, plus admin
    # consent for the sign-in scopes, so test users get no consent prompt.
    Set-AppRole        $hostSp.Id $claimsApiSp "Claims.Archive.All" "host app -> Claims API"
    Set-DelegatedGrant $hostSp.Id $claimsApiSp.Id "Claims.Archive" "host app -> Claims API"
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
    $signInScopes = @("openid", "profile", "offline_access", "User.Read")
    foreach ($signInScope in $signInScopes) { Set-DelegatedGrant $hostSp.Id $graphSp.Id $signInScope "host app -> Microsoft Graph (sign-in)" }

    # The registration's API permissions list (what the portal shows and admin consent covers) to match.
    # Id of the scope / role with this value ($null when absent; such entries are skipped below).
    $idOf = { param($items, $value) foreach ($i in @($items)) { if ($i -and $i.Value -eq $value) { return $i.Id } } }
    $bpScopeId = $null
    foreach ($sc in @((Invoke-MgGraphRequest -Method GET -Headers $graphHeaders -Uri "$graph/applications/$blueprintObjectId`?`$select=api").api.oauth2PermissionScopes)) {
        if ($sc -and $sc["value"] -eq "access_agent") { $bpScopeId = $sc["id"] }
    }
    $wanted = [ordered] @{
        $ClaimsApiAppId = @(@{ id = (& $idOf $claimsApiSp.Oauth2PermissionScopes "Claims.Archive"); type = "Scope" },
                            @{ id = (& $idOf $claimsApiSp.AppRoles "Claims.Archive.All"); type = "Role" })
        $BlueprintAppId = @(@{ id = $bpScopeId; type = "Scope" })
        "00000003-0000-0000-c000-000000000000" = @($signInScopes | ForEach-Object { @{ id = (& $idOf $graphSp.Oauth2PermissionScopes $_); type = "Scope" } })
    }
    $hostReg = Invoke-MgGraphRequest -Method GET -Uri "$graph/applications(appId='$HostAppId')?`$select=id,requiredResourceAccess"
    $access = @(@($hostReg.requiredResourceAccess) | Where-Object { $_ -and -not $wanted.Contains($_.resourceAppId) })
    foreach ($resource in $wanted.Keys) {
        $have = @(@($hostReg.requiredResourceAccess) | Where-Object { $_ -and $_.resourceAppId -eq $resource } | ForEach-Object { $_.resourceAccess })
        $list = @($have | Where-Object { $_ })
        foreach ($w in $wanted[$resource]) { if ($w.id -and -not ($list | Where-Object { $_.id -eq $w.id })) { $list += $w } }
        $access += @{ resourceAppId = $resource; resourceAccess = $list }
    }
    Invoke-MgGraphRequest -Method PATCH -ContentType "application/json" -Uri "$graph/applications/$($hostReg.id)" `
        -Body (@{ requiredResourceAccess = $access } | ConvertTo-Json -Depth 6) | Out-Null
    Write-Host "    API permissions list: Claims.Archive, Claims.Archive.All, access_agent, $($signInScopes -join ', ')" -ForegroundColor Green

    # The MCP server: its own registration, grants on the Claims API, and the host app's grants on it.
    # Agent grants on it come with the agents (step 3, Set-McpAgentGrants).
    Write-Host "`n[2b] MCP server registration (Configure-McpEntra.ps1 -WriteConfig)" -ForegroundColor Cyan
    $mcpArgs = @{ TenantId = $TenantId; ClaimsApiAppId = $ClaimsApiAppId; HostAppId = $HostAppId; WriteConfig = $true }
    if (Test-ConfiguredId $AgentIdentityId) { $mcpArgs.AgentIdentityId = $AgentIdentityId }
    if ($NewSecrets) { $mcpArgs.NewSecret = $true }
    & (Join-Path $PSScriptRoot "Configure-McpEntra.ps1") @mcpArgs
    $McpAppId = Resolve-Setting "" "McpAppId" $appsPath "McpServer:ClientId"
    if ($needsMcp) {
        $mcpSp = Get-ReadyServicePrincipal $McpAppId @("Mcp.Analyze.All") @("Mcp.Analyze")
        if (-not $mcpSp) { throw "No service principal for the MCP server $McpAppId." }
    }
}

# ---------------------------------------------------------------------------
# 3. Test agents (docs/test-identities.md)
# ---------------------------------------------------------------------------
if ($TestAgents) {
    Write-Host "`n[3] Test agents Agent1-4 from blueprint $BlueprintAppId" -ForegroundColor Cyan

    # Agent1: the local tabs' agent. Application AND delegated permission on the Claims API (scenarios
    # 3 and 4) and on the MCP server (agent loop). Deliberately not registered in the PDP.
    $agent1Name = "POC Claims Local Analysis Agent (Agent1)"
    Write-Host "`n    Agent1 $agent1Name (local: application vs delegated)" -ForegroundColor Yellow
    if (-not (Test-ConfiguredId $AgentIdentityId)) {
        $AgentIdentityId = Use-AgentIdentity $agent1Name @("POC Claims Analysis Agent")
        Set-AppSetting $appsPath "AgentIdentity" "ClientId" $AgentIdentityId
        Write-Host "    appsettings.json AgentIdentity:ClientId = $AgentIdentityId" -ForegroundColor Green
    }
    else {
        Write-Host "    AgentIdentity:ClientId = $AgentIdentityId" -ForegroundColor Green
        $current = (Invoke-MgGraphRequest -Method GET -Uri "$graph/servicePrincipals/$AgentIdentityId`?`$select=displayName").displayName
        Rename-AgentIdentity $AgentIdentityId $current $agent1Name
    }
    Invoke-WhenReplicated $AgentIdentityId { Set-AppRole $AgentIdentityId $claimsApiSp "Claims.Analyze.All" "-> Claims API" }
    Invoke-WhenReplicated $AgentIdentityId { Set-DelegatedGrant $AgentIdentityId $claimsApiSp.Id "Claims.Analyze" "-> Claims API" }
    Set-McpAgentGrants $AgentIdentityId
    $action = Set-GatewayAgentIdentity $appsPath $agent1Name $AgentIdentityId "Agent1: the local tabs' agent; not registered in the PDP, so the gateway refuses it"
    Write-Host "    appsettings.json GatewayAgentIdentities ($action)" -ForegroundColor Green
    if ($pdpTable -and (Remove-PdpEntity $pdpTable "agent" $AgentIdentityId.ToLower())) {
        Write-Host "    PdpEntities agent/$($AgentIdentityId.ToLower()) removed (Agent1 stays unregistered)" -ForegroundColor Green
    }

    # Agents 2-4: gateway agents with the same Entra permissions (MCP server only); the PDP tells them apart.
    $agentPlan = @(
        @{ Key = "Agent2"; Name = "POC Claims Limited Gateway Agent (Agent2)"; OldNames = @("POC Claims Gateway Agent"); Limit = 10000;
           Label = "PDP, limited"; Note = "Agent2: registered in the PDP, autonomous limit 10,000 (limited)" }
        @{ Key = "Agent3"; Name = "POC Claims Senior Gateway Agent (Agent3)"; OldNames = @("POC Claims Senior Agent"); Limit = 50000;
           Label = "PDP, greater access"; Note = "Agent3: registered in the PDP, autonomous limit 50,000 (greater access)" }
        @{ Key = "Agent4"; Name = "POC Claims Rogue Agent, Unregistered (Agent4)"; OldNames = @("POC Claims Rogue Agent"); Limit = 0;
           Label = "bad agent: Entra permissions, no PDP registration"; Note = "Agent4: Entra grants it MCP permissions, but it is not registered in the PDP, so the gateway refuses it" }
    )
    foreach ($a in $agentPlan) {
        Write-Host "`n    $($a.Key) $($a.Name) ($($a.Label))" -ForegroundColor Yellow
        $id = Use-AgentIdentity $a.Name $a.OldNames
        Set-McpAgentGrants $id
        $action = Set-GatewayAgentIdentity $appsPath $a.Name $id $a.Note
        Write-Host "    appsettings.json GatewayAgentIdentities ($action)" -ForegroundColor Green
        if ($a.Key -eq "Agent2") {
            Set-AppSetting $appsPath "GatewayMcp" "AgentIdentityClientId" $id
            Write-Host "    appsettings.json GatewayMcp:AgentIdentityClientId = $id (default in the drop-down)" -ForegroundColor Green
        }
        if (-not $pdpTable) { continue }
        if ($a.Limit -gt 0) {
            # The script owns the test agents' baseline, so the limit is reset on every run.
            Set-PdpEntity $pdpTable "agent" $id.ToLower() @{ displayName = $a.Name; blueprint = $BlueprintAppId.ToLower(); autonomousLimit = $a.Limit }
            Write-Host ("    PdpEntities agent/{0} (autonomousLimit {1:N0})" -f $id.ToLower(), $a.Limit) -ForegroundColor Green
        }
        elseif (Remove-PdpEntity $pdpTable "agent" $id.ToLower()) {
            Write-Host "    PdpEntities agent/$($id.ToLower()) removed (stays unregistered)" -ForegroundColor Green
        }
        else { Write-Host "    PdpEntities: not registered (as intended)" -ForegroundColor Green }
    }
    if (-not $pdpTable) { Write-Host $pdpPending -ForegroundColor Yellow }
}

# ---------------------------------------------------------------------------
# 4. Test users and the PDP groups (docs/test-identities.md)
# ---------------------------------------------------------------------------
if ($TestUsers) {
    Write-Host "`n[4] Test users User1-4 and PDP groups" -ForegroundColor Cyan

    if (-not $UserDomain) {
        $org = (Invoke-MgGraphRequest -Method GET -Uri "$graph/organization?`$select=verifiedDomains").value | Select-Object -First 1
        $UserDomain = (@($org.verifiedDomains) | Where-Object { $_.isDefault } | Select-Object -First 1).name
    }

    function New-TestPassword {
        $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
        $bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
        (-join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })) + "!7aZ"
    }

    $userPlan = @(
        @{ Key = "User1"; Given = $User1; Nick = "poc-claims-user1"; Name = "POC Claims EU Adjuster (User1)";
           Groups = @("adjusters-eu");                       AgentAccess = $true }
        @{ Key = "User2"; Given = $User2; Nick = "poc-claims-user2"; Name = "POC Claims US Senior Adjuster (User2)";
           Groups = @("adjusters-us", "senior-adjusters");   AgentAccess = $true }
        @{ Key = "User3"; Given = $User3; Nick = "poc-claims-user3"; Name = "POC Claims Agent User, No Adjuster Group (User3)";
           Groups = @();                                     AgentAccess = $true }
        @{ Key = "User4"; Given = $User4; Nick = "poc-claims-user4"; Name = "POC Claims Unassigned User (User4)";
           Groups = @();                                     AgentAccess = $false }
    )
    foreach ($u in $userPlan) {
        $lookup = if ($u.Given) { $u.Given } else { "$($u.Nick)@$UserDomain" }
        $found = $null
        try { $found = Invoke-MgGraphRequest -Method GET -Uri "$graph/users/$([uri]::EscapeDataString($lookup))?`$select=id,userPrincipalName,displayName" }
        catch { if ("$($_.Exception.Message) $($_.ErrorDetails)" -notmatch "Request_ResourceNotFound|does not exist|404") { throw } }
        if ($found) {
            Write-Host ("    {0}: found {1} ({2})" -f $u.Key, $found.userPrincipalName, $found.id) -ForegroundColor Green
            # Our own test accounts carry the role in their display name; accounts passed in are left alone.
            if (-not $u.Given -and $found.displayName -ne $u.Name) {
                Invoke-MgGraphRequest -Method PATCH -ContentType "application/json" -Uri "$graph/users/$($found.id)" `
                    -Body (@{ displayName = $u.Name } | ConvertTo-Json) | Out-Null
                Write-Host "           renamed: '$($found.displayName)' -> '$($u.Name)'" -ForegroundColor Green
            }
        }
        elseif ($u.Given) { throw "$($u.Key) '$($u.Given)' was not found in the tenant." }
        else {
            $password = New-TestPassword
            $body = @{
                accountEnabled    = $true
                displayName       = $u.Name
                mailNickname      = $u.Nick
                userPrincipalName = $lookup
                passwordProfile   = @{ password = $password; forceChangePasswordNextSignIn = $true }
            } | ConvertTo-Json
            $found = Invoke-MgGraphRequest -Method POST -ContentType "application/json" -Uri "$graph/users" -Body $body
            Write-Host ("    {0}: created {1} ({2}) as '{3}'" -f $u.Key, $found.userPrincipalName, $found.id, $u.Name) -ForegroundColor Green
            Write-Host "           one-time password (shown once, must be changed at first sign-in): $password" -ForegroundColor Yellow
        }
        $u.Id  = $found.id
        $u.Upn = $found.userPrincipalName
    }

    # Groups used by the Cedar policies (claims-pdp/policies/claims/claims.cedar).
    $groupPlan = @(
        @{ id = "adjusters-eu";     name = "POC Claims Adjusters EU";     region = "EU" }
        @{ id = "adjusters-us";     name = "POC Claims Adjusters US";     region = "US" }
        @{ id = "senior-adjusters"; name = "POC Claims Senior Adjusters"; region = $null }
    )
    Write-Host ""
    foreach ($g in $groupPlan) {
        $group = @((Invoke-MgGraphRequest -Method GET `
            -Uri "$graph/groups?`$filter=displayName eq '$($g.name)'&`$select=id,displayName").value) | Select-Object -First 1
        if (-not $group) {
            $body = @{
                displayName     = $g.name
                mailEnabled     = $false
                mailNickname    = ($g.name -replace '[^A-Za-z0-9]', '').ToLower()
                securityEnabled = $true
                description     = "Used by the POC Claims PDP (Cedar policies, group '$($g.id)')."
            } | ConvertTo-Json
            $group = Invoke-MgGraphRequest -Method POST -ContentType "application/json" -Uri "$graph/groups" -Body $body
            Write-Host "    created group $($g.name) ($($group.id))" -ForegroundColor Green
        }
        else { Write-Host "    found group $($g.name) ($($group.id))" -ForegroundColor Green }
        $g.objectId = $group.id

        # Make membership match the plan for the four test users; other members are not touched.
        $current = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/groups/$($group.id)/members?`$select=id").value | ForEach-Object { $_.id })
        foreach ($u in $userPlan) {
            $wanted = $u.Groups -contains $g.id
            $isMember = $current -contains $u.Id
            if ($wanted -and -not $isMember) {
                Invoke-MgGraphRequest -Method POST -ContentType "application/json" -Uri "$graph/groups/$($group.id)/members/`$ref" `
                    -Body (@{ "@odata.id" = "$graph/directoryObjects/$($u.Id)" } | ConvertTo-Json) | Out-Null
                Write-Host "      added   $($u.Key) $($u.Upn)" -ForegroundColor Green
            }
            elseif (-not $wanted -and $isMember) {
                Invoke-MgGraphRequest -Method DELETE -Uri "$graph/groups/$($group.id)/members/$($u.Id)/`$ref" | Out-Null
                Write-Host "      removed $($u.Key) $($u.Upn)" -ForegroundColor Green
            }
            elseif ($wanted) { Write-Host "      member  $($u.Key) $($u.Upn)" }
        }
    }

    # Who may use the agents: app role Agent.Invoke on the blueprint and on every agent identity.
    # It only blocks anyone once the gate is on (Set-AgentUserAccess.ps1 -RequireAssignment $true).
    $agentIds = @(@($AgentIdentityId) + @((Read-JsonWithComments $appsPath).GatewayAgentIdentities |
        Where-Object { $_ -and (Test-ConfiguredId $_["ClientId"]) } | ForEach-Object { $_["ClientId"] })) |
        Where-Object { $_ } | Sort-Object -Unique
    Write-Host "`n    Blueprint and agent assignments (Set-AgentUserAccess.ps1, $($agentIds.Count) agents)" -ForegroundColor Yellow
    $access = @{ TenantId = $TenantId; BlueprintAppId = $BlueprintAppId; AgentIdentityId = $agentIds; NoReport = $true }
    & (Join-Path $PSScriptRoot "Set-AgentUserAccess.ps1") @access -Grant  -User @($userPlan | Where-Object { $_.AgentAccess } | ForEach-Object { $_.Id })
    & (Join-Path $PSScriptRoot "Set-AgentUserAccess.ps1") @access -Revoke -User @($userPlan | Where-Object { -not $_.AgentAccess } | ForEach-Object { $_.Id })

    # Object ids for the gateway tab's PDP playground presets.
    foreach ($u in @($userPlan | Where-Object { $_.Key -ne "User4" })) {
        Set-AppSetting $appsPath "GatewayMcp" "$($u.Key)ObjectId" $u.Id
    }
    Write-Host "`n    appsettings.json GatewayMcp:User1ObjectId..User3ObjectId" -ForegroundColor Green

    if ($pdpTable) {
        foreach ($g in $groupPlan) {
            $properties = @{ displayName = $g.name; entraObjectId = $g.objectId }
            if ($g.region) { $properties.region = $g.region }
            Set-PdpEntity $pdpTable "group" $g.id $properties
        }
        Write-Host "    PdpEntities group/*: $($groupPlan.Count) group object ids" -ForegroundColor Green
        # Local members are only used when the PDP runs with GROUP_SOURCE=local (no Graph).
        foreach ($u in $userPlan) {
            foreach ($key in @($u.Id.ToLower(), $u.Upn.ToLower())) {
                if ($u.Groups.Count) { Set-PdpEntity $pdpTable "member" $key @{ groups = ($u.Groups -join ",") } }
                else { Remove-PdpEntity $pdpTable "member" $key | Out-Null }
            }
        }
        Write-Host "    PdpEntities member/*: User1, User2 (User3 and User4 have no row)" -ForegroundColor Green
    }
    else { Write-Host $pdpPending -ForegroundColor Yellow }
}

# ---------------------------------------------------------------------------
# 5. Optional: direct grants on Agent1 (docs/entra-setup.md 4D; -TestAgents does this too)
# ---------------------------------------------------------------------------
if ($AssignAgentPermissions -and -not $TestAgents) {
    Write-Host "`n[5] Direct grants on the agent identity" -ForegroundColor Cyan
    if (-not (Test-ConfiguredId $AgentIdentityId)) { throw "No agent identity yet: pass -AgentIdentityId, or use -TestAgents to create Agent1." }
    Set-AppRole $AgentIdentityId $claimsApiSp "Claims.Analyze.All" "agent identity -> Claims API"
    Set-DelegatedGrant $AgentIdentityId $claimsApiSp.Id "Claims.Analyze" "agent identity -> Claims API"
}

# ---------------------------------------------------------------------------
# 6. Optional: more agent identities from the same blueprint
# ---------------------------------------------------------------------------
if ($NewAgent.Count) {
    Write-Host "`n[6] Additional agent identities from blueprint $BlueprintAppId" -ForegroundColor Cyan
    foreach ($name in $NewAgent) {
        Write-Host "`n    $name" -ForegroundColor Yellow
        $agentId = Use-AgentIdentity $name
        Set-McpAgentGrants $agentId

        $note = if ($NotInPdp) { "not registered in the PDP, so the gateway refuses it" } else { "registered in the PDP, autonomous limit $('{0:N0}' -f $AutonomousLimit)" }
        $action = Set-GatewayAgentIdentity $appsPath $name $agentId $note
        Write-Host "    appsettings.json GatewayAgentIdentities ($action)" -ForegroundColor Green
        if ($NotInPdp) {
            Write-Host "    PDP registry: left out (-NotInPdp)" -ForegroundColor DarkGray
        }
        elseif ($pdpTable) {
            $action = Set-PdpAgent $pdpTable $agentId $name $BlueprintAppId $AutonomousLimit
            Write-Host "    PdpEntities agent/$($agentId.ToLower()) ($action, autonomousLimit $AutonomousLimit)" -ForegroundColor Green
        }
        else {
            Write-Host "    PDP registry: storage not deployed yet; add the agent on the web app's PDP entities sub-tab later" -ForegroundColor Yellow
        }
        Write-Host "    For 'on behalf of user' with the user gate on: .\Configure\Set-AgentUserAccess.ps1 -AgentIdentityId $agentId -Grant -User <upn>" -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# 7. Report what Agent1, the blueprint principal and the host app currently hold
# ---------------------------------------------------------------------------
function Show-Grants([string] $Label, [string] $PrincipalId) {
    Write-Host "`n    $Label ($PrincipalId)" -ForegroundColor Yellow
    $roleAssignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -ErrorAction SilentlyContinue)
    # (SilentlyContinue is deliberate here: this is a report, an unreadable principal just shows "none".)
    if ($roleAssignments.Count -eq 0) { Write-Host "      app role assignments : none" }
    foreach ($ra in $roleAssignments) {
        $resourceSp = Get-MgServicePrincipal -ServicePrincipalId $ra.ResourceId
        $roleValue = ($resourceSp.AppRoles | Where-Object Id -eq $ra.AppRoleId | Select-Object -First 1).Value
        Write-Host ("      app role assignment  : {0} -> {1}" -f $ra.ResourceDisplayName, $roleValue)
    }
    $grants = @(Get-DelegatedGrants $PrincipalId "")
    if ($grants.Count -eq 0) { Write-Host "      delegated grants     : none" }
    foreach ($g in $grants) {
        $resourceSp = Get-MgServicePrincipal -ServicePrincipalId $g.resourceId
        Write-Host ("      delegated grant      : {0} -> {1} ({2})" -f $resourceSp.DisplayName, $g.scope, $g.consentType)
    }
}

Write-Host "`n[7] Current grants" -ForegroundColor Cyan
if (Test-ConfiguredId $AgentIdentityId) { Show-Grants "Agent identity (Agent1)" $AgentIdentityId }
Show-Grants "Blueprint principal" $blueprintSp.Id
Show-Grants "Host app" $hostSp.Id

$inheritable = Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
    -Uri "$graph/applications/microsoft.graph.agentIdentityBlueprint/$blueprintObjectId/inheritablePermissions" -ErrorAction SilentlyContinue
$inheritableForClaims = @($inheritable.value | Where-Object { $_.resourceAppId -eq $ClaimsApiAppId })
Write-Host ("`n    Blueprint inheritablePermissions for Claims API: {0}" -f ($(if ($inheritableForClaims.Count) { "yes (scopes: $($inheritableForClaims[0].inheritableScopes.kind), roles: $($inheritableForClaims[0].inheritableRoles.kind))" } else { "none" })))

if (-not ($TestAgents -or $AssignAgentPermissions -or $NewAgent.Count)) {
    Write-Host "`nRe-run with -AssignAgentPermissions for the direct Claims API grants on the agent identity (docs/entra-setup.md 4D), or with -SetupAll (or -TestAgents -TestUsers) for the full test setup (docs/test-identities.md)." -ForegroundColor DarkGray
}
if ($TestAppRegs -or $TestAgents -or $TestUsers -or $NewAgent.Count) {
    Write-Host "`nRestart the web app to pick up appsettings.json changes (agent drop-down, PDP presets)." -ForegroundColor Cyan
}
if ($TestUsers) {
    Write-Host "User4 is refused an agent token only while the blueprint's user gate is on: .\Configure\Set-AgentUserAccess.ps1 -RequireAssignment `$true" -ForegroundColor Cyan
}
Write-Host "`nDone. Grants can take a minute or two to show up in new tokens." -ForegroundColor Cyan
