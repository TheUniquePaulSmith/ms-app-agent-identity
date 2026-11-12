#requires -Version 7.0
<#
.SYNOPSIS
    Applies the Graph-only parts of docs/entra-setup.md for the agent blueprint and agent identity,
    and optionally creates the POC's test agents (Agent1-4) and test users (User1-4) with the Entra
    groups the PDP policies use.

.DESCRIPTION
    Steps (each is idempotent and prints what it found or changed):

      1. Blueprint: set identifier URI api://<blueprint-app-id> and expose the access_agent scope (docs/entra-setup.md 4C.3).
      2. Host app: grant the delegated access_agent scope on the blueprint principal (docs/entra-setup.md 4B).
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
      .\Configure\Configure-Entra.ps1 -TestAgents -TestUsers             # the full test setup
      .\Configure\Configure-Entra.ps1 -TestUsers -User1 alice@contoso.com -User2 bob@contoso.com
      .\Configure\Configure-Entra.ps1 -NewAgent "POC Claims Agent 5" -AutonomousLimit 2000

    Run it again after Deploy-GatewayPoc.ps1 to write the test agents, groups and members into the
    PDP registry (the table exists only once deployed).

.NOTES
    Needs: Microsoft.Graph PowerShell module and a user with Agent ID Administrator (or owner of the
    blueprint) plus rights to grant application permissions (for example Cloud Application Administrator).
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
    [switch]   $TestAgents,
    [switch]   $TestUsers,
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

$TenantId        = Resolve-Setting $TenantId        "TenantId"        $appsPath "HostApplication:TenantId", "AgentBlueprint:TenantId"
$ClaimsApiAppId  = Resolve-Setting $ClaimsApiAppId  "ClaimsApiAppId"  $appsPath "DownstreamApis:ClaimsApiAsAgent:Scopes:0"
$HostAppId       = Resolve-Setting $HostAppId       "HostAppId"       $appsPath "HostApplication:ClientId"
$BlueprintAppId  = Resolve-Setting $BlueprintAppId  "BlueprintAppId"  $appsPath "AgentBlueprint:ClientId"
# -TestAgents creates Agent1 when AgentIdentity:ClientId is still a placeholder.
$AgentIdentityId = if ($TestAgents) {
    try { Resolve-Setting $AgentIdentityId "AgentIdentityId" $appsPath "AgentIdentity:ClientId" } catch { "" }
}
else { Resolve-Setting $AgentIdentityId "AgentIdentityId" $appsPath "AgentIdentity:ClientId" }
# The MCP server (created by Configure-McpEntra.ps1) is needed only for agent grants on it.
$needsMcp = ($TestAgents -or $NewAgent.Count -gt 0) -and -not $SkipMcpPermissions
if ($needsMcp) {
    $McpAppId = Resolve-Setting $McpAppId "McpAppId" $appsPath "McpServer:ClientId"
}

$scopes = @(
    "Application.Read.All",
    "AgentIdentityBlueprint.UpdateAuthProperties.All",
    "DelegatedPermissionGrant.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "User.Read"
)
if ($TestUsers) {
    # Users, groups, and the blueprint / agent user assignments (Set-AgentUserAccess.ps1).
    $scopes += @("User.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.ReadWrite.All",
                 "AgentIdentityBlueprintPrincipal.ReadWrite.All", "User.ReadBasic.All", "GroupMember.Read.All")
}
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes $scopes

$claimsApiSp = Get-MgServicePrincipal -Filter "appId eq '$ClaimsApiAppId'"
$hostSp      = Get-MgServicePrincipal -Filter "appId eq '$HostAppId'"
$blueprintSp = Get-MgServicePrincipal -Filter "appId eq '$BlueprintAppId'"
if (-not $claimsApiSp) { throw "No service principal for Claims API $ClaimsApiAppId. Open its Enterprise application once." }
if (-not $hostSp)      { throw "No service principal for host app $HostAppId." }
if (-not $blueprintSp) { throw "No blueprint principal for $BlueprintAppId (docs/entra-setup.md 4C.1)." }
$mcpSp = $null
if ($needsMcp) {
    $mcpSp = Get-MgServicePrincipal -Filter "appId eq '$McpAppId'"
    if (-not $mcpSp) { throw "No service principal for the MCP server $McpAppId (run Configure-McpEntra.ps1 first)." }
}

Write-Host ("Claims API SP  : {0}  ({1})" -f $claimsApiSp.Id, $claimsApiSp.DisplayName)
Write-Host ("Host app SP    : {0}  ({1})" -f $hostSp.Id, $hostSp.DisplayName)
Write-Host ("Blueprint SP   : {0}  ({1})" -f $blueprintSp.Id, $blueprintSp.DisplayName)
Write-Host ("Agent identity : {0}" -f $(if ($AgentIdentityId) { $AgentIdentityId } else { "(not set; -TestAgents creates it)" }))

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

# A just-created agent identity takes a while to replicate in the directory: until then Graph answers
# 404 Request_ResourceNotFound for it, and even once one read succeeds another replica may still 404.
# Runs $Action, retrying 404s every 10 s for up to 2 minutes.
function Invoke-WhenReplicated([string] $PrincipalId, [scriptblock] $Action) {
    for ($attempt = 1; ; $attempt++) {
        try { & $Action; return }
        catch {
            $message = "$($_.Exception.Message) $($_.ErrorDetails)"
            if ($attempt -ge 12 -or $message -notmatch "Request_ResourceNotFound|does not exist|404") { throw }
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
        $tokenResponse = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body @{
            grant_type    = "client_credentials"
            client_id     = $BlueprintAppId
            client_secret = $blueprintSecret
            scope         = "https://graph.microsoft.com/.default"
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

# Finds the agent identity with this display name (or one of its older names) under the blueprint,
# or creates it (sponsor: the signed-in admin). Returns its id (for agent identities the app id
# equals the object id).
$script:me = $null
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
    if (-not $script:me) { $script:me = Invoke-MgGraphRequest -Method GET -Uri "$graph/me?`$select=id,userPrincipalName" }
    $body = @{
        displayName              = $Name
        agentIdentityBlueprintId = $BlueprintAppId
        "sponsors@odata.bind"    = @("$graph/users/$($script:me.id)")
    } | ConvertTo-Json
    $new = Invoke-RestMethod -Method POST -Headers (Get-BlueprintHeaders) -ContentType "application/json" `
        -Uri "$graph/servicePrincipals/microsoft.graph.agentIdentity" -Body $body
    Write-Host "    created: $($new.id) (sponsor $($script:me.userPrincipalName))" -ForegroundColor Green
    return $new.id
}

function Set-McpAgentGrants([string] $AgentId) {
    if (-not $mcpSp) { return }
    Invoke-WhenReplicated $AgentId { Set-AppRole $AgentId $mcpSp "Mcp.Analyze.All" "-> MCP server" }
    Invoke-WhenReplicated $AgentId { Set-DelegatedGrant $AgentId $mcpSp.Id "Mcp.Analyze" "-> MCP server" }
}

$pdpTable = Get-PdpTable $appsPath
$pdpPending = "    PDP registry: storage not deployed yet (GatewayMcp:StorageConnectionString empty); run this script again after Deploy-GatewayPoc.ps1"

# ---------------------------------------------------------------------------
# 1. Blueprint identifier URI + access_agent scope
# ---------------------------------------------------------------------------
Write-Host "`n[1] Blueprint identifier URI and access_agent scope" -ForegroundColor Cyan
$bpApp = Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
    -Uri "$graph/applications/$BlueprintAppId`?`$select=id,appId,displayName,identifierUris,api"

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
        -Uri "$graph/applications/$BlueprintAppId" -Body $body | Out-Null

    $check = Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
        -Uri "$graph/applications/$BlueprintAppId`?`$select=identifierUris,api"
    Write-Host ("    set: {0}; scopes: {1}" -f ($check.identifierUris -join ", "), (($check.api.oauth2PermissionScopes | ForEach-Object value) -join ", ")) -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 2. Host app -> delegated access_agent on the blueprint principal
# ---------------------------------------------------------------------------
Write-Host "`n[2] Host app delegated grant: access_agent on the blueprint" -ForegroundColor Cyan
Set-DelegatedGrant $hostSp.Id $blueprintSp.Id "access_agent" "host app -> blueprint"

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
Show-Grants "Agent identity (Agent1)" $AgentIdentityId
Show-Grants "Blueprint principal" $blueprintSp.Id
Show-Grants "Host app" $hostSp.Id

$inheritable = Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
    -Uri "$graph/applications/microsoft.graph.agentIdentityBlueprint/$BlueprintAppId/inheritablePermissions" -ErrorAction SilentlyContinue
$inheritableForClaims = @($inheritable.value | Where-Object { $_.resourceAppId -eq $ClaimsApiAppId })
Write-Host ("`n    Blueprint inheritablePermissions for Claims API: {0}" -f ($(if ($inheritableForClaims.Count) { "yes (scopes: $($inheritableForClaims[0].inheritableScopes.kind), roles: $($inheritableForClaims[0].inheritableRoles.kind))" } else { "none" })))

if (-not ($TestAgents -or $AssignAgentPermissions -or $NewAgent.Count)) {
    Write-Host "`nRe-run with -AssignAgentPermissions for the direct Claims API grants on the agent identity (docs/entra-setup.md 4D), or with -TestAgents -TestUsers for the full test setup (docs/test-identities.md)." -ForegroundColor DarkGray
}
if ($TestAgents -or $TestUsers -or $NewAgent.Count) {
    Write-Host "`nRestart the web app to pick up appsettings.json changes (agent drop-down, PDP presets)." -ForegroundColor Cyan
}
if ($TestUsers) {
    Write-Host "User4 is refused an agent token only while the blueprint's user gate is on: .\Configure\Set-AgentUserAccess.ps1 -RequireAssignment `$true" -ForegroundColor Cyan
}
Write-Host "`nDone. Grants can take a minute or two to show up in new tokens." -ForegroundColor Cyan
