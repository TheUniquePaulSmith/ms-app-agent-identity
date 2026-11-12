#requires -Version 7.0
<#
.SYNOPSIS
    Controls which users and groups may use an agent, through an app role gate on its blueprint.

.DESCRIPTION
    Users never get a token for the agent identity itself. In scenario 4 they get a token for the
    BLUEPRINT (api://<blueprint>/access_agent) and the blueprint exchanges it (OBO) as the agent
    identity. "Who may use the agent" is therefore enforced on the blueprint principal:

      1. Agent identity: confirm it belongs to the blueprint and list the other agent identities
         under the same blueprint (the gate applies to all of them).
      2. Blueprint: make sure it defines a user-assignable app role (default Agent.Invoke).
      3. With -Grant / -Revoke: add or remove that role for the given users and groups, on the
         blueprint AND on each agent identity (-AgentIdentityId, one or more). With the gate on, the OBO exchange
         as the agent checks the agent identity's own assignments (AADSTS50106).
      4. With -RequireAssignment $true|$false: switch appRoleAssignmentRequired on the blueprint
         principal. When on, Entra refuses to issue blueprint tokens to unassigned users
         (AADSTS50105), so they can never reach the OBO exchange.
      5. Report the current gate setting and every assignment.

    Run it in a normal PowerShell 7 prompt:
      .\Configure\Set-AgentUserAccess.ps1                                              # report only
      .\Configure\Set-AgentUserAccess.ps1 -Grant  -User alice@contoso.com -Group "Claims Adjusters"
      .\Configure\Set-AgentUserAccess.ps1 -Revoke -User alice@contoso.com
      .\Configure\Set-AgentUserAccess.ps1 -RequireAssignment $true                     # turn the gate on
      .\Configure\Set-AgentUserAccess.ps1 -RequireAssignment $false                    # back to open

    -User takes a UPN or object id, -Group a display name or object id. Assigned users get the role
    value in the roles claim of their access_agent token, so the agent can also check it in code.

.NOTES
    Needs: Microsoft.Graph PowerShell module and a user with Agent ID Administrator (or owner of the
    blueprint) plus Cloud Application Administrator for app roles and assignments.
    Assigning groups needs Microsoft Entra ID P1; only direct members of a group get the role.
    If adding the app role fails with 403, reconnect with AgentIdentityBlueprint.ReadWrite.All.
#>
[CmdletBinding()]
param(
    # Ids default to the values in appsettings.json; pass them to override (nothing is hard-coded).
    [string]   $TenantId,
    [string]   $BlueprintAppId,
    [string[]] $AgentIdentityId = @(),
    [string]   $RoleValue       = "Agent.Invoke",
    [string[]] $User            = @(),
    [string[]] $Group           = @(),
    [switch]   $Grant,
    [switch]   $Revoke,
    [Nullable[bool]] $RequireAssignment,
    [switch]   $NoReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$appsPath = Join-Path (Split-Path -Parent $PSScriptRoot) "appsettings.json"

# Read-JsonWithComments, Resolve-Setting
. (Join-Path $PSScriptRoot "GatewayConfigFiles.ps1")

$TenantId        = Resolve-Setting $TenantId        "TenantId"        $appsPath "HostApplication:TenantId", "AgentBlueprint:TenantId"
$BlueprintAppId  = Resolve-Setting $BlueprintAppId  "BlueprintAppId"  $appsPath "AgentBlueprint:ClientId"
# One or more agent identities from the blueprint; each gets the same assignments.
if ($AgentIdentityId.Count -eq 0) {
    $AgentIdentityId = @(Resolve-Setting "" "AgentIdentityId" $appsPath "AgentIdentity:ClientId")
}

if ($Grant -and $Revoke) { throw "Use either -Grant or -Revoke, not both." }
if (($Grant -or $Revoke) -and ($User.Count + $Group.Count) -eq 0) { throw "-Grant / -Revoke need at least one -User or -Group." }

$graphHeaders = @{ "OData-Version" = "4.0" }
$graph = "https://graph.microsoft.com/v1.0"

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes @(
    "Application.Read.All",
    "AgentIdentityBlueprint.UpdateAuthProperties.All",
    "AgentIdentityBlueprintPrincipal.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "User.ReadBasic.All",
    "GroupMember.Read.All"
)

function Get-AllPages([string] $Uri) {
    $items = @()
    while ($Uri) {
        $page = Invoke-MgGraphRequest -Method GET -Headers $graphHeaders -Uri $Uri
        $items += @($page.value)
        $Uri = $page["@odata.nextLink"]
    }
    return $items
}

$blueprintSp = (Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
    -Uri "$graph/servicePrincipals?`$filter=appId eq '$BlueprintAppId'&`$select=id,displayName,appRoleAssignmentRequired,appRoles").value |
    Select-Object -First 1
if (-not $blueprintSp) { throw "No blueprint principal for $BlueprintAppId (docs/entra-setup.md 4C.1)." }

Write-Host ("Blueprint SP   : {0}  ({1})" -f $blueprintSp.id, $blueprintSp.displayName)

# ---------------------------------------------------------------------------
# 1. The agent identity and its siblings under the same blueprint
# ---------------------------------------------------------------------------
Write-Host "`n[1] Agent identities and blueprint" -ForegroundColor Cyan
$agents = foreach ($id in $AgentIdentityId) {
    $a = Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
        -Uri "$graph/servicePrincipals/$id/microsoft.graph.agentIdentity?`$select=id,displayName,agentIdentityBlueprintId"
    if ($a.agentIdentityBlueprintId -ne $BlueprintAppId) {
        throw "Agent identity $id belongs to blueprint $($a.agentIdentityBlueprintId), not $BlueprintAppId."
    }
    Write-Host ("    agent identity : {0}  ({1})" -f $a.id, $a.displayName)
    $a
}
$agents = @($agents)

$siblings = $agents
try {
    $siblings = @(Get-AllPages "$graph/servicePrincipals/microsoft.graph.agentIdentity?`$filter=agentIdentityBlueprintId eq '$BlueprintAppId'&`$select=id,displayName")
    Write-Host ("    agent identities under this blueprint: {0}" -f $siblings.Count)
    foreach ($s in $siblings) { Write-Host ("      {0}  ({1})" -f $s.id, $s.displayName) }
    if ($siblings.Count -gt 1) {
        Write-Host "    note: the gate is per blueprint, so it controls access to ALL of these agents." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "    could not list sibling agent identities: $($_.Exception.Message)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 2. Blueprint app role that users are assigned to
# ---------------------------------------------------------------------------
Write-Host "`n[2] Blueprint app role '$RoleValue'" -ForegroundColor Cyan
$bpApp = Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
    -Uri "$graph/applications/$BlueprintAppId`?`$select=id,appId,appRoles"
$existingRoles = @($bpApp.appRoles)
$role = $existingRoles | Where-Object { $_.value -eq $RoleValue } | Select-Object -First 1

if ($role) {
    if (@($role.allowedMemberTypes) -notcontains "User") { throw "App role '$RoleValue' exists but is not assignable to users." }
    Write-Host "    already defined (id $($role.id))" -ForegroundColor Green
}
else {
    $role = @{
        id                 = [guid]::NewGuid().ToString()
        value              = $RoleValue
        displayName        = "Use the agent"
        description        = "Allows the user to call the agent, which then acts on the user's behalf."
        allowedMemberTypes = @("User")
        isEnabled          = $true
    }
    $body = @{ appRoles = @($existingRoles + $role) } | ConvertTo-Json -Depth 8
    Invoke-MgGraphRequest -Method PATCH -Headers $graphHeaders -ContentType "application/json" `
        -Uri "$graph/applications/$BlueprintAppId" -Body $body | Out-Null
    Write-Host "    added app role $RoleValue (id $($role.id))" -ForegroundColor Green

    # The blueprint principal picks the role up from the application asynchronously; assignments
    # against it are rejected until it does.
    for ($i = 0; $i -lt 10; $i++) {
        $spRoles = (Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
            -Uri "$graph/servicePrincipals/$($blueprintSp.id)?`$select=appRoles").appRoles
        if (@($spRoles | Where-Object { $_.id -eq $role.id }).Count) { break }
        Start-Sleep -Seconds 3
    }
}
$roleId = $role.id

# ---------------------------------------------------------------------------
# 3. Grant / revoke for users and groups
# ---------------------------------------------------------------------------
function Resolve-Principal([string] $Kind, [string] $Value) {
    $parsed = [guid]::Empty
    if ([guid]::TryParse($Value, [ref] $parsed)) {
        $obj = Invoke-MgGraphRequest -Method GET -Headers $graphHeaders -Uri "$graph/directoryObjects/$Value"
        return @{ id = $obj.id; name = $obj.displayName }
    }
    if ($Kind -eq "user") {
        $obj = Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
            -Uri "$graph/users/$([uri]::EscapeDataString($Value))?`$select=id,displayName,userPrincipalName"
        return @{ id = $obj.id; name = "$($obj.displayName) <$($obj.userPrincipalName)>" }
    }
    $escaped = $Value.Replace("'", "''")
    $found = @((Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
        -Uri "$graph/groups?`$filter=displayName eq '$([uri]::EscapeDataString($escaped))'&`$select=id,displayName").value)
    if ($found.Count -ne 1) { throw "Group '$Value' matched $($found.Count) groups; pass its object id instead." }
    return @{ id = $found[0].id; name = $found[0].displayName }
}

$assignedToUri = "$graph/servicePrincipals/$($blueprintSp.id)/appRoleAssignedTo"

# With the gate on, Entra checks the user twice: assignment to the blueprint when the client asks
# for an access_agent token (AADSTS50105), and assignment to the agent identity itself when the
# blueprint exchanges that token as the agent (AADSTS50106, "parent application ... blocks users").
$gates = @(@{ label = "blueprint"; uri = $assignedToUri; resourceId = $blueprintSp.id; roleId = $roleId })
foreach ($agent in $agents) {
    # The agent identity has no app roles of its own unless it surfaces the blueprint's; use the
    # matching role when it does, otherwise the default access role (all zeros).
    $agentSpRoles = @((Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
        -Uri "$graph/servicePrincipals/$($agent.id)?`$select=appRoles").appRoles)
    $agentRole = $agentSpRoles | Where-Object { $_.value -eq $RoleValue } | Select-Object -First 1
    $gates += @{
        label      = "agent $($agent.displayName)"
        uri        = "$graph/servicePrincipals/$($agent.id)/appRoleAssignedTo"
        resourceId = $agent.id
        roleId     = if ($agentRole) { $agentRole.id } else { [guid]::Empty.ToString() }
    }
}

if ($Grant -or $Revoke) {
    Write-Host ("`n[3] {0}" -f $(if ($Grant) { "Grant $RoleValue" } else { "Revoke $RoleValue" })) -ForegroundColor Cyan
    $targets = @($User | ForEach-Object { Resolve-Principal "user" $_ }) + @($Group | ForEach-Object { Resolve-Principal "group" $_ })

    foreach ($gate in $gates) {
        Write-Host "    on $($gate.label):"
        $current = @(Get-AllPages $gate.uri)
        foreach ($t in $targets) {
            $existing = @($current | Where-Object { $_.principalId -eq $t.id -and $_.appRoleId -eq $gate.roleId })
            if ($Grant) {
                if ($existing.Count) {
                    Write-Host "      already assigned : $($t.name)" -ForegroundColor Green
                    continue
                }
                $body = @{ principalId = $t.id; resourceId = $gate.resourceId; appRoleId = $gate.roleId } | ConvertTo-Json
                Invoke-MgGraphRequest -Method POST -Headers $graphHeaders -ContentType "application/json" `
                    -Uri $gate.uri -Body $body | Out-Null
                Write-Host "      assigned         : $($t.name)" -ForegroundColor Green
            }
            else {
                if (-not $existing.Count) {
                    Write-Host "      not assigned     : $($t.name)" -ForegroundColor DarkGray
                    continue
                }
                foreach ($a in $existing) {
                    Invoke-MgGraphRequest -Method DELETE -Headers $graphHeaders -Uri "$($gate.uri)/$($a.id)" | Out-Null
                }
                Write-Host "      revoked          : $($t.name)" -ForegroundColor Green
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 4. appRoleAssignmentRequired on the blueprint principal
# ---------------------------------------------------------------------------
if ($null -ne $RequireAssignment) {
    Write-Host "`n[4] appRoleAssignmentRequired = $RequireAssignment" -ForegroundColor Cyan
    if ($RequireAssignment -and @(Get-AllPages $assignedToUri).Count -eq 0) {
        Write-Host "    warning: nobody is assigned yet, so every user will now be refused (AADSTS50105)." -ForegroundColor Yellow
    }
    $body = @{ appRoleAssignmentRequired = [bool] $RequireAssignment } | ConvertTo-Json
    Invoke-MgGraphRequest -Method PATCH -Headers $graphHeaders -ContentType "application/json" `
        -Uri "$graph/servicePrincipals/$($blueprintSp.id)/microsoft.graph.agentIdentityBlueprintPrincipal" -Body $body | Out-Null
    Write-Host "    set" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 5. Report
# ---------------------------------------------------------------------------
if ($NoReport) { return }
Write-Host "`n[5] Current access" -ForegroundColor Cyan
$required = (Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
    -Uri "$graph/servicePrincipals/$($blueprintSp.id)?`$select=appRoleAssignmentRequired").appRoleAssignmentRequired
if ($required) {
    Write-Host "    gate: ON  (only the principals below can get an access_agent token)" -ForegroundColor Green
}
else {
    Write-Host "    gate: OFF (any user in the tenant can get an access_agent token; assignments only add the roles claim)" -ForegroundColor Yellow
}

$spRoles = (Invoke-MgGraphRequest -Method GET -Headers $graphHeaders `
    -Uri "$graph/servicePrincipals/$($blueprintSp.id)?`$select=appRoles").appRoles
$assignments = @(Get-AllPages $assignedToUri)
Write-Host "    on blueprint $($blueprintSp.displayName):"
if ($assignments.Count -eq 0) { Write-Host "      none" }
foreach ($a in $assignments) {
    $value = if ($a.appRoleId -eq [guid]::Empty.ToString()) { "(default access)" }
             else { (@($spRoles | Where-Object { $_.id -eq $a.appRoleId }) | Select-Object -First 1).value }
    Write-Host ("      {0,-17} {1,-40} {2}" -f $a.principalType, $a.principalDisplayName, $value)
}

# Per agent identity: the second check (AADSTS50106) happens here.
foreach ($s in $siblings) {
    Write-Host "    on agent $($s.id) ($($s.displayName)):"
    try {
        $agentAssignments = @(Get-AllPages "$graph/servicePrincipals/$($s.id)/appRoleAssignedTo")
        if ($agentAssignments.Count -eq 0) { Write-Host "      none" -ForegroundColor $(if ($required) { "Yellow" } else { "Gray" }) }
        foreach ($a in $agentAssignments) {
            $value = if ($a.appRoleId -eq [guid]::Empty.ToString()) { "(default access)" } else { $a.appRoleId }
            Write-Host ("      {0,-17} {1,-40} {2}" -f $a.principalType, $a.principalDisplayName, $value)
        }
    }
    catch {
        Write-Host "      could not read: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

Write-Host "`nDone. Changes apply to new access_agent tokens; sign out and back in to pick them up." -ForegroundColor Cyan
