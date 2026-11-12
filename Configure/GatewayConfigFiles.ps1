# Helpers shared by the scripts in Configure/ for the configuration the web app, the gateway tab
# and the PDP read.
# Dot-source it:  . (Join-Path $PSScriptRoot "GatewayConfigFiles.ps1")
#
#   appsettings.json                   tenant and app ids (Resolve-Setting), GatewayAgentIdentities
#                                      (agent drop-down on the gateway tab)
#   Azure Table "PdpEntities"          PDP entity registry (agent-must-be-registered, groups, ...),
#                                      reached with GatewayMcp:StorageConnectionString
#
# appsettings.json is local (git-ignored): copy appsettings.sample.json and fill it in (docs/run-locally.md).
# It has // comments, so it is edited as text: only the GatewayAgentIdentities array is rewritten
# and every comment outside it is kept.

function Read-JsonWithComments([string] $Path) {
    (Get-Content $Path -Raw) -replace '(?m)^\s*//.*$', '' | ConvertFrom-Json -AsHashtable
}

function Test-ConfiguredId([string] $Value) {
    -not [string]::IsNullOrWhiteSpace($Value) -and -not $Value.StartsWith("<")
}

# Sets "Key": "value" inside the top-level object "Section" of appsettings.json, editing the text so
# comments survive. Adds the key at the top of the section when it is missing.
function Set-AppSetting([string] $AppsPath, [string] $Section, [string] $Key, [string] $Value) {
    $text  = Get-Content $AppsPath -Raw
    $start = $text.IndexOf('"' + $Section + '"')
    if ($start -lt 0) { throw "appsettings.json has no $Section section." }
    $open  = $text.IndexOf("{", $start)
    $end   = $text.IndexOf("}", $open)
    $body  = $text.Substring($open, $end - $open)
    $quoted = ConvertTo-Json -InputObject $Value
    $pattern = '("' + [regex]::Escape($Key) + '"\s*:\s*)"[^"]*"'
    if ($body -match $pattern) {
        $body = [regex]::Replace($body, $pattern, { param($m) $m.Groups[1].Value + $quoted })
    }
    else {
        $body = "{`n    `"$Key`": $quoted," + $body.Substring(1)
    }
    Set-Content -Path $AppsPath -Value ($text.Substring(0, $open) + $body + $text.Substring($end)) -NoNewline
}

# No tenant or object id is hard-coded in these scripts. Returns $Value when the caller passed it;
# otherwise the first configured value among $Keys ("Section:Key", array indexes allowed) in
# appsettings.json; otherwise stops and names the missing parameter.
# "api://<app-id>/<scope>" yields <app-id>. With -Pattern, the value must match and capture group 1
# is returned (for example the name prefix inside a deployed URL).
function Resolve-Setting([string] $Value, [string] $Parameter, [string] $AppsPath, [string[]] $Keys, [string] $Pattern) {
    if (Test-ConfiguredId $Value) { return $Value }
    $settings = if ($AppsPath -and (Test-Path $AppsPath)) { Read-JsonWithComments $AppsPath } else { @{} }
    foreach ($key in $Keys) {
        $v = $settings
        foreach ($part in $key.Split(":")) {
            if ($v -is [System.Collections.IDictionary] -and $v.Contains($part)) { $v = $v[$part] }
            elseif ($v -is [System.Collections.IList] -and $part -match '^\d+$' -and [int] $part -lt $v.Count) { $v = $v[[int] $part] }
            else { $v = $null; break }
        }
        $v = [string] $v
        if ($Pattern) { $v = if ($v -match $Pattern) { $Matches[1] } else { "" } }
        elseif ($v -match '^api://([^/]+)/') { $v = $Matches[1] }
        if (Test-ConfiguredId $v) { return $v }
    }
    $where = if ($Keys) { " or set $($Keys -join ' / ') in appsettings.json (copy of appsettings.sample.json)" } else { "" }
    throw "Missing -$Parameter. Pass it$where."
}

# Start and end (inclusive) of the JSON array that follows "<Key>": in $Text, skipping brackets in strings.
function Find-JsonArray([string] $Text, [string] $Key) {
    $keyAt = $Text.IndexOf('"' + $Key + '"')
    if ($keyAt -lt 0) { return $null }
    $start = $Text.IndexOf("[", $keyAt)
    $depth = 0; $inString = $false
    for ($i = $start; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ($inString) {
            if ($c -eq "\") { $i++ } elseif ($c -eq '"') { $inString = $false }
            continue
        }
        if ($c -eq '"') { $inString = $true }
        elseif ($c -eq "[") { $depth++ }
        elseif ($c -eq "]") { $depth--; if ($depth -eq 0) { return @{ Start = $start; End = $i } } }
    }
    throw "Unbalanced brackets after `"$Key`"."
}

# Adds or updates one agent in appsettings.json GatewayAgentIdentities. Matches by ClientId, or by
# Name when that entry still holds a placeholder ("<run ...>"); otherwise appends.
function Set-GatewayAgentIdentity([string] $AppsPath, [string] $Name, [string] $ClientId, [string] $Note) {
    $text = Get-Content $AppsPath -Raw
    $span = Find-JsonArray $text "GatewayAgentIdentities"
    if (-not $span) {
        # No section yet: add one right after the GatewayMcp object.
        $gwAt = $text.IndexOf('"GatewayMcp"')
        if ($gwAt -lt 0) { throw "appsettings.json has neither GatewayAgentIdentities nor GatewayMcp." }
        $insertAt = $text.IndexOf("}", $gwAt) + 1
        # The comma that followed GatewayMcp (if any) now follows the new array.
        $text = $text.Substring(0, $insertAt) + ",`n`n  `"GatewayAgentIdentities`": []" + $text.Substring($insertAt)
        $span = Find-JsonArray $text "GatewayAgentIdentities"
    }

    $arrayText = $text.Substring($span.Start, $span.End - $span.Start + 1) -replace '(?m)^\s*//.*$', ''
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($e in @(ConvertFrom-Json $arrayText -AsHashtable)) { if ($e) { $entries.Add($e) } }

    $match = $entries | Where-Object { $_["ClientId"] -and $_["ClientId"] -ieq $ClientId } | Select-Object -First 1
    if (-not $match) {
        $match = $entries | Where-Object { $_["Name"] -eq $Name -and -not (Test-ConfiguredId $_["ClientId"]) } | Select-Object -First 1
    }
    $action = "updated"
    if (-not $match) { $match = @{}; $entries.Add($match); $action = "added" }
    $match["Name"] = $Name
    $match["ClientId"] = $ClientId
    if ($Note) { $match["Note"] = $Note }

    $json = { param($v) ConvertTo-Json -InputObject ([string] $v) }
    $lines = foreach ($e in $entries) {
        $fields = @("`"Name`": $(& $json $e["Name"])", "`"ClientId`": $(& $json $e["ClientId"])")
        if ($e["Note"]) { $fields += "`"Note`": $(& $json $e["Note"])" }
        "    { " + ($fields -join ", ") + " }"
    }
    $newArray = "[`n" + ($lines -join ",`n") + "`n  ]"
    Set-Content -Path $AppsPath -Value ($text.Substring(0, $span.Start) + $newArray + $text.Substring($span.End + 1)) -NoNewline
    return $action
}

# ---------------------------------------------------------------------------
# PDP entity registry: Azure Table "PdpEntities", PartitionKey = kind
#   blueprint | agent | application | group | member   (columns: see claims-pdp/pdp-core.mjs)
# Table REST API with SharedKeyLite from the connection string, so no Az module is needed.
# The PDP re-reads the table every 30 s (or at once via the web app's PDP entities sub-tab).
# ---------------------------------------------------------------------------

# Table connection from appsettings.json GatewayMcp:StorageConnectionString (written by
# Deploy-GatewayPoc.ps1), or $null while the storage account is not deployed yet.
function Get-PdpTable([string] $AppsPath) {
    $gw = (Read-JsonWithComments $AppsPath)["GatewayMcp"]
    if (-not $gw -or -not (Test-ConfiguredId $gw["StorageConnectionString"])) { return $null }
    $parts = @{}
    foreach ($p in $gw["StorageConnectionString"].Split(";")) { if ($p -match '^([^=]+)=(.*)$') { $parts[$Matches[1]] = $Matches[2] } }
    $endpoint = $parts["TableEndpoint"]
    if (-not $endpoint) {
        $endpoint = "{0}://{1}.table.{2}" -f ($parts["DefaultEndpointsProtocol"] ?? "https"), $parts["AccountName"], ($parts["EndpointSuffix"] ?? "core.windows.net")
    }
    @{
        Endpoint = $endpoint.TrimEnd("/")
        Account  = $parts["AccountName"]
        Key      = [Convert]::FromBase64String($parts["AccountKey"])
        Table    = if (Test-ConfiguredId $gw["PdpEntitiesTable"]) { $gw["PdpEntitiesTable"] } else { "PdpEntities" }
    }
}

function Invoke-PdpTable($Table, [string] $Method, [string] $Kind, [string] $Id, [hashtable] $Body) {
    $key = { param($v) [uri]::EscapeDataString($v.Replace("'", "''")) }
    $uri = [uri] ("{0}/{1}(PartitionKey='{2}',RowKey='{3}')" -f $Table.Endpoint, $Table.Table, (& $key $Kind), (& $key $Id))
    $date = [DateTime]::UtcNow.ToString("R")
    $hmac = [Security.Cryptography.HMACSHA256]::new($Table.Key)
    $signature = [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes("$date`n/$($Table.Account)$($uri.AbsolutePath)")))
    $headers = @{
        "x-ms-date"          = $date
        "x-ms-version"       = "2019-02-02"
        "Authorization"      = "SharedKeyLite $($Table.Account):$signature"
        "Accept"             = "application/json;odata=nometadata"
        "DataServiceVersion" = "3.0;NetFx"
    }
    $request = @{ Uri = $uri; CustomMethod = $Method; Headers = $headers }
    if ($Method -eq "DELETE") { $headers["If-Match"] = "*" }
    if ($Body) { $request.Body = ($Body | ConvertTo-Json -Compress); $request.ContentType = "application/json" }
    Invoke-RestMethod @request
}

# One row as a hashtable, or $null if it does not exist.
function Get-PdpEntity($Table, [string] $Kind, [string] $Id) {
    try { Invoke-PdpTable $Table "GET" $Kind $Id | ConvertTo-Json -Depth 3 | ConvertFrom-Json -AsHashtable }
    catch { if ($_.Exception.Response.StatusCode -eq 404) { $null } else { throw } }
}

# Insert-or-merge: the given columns are set, other columns of an existing row are kept.
function Set-PdpEntity($Table, [string] $Kind, [string] $Id, [hashtable] $Properties) {
    Invoke-PdpTable $Table "MERGE" $Kind $Id $Properties | Out-Null
}

# Deletes a row if it exists. Returns $true when a row was removed.
function Remove-PdpEntity($Table, [string] $Kind, [string] $Id) {
    if (-not (Get-PdpEntity $Table $Kind $Id)) { return $false }
    Invoke-PdpTable $Table "DELETE" $Kind $Id | Out-Null
    return $true
}

# Adds or updates one agent in the PDP registry. An existing row keeps its autonomousLimit
# (it may have been changed on the web app's PDP entities sub-tab).
function Set-PdpAgent($Table, [string] $Id, [string] $Name, [string] $BlueprintId, [int] $AutonomousLimit = 10000) {
    $Id = $Id.ToLower()
    $existing = Get-PdpEntity $Table "agent" $Id
    $properties = @{ displayName = $Name; blueprint = $BlueprintId.ToLower() }
    if (-not $existing) { $properties.autonomousLimit = $AutonomousLimit }
    Set-PdpEntity $Table "agent" $Id $properties
    if ($existing) { "updated" } else { "added" }
}

# The rows the policies need to make sense (blueprint, host app, MCP server, the three groups,
# and the gateway agent (Agent2) once Configure-Entra.ps1 -TestAgents has created it). Only missing rows are
# added, so edits made on the PDP entities sub-tab survive a redeployment.
function Initialize-PdpEntities($Table, [string] $AppsPath) {
    $s = Read-JsonWithComments $AppsPath
    $rows = @(
        @{ kind = "blueprint";   id = $s.AgentBlueprint.ClientId;   p = @{ displayName = "POC Claims Analysis Agent Blueprint" } }
        @{ kind = "application"; id = $s.HostApplication.ClientId;  p = @{ displayName = "POC Claims Web (host application)"; isMcpServer = $false } }
        @{ kind = "application"; id = $s.McpServer.ClientId;        p = @{ displayName = "POC Claims MCP Server"; isMcpServer = $true } }
        @{ kind = "group";       id = "adjusters-eu";               p = @{ displayName = "POC Claims Adjusters EU"; entraObjectId = ""; region = "EU" } }
        @{ kind = "group";       id = "adjusters-us";               p = @{ displayName = "POC Claims Adjusters US"; entraObjectId = ""; region = "US" } }
        @{ kind = "group";       id = "senior-adjusters";           p = @{ displayName = "POC Claims Senior Adjusters"; entraObjectId = "" } }
    )
    $agentId = $s.GatewayMcp.AgentIdentityClientId
    if (Test-ConfiguredId $agentId) {
        $rows += @{ kind = "agent"; id = $agentId; p = @{ displayName = "POC Claims Limited Gateway Agent (Agent2)"; blueprint = $s.AgentBlueprint.ClientId.ToLower(); autonomousLimit = 10000 } }
    }
    foreach ($r in $rows) {
        $id = $r.id.ToLower()
        if ($r.kind -eq "group") { $id = $r.id }
        if (Get-PdpEntity $Table $r.kind $id) { Write-Host "    $($r.kind)/$id exists" }
        else { Set-PdpEntity $Table $r.kind $id $r.p; Write-Host "    $($r.kind)/$id added" -ForegroundColor Green }
    }
}
