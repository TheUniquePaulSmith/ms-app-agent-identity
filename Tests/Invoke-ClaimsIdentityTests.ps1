#requires -Version 7.0

<#
.SYNOPSIS
    Runs the six identity scenarios against the POC host application.

.DESCRIPTION
    Scenarios (who is the actor x is a user present):

      1. Host application + application permission      (roles: Claims.Archive.All)
      2. Host application + user-delegated permission   (scp:   Claims.Archive)
      3. Agent identity   + application permission      (roles: Claims.Analyze.All)
      4. Agent identity   + user-delegated permission   (scp:   Claims.Analyze)
      5. Negative: agent identity tries to archive       (expect 403)
      6. Negative: host application tries to analyze    (expect 403)

    Scenarios 1, 3, 5 and 6 need no user token. Scenario 2 needs the host
    token and scenario 4 needs the agent token; both come from the host
    application's browser endpoint /auth/token after /auth/sign-in.

.PARAMETER HostToken
    Access token whose audience is the host application
    (api://<host-app-id>/access_as_user). From /auth/token -> hostToken.

.PARAMETER AgentToken
    Access token whose audience is the agent blueprint
    (api://<blueprint-id>/access_agent). From /auth/token -> agentToken.
    Optional: scenario 4 is skipped when it is not supplied.

.PARAMETER BaseUrl
    Base URL of the host application. Default: http://localhost:5094

.PARAMETER ClaimId
    Claim identifier used for every call. Default: CLAIM-1001

.EXAMPLE
    .\Invoke-ClaimsIdentityTests.ps1 -HostToken $hostToken -AgentToken $agentToken

.EXAMPLE
    .\Invoke-ClaimsIdentityTests.ps1 -HostToken $hostToken -BaseUrl "http://localhost:5094" -ClaimId "CLAIM-2002"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $HostToken,

    [Parameter(Mandatory = $false)]
    [string] $AgentToken,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $BaseUrl = "http://localhost:5094",

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ClaimId = "CLAIM-1001"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BaseUrl = $BaseUrl.TrimEnd("/")
$hasAgentToken = -not [string]::IsNullOrWhiteSpace($AgentToken)

$testCases = @(
    [pscustomobject]@{
        Name           = "1. Host app + application permission"
        Endpoint       = "/claims/$ClaimId/archive"
        Auth           = "None"
        Token          = $null
        ExpectedStatus = 200
        Skip           = $false
    }
    [pscustomobject]@{
        Name           = "2. Host app + user-delegated permission"
        Endpoint       = "/claims/$ClaimId/archive-as-user"
        Auth           = "Bearer host token"
        Token          = $HostToken
        ExpectedStatus = 200
        Skip           = $false
    }
    [pscustomobject]@{
        Name           = "3. Agent identity + application permission"
        Endpoint       = "/claims/$ClaimId/agent-analyze"
        Auth           = "None"
        Token          = $null
        ExpectedStatus = 200
        Skip           = $false
    }
    [pscustomobject]@{
        Name           = "4. Agent identity + user-delegated permission"
        Endpoint       = "/claims/$ClaimId/agent-analyze-as-user"
        Auth           = "Bearer agent token"
        Token          = $AgentToken
        ExpectedStatus = 200
        Skip           = -not $hasAgentToken
    }
    [pscustomobject]@{
        Name           = "Negative: agent tries to archive"
        Endpoint       = "/claims/$ClaimId/archive-as-agent"
        Auth           = "None"
        Token          = $null
        ExpectedStatus = 403
        Skip           = $false
    }
    [pscustomobject]@{
        Name           = "Negative: host tries to analyze"
        Endpoint       = "/claims/$ClaimId/analyze-as-host"
        Auth           = "None"
        Token          = $null
        ExpectedStatus = 403
        Skip           = $false
    }
)

function Get-Prop {
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-TokenInfo {
    param($Response)
    $downstream = Get-Prop $Response "downstream"
    $debug = Get-Prop $downstream "_debug"
    return Get-Prop $debug "tokenInfo"
}

$results = foreach ($testCase in $testCases) {
    $uri = "$BaseUrl$($testCase.Endpoint)"

    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkGray
    Write-Host $testCase.Name -ForegroundColor Cyan
    Write-Host "POST $uri" -ForegroundColor Gray
    Write-Host "Authentication: $($testCase.Auth)" -ForegroundColor Gray
    Write-Host ("=" * 72) -ForegroundColor DarkGray

    if ($testCase.Skip) {
        Write-Host "SKIPPED" -ForegroundColor Yellow
        Write-Host ("No -AgentToken supplied. Sign in at /auth/sign-in, open /auth/token " +
                    "and pass its agentToken.accessToken as -AgentToken.") -ForegroundColor Yellow

        [pscustomobject]@{
            Test           = $testCase.Name
            Expected       = $testCase.ExpectedStatus
            Actual         = $null
            Result         = "SKIPPED"
            CallerKind     = $null
            CallerAppId    = $null
            ObjectId       = $null
            Roles          = $null
            Scp            = $null
            ParentBlueprint = $null
        }
        continue
    }

    $headers = @{ Accept = "application/json" }
    if ($null -ne $testCase.Token) {
        $headers.Authorization = "Bearer $($testCase.Token)"
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $statusCode = $null
    $response = $null
    $rawContent = $null

    try {
        $web = Invoke-WebRequest -Method Post -Uri $uri -Headers $headers `
            -ContentType "application/json" -Body "{}" -SkipHttpErrorCheck
        $statusCode = [int] $web.StatusCode
        $rawContent = $web.Content
        try { $response = $rawContent | ConvertFrom-Json -Depth 30 } catch { $response = $null }
    }
    catch {
        Write-Host "FAILED (request error)" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
    finally {
        $stopwatch.Stop()
    }

    $result = if ($statusCode -eq $testCase.ExpectedStatus) { "PASS" } else { "FAIL" }
    $color = if ($result -eq "PASS") { "Green" } else { "Red" }
    Write-Host "$result  (HTTP $statusCode, expected $($testCase.ExpectedStatus), $($stopwatch.ElapsedMilliseconds) ms)" -ForegroundColor $color

    if ($null -ne $response) {
        $response | ConvertTo-Json -Depth 20 | Write-Host
    }
    elseif (-not [string]::IsNullOrWhiteSpace($rawContent)) {
        Write-Host $rawContent
    }

    $tokenInfo = Get-TokenInfo $response
    $roles = Get-Prop $tokenInfo "roles"

    [pscustomobject]@{
        Test            = $testCase.Name
        Expected        = $testCase.ExpectedStatus
        Actual          = $statusCode
        Result          = $result
        CallerKind      = Get-Prop $tokenInfo "callerKind"
        CallerAppId     = Get-Prop $tokenInfo "callerAppId"
        ObjectId        = Get-Prop $tokenInfo "objectId"
        Roles           = if ($null -ne $roles) { @($roles) -join " " } else { $null }
        Scp             = Get-Prop $tokenInfo "scp"
        ParentBlueprint = Get-Prop $tokenInfo "parentBlueprintAppId"
    }
}

Write-Host ""
Write-Host ("=" * 30 + " SUMMARY " + "=" * 33) -ForegroundColor Cyan

$results |
    Format-Table Test, Expected, Actual, Result, CallerKind, CallerAppId, ObjectId, Roles, Scp, ParentBlueprint -AutoSize -Wrap

Write-Host "Legend: roles = application permission (no user) | scp = delegated permission (user present) | ParentBlueprint present = token minted for an agent identity" -ForegroundColor DarkGray

$failed = @($results | Where-Object Result -eq "FAIL")
$skipped = @($results | Where-Object Result -eq "SKIPPED")

if ($failed.Count -gt 0) {
    Write-Host "$($failed.Count) test(s) failed." -ForegroundColor Red
    exit 1
}

$passedCount = $results.Count - $skipped.Count
Write-Host "$passedCount test(s) passed, $($skipped.Count) skipped." -ForegroundColor Green
exit 0
