#requires -Version 7.0
<#
.SYNOPSIS
    Deploys the Azure side of the "Local LLM & Gateway MCP" scenario into ONE resource group.

.DESCRIPTION
      1. Resource group + Bicep/main.bicep (storage, Azure Managed Redis, App Service plan with
         4 web apps, API Management Consumption, Event Grid topic, Logic App).
      2. Zip-deploys the Node apps (claims-pdp, claims-killswitch, claims-api-azure,
         claims-mcp-azure); App Service runs npm install (SCM_DO_BUILD_DURING_DEPLOYMENT).
      3. Bicep/eventgrid-subscription.bicep once the kill switch answers (Event Grid validates
         the webhook when the subscription is created).
      4. Writes the URLs, the internal key, the storage connection string and the Logic App
         trigger URL into appsettings.json (section GatewayMcp), so the web app's
         "Local LLM & Gateway MCP" tab works as is.
      5. Adds the baseline rows of the PDP entity registry (Azure Table PdpEntities) that are
         still missing: blueprint, host app, MCP server, groups, gateway agent.

    Order:  .\Configure\Configure-Entra.ps1 -TestAgents -TestUsers   (test agents, users, groups, ids into appsettings.json)
            .\Configure\Deploy-GatewayPoc.ps1 -NamePrefix <prefix> -PublisherEmail you@contoso.com
            .\Configure\Configure-Entra.ps1 -TestAgents -TestUsers   (again: writes them into the PDP registry)
            .\Configure\Configure-GatewayEntra.ps1                   (MCP optional claims, managed identity Graph permissions)

    Tenant and Claims API ids come from appsettings.json, the MCP server id and secret from
    claims-mcp/config.json, unless passed as parameters. After the first deployment -NamePrefix
    defaults to the prefix in appsettings.json GatewayMcp:PdpUrl.

    Redeploy only code:  .\Configure\Deploy-GatewayPoc.ps1 -SkipInfra [-Apps claims-pdp,claims-mcp-azure]

.NOTES
    Needs the Azure CLI (az login) with Owner or User Access Administrator on the resource group
    (the template creates role assignments). The internal and gateway keys are generated once and
    kept in Configure/Bicep/poc-secrets.local.json (POC: no secret store).
#>
[CmdletBinding()]
param(
    [string]   $ResourceGroup  = "rg-poc-agent-gateway",
    [string]   $Location       = "eastus2",
    # Lowercase letters and digits, 3-11 chars, globally unique (App Service / APIM host names).
    # Required on the first deployment; later it defaults to the prefix in appsettings.json GatewayMcp:PdpUrl.
    [string]   $NamePrefix,
    # Ids default to the values in appsettings.json; pass them to override (nothing is hard-coded).
    [string]   $TenantId,
    [string]   $ClaimsApiAppId,
    [string]   $PublisherEmail = "",
    [string]   $SubscriptionId = "",
    [switch]   $SkipInfra,
    [string[]] $Apps           = @("claims-pdp", "claims-killswitch", "claims-api-azure", "claims-mcp-azure")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$root       = Split-Path -Parent $PSScriptRoot
$bicepDir   = Join-Path $PSScriptRoot "Bicep"
$secretsPath = Join-Path $bicepDir "poc-secrets.local.json"
$appsPath   = Join-Path $root "appsettings.json"

# Read-JsonWithComments, Resolve-Setting, Set-AppSetting, Get-PdpTable, Initialize-PdpEntities
. (Join-Path $PSScriptRoot "GatewayConfigFiles.ps1")

$NamePrefix     = Resolve-Setting $NamePrefix     "NamePrefix"     $appsPath "GatewayMcp:PdpUrl" -Pattern '^https://([a-z0-9]+)-pdp\.'
$TenantId       = Resolve-Setting $TenantId       "TenantId"       $appsPath "HostApplication:TenantId", "AgentBlueprint:TenantId"
$ClaimsApiAppId = Resolve-Setting $ClaimsApiAppId "ClaimsApiAppId" $appsPath "DownstreamApis:ClaimsApiAsAgent:Scopes:0"

function Set-GatewaySetting([string] $Key, [string] $Value) { Set-AppSetting $appsPath "GatewayMcp" $Key $Value }

function New-Key { [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)).Replace("+", "A").Replace("/", "B").Replace("=", "") }

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
if ($SubscriptionId) { az account set --subscription $SubscriptionId | Out-Null }
$account = az account show --query "{name:name, id:id, user:user.name}" -o json | ConvertFrom-Json
Write-Host "Subscription: $($account.name) ($($account.id)) as $($account.user)" -ForegroundColor Cyan

if (Test-Path $secretsPath) { $secrets = Get-Content $secretsPath -Raw | ConvertFrom-Json -AsHashtable }
else {
    $secrets = @{ internalKey = New-Key; gatewayKey = New-Key }
    $secrets | ConvertTo-Json | Set-Content $secretsPath
    Write-Host "Generated internal and gateway keys -> $secretsPath"
}

$settings   = Read-JsonWithComments $appsPath
$mcpConfig  = Get-Content (Join-Path $root "claims-mcp/config.json") -Raw | ConvertFrom-Json
# The kill switch's Entra drift sync watches every configured agent (Agent1-4 and any added later).
$watched    = @(@($settings.AgentIdentity.ClientId) + @($settings.GatewayAgentIdentities | Where-Object { $_ } | ForEach-Object { $_["ClientId"] })) |
    Where-Object { Test-ConfiguredId $_ } | ForEach-Object { $_.ToLower() } | Sort-Object -Unique
if (-not (Test-ConfiguredId $settings.GatewayMcp.AgentIdentityClientId)) {
    Write-Host "GatewayMcp:AgentIdentityClientId is not set yet: run Configure-Entra.ps1 -TestAgents first." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 1. Infrastructure
# ---------------------------------------------------------------------------
$deploymentName = "poc-gateway-main"
if (-not $SkipInfra) {
    if (-not $PublisherEmail) { $PublisherEmail = $account.user }
    Write-Host "`n[1] Resource group $ResourceGroup ($Location) and main.bicep" -ForegroundColor Cyan
    az group create --name $ResourceGroup --location $Location --tags purpose=poc-agent-identity-gateway -o none

    $params = @{
        namePrefix        = @{ value = $NamePrefix }
        publisherEmail    = @{ value = $PublisherEmail }
        tenantId          = @{ value = $TenantId }
        claimsApiAppId    = @{ value = $ClaimsApiAppId }
        mcpClientId       = @{ value = $mcpConfig.MCP_CLIENT_ID }
        mcpClientSecret   = @{ value = $mcpConfig.MCP_CLIENT_SECRET }
        internalKey       = @{ value = $secrets.internalKey }
        gatewayKey        = @{ value = $secrets.gatewayKey }
        watchedPrincipals = @{ value = ($watched -join ",") }
    }
    $paramFile = New-TemporaryFile
    @{ '$schema' = "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"; contentVersion = "1.0.0.0"; parameters = $params } |
        ConvertTo-Json -Depth 5 | Set-Content $paramFile
    try {
        Write-Host "    deploying (API Management Consumption and Azure Managed Redis take a few minutes)..."
        az deployment group create --resource-group $ResourceGroup --name $deploymentName `
            --template-file (Join-Path $bicepDir "main.bicep") --parameters "@$paramFile" -o none
    }
    finally { Remove-Item $paramFile -ErrorAction SilentlyContinue }
}

$outputs = az deployment group show --resource-group $ResourceGroup --name $deploymentName --query properties.outputs -o json | ConvertFrom-Json
$out = @{}
$outputs.PSObject.Properties | ForEach-Object { $out[$_.Name] = $_.Value.value }
Write-Host ("    MCP endpoint (APIM): {0}" -f $out.mcpEndpoint) -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2. Application code
# ---------------------------------------------------------------------------
$appNames = @{
    "claims-pdp"        = $out.pdpAppName
    "claims-killswitch" = $out.killSwitchAppName
    "claims-api-azure"  = $out.claimsApiAppName
    "claims-mcp-azure"  = $out.mcpAppName
}
Write-Host "`n[2] Code deployment" -ForegroundColor Cyan
foreach ($app in $Apps) {
    $source = Join-Path $root $app
    $stage  = Join-Path ([IO.Path]::GetTempPath()) "poc-$app-$([guid]::NewGuid().ToString('N').Substring(0, 6))"
    $zip    = "$stage.zip"
    New-Item -ItemType Directory -Path $stage | Out-Null
    Get-ChildItem $source -Force | Where-Object { $_.Name -notin @("node_modules", "test", "config.json", ".env") } |
        Copy-Item -Destination $stage -Recurse
    # The MCP server must not ship the local MCP credential file.
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -Force
    Write-Host "    $app -> $($appNames[$app])"
    az webapp deploy --resource-group $ResourceGroup --name $appNames[$app] --src-path $zip --type zip --async false -o none
    Remove-Item $stage -Recurse -Force
    Remove-Item $zip -Force
}

# ---------------------------------------------------------------------------
# 3. Event Grid subscription (needs the kill switch running for the handshake)
# ---------------------------------------------------------------------------
Write-Host "`n[3] Event Grid subscription -> kill switch" -ForegroundColor Cyan
$healthy = $false
for ($i = 0; $i -lt 30 -and -not $healthy; $i++) {
    try { $healthy = (Invoke-RestMethod -Uri "$($out.killSwitchUrl)/health" -TimeoutSec 10).ok } catch { Start-Sleep -Seconds 10 }
}
if (-not $healthy) { throw "Kill switch $($out.killSwitchUrl)/health did not answer; check 'az webapp log tail -n $($out.killSwitchAppName) -g $ResourceGroup'." }
az deployment group create --resource-group $ResourceGroup --name "poc-gateway-eventgrid" `
    --template-file (Join-Path $bicepDir "eventgrid-subscription.bicep") `
    --parameters topicName=$($out.topicName) killSwitchHost=$($out.killSwitchHost) storageAccountName=$($out.storageAccountName) internalKey=$($secrets.internalKey) -o none
Write-Host "    subscription to-killswitch created (webhook validated)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. appsettings.json
# ---------------------------------------------------------------------------
Write-Host "`n[4] appsettings.json (GatewayMcp)" -ForegroundColor Cyan
$sub = $account.id
$callback = az rest --method post `
    --uri "https://management.azure.com/subscriptions/$sub/resourceGroups/$ResourceGroup/providers/Microsoft.Logic/workflows/$($out.workflowName)/triggers/manual/listCallbackUrl?api-version=2019-05-01" `
    --query value -o tsv
Set-GatewaySetting "Endpoint"              $out.mcpEndpoint
Set-GatewaySetting "PdpUrl"                $out.pdpUrl
Set-GatewaySetting "KillSwitchUrl"         $out.killSwitchUrl
Set-GatewaySetting "ClaimsApiUrl"          $out.claimsApiUrl
Set-GatewaySetting "InternalKey"           $secrets.internalKey
Set-GatewaySetting "KillSwitchWorkflowUrl" $callback
# The web app's PDP entities sub-tab and the Configure scripts write the registry with it (POC: account key).
$storageConnection = az storage account show-connection-string --resource-group $ResourceGroup --name $out.storageAccountName --query connectionString -o tsv
Set-GatewaySetting "StorageConnectionString" $storageConnection
Set-GatewaySetting "PdpEntitiesTable"        $out.pdpEntitiesTableName
Write-Host "    written: Endpoint, PdpUrl, KillSwitchUrl, ClaimsApiUrl, InternalKey, KillSwitchWorkflowUrl, StorageConnectionString, PdpEntitiesTable" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. PDP entity registry baseline (only missing rows; the PDP re-reads the table every 30 s)
# ---------------------------------------------------------------------------
Write-Host "`n[5] PDP entity registry ($($out.pdpEntitiesTableName))" -ForegroundColor Cyan
Initialize-PdpEntities (Get-PdpTable $appsPath) $appsPath

Write-Host "`nHealth:" -ForegroundColor Cyan
foreach ($u in @($out.pdpUrl, $out.killSwitchUrl, $out.claimsApiUrl)) {
    try { Write-Host ("    {0}/health -> {1}" -f $u, ((Invoke-RestMethod -Uri "$u/health" -TimeoutSec 20) | ConvertTo-Json -Compress)) }
    catch { Write-Host "    $u/health -> $($_.Exception.Message)" -ForegroundColor Yellow }
}
Write-Host "`nDone. Next: run .\Configure\Configure-Entra.ps1 -TestAgents -TestUsers (PDP registry) and .\Configure\Configure-GatewayEntra.ps1 (managed identity Graph permissions), then 'dotnet run' and open the 'Local LLM & Gateway MCP' tab." -ForegroundColor Cyan
