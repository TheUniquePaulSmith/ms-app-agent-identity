// ============================================================================
// POC: "Local LLM & Gateway MCP" scenario (docs/Proposal.md, layers 4 and 5).
// Everything goes into ONE resource group, cheapest SKU that still works:
//
//   Storage account (Standard_LRS)    tables Claims + KillAudit + PdpEntities (PDP
//                                     registry), blob container "deadletter" for Event Grid
//   Azure Managed Redis Balanced_B0   kill list + APIM external cache
//     (no HA, non-production)         (Azure Cache for Redis Basic is closed to
//                                     new customers since April 2026)
//   App Service plan Linux B1         4 Node apps on one plan:
//                                     PDP, kill switch, Claims API, MCP server
//   API Management Consumption        MCP gateway (PEP 1), internet facing
//   Event Grid custom topic           agent.lifecycle CloudEvents (pay per op)
//   Logic App Consumption             kill / restore workflow (managed identity)
//
// Deploy with Configure/Deploy-GatewayPoc.ps1 (this template, then the app code,
// then eventgrid-subscription.bicep, which needs the kill switch code running
// because Event Grid validates the webhook when the subscription is created).
// ============================================================================

targetScope = 'resourceGroup'

@description('Azure region for every resource.')
param location string = resourceGroup().location

@description('Lowercase letters and digits, 3-11 chars. Prefix of every resource name; keep it in sync with appsettings.json GatewayMcp.')
@minLength(3)
@maxLength(11)
param namePrefix string

@description('APIM publisher e-mail (required by API Management).')
param publisherEmail string

param publisherName string = 'POC Claims'

@description('Entra tenant of the app registrations (defaults to the deployment tenant).')
param tenantId string = tenant().tenantId

@description('App id of the "POC Claims MCP Server" registration (audience of tool-call tokens).')
param mcpClientId string

@description('Client secret of the MCP server registration (used for OBO / client credentials).')
@secure()
param mcpClientSecret string

@description('App id of the "POC Claims API" registration.')
param claimsApiAppId string

@description('Shared key for internal calls (PEPs -> PDP, APIM/Logic App -> kill switch, Event Grid webhook).')
@secure()
param internalKey string

@description('Key APIM adds to forwarded requests so the MCP server can trust x-gateway-decision.')
@secure()
param gatewayKey string

@description('Comma separated agent identity ids the kill switch watches in Entra (drift sync).')
param watchedPrincipals string = ''

@allowed([ 'B1', 'B2', 'S1', 'P0v3' ])
param appServicePlanSku string = 'B1'

param nodeVersion string = 'NODE|22-lts'

@description('MCP requests per minute per caller (azp) at the gateway.')
param rateLimitPerMinute int = 30

@description('Seconds the gateway caches a kill-list answer.')
param killCacheSeconds int = 5

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

var storageName = '${namePrefix}st${take(uniqueString(resourceGroup().id), 6)}'
var redisName = '${namePrefix}-redis'
var planName = '${namePrefix}-plan'
var pdpName = '${namePrefix}-pdp'
var killSwitchName = '${namePrefix}-killswitch'
var claimsApiName = '${namePrefix}-claims-api'
var mcpName = '${namePrefix}-mcp'
var apimName = '${namePrefix}-apim'
var topicName = '${namePrefix}-agent-lifecycle'
var workflowName = '${namePrefix}-killswitch-workflow'

var pdpUrl = 'https://${pdpName}.azurewebsites.net'
var killSwitchUrl = 'https://${killSwitchName}.azurewebsites.net'
var claimsApiUrl = 'https://${claimsApiName}.azurewebsites.net'
var mcpPublicBase = 'https://${apimName}.azure-api.net/claims-mcp'

// Built-in role definition ids
var roleTableDataContributor = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
var roleTableDataReader = '76199698-9eea-4c19-bc75-cec21354c6b6'
var roleEventGridDataSender = 'd5a91429-5739-47e2-a06b-3470a27159e7'

var tags = {
  purpose: 'poc-agent-identity-gateway'
}

// ---------------------------------------------------------------------------
// Storage: claim records, kill audit, PDP entity registry, Event Grid dead letters
// ---------------------------------------------------------------------------

resource storage 'Microsoft.Storage/storageAccounts@2024-01-01' = {
  name: storageName
  location: location
  tags: tags
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
    accessTier: 'Hot'
  }
}

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2024-01-01' = {
  parent: storage
  name: 'default'
}

resource claimsTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2024-01-01' = {
  parent: tableService
  name: 'Claims'
}

resource auditTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2024-01-01' = {
  parent: tableService
  name: 'KillAudit'
}

// Blueprints, agents, applications, groups and local members the PDP reads
// (PartitionKey = kind). Written by the web app's "PDP entities" sub-tab and the
// Configure scripts with the account connection string; the PDP only reads.
resource pdpEntitiesTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2024-01-01' = {
  parent: tableService
  name: 'PdpEntities'
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2024-01-01' = {
  parent: storage
  name: 'default'
}

resource deadLetterContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2024-01-01' = {
  parent: blobService
  name: 'deadletter'
  properties: { publicAccess: 'None' }
}

// ---------------------------------------------------------------------------
// Azure Managed Redis: kill list (PDP, kill switch) + APIM external cache
// ---------------------------------------------------------------------------

resource redis 'Microsoft.Cache/redisEnterprise@2025-04-01' = {
  name: redisName
  location: location
  tags: tags
  sku: { name: 'Balanced_B0' }
  properties: {
    minimumTlsVersion: '1.2'
    highAvailability: 'Disabled' // dev/test: half the price, no SLA
  }
}

resource redisDb 'Microsoft.Cache/redisEnterprise/databases@2025-04-01' = {
  parent: redis
  name: 'default'
  properties: {
    clientProtocol: 'Encrypted'
    port: 10000
    clusteringPolicy: 'EnterpriseCluster' // single endpoint: any client, incl. APIM
    evictionPolicy: 'VolatileLRU' // kill entries have no TTL, so they are never evicted
    accessKeysAuthentication: 'Enabled' // APIM external cache needs a connection string
  }
}

var redisHost = redis.properties.hostName
var redisKey = redisDb.listKeys().primaryKey

// ---------------------------------------------------------------------------
// App Service: one Linux B1 plan, four Node apps
// ---------------------------------------------------------------------------

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: planName
  location: location
  tags: tags
  sku: { name: appServicePlanSku }
  kind: 'linux'
  properties: { reserved: true }
}

var commonSettings = [
  { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
  { name: 'WEBSITE_HTTPLOGGING_RETENTION_DAYS', value: '3' }
  { name: 'POC_INTERNAL_KEY', value: internalKey }
  { name: 'TENANT_ID', value: tenantId }
]

var siteConfigBase = {
  linuxFxVersion: nodeVersion
  alwaysOn: true
  appCommandLine: 'node server.mjs'
  ftpsState: 'Disabled'
  minTlsVersion: '1.2'
  http20Enabled: true
}

resource pdpApp 'Microsoft.Web/sites@2024-04-01' = {
  name: pdpName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: union(siteConfigBase, {
      appSettings: concat(commonSettings, [
        { name: 'REDIS_HOST', value: redisHost }
        { name: 'REDIS_PASSWORD', value: redisKey }
        { name: 'STORAGE_TABLE_ENDPOINT', value: storage.properties.primaryEndpoints.table }
        { name: 'CLAIMS_TABLE', value: claimsTable.name }
        { name: 'PDP_ENTITIES_TABLE', value: pdpEntitiesTable.name }
        { name: 'GROUP_SOURCE', value: 'graph' }
        { name: 'FAIL_OPEN_FOR_APPLICATIONS', value: 'true' }
      ])
    })
  }
}

resource killSwitchApp 'Microsoft.Web/sites@2024-04-01' = {
  name: killSwitchName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: union(siteConfigBase, {
      appSettings: concat(commonSettings, [
        { name: 'REDIS_HOST', value: redisHost }
        { name: 'REDIS_PASSWORD', value: redisKey }
        { name: 'STORAGE_TABLE_ENDPOINT', value: storage.properties.primaryEndpoints.table }
        { name: 'AUDIT_TABLE', value: auditTable.name }
        { name: 'WATCHED_PRINCIPALS', value: watchedPrincipals }
        { name: 'DRIFT_INTERVAL_SECONDS', value: '60' }
      ])
    })
  }
}

resource claimsApiApp 'Microsoft.Web/sites@2024-04-01' = {
  name: claimsApiName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: union(siteConfigBase, {
      appSettings: concat(commonSettings, [
        { name: 'CLAIMS_API_APP_ID', value: claimsApiAppId }
        { name: 'PDP_URL', value: pdpUrl }
        { name: 'STORAGE_TABLE_ENDPOINT', value: storage.properties.primaryEndpoints.table }
        { name: 'CLAIMS_TABLE', value: claimsTable.name }
        { name: 'KNOWN_MCP_APP_IDS', value: mcpClientId }
      ])
    })
  }
}

resource mcpApp 'Microsoft.Web/sites@2024-04-01' = {
  name: mcpName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: union(siteConfigBase, {
      appSettings: concat(commonSettings, [
        { name: 'MCP_CLIENT_ID', value: mcpClientId }
        { name: 'MCP_CLIENT_SECRET', value: mcpClientSecret }
        { name: 'CLAIMS_API_APP_ID', value: claimsApiAppId }
        { name: 'CLAIMS_API_URL', value: claimsApiUrl }
        { name: 'PDP_URL', value: pdpUrl }
        { name: 'SELF_URL', value: mcpPublicBase }
        { name: 'GATEWAY_KEY', value: gatewayKey }
      ])
    })
  }
}

// Table access with managed identities (no storage keys in the apps)
resource claimsApiTableRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, claimsApiApp.id, roleTableDataContributor)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleTableDataContributor)
    principalId: claimsApiApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource killSwitchTableRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, killSwitchApp.id, roleTableDataContributor)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleTableDataContributor)
    principalId: killSwitchApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource pdpTableRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, pdpApp.id, roleTableDataReader)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleTableDataReader)
    principalId: pdpApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// Event Grid custom topic: agent.lifecycle (CloudEvents 1.0)
// ---------------------------------------------------------------------------

resource topic 'Microsoft.EventGrid/topics@2025-02-15' = {
  name: topicName
  location: location
  tags: tags
  properties: {
    inputSchema: 'CloudEventSchemaV1_0'
    publicNetworkAccess: 'Enabled'
    disableLocalAuth: false
  }
}

// ---------------------------------------------------------------------------
// Logic App: kill / restore workflow (Proposal 6.2 and 6.4)
// ---------------------------------------------------------------------------

resource workflow 'Microsoft.Logic/workflows@2019-05-01' = {
  name: workflowName
  location: location
  tags: tags
  identity: { type: 'SystemAssigned' }
  properties: {
    state: 'Enabled'
    definition: loadJsonContent('logicapp/killswitch-workflow.json')
    parameters: {
      topicEndpoint: { value: topic.properties.endpoint }
      killSwitchUrl: { value: killSwitchUrl }
      internalKey: { value: internalKey }
    }
  }
}

resource workflowTopicRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(topic.id, workflow.id, roleEventGridDataSender)
  scope: topic
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleEventGridDataSender)
    principalId: workflow.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// API Management (Consumption): the MCP gateway, PEP 1
// ---------------------------------------------------------------------------

resource apim 'Microsoft.ApiManagement/service@2024-05-01' = {
  name: apimName
  location: location
  tags: tags
  sku: { name: 'Consumption', capacity: 0 }
  properties: {
    publisherEmail: publisherEmail
    publisherName: publisherName
  }
}

resource apimCache 'Microsoft.ApiManagement/service/caches@2024-05-01' = {
  parent: apim
  name: 'default'
  properties: {
    description: 'Azure Managed Redis (kill-list answers, rate-limit counters)'
    connectionString: '${redisHost}:10000,password=${redisKey},ssl=True,abortConnect=False'
    useFromLocation: 'default'
    resourceId: '${environment().resourceManager}${substring(redis.id, 1)}'
  }
}

var namedValues = [
  { name: 'tenant-id', value: tenantId, secret: false }
  { name: 'mcp-client-id', value: mcpClientId, secret: false }
  { name: 'pdp-url', value: pdpUrl, secret: false }
  { name: 'killswitch-url', value: killSwitchUrl, secret: false }
  { name: 'mcp-public-url', value: mcpPublicBase, secret: false }
  { name: 'rate-limit-per-minute', value: string(rateLimitPerMinute), secret: false }
  { name: 'kill-cache-seconds', value: string(killCacheSeconds), secret: false }
  { name: 'internal-key', value: internalKey, secret: true }
  { name: 'gateway-key', value: gatewayKey, secret: true }
]

resource apimNamedValues 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = [
  for nv in namedValues: {
    parent: apim
    name: nv.name
    properties: {
      displayName: nv.name
      value: nv.value
      secret: nv.secret
    }
  }
]

resource mcpApi 'Microsoft.ApiManagement/service/apis@2024-05-01' = {
  parent: apim
  name: 'claims-mcp'
  properties: {
    displayName: 'POC Claims MCP Server'
    description: 'MCP gateway (PEP 1): Entra token validation, rate limit, kill list, AuthZEN coarse decision, then forward to the MCP server.'
    path: 'claims-mcp'
    protocols: [ 'https' ]
    serviceUrl: 'https://${mcpApp.properties.defaultHostName}'
    subscriptionRequired: false
    apiType: 'http'
  }
}

var mcpOperations = [
  { name: 'mcp-post', method: 'POST', url: '/mcp', gated: true }
  { name: 'mcp-get', method: 'GET', url: '/mcp', gated: true }
  { name: 'mcp-delete', method: 'DELETE', url: '/mcp', gated: true }
  { name: 'prm', method: 'GET', url: '/.well-known/oauth-protected-resource', gated: false }
  { name: 'prm-mcp', method: 'GET', url: '/.well-known/oauth-protected-resource/mcp', gated: false }
]

resource operations 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' = [
  for op in mcpOperations: {
    parent: mcpApi
    name: op.name
    properties: {
      displayName: '${op.method} ${op.url}'
      method: op.method
      urlTemplate: op.url
    }
  }
]

resource operationPolicies 'Microsoft.ApiManagement/service/apis/operations/policies@2024-05-01' = [
  for (op, i) in mcpOperations: if (op.gated) {
    parent: operations[i]
    name: 'policy'
    properties: {
      format: 'rawxml'
      value: loadTextContent('apim/mcp-policy.xml')
    }
    dependsOn: [
      apimNamedValues
      apimCache
    ]
  }
]

// ---------------------------------------------------------------------------
// Outputs (Deploy-GatewayPoc.ps1 writes them into appsettings.json)
// ---------------------------------------------------------------------------

output apimGatewayUrl string = apim.properties.gatewayUrl
output mcpEndpoint string = '${apim.properties.gatewayUrl}/claims-mcp/mcp'
output pdpUrl string = pdpUrl
output killSwitchUrl string = killSwitchUrl
output claimsApiUrl string = claimsApiUrl
output mcpAppName string = mcpApp.name
output pdpAppName string = pdpApp.name
output killSwitchAppName string = killSwitchApp.name
output claimsApiAppName string = claimsApiApp.name
output killSwitchHost string = killSwitchApp.properties.defaultHostName
output topicName string = topic.name
output storageAccountName string = storage.name
output pdpEntitiesTableName string = pdpEntitiesTable.name
output workflowName string = workflow.name
output workflowPrincipalId string = workflow.identity.principalId
output killSwitchPrincipalId string = killSwitchApp.identity.principalId
output pdpPrincipalId string = pdpApp.identity.principalId
