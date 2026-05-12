@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Unique resource token')
param resourceToken string

@description('Principal ID of the orchestrator managed identity')
param orchestratorPrincipalId string

@description('Subnet ID for private endpoint')
param privateEndpointSubnetId string

@description('Private DNS zone ID for App Configuration')
param privateDnsZoneAppConfigId string

// ─── App Configuration Store ──────────────────────────────────────────────────

resource appConfig 'Microsoft.AppConfiguration/configurationStores@2024-05-01' = {
  name: 'appcs-${resourceToken}'
  location: location
  tags: tags
  sku: { name: 'standard' }
  properties: {
    disableLocalAuth: false          // PE + firewall control network access;
                                      // RBAC still enforces data-plane authZ at runtime.
    publicNetworkAccess: 'Enabled'   // ARM needs data-plane access to write feature flags during provisioning.
    enablePurgeProtection: true
    softDeleteRetentionInDays: 7
  }
}

// ─── Feature Flags ────────────────────────────────────────────────────────────
// Each flag is a key in App Configuration with content-type for feature flags.
// production label applied to all — app reads this label exclusively.

var featureFlags = [
  {
    key: '.appconfig.featureflag/agent-execution-enabled'
    description: 'Global kill switch: set to false to stop ALL agent execution immediately'
    defaultValue: true
  }
  {
    key: '.appconfig.featureflag/file-write-enabled'
    description: 'Disable all file write operations across all agent types'
    defaultValue: true
  }
  {
    key: '.appconfig.featureflag/network-egress-enabled'
    description: 'Disable all outbound network calls from agents'
    defaultValue: true
  }
  {
    key: '.appconfig.featureflag/openai-calls-enabled'
    description: 'Disable Azure OpenAI calls specifically (cost runaway protection)'
    defaultValue: true
  }
  {
    key: '.appconfig.featureflag/agent-data-analyst-enabled'
    description: 'Kill switch for data-analyst agent type only'
    defaultValue: true
  }
  {
    key: '.appconfig.featureflag/agent-web-researcher-enabled'
    description: 'Kill switch for web-researcher agent type only'
    defaultValue: true
  }
]

@batchSize(1)
resource flags 'Microsoft.AppConfiguration/configurationStores/keyValues@2024-05-01' = [for flag in featureFlags: {
  parent: appConfig
  name: '${replace(flag.key, '/', '~2F')}$production'
  properties: {
    value: string({
      id: last(split(flag.key, '/'))
      description: flag.description
      enabled: flag.defaultValue
      conditions: { client_filters: [] }
    })
    contentType: 'application/vnd.microsoft.appconfig.ff+json;charset=utf-8'
    tags: { label: 'production' }
  }
  dependsOn: [appConfig]
}]

// ─── RBAC ─────────────────────────────────────────────────────────────────────

// App Configuration Data Reader — read-only access for orchestrator (agents read flags, never write them)
var appConfigDataReaderRoleId = '516239f1-63e1-4d78-a4de-a74fb236a071'

resource orchestratorAppConfigReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appConfig.id, orchestratorPrincipalId, appConfigDataReaderRoleId)
  scope: appConfig
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', appConfigDataReaderRoleId)
    principalId: orchestratorPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// ─── Private Endpoint ─────────────────────────────────────────────────────────

resource appConfigPe 'Microsoft.Network/privateEndpoints@2023-06-01' = {
  name: 'pe-appcs-${resourceToken}'
  location: location
  tags: tags
  properties: {
    subnet: { id: privateEndpointSubnetId }
    privateLinkServiceConnections: [
      {
        name: 'appconfig-connection'
        properties: {
          privateLinkServiceId: appConfig.id
          groupIds: ['configurationStores']
        }
      }
    ]
  }
}

resource appConfigDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-06-01' = {
  name: 'appconfig-dns-group'
  parent: appConfigPe
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'privatelink-azconfig-io'
        properties: { privateDnsZoneId: privateDnsZoneAppConfigId }
      }
    ]
  }
}

// ─── Outputs ──────────────────────────────────────────────────────────────────

output appConfigName string = appConfig.name
output appConfigEndpoint string = appConfig.properties.endpoint
