@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Unique resource token')
param resourceToken string

@description('Subnet ID for private endpoints')
param privateEndpointSubnetId string

@description('Private DNS zone ID for Key Vault')
param privateDnsZoneKeyVaultId string

var keyVaultName = 'kv-${resourceToken}'

// ─── Managed Identities ───────────────────────────────────────────────────────
// Two separate identities: orchestrator (API gateway) has broader read rights;
// agent-runner (ephemeral jobs) has minimal rights scoped to its own run only.

resource orchestratorIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-orchestrator-${resourceToken}'
  location: location
  tags: tags
}

resource agentRunnerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-agent-runner-${resourceToken}'
  location: location
  tags: tags
}

// ─── Key Vault ────────────────────────────────────────────────────────────────

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'premium' // HSM-backed keys
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true       // no legacy access policies
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'None'
    }
  }
}

// Key Vault diagnostic settings → Log Analytics (created in monitoring module,
// but we wire this up via a separate deployment to avoid circular deps).
// The monitoring module will assign diagnostics after workspace is available.

// ─── Key Vault RBAC Assignments ───────────────────────────────────────────────

// Key Vault Secrets User: read secret values (not manage)
var kvSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'

resource orchestratorKvRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, orchestratorIdentity.id, kvSecretsUserRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUserRoleId)
    principalId: orchestratorIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Agent runner does NOT get Key Vault access — it reads secrets via orchestrator
// environment injection only, never directly.

// ─── Private Endpoint for Key Vault ──────────────────────────────────────────

resource kvPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-06-01' = {
  name: 'pe-kv-${resourceToken}'
  location: location
  tags: tags
  properties: {
    subnet: { id: privateEndpointSubnetId }
    privateLinkServiceConnections: [
      {
        name: 'kv-connection'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: ['vault']
        }
      }
    ]
  }
}

resource kvDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-06-01' = {
  name: 'kv-dns-zone-group'
  parent: kvPrivateEndpoint
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'privatelink-vaultcore-azure-net'
        properties: { privateDnsZoneId: privateDnsZoneKeyVaultId }
      }
    ]
  }
}

// ─── Outputs ──────────────────────────────────────────────────────────────────

output keyVaultName string = keyVault.name
output keyVaultId string = keyVault.id
output orchestratorIdentityId string = orchestratorIdentity.id
output orchestratorPrincipalId string = orchestratorIdentity.properties.principalId
output orchestratorClientId string = orchestratorIdentity.properties.clientId
output agentRunnerIdentityId string = agentRunnerIdentity.id
output agentRunnerPrincipalId string = agentRunnerIdentity.properties.principalId
output agentRunnerClientId string = agentRunnerIdentity.properties.clientId
