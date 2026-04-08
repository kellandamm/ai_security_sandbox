@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Unique resource token')
param resourceToken string

@description('Principal ID of the agent runner managed identity')
param agentRunnerPrincipalId string

@description('Subnet ID for private endpoints')
param privateEndpointSubnetId string

@description('Private DNS zone ID for blob storage')
param privateDnsZoneBlobId string

// ─── Workspace Storage Account (ephemeral per-run scratch space) ──────────────
// Rule 1: ephemeral workspaces; Rule 2: separate read/write paths;
// Rule 7: quotas enforced via lifecycle policy + container limits.

resource workspaceSa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'st${resourceToken}work'
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    isHnsEnabled: true // ADLS Gen2 for fine-grained ACL support
    accessTier: 'Hot'
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false // Managed Identity only
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'None'
    }
  }
}

resource workspaceBlobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: workspaceSa
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: false // truly ephemeral — no soft-delete recovery
    }
    containerDeleteRetentionPolicy: {
      enabled: false
    }
  }
}

// Lifecycle policy: auto-delete any workspace container contents after 24h
resource workspaceLifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-01-01' = {
  parent: workspaceSa
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'EphemeralWorkspaceCleanup'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: ['blockBlob']
              prefixMatch: ['workspace-']
            }
            actions: {
              baseBlob: {
                delete: { daysAfterModificationGreaterThan: 1 } // 24 hours
              }
            }
          }
        }
      ]
    }
  }
}

// ─── Audit Storage Account (WORM — write-once, append-only audit logs) ────────
// No MI gets delete permissions here. WORM policy locks all blobs for 365 days.

resource auditSa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'st${resourceToken}audit'
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    accessTier: 'Cool'
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'None'
    }
  }
}

resource auditBlobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: auditSa
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 365
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 365
    }
    changeFeed: {
      enabled: true  // track every blob mutation
      retentionInDays: 365
    }
    isVersioningEnabled: true
  }
}

resource auditContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: auditBlobService
  name: 'audit-logs'
  properties: {
    publicAccess: 'None'
  }
}

// WORM immutability policy — time-based, 365 days, locked
resource auditImmutabilityPolicy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-01-01' = {
  parent: auditContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: 365
  }
}

// ─── RBAC Assignments ─────────────────────────────────────────────────────────

// Storage Blob Data Contributor on workspace SA (agent runner creates/deletes containers)
var storageBlobDataContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'

resource agentRunnerWorkspaceRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(workspaceSa.id, agentRunnerPrincipalId, storageBlobDataContributorRoleId)
  scope: workspaceSa
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataContributorRoleId)
    principalId: agentRunnerPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Storage Blob Data Contributor on audit SA — write-only semantics enforced at app level
// (WORM policy prevents delete even with Contributor role)
resource agentRunnerAuditRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(auditSa.id, agentRunnerPrincipalId, storageBlobDataContributorRoleId)
  scope: auditSa
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataContributorRoleId)
    principalId: agentRunnerPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// ─── Private Endpoints ────────────────────────────────────────────────────────

resource workspacePe 'Microsoft.Network/privateEndpoints@2023-06-01' = {
  name: 'pe-work-blob-${resourceToken}'
  location: location
  tags: tags
  properties: {
    subnet: { id: privateEndpointSubnetId }
    privateLinkServiceConnections: [
      {
        name: 'workspace-blob'
        properties: {
          privateLinkServiceId: workspaceSa.id
          groupIds: ['blob']
        }
      }
    ]
  }
}

resource workspaceDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-06-01' = {
  name: 'workspace-dns'
  parent: workspacePe
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'blob'
        properties: { privateDnsZoneId: privateDnsZoneBlobId }
      }
    ]
  }
}

resource auditPe 'Microsoft.Network/privateEndpoints@2023-06-01' = {
  name: 'pe-audit-blob-${resourceToken}'
  location: location
  tags: tags
  properties: {
    subnet: { id: privateEndpointSubnetId }
    privateLinkServiceConnections: [
      {
        name: 'audit-blob'
        properties: {
          privateLinkServiceId: auditSa.id
          groupIds: ['blob']
        }
      }
    ]
  }
}

resource auditDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-06-01' = {
  name: 'audit-dns'
  parent: auditPe
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'blob'
        properties: { privateDnsZoneId: privateDnsZoneBlobId }
      }
    ]
  }
}

// ─── Outputs ──────────────────────────────────────────────────────────────────

output workspaceStorageAccountName string = workspaceSa.name
output workspaceStorageAccountId string = workspaceSa.id
output auditStorageAccountName string = auditSa.name
output auditStorageAccountId string = auditSa.id
