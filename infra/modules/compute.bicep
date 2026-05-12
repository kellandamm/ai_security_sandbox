@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Unique resource token')
@minLength(3)
param resourceToken string

@description('Subnet ID for Container Apps environment')
param containerAppsSubnetId string

@description('Log Analytics workspace resource ID')
param logAnalyticsWorkspaceId string

@description('Orchestrator managed identity resource ID')
param orchestratorIdentityId string

@description('Agent runner managed identity resource ID')
param agentRunnerIdentityId string

@description('Key Vault name (for secret references)')
param keyVaultName string

@description('Key Vault URI (for secret references)')
param keyVaultUri string

@description('Workspace storage account name')
param workspaceStorageAccountName string

@description('Audit storage account name')
param auditStorageAccountName string

@description('Subnet ID for private endpoints')
param privateEndpointSubnetId string

@description('Private DNS zone ID for ACR (privatelink.azurecr.io)')
param privateDnsZoneAcrId string

var acrName = 'cr${resourceToken}'
var acrLoginServer = '${acrName}.azurecr.io'
var normalizedKeyVaultUri = endsWith(keyVaultUri, '/') ? keyVaultUri : '${keyVaultUri}/'
// OPA image lives in ACR after the postprovision hook (scripts/import-opa-image.ps1) runs.
// Bicep uses placeholderImage here so ARM doesn't validate an image that doesn't exist yet.
// The hook patches the job to the real ACR image immediately after provisioning.
var opaImageAcr = '${acrLoginServer}/opa:latest-static'

// Placeholder for initial provisioning — azd deploy overwrites with the real build.
// Container Apps with minReplicas≥1 try to pull immediately; if the image doesn't
// exist in ACR yet (first azd up), the revision times out. MCR quickstart always works.
var placeholderImage = 'mcr.microsoft.com/k8se/quickstart:latest'

// ─── Container Registry ───────────────────────────────────────────────────────

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: location
  tags: tags
  sku: { name: 'Premium' }
  properties: {
    adminUserEnabled: false          // Managed Identity auth only
    publicNetworkAccess: 'Enabled'   // Required for ACR Tasks remote build agents (azd deploy remoteBuild:true)
    zoneRedundancy: 'Disabled'       // dev — enable for prod
    policies: {
      quarantinePolicy: { status: 'disabled' }
      trustPolicy: {
        type: 'Notary'
        status: 'enabled'
      }
      retentionPolicy: {
        days: 30
        status: 'enabled'
      }
    }
  }
}

// AcrPull for agent runner identity
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
resource agentAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, agentRunnerIdentityId, acrPullRoleId)
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: reference(agentRunnerIdentityId, '2023-01-31').principalId
    principalType: 'ServicePrincipal'
  }
}

resource orchestratorAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, orchestratorIdentityId, acrPullRoleId)
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: reference(orchestratorIdentityId, '2023-01-31').principalId
    principalType: 'ServicePrincipal'
  }
}

// ─── ACR Private Endpoint ─────────────────────────────────────────────────────
// Container Apps (and jobs) pull images from ACR via private endpoint for low-latency
// in-VNet pulls. Public network access is also enabled for ACR Tasks remote builds.

resource acrPe 'Microsoft.Network/privateEndpoints@2023-06-01' = {
  name: 'pe-acr-${resourceToken}'
  location: location
  tags: tags
  properties: {
    subnet: { id: privateEndpointSubnetId }
    privateLinkServiceConnections: [
      {
        name: 'acr-connection'
        properties: {
          privateLinkServiceId: acr.id
          groupIds: ['registry']
        }
      }
    ]
  }
}

resource acrDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-06-01' = {
  name: 'acr-dns-group'
  parent: acrPe
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'privatelink-azurecr-io'
        properties: { privateDnsZoneId: privateDnsZoneAcrId }
      }
    ]
  }
}

// ─── Container Apps Environment ───────────────────────────────────────────────
// Use a public environment for the long-lived control-plane apps so APIM can
// route to stable, supported app FQDNs instead of relying on VNet-scope ingress.

resource acaEnv 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: 'cae-${resourceToken}'
  location: location
  tags: tags
  properties: {
    vnetConfiguration: {
      infrastructureSubnetId: containerAppsSubnetId
      internal: false              // public environment for APIM-facing app ingress
    }
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: reference(logAnalyticsWorkspaceId, '2022-10-01').customerId
        sharedKey: listKeys(logAnalyticsWorkspaceId, '2022-10-01').primarySharedKey
      }
    }
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
      {
        name: 'agent-runner'
        workloadProfileType: 'D4'  // dedicated profile for agent jobs — stronger isolation
        minimumCount: 0
        maximumCount: 10
      }
    ]
  }
}

// ─── Orchestrator Container App (always-on API gateway) ──────────────────────

resource orchestratorApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: 'ca-orchestrator-${resourceToken}'
  location: location
  tags: union(tags, { 'azd-service-name': 'orchestrator' })
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${orchestratorIdentityId}': {}
    }
  }
  properties: {
    managedEnvironmentId: acaEnv.id
    workloadProfileName: 'agent-runner'
    configuration: {
      ingress: {
        external: true             // APIM targets the public app FQDN in the supported topology
        targetPort: 8000
        transport: 'http'
        allowInsecure: true  // APIM connects via HTTP within the VNet
      }
      registries: [
        {
          server: acr.properties.loginServer
          identity: orchestratorIdentityId
        }
      ]
      secrets: [
        {
          name: 'appinsights-connection-string'
          keyVaultUrl: '${normalizedKeyVaultUri}secrets/appinsights-connection-string'
          identity: orchestratorIdentityId
        }
        {
          name: 'approval-logic-app-url'
          keyVaultUrl: '${normalizedKeyVaultUri}secrets/approval-logic-app-url'
          identity: orchestratorIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'orchestrator'
          image: placeholderImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'WORKSPACE_STORAGE_ACCOUNT', value: workspaceStorageAccountName }
            { name: 'AUDIT_STORAGE_ACCOUNT', value: auditStorageAccountName }
            { name: 'KEY_VAULT_NAME', value: keyVaultName }
            { name: 'AZURE_CLIENT_ID', value: reference(orchestratorIdentityId, '2023-01-31').clientId }
            { name: 'APPINSIGHTS_CONNECTION_STRING', secretRef: 'appinsights-connection-string' }
            { name: 'APPROVAL_LOGIC_APP_URL', secretRef: 'approval-logic-app-url' }
            { name: 'APP_CONFIG_ENDPOINT', value: 'https://appcs-${resourceToken}.azconfig.io' }
            { name: 'OPA_URL', value: 'http://localhost:8181' }
            { name: 'AGENT_JOB_NAME', value: 'caj-agent-runner-${resourceToken}' }
            { name: 'ACA_ENVIRONMENT_NAME', value: 'cae-${resourceToken}' }
            { name: 'RESOURCE_GROUP', value: resourceGroup().name }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: { path: '/health', port: 8000 }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: { path: '/health', port: 8000 }
              initialDelaySeconds: 5
              periodSeconds: 10
            }
          ]
        }
        // OPA sidecar — policy decisions stay in-process, no network hop.
        // placeholderImage used here so ARM preflight doesn't validate an ACR image
        // that doesn't exist yet. The postprovision hook patches this to the real
        // ACR image (custom build with policies baked in) after provisioning.
        {
          name: 'opa-sidecar'
          image: placeholderImage
          resources: {
            cpu: json('0.25')
            memory: '0.25Gi'
          }
          args: [
            'run'
            '--server'
            '--v0-compatible'
            '--addr=0.0.0.0:8181'
            '--log-level=info'
            '/policies/'
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 10
        rules: [
          {
            name: 'http-scale'
            http: { metadata: { concurrentRequests: '20' } }
          }
        ]
      }
    }
  }
  dependsOn: [
    acrDnsGroup
  ]
}

// ─── Agent Runner Container App Job (ephemeral, one per run) ─────────────────
// trigger=Manual means the orchestrator spawns one job execution per agent run.
// retries=0 and timeout=300s enforce hard limits — no runaway loops.

resource agentJob 'Microsoft.App/jobs@2023-05-01' = {
  name: 'caj-agent-runner-${resourceToken}'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${agentRunnerIdentityId}': {}
    }
  }
  properties: {
    environmentId: acaEnv.id
    workloadProfileName: 'agent-runner'  // dedicated profile for isolation
    configuration: {
      triggerType: 'Manual'
      replicaTimeout: 300          // hard 5-minute timeout per execution
      replicaRetryLimit: 0         // fail fast — no retry loops
      manualTriggerConfig: {
        replicaCompletionCount: 1
        parallelism: 1
      }
      registries: [
        {
          server: acr.properties.loginServer
          identity: agentRunnerIdentityId
        }
      ]
      secrets: [
        {
          name: 'appinsights-connection-string'
          keyVaultUrl: '${normalizedKeyVaultUri}secrets/appinsights-connection-string'
          identity: agentRunnerIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'agent-runner'
          image: placeholderImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'WORKSPACE_STORAGE_ACCOUNT', value: workspaceStorageAccountName }
            { name: 'AUDIT_STORAGE_ACCOUNT', value: auditStorageAccountName }
            { name: 'AZURE_CLIENT_ID', value: reference(agentRunnerIdentityId, '2023-01-31').clientId }
            { name: 'APPINSIGHTS_CONNECTION_STRING', secretRef: 'appinsights-connection-string' }
            // RUN_ID, AGENT_TYPE, TASK injected at job start time by orchestrator
          ]
        }
        // OPA sidecar — policy decisions stay in-process, no network hop.
        // placeholderImage used here so ARM preflight doesn't validate an ACR image
        // that doesn't exist yet. The postprovision hook patches this to the real
        // ACR image (opaImageAcr) immediately after provisioning completes.
        {
          name: 'opa-sidecar'
          image: placeholderImage
          resources: {
            cpu: json('0.25')
            memory: '0.25Gi'
          }
          args: [
            'run'
            '--server'
            '--v0-compatible'
            '--addr=0.0.0.0:8181'
            '--log-level=info'
            '/policies/'
          ]
        }
      ]
    }
  }
  dependsOn: [
    acrDnsGroup
  ]
}

// ─── Outputs ──────────────────────────────────────────────────────────────────

output acrLoginServer string = acr.properties.loginServer
output acrName string = acr.name
output opaImageAcr string = opaImageAcr
output containerAppsEnvironmentName string = acaEnv.name
output containerAppsEnvironmentId string = acaEnv.id
output orchestratorAppName string = orchestratorApp.name
output orchestratorAppUrl string = 'http://${orchestratorApp.properties.configuration.ingress.fqdn}'
output agentJobName string = agentJob.name
