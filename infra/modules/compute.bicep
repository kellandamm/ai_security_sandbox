@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Unique resource token')
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

@description('Workspace storage account name')
param workspaceStorageAccountName string

@description('Audit storage account name')
param auditStorageAccountName string

var acrName = 'cr${resourceToken}'

// ─── Container Registry ───────────────────────────────────────────────────────

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: location
  tags: tags
  sku: { name: 'Premium' }
  properties: {
    adminUserEnabled: false          // Managed Identity auth only
    publicNetworkAccess: 'Disabled'
    zoneRedundancy: 'Disabled'       // dev — enable for prod
    policies: {
      quarantinePolicy: { status: 'enabled' }
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

// ─── Container Apps Environment ───────────────────────────────────────────────

resource acaEnv 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: 'cae-${resourceToken}'
  location: location
  tags: tags
  properties: {
    vnetConfiguration: {
      infrastructureSubnetId: containerAppsSubnetId
      internal: true               // no public IP on environment
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
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${orchestratorIdentityId}': {}
    }
  }
  properties: {
    managedEnvironmentId: acaEnv.id
    workloadProfileName: 'Consumption'
    configuration: {
      ingress: {
        external: false            // internal only — APIM is the only entry point
        targetPort: 8000
        transport: 'http'
        allowInsecure: false
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
          keyVaultUrl: 'https://${keyVaultName}.vault.azure.net/secrets/appinsights-connection-string'
          identity: orchestratorIdentityId
        }
        {
          name: 'approval-webhook-secret'
          keyVaultUrl: 'https://${keyVaultName}.vault.azure.net/secrets/approval-webhook-secret'
          identity: orchestratorIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'orchestrator'
          image: '${acr.properties.loginServer}/ai-sandbox/orchestrator:latest'
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
            { name: 'APPROVAL_WEBHOOK_SECRET', secretRef: 'approval-webhook-secret' }
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
    managedEnvironmentId: acaEnv.id
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
          keyVaultUrl: 'https://${keyVaultName}.vault.azure.net/secrets/appinsights-connection-string'
          identity: agentRunnerIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'agent-runner'
          image: '${acr.properties.loginServer}/ai-sandbox/agent-runner:latest'
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
        // OPA sidecar — policy decisions stay in-process, no network hop
        {
          name: 'opa-sidecar'
          image: 'openpolicyagent/opa:latest-static'
          resources: {
            cpu: json('0.25')
            memory: '256Mi'
          }
          args: [
            'run'
            '--server'
            '--addr=0.0.0.0:8181'
            '--log-level=info'
            '--bundle=/policies'
          ]
        }
      ]
      initContainers: [
        // Init container pulls OPA policy bundle from Blob Storage before job starts
        {
          name: 'policy-loader'
          image: '${acr.properties.loginServer}/ai-sandbox/policy-loader:latest'
          resources: {
            cpu: json('0.1')
            memory: '128Mi'
          }
          env: [
            { name: 'WORKSPACE_STORAGE_ACCOUNT', value: workspaceStorageAccountName }
            { name: 'AZURE_CLIENT_ID', value: reference(agentRunnerIdentityId, '2023-01-31').clientId }
          ]
        }
      ]
    }
  }
}

// ─── Frontend Container App (SOC dashboard) ──────────────────────────────────
// Separate app serving the React SPA. Internal ingress — fronted by APIM.
// No secrets, no managed identity needed — just static files via nginx.

resource frontendApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: 'ca-frontend-${resourceToken}'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${orchestratorIdentityId}': {}  // ACR pull only
    }
  }
  properties: {
    managedEnvironmentId: acaEnv.id
    workloadProfileName: 'Consumption'
    configuration: {
      ingress: {
        external: false         // APIM is the public entry point
        targetPort: 80
        transport: 'http'
        allowInsecure: false
      }
      registries: [
        {
          server: acr.properties.loginServer
          identity: orchestratorIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'frontend'
          image: '${acr.properties.loginServer}/ai-sandbox/frontend:latest'
          resources: {
            cpu: json('0.25')
            memory: '512Mi'
          }
          env: [
            // VITE_API_BASE is baked into the image at build time via ARG/ENV.
            // The nginx proxy rewrites /api → orchestrator app on port 8000.
            { name: 'BACKEND_URL', value: 'http://ca-orchestrator-${resourceToken}:8000' }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 5
        rules: [
          {
            name: 'http-scale'
            http: { metadata: { concurrentRequests: '20' } }
          }
        ]
      }
    }
  }
}

// ─── Outputs ──────────────────────────────────────────────────────────────────

output acrLoginServer string = acr.properties.loginServer
output containerAppsEnvironmentName string = acaEnv.name
output containerAppsEnvironmentId string = acaEnv.id
output orchestratorAppName string = orchestratorApp.name
output orchestratorAppUrl string = 'https://${orchestratorApp.properties.configuration.ingress.fqdn}'
output agentJobName string = agentJob.name
output frontendAppName string = frontendApp.name
output frontendAppUrl string = 'https://${frontendApp.properties.configuration.ingress.fqdn}'
