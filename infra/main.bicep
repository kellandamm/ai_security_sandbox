targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the environment (e.g. dev, prod)')
param environmentName string

@description('Azure region for all resources')
param location string = 'eastus'

@description('Email address for human-in-the-loop approvals')
param approverEmail string

@description('Azure OpenAI model deployment name')
param openAiModelName string = 'gpt-4o'

@description('Allowed egress FQDNs beyond default Azure services')
param allowedEgressFqdns array = []

@description('Azure AD tenant ID for JWT validation in APIM')
param aadTenantId string = tenant().tenantId

var abbrs = loadJsonContent('abbreviations.json')
var resourceToken = toLower(uniqueString(subscription().id, environmentName, location))
var tags = { 'azd-env-name': environmentName, project: 'ai-security-sandbox' }

// Resource Group
resource rg 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: '${abbrs.resourcesResourceGroups}${environmentName}'
  location: location
  tags: tags
}

// 1. Networking — prerequisite for all private resources
module networking 'modules/networking.bicep' = {
  name: 'networking'
  scope: rg
  params: {
    location: location
    tags: tags
    resourceToken: resourceToken
    allowedEgressFqdns: allowedEgressFqdns
  }
}

// 2. Security — Managed Identities + Key Vault needed by compute
module security 'modules/security.bicep' = {
  name: 'security'
  scope: rg
  params: {
    location: location
    tags: tags
    resourceToken: resourceToken
    privateEndpointSubnetId: networking.outputs.privateEndpointSubnetId
    privateDnsZoneKeyVaultId: networking.outputs.privateDnsZoneKeyVaultId
  }
}

// 3. Storage — SAs needed before jobs reference them
module storage 'modules/storage.bicep' = {
  name: 'storage'
  scope: rg
  params: {
    location: location
    tags: tags
    resourceToken: resourceToken
    agentRunnerPrincipalId: security.outputs.agentRunnerPrincipalId
    privateEndpointSubnetId: networking.outputs.privateEndpointSubnetId
    privateDnsZoneBlobId: networking.outputs.privateDnsZoneBlobId
  }
}

// 4. Monitoring — Log Analytics workspace ID needed by compute + APIM
module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  scope: rg
  params: {
    location: location
    tags: tags
    resourceToken: resourceToken
  }
}

// 5. Compute — Container Apps Environment + Jobs + ACR
module compute 'modules/compute.bicep' = {
  name: 'compute'
  scope: rg
  params: {
    location: location
    tags: tags
    resourceToken: resourceToken
    containerAppsSubnetId: networking.outputs.containerAppsSubnetId
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
    orchestratorIdentityId: security.outputs.orchestratorIdentityId
    agentRunnerIdentityId: security.outputs.agentRunnerIdentityId
    keyVaultName: security.outputs.keyVaultName
    workspaceStorageAccountName: storage.outputs.workspaceStorageAccountName
    auditStorageAccountName: storage.outputs.auditStorageAccountName
  }
}

// 6. APIM — rate limiting + JWT gateway
module apim 'modules/apim.bicep' = {
  name: 'apim'
  scope: rg
  params: {
    location: location
    tags: tags
    resourceToken: resourceToken
    apimSubnetId: networking.outputs.apimSubnetId
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
    backendAppUrl: compute.outputs.orchestratorAppUrl
    aadTenantId: aadTenantId
  }
}

// 7. Approvals — Logic App HITL workflow
module approvals 'modules/approvals.bicep' = {
  name: 'approvals'
  scope: rg
  params: {
    location: location
    tags: tags
    resourceToken: resourceToken
    approverEmail: approverEmail
    keyVaultName: security.outputs.keyVaultName
    orchestratorAppUrl: compute.outputs.orchestratorAppUrl
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
  }
}

// 8. Kill Switch — App Configuration + feature flags
module killSwitch 'modules/kill_switch.bicep' = {
  name: 'killSwitch'
  scope: rg
  params: {
    location: location
    tags: tags
    resourceToken: resourceToken
    orchestratorPrincipalId: security.outputs.orchestratorPrincipalId
    privateEndpointSubnetId: networking.outputs.privateEndpointSubnetId
    privateDnsZoneAppConfigId: networking.outputs.privateDnsZoneAppConfigId
  }
}

// Outputs for local tooling and CI/CD
output AZURE_LOCATION string = location
output AZURE_TENANT_ID string = aadTenantId
output AZURE_RESOURCE_GROUP string = rg.name
output AZURE_CONTAINER_REGISTRY_ENDPOINT string = compute.outputs.acrLoginServer
output AZURE_CONTAINER_APPS_ENVIRONMENT_NAME string = compute.outputs.containerAppsEnvironmentName
output ORCHESTRATOR_APP_NAME string = compute.outputs.orchestratorAppName
output AGENT_JOB_NAME string = compute.outputs.agentJobName
output APIM_GATEWAY_URL string = apim.outputs.gatewayUrl
output KEY_VAULT_NAME string = security.outputs.keyVaultName
output LOG_ANALYTICS_WORKSPACE_ID string = monitoring.outputs.logAnalyticsWorkspaceId
output APP_CONFIG_ENDPOINT string = killSwitch.outputs.appConfigEndpoint
output LOGIC_APP_APPROVAL_URL string = approvals.outputs.approvalWebhookUrl
