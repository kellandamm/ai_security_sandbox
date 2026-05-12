@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Unique resource token')
param resourceToken string

@description('Azure Container Registry login server')
param acrLoginServer string

@description('OPA image in ACR')
param opaImage string

@description('Orchestrator managed identity resource ID')
param orchestratorIdentityId string

@description('Key Vault name')
param keyVaultName string

@description('Key Vault URI')
param keyVaultUri string

@description('Workspace storage account name')
param workspaceStorageAccountName string

@description('Audit storage account name')
param auditStorageAccountName string

@description('Agent runner job name')
param agentJobName string

@description('App Configuration endpoint')
param appConfigEndpoint string

var normalizedKeyVaultUri = endsWith(keyVaultUri, '/') ? keyVaultUri : '${keyVaultUri}/'

resource orchestratorPlan 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: 'asp-${resourceToken}-orchestrator'
  location: location
  tags: tags
  kind: 'linux'
  sku: {
    name: 'B1'
    tier: 'Basic'
    size: 'B1'
    capacity: 1
  }
  properties: {
    reserved: true
  }
}

resource orchestratorWebApp 'Microsoft.Web/sites@2022-09-01' = {
  name: 'app-${resourceToken}-orchestrator'
  location: location
  tags: tags
  kind: 'app,linux,container'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${orchestratorIdentityId}': {}
    }
  }
  properties: {
    serverFarmId: orchestratorPlan.id
    httpsOnly: true
    clientAffinityEnabled: false
    keyVaultReferenceIdentity: orchestratorIdentityId
    siteConfig: {
      linuxFxVersion: 'DOCKER|mcr.microsoft.com/k8se/quickstart:latest'
      acrUseManagedIdentityCreds: true
      acrUserManagedIdentityID: reference(orchestratorIdentityId, '2023-01-31').clientId
      alwaysOn: true
      http20Enabled: true
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'WEBSITES_PORT'
          value: '8000'
        }
        {
          name: 'WEBSITES_ENABLE_APP_SERVICE_STORAGE'
          value: 'false'
        }
        {
          name: 'DOCKER_REGISTRY_SERVER_URL'
          value: 'https://${acrLoginServer}'
        }
        {
          name: 'WORKSPACE_STORAGE_ACCOUNT'
          value: workspaceStorageAccountName
        }
        {
          name: 'AUDIT_STORAGE_ACCOUNT'
          value: auditStorageAccountName
        }
        {
          name: 'KEY_VAULT_NAME'
          value: keyVaultName
        }
        {
          name: 'AZURE_CLIENT_ID'
          value: reference(orchestratorIdentityId, '2023-01-31').clientId
        }
        {
          name: 'APPINSIGHTS_CONNECTION_STRING'
          value: '@Microsoft.KeyVault(SecretUri=${normalizedKeyVaultUri}secrets/appinsights-connection-string)'
        }
        {
          name: 'APPROVAL_LOGIC_APP_URL'
          value: '@Microsoft.KeyVault(SecretUri=${normalizedKeyVaultUri}secrets/approval-logic-app-url)'
        }
        {
          name: 'APP_CONFIG_ENDPOINT'
          value: appConfigEndpoint
        }
        {
          name: 'OPA_URL'
          value: 'https://${opaWebApp.properties.defaultHostName}'
        }
        {
          name: 'AGENT_JOB_NAME'
          value: agentJobName
        }
        {
          name: 'RESOURCE_GROUP'
          value: resourceGroup().name
        }
      ]
    }
  }
}

resource opaWebApp 'Microsoft.Web/sites@2022-09-01' = {
  name: 'app-${resourceToken}-opa'
  location: location
  tags: tags
  kind: 'app,linux,container'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${orchestratorIdentityId}': {}
    }
  }
  properties: {
    serverFarmId: orchestratorPlan.id
    httpsOnly: true
    clientAffinityEnabled: false
    keyVaultReferenceIdentity: orchestratorIdentityId
    siteConfig: {
      linuxFxVersion: 'DOCKER|${opaImage}'
      appCommandLine: ''
      acrUseManagedIdentityCreds: true
      acrUserManagedIdentityID: reference(orchestratorIdentityId, '2023-01-31').clientId
      alwaysOn: true
      http20Enabled: true
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'WEBSITES_PORT'
          value: '8181'
        }
        {
          name: 'WEBSITES_ENABLE_APP_SERVICE_STORAGE'
          value: 'false'
        }
        {
          name: 'DOCKER_REGISTRY_SERVER_URL'
          value: 'https://${acrLoginServer}'
        }
      ]
    }
  }
}

output orchestratorWebAppName string = orchestratorWebApp.name
output orchestratorUrl string = 'https://${orchestratorWebApp.properties.defaultHostName}'
output opaWebAppName string = opaWebApp.name
output opaUrl string = 'https://${opaWebApp.properties.defaultHostName}'
