@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Unique resource token')
param resourceToken string

@description('Azure Container Registry name')
param acrName string

@description('Azure Container Registry login server')
param acrLoginServer string

var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var frontendImage = '${acrLoginServer}/ai-sandbox/frontend:latest'

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: acrName
}

resource frontendPlan 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: 'asp-${resourceToken}-frontend'
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

resource frontendApp 'Microsoft.Web/sites@2022-09-01' = {
  name: 'app-${resourceToken}-frontend'
  location: location
  tags: tags
  kind: 'app,linux,container'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: frontendPlan.id
    httpsOnly: true
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'DOCKER|${frontendImage}'
      acrUseManagedIdentityCreds: true
      alwaysOn: true
      http20Enabled: true
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'WEBSITES_PORT'
          value: '80'
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

resource frontendAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, frontendApp.id, acrPullRoleId)
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: frontendApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output frontendAppName string = frontendApp.name
output frontendUrl string = 'https://${frontendApp.properties.defaultHostName}'
