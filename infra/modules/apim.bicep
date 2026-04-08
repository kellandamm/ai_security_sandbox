@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Unique resource token')
param resourceToken string

@description('Subnet ID for APIM VNet injection')
param apimSubnetId string

@description('Log Analytics workspace resource ID')
param logAnalyticsWorkspaceId string

@description('Backend Container App URL')
param backendAppUrl string

@description('Azure AD tenant ID for JWT validation')
param aadTenantId string

// ─── API Management ───────────────────────────────────────────────────────────

resource apim 'Microsoft.ApiManagement/service@2023-05-01-preview' = {
  name: 'apim-${resourceToken}'
  location: location
  tags: tags
  sku: {
    name: 'Developer'    // use Standard_v2 or Premium for production
    capacity: 1
  }
  identity: {
    type: 'SystemAssigned'   // for Key Vault cert retrieval
  }
  properties: {
    publisherEmail: 'admin@example.com'
    publisherName: 'AI Security Sandbox'
    virtualNetworkType: 'Internal'
    virtualNetworkConfiguration: {
      subnetResourceId: apimSubnetId
    }
  }
}

// ─── Diagnostic Settings → Log Analytics ─────────────────────────────────────

resource apimDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'apim-diag'
  scope: apim
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { category: 'GatewayLogs'; enabled: true }
      { category: 'WebSocketConnectionLogs'; enabled: true }
    ]
    metrics: [
      { category: 'AllMetrics'; enabled: true }
    ]
  }
}

// ─── Logger for request/response audit ───────────────────────────────────────

resource apimLogger 'Microsoft.ApiManagement/service/loggers@2023-05-01-preview' = {
  name: 'log-analytics-logger'
  parent: apim
  properties: {
    loggerType: 'azureMonitor'
    isBuffered: false
    resourceId: logAnalyticsWorkspaceId
  }
}

// ─── Backend pointing to Container App orchestrator ───────────────────────────

resource backend 'Microsoft.ApiManagement/service/backends@2023-05-01-preview' = {
  name: 'orchestrator-backend'
  parent: apim
  properties: {
    url: backendAppUrl
    protocol: 'http'
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
  }
}

// ─── API Definition ───────────────────────────────────────────────────────────

resource api 'Microsoft.ApiManagement/service/apis@2023-05-01-preview' = {
  name: 'ai-sandbox-api'
  parent: apim
  properties: {
    displayName: 'AI Security Sandbox API'
    description: 'Sandboxed AI agent execution with full security controls'
    path: 'sandbox'
    protocols: ['https']
    subscriptionRequired: true
    subscriptionKeyParameterNames: {
      header: 'Ocp-Apim-Subscription-Key'
      query: 'subscription-key'
    }
  }
}

// ─── Global API Policy — rate limiting + JWT validation + correlation ─────────

resource apiPolicy 'Microsoft.ApiManagement/service/apis/policies@2023-05-01-preview' = {
  name: 'policy'
  parent: api
  properties: {
    format: 'xml'
    value: '''
<policies>
  <inbound>
    <base />

    <!-- Correlation ID: generate if not provided, propagate throughout -->
    <set-variable name="correlationId" value="@(context.Request.Headers.GetValueOrDefault("X-Correlation-ID", Guid.NewGuid().ToString()))" />
    <set-header name="X-Correlation-ID" exists-action="override">
      <value>@((string)context.Variables["correlationId"])</value>
    </set-header>

    <!-- JWT validation: require valid Azure AD bearer token -->
    <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized: valid Azure AD token required">
      <openid-config url="https://login.microsoftonline.com/{{aadTenantId}}/v2.0/.well-known/openid-configuration" />
      <required-claims>
        <claim name="aud" match="any">
          <value>api://ai-security-sandbox</value>
        </claim>
      </required-claims>
    </validate-jwt>

    <!-- Rate limiting: 100 calls per 60 seconds per agent-id header -->
    <rate-limit-by-key calls="100" renewal-period="60"
      counter-key="@(context.Request.Headers.GetValueOrDefault("X-Agent-ID", context.Subscription.Id))"
      increment-condition="@(true)"
      retry-after-header-name="Retry-After"
      remaining-calls-header-name="X-RateLimit-Remaining" />

    <!-- Daily quota: 10,000 calls per subscription key per day -->
    <quota-by-key calls="10000" renewal-period="86400"
      counter-key="@(context.Subscription.Id)"
      increment-condition="@(true)" />

    <!-- Route to backend -->
    <set-backend-service backend-id="orchestrator-backend" />
  </inbound>

  <backend>
    <base />
  </backend>

  <outbound>
    <base />
    <!-- Propagate correlation ID back to caller -->
    <set-header name="X-Correlation-ID" exists-action="override">
      <value>@((string)context.Variables["correlationId"])</value>
    </set-header>
  </outbound>

  <on-error>
    <base />
    <set-header name="X-Correlation-ID" exists-action="override">
      <value>@((string)context.Variables["correlationId"])</value>
    </set-header>
  </on-error>
</policies>
'''
  }
}

// ─── Operations ───────────────────────────────────────────────────────────────

resource opPostRuns 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  name: 'post-runs'
  parent: api
  properties: {
    displayName: 'Start Agent Run'
    method: 'POST'
    urlTemplate: '/runs'
    description: 'Submit a new sandboxed agent task'
  }
}

resource opGetRun 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  name: 'get-run'
  parent: api
  properties: {
    displayName: 'Get Run Status'
    method: 'GET'
    urlTemplate: '/runs/{runId}'
    description: 'Poll the status of a specific run'
    templateParameters: [
      { name: 'runId'; type: 'string'; required: true }
    ]
  }
}

resource opDeleteRun 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  name: 'delete-run'
  parent: api
  properties: {
    displayName: 'Kill Run'
    method: 'DELETE'
    urlTemplate: '/runs/{runId}'
    description: 'Emergency kill switch for a specific run'
    templateParameters: [
      { name: 'runId'; type: 'string'; required: true }
    ]
  }
}

// ─── Product ──────────────────────────────────────────────────────────────────

resource product 'Microsoft.ApiManagement/service/products@2023-05-01-preview' = {
  name: 'ai-agent-sandbox'
  parent: apim
  properties: {
    displayName: 'AI Agent Sandbox'
    description: 'Subscription required for sandbox API access'
    state: 'published'
    subscriptionRequired: true
    approvalRequired: true         // human must approve new subscriptions
  }
}

resource productApi 'Microsoft.ApiManagement/service/products/apis@2023-05-01-preview' = {
  name: api.name
  parent: product
}

// ─── Outputs ──────────────────────────────────────────────────────────────────

output gatewayUrl string = apim.properties.gatewayUrl
output apimName string = apim.name
