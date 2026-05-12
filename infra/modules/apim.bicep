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

@description('Backend Container App URL (orchestrator)')
param backendAppUrl string

@description('Azure AD tenant ID for JWT validation')
param aadTenantId string

@description('Azure AD app client ID (used as the token audience: api://<clientId>)')
param aadClientId string

@description('Shared secret APIM adds before forwarding requests to the orchestrator')
@secure()
param orchestratorGatewaySecret string

@description('Publisher email for APIM portal notifications')
param publisherEmail string

var backendHost = replace(replace(backendAppUrl, 'http://', ''), 'https://', '')
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
    publisherEmail: publisherEmail
    publisherName: 'AI Security Sandbox'
    virtualNetworkType: 'External'    // public gateway IP; backends stay internal
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
      {
        category: 'GatewayLogs'
        enabled: true
      }
      {
        category: 'WebSocketConnectionLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// ─── Named Values ─────────────────────────────────────────────────────────────
// The JWT policy XML uses {{aadTenantId}} — APIM resolves this at request time
// via the named-value store. Without this resource the policy URL stays a literal
// "{{aadTenantId}}" string and every JWT validation call will fail with a 401.

resource namedValueTenantId 'Microsoft.ApiManagement/service/namedValues@2023-05-01-preview' = {
  name: 'aadTenantId'
  parent: apim
  properties: {
    displayName: 'aadTenantId'
    value: !empty(aadTenantId) ? aadTenantId : 'NOT_CONFIGURED'
    secret: false
  }
}

resource namedValueClientId 'Microsoft.ApiManagement/service/namedValues@2023-05-01-preview' = {
  name: 'aadClientId'
  parent: apim
  properties: {
    displayName: 'aadClientId'
    value: !empty(aadClientId) ? aadClientId : 'NOT_CONFIGURED'
    secret: false
  }
}

resource namedValueBackendHost 'Microsoft.ApiManagement/service/namedValues@2023-05-01-preview' = {
  name: 'backendHost'
  parent: apim
  properties: {
    displayName: 'backendHost'
    value: backendHost
    secret: false
  }
}

resource namedValueGatewaySecret 'Microsoft.ApiManagement/service/namedValues@2023-05-01-preview' = {
  name: 'orchestratorGatewaySecret'
  parent: apim
  properties: {
    displayName: 'orchestratorGatewaySecret'
    value: orchestratorGatewaySecret
    secret: true
  }
}

// ─── Backend — orchestrator ───────────────────────────────────────────────────

resource backend 'Microsoft.ApiManagement/service/backends@2023-05-01-preview' = {
  name: 'orchestrator-backend'
  parent: apim
  properties: {
    url: backendAppUrl
    protocol: 'http'
    tls: {
      validateCertificateChain: false
      validateCertificateName: false
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
    serviceUrl: backendAppUrl
    protocols: ['https']
    subscriptionRequired: false
  }
}

// Catch-all operations — one per HTTP method with a path template parameter.
// APIM requires explicit methods; wildcard method '*' cannot coexist with others.
var httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']

resource catchAllOperations 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = [for method in httpMethods: {
  name: 'catch-all-${toLower(method)}'
  parent: api
  properties: {
    displayName: '${method} catch-all'
    method: method
    urlTemplate: '/{*path}'
    templateParameters: [
      {
        name: 'path'
        required: true
        type: 'string'
      }
    ]
    description: 'Forwards ${method} requests to the orchestrator backend'
  }
}]

// ─── Global API Policy — rate limiting + JWT validation + correlation ─────────

resource apiPolicy 'Microsoft.ApiManagement/service/apis/policies@2023-05-01-preview' = {
  name: 'policy'
  parent: api
  dependsOn: [namedValueTenantId, namedValueClientId, namedValueBackendHost, namedValueGatewaySecret]   // named values must exist before policy is applied
  properties: {
    format: 'xml'
    value: '''
<policies>
  <inbound>
    <base />

    <!-- Correlation ID: generate if not provided, propagate throughout -->
    <set-variable name="correlationId" value="@(context.Request.Headers.GetValueOrDefault(&quot;X-Correlation-ID&quot;, Guid.NewGuid().ToString()))" />
    <set-header name="X-Correlation-ID" exists-action="override">
      <value>@((string)context.Variables["correlationId"])</value>
    </set-header>
    <set-header name="X-Orchestrator-Gateway-Secret" exists-action="override">
      <value>{{orchestratorGatewaySecret}}</value>
    </set-header>

    <!-- CORS for the static frontend and local Vite dev server -->
    <cors allow-credentials="false">
      <allowed-origins>
        <origin>*</origin>
      </allowed-origins>
      <allowed-methods preflight-result-max-age="300">
        <method>GET</method>
        <method>POST</method>
        <method>PUT</method>
        <method>DELETE</method>
        <method>OPTIONS</method>
      </allowed-methods>
      <allowed-headers>
        <header>*</header>
      </allowed-headers>
      <expose-headers>
        <header>X-Correlation-ID</header>
        <header>X-RateLimit-Remaining</header>
        <header>Retry-After</header>
      </expose-headers>
    </cors>

    <!-- JWT validation: require valid Azure AD bearer token (skipped when AAD not configured) -->
    <choose>
      <when condition="@(&quot;{{aadClientId}}&quot; != &quot;NOT_CONFIGURED&quot; &amp;&amp; !context.Request.Url.Path.EndsWith(&quot;/health&quot;))">
        <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized: valid Azure AD token required">
          <openid-config url="https://login.microsoftonline.com/{{aadTenantId}}/v2.0/.well-known/openid-configuration" />
          <required-claims>
            <claim name="aud" match="any">
              <value>api://{{aadClientId}}</value>
              <value>{{aadClientId}}</value>
            </claim>
          </required-claims>
        </validate-jwt>
      </when>
    </choose>

    <set-variable name="subscriptionCounterKey" value="@(context.Subscription != null ? context.Subscription.Id : &quot;anonymous&quot;)" />
    <set-variable name="rateLimitKey" value="@(context.Request.Headers.ContainsKey(&quot;X-Agent-ID&quot;) ? context.Request.Headers.GetValueOrDefault(&quot;X-Agent-ID&quot;, &quot;&quot;) : (string)context.Variables[&quot;subscriptionCounterKey&quot;])" />

    <!-- Rate limiting: 100 calls per 60 seconds per agent-id header -->
    <rate-limit-by-key calls="100" renewal-period="60"
      counter-key="@((string)context.Variables[&quot;rateLimitKey&quot;])"
      increment-condition="@(true)"
      retry-after-header-name="Retry-After"
      remaining-calls-header-name="X-RateLimit-Remaining" />

    <!-- Daily quota: 10,000 calls per subscription key per day -->
    <quota-by-key calls="10000" renewal-period="86400"
      counter-key="@((string)context.Variables[&quot;subscriptionCounterKey&quot;])"
      increment-condition="@(true)" />

  </inbound>

  <backend>
    <base />
  </backend>

  <outbound>
    <base />
    <!-- Backend routing is resolved from the API serviceUrl/backend resource -->
  </outbound>

  <on-error>
    <base />
    <set-header name="X-Correlation-ID" exists-action="override">
      <value>@(context.Variables.ContainsKey("correlationId") ? (string)context.Variables["correlationId"] : context.RequestId.ToString())</value>
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
      {
        name: 'runId'
        type: 'string'
        required: true
      }
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
      {
        name: 'runId'
        type: 'string'
        required: true
      }
    ]
  }
}

resource opStreamRun 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  name: 'stream-run'
  parent: api
  properties: {
    displayName: 'Stream Run Audit Events (SSE)'
    method: 'GET'
    urlTemplate: '/stream/runs/{runId}'
    description: 'Server-sent events stream of real-time audit events for a run'
    templateParameters: [
      {
        name: 'runId'
        type: 'string'
        required: true
      }
    ]
  }
}

// Disable response buffering so SSE frames are flushed immediately to the client.
resource opStreamRunPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2023-05-01-preview' = {
  name: 'policy'
  parent: opStreamRun
  properties: {
    format: 'xml'
    value: '''
<policies>
  <inbound><base /></inbound>
  <backend>
    <forward-request buffer-response="false" />
  </backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>
'''
  }
}

resource opGetTimeline 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  name: 'get-timeline'
  parent: api
  properties: {
    displayName: 'Get Run Timeline'
    method: 'GET'
    urlTemplate: '/runs/{runId}/timeline'
    description: 'Retrieve the ordered list of audit events for a completed or active run'
    templateParameters: [
      {
        name: 'runId'
        type: 'string'
        required: true
      }
    ]
  }
}

resource opApproveRun 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  name: 'approve-run'
  parent: api
  properties: {
    displayName: 'Approve HITL Action'
    method: 'POST'
    urlTemplate: '/runs/{runId}/approve'
    description: 'Human-in-the-loop approval callback: allow or deny a held agent action'
    templateParameters: [
      {
        name: 'runId'
        type: 'string'
        required: true
      }
    ]
  }
}

resource opGetAlerts 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  name: 'get-alerts'
  parent: api
  properties: {
    displayName: 'Get Active Security Alerts'
    method: 'GET'
    urlTemplate: '/alerts'
    description: 'List security alerts raised across all recent runs (SOC console feed)'
  }
}

resource opGetKillSwitches 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  name: 'get-kill-switches'
  parent: api
  properties: {
    displayName: 'List Kill Switches'
    method: 'GET'
    urlTemplate: '/kill-switches'
    description: 'List all App Configuration feature flags used as kill switches'
  }
}

resource opPutKillSwitch 'Microsoft.ApiManagement/service/apis/operations@2023-05-01-preview' = {
  name: 'put-kill-switch'
  parent: api
  properties: {
    displayName: 'Toggle Kill Switch'
    method: 'PUT'
    urlTemplate: '/kill-switches/{flagName}'
    description: 'Enable or disable a named kill-switch flag in App Configuration'
    templateParameters: [
      {
        name: 'flagName'
        type: 'string'
        required: true
      }
    ]
  }
}

// ─── Outputs ──────────────────────────────────────────────────────────────────

output gatewayUrl string = apim.properties.gatewayUrl
output apimName string = apim.name
