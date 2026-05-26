param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory = $true)]
    [string]$ServiceName,

    [Parameter(Mandatory = $true)]
    [string]$ApiId,

    [Parameter(Mandatory = $true)]
    [string]$BackendHost,

    [string]$SubscriptionId = (az account show --query id -o tsv)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$policy = @"
<policies>
  <inbound>
    <base />
    <set-variable name="correlationId" value="@(context.Request.Headers.GetValueOrDefault(&quot;X-Correlation-ID&quot;, Guid.NewGuid().ToString()))" />
    <set-header name="X-Correlation-ID" exists-action="override">
      <value>@((string)context.Variables["correlationId"])</value>
    </set-header>

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

    <choose>
      <when condition="@(&quot;{{aadClientId}}&quot; != &quot;NOT_CONFIGURED&quot; &amp;&amp; context.Request.Url.Path != &quot;/health&quot;)">
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

    <rate-limit-by-key calls="100" renewal-period="60"
      counter-key="@((string)context.Variables[&quot;rateLimitKey&quot;])"
      increment-condition="@(true)"
      retry-after-header-name="Retry-After"
      remaining-calls-header-name="X-RateLimit-Remaining" />

    <quota-by-key calls="10000" renewal-period="86400"
      counter-key="@((string)context.Variables[&quot;subscriptionCounterKey&quot;])"
      increment-condition="@(true)" />

    <set-header name="Host" exists-action="override">
      <value>$BackendHost</value>
    </set-header>
    <set-backend-service base-url="http://10.0.1.57" />
  </inbound>

  <backend>
    <base />
  </backend>

  <outbound>
    <base />
    <set-header name="X-Correlation-ID" exists-action="override">
      <value>@(context.Variables.ContainsKey("correlationId") ? (string)context.Variables["correlationId"] : context.RequestId.ToString())</value>
    </set-header>
  </outbound>

  <on-error>
    <base />
    <set-header name="X-Correlation-ID" exists-action="override">
      <value>@(context.Variables.ContainsKey("correlationId") ? (string)context.Variables["correlationId"] : context.RequestId.ToString())</value>
    </set-header>
  </on-error>
</policies>
"@

$body = @{
    properties = @{
        format = 'xml'
        value = $policy
    }
} | ConvertTo-Json -Depth 5

$tempFile = Join-Path $env:TEMP 'apim-policy-body.json'
[System.IO.File]::WriteAllText($tempFile, $body, [System.Text.UTF8Encoding]::new($false))

az rest --method PUT `
    --uri "https://management.azure.com/subscriptions/${SubscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.ApiManagement/service/${ServiceName}/apis/${ApiId}/policies/policy?api-version=2023-05-01-preview" `
    --headers "Content-Type=application/json" `
    --body "@$tempFile"

Remove-Item $tempFile -Force -ErrorAction SilentlyContinue