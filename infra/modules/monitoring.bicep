@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Unique resource token')
param resourceToken string

@description('Key Vault name for storing secrets')
param keyVaultName string

// ─── Log Analytics Workspace ──────────────────────────────────────────────────

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'log-${resourceToken}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 90
    workspaceCapping: {
      dailyQuotaGb: 5 // prevent runaway logging costs
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    publicNetworkAccessForIngestion: 'Enabled'   // agents push via DCE
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Append-only lock: prevents deletion of the workspace (but not log ingestion)
resource logAnalyticsLock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: 'log-delete-lock'
  scope: logAnalytics
  properties: {
    level: 'CanNotDelete'
    notes: 'Audit workspace must not be deleted — it is the system of record'
  }
}

// ─── Application Insights ─────────────────────────────────────────────────────

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'appi-${resourceToken}'
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
    RetentionInDays: 90
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// ─── Custom Audit Table ───────────────────────────────────────────────────────
// Must exist before the DCR and before Sentinel rules validate their queries.

resource auditTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: logAnalytics
  name: 'AiAgentAudit_CL'
  properties: {
    schema: {
      name: 'AiAgentAudit_CL'
      columns: [
        { name: 'TimeGenerated', type: 'dateTime' }
        { name: 'run_id', type: 'string' }
        { name: 'agent_type', type: 'string' }
        { name: 'action_type', type: 'string' }
        { name: 'policy_decision', type: 'string' }
        { name: 'path', type: 'string' }
        { name: 'destination', type: 'string' }
        { name: 'content_hash', type: 'string' }
        { name: 'token_count', type: 'int' }
        { name: 'risk_score', type: 'real' }
        { name: 'outcome', type: 'string' }
        { name: 'error_code', type: 'string' }
        { name: 'classification_label', type: 'string' }
        { name: 'dlp_patterns', type: 'string' }
        { name: 'content_safety_category', type: 'string' }
        { name: 'grounding_score', type: 'real' }
        { name: 'data_processing_basis', type: 'string' }
        { name: 'consent_status', type: 'string' }
        { name: 'parent_run_id', type: 'string' }
        { name: 'correlation_id', type: 'string' }
      ]
    }
    retentionInDays: 90
  }
}

// ─── Data Collection Endpoint + Rule ─────────────────────────────────────────
// Structured AI agent audit events land in AiAgentAudit_CL table.

resource auditDce 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' = {
  name: 'dce-${resourceToken}'
  location: location
  tags: tags
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource auditDcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: 'dcr-agent-audit-${resourceToken}'
  location: location
  tags: tags
  properties: {
    dataCollectionEndpointId: auditDce.id
    streamDeclarations: {
      'Custom-AiAgentAudit_CL': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'run_id', type: 'string' }
          { name: 'agent_type', type: 'string' }
          { name: 'action_type', type: 'string' }
          { name: 'policy_decision', type: 'string' }
          { name: 'path', type: 'string' }
          { name: 'destination', type: 'string' }
          { name: 'content_hash', type: 'string' }
          { name: 'token_count', type: 'int' }
          { name: 'risk_score', type: 'real' }
          { name: 'outcome', type: 'string' }
          { name: 'error_code', type: 'string' }
          { name: 'classification_label', type: 'string' }
          { name: 'dlp_patterns', type: 'string' }
          { name: 'content_safety_category', type: 'string' }
          { name: 'grounding_score', type: 'real' }
          { name: 'data_processing_basis', type: 'string' }
          { name: 'consent_status', type: 'string' }
          { name: 'parent_run_id', type: 'string' }
          { name: 'correlation_id', type: 'string' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalytics.id
          name: 'audit-workspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Custom-AiAgentAudit_CL']
        destinations: ['audit-workspace']
        transformKql: 'source | extend TimeGenerated = todatetime(TimeGenerated)'
        outputStream: 'Custom-AiAgentAudit_CL'
      }
    ]
  }
  dependsOn: [auditTable]
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2022-12-01-preview' = {
  name: 'default'
  scope: logAnalytics
  properties: {}
}

// ─── Sentinel Analytics Rules ─────────────────────────────────────────────────

// Rule 1: Chat/upload content blocked before or during policy evaluation
resource ruleFrequentDeny 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('frequent-deny-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'Secure Agent Chat: Prompt or Upload Blocked by Policy'
    description: 'A chat prompt or uploaded file was blocked by deterministic input policy or OPA before unsafe agent execution.'
    severity: 'High'
    enabled: true
    query: '''
      AiAgentAudit_CL
      | where policy_decision == "deny" or outcome == "blocked"
      | where error_code startswith "input_policy_violation:"
         or error_code has_any ("prompt_instruction_override", "network_exfiltration_instruction", "path_traversal_or_sensitive_path", "token_bomb_instruction")
      | extend Violation = tostring(split(error_code, ":")[1])
      | summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Events=count(), Violations=make_set(Violation) by run_id, agent_type, correlation_id
    '''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT30M'
    suppressionEnabled: false
    tactics: ['DefenseEvasion', 'Exfiltration']
  }
  dependsOn: [sentinel, auditTable]
}

// Rule 2: Chat request attempted sandbox path traversal or unsafe file write
resource rulePathEscape 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('path-escape-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'Secure Agent Chat: Sandbox Path Traversal Attempt'
    description: 'A chat prompt or uploaded document attempted path traversal, sensitive path access, or a file write outside the allowed sandbox path.'
    severity: 'High'
    enabled: true
    query: '''
      AiAgentAudit_CL
      | where error_code has "path_traversal_or_sensitive_path"
         or (action_type == "file_write" and (path !startswith "/workspace/" or not(path matches regex @"/workspace/[0-9a-f\-]{36}/write/")))
      | project TimeGenerated, run_id, agent_type, action_type, path, outcome, policy_decision, error_code, correlation_id
    '''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT30M'
    suppressionEnabled: false
    tactics: ['Impact', 'Persistence']
  }
  dependsOn: [sentinel, auditTable]
}

// Rule 3: Chat request indicates token abuse or runaway summarization
resource ruleTokenSpike 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('token-spike-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'Secure Agent Chat: Token Abuse or Runaway Request'
    description: 'A chat/upload request asked for excessive token-expensive work or the run consumed an unusual number of tokens.'
    severity: 'Medium'
    enabled: true
    query: '''
      let TokenBombBlocks = AiAgentAudit_CL
        | where error_code has "token_bomb_instruction"
        | project TimeGenerated, run_id, agent_type, TotalTokens=long(null), Reason="input-policy-token-bomb", correlation_id;
      let RuntimeTokenSpikes = AiAgentAudit_CL
        | where action_type == "openai_call"
        | summarize TotalTokens = sum(token_count), TimeGenerated=max(TimeGenerated), agent_type=any(agent_type), correlation_id=any(correlation_id) by run_id, bin(TimeGenerated, 1m)
        | where TotalTokens > 10000
        | project TimeGenerated, run_id, agent_type, TotalTokens, Reason="runtime-token-spike", correlation_id;
      union TokenBombBlocks, RuntimeTokenSpikes
    '''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT15M'
    suppressionEnabled: false
    tactics: ['Impact']
  }
  dependsOn: [sentinel, auditTable]
}

// Rule 4: Runtime kill switch blocked chat execution
resource ruleKillSwitch 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('kill-switch-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'Secure Agent Chat: Kill Switch Blocked Execution'
    description: 'A chat request was blocked because a global, capability, or agent-type kill switch is off.'
    severity: 'High'
    enabled: true
    query: '''
      AiAgentAudit_CL
      | where action_type == "kill_switch_check"
      | where outcome == "blocked"
      | project TimeGenerated, run_id, agent_type, error_code, correlation_id
    '''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5M'
    suppressionEnabled: false
    tactics: ['Impact']
  }
  dependsOn: [sentinel, auditTable]
}

// Rule 5: Chat request attempted unsafe egress or data exfiltration
resource ruleChatExfiltration 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('chat-exfiltration-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'Secure Agent Chat: Unsafe Egress or Exfiltration Attempt'
    description: 'A chat prompt or uploaded document attempted metadata-service access, localhost/sidecar probing, webhook exfiltration, or disallowed external egress.'
    severity: 'High'
    enabled: true
    query: '''
      AiAgentAudit_CL
      | where error_code has "network_exfiltration_instruction"
         or destination has_any ("169.254.169.254", "localhost", "127.0.0.1", "webhook.site", "example.com")
         or (action_type in ("network_call", "http_get", "http_post") and policy_decision == "deny")
      | project TimeGenerated, run_id, agent_type, action_type, destination, outcome, policy_decision, error_code, correlation_id
    '''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT30M'
    suppressionEnabled: false
    tactics: ['Exfiltration', 'Discovery']
  }
  dependsOn: [sentinel, auditTable]
}

// Rule 6: Repeated signature verification failures suggest identity tampering/replay
resource ruleSignatureFailures 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('signature-failures-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'Secure Agent API: Repeated Identity Signature Failures'
    description: 'Multiple signed identity validation failures detected in a short window, indicating header tampering, replay, or brute-force attempts.'
    severity: 'High'
    enabled: true
    query: '''
      AiAgentAudit_CL
      | where action_type == "signature_verification_failure"
      | where outcome == "blocked"
      | summarize Failures=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by error_code, correlation_id, bin(TimeGenerated, 5m)
      | where Failures >= 3
    '''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT15M'
    suppressionEnabled: false
    tactics: ['CredentialAccess', 'DefenseEvasion']
  }
  dependsOn: [sentinel, auditTable]
}

// Rule 7: Repeated cross-tenant lookup attempts indicate run enumeration/probing
resource ruleCrossTenantProbe 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('cross-tenant-probe-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'Secure Agent API: Cross-Tenant Run Probing'
    description: 'Repeated cross-tenant run access attempts were blocked and should be investigated as tenant isolation probing.'
    severity: 'High'
    enabled: true
    query: '''
      AiAgentAudit_CL
      | where action_type == "cross_tenant_access_attempt"
      | summarize Attempts=count(), Paths=make_set(path) by correlation_id, bin(TimeGenerated, 5m)
      | where Attempts >= 3
    '''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT15M'
    suppressionEnabled: false
    tactics: ['Discovery', 'LateralMovement']
  }
  dependsOn: [sentinel, auditTable]
}

// Rule 8: Rate-limit bursts can indicate API flooding or token exhaustion attempts
resource ruleRateLimitSpike 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('rate-limit-spike-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'Secure Agent API: Rate-Limit Spike'
    description: 'A burst of rate-limit blocks indicates potential flooding or abusive traffic patterns.'
    severity: 'Medium'
    enabled: true
    query: '''
      AiAgentAudit_CL
      | where action_type == "rate_limit_exceeded"
      | summarize Blocked=count() by error_code, path, bin(TimeGenerated, 5m)
      | where Blocked >= 5
    '''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT10M'
    suppressionEnabled: false
    tactics: ['Impact']
  }
  dependsOn: [sentinel, auditTable]
}

// Rule 9: Admin control-plane actions must be visible for privileged operation auditing
resource ruleAdminActions 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('admin-actions-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'Secure Agent API: Privileged Admin Action Performed'
    description: 'Kill switch toggles and run termination actions were performed and require SOC visibility.'
    severity: 'Medium'
    enabled: true
    query: '''
      AiAgentAudit_CL
      | where action_type in ("admin_kill_switch_toggle", "admin_run_delete", "admin_dsar_export")
      | project TimeGenerated, action_type, error_code, path, correlation_id, run_id, agent_type
    '''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5M'
    suppressionEnabled: false
    tactics: ['PrivilegeEscalation', 'Impact']
  }
  dependsOn: [sentinel, auditTable]
}

// ─── Store App Insights connection string in Key Vault ───────────────────────
// Container Apps reference this as a Key Vault secret for the APPINSIGHTS_CONNECTION_STRING env var.

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource appInsightsSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'appinsights-connection-string'
  properties: {
    value: appInsights.properties.ConnectionString
    attributes: { enabled: true }
  }
}

// ─── Outputs ──────────────────────────────────────────────────────────────────

output logAnalyticsWorkspaceId string = logAnalytics.id
output logAnalyticsWorkspaceName string = logAnalytics.name
output appInsightsConnectionString string = appInsights.properties.ConnectionString
output appInsightsInstrumentationKey string = appInsights.properties.InstrumentationKey
output dcrImmutableId string = auditDcr.properties.immutableId
output dceEndpoint string = auditDce.properties.logsIngestion.endpoint
