@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Unique resource token')
param resourceToken string

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

// ─── Custom Audit Table (Data Collection Rule) ────────────────────────────────
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
}

// ─── Microsoft Sentinel ───────────────────────────────────────────────────────

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2022-12-01-preview' = {
  name: 'default'
  scope: logAnalytics
  properties: {}
}

// ─── Sentinel Analytics Rules ─────────────────────────────────────────────────

// Rule 1: Too many OPA DENY decisions in a short window (anomaly / attack probe)
resource ruleFrequentDeny 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('frequent-deny-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'AI Agent: Frequent OPA Policy Denials'
    description: 'More than 5 OPA deny decisions in 10 minutes — possible policy bypass probing.'
    severity: 'Medium'
    enabled: true
    query: '''
      AiAgentAudit_CL
      | where policy_decision == "deny"
      | summarize DenyCount = count() by run_id, bin(TimeGenerated, 10m)
      | where DenyCount > 5
    '''
    queryFrequency: 'PT10M'
    queryPeriod: 'PT10M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: ['DefenseEvasion']
  }
  dependsOn: [sentinel]
}

// Rule 2: File write outside allowed virtual path
resource rulePathEscape 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('path-escape-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'AI Agent: File Write Outside Sandbox Path'
    description: 'A file write was attempted to a path outside /workspace/{run_id}/write/ — possible sandbox escape.'
    severity: 'High'
    enabled: true
    query: '''
      AiAgentAudit_CL
      | where action_type == "file_write"
      | where path !startswith "/workspace/"
         or not(path matches regex @"/workspace/[0-9a-f\-]{36}/write/")
      | project TimeGenerated, run_id, agent_type, path, outcome, correlation_id
    '''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT30M'
    suppressionEnabled: false
    tactics: ['Impact', 'Persistence']
  }
  dependsOn: [sentinel]
}

// Rule 3: Token usage spike per run
resource ruleTokenSpike 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('token-spike-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'AI Agent: Token Usage Spike'
    description: 'Agent run consumed more than 10,000 tokens in one minute — possible prompt injection or runaway loop.'
    severity: 'Medium'
    enabled: true
    query: '''
      AiAgentAudit_CL
      | where action_type == "openai_call"
      | summarize TotalTokens = sum(token_count) by run_id, bin(TimeGenerated, 1m)
      | where TotalTokens > 10000
    '''
    queryFrequency: 'PT1M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT15M'
    suppressionEnabled: false
    tactics: ['Impact']
  }
  dependsOn: [sentinel]
}

// Rule 4: Kill switch triggered — high-priority ops event
resource ruleKillSwitch 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('kill-switch-${resourceToken}')
  scope: logAnalytics
  kind: 'Scheduled'
  properties: {
    displayName: 'AI Agent: Kill Switch Activated'
    description: 'A global or agent-type kill switch was triggered — operator intervention required.'
    severity: 'High'
    enabled: true
    query: '''
      AiAgentAudit_CL
      | where action_type == "kill_switch_check"
      | where outcome == "blocked"
      | project TimeGenerated, run_id, agent_type, error_code, correlation_id
    '''
    queryFrequency: 'PT1M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5M'
    suppressionEnabled: false
    tactics: ['Impact']
  }
  dependsOn: [sentinel]
}

// ─── Outputs ──────────────────────────────────────────────────────────────────

output logAnalyticsWorkspaceId string = logAnalytics.id
output logAnalyticsWorkspaceName string = logAnalytics.name
output appInsightsConnectionString string = appInsights.properties.ConnectionString
output appInsightsInstrumentationKey string = appInsights.properties.InstrumentationKey
output dcrImmutableId string = auditDcr.properties.immutableId
output dceEndpoint string = auditDce.properties.logsIngestion.endpoint
