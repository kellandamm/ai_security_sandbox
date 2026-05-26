@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Unique resource token')
param resourceToken string

@description('Email address for human-in-the-loop approvals')
param approverEmail string

@description('Key Vault name for storing webhook secret')
param keyVaultName string

@description('Container App orchestrator URL for approval callbacks')
param orchestratorAppUrl string

@description('Log Analytics workspace resource ID')
param logAnalyticsWorkspaceId string

// ─── Logic App — Human-in-the-Loop Approval Workflow ─────────────────────────
// Flow: HTTP trigger (from agent) → send approval email → 24h wait →
//       callback to orchestrator with approve/deny result.

resource approvalLogicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'logic-approval-${resourceToken}'
  location: location
  tags: tags
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        approverEmail: {
          type: 'String'
          defaultValue: approverEmail
        }
        orchestratorUrl: {
          type: 'String'
          defaultValue: orchestratorAppUrl
        }
      }
      triggers: {
        manual: {
          type: 'Request'
          kind: 'Http'
          inputs: {
            schema: {
              type: 'object'
              properties: {
                run_id: { type: 'string' }
                agent_type: { type: 'string' }
                action_type: { type: 'string' }
                action_details: { type: 'object' }
                risk_score: { type: 'number' }
                correlation_id: { type: 'string' }
                callback_token: { type: 'string' }
              }
              required: ['run_id', 'agent_type', 'action_type', 'risk_score', 'callback_token']
            }
          }
        }
      }
      actions: {
        // Send approval email with action details
        Send_Approval_Email: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'office365\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/v2/Mail/SendApproval'
            body: {
              To: '@parameters(\'approverEmail\')'
              Subject: '[AI Sandbox] APPROVAL REQUIRED: @{triggerBody()?[\'action_type\']} by @{triggerBody()?[\'agent_type\']}'
              Importance: 'High'
              Options: 'Approve, Reject'
              Body: '''
<h2>AI Agent Action Requires Your Approval</h2>
<table>
  <tr><td><b>Run ID:</b></td><td>@{triggerBody()?['run_id']}</td></tr>
  <tr><td><b>Agent Type:</b></td><td>@{triggerBody()?['agent_type']}</td></tr>
  <tr><td><b>Action:</b></td><td>@{triggerBody()?['action_type']}</td></tr>
  <tr><td><b>Risk Score:</b></td><td>@{triggerBody()?['risk_score']}</td></tr>
  <tr><td><b>Details:</b></td><td>@{string(triggerBody()?['action_details'])}</td></tr>
  <tr><td><b>Correlation ID:</b></td><td>@{triggerBody()?['correlation_id']}</td></tr>
</table>
<p>This request will auto-deny after 24 hours if no response is received.</p>
'''
            }
          }
          runAfter: {}
        }
        // Branch on approval decision
        Approval_Decision: {
          type: 'Switch'
          expression: '@body(\'Send_Approval_Email\')?[\'SelectedOption\']'
          cases: {
            Approve: {
              case: 'Approve'
              actions: {
                Callback_Approve: {
                  type: 'Http'
                  inputs: {
                    method: 'POST'
                    uri: '@concat(parameters(\'orchestratorUrl\'), \'/runs/\', triggerBody()?[\'run_id\'], \'/approve\')'
                    headers: {
                      'Content-Type': 'application/json'
                      'X-Callback-Token': '@triggerBody()?[\'callback_token\']'
                    }
                    body: {
                      approved: true
                      approver: '@parameters(\'approverEmail\')'
                      timestamp: '@{utcNow()}'
                    }
                  }
                  runAfter: {}
                }
              }
            }
          }
          default: {
            actions: {
              Callback_Deny: {
                type: 'Http'
                inputs: {
                  method: 'POST'
                  uri: '@concat(parameters(\'orchestratorUrl\'), \'/runs/\', triggerBody()?[\'run_id\'], \'/approve\')'
                  headers: {
                    'Content-Type': 'application/json'
                    'X-Callback-Token': '@triggerBody()?[\'callback_token\']'
                  }
                  body: {
                    approved: false
                    reason: 'rejected_or_timeout'
                    approver: '@parameters(\'approverEmail\')'
                    timestamp: '@{utcNow()}'
                  }
                }
                runAfter: {}
              }
            }
          }
          runAfter: {
            Send_Approval_Email: ['Succeeded', 'TimedOut']
          }
        }
        // Respond to the original HTTP trigger with acknowledgement
        Respond_To_Agent: {
          type: 'Response'
          inputs: {
            statusCode: 202
            body: {
              status: 'pending'
              message: 'Approval request sent. Agent will receive callback within 24 hours.'
              run_id: '@triggerBody()?[\'run_id\']'
            }
          }
          runAfter: {}
        }
      }
      outputs: {}
    }
  }
}

// ─── Diagnostic Settings ─────────────────────────────────────────────────────

resource logicAppDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'logic-diag'
  scope: approvalLogicApp
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        category: 'WorkflowRuntime'
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

// ─── Store webhook URL secret in Key Vault ────────────────────────────────────
// The trigger URL contains the SAS signature — store it securely.

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource approvalTrigger 'Microsoft.Logic/workflows/triggers@2019-05-01' existing = {
  name: 'manual'
  parent: approvalLogicApp
}

resource approvalUrlSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'approval-logic-app-url'
  properties: {
    value: approvalTrigger.listCallbackUrl().value
    attributes: { enabled: true }
  }
}

// ─── Outputs ──────────────────────────────────────────────────────────────────

output logicAppName string = approvalLogicApp.name
