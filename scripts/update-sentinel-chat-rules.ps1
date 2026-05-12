$ErrorActionPreference = "Stop"

$subscriptionId = az account show --query id -o tsv
$workspaceName = az monitor log-analytics workspace list -g rg-dev --query "[0].name" -o tsv
$baseUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/rg-dev/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules"
$apiVersion = "2023-02-01-preview"

$rules = @(
    @{
        Name = "31a8ed35-1cd5-511a-9544-6ca62e9eadad"
        DisplayName = "Secure Agent Chat: Prompt or Upload Blocked by Policy"
        Description = "A chat prompt or uploaded file was blocked by deterministic input policy or OPA before unsafe agent execution."
        Severity = "High"
        Tactics = @("DefenseEvasion", "Exfiltration")
        Query = @'
AiAgentAudit_CL
| where policy_decision == "deny" or outcome == "blocked"
| where error_code startswith "input_policy_violation:"
   or error_code has_any ("prompt_instruction_override", "network_exfiltration_instruction", "path_traversal_or_sensitive_path", "token_bomb_instruction")
| extend Violation = tostring(split(error_code, ":")[1])
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Events=count(), Violations=make_set(Violation) by run_id, agent_type, correlation_id
'@
    }
    @{
        Name = "4694083d-4396-5fd5-bd7c-280b7d74a478"
        DisplayName = "Secure Agent Chat: Sandbox Path Traversal Attempt"
        Description = "A chat prompt or uploaded document attempted path traversal, sensitive path access, or a file write outside the allowed sandbox path."
        Severity = "High"
        Tactics = @("Impact", "Persistence")
        Query = @'
AiAgentAudit_CL
| where error_code has "path_traversal_or_sensitive_path"
   or (action_type == "file_write" and (path !startswith "/workspace/" or not(path matches regex @"/workspace/[0-9a-f\-]{36}/write/")))
| project TimeGenerated, run_id, agent_type, action_type, path, outcome, policy_decision, error_code, correlation_id
'@
    }
    @{
        Name = "c24c592b-2ef9-5675-97bc-d8748b15c22a"
        DisplayName = "Secure Agent Chat: Token Abuse or Runaway Request"
        Description = "A chat/upload request asked for excessive token-expensive work or the run consumed an unusual number of tokens."
        Severity = "Medium"
        Tactics = @("Impact")
        Query = @'
let TokenBombBlocks = AiAgentAudit_CL
  | where error_code has "token_bomb_instruction"
  | project TimeGenerated, run_id, agent_type, TotalTokens=long(null), Reason="input-policy-token-bomb", correlation_id;
let RuntimeTokenSpikes = AiAgentAudit_CL
  | where action_type == "openai_call"
  | summarize TotalTokens = sum(token_count), TimeGenerated=max(TimeGenerated), agent_type=any(agent_type), correlation_id=any(correlation_id) by run_id, bin(TimeGenerated, 1m)
  | where TotalTokens > 10000
  | project TimeGenerated, run_id, agent_type, TotalTokens, Reason="runtime-token-spike", correlation_id;
union TokenBombBlocks, RuntimeTokenSpikes
'@
    }
    @{
        Name = "736d44f6-d162-5413-a4ee-a11530fd6c94"
        DisplayName = "Secure Agent Chat: Kill Switch Blocked Execution"
        Description = "A chat request was blocked because a global, capability, or agent-type kill switch is off."
        Severity = "High"
        Tactics = @("Impact")
        Query = @'
AiAgentAudit_CL
| where action_type == "kill_switch_check"
| where outcome == "blocked"
| project TimeGenerated, run_id, agent_type, error_code, correlation_id
'@
    }
    @{
        Name = "2d2ef011-66ca-4ddc-b343-8ce60f000001"
        DisplayName = "Secure Agent Chat: Unsafe Egress or Exfiltration Attempt"
        Description = "A chat prompt or uploaded document attempted metadata-service access, localhost/sidecar probing, webhook exfiltration, or disallowed external egress."
        Severity = "High"
        Tactics = @("Exfiltration", "Discovery")
        Query = @'
AiAgentAudit_CL
| where error_code has "network_exfiltration_instruction"
   or destination has_any ("169.254.169.254", "localhost", "127.0.0.1", "webhook.site", "example.com")
   or (action_type in ("network_call", "http_get", "http_post") and policy_decision == "deny")
| project TimeGenerated, run_id, agent_type, action_type, destination, outcome, policy_decision, error_code, correlation_id
'@
    }
)

foreach ($rule in $rules) {
    $body = @{
        kind = "Scheduled"
        properties = @{
            displayName = $rule.DisplayName
            description = $rule.Description
            severity = $rule.Severity
            enabled = $true
            query = $rule.Query
            queryFrequency = "PT5M"
            queryPeriod = "PT5M"
            triggerOperator = "GreaterThan"
            triggerThreshold = 0
            suppressionDuration = "PT30M"
            suppressionEnabled = $false
            tactics = $rule.Tactics
        }
    } | ConvertTo-Json -Depth 10

    $bodyFile = New-TemporaryFile
    Set-Content -Path $bodyFile -Value $body -Encoding utf8
    az rest --method put --url "$baseUrl/$($rule.Name)?api-version=$apiVersion" --body "@$bodyFile" --headers "Content-Type=application/json" "Accept=application/json" | Out-Null
    Remove-Item $bodyFile -Force
    Write-Host "UPSERTED=$($rule.DisplayName)"
}

az rest --method get --url "${baseUrl}?api-version=$apiVersion" --query "value[?starts_with(properties.displayName, 'Secure Agent Chat')].{displayName:properties.displayName,severity:properties.severity,enabled:properties.enabled}" -o table
