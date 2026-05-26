param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [string]$WorkspaceResourceId,

    [string]$WorkbookDisplayName = "AI Security Sandbox - SOC Workbook",

    [string]$WorkbookId,

<<<<<<< HEAD
    [string]$Location,

    [string]$WorkbookDefinitionPath
=======
    [string]$Location
>>>>>>> origin/main
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

<<<<<<< HEAD
if (-not $WorkbookDefinitionPath) {
    $WorkbookDefinitionPath = Join-Path $PSScriptRoot "..\infra\workbooks\soc-workbook.json"
}

if (-not (Test-Path $WorkbookDefinitionPath)) {
    throw "Workbook definition file not found: $WorkbookDefinitionPath"
}

=======
>>>>>>> origin/main
$null = az account show 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Azure CLI is not authenticated. Run 'az login' first."
}

$subscriptionId = az account show --query id -o tsv

if (-not $WorkspaceResourceId) {
    $WorkspaceResourceId = az monitor log-analytics workspace list --resource-group $ResourceGroup --query "[0].id" -o tsv
}

if (-not $WorkspaceResourceId) {
    throw "Could not resolve a Log Analytics workspace in resource group '$ResourceGroup'."
}

if (-not $Location) {
    $Location = az resource show --ids $WorkspaceResourceId --query location -o tsv
}

if (-not $Location) {
    throw "Could not resolve a location for workspace '$WorkspaceResourceId'."
}

if (-not $WorkbookId) {
    $existingId = az resource list --resource-group $ResourceGroup --resource-type Microsoft.Insights/workbooks -o json 2>$null |
        ConvertFrom-Json |
        Where-Object { $_.tags -and $_.tags.'hidden-title' -eq $WorkbookDisplayName } |
        ForEach-Object { $_.name } |
        Select-Object -First 1
    if ($existingId) {
        $WorkbookId = $existingId
    } else {
        $WorkbookId = [guid]::NewGuid().ToString()
    }
}

<<<<<<< HEAD
# Read the shared definition and substitute the workspace placeholder.
# The definition keeps `__WORKSPACE_RESOURCE_ID__` everywhere a crossComponentResources / fallback id is needed.
$definitionText = Get-Content -Path $WorkbookDefinitionPath -Raw
$definitionText = $definitionText.Replace('__WORKSPACE_RESOURCE_ID__', $WorkspaceResourceId)

# Validate it round-trips as JSON before we send it.
$null = $definitionText | ConvertFrom-Json
=======
$serialized = @{
    version = "Notebook/1.0"
    items = @(
        @{
            type = 1
            content = @{
                json = "# AI Security Sandbox SOC Workbook`n`nOperational visibility for policy enforcement, DLP/content-safety controls, and run-level anomalies from AiAgentAudit_CL."
            }
            name = "text - intro"
        },
        @{
            type = 3
            content = @{
                version = "KqlItem/1.0"
                query = "AiAgentAudit_CL | extend action_type_x=tostring(column_ifexists('action_type_s', column_ifexists('action_type', ''))), policy_decision_x=tostring(column_ifexists('policy_decision_s', column_ifexists('policy_decision', ''))), outcome_x=tostring(column_ifexists('outcome_s', column_ifexists('outcome', ''))) | summarize events=count(), blocks=countif(policy_decision_x == 'deny' or outcome_x == 'blocked') by action_type_x | order by blocks desc, events desc"
                size = 0
                title = "Policy Posture Overview"
                queryType = 0
                resourceType = "microsoft.operationalinsights/workspaces"
                crossComponentResources = @($WorkspaceResourceId)
            }
            name = "query - posture"
        },
        @{
            type = 3
            content = @{
                version = "KqlItem/1.0"
                query = "AiAgentAudit_CL | extend agent_type_x=tostring(column_ifexists('agent_type_s', column_ifexists('agent_type', ''))), action_type_x=tostring(column_ifexists('action_type_s', column_ifexists('action_type', ''))), risk_score_x=todouble(column_ifexists('risk_score_d', column_ifexists('risk_score', real(null)))) | summarize avg_risk=avg(risk_score_x), max_risk=max(risk_score_x), events=count() by agent_type_x, action_type_x | order by avg_risk desc"
                size = 0
                title = "Agent Risk Heatmap Data"
                queryType = 0
                resourceType = "microsoft.operationalinsights/workspaces"
                crossComponentResources = @($WorkspaceResourceId)
            }
            name = "query - risk"
        },
        @{
            type = 3
            content = @{
                version = "KqlItem/1.0"
                query = "AiAgentAudit_CL | extend action_type_x=tostring(column_ifexists('action_type_s', column_ifexists('action_type', ''))), policy_decision_x=tostring(column_ifexists('policy_decision_s', column_ifexists('policy_decision', ''))), outcome_x=tostring(column_ifexists('outcome_s', column_ifexists('outcome', ''))), dlp_patterns_x=tostring(column_ifexists('dlp_patterns_s', column_ifexists('dlp_patterns', ''))), run_id_x=tostring(column_ifexists('run_id_s', column_ifexists('run_id', ''))), agent_type_x=tostring(column_ifexists('agent_type_s', column_ifexists('agent_type', ''))), classification_label_x=tostring(column_ifexists('classification_label_s', column_ifexists('classification_label', ''))), risk_score_x=todouble(column_ifexists('risk_score_d', column_ifexists('risk_score', real(null)))), error_code_x=tostring(column_ifexists('error_code_s', column_ifexists('error_code', ''))), correlation_id_x=tostring(column_ifexists('correlation_id_s', column_ifexists('correlation_id', ''))) | where action_type_x == 'dlp_scan' | where policy_decision_x == 'deny' or outcome_x == 'blocked' or dlp_patterns_x != '' | project TimeGenerated, run_id_x, agent_type_x, dlp_patterns_x, classification_label_x, risk_score_x, error_code_x, correlation_id_x | order by TimeGenerated desc"
                size = 0
                title = "DLP Interceptions"
                queryType = 0
                resourceType = "microsoft.operationalinsights/workspaces"
                crossComponentResources = @($WorkspaceResourceId)
            }
            name = "query - dlp"
        },
        @{
            type = 3
            content = @{
                version = "KqlItem/1.0"
                query = "AiAgentAudit_CL | extend action_type_x=tostring(column_ifexists('action_type_s', column_ifexists('action_type', ''))), policy_decision_x=tostring(column_ifexists('policy_decision_s', column_ifexists('policy_decision', ''))), outcome_x=tostring(column_ifexists('outcome_s', column_ifexists('outcome', ''))), run_id_x=tostring(column_ifexists('run_id_s', column_ifexists('run_id', ''))), agent_type_x=tostring(column_ifexists('agent_type_s', column_ifexists('agent_type', ''))), content_safety_category_x=tostring(column_ifexists('content_safety_category_s', column_ifexists('content_safety_category', ''))), risk_score_x=todouble(column_ifexists('risk_score_d', column_ifexists('risk_score', real(null)))), error_code_x=tostring(column_ifexists('error_code_s', column_ifexists('error_code', ''))), correlation_id_x=tostring(column_ifexists('correlation_id_s', column_ifexists('correlation_id', ''))) | where action_type_x == 'content_safety_check' | where policy_decision_x == 'deny' or outcome_x == 'blocked' | project TimeGenerated, run_id_x, agent_type_x, content_safety_category_x, risk_score_x, error_code_x, correlation_id_x | order by TimeGenerated desc"
                size = 0
                title = "Content Safety Blocks"
                queryType = 0
                resourceType = "microsoft.operationalinsights/workspaces"
                crossComponentResources = @($WorkspaceResourceId)
            }
            name = "query - content-safety"
        },
        @{
            type = 3
            content = @{
                version = "KqlItem/1.0"
                query = "AiAgentAudit_CL | extend action_type_x=tostring(column_ifexists('action_type_s', column_ifexists('action_type', ''))), run_id_x=tostring(column_ifexists('run_id_s', column_ifexists('run_id', ''))), agent_type_x=tostring(column_ifexists('agent_type_s', column_ifexists('agent_type', ''))), token_count_x=toint(column_ifexists('token_count_d', column_ifexists('token_count', int(0)))) | where action_type_x == 'openai_call' | summarize total_tokens=sum(token_count_x), avg_tokens=avg(token_count_x), calls=count() by run_id_x, agent_type_x | order by total_tokens desc"
                size = 0
                title = "Token Budget Consumption"
                queryType = 0
                resourceType = "microsoft.operationalinsights/workspaces"
                crossComponentResources = @($WorkspaceResourceId)
            }
            name = "query - token"
        },
        @{
            type = 3
            content = @{
                version = "KqlItem/1.0"
                query = "let per_run = AiAgentAudit_CL | extend run_id_x=tostring(column_ifexists('run_id_s', column_ifexists('run_id', ''))), agent_type_x=tostring(column_ifexists('agent_type_s', column_ifexists('agent_type', ''))), token_count_x=toint(column_ifexists('token_count_d', column_ifexists('token_count', int(0)))), risk_score_x=todouble(column_ifexists('risk_score_d', column_ifexists('risk_score', real(null)))) | summarize total_events=count(), total_tokens=sum(token_count_x), max_risk=max(risk_score_x) by run_id_x, agent_type_x; let baselines = per_run | summarize avg_events=avg(total_events), avg_tokens=avg(total_tokens); per_run | join kind=inner baselines on 1==1 | where total_events > (avg_events * 3.0) or total_tokens > (avg_tokens * 3.0) or max_risk >= 0.8 | project run_id_x, agent_type_x, total_events, total_tokens, max_risk, avg_events, avg_tokens | order by max_risk desc, total_events desc"
                size = 0
                title = "Anomaly Candidates"
                queryType = 0
                resourceType = "microsoft.operationalinsights/workspaces"
                crossComponentResources = @($WorkspaceResourceId)
            }
            name = "query - anomaly"
        }
    )
}
>>>>>>> origin/main

$payload = @{
    kind = "shared"
    location = $Location
    properties = @{
        displayName = $WorkbookDisplayName
        sourceId = $WorkspaceResourceId
        category = "sentinel"
<<<<<<< HEAD
        serializedData = $definitionText
=======
        serializedData = ($serialized | ConvertTo-Json -Depth 20 -Compress)
>>>>>>> origin/main
        version = "1.0"
    }
}

$payloadFile = [System.IO.Path]::GetTempFileName() + ".json"
[System.IO.File]::WriteAllText($payloadFile, ($payload | ConvertTo-Json -Depth 30), [System.Text.UTF8Encoding]::new($false))

az rest --method PUT --url "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${WorkbookId}?api-version=2022-04-01" --body "@$payloadFile" --headers "Content-Type=application/json" | Out-Null

Remove-Item $payloadFile -Force -ErrorAction SilentlyContinue

$workbookUrl = "https://portal.azure.com/#resource/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/$WorkbookId/overview"
Write-Host "Workbook upserted: $WorkbookDisplayName"
Write-Host "Workbook resource id: /subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/$WorkbookId"
Write-Host "Workbook portal link: $workbookUrl"
