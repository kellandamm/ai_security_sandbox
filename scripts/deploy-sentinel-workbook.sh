#!/usr/bin/env sh
set -eu

RESOURCE_GROUP="${1:-${AZURE_RESOURCE_GROUP:-}}"
WORKSPACE_RESOURCE_ID="${2:-${LOG_ANALYTICS_WORKSPACE_ID:-}}"
WORKBOOK_DISPLAY_NAME="${WORKBOOK_DISPLAY_NAME:-AI Security Sandbox - SOC Workbook}"
WORKBOOK_ID="${WORKBOOK_ID:-}"

<<<<<<< HEAD
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKBOOK_DEFINITION_PATH="${WORKBOOK_DEFINITION_PATH:-$SCRIPT_DIR/../infra/workbooks/soc-workbook.json}"

=======
>>>>>>> origin/main
if [ -z "$RESOURCE_GROUP" ]; then
  echo "Resource group is required. Pass as arg1 or set AZURE_RESOURCE_GROUP." >&2
  exit 1
fi

<<<<<<< HEAD
if [ ! -f "$WORKBOOK_DEFINITION_PATH" ]; then
  echo "Workbook definition file not found: $WORKBOOK_DEFINITION_PATH" >&2
  exit 1
fi

=======
>>>>>>> origin/main
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"

if [ -z "$WORKSPACE_RESOURCE_ID" ]; then
  WORKSPACE_RESOURCE_ID="$(az monitor log-analytics workspace list --resource-group "$RESOURCE_GROUP" --query "[0].id" -o tsv)"
fi

if [ -z "$WORKSPACE_RESOURCE_ID" ]; then
  echo "Could not resolve a Log Analytics workspace in '$RESOURCE_GROUP'." >&2
  exit 1
fi

LOCATION="$(az resource show --ids "$WORKSPACE_RESOURCE_ID" --query location -o tsv)"
if [ -z "$LOCATION" ]; then
  echo "Could not resolve workspace location for '$WORKSPACE_RESOURCE_ID'." >&2
  exit 1
fi

if [ -z "$WORKBOOK_ID" ]; then
    export WORKBOOK_DISPLAY_NAME
    EXISTING_ID="$(az resource list --resource-group "$RESOURCE_GROUP" --resource-type Microsoft.Insights/workbooks -o json 2>/dev/null | python3 - <<'PY'
import json
import os
import sys

display_name = os.environ["WORKBOOK_DISPLAY_NAME"]
rows = json.load(sys.stdin)
for row in rows:
        tags = row.get("tags") or {}
        if tags.get("hidden-title") == display_name:
                print(row.get("name", ""))
                break
PY
)"
  if [ -n "$EXISTING_ID" ]; then
    WORKBOOK_ID="$EXISTING_ID"
  else
    WORKBOOK_ID="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"
  fi
fi

PAYLOAD_FILE="$(mktemp)"
export WORKSPACE_RESOURCE_ID
export LOCATION
export WORKBOOK_DISPLAY_NAME
<<<<<<< HEAD
export WORKBOOK_DEFINITION_PATH
=======
>>>>>>> origin/main
python3 - <<'PY' > "$PAYLOAD_FILE"
import json
import os

workspace = os.environ["WORKSPACE_RESOURCE_ID"]
location = os.environ["LOCATION"]
display_name = os.environ["WORKBOOK_DISPLAY_NAME"]
<<<<<<< HEAD
definition_path = os.environ["WORKBOOK_DEFINITION_PATH"]

with open(definition_path, "r", encoding="utf-8") as f:
    raw = f.read()

# Substitute the workspace placeholder, then validate the result is JSON.
raw = raw.replace("__WORKSPACE_RESOURCE_ID__", workspace)
serialized = json.loads(raw)
=======

serialized = {
    "version": "Notebook/1.0",
    "items": [
        {
            "type": 1,
            "content": {
                "json": "# AI Security Sandbox SOC Workbook\n\nOperational visibility for policy enforcement, DLP/content-safety controls, and run-level anomalies from AiAgentAudit_CL."
            },
            "name": "text - intro",
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "AiAgentAudit_CL | extend action_type_x=tostring(column_ifexists('action_type_s', column_ifexists('action_type', ''))), policy_decision_x=tostring(column_ifexists('policy_decision_s', column_ifexists('policy_decision', ''))), outcome_x=tostring(column_ifexists('outcome_s', column_ifexists('outcome', ''))) | summarize events=count(), blocks=countif(policy_decision_x == 'deny' or outcome_x == 'blocked') by action_type_x | order by blocks desc, events desc",
                "size": 0,
                "title": "Policy Posture Overview",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "crossComponentResources": [workspace],
            },
            "name": "query - posture",
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "AiAgentAudit_CL | extend agent_type_x=tostring(column_ifexists('agent_type_s', column_ifexists('agent_type', ''))), action_type_x=tostring(column_ifexists('action_type_s', column_ifexists('action_type', ''))), risk_score_x=todouble(column_ifexists('risk_score_d', column_ifexists('risk_score', real(null)))) | summarize avg_risk=avg(risk_score_x), max_risk=max(risk_score_x), events=count() by agent_type_x, action_type_x | order by avg_risk desc",
                "size": 0,
                "title": "Agent Risk Heatmap Data",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "crossComponentResources": [workspace],
            },
            "name": "query - risk",
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "AiAgentAudit_CL | extend action_type_x=tostring(column_ifexists('action_type_s', column_ifexists('action_type', ''))), policy_decision_x=tostring(column_ifexists('policy_decision_s', column_ifexists('policy_decision', ''))), outcome_x=tostring(column_ifexists('outcome_s', column_ifexists('outcome', ''))), dlp_patterns_x=tostring(column_ifexists('dlp_patterns_s', column_ifexists('dlp_patterns', ''))), run_id_x=tostring(column_ifexists('run_id_s', column_ifexists('run_id', ''))), agent_type_x=tostring(column_ifexists('agent_type_s', column_ifexists('agent_type', ''))), classification_label_x=tostring(column_ifexists('classification_label_s', column_ifexists('classification_label', ''))), risk_score_x=todouble(column_ifexists('risk_score_d', column_ifexists('risk_score', real(null)))), error_code_x=tostring(column_ifexists('error_code_s', column_ifexists('error_code', ''))), correlation_id_x=tostring(column_ifexists('correlation_id_s', column_ifexists('correlation_id', ''))) | where action_type_x == 'dlp_scan' | where policy_decision_x == 'deny' or outcome_x == 'blocked' or dlp_patterns_x != '' | project TimeGenerated, run_id_x, agent_type_x, dlp_patterns_x, classification_label_x, risk_score_x, error_code_x, correlation_id_x | order by TimeGenerated desc",
                "size": 0,
                "title": "DLP Interceptions",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "crossComponentResources": [workspace],
            },
            "name": "query - dlp",
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "AiAgentAudit_CL | extend action_type_x=tostring(column_ifexists('action_type_s', column_ifexists('action_type', ''))), policy_decision_x=tostring(column_ifexists('policy_decision_s', column_ifexists('policy_decision', ''))), outcome_x=tostring(column_ifexists('outcome_s', column_ifexists('outcome', ''))), run_id_x=tostring(column_ifexists('run_id_s', column_ifexists('run_id', ''))), agent_type_x=tostring(column_ifexists('agent_type_s', column_ifexists('agent_type', ''))), content_safety_category_x=tostring(column_ifexists('content_safety_category_s', column_ifexists('content_safety_category', ''))), risk_score_x=todouble(column_ifexists('risk_score_d', column_ifexists('risk_score', real(null)))), error_code_x=tostring(column_ifexists('error_code_s', column_ifexists('error_code', ''))), correlation_id_x=tostring(column_ifexists('correlation_id_s', column_ifexists('correlation_id', ''))) | where action_type_x == 'content_safety_check' | where policy_decision_x == 'deny' or outcome_x == 'blocked' | project TimeGenerated, run_id_x, agent_type_x, content_safety_category_x, risk_score_x, error_code_x, correlation_id_x | order by TimeGenerated desc",
                "size": 0,
                "title": "Content Safety Blocks",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "crossComponentResources": [workspace],
            },
            "name": "query - content-safety",
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "AiAgentAudit_CL | extend action_type_x=tostring(column_ifexists('action_type_s', column_ifexists('action_type', ''))), run_id_x=tostring(column_ifexists('run_id_s', column_ifexists('run_id', ''))), agent_type_x=tostring(column_ifexists('agent_type_s', column_ifexists('agent_type', ''))), token_count_x=toint(column_ifexists('token_count_d', column_ifexists('token_count', int(0)))) | where action_type_x == 'openai_call' | summarize total_tokens=sum(token_count_x), avg_tokens=avg(token_count_x), calls=count() by run_id_x, agent_type_x | order by total_tokens desc",
                "size": 0,
                "title": "Token Budget Consumption",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "crossComponentResources": [workspace],
            },
            "name": "query - token",
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "let per_run = AiAgentAudit_CL | extend run_id_x=tostring(column_ifexists('run_id_s', column_ifexists('run_id', ''))), agent_type_x=tostring(column_ifexists('agent_type_s', column_ifexists('agent_type', ''))), token_count_x=toint(column_ifexists('token_count_d', column_ifexists('token_count', int(0)))), risk_score_x=todouble(column_ifexists('risk_score_d', column_ifexists('risk_score', real(null)))) | summarize total_events=count(), total_tokens=sum(token_count_x), max_risk=max(risk_score_x) by run_id_x, agent_type_x; let baselines = per_run | summarize avg_events=avg(total_events), avg_tokens=avg(total_tokens); per_run | join kind=inner baselines on 1==1 | where total_events > (avg_events * 3.0) or total_tokens > (avg_tokens * 3.0) or max_risk >= 0.8 | project run_id_x, agent_type_x, total_events, total_tokens, max_risk, avg_events, avg_tokens | order by max_risk desc, total_events desc",
                "size": 0,
                "title": "Anomaly Candidates",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "crossComponentResources": [workspace],
            },
            "name": "query - anomaly",
        },
    ],
}
>>>>>>> origin/main

payload = {
    "kind": "shared",
    "location": location,
    "properties": {
        "displayName": display_name,
        "sourceId": workspace,
        "category": "sentinel",
        "serializedData": json.dumps(serialized, separators=(",", ":")),
        "version": "1.0",
    },
}

print(json.dumps(payload))
PY

az rest \
  --method PUT \
  --url "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Insights/workbooks/$WORKBOOK_ID?api-version=2022-04-01" \
  --body "@$PAYLOAD_FILE" \
  --headers "Content-Type=application/json" >/dev/null

rm -f "$PAYLOAD_FILE"

echo "Workbook upserted: $WORKBOOK_DISPLAY_NAME"
echo "Workbook resource id: /subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Insights/workbooks/$WORKBOOK_ID"
echo "Workbook portal link: https://portal.azure.com/#resource/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Insights/workbooks/$WORKBOOK_ID/overview"
