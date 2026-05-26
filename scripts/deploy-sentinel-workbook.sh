#!/usr/bin/env sh
set -eu

RESOURCE_GROUP="${1:-${AZURE_RESOURCE_GROUP:-}}"
WORKSPACE_RESOURCE_ID="${2:-${LOG_ANALYTICS_WORKSPACE_ID:-}}"
WORKBOOK_DISPLAY_NAME="${WORKBOOK_DISPLAY_NAME:-AI Security Sandbox - SOC Workbook}"
WORKBOOK_ID="${WORKBOOK_ID:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKBOOK_DEFINITION_PATH="${WORKBOOK_DEFINITION_PATH:-$SCRIPT_DIR/../infra/workbooks/soc-workbook.json}"

if [ -z "$RESOURCE_GROUP" ]; then
  echo "Resource group is required. Pass as arg1 or set AZURE_RESOURCE_GROUP." >&2
  exit 1
fi

if [ ! -f "$WORKBOOK_DEFINITION_PATH" ]; then
  echo "Workbook definition file not found: $WORKBOOK_DEFINITION_PATH" >&2
  exit 1
fi

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
export WORKBOOK_DEFINITION_PATH
python3 - <<'PY' > "$PAYLOAD_FILE"
import json
import os

workspace = os.environ["WORKSPACE_RESOURCE_ID"]
location = os.environ["LOCATION"]
display_name = os.environ["WORKBOOK_DISPLAY_NAME"]
definition_path = os.environ["WORKBOOK_DEFINITION_PATH"]

with open(definition_path, "r", encoding="utf-8") as f:
    raw = f.read()

# Substitute the workspace placeholder, then validate the result is JSON.
raw = raw.replace("__WORKSPACE_RESOURCE_ID__", workspace)
serialized = json.loads(raw)

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
