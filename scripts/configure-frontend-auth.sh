#!/usr/bin/env bash
set -euo pipefail

FRONTEND_URL="${1:-${FRONTEND_URL:-}}"
WEBAPP_NAME="${2:-${FRONTEND_WEBAPP_NAME:-}}"
RESOURCE_GROUP="${3:-${AZURE_RESOURCE_GROUP:-}}"
SPA_CLIENT_ID="${4:-${AAD_CLIENT_ID:-}}"

if [[ -z "$FRONTEND_URL" || -z "$WEBAPP_NAME" || -z "$RESOURCE_GROUP" || -z "$SPA_CLIENT_ID" ]]; then
  echo "Usage: configure-frontend-auth.sh <frontend-url> <webapp-name> <resource-group> <spa-client-id>" >&2
  exit 1
fi

if ! az account show &>/dev/null; then
  echo "ERROR: Not logged in. Run 'az login' first." >&2
  exit 1
fi

TENANT_ID=$(az account show --query tenantId -o tsv)
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
OBJECT_ID=$(az ad app show --id "$SPA_CLIENT_ID" --query id -o tsv)

python3 - <<'PY' "$OBJECT_ID" "$FRONTEND_URL"
import json
import subprocess
import sys

object_id = sys.argv[1]
frontend_url = sys.argv[2]
result = subprocess.check_output([
    "az", "rest", "--method", "GET",
    "--uri", f"https://graph.microsoft.com/v1.0/applications/{object_id}?$select=spa,web",
], text=True)
registration = json.loads(result)
spa_redirects = sorted({"http://localhost:3000", frontend_url, *registration.get("spa", {}).get("redirectUris", [])})
web_redirects = sorted({f"{frontend_url}/.auth/login/aad/callback", *registration.get("web", {}).get("redirectUris", [])})
payload = {
    "spa": {"redirectUris": spa_redirects},
    "web": {
        "redirectUris": web_redirects,
        "implicitGrantSettings": {
            "enableAccessTokenIssuance": False,
            "enableIdTokenIssuance": True,
        },
    },
}
with open("/tmp/frontend-auth-app.json", "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
PY

az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications/$OBJECT_ID" \
  --body @/tmp/frontend-auth-app.json \
  --headers "Content-Type=application/json" >/dev/null

EXISTING_SECRET=$(az webapp config appsettings list \
  --resource-group "$RESOURCE_GROUP" \
  --name "$WEBAPP_NAME" \
  --query "[?name=='MICROSOFT_PROVIDER_AUTHENTICATION_SECRET'].value | [0]" \
  -o tsv 2>/dev/null || true)

if [[ -z "$EXISTING_SECRET" ]]; then
  CLIENT_SECRET=$(az ad app credential reset --id "$SPA_CLIENT_ID" --append --display-name app-service-auth --years 2 --query password -o tsv)
  az webapp config appsettings set \
    --resource-group "$RESOURCE_GROUP" \
    --name "$WEBAPP_NAME" \
    --settings MICROSOFT_PROVIDER_AUTHENTICATION_SECRET="$CLIENT_SECRET" >/dev/null
fi

python3 - <<'PY' "$TENANT_ID" "$SPA_CLIENT_ID"
import json
import sys

tenant_id = sys.argv[1]
client_id = sys.argv[2]
payload = {
    "properties": {
        "platform": {"enabled": True, "runtimeVersion": "~1"},
        "globalValidation": {
            "requireAuthentication": True,
            "unauthenticatedClientAction": "RedirectToLoginPage",
            "redirectToProvider": "azureActiveDirectory",
        },
        "httpSettings": {
            "requireHttps": True,
            "routes": {"apiPrefix": "/.auth"},
            "forwardProxy": {"convention": "NoProxy"},
        },
        "login": {"tokenStore": {"enabled": True}},
        "identityProviders": {
            "azureActiveDirectory": {
                "enabled": True,
                "registration": {
                    "clientId": client_id,
                    "clientSecretSettingName": "MICROSOFT_PROVIDER_AUTHENTICATION_SECRET",
                    "openIdIssuer": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
                },
            }
        },
    }
}
with open("/tmp/frontend-authsettings.json", "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
PY

az rest --method PUT \
  --uri "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Web/sites/$WEBAPP_NAME/config/authsettingsV2?api-version=2022-09-01" \
  --body @/tmp/frontend-authsettings.json \
  --headers "Content-Type=application/json" >/dev/null

rm -f /tmp/frontend-auth-app.json /tmp/frontend-authsettings.json
echo "Configured App Service auth for $WEBAPP_NAME"