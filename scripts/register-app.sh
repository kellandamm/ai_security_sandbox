#!/usr/bin/env bash
# register-app.sh — Create (or reuse) an Entra ID App Registration for the
# AI Security Sandbox. The same app registration serves as the SPA client,
# the App Service auth client, and the API audience that APIM validates.
#
# Usage:
#   bash scripts/register-app.sh
#   azd env set AAD_CLIENT_ID <output client-id>
#
# Prerequisites: az login

set -euo pipefail

APP_DISPLAY_NAME="${APP_DISPLAY_NAME:-AI Security Sandbox}"
FRONTEND_URL="${FRONTEND_URL:-}"

# ── Preflight ────────────────────────────────────────────────────────────────
if ! az account show &>/dev/null; then
  echo "ERROR: Not logged in. Run 'az login' first." >&2
  exit 1
fi

TENANT_ID=$(az account show --query tenantId -o tsv)

# ── Create or reuse app registration ─────────────────────────────────────────
APP_ID=$(az ad app list --display-name "$APP_DISPLAY_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo "")

if [[ -z "$APP_ID" ]]; then
  APP_ID=$(az ad app create --display-name "$APP_DISPLAY_NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv)
  echo "Created app registration: $APP_ID"
else
  echo "Reusing existing app registration: $APP_ID"
fi

OBJECT_ID=$(az ad app show --id "$APP_ID" --query id -o tsv)

# ── Set identifier URI (api://{clientId}) ─────────────────────────────────────
az ad app update --id "$APP_ID" --identifier-uris "api://$APP_ID"
echo "Set identifierUri: api://$APP_ID"

# ── Expose an API scope: access_as_user ───────────────────────────────────────
SCOPE_ID=$(python3 -c "import uuid; print(str(uuid.uuid4()))")

cat > /tmp/api-scope.json <<SCOPEJSON
{
  "api": {
    "requestedAccessTokenVersion": 2,
    "oauth2PermissionScopes": [
      {
        "id": "$SCOPE_ID",
        "adminConsentDisplayName": "Access AI Security Sandbox",
        "adminConsentDescription": "Allow the application to access the AI Security Sandbox API on behalf of the signed-in user.",
        "userConsentDisplayName": "Access AI Security Sandbox",
        "userConsentDescription": "Allow the application to access the AI Security Sandbox API on your behalf.",
        "isEnabled": true,
        "type": "User",
        "value": "access_as_user"
      }
    ]
  }
}
SCOPEJSON

az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications/$OBJECT_ID" \
  --body @/tmp/api-scope.json \
  --headers "Content-Type=application/json"

echo "Exposed API scope: api://$APP_ID/access_as_user"

# ── Add SPA platform with redirect URIs ───────────────────────────────────────
REDIRECT_URIS='["http://localhost:3000"'
if [[ -n "$FRONTEND_URL" ]]; then
  REDIRECT_URIS="$REDIRECT_URIS, \"$FRONTEND_URL\""
fi
REDIRECT_URIS="$REDIRECT_URIS]"

cat > /tmp/spa-platform.json <<SPAJSON
{
  "spa": {
    "redirectUris": $REDIRECT_URIS
  }
}
SPAJSON

az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications/$OBJECT_ID" \
  --body @/tmp/spa-platform.json \
  --headers "Content-Type=application/json"

echo "Configured SPA redirect URIs: $REDIRECT_URIS"

# ── Add Web platform callback for App Service authentication ─────────────────
if [[ -n "$FRONTEND_URL" ]]; then
  cat > /tmp/web-platform.json <<WEBJSON
{
  "web": {
    "redirectUris": ["$FRONTEND_URL/.auth/login/aad/callback"],
    "implicitGrantSettings": {
      "enableAccessTokenIssuance": false,
      "enableIdTokenIssuance": true
    }
  }
}
WEBJSON

  az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/applications/$OBJECT_ID" \
    --body @/tmp/web-platform.json \
    --headers "Content-Type=application/json"

  echo "Configured Web redirect URI: $FRONTEND_URL/.auth/login/aad/callback"
fi

# ── Pre-authorize the SPA to skip user consent ───────────────────────────────
cat > /tmp/pre-auth.json <<PREAUTHJSON
{
  "api": {
    "preAuthorizedApplications": [
      {
        "appId": "$APP_ID",
        "delegatedPermissionIds": ["$SCOPE_ID"]
      }
    ]
  }
}
PREAUTHJSON

az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications/$OBJECT_ID" \
  --body @/tmp/pre-auth.json \
  --headers "Content-Type=application/json"

echo "Pre-authorized SPA for scope (no consent prompt)"

# ── Create service principal if it doesn't exist ──────────────────────────────
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv 2>/dev/null || echo "")
if [[ -z "$SP_ID" ]]; then
  SP_ID=$(az ad sp create --id "$APP_ID" --query id -o tsv)
  echo "Created service principal: $SP_ID"
fi

# ── Cleanup temp files ────────────────────────────────────────────────────────
rm -f /tmp/api-scope.json /tmp/spa-platform.json /tmp/web-platform.json /tmp/pre-auth.json

# ── Output ────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo " App Registration Complete"
echo "================================================================"
echo ""
echo "  Client ID  : $APP_ID"
echo "  Tenant ID  : $TENANT_ID"
echo "  API Scope  : api://$APP_ID/access_as_user"
echo ""
echo " Next steps:"
echo "   azd env set AAD_CLIENT_ID $APP_ID"
echo "   azd up"
echo ""
echo "================================================================"
