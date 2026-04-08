#!/usr/bin/env bash
# bootstrap.sh — One-shot setup for the AI Security Sandbox
#
# Run this ONCE before deploying via Bicep or GitHub Actions.
# It creates the resource group (the Bicep deployment expects it at
# subscription scope so this is optional), configures OIDC for GitHub
# Actions, and assigns the minimum roles needed for deployment.
#
# Usage:
#   export AZURE_SUBSCRIPTION_ID="<your-sub-id>"
#   export GITHUB_ORG="kellandamm"
#   export GITHUB_REPO="ai_security_sandbox"
#   export ENVIRONMENT="dev"
#   bash scripts/bootstrap.sh

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:?Set AZURE_SUBSCRIPTION_ID}"
GITHUB_ORG="${GITHUB_ORG:?Set GITHUB_ORG}"
GITHUB_REPO="${GITHUB_REPO:?Set GITHUB_REPO}"
ENVIRONMENT="${ENVIRONMENT:-dev}"
LOCATION="${LOCATION:-eastus}"
APP_NAME="ai-sandbox-deploy-${ENVIRONMENT}"

echo "==> Bootstrapping AI Security Sandbox"
echo "    Subscription : $SUBSCRIPTION_ID"
echo "    Environment  : $ENVIRONMENT"
echo "    Location     : $LOCATION"
echo "    GitHub       : ${GITHUB_ORG}/${GITHUB_REPO}"
echo ""

# ── Login check ───────────────────────────────────────────────────────────────
if ! az account show &>/dev/null; then
  echo "ERROR: Not logged in. Run 'az login' first."
  exit 1
fi

az account set --subscription "$SUBSCRIPTION_ID"
echo "==> Using subscription: $(az account show --query name -o tsv)"

# ── Create Entra ID app registration for GitHub Actions OIDC ─────────────────
echo ""
echo "==> Creating Entra ID app registration for GitHub Actions OIDC..."

APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo "")

if [[ -z "$APP_ID" ]]; then
  APP_ID=$(az ad app create --display-name "$APP_NAME" --query appId -o tsv)
  echo "    Created app: $APP_ID"
else
  echo "    App already exists: $APP_ID"
fi

# Create service principal if it doesn't exist
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv 2>/dev/null || echo "")
if [[ -z "$SP_ID" ]]; then
  SP_ID=$(az ad sp create --id "$APP_ID" --query id -o tsv)
  echo "    Created service principal: $SP_ID"
fi

# ── Federated credentials for GitHub Actions (OIDC — no stored secrets) ──────
echo ""
echo "==> Configuring federated identity credentials (OIDC)..."

CRED_NAME="github-${GITHUB_ORG}-${GITHUB_REPO}-main"
EXISTING_CRED=$(az ad app federated-credential list --id "$APP_ID" \
  --query "[?name=='${CRED_NAME}'].name" -o tsv 2>/dev/null || echo "")

if [[ -z "$EXISTING_CRED" ]]; then
  az ad app federated-credential create --id "$APP_ID" --parameters "{
    \"name\": \"${CRED_NAME}\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"repo:${GITHUB_ORG}/${GITHUB_REPO}:ref:refs/heads/main\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" > /dev/null
  echo "    Created federated credential for main branch"
fi

# Also allow workflow_dispatch from any branch
CRED_NAME_WD="github-${GITHUB_ORG}-${GITHUB_REPO}-dispatch"
EXISTING_WD=$(az ad app federated-credential list --id "$APP_ID" \
  --query "[?name=='${CRED_NAME_WD}'].name" -o tsv 2>/dev/null || echo "")

if [[ -z "$EXISTING_WD" ]]; then
  az ad app federated-credential create --id "$APP_ID" --parameters "{
    \"name\": \"${CRED_NAME_WD}\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"repo:${GITHUB_ORG}/${GITHUB_REPO}:environment:${ENVIRONMENT}\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" > /dev/null
  echo "    Created federated credential for '${ENVIRONMENT}' environment"
fi

# ── Assign minimum RBAC roles for Bicep deployment ───────────────────────────
echo ""
echo "==> Assigning RBAC roles for deployment identity..."

# Contributor at subscription scope (needed for resource group + resources)
az role assignment create \
  --assignee "$APP_ID" \
  --role "Contributor" \
  --scope "/subscriptions/$SUBSCRIPTION_ID" \
  --condition-type "None" \
  2>/dev/null || echo "    Contributor role already assigned"

# User Access Administrator (needed to create role assignments in Bicep)
az role assignment create \
  --assignee "$APP_ID" \
  --role "User Access Administrator" \
  --scope "/subscriptions/$SUBSCRIPTION_ID" \
  2>/dev/null || echo "    User Access Administrator role already assigned"

# ── Output GitHub Actions secrets to configure ────────────────────────────────
TENANT_ID=$(az account show --query tenantId -o tsv)

echo ""
echo "================================================================"
echo " Set these as GitHub Actions secrets in your repository:"
echo " Settings → Secrets and variables → Actions → New repository secret"
echo "================================================================"
echo ""
echo "  AZURE_CLIENT_ID       = $APP_ID"
echo "  AZURE_TENANT_ID       = $TENANT_ID"
echo "  AZURE_SUBSCRIPTION_ID = $SUBSCRIPTION_ID"
echo "  APPROVER_EMAIL        = <security-team-email@yourorg.com>"
echo ""
echo "================================================================"
echo " Also configure GitHub Actions environment '${ENVIRONMENT}':"
echo " Settings → Environments → New environment → ${ENVIRONMENT}"
echo " Add the same secrets there too for environment-scoped OIDC."
echo "================================================================"
echo ""
echo "==> Bootstrap complete. Next step:"
echo "    git push origin main   (triggers the deploy workflow)"
echo ""
