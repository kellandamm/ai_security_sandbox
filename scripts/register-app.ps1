# register-app.ps1 — Create (or reuse) an Entra ID App Registration for the
# AI Security Sandbox. The same app registration serves as the SPA client,
# the App Service auth client, and the API audience that APIM validates.
#
# Usage:
#   pwsh scripts/register-app.ps1
#   azd env set AAD_CLIENT_ID <output client-id>
#
# Prerequisites: az login

param(
    [string]$AppDisplayName = "AI Security Sandbox",
    [string]$FrontendUrl    = $env:FRONTEND_URL
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Preflight ────────────────────────────────────────────────────────────────
$account = az account show 2>$null
if (-not $account) {
    Write-Error "Not logged in. Run 'az login' first."
    exit 1
}

$tenantId = az account show --query tenantId -o tsv

# ── Create or reuse app registration ─────────────────────────────────────────
$appId = az ad app list --display-name $AppDisplayName --query "[0].appId" -o tsv 2>$null

if (-not $appId) {
    $appId = az ad app create --display-name $AppDisplayName --sign-in-audience AzureADMyOrg --query appId -o tsv
    Write-Host "Created app registration: $appId"
} else {
    Write-Host "Reusing existing app registration: $appId"
}

$objectId = az ad app show --id $appId --query id -o tsv

# ── Set identifier URI (api://{clientId}) ─────────────────────────────────────
az ad app update --id $appId --identifier-uris "api://$appId"
Write-Host "Set identifierUri: api://$appId"

# ── Expose an API scope: access_as_user ───────────────────────────────────────
$scopeId = [guid]::NewGuid().ToString()
$apiBody = @{
    api = @{
        requestedAccessTokenVersion = 2
        oauth2PermissionScopes = @(
            @{
                id                      = $scopeId
                adminConsentDisplayName = "Access AI Security Sandbox"
                adminConsentDescription = "Allow the application to access the AI Security Sandbox API on behalf of the signed-in user."
                userConsentDisplayName  = "Access AI Security Sandbox"
                userConsentDescription  = "Allow the application to access the AI Security Sandbox API on your behalf."
                isEnabled               = $true
                type                    = "User"
                value                   = "access_as_user"
            }
        )
    }
} | ConvertTo-Json -Depth 10 -Compress

# Write JSON to a BOM-free temp file
$tempFile = [System.IO.Path]::GetTempFileName() + ".json"
[System.IO.File]::WriteAllText($tempFile, $apiBody, [System.Text.UTF8Encoding]::new($false))

az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/applications/$objectId" `
    --body "@$tempFile" `
    --headers "Content-Type=application/json"

Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
Write-Host "Exposed API scope: api://$appId/access_as_user"

# ── Add SPA platform with redirect URIs ───────────────────────────────────────
$redirectUris = @("http://localhost:3000")
if ($FrontendUrl) {
    $redirectUris += $FrontendUrl
}

$spaBody = @{
    spa = @{
        redirectUris = $redirectUris
    }
} | ConvertTo-Json -Depth 5 -Compress

$tempFile2 = [System.IO.Path]::GetTempFileName() + ".json"
[System.IO.File]::WriteAllText($tempFile2, $spaBody, [System.Text.UTF8Encoding]::new($false))

az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/applications/$objectId" `
    --body "@$tempFile2" `
    --headers "Content-Type=application/json"

Remove-Item $tempFile2 -Force -ErrorAction SilentlyContinue
Write-Host "Configured SPA redirect URIs: $($redirectUris -join ', ')"

# ── Add Web platform callback for App Service authentication ─────────────────
if ($FrontendUrl) {
    $webRedirectUri = "$FrontendUrl/.auth/login/aad/callback"
    $webBody = @{
        web = @{
            redirectUris = @($webRedirectUri)
            implicitGrantSettings = @{
                enableAccessTokenIssuance = $false
                enableIdTokenIssuance = $true
            }
        }
    } | ConvertTo-Json -Depth 8 -Compress

    $tempFileWeb = [System.IO.Path]::GetTempFileName() + ".json"
    [System.IO.File]::WriteAllText($tempFileWeb, $webBody, [System.Text.UTF8Encoding]::new($false))

    az rest --method PATCH `
        --uri "https://graph.microsoft.com/v1.0/applications/$objectId" `
        --body "@$tempFileWeb" `
        --headers "Content-Type=application/json"

    Remove-Item $tempFileWeb -Force -ErrorAction SilentlyContinue
    Write-Host "Configured Web redirect URI: $webRedirectUri"
}

# ── Pre-authorize the SPA to skip user consent for its own scope ──────────────
$preAuthBody = @{
    api = @{
        preAuthorizedApplications = @(
            @{
                appId               = $appId
                delegatedPermissionIds = @($scopeId)
            }
        )
    }
} | ConvertTo-Json -Depth 5 -Compress

$tempFile3 = [System.IO.Path]::GetTempFileName() + ".json"
[System.IO.File]::WriteAllText($tempFile3, $preAuthBody, [System.Text.UTF8Encoding]::new($false))

az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/applications/$objectId" `
    --body "@$tempFile3" `
    --headers "Content-Type=application/json"

Remove-Item $tempFile3 -Force -ErrorAction SilentlyContinue
Write-Host "Pre-authorized SPA for scope (no consent prompt)"

# ── Create service principal if it doesn't exist ──────────────────────────────
$spId = az ad sp show --id $appId --query id -o tsv 2>$null
if (-not $spId) {
    $spId = az ad sp create --id $appId --query id -o tsv
    Write-Host "Created service principal: $spId"
}

# ── Output ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================"
Write-Host " App Registration Complete"
Write-Host "================================================================"
Write-Host ""
Write-Host "  Client ID  : $appId"
Write-Host "  Tenant ID  : $tenantId"
Write-Host "  API Scope  : api://$appId/access_as_user"
Write-Host ""
Write-Host " Next steps:"
Write-Host "   azd env set AAD_CLIENT_ID $appId"
Write-Host "   azd up"
Write-Host ""
Write-Host " If the frontend URL changes, update the redirect URI:"
Write-Host "   az ad app update --id $appId --public-client-redirect-uris <new-url>"
Write-Host "================================================================"
