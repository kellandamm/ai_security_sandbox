param(
    [Parameter(Mandatory = $true)]
    [string]$FrontendUrl,

    [Parameter(Mandatory = $true)]
    [string]$WebAppName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory = $true)]
    [string]$SpaClientId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $SpaClientId) {
    throw 'SpaClientId is required.'
}

if (-not (az account show 2>$null)) {
    throw "Not logged in. Run 'az login' first."
}

$tenantId = az account show --query tenantId -o tsv
$subscriptionId = az account show --query id -o tsv
$objectId = az ad app show --id $SpaClientId --query id -o tsv

$currentRegistration = az rest --method GET --uri "https://graph.microsoft.com/v1.0/applications/${objectId}?%24select=spa,web" | ConvertFrom-Json

$spaRedirectUris = @('http://localhost:3000')
if ($currentRegistration.spa.redirectUris) {
    $spaRedirectUris += $currentRegistration.spa.redirectUris
}
$spaRedirectUris += $FrontendUrl
$spaRedirectUris = $spaRedirectUris | Where-Object { $_ } | Sort-Object -Unique

$webRedirectUri = "$FrontendUrl/.auth/login/aad/callback"
$webRedirectUris = @()
if ($currentRegistration.web.redirectUris) {
    $webRedirectUris += $currentRegistration.web.redirectUris
}
$webRedirectUris += $webRedirectUri
$webRedirectUris = $webRedirectUris | Where-Object { $_ } | Sort-Object -Unique

$appPatch = @{
    spa = @{
        redirectUris = $spaRedirectUris
    }
    api = @{
        requestedAccessTokenVersion = 2
    }
    web = @{
        redirectUris = $webRedirectUris
        implicitGrantSettings = @{
            enableAccessTokenIssuance = $false
            enableIdTokenIssuance = $true
        }
    }
} | ConvertTo-Json -Depth 10 -Compress

$appPatchFile = [System.IO.Path]::GetTempFileName() + '.json'
[System.IO.File]::WriteAllText($appPatchFile, $appPatch, [System.Text.UTF8Encoding]::new($false))

az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/applications/${objectId}" `
    --body "@$appPatchFile" `
    --headers "Content-Type=application/json" | Out-Null

Remove-Item $appPatchFile -Force -ErrorAction SilentlyContinue

$existingSecret = az webapp config appsettings list --resource-group $ResourceGroup --name $WebAppName --query "[?name=='MICROSOFT_PROVIDER_AUTHENTICATION_SECRET'].value | [0]" -o tsv 2>$null

if (-not $existingSecret) {
    $clientSecret = az ad app credential reset --id $SpaClientId --append --display-name 'app-service-auth' --years 2 --query password -o tsv
    az webapp config appsettings set --resource-group $ResourceGroup --name $WebAppName --settings MICROSOFT_PROVIDER_AUTHENTICATION_SECRET=$clientSecret | Out-Null
}

$authBody = @{
    properties = @{
        platform = @{
            enabled = $true
            runtimeVersion = '~1'
        }
        globalValidation = @{
            requireAuthentication = $true
            unauthenticatedClientAction = 'RedirectToLoginPage'
            redirectToProvider = 'azureActiveDirectory'
        }
        httpSettings = @{
            requireHttps = $true
            routes = @{
                apiPrefix = '/.auth'
            }
            forwardProxy = @{
                convention = 'NoProxy'
            }
        }
        login = @{
            tokenStore = @{
                enabled = $true
            }
        }
        identityProviders = @{
            azureActiveDirectory = @{
                enabled = $true
                registration = @{
                    clientId = $SpaClientId
                    clientSecretSettingName = 'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET'
                    openIdIssuer = "https://login.microsoftonline.com/$tenantId/v2.0"
                }
            }
        }
    }
} | ConvertTo-Json -Depth 10

$authBodyFile = [System.IO.Path]::GetTempFileName() + '.json'
[System.IO.File]::WriteAllText($authBodyFile, $authBody, [System.Text.UTF8Encoding]::new($false))

az rest --method PUT `
    --uri "https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${ResourceGroup}/providers/Microsoft.Web/sites/${WebAppName}/config/authsettingsV2?api-version=2022-09-01" `
    --body "@$authBodyFile" `
    --headers "Content-Type=application/json" | Out-Null

Remove-Item $authBodyFile -Force -ErrorAction SilentlyContinue

Write-Host "Configured App Service auth for $WebAppName"