# set-deployer-principal-id.ps1
# Resolves the current Azure login to a Microsoft Entra object ID and stores it
# in the azd environment as AZURE_PRINCIPAL_ID so Bicep can grant frontend blob
# data-plane access during provisioning.

$userType = az account show --query user.type -o tsv
if ($LASTEXITCODE -ne 0 -or -not $userType) {
    Write-Error "Unable to determine the current Azure account type."
    exit 1
}

$principalId = ""

if ($userType -eq "user") {
    $principalId = az ad signed-in-user show --query id -o tsv
} else {
    $clientId = az account show --query user.name -o tsv
    if ($LASTEXITCODE -ne 0 -or -not $clientId) {
        Write-Error "Unable to determine the service principal client ID."
        exit 1
    }

    $principalId = az ad sp show --id $clientId --query id -o tsv
}

if ($LASTEXITCODE -ne 0 -or -not $principalId) {
    Write-Error "Unable to resolve the Microsoft Entra principal object ID for the current Azure login."
    exit 1
}

azd env set AZURE_PRINCIPAL_ID $principalId
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to persist AZURE_PRINCIPAL_ID in the azd environment."
    exit 1
}

Write-Host "Stored AZURE_PRINCIPAL_ID=$principalId in the azd environment."
