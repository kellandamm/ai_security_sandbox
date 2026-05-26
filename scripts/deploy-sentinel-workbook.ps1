param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [string]$WorkspaceResourceId,

    [string]$WorkbookDisplayName = "AI Security Sandbox - SOC Workbook",

    [string]$WorkbookId,

    [string]$Location,

    [string]$WorkbookDefinitionPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $WorkbookDefinitionPath) {
    $WorkbookDefinitionPath = Join-Path $PSScriptRoot "..\infra\workbooks\soc-workbook.json"
}

if (-not (Test-Path $WorkbookDefinitionPath)) {
    throw "Workbook definition file not found: $WorkbookDefinitionPath"
}

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

# Read the shared definition and substitute the workspace placeholder.
# The definition keeps `__WORKSPACE_RESOURCE_ID__` everywhere a crossComponentResources / fallback id is needed.
$definitionText = Get-Content -Path $WorkbookDefinitionPath -Raw
$definitionText = $definitionText.Replace('__WORKSPACE_RESOURCE_ID__', $WorkspaceResourceId)

# Validate it round-trips as JSON before we send it.
$null = $definitionText | ConvertFrom-Json

$payload = @{
    kind = "shared"
    location = $Location
    properties = @{
        displayName = $WorkbookDisplayName
        sourceId = $WorkspaceResourceId
        category = "sentinel"
        serializedData = $definitionText
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
