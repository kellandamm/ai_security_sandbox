# import-opa-image.ps1
# Builds the custom OPA image (with policies baked in) in ACR, then patches both
# the orchestrator Container App and agent runner job to use the real ACR image
# instead of the placeholder set at provision time.
#
# Why not use Microsoft.Resources/deploymentScripts in Bicep?
# That service always requires key-based storage auth at ARM preflight, which is
# blocked by the tenant's allowSharedKeyAccess: false policy. The postprovision
# hook runs after Bicep completes, so ACR already exists and we can build + patch.
#
# Called automatically by the azd postprovision hook defined in azure.yaml.

param(
    [string]$ResourceGroup      = $env:AZURE_RESOURCE_GROUP,
    [string]$AcrName            = $env:AZURE_CONTAINER_REGISTRY_NAME,
    [string]$JobName            = $env:AGENT_JOB_NAME,
    [string]$OrchestratorName   = $env:ORCHESTRATOR_APP_NAME,
    [string]$OpaImage           = $env:AGENT_JOB_OPA_IMAGE
)

if (-not $ResourceGroup)    { Write-Error "AZURE_RESOURCE_GROUP not set"; exit 1 }
if (-not $AcrName)          { Write-Error "AZURE_CONTAINER_REGISTRY_NAME not set"; exit 1 }
if (-not $JobName)          { Write-Error "AGENT_JOB_NAME not set"; exit 1 }
if (-not $OrchestratorName) { Write-Error "ORCHESTRATOR_APP_NAME not set"; exit 1 }
if (-not $OpaImage) {
    # Fallback: derive from ACR name using same convention as Bicep
    $OpaImage = "$AcrName.azurecr.io/opa:latest-static"
}

# ── Step 1: Build custom OPA image with policies baked in ────────────────────
# az acr build runs remotely on ACR build agents — works even with VNet restrictions.
Write-Host "Building custom OPA image in ACR '$AcrName' ..."
az acr build `
    --registry $AcrName `
    --image opa:latest-static `
    --file opa/Dockerfile `
    .

if ($LASTEXITCODE -ne 0) { Write-Error "az acr build failed"; exit $LASTEXITCODE }
Write-Host "OPA image available at: $OpaImage"

# ── Helper: strip read-only properties from container specs ──────────────────
# ARM GET returns fields like imageType that PATCH rejects as read-only.
$readOnlyProps = @('imageType')
$stripReadOnly = {
    param($containers)
    $containers | ForEach-Object {
        $c = $_
        $readOnlyProps | ForEach-Object { $c.PSObject.Properties.Remove($_) }
        $c
    }
}

# ── Helper: write JSON without BOM ───────────────────────────────────────────
# Windows PowerShell's Set-Content -Encoding utf8 adds a BOM which Azure rejects.
function Write-JsonFile($path, $body) {
    $json = $body | ConvertTo-Json -Depth 20 -Compress
    [System.IO.File]::WriteAllText($path, $json, [System.Text.UTF8Encoding]::new($false))
}

$subscriptionId = az account show --query id -o tsv

# ── Step 2: Patch orchestrator Container App ─────────────────────────────────
Write-Host "Patching orchestrator '$OrchestratorName' with real OPA image ..."

$app = az containerapp show --name $OrchestratorName --resource-group $ResourceGroup `
    | ConvertFrom-Json

$opaContainer = $app.properties.template.containers | Where-Object { $_.name -eq 'opa-sidecar' }
if (-not $opaContainer) {
    Write-Error "opa-sidecar container not found in orchestrator template"
    exit 1
}
$opaContainer.image = $OpaImage
$containers = @(& $stripReadOnly $app.properties.template.containers)

$patchBody = @{
    properties = @{
        template = @{
            containers = $containers
        }
    }
}

$tempFile = [System.IO.Path]::GetTempFileName() + ".json"
Write-JsonFile $tempFile $patchBody

az rest `
    --method PATCH `
    --uri "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$OrchestratorName`?api-version=2024-03-01" `
    --body "@$tempFile" `
    --headers "Content-Type=application/json"

Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
if ($LASTEXITCODE -ne 0) { Write-Error "Orchestrator patch failed"; exit $LASTEXITCODE }
Write-Host "Orchestrator updated successfully -> opa-sidecar: $OpaImage"

# ── Step 3: Patch agent runner job ───────────────────────────────────────────
Write-Host "Patching agent runner job '$JobName' with real OPA image ..."

$job = az containerapp job show --name $JobName --resource-group $ResourceGroup `
    | ConvertFrom-Json

$opaJobContainer = $job.properties.template.containers | Where-Object { $_.name -eq 'opa-sidecar' }
if (-not $opaJobContainer) {
    Write-Error "opa-sidecar container not found in job template"
    exit 1
}
$opaJobContainer.image = $OpaImage
$jobContainers = @(& $stripReadOnly $job.properties.template.containers)

$jobPatchBody = @{
    properties = @{
        template = @{
            containers = $jobContainers
        }
    }
}

$tempFile2 = [System.IO.Path]::GetTempFileName() + ".json"
Write-JsonFile $tempFile2 $jobPatchBody

az rest `
    --method PATCH `
    --uri "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName`?api-version=2024-03-01" `
    --body "@$tempFile2" `
    --headers "Content-Type=application/json"

Remove-Item $tempFile2 -Force -ErrorAction SilentlyContinue
if ($LASTEXITCODE -ne 0) { Write-Error "Job patch failed"; exit $LASTEXITCODE }
Write-Host "Agent runner job updated successfully -> opa-sidecar: $OpaImage"
