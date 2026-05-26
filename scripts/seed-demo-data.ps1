<#
.SYNOPSIS
    Wrapper for scripts/seed_demo_data.py — seeds the AI Security Sandbox
    with realistic demo data (benign baseline + curated attacks + admin
    actions + Phase 1-7 controls).

.DESCRIPTION
    Thin wrapper around the Python implementation. Real logic lives in
    scripts/seed_demo_data.py; the scenario catalog lives in
    scripts/seed-scenarios.json. Edit the JSON to tune scenarios.

    Three modes:
      runs    Fire real /sandbox/runs through APIM (exercises full pipeline).
      direct  POST synthetic AuditEvent rows to the Log Analytics DCE.
      both    Direct-seed history, then fire a small live wave.

.EXAMPLE
    # Fast history backfill for the workbook
    ./scripts/seed-demo-data.ps1 -Mode direct `
        -DceLogs https://<your-dce>.<region>.ingest.monitor.azure.com `
        -DcrImmutableId dcr-<immutable-id>

.EXAMPLE
    # Real APIM runs to drive SSE + anomaly state
    ./scripts/seed-demo-data.ps1 -Mode runs `
        -ApimUrl https://apim-xxx.azure-api.net `
        -AadClientId 11111111-2222-3333-4444-555555555555 `
        -BenignRuns 8 -AttackRuns 4

.EXAMPLE
    # Full setup: backfill + live wave + 30-minute drip
    ./scripts/seed-demo-data.ps1 -Mode both `
        -ApimUrl https://apim-xxx.azure-api.net `
        -AadClientId 11111111-2222-3333-4444-555555555555 `
        -DceLogs https://<your-dce>.<region>.ingest.monitor.azure.com `
        -DcrImmutableId dcr-<immutable-id> `
        -LoopMinutes 30
#>
param(
    [ValidateSet('runs','direct','both')][string]$Mode = 'direct',
    [string]$ApimUrl,
    [string]$AadClientId,
    [string]$ApimSubscriptionKey,
    [string]$DceLogs,
    [string]$DcrImmutableId,
    [string]$Stream = 'Custom-AiAgentAudit_CL',
    [int]$BenignRuns = 10000,
    [int]$AttackRuns = 2500,
    [int]$BenignEvents = 9000,
    [int]$AttackEvents = 950,
    [double]$BackfillHours = 365,
    [int]$Parallel = 5,
    [int]$LoopMinutes = 1,
    [int]$LoopIntervalSeconds = 30,
    [int]$LoopWaveSize = 2,
    [string]$UploadSample,
    [switch]$DryRun,
    [switch]$Reset,
    [Nullable[int]]$Seed,
    [string]$ScenariosPath
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PyScript = Join-Path $ScriptDir 'seed_demo_data.py'

if (-not (Test-Path $PyScript)) {
    throw "seed_demo_data.py not found at $PyScript"
}

$pythonExe = $null
foreach ($candidate in @('python', 'python3', 'py')) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) { $pythonExe = $candidate; break }
}
if (-not $pythonExe) {
    throw "Python 3 not found on PATH. Install Python 3.10+ and retry."
}

$argList = @($PyScript, '--mode', $Mode)
if ($ApimUrl)             { $argList += @('--apim-url', $ApimUrl) }
if ($AadClientId)         { $argList += @('--aad-client-id', $AadClientId) }
if ($ApimSubscriptionKey) { $argList += @('--apim-subscription-key', $ApimSubscriptionKey) }
if ($DceLogs)             { $argList += @('--dce-logs', $DceLogs) }
if ($DcrImmutableId)      { $argList += @('--dcr-immutable-id', $DcrImmutableId) }
if ($Stream)              { $argList += @('--stream', $Stream) }
$argList += @('--benign-runs', $BenignRuns, '--attack-runs', $AttackRuns)
$argList += @('--benign-events', $BenignEvents, '--attack-events', $AttackEvents)
$argList += @('--backfill-hours', $BackfillHours, '--parallel', $Parallel)
$argList += @('--loop-minutes', $LoopMinutes, '--loop-interval-seconds', $LoopIntervalSeconds, '--loop-wave-size', $LoopWaveSize)
if ($UploadSample)   { $argList += @('--upload-sample', $UploadSample) }
if ($DryRun)         { $argList += '--dry-run' }
if ($Reset)          { $argList += '--reset' }
if ($PSBoundParameters.ContainsKey('Seed') -and $null -ne $Seed) { $argList += @('--seed', $Seed) }
if ($ScenariosPath)  { $argList += @('--scenarios-path', $ScenariosPath) }

Write-Host "==> $pythonExe $($argList -join ' ')" -ForegroundColor Cyan
& $pythonExe @argList
exit $LASTEXITCODE
