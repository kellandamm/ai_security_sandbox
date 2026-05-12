[CmdletBinding()]
param(
    [switch]$InstallPythonDeps,
    [switch]$InstallFrontendDeps,
    [switch]$Strict,
    [switch]$SkipPython,
    [switch]$SkipRuff,
    [switch]$SkipOpa,
    [switch]$SkipBicep,
    [switch]$SkipFrontend,
    [switch]$SkipDocker,
    [string]$PythonCommand = "python"
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$failures = New-Object System.Collections.Generic.List[string]
$skips = New-Object System.Collections.Generic.List[string]

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Test-CommandExists {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @()
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with code $LASTEXITCODE"
    }
}

function Get-PythonVersion {
    param([string]$Command)

    $version = & $Command -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    if ($LASTEXITCODE -ne 0) {
        throw "$Command exited with code $LASTEXITCODE while checking Python version"
    }

    return [version]$version
}

function Test-PythonModule {
    param(
        [string]$Command,
        [string]$Module
    )

    & $Command -m $Module --version *> $null
    return $LASTEXITCODE -eq 0
}

function Add-Skip {
    param([string]$Message)
    $skips.Add($Message) | Out-Null
    Write-Warning $Message
    if ($Strict) {
        throw $Message
    }
}

function Invoke-Check {
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock
    )

    Write-Step $Name
    try {
        & $ScriptBlock
        Write-Host "PASS: $Name" -ForegroundColor Green
    }
    catch {
        $failures.Add("${Name}: $($_.Exception.Message)") | Out-Null
        Write-Host "FAIL: $Name" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

Push-Location $repoRoot
try {
    if (-not $SkipPython) {
        if (-not (Test-CommandExists $PythonCommand)) {
            Add-Skip "$PythonCommand was not found on PATH; skipping Python unit tests."
        }
        else {
            $pythonVersion = Get-PythonVersion $PythonCommand
            if ($pythonVersion.Major -ne 3 -or $pythonVersion.Minor -lt 10 -or $pythonVersion.Minor -gt 13) {
                $message = "Unsupported Python version $pythonVersion. Use Python 3.12 for this accelerator; Python 3.14 is not supported by the pinned pydantic-core dependency."
                $failures.Add("Python version: $message") | Out-Null
                Write-Host "FAIL: Python version" -ForegroundColor Red
                Write-Host $message -ForegroundColor Red
            }
            else {
            if ($InstallPythonDeps) {
                Invoke-Check "Install Python test dependencies" {
                    Invoke-Native $PythonCommand @("-m", "pip", "install", "-r", "app/requirements.txt", "pytest", "pytest-asyncio", "ruff")
                }
            }

            Invoke-Check "Python unit tests" {
                $env:APP_CONFIG_ENDPOINT = ""
                $env:WORKSPACE_STORAGE_ACCOUNT = ""
                $env:AUDIT_STORAGE_ACCOUNT = ""
                $env:AZURE_OPENAI_ENDPOINT = ""
                $env:DCE_ENDPOINT = ""
                $env:DCR_IMMUTABLE_ID = ""
                Invoke-Native $PythonCommand @("-m", "pytest", "tests/unit/", "-v", "--tb=short")
            }
            }
        }
    }

    if (-not $SkipRuff) {
        if (Test-CommandExists "ruff") {
            Invoke-Check "Python lint" {
                Invoke-Native "ruff" @("check", "app", "tests", "--select", "E,W,F,I")
            }
        }
        elseif ((Test-CommandExists $PythonCommand) -and (Test-PythonModule $PythonCommand "ruff")) {
            Invoke-Check "Python lint" {
                Invoke-Native $PythonCommand @("-m", "ruff", "check", "app", "tests", "--select", "E,W,F,I")
            }
        }
        else {
            Add-Skip "ruff was not found on PATH; run with -InstallPythonDeps or install ruff to enable linting."
        }
    }

    if (-not $SkipOpa) {
        if (Test-CommandExists "opa") {
            Invoke-Check "OPA policy validation" {
                Invoke-Native "opa" @("check", "policies/")
                Invoke-Native "opa" @("test", "policies/", "-v")
            }
        }
        else {
            Add-Skip "OPA was not found on PATH; install opa or run with -SkipOpa."
        }
    }

    if (-not $SkipBicep) {
        if (Test-CommandExists "bicep") {
            Invoke-Check "Bicep lint" {
                Invoke-Native "bicep" @("lint", "infra/main.bicep")
                Get-ChildItem infra/modules/*.bicep | ForEach-Object {
                    Invoke-Native "bicep" @("lint", $_.FullName)
                }
            }
        }
        else {
            Add-Skip "Bicep CLI was not found on PATH; install bicep or run with -SkipBicep."
        }
    }

    if (-not $SkipFrontend) {
        if (Test-CommandExists "npm") {
            if ($InstallFrontendDeps) {
                Invoke-Check "Install frontend dependencies" {
                    Push-Location frontend
                    try {
                        Invoke-Native "npm" @("install")
                    }
                    finally {
                        Pop-Location
                    }
                }
            }

            Invoke-Check "Frontend lint and build" {
                Push-Location frontend
                try {
                    Invoke-Native "npm" @("run", "lint")
                    Invoke-Native "npm" @("run", "build")
                }
                finally {
                    Pop-Location
                }
            }
        }
        else {
            Add-Skip "npm was not found on PATH; install Node.js or run with -SkipFrontend."
        }
    }

    if (-not $SkipDocker) {
        if (Test-CommandExists "docker") {
            Invoke-Check "Docker image build" {
                Invoke-Native "docker" @("build", "app", "--tag", "ai-security-sandbox/orchestrator:local-test")
            }
        }
        else {
            Add-Skip "Docker was not found on PATH; install Docker or run with -SkipDocker."
        }
    }
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "Test summary" -ForegroundColor Cyan
Write-Host "Failures: $($failures.Count)"
Write-Host "Skipped:  $($skips.Count)"

if ($skips.Count -gt 0) {
    Write-Host ""
    Write-Host "Skipped checks:" -ForegroundColor Yellow
    $skips | ForEach-Object { Write-Host "- $_" -ForegroundColor Yellow }
}

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host "Failed checks:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "- $_" -ForegroundColor Red }
    exit 1
}

Write-Host ""
Write-Host "All executed checks passed." -ForegroundColor Green
