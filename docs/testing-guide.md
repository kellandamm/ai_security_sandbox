# Testing Guide

This guide explains how to validate the accelerator locally, in CI, and after deployment.

## Quick Start

Run the local validation script from the repository root:

```powershell
pwsh ./scripts/run-tests.ps1
```

By default, the script runs the offline Python unit tests and then runs optional checks when the required tools are installed. Missing optional tools are reported as skipped unless you use `-Strict`.

Use Python 3.12 for local testing. The CI workflow uses Python 3.12, and the pinned Pydantic dependency does not currently install cleanly on Python 3.14.

## Install Dependencies And Run Everything Available

```powershell
pwsh ./scripts/run-tests.ps1 -InstallPythonDeps -InstallFrontendDeps
```

Use strict mode for CI-like behavior where missing OPA, Bicep, or Node should fail the run:

```powershell
pwsh ./scripts/run-tests.ps1 -InstallPythonDeps -InstallFrontendDeps -Strict
```

## Common Switches

| Switch | Behavior |
|---|---|
| `-InstallPythonDeps` | Installs backend requirements plus `pytest`, `pytest-asyncio`, and `ruff`. |
| `-InstallFrontendDeps` | Runs `npm install` in the frontend folder before lint/build. |
| `-Strict` | Fails when optional tools are missing instead of skipping those checks. |
| `-SkipPython` | Skips Python unit tests. |
| `-SkipRuff` | Skips Python lint. |
| `-SkipOpa` | Skips OPA policy validation. |
| `-SkipBicep` | Skips Bicep lint. |
| `-SkipFrontend` | Skips frontend lint/build. |
| `-SkipDocker` | Skips Docker image build validation. |
| `-PythonCommand <path>` | Uses a specific Python executable instead of `python`. |

## What The Script Checks

| Check | Command | Notes |
|---|---|---|
| Python unit tests | `pytest tests/unit/ -v --tb=short` | Offline; Azure environment variables are set to empty strings for import safety. |
| Python lint | `ruff check app tests --select E,W,F,I` | Runs when `ruff` is installed or after `-InstallPythonDeps`. |
| OPA syntax/tests | `opa check policies/` and `opa test policies/ -v` | Runs when `opa` is installed. |
| Bicep lint | `bicep lint infra/main.bicep` and modules | Runs when `bicep` is installed. |
| Frontend lint/build | `npm run lint` and `npm run build` | Runs when `npm` is installed. Use `-InstallFrontendDeps` if dependencies are missing. |
| Docker build | `docker build app` | Runs when Docker is installed and reachable. |

## Manual Local Commands

If you prefer to run checks directly:

```powershell
python -m pip install -r app/requirements.txt pytest pytest-asyncio ruff
$env:APP_CONFIG_ENDPOINT=""
$env:WORKSPACE_STORAGE_ACCOUNT=""
$env:AUDIT_STORAGE_ACCOUNT=""
$env:AZURE_OPENAI_ENDPOINT=""
python -m pytest tests/unit/ -v --tb=short
ruff check app tests --select E,W,F,I
```

```powershell
opa check policies/
opa test policies/ -v
```

```powershell
bicep lint infra/main.bicep
Get-ChildItem infra/modules/*.bicep | ForEach-Object { bicep lint $_.FullName }
```

```powershell
Push-Location frontend
npm install
npm run lint
npm run build
Pop-Location
```

## Deployment Smoke Test

After deploying to Azure, use the existing smoke test to validate the live path through APIM and the frontend:

```powershell
pwsh ./scripts/smoke-test.ps1 `
  -ApimUrl "https://<your-apim-gateway>" `
  -FrontendUrl "https://<your-frontend-url>" `
  -AadClientId "<api-audience-client-id>"
```

The smoke test validates unauthenticated denial, authenticated kill-switch access, run creation, SSE events, run completion, and timeline retrieval.

The unit suite also validates governance controls, including block-by-default DLP/content safety and classification helpers in [tests/unit/test_governance_controls.py](../tests/unit/test_governance_controls.py).

For current authorization behavior, use an admin token when validating `/kill-switches`; non-admin tokens should receive `403`.

When rolling out signed APIM identity headers, deploy APIM policy and backend together. The backend expects validated and signed `X-Auth-*` headers from APIM and will reject requests with missing or invalid signatures.

For the deployed architecture to match the security design, the frontend image must be built with `VITE_API_BASE=https://<your-apim-gateway>/sandbox`, `VITE_AAD_CLIENT_ID`, and `VITE_AAD_TENANT_ID`. The deployment hooks and GitHub Actions workflow pass those build arguments automatically. The production frontend container now fails its Docker build when those values are missing, and its Nginx config rejects same-origin `/api/*` or `/sandbox/*` calls so browser traffic cannot fall back to a direct orchestrator proxy.

Normal orchestrator API routes also require the `X-Orchestrator-Gateway-Secret` header injected by APIM. A direct call to the orchestrator Web App should return `403` for routes such as `/runs`, while `GET /health` remains available for platform health probes.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Python imports fail for Azure settings | Environment variables are unset. | Use `scripts/run-tests.ps1`, which sets safe empty values for offline tests. |
| Python dependency install fails on `pydantic-core` | The default `python` is likely Python 3.14. | Install/use Python 3.12 and pass `-PythonCommand <path-to-python-3.12>`. |
| OPA checks are skipped | `opa` is not installed or not on `PATH`. | Install OPA or run with `-SkipOpa` intentionally. |
| Bicep lint is skipped | `bicep` is not installed or not on `PATH`. | Install Azure CLI/Bicep or run with `-SkipBicep`. |
| Frontend build fails due missing modules | Dependencies are not installed. | Run with `-InstallFrontendDeps`. |
| Docker build is skipped | Docker CLI or daemon is unavailable. | Start Docker or run with `-SkipDocker`. |
