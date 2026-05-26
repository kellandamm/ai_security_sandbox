# Public Release Checklist

Use this checklist before publishing the accelerator to a public repository or sharing it with external users.

## Source Hygiene

- Confirm generated folders are absent: `.azure`, `.vscode`, `.stubs`, `node_modules`, `frontend/dist`, `__pycache__`, downloaded log folders, and ZIP bundles.
- Confirm generated ARM JSON is absent unless intentionally published: `infra/main.json`, `infra/main.parameters.json`, and `infra/modules/*.json`.
- Confirm `.gitignore` includes local state, build output, dependency folders, logs, ZIPs, and environment files.
- Confirm no deployment-specific IDs, tenant-specific settings, or local workspace exports are included accidentally.

## Secret And Credential Review

- Run a secret scanner before publishing, even when values are believed to be fake.
- Avoid realistic secret prefixes in sample data such as `sk-`, `ghp_`, real SAS token shapes, real Slack webhook URLs, or base64-looking storage keys.
- Keep demo credentials visibly invalid, for example `DEMO_CLIENT_SECRET_DO_NOT_USE`.
- Do not publish `.env`, App Configuration exports, Azure profiles, kubeconfig files, or downloaded platform logs.

## Documentation Readiness

- [solution-accelerator-guide.md](solution-accelerator-guide.md) explains what the accelerator does and who it is for.
- [testing-guide.md](testing-guide.md) explains how to run local and deployment tests.
- [../README.md](../README.md) gives the architecture and deployment overview.
- Add a `LICENSE` file before public distribution.
- Consider adding `SECURITY.md` with vulnerability reporting instructions.
- Consider adding `CONTRIBUTING.md` if outside contributions are expected.

## Test Gate

Use Python 3.12 for the local Python test environment. This matches the GitHub Actions workflow.

Run local validation:

```powershell
pwsh ./scripts/run-tests.ps1 -InstallPythonDeps -InstallFrontendDeps
```

For stricter release validation:

```powershell
pwsh ./scripts/run-tests.ps1 -InstallPythonDeps -InstallFrontendDeps -Strict
```

After Azure deployment, run:

```powershell
pwsh ./scripts/smoke-test.ps1 `
  -ApimUrl "https://<your-apim-gateway>" `
  -FrontendUrl "https://<your-frontend-url>" `
  -AadClientId "<api-audience-client-id>"
```

## Public Repository Settings

- Enable branch protection on the default branch.
- Require CI before merge.
- Enable secret scanning and push protection where available.
- Enable Dependabot or equivalent dependency update automation.
- Review GitHub Actions secrets and environment protection rules.
- Confirm deploy workflows target non-production defaults or require manual approval.

## Azure Safety Checks

- Deploy into a non-production subscription first.
- Confirm managed identities are scoped to least privilege.
- Confirm App Configuration kill switches are enabled and documented.
- Confirm WORM retention, Log Analytics retention, and Sentinel analytics rules match your organization policy.
- Confirm APIM authentication and frontend authentication are tenant-specific before production use.
- Confirm [data-retention-policy.md](data-retention-policy.md) is reviewed and approved for the target environment.
- Confirm [incident-response-runbook.md](incident-response-runbook.md) is linked in operational handoff documentation.
- Confirm `DLP_ENFORCEMENT_MODE` and `CONTENT_SAFETY_ENFORCEMENT_MODE` are set to `block` in production runtime settings.
