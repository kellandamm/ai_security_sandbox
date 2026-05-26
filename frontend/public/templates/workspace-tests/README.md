# Workspace Test Document Pack

This folder contains uploadable documents for control-focused workspace tests.

## Files
- `deny-tool-not-allowed.md`: deterministic capability deny scenario
- `approval-high-risk-http-post.md`: human approval scenario (requires temporary policy setup)
- `kill-switch-validation.md`: containment and recovery via App Configuration flags
- `opa-unreachable-simulation.md`: policy-engine outage fail-closed validation

## Recommended Execution Order
1. `deny-tool-not-allowed.md`
2. `kill-switch-validation.md`
3. `opa-unreachable-simulation.md`
4. `approval-high-risk-http-post.md`

## Notes
- Keep tests in non-production windows when simulating outages.
- Capture run IDs for each test and attach them to your demo notes.
