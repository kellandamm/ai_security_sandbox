#!/usr/bin/env bash
# Wrapper for scripts/seed_demo_data.py — seeds the AI Security Sandbox.
# Real logic lives in scripts/seed_demo_data.py; scenarios in
# scripts/seed-scenarios.json. Forwards all args through to the Python tool.
#
# Usage:
#   ./scripts/seed-demo-data.sh --mode direct --dce-logs https://... --dcr-immutable-id dcr-...
#   ./scripts/seed-demo-data.sh --mode runs --apim-url https://... --aad-client-id <guid>
#   ./scripts/seed-demo-data.sh --mode both --apim-url ... --aad-client-id ... \
#       --dce-logs ... --dcr-immutable-id ... --loop-minutes 30
#
# Run `./scripts/seed-demo-data.sh --help` for the full flag list.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_SCRIPT="${SCRIPT_DIR}/seed_demo_data.py"

if [[ ! -f "${PY_SCRIPT}" ]]; then
  echo "ERROR: ${PY_SCRIPT} not found." >&2
  exit 1
fi

PYTHON_EXE=""
for candidate in python3 python; do
  if command -v "${candidate}" >/dev/null 2>&1; then
    PYTHON_EXE="${candidate}"
    break
  fi
done

if [[ -z "${PYTHON_EXE}" ]]; then
  echo "ERROR: Python 3 not found on PATH. Install Python 3.10+ and retry." >&2
  exit 1
fi

echo "==> ${PYTHON_EXE} ${PY_SCRIPT} $*"
exec "${PYTHON_EXE}" "${PY_SCRIPT}" "$@"
