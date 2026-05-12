#!/usr/bin/env bash
set -euo pipefail

user_type="$(az account show --query user.type -o tsv)"
if [[ -z "$user_type" ]]; then
  echo "Unable to determine the current Azure account type." >&2
  exit 1
fi

principal_id=""

if [[ "$user_type" == "user" ]]; then
  principal_id="$(az ad signed-in-user show --query id -o tsv)"
else
  client_id="$(az account show --query user.name -o tsv)"
  if [[ -z "$client_id" ]]; then
    echo "Unable to determine the service principal client ID." >&2
    exit 1
  fi

  principal_id="$(az ad sp show --id "$client_id" --query id -o tsv)"
fi

if [[ -z "$principal_id" ]]; then
  echo "Unable to resolve the Microsoft Entra principal object ID for the current Azure login." >&2
  exit 1
fi

azd env set AZURE_PRINCIPAL_ID "$principal_id"
echo "Stored AZURE_PRINCIPAL_ID=$principal_id in the azd environment."
