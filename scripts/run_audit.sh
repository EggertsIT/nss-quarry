#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWLIST_FILE="${AUDIT_ALLOWLIST_FILE:-${ROOT_DIR}/audit-allowlist.txt}"

args=(--deny warnings)

if [[ -f "${ALLOWLIST_FILE}" ]]; then
  while IFS= read -r raw_line || [[ -n "${raw_line}" ]]; do
    id="$(printf '%s' "${raw_line}" | sed 's/#.*$//' | tr -d '[:space:]')"
    if [[ -n "${id}" ]]; then
      args+=(--ignore "${id}")
    fi
  done < "${ALLOWLIST_FILE}"
fi

exec cargo audit "${args[@]}"
