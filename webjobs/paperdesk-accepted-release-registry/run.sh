#!/usr/bin/env bash
set -euo pipefail

readonly job_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly helper="${job_directory}/accepted_release_registry.py"
readonly expected_helper_sha256="${PAPERDESK_REGISTRY_HELPER_SHA256:-}"
readonly operation="${PAPERDESK_REGISTRY_OPERATION:-}"

[[ "${expected_helper_sha256}" =~ ^[0-9a-f]{64}$ ]]
test -f "${helper}"
test ! -L "${helper}"
test "$(sha256sum "${helper}" | cut -d ' ' -f 1)" = "${expected_helper_sha256}"
case "${operation}" in
  runtime-canary|storage-rbac-canary|persist-actions-artifact) ;;
  *)
    echo "Registry WebJob operation is invalid." >&2
    exit 1
    ;;
esac
unset PAPERDESK_REGISTRY_HELPER_SHA256 PAPERDESK_REGISTRY_OPERATION
exec python3 -I "${helper}" "${operation}"
