#!/usr/bin/env bash
set -euo pipefail

readonly job_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly helper="${job_directory}/accepted_release_registry.py"

test -f "${helper}"
test ! -L "${helper}"
exec python3 -I "${helper}" persist-actions-artifact
