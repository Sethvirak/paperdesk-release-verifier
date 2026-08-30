#!/usr/bin/env bash
set -euo pipefail

test "${WEBSITE_SITE_NAME:-}" = "paperdesk-registry-cleanup-watcher-9c4e0d0d"
python3 -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'
test -f registry_bridge_cleanup_runtime.py
test -f registry_bridge_cleanup_azure.py
test -f registry_bridge_cleanup_watcher.py
test -f registry_bridge_cleanup_contract.json

exec python3 -I registry_bridge_cleanup_runtime.py --continuous
