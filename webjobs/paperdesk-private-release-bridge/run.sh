#!/usr/bin/env bash
set -euo pipefail
test "${WEBSITE_SITE_NAME:-}" = "paperdesk-release-registry-bridge-v2-9c4e0d0d"
python3 -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'
exec python3 -I private_release_bridge_entry.py --process-pending
