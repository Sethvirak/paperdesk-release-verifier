#!/usr/bin/env bash
set -euo pipefail
if [[ "${WEBSITE_SITE_NAME:-}" != "paperdesk-release-registry-bridge-v2-9c4e0d0d" ]]; then
  echo 'paperdesk-bridge-startup:site-name' >&2
  exit 1
fi
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'; then
  echo 'paperdesk-bridge-startup:python-version' >&2
  exit 1
fi
if [[ ! -f private_release_bridge_entry.py ]]; then
  echo 'paperdesk-bridge-startup:entry-missing' >&2
  exit 1
fi
exec python3 -I private_release_bridge_entry.py --process-pending
