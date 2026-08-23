#!/usr/bin/env bash
set -euo pipefail

test "${WEBSITE_SITE_NAME:-}" = "paperdesk-watchdog-state-9c4e0d0d"
python3 -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'
watchdog_port="${PORT:-8000}"
[[ "${watchdog_port}" =~ ^[1-9][0-9]{3,4}$ ]]
(( watchdog_port >= 1024 && watchdog_port <= 65535 ))

exec python3 -m gunicorn \
  --bind "0.0.0.0:${watchdog_port}" \
  --worker-class sync \
  --workers 2 \
  --threads 1 \
  --timeout 60 \
  --graceful-timeout 30 \
  --keep-alive 2 \
  --limit-request-line 4094 \
  --limit-request-fields 50 \
  --limit-request-field_size 8190 \
  --access-logfile - \
  --error-logfile - \
  provider.wsgi:application
