#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3.10+ is required. Install Python, then run this script again."
  exit 1
fi

if [ ! -x ".venv/bin/python" ]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install -r requirements.txt
cat <<'MSG'

RECK-0 is starting at http://127.0.0.1:8000
Keep this terminal open while using the app. Press Ctrl+C to stop.
MSG
exec .venv/bin/python -m uvicorn server:app --host 127.0.0.1 --port 8000
