#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$ROOT/data"

if [ -f "$ROOT/data/api.pid" ] && kill -0 "$(cat "$ROOT/data/api.pid")" 2>/dev/null; then
  echo "Backend already running"
else
  nohup "$ROOT/.venv/bin/python" -m uvicorn mailsleuth.api:app --app-dir "$ROOT/src" --host 127.0.0.1 --port 8000 > "$ROOT/data/api.log" 2>&1 < /dev/null &
  echo $! > "$ROOT/data/api.pid"
fi

if [ -f "$ROOT/data/frontend.pid" ] && kill -0 "$(cat "$ROOT/data/frontend.pid")" 2>/dev/null; then
  echo "Frontend already running"
else
  cd "$ROOT/frontend"
  nohup npm run dev -- --host 127.0.0.1 --port 5173 > "$ROOT/data/frontend.log" 2>&1 < /dev/null &
  echo $! > "$ROOT/data/frontend.pid"
fi

for i in {1..30}; do
  if curl -fsS http://127.0.0.1:8000/api/health >/dev/null && curl -fsS http://127.0.0.1:5173 >/dev/null; then
    echo
    echo "MAILSLEUTH STARTED"
    echo "Dashboard: http://127.0.0.1:5173"
    echo "Backend:   http://127.0.0.1:8000"
    echo "API Docs:  http://127.0.0.1:8000/docs"
    exit 0
  fi
  sleep 1
done

echo "Startup check failed. Check data/api.log and data/frontend.log"
exit 1
