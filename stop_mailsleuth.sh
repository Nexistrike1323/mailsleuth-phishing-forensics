#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")" && pwd)"
for name in api frontend; do
  file="$ROOT/data/$name.pid"
  if [ -f "$file" ]; then
    pid="$(cat "$file")"
    kill "$pid" 2>/dev/null || true
    rm -f "$file"
  fi
done
echo "MailSleuth services stopped."
