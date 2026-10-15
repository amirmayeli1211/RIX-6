#!/bin/sh
set -eu
export PORT="${PORT:-8080}"
uvicorn main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips="*" &
APP_PID=$!
caddy run --config /app/Caddyfile --adapter caddyfile &
CADDY_PID=$!
cleanup() {
  kill "$APP_PID" "$CADDY_PID" 2>/dev/null || true
  wait "$APP_PID" "$CADDY_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
# Exit when either long-running process exits.
while kill -0 "$APP_PID" 2>/dev/null && kill -0 "$CADDY_PID" 2>/dev/null; do
  sleep 2
done
exit 1
