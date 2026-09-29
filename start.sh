#!/bin/sh
set -e
# Front router on $PORT: /s/* -> local service (127.0.0.1:10000), everything else -> FastAPI (127.0.0.1:8000)
caddy run --config /app/Caddyfile --adapter caddyfile &
# The background service is started/restarted by engine.py whenever data changes
exec uvicorn main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips="*"
