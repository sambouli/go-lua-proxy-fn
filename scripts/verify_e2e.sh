#!/usr/bin/env bash
# End-to-end rig: dummy upstream + reverse proxy with a Lua rule that echoes
# the client IP and the day of the week into response headers.
# Usage: bash scripts/verify_e2e.sh <binary> <scratchdir>
set -u
BIN="$1"
SCRATCH="$2"
mkdir -p "$SCRATCH"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $1"; }

UP_PORT=18099
PX_PORT=18080

cleanup() {
  [[ -n "${UP_PID:-}" ]] && kill "$UP_PID" 2>/dev/null
  [[ -n "${PX_PID:-}" ]] && kill "$PX_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

# --- dummy web server: echoes request info as JSON ---
cat > "$SCRATCH/upstream.py" <<'PYEOF'
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        body = json.dumps({
            "path": self.path,
            "xff": self.headers.get("X-Forwarded-For", ""),
            "x_from_lua": self.headers.get("X-From-Lua", ""),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Upstream-Marker", "dummy-server")
        self.end_headers()
        self.wfile.write(body)
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PYEOF
python3 "$SCRATCH/upstream.py" "$UP_PORT" & UP_PID=$!

# --- Lua rule: client IP + day of week as response headers ---
cat > "$SCRATCH/rule.lua" <<'LUAEOF'
local ip = proxy.clientIP()
proxy.setResponseHeader("X-Client-IP", ip)
proxy.setResponseHeader("X-Day-Of-Week", os.date("!%A"))
proxy.setRequestHeader("X-From-Lua", "lua-rule-ran")
proxy.log("serving " .. proxy.request.path .. " for " .. ip)
LUAEOF

sleep 0.5
curl -sf "http://127.0.0.1:$UP_PORT/ping" >/dev/null || { echo "upstream failed to start"; exit 1; }
ok "dummy upstream is up"

# --- start the proxy ---
LISTEN_ADDR="127.0.0.1:$PX_PORT" UPSTREAM="http://127.0.0.1:$UP_PORT" \
  LUA_SCRIPTS="$SCRATCH/rule.lua" "$BIN" >"$SCRATCH/proxy.log" 2>&1 & PX_PID=$!

for i in $(seq 1 40); do
  curl -sf "http://127.0.0.1:$PX_PORT/ping" >/dev/null 2>&1 && break
  sleep 0.25
done

# --- checks ---
HDRS=$(curl -sD - -o "$SCRATCH/body.json" "http://127.0.0.1:$PX_PORT/hello?x=1")

echo "$HDRS" | grep -qi "^X-Client-IP: 127.0.0.1" \
  && ok "client sees X-Client-IP: 127.0.0.1" \
  || bad "X-Client-IP missing/wrong: $(echo "$HDRS" | grep -i x-client-ip)"

WANT_DOW=$(date -u +%A)
echo "$HDRS" | grep -qi "^X-Day-Of-Week: $WANT_DOW" \
  && ok "client sees X-Day-Of-Week: $WANT_DOW (matches date -u +%A)" \
  || bad "X-Day-Of-Week wrong: got '$(echo "$HDRS" | grep -i x-day-of-week)' want $WANT_DOW"

grep -q '"x_from_lua": "lua-rule-ran"' "$SCRATCH/body.json" \
  && ok "upstream saw Lua-set request header X-From-Lua" \
  || bad "upstream did not see X-From-Lua: $(cat "$SCRATCH/body.json")"

grep -q '"xff": "127.0.0.1"' "$SCRATCH/body.json" \
  && ok "upstream saw proxy-set X-Forwarded-For" \
  || bad "upstream XFF wrong: $(cat "$SCRATCH/body.json")"

grep -q '"path": "/hello?x=1"' "$SCRATCH/body.json" \
  && ok "path+query forwarded intact" \
  || bad "path/query mangled: $(cat "$SCRATCH/body.json")"

grep -qi "^X-Upstream-Marker: dummy-server" <<<"$HDRS" \
  && ok "upstream response headers pass through" \
  || bad "upstream marker lost"

# forged XFF must be ignored (untrusted by default)
FORGED=$(curl -sD - -o /dev/null -H "X-Forwarded-For: 1.2.3.4" -H "X-Real-Ip: 5.6.7.8" \
  "http://127.0.0.1:$PX_PORT/forged")
echo "$FORGED" | grep -qi "^X-Client-IP: 127.0.0.1" \
  && ok "forged XFF/X-Real-Ip ignored (still 127.0.0.1)" \
  || bad "client forged its IP: $(echo "$FORGED" | grep -i x-client-ip)"

# stats endpoint
curl -sf "http://127.0.0.1:$PX_PORT/__proxy_stats__" | grep -q '"total_requests"' \
  && ok "stats endpoint serves JSON" \
  || bad "stats endpoint broken"

# graceful shutdown exits 0
kill -TERM "$PX_PID"; wait "$PX_PID"; RC=$?; PX_PID=""
[[ $RC -eq 0 ]] && ok "SIGTERM shutdown exits 0" || bad "shutdown exit code $RC"

echo "----"
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
