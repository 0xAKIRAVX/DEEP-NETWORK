#!/bin/bash
# DEEP NETWORK v3 — local E2E boot test (Go server + xray + deep-probe)
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
DATA=/tmp/dn-e2e
rm -rf "$DATA" && mkdir -p "$DATA"
export PORT=8099 DATA_DIR="$DATA" ADMIN_PASSWORD='test123' ADMIN_USER='admin' DOMAIN='test.local'
[ -x out ] || { echo "FATAL: build ./out first"; exit 1; }

./out >"$DATA/boot.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 2.5

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
ck()  { eval "$2" >/dev/null 2>&1 && ok "$1" || bad "$1"; }

echo "── DEEP NETWORK v3 E2E ──"
ck "decoy site at /"            "curl -sf http://127.0.0.1:8099/ | grep -qi html"
ck "panel UI at /panel"         "curl -sf http://127.0.0.1:8099/panel | grep -q 'DEEP NETWORK'"
ck "panel css served"           "curl -sf http://127.0.0.1:8099/panel/style.css | grep -q Vazirmatn"
ck "panel js served"            "curl -sf http://127.0.0.1:8099/panel/app.js | grep -q FX"
ck "fonts served"               "curl -sfo /dev/null http://127.0.0.1:8099/panel/assets/fonts/Vazirmatn-arabic.woff2"
ck "wolf image served"          "curl -sfo /dev/null http://127.0.0.1:8099/panel/assets/img/wolf-128.png"
ck "api w/o auth = 401"         '[ "$(curl -s -o /dev/null -w %{http_code} http://127.0.0.1:8099/panel/api/stats)" = 401 ]'
ck "bad login = 401"            '[ "$(curl -s -o /dev/null -w %{http_code} -X POST -d "{\"user\":\"admin\",\"pass\":\"nope\"}" http://127.0.0.1:8099/panel/api/login)" = 401 ]'

curl -sf -c "$DATA/jar" -X POST -H 'Content-Type: application/json' \
  -d '{"user":"admin","pass":"test123"}' http://127.0.0.1:8099/panel/api/login > /dev/null \
  && ok "login sets cookie" || bad "login sets cookie"

ck "stats (authed)"             "curl -sf -b $DATA/jar http://127.0.0.1:8099/panel/api/stats | grep -q cpu"
ck "state (authed)"             "curl -sf -b $DATA/jar http://127.0.0.1:8099/panel/api/state | grep -q clients"
ck "health (authed)"            "curl -sf -b $DATA/jar http://127.0.0.1:8099/panel/api/health | grep -q xray"
ck "ping (authed)"              "curl -sf -b $DATA/jar http://127.0.0.1:8099/panel/api/ping | grep -q ok"
ck "whoami works"               "curl -sf -b $DATA/jar http://127.0.0.1:8099/panel/api/whoami | grep -q operator"
ck "log (authed)"               "curl -sf -b $DATA/jar http://127.0.0.1:8099/panel/api/log"
ck "server-config download"     "curl -sf -b $DATA/jar http://127.0.0.1:8099/panel/api/server-config | grep -q inbounds"
ck "backup download"            "curl -sf -b $DATA/jar http://127.0.0.1:8099/panel/api/backup | grep -q ng_backup"
ck "qr endpoint"                "curl -sf -b $DATA/jar 'http://127.0.0.1:8099/panel/api/qr?data=hello' | grep -q svg"

MAIN_ID=$(curl -sf -b $DATA/jar http://127.0.0.1:8099/panel/api/state | python3 -c "import sys,json; s=json.load(sys.stdin); print([c for c in s['clients'] if c['main']][0]['id'])")
ck "main client found"          "[ -n '$MAIN_ID' ]"
ck "client config JSON"         "curl -sf -b $DATA/jar http://127.0.0.1:8099/panel/api/client/$MAIN_ID | grep -q outbounds"
SUB_URL=$(curl -sf -b $DATA/jar http://127.0.0.1:8099/panel/api/state | python3 -c "import sys,json; s=json.load(sys.stdin); print([c for c in s['clients'] if c['main']][0]['sub_url'])")
TOK=${SUB_URL##*/}
ck "sub returns base64 links"   "curl -sf http://127.0.0.1:8099/sub/$TOK | base64 -d | grep -q 'vless://'"
ck "sub headers present"       "curl -sI http://127.0.0.1:8099/sub/$TOK | grep -qi subscription-userinfo"
ck "bad sub token = 404"        '[ "$(curl -s -o /dev/null -w %{http_code} http://127.0.0.1:8099/sub/deadbeef)" = 404 ]'

ck "ws upgrade = 101"           '[ "$(curl -s -o /dev/null -w %{http_code} -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" http://127.0.0.1:8099/ws)" = 101 ]'
ck "xhttp reaches xray (404)"   '[ "$(curl -s --max-time 6 -o /dev/null -w %{http_code} -X POST --data-binary xx -H "Content-Type: text/plain" http://127.0.0.1:8099/xhttp)" = 404 ]'
ck "httpupgrade answers"        '[ "$(curl -s -o /dev/null -w %{http_code} -H "Connection: Upgrade" -H "Upgrade: foo" http://127.0.0.1:8099/hu)" != 404 ]'

NEW=$(curl -sf -b $DATA/jar -X POST -H 'Content-Type: application/json' -d '{"name":"e2e-user","days":30,"quota":0}' http://127.0.0.1:8099/panel/api/clients | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
ck "client add"                "[ -n '$NEW' ]"
ck "client edit"               "curl -sf -b $DATA/jar -X POST -H 'Content-Type: application/json' -d '{\"id\":\"$NEW\",\"name\":\"e2e-renamed\"}' http://127.0.0.1:8099/panel/api/clients/edit | grep -q ok"
ck "client delete"             "curl -sf -b $DATA/jar -X POST -H 'Content-Type: application/json' -d '{\"id\":\"$NEW\"}' http://127.0.0.1:8099/panel/api/clients/delete | grep -q ok"

ck "settings save"             "curl -sf -b $DATA/jar -X POST -H 'Content-Type: application/json' -d '{\"cfg_fmt\":\"{name}-{label}\"}' http://127.0.0.1:8099/panel/api/settings | grep -q ok"
ck "restart xray"              "curl -sf -b $DATA/jar -X POST http://127.0.0.1:8099/panel/api/restart | grep -q ok"
sleep 1
ck "ws still 101 after restart" '[ "$(curl -s -o /dev/null -w %{http_code} -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" http://127.0.0.1:8099/ws)" = 101 ]'

ck "ipscan (rust)"             "curl -sf -b $DATA/jar -X POST -H 'Content-Type: application/json' -d '{\"targets\":[\"1.1.1.1\",\"8.8.8.8\"]}' http://127.0.0.1:8099/panel/api/ipscan | grep -q 1.1.1.1"

ck "state.json persisted"       "python3 -c \"import json;d=json.load(open('$DATA/state.json'));assert d['admin_user']=='admin'\""

echo "──"
echo "PASS=$PASS FAIL=$FAIL"
echo "boot log:"; head -22 "$DATA/boot.log"
[ $FAIL -eq 0 ]
