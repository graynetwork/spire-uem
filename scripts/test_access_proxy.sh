#!/usr/bin/env bash
# Real-proxy test of the SpireUEM forward-auth endpoint: Traefik v3, nginx (auth_request) and
# Caddy (forward_auth) in Docker on 127.0.0.1, in front of a tiny header-echo backend, with a
# SpireUEM server built from this checkout against a throwaway Postgres.
#
# It proves: a compliant device's address is let through with the posture headers; noncompliant,
# unknown and ambiguous devices are refused; the connector credential never reaches the protected
# application (and that the check would notice if it did); a spoofed X-Forwarded-For does not
# help; weak identity is refused when disabled.
#
# Everything binds to 127.0.0.1 and is removed on exit. Nothing outside this host is contacted
# (Docker images traefik:v3, nginx:alpine, caddy:2-alpine, postgres:16-alpine are pulled once).
#
# Usage: scripts/test_access_proxy.sh      (AP_PG_PORT=55452 by default)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PG_PORT="${AP_PG_PORT:-55452}"
SRV_PORT="${AP_SERVER_PORT:-18390}"
TRAEFIK_PORT="${AP_TRAEFIK_PORT:-18391}"
ECHO_PORT="${AP_ECHO_PORT:-18392}"
NGINX_PORT="${AP_NGINX_PORT:-18393}"
CADDY_PORT="${AP_CADDY_PORT:-18394}"
PGC=spire-ap-e2e-pg
TRC=spire-ap-e2e-traefik
NGC=spire-ap-e2e-nginx
CAC=spire-ap-e2e-caddy
ADMIN_PW="ap-e2e-breakglass-pw"
WORK="$(mktemp -d "${KIROCREW_SCRATCH:-${TMPDIR:-/tmp}}/ap-e2e.XXXXXX")"
DB_URL="postgres://spire:spirepassword@127.0.0.1:${PG_PORT}/spire_uem?sslmode=disable"
SRV_PID=""
ECHO_PID=""
FAILS=0
PASSES=0

cleanup() {
    docker rm -f "$TRC" "$NGC" "$CAC" "$PGC" >/dev/null 2>&1 || true
    [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null || true
    [[ -n "$ECHO_PID" ]] && kill "$ECHO_PID" 2>/dev/null || true
}
trap cleanup EXIT

ok()   { PASSES=$((PASSES+1)); echo "  PASS  $*"; }
bad()  { FAILS=$((FAILS+1));  echo "  FAIL  $*"; }

cat > "$WORK/jget.py" <<'PY'
import json, sys
# jget.py FILE KEY  -> value of header KEY (case-insensitive) in the echo backend's JSON, or "".
d = json.load(open(sys.argv[1]))
want = sys.argv[2].lower()
for k, v in d.get("headers", {}).items():
    if k.lower() == want:
        print(v); break
PY
cat > "$WORK/echo.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    def _go(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n: self.rfile.read(n)
        body = json.dumps({"method": self.command, "path": self.path, "headers": dict(self.headers)}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    do_GET = do_POST = do_PUT = do_DELETE = _go
    def log_message(self, *a): pass
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY

# req NAME PORT SOURCE_IP HOST [extra curl args...] -> sets CODE, body in $WORK/NAME.json
req() {
    local name="$1" port="$2" src="$3" host="$4"; shift 4
    CODE="$(curl -s -o "$WORK/$name.json" -w '%{http_code}' --interface "$src" --max-time 15 \
        -H "Host: $host" "$@" "http://127.0.0.1:${port}/app?x=1" || true)"
}
expect() { # expect LABEL WANT_CODE
    if [[ "$CODE" == "$2" ]]; then ok "$1 -> $CODE"; else bad "$1 -> $CODE (wanted $2): $(head -c 200 "$WORK/$NAME.json" 2>/dev/null)"; fi
}
psqlc() { docker exec -i "$PGC" psql -U spire -d spire_uem --tuples-only --no-align --command="$1"; }

echo "== Postgres"
docker rm -f "$PGC" >/dev/null 2>&1 || true
docker run -d --name "$PGC" -e POSTGRES_USER=spire -e POSTGRES_PASSWORD=spirepassword -e POSTGRES_DB=spire_uem \
    -p "127.0.0.1:${PG_PORT}:5432" postgres:16-alpine >/dev/null
for i in $(seq 1 40); do
    docker exec "$PGC" pg_isready -U spire -d spire_uem >/dev/null 2>&1 && break
    sleep 1
done

echo "== Build server and seeder from this checkout"
go build -o "$WORK/spire-server" ./cmd/spire-server
go build -o "$WORK/seed" ./test/access_proxy_seed

echo "== Start SpireUEM on 127.0.0.1:${SRV_PORT}"
mkdir -p "$WORK/apt" "$WORK/bundles"
DATABASE_URL="$DB_URL" SPIRE_LISTEN_ADDR="127.0.0.1:${SRV_PORT}" \
SPIRE_MIGRATIONS_PATH="$ROOT/migrations/000001_init_schema.up.sql" \
SPIRE_SESSION_SECRET="ap-e2e-session-secret-key-32b-fixed" SPIRE_ADMIN_PASSWORD="$ADMIN_PW" \
SPIRE_KEK_PATH="$WORK/kek" SPIRE_WIPE_SIGNING_KEY_PATH="$WORK/wipe.key" \
SPIRE_DEVICE_CA_CERT_FILE="$WORK/ca.pem" SPIRE_DEVICE_CA_KEY_FILE="$WORK/ca.key" \
SPIRE_APT_REPO_DIR="$WORK/apt" SPIRE_BUNDLE_STORAGE_DIR="$WORK/bundles" \
    "$WORK/spire-server" > "$WORK/server.log" 2>&1 &
SRV_PID=$!
for i in $(seq 1 60); do
    c="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${SRV_PORT}/admin/devices" || true)"
    [[ "$c" == "303" || "$c" == "401" || "$c" == "200" ]] && break
    sleep 1
    if [[ "$i" == 60 ]]; then echo "server did not start"; tail -20 "$WORK/server.log"; exit 1; fi
done

echo "== Seed devices, connector token, forward-auth settings"
eval "$(DATABASE_URL="$DB_URL" "$WORK/seed")"   # SPIRE_CONNECTOR_TOKEN, GOOD_DEVICE_ID
TOKEN="$SPIRE_CONNECTOR_TOKEN"
FA="http://127.0.0.1:${SRV_PORT}/api/admin/v1/access/forward-auth"

echo "== Echo backend on 127.0.0.1:${ECHO_PORT}"
python3 "$WORK/echo.py" "$ECHO_PORT" &
ECHO_PID=$!
sleep 1

echo "== Traefik v3 (token via headers middleware, stripped before the app)"
mkdir -p "$WORK/traefik"
cat > "$WORK/traefik/dyn.yml" <<YML
http:
  middlewares:
    add-token:
      headers:
        customRequestHeaders:
          X-Spire-Connector-Token: "${TOKEN}"
    strip-token:
      headers:
        customRequestHeaders:
          X-Spire-Connector-Token: ""
    posture:
      forwardAuth:
        address: "${FA}"
        authResponseHeaders: [X-Spire-Device-Id, X-Spire-Posture, X-Spire-Identity-Strength]
    posture-trusting:
      forwardAuth:
        address: "${FA}"
        trustForwardHeader: true
        authResponseHeaders: [X-Spire-Device-Id, X-Spire-Posture, X-Spire-Identity-Strength]
    chain-strict:
      chain: {middlewares: [add-token, posture, strip-token]}
    chain-trusting:
      chain: {middlewares: [add-token, posture-trusting, strip-token]}
    chain-leaky:
      chain: {middlewares: [add-token, posture]}
  services:
    echo:
      loadBalancer:
        servers: [{url: "http://127.0.0.1:${ECHO_PORT}"}]
  routers:
    strict:   {rule: "Host(\`strict.test\`)",   entryPoints: [web], middlewares: [chain-strict],   service: echo}
    trusting: {rule: "Host(\`trusting.test\`)", entryPoints: [web], middlewares: [chain-trusting], service: echo}
    leaky:    {rule: "Host(\`leaky.test\`)",    entryPoints: [web], middlewares: [chain-leaky],    service: echo}
YML
docker rm -f "$TRC" >/dev/null 2>&1 || true
docker run -d --name "$TRC" --network host -v "$WORK/traefik:/dyn:ro" traefik:v3 \
    --entrypoints.web.address="127.0.0.1:${TRAEFIK_PORT}" --providers.file.directory=/dyn \
    --global.checknewversion=false --global.sendanonymoususage=false --log.level=ERROR >/dev/null
for i in $(seq 1 30); do
    curl -s -o /dev/null --max-time 2 -H "Host: strict.test" "http://127.0.0.1:${TRAEFIK_PORT}/" && break
    sleep 1
done
sleep 1

T=$TRAEFIK_PORT
echo "== Traefik"
NAME=a; req a $T 127.0.0.2 strict.test;  expect "compliant device through Traefik" 200
if [[ "$CODE" == 200 ]]; then
    [[ "$(python3 "$WORK/jget.py" "$WORK/a.json" X-Spire-Device-Id)" == "$GOOD_DEVICE_ID" ]] && ok "backend got X-Spire-Device-Id" || bad "backend X-Spire-Device-Id"
    [[ "$(python3 "$WORK/jget.py" "$WORK/a.json" X-Spire-Posture)" == "COMPLIANT" ]] && ok "backend got X-Spire-Posture" || bad "backend X-Spire-Posture"
    [[ "$(python3 "$WORK/jget.py" "$WORK/a.json" X-Spire-Identity-Strength)" == "weak" ]] && ok "identity strength is labelled weak" || bad "identity strength"
fi
grep -q "$TOKEN" "$WORK/a.json" && bad "Traefik: connector token reached the protected app" || ok "Traefik: connector token did NOT reach the protected app"
[[ -z "$(python3 "$WORK/jget.py" "$WORK/a.json" X-Spire-Connector-Token)" ]] && ok "Traefik: connector header stripped" || bad "Traefik: connector header present upstream"
NAME=a2; req a2 $T 127.0.0.2 leaky.test; expect "control route without the strip middleware" 200
grep -q "$TOKEN" "$WORK/a2.json" && ok "control: WITHOUT the strip middleware the token does leak (so the check above can fail)" || bad "control: leak not detected, the leak check is blind"
NAME=b; req b $T 127.0.0.2 strict.test -H "X-Spire-Device-Id: attacker-chosen"; expect "client-supplied X-Spire-Device-Id" 200
[[ "$(python3 "$WORK/jget.py" "$WORK/b.json" X-Spire-Device-Id)" == "$GOOD_DEVICE_ID" ]] && ok "client cannot choose X-Spire-Device-Id upstream" || bad "client-supplied X-Spire-Device-Id reached the app"
NAME=c; req c $T 127.0.0.2 strict.test -X POST -d 'hello=1'; expect "POST through Traefik" 200
NAME=d; req d $T 127.0.0.3 strict.test;  expect "noncompliant device" 403
NAME=e; req e $T 127.0.0.4 strict.test;  expect "unknown device" 403
NAME=f; req f $T 127.0.0.5 strict.test;  expect "two devices on one address (ambiguous)" 403
NAME=g; req g $T 127.0.0.4 strict.test -H "X-Forwarded-For: 127.0.0.2"; expect "spoofed X-Forwarded-For via Traefik (default replaces it)" 403
NAME=g2; req g2 $T 127.0.0.4 trusting.test -H "X-Forwarded-For: 127.0.0.2"; expect "spoofed X-Forwarded-For with trustForwardHeader (rightmost wins)" 403
NAME=g3; req g3 $T 127.0.0.2 trusting.test; expect "compliant device via trustForwardHeader route" 200

echo "== Direct calls to SpireUEM"
NAME=h; CODE="$(curl -s -o "$WORK/h.json" -w '%{http_code}' --interface 127.0.0.9 -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: 127.0.0.2" "$FA" || true)"
expect "untrusted peer 127.0.0.9 forging X-Forwarded-For" 403
NAME=h2; CODE="$(curl -s -o "$WORK/h2.json" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: 127.0.0.2" "$FA" || true)"
expect "trusted proxy 127.0.0.1 asking about the compliant address" 200
NAME=h3; CODE="$(curl -s -o "$WORK/h3.json" -w '%{http_code}' -H "X-Forwarded-For: 127.0.0.2" "$FA" || true)"
expect "no connector credential" 401
NAME=h4; CODE="$(curl -s -o "$WORK/h4.json" -w '%{http_code}' -H "Authorization: Bearer spire_sa_0000000000000000_$(printf '0%.0s' $(seq 1 64))" -H "X-Forwarded-For: 127.0.0.2" "$FA" || true)"
expect "bad connector credential" 401

echo "== Posture changes take effect immediately"
DEVB="$(psqlc "SELECT id FROM devices WHERE hostname='e2e-noncompliant'")"
psqlc "UPDATE device_posture SET state='COMPLIANT', valid_until=NOW()+interval '1 hour' WHERE device_id='$DEVB'" >/dev/null
NAME=i; req i $T 127.0.0.3 strict.test; expect "device became COMPLIANT" 200
psqlc "UPDATE device_posture SET state='QUARANTINED' WHERE device_id='$DEVB'" >/dev/null
NAME=i2; req i2 $T 127.0.0.3 strict.test; expect "device QUARANTINED" 403
psqlc "UPDATE device_posture SET state='COMPLIANT', valid_until=NOW()-interval '1 second' WHERE device_id='$DEVB'" >/dev/null
NAME=i3; req i3 $T 127.0.0.3 strict.test; expect "COMPLIANT but verdict stale" 403
psqlc "UPDATE device_posture SET state='NONCOMPLIANT', valid_until=NOW()+interval '1 hour' WHERE device_id='$DEVB'" >/dev/null

echo "== Weak identity switch (admin page, audited)"
curl -s -o /dev/null -w '' -u "admin:${ADMIN_PW}" --data-urlencode "trusted_proxies=127.0.0.1" \
    "http://127.0.0.1:${SRV_PORT}/admin/access-proxy" || true
NAME=j; req j $T 127.0.0.2 strict.test; expect "weak identity disabled" 403
curl -s -o /dev/null -u "admin:${ADMIN_PW}" --data-urlencode "trusted_proxies=127.0.0.1" --data-urlencode "allow_weak_identity=on" \
    "http://127.0.0.1:${SRV_PORT}/admin/access-proxy" || true
NAME=j2; req j2 $T 127.0.0.2 strict.test; expect "weak identity re-enabled" 200
[[ "$(psqlc "SELECT COUNT(*) FROM system_audit_events WHERE action='ACCESS_PROXY_SETTINGS_CHANGE'")" -ge 2 ]] && ok "both settings changes audited" || bad "settings changes not audited"

echo "== nginx auth_request"
cat > "$WORK/nginx.conf" <<NGX
events {}
http {
  access_log off;
  server {
    listen 127.0.0.1:${NGINX_PORT};
    location / {
      auth_request /_spire_posture;
      auth_request_set \$spire_dev \$upstream_http_x_spire_device_id;
      auth_request_set \$spire_pos \$upstream_http_x_spire_posture;
      auth_request_set \$spire_str \$upstream_http_x_spire_identity_strength;
      proxy_set_header X-Spire-Device-Id \$spire_dev;
      proxy_set_header X-Spire-Posture \$spire_pos;
      proxy_set_header X-Spire-Identity-Strength \$spire_str;
      proxy_pass http://127.0.0.1:${ECHO_PORT};
    }
    location = /_spire_posture {
      internal;
      proxy_pass ${FA};
      proxy_method GET;
      proxy_pass_request_body off;
      proxy_set_header Content-Length "";
      proxy_set_header Authorization "Bearer ${TOKEN}";
      proxy_set_header X-Forwarded-For \$remote_addr;
    }
  }
}
NGX
docker rm -f "$NGC" >/dev/null 2>&1 || true
docker run -d --name "$NGC" --network host -v "$WORK/nginx.conf:/etc/nginx/nginx.conf:ro" nginx:alpine >/dev/null
sleep 2
N=$NGINX_PORT
NAME=n1; req n1 $N 127.0.0.2 nginx.test -H "Authorization: Bearer the-apps-own-token"; expect "compliant device through nginx" 200
grep -q "$TOKEN" "$WORK/n1.json" && bad "nginx: connector token reached the protected app" || ok "nginx: connector token did NOT reach the protected app"
[[ "$(python3 "$WORK/jget.py" "$WORK/n1.json" Authorization)" == "Bearer the-apps-own-token" ]] && ok "nginx: the app's own Authorization header is untouched" || bad "nginx: app Authorization altered"
[[ "$(python3 "$WORK/jget.py" "$WORK/n1.json" X-Spire-Device-Id)" == "$GOOD_DEVICE_ID" ]] && ok "nginx: posture headers passed upstream" || bad "nginx: posture headers missing"
NAME=n2; req n2 $N 127.0.0.3 nginx.test; expect "noncompliant device through nginx" 403
NAME=n3; req n3 $N 127.0.0.4 nginx.test -H "X-Forwarded-For: 127.0.0.2"; expect "spoofed X-Forwarded-For through nginx (proxy overwrites it)" 403

echo "== Caddy forward_auth"
cat > "$WORK/Caddyfile" <<CDY
{
  admin off
  auto_https off
}
:${CADDY_PORT} {
  bind 127.0.0.1
  forward_auth 127.0.0.1:${SRV_PORT} {
    uri /api/admin/v1/access/forward-auth
    header_up Authorization "Bearer ${TOKEN}"
    copy_headers X-Spire-Device-Id X-Spire-Posture X-Spire-Identity-Strength
  }
  reverse_proxy 127.0.0.1:${ECHO_PORT}
}
CDY
docker rm -f "$CAC" >/dev/null 2>&1 || true
docker run -d --name "$CAC" --network host -v "$WORK/Caddyfile:/etc/caddy/Caddyfile:ro" caddy:2-alpine >/dev/null
sleep 3
C=$CADDY_PORT
NAME=c1; req c1 $C 127.0.0.2 caddy.test -H "Authorization: Bearer the-apps-own-token"; expect "compliant device through Caddy" 200
grep -q "$TOKEN" "$WORK/c1.json" && bad "Caddy: connector token reached the protected app" || ok "Caddy: connector token did NOT reach the protected app"
[[ "$(python3 "$WORK/jget.py" "$WORK/c1.json" Authorization)" == "Bearer the-apps-own-token" ]] && ok "Caddy: the app's own Authorization header is untouched" || bad "Caddy: app Authorization altered"
[[ "$(python3 "$WORK/jget.py" "$WORK/c1.json" X-Spire-Device-Id)" == "$GOOD_DEVICE_ID" ]] && ok "Caddy: posture headers passed upstream" || bad "Caddy: posture headers missing"
NAME=c2; req c2 $C 127.0.0.3 caddy.test; expect "noncompliant device through Caddy" 403
NAME=c3; req c3 $C 127.0.0.4 caddy.test -H "X-Forwarded-For: 127.0.0.2"; expect "spoofed X-Forwarded-For through Caddy" 403

echo
echo "access proxy E2E: ${PASSES} passed, ${FAILS} failed"
[[ "$FAILS" == 0 ]]
