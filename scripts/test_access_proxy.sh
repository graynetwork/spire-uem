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
# The last section covers BROWSER CERTIFICATES end to end: a second SpireUEM instance with
# built-in TLS issues a browser certificate (and a network certificate) through the real
# /api/v1/desktop/cert/issue endpoint, and a real Traefik terminates TLS with optional client
# auth against the device CA and passes the certificate to forward-auth. curl then shows what
# is allowed (compliant device, browser certificate, user header set) and what is denied (no
# certificate, agent certificate, network certificate, revoked certificate, quarantined device,
# a forged certificate header).
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
TLS_SRV_PORT="${AP_TLS_SERVER_PORT:-18395}"
TLS_EDGE_PORT="${AP_TLS_TRAEFIK_PORT:-18396}"
PGC=spire-ap-e2e-pg
TRC=spire-ap-e2e-traefik
NGC=spire-ap-e2e-nginx
CAC=spire-ap-e2e-caddy
TTC=spire-ap-e2e-traefik-tls
ADMIN_PW="ap-e2e-breakglass-pw"
WORK="$(mktemp -d "${KIROCREW_SCRATCH:-${TMPDIR:-/tmp}}/ap-e2e.XXXXXX")"
DB_URL="postgres://spire:spirepassword@127.0.0.1:${PG_PORT}/spire_uem?sslmode=disable"
SRV_PID=""
SRV2_PID=""
ECHO_PID=""
FAILS=0
PASSES=0

cleanup() {
    docker rm -f "$TRC" "$NGC" "$CAC" "$TTC" "$PGC" >/dev/null 2>&1 || true
    [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null || true
    [[ -n "$SRV2_PID" ]] && kill "$SRV2_PID" 2>/dev/null || true
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
SPIRE_POSTURE_INTERVAL=24h DATABASE_URL="$DB_URL" SPIRE_LISTEN_ADDR="127.0.0.1:${SRV_PORT}" \
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
echo "== Browser certificates: real TLS client auth through Traefik"
BC="$WORK/bc"; mkdir -p "$BC/traefik"
# One self-signed server certificate serves both the SpireUEM TLS instance and the Traefik edge.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "$BC/edge.key" -out "$BC/edge.crt" -subj "/CN=bc.test" \
    -addext "subjectAltName=DNS:bc.test,DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
go build -o "$WORK/bcseed" ./test/browser_cert_seed
eval "$(DATABASE_URL="$DB_URL" "$WORK/bcseed" "$BC" "$WORK/ca.pem" "$WORK/ca.key")"   # BC_DEVICE_ID, BC_BEARER

# Second SpireUEM instance, same database and device CA, terminating TLS itself so the agent
# certificate is visible to /cert/issue.
SPIRE_POSTURE_INTERVAL=24h DATABASE_URL="$DB_URL" SPIRE_LISTEN_ADDR="127.0.0.1:${TLS_SRV_PORT}" \
SPIRE_MIGRATIONS_PATH="$ROOT/migrations/000001_init_schema.up.sql" \
SPIRE_SESSION_SECRET="ap-e2e-session-secret-key-32b-fixed" SPIRE_ADMIN_PASSWORD="$ADMIN_PW" \
SPIRE_KEK_PATH="$WORK/kek" SPIRE_WIPE_SIGNING_KEY_PATH="$WORK/wipe.key" \
SPIRE_DEVICE_CA_CERT_FILE="$WORK/ca.pem" SPIRE_DEVICE_CA_KEY_FILE="$WORK/ca.key" \
SPIRE_TLS_CERT_FILE="$BC/edge.crt" SPIRE_TLS_KEY_FILE="$BC/edge.key" \
SPIRE_APT_REPO_DIR="$WORK/apt" SPIRE_BUNDLE_STORAGE_DIR="$WORK/bundles" \
    "$WORK/spire-server" > "$WORK/server-tls.log" 2>&1 &
SRV2_PID=$!
for i in $(seq 1 60); do
    c="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$BC/edge.crt" "https://127.0.0.1:${TLS_SRV_PORT}/admin/devices" || true)"
    [[ "$c" == "303" || "$c" == "401" || "$c" == "200" ]] && break
    sleep 1
    if [[ "$i" == 60 ]]; then echo "TLS server did not start"; tail -20 "$WORK/server-tls.log"; exit 1; fi
done

ISSUE="https://127.0.0.1:${TLS_SRV_PORT}/api/v1/desktop/cert/issue"
cat > "$BC/mkcsr.py" <<'PY'
import json, sys
# mkcsr.py PURPOSE USER CSRFILE -> JSON body for /cert/issue
purpose, user, path = sys.argv[1:4]
body = {"purpose": purpose, "csr_pem": open(path).read()}
if user: body["user"] = user
print(json.dumps(body))
PY
cat > "$BC/leaf.py" <<'PY'
import json, sys
# leaf.py RESPONSE.json -> device_certificate_pem
print(json.load(open(sys.argv[1])).get("device_certificate_pem", ""), end="")
PY
# issue NAME PURPOSE USER [curl args...] -> new key NAME.key, leaf NAME.crt, CODE
issue() {
    local name="$1" purpose="$2" user="$3"; shift 3
    openssl ecparam -name prime256v1 -genkey -noout -out "$BC/$name.key" 2>/dev/null
    openssl req -new -key "$BC/$name.key" -subj "/CN=ignored" -out "$BC/$name.csr" 2>/dev/null
    local body; body="$(python3 "$BC/mkcsr.py" "$purpose" "$user" "$BC/$name.csr")"
    CODE="$(curl -s -o "$BC/$name.resp" -w '%{http_code}' --cacert "$BC/edge.crt" \
        -H "Authorization: Bearer $BC_BEARER" -H 'Content-Type: application/json' -d "$body" "$@" "$ISSUE" || true)"
    python3 "$BC/leaf.py" "$BC/$name.resp" > "$BC/$name.crt"
}
AGENT=(--cert "$BC/agent.crt" --key "$BC/agent.key")
issue noagent browser carol;                       NAME=noagent; expect "issue without the agent certificate" 401
issue carolbad browser "../root" "${AGENT[@]}";    NAME=carolbad; expect "issue for an invalid user name" 400
issue carol browser carol "${AGENT[@]}";           NAME=carol; expect "browser certificate issued for carol" 200
issue netcert network "" "${AGENT[@]}";            NAME=netcert; expect "network certificate issued" 200
[[ "$(openssl x509 -in "$BC/carol.crt" -noout -subject 2>/dev/null)" == *"carol@${BC_DEVICE_ID}"* ]] && ok "leaf subject is carol@<device id>" || bad "leaf subject: $(openssl x509 -in "$BC/carol.crt" -noout -subject 2>&1)"
openssl x509 -in "$BC/carol.crt" -noout -ext subjectAltName 2>/dev/null | grep -q "spire://user/carol" && ok "leaf carries spire://user/carol" || bad "leaf has no user SAN"
openssl verify -CAfile "$WORK/ca.pem" -purpose sslclient "$BC/carol.crt" >/dev/null 2>&1 && ok "leaf verifies against the device CA for client auth" || bad "leaf does not verify"

# Forward-auth settings: trusted proxy, certificate header, weak identity OFF.
setcfg() { # setcfg [extra form fields...]
    curl -s -o /dev/null -u "admin:${ADMIN_PW}" --data-urlencode "trusted_proxies=127.0.0.1" \
        --data-urlencode "cert_header=X-Forwarded-Tls-Client-Cert" "$@" \
        "http://127.0.0.1:${SRV_PORT}/admin/access-proxy" || true
}
setcfg

echo "== Traefik terminating TLS, optional client auth against the device CA"
cp "$WORK/ca.pem" "$BC/traefik/ca.pem"; cp "$BC/edge.crt" "$BC/edge.key" "$BC/traefik/"
cat > "$BC/traefik/dyn.yml" <<YML
tls:
  certificates:
    - certFile: /dyn/edge.crt
      keyFile: /dyn/edge.key
  options:
    default:
      clientAuth:
        caFiles: [/dyn/ca.pem]
        clientAuthType: VerifyClientCertIfGiven
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
    pass-cert:
      passTLSClientCert:
        pem: true
    posture:
      forwardAuth:
        address: "${FA}"
        authResponseHeaders: [X-Spire-Device-Id, X-Spire-Posture, X-Spire-Identity-Strength, X-Spire-User]
    chain:
      chain: {middlewares: [add-token, pass-cert, posture, strip-token]}
  services:
    echo:
      loadBalancer:
        servers: [{url: "http://127.0.0.1:${ECHO_PORT}"}]
  routers:
    bc: {rule: "Host(\`bc.test\`)", entryPoints: [websecure], middlewares: [chain], service: echo, tls: {}}
YML
docker rm -f "$TTC" >/dev/null 2>&1 || true
docker run -d --name "$TTC" --network host -v "$BC/traefik:/dyn:ro" traefik:v3 \
    --entrypoints.websecure.address="127.0.0.1:${TLS_EDGE_PORT}" --providers.file.directory=/dyn \
    --global.checknewversion=false --global.sendanonymoususage=false --log.level=ERROR >/dev/null
for i in $(seq 1 30); do
    curl -s -o /dev/null --max-time 2 --cacert "$BC/edge.crt" --resolve "bc.test:${TLS_EDGE_PORT}:127.0.0.1" "https://bc.test:${TLS_EDGE_PORT}/" && break
    sleep 1
done
sleep 1

# breq NAME [curl args...]
breq() {
    local name="$1"; shift
    CODE="$(curl -s -o "$WORK/$name.json" -w '%{http_code}' --max-time 15 --cacert "$BC/edge.crt" \
        --resolve "bc.test:${TLS_EDGE_PORT}:127.0.0.1" "$@" "https://bc.test:${TLS_EDGE_PORT}/app?x=1" || true)"
}
hdr() { python3 "$WORK/jget.py" "$WORK/$1.json" "$2"; }
CARTHDR=(--cert "$BC/carol.crt" --key "$BC/carol.key")
psqlc "UPDATE device_posture SET state='COMPLIANT', valid_until=NOW()+interval '1 hour' WHERE device_id='$BC_DEVICE_ID'" >/dev/null

echo "== Allowed"
NAME=bc1; breq bc1 "${CARTHDR[@]}"; expect "browser certificate on a compliant device" 200
[[ "$(hdr bc1 X-Spire-User)" == "carol" ]] && ok "backend got X-Spire-User=carol" || bad "backend X-Spire-User='$(hdr bc1 X-Spire-User)'"
[[ "$(hdr bc1 X-Spire-Device-Id)" == "$BC_DEVICE_ID" ]] && ok "backend got X-Spire-Device-Id" || bad "backend X-Spire-Device-Id"
[[ "$(hdr bc1 X-Spire-Identity-Strength)" == "strong" ]] && ok "identity strength is strong" || bad "identity strength"
grep -q "$TOKEN" "$WORK/bc1.json" && bad "connector token reached the protected app" || ok "connector token did NOT reach the protected app"
NAME=bc2; breq bc2 "${CARTHDR[@]}" -H "X-Spire-User: root" -H "X-Spire-Device-Id: attacker"; expect "client forges X-Spire-User and X-Spire-Device-Id" 200
[[ "$(hdr bc2 X-Spire-User)" == "carol" && "$(hdr bc2 X-Spire-Device-Id)" == "$BC_DEVICE_ID" ]] && ok "forged X-Spire-* headers were overwritten by the real identity" || bad "forged header reached the app: user='$(hdr bc2 X-Spire-User)' device='$(hdr bc2 X-Spire-Device-Id)'"

echo "== Denied"
NAME=bc3; breq bc3; expect "no client certificate (IP fallback off)" 403
NAME=bc4; breq bc4 --cert "$BC/agent.crt" --key "$BC/agent.key"; expect "the device's AGENT certificate" 403
NAME=bc5; breq bc5 --cert "$BC/netcert.crt" --key "$BC/netcert.key"; expect "a NETWORK certificate" 403
LEAFB64="$(openssl x509 -in "$BC/carol.crt" -outform DER | base64 -w0)"
NAME=bc6; breq bc6 -H "X-Forwarded-Tls-Client-Cert: ${LEAFB64}"; expect "valid certificate pasted into the header, no TLS client certificate" 403
NAME=bc7; breq bc7 --cert "$BC/carol.crt" --key "$BC/carol.key" -H "X-Forwarded-Tls-Client-Cert: bogus"; expect "forged header alongside a real certificate (Traefik overwrites it)" 200
# A certificate from another CA: the TLS handshake itself fails.
openssl ecparam -name prime256v1 -genkey -noout -out "$BC/rogue.key" 2>/dev/null
openssl req -x509 -new -key "$BC/rogue.key" -subj "/CN=SpireUEM Device CA" -days 2 -out "$BC/rogue.crt" 2>/dev/null
NAME=bc8; breq bc8 --cert "$BC/rogue.crt" --key "$BC/rogue.key"; if [[ "$CODE" == "000" || "$CODE" == "403" || "$CODE" == "401" ]]; then ok "certificate from another CA refused (HTTP $CODE)"; else bad "rogue certificate got $CODE"; fi

echo "== Quarantine and revocation take effect at once"
psqlc "UPDATE device_posture SET state='QUARANTINED' WHERE device_id='$BC_DEVICE_ID'" >/dev/null
NAME=bc9; breq bc9 "${CARTHDR[@]}"; expect "quarantined device with a valid browser certificate" 403
psqlc "UPDATE device_posture SET state='COMPLIANT' WHERE device_id='$BC_DEVICE_ID'" >/dev/null
NAME=bc10; breq bc10 "${CARTHDR[@]}"; expect "device compliant again" 200
psqlc "UPDATE device_certificates SET revoked_at=NOW() WHERE device_id='$BC_DEVICE_ID' AND purpose='browser'" >/dev/null
NAME=bc11; breq bc11 "${CARTHDR[@]}"; expect "revoked browser certificate" 403
issue carol2 browser carol "${AGENT[@]}"; NAME=carol2; expect "a new browser certificate is issued after revocation" 200
NAME=bc12; breq bc12 --cert "$BC/carol2.crt" --key "$BC/carol2.key"; expect "the new certificate works" 200

echo "== IP fallback and the user header"
setcfg --data-urlencode "allow_weak_identity=on"
NAME=bc13; breq bc13 --interface 127.0.0.20; expect "no certificate, IP fallback ON, address of the device" 200
[[ "$(hdr bc13 X-Spire-Identity-Strength)" == "weak" ]] && ok "identity strength is weak" || bad "identity strength on fallback"
NAME=bc14; breq bc14 --interface 127.0.0.20 -H "X-Spire-User: root"; expect "IP fallback with a forged X-Spire-User" 200
if [[ -z "$(hdr bc14 X-Spire-User)" ]]; then ok "forged X-Spire-User did not reach the app on the IP fallback path"; else bad "forged X-Spire-User='$(hdr bc14 X-Spire-User)' reached the app on the IP fallback path (the proxy must strip X-Spire-*)"; fi

echo "== Optional: certificate user must be the device's active user"
setcfg --data-urlencode "require_same_user=on"
NAME=bc15; breq bc15 --cert "$BC/carol2.crt" --key "$BC/carol2.key"; expect "same-user ON, active user is carol" 200
psqlc "UPDATE devices SET last_active_user='dave' WHERE id='$BC_DEVICE_ID'" >/dev/null
NAME=bc16; breq bc16 --cert "$BC/carol2.crt" --key "$BC/carol2.key"; expect "same-user ON, active user is dave" 403
setcfg
psqlc "UPDATE devices SET last_active_user='carol' WHERE id='$BC_DEVICE_ID'" >/dev/null
[[ "$(psqlc "SELECT COUNT(*) FROM system_audit_events WHERE action='DEVICE_CERT_ISSUE' AND details::text LIKE '%browser%'")" -ge 2 ]] && ok "browser certificate issuance audited" || bad "issuance not audited"

echo
echo "access proxy E2E: ${PASSES} passed, ${FAILS} failed"
[[ "$FAILS" == 0 ]]
