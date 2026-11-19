#!/usr/bin/env bash
# Real-Authentik test of contrib/authentik/spire_posture_policy.py: an authentik server and worker
# plus Postgres in Docker, a SpireUEM server built from this checkout, the policy created through
# authentik's API and evaluated with authentik's own policy test endpoint.
#
# Everything binds to 127.0.0.1 and is removed on exit. It never contacts a real authentik.
# First start of authentik runs its migrations and takes a few minutes.
#
# Usage: scripts/test_access_authentik.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AK_IMAGE="${AK_IMAGE:-ghcr.io/goauthentik/server:2026.2}"
SPIRE_PG_PORT="${AP_PG_PORT:-55452}"
AK_PG_PORT="${AK_PG_PORT:-55472}"
SRV_PORT="${AP_SERVER_PORT:-18395}"
AK_HTTP="${AK_HTTP_PORT:-19000}"
PGC=spire-ak-e2e-spirepg
AKPGC=spire-ak-e2e-akpg
AKC=spire-ak-e2e-server
AKW=spire-ak-e2e-worker
WORK="$(mktemp -d "${KIROCREW_SCRATCH:-${TMPDIR:-/tmp}}/ak-e2e.XXXXXX")"
SPIRE_DB="postgres://spire:spirepassword@127.0.0.1:${SPIRE_PG_PORT}/spire_uem?sslmode=disable"
AK_BOOT_TOKEN="ak-e2e-bootstrap-token-$(date +%s)"
SRV_PID=""
FAILS=0
PASSES=0

cleanup() {
    docker rm -f "$AKC" "$AKW" "$AKPGC" "$PGC" >/dev/null 2>&1 || true
    [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null || true
}
trap cleanup EXIT
ok()  { PASSES=$((PASSES+1)); echo "  PASS  $*"; }
bad() { FAILS=$((FAILS+1));  echo "  FAIL  $*"; }

echo "== SpireUEM (Postgres + server + seed)"
docker rm -f "$PGC" >/dev/null 2>&1 || true
docker run -d --name "$PGC" -e POSTGRES_USER=spire -e POSTGRES_PASSWORD=spirepassword -e POSTGRES_DB=spire_uem \
    -p "127.0.0.1:${SPIRE_PG_PORT}:5432" postgres:16-alpine >/dev/null
for i in $(seq 1 40); do docker exec "$PGC" pg_isready -U spire -d spire_uem >/dev/null 2>&1 && break; sleep 1; done
go build -o "$WORK/spire-server" ./cmd/spire-server
go build -o "$WORK/seed" ./test/access_proxy_seed
mkdir -p "$WORK/apt" "$WORK/bundles"
DATABASE_URL="$SPIRE_DB" SPIRE_LISTEN_ADDR="127.0.0.1:${SRV_PORT}" \
SPIRE_MIGRATIONS_PATH="$ROOT/migrations/000001_init_schema.up.sql" \
SPIRE_SESSION_SECRET="ak-e2e-session-secret-key-32b-fixed" SPIRE_ADMIN_PASSWORD="ak-e2e-breakglass-pw" \
SPIRE_KEK_PATH="$WORK/kek" SPIRE_WIPE_SIGNING_KEY_PATH="$WORK/wipe.key" \
SPIRE_DEVICE_CA_CERT_FILE="$WORK/ca.pem" SPIRE_DEVICE_CA_KEY_FILE="$WORK/ca.key" \
SPIRE_APT_REPO_DIR="$WORK/apt" SPIRE_BUNDLE_STORAGE_DIR="$WORK/bundles" \
    "$WORK/spire-server" > "$WORK/server.log" 2>&1 &
SRV_PID=$!
for i in $(seq 1 60); do
    c="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${SRV_PORT}/admin/devices" || true)"
    [[ "$c" == "303" || "$c" == "401" || "$c" == "200" ]] && break
    sleep 1
done
eval "$(DATABASE_URL="$SPIRE_DB" "$WORK/seed")"   # SPIRE_CONNECTOR_TOKEN, GOOD_DEVICE_ID

echo "== authentik (Postgres + server + worker), token only in the container environment"
docker rm -f "$AKPGC" >/dev/null 2>&1 || true
docker run -d --name "$AKPGC" -e POSTGRES_USER=authentik -e POSTGRES_PASSWORD=akpass -e POSTGRES_DB=authentik \
    -p "127.0.0.1:${AK_PG_PORT}:5432" postgres:16-alpine >/dev/null
for i in $(seq 1 40); do docker exec "$AKPGC" pg_isready -U authentik -d authentik >/dev/null 2>&1 && break; sleep 1; done
AK_ENV=(-e AUTHENTIK_SECRET_KEY=ak-e2e-secret-key-not-for-production-0123456789
        -e AUTHENTIK_POSTGRESQL__HOST=127.0.0.1 -e AUTHENTIK_POSTGRESQL__PORT="${AK_PG_PORT}"
        -e AUTHENTIK_POSTGRESQL__USER=authentik -e AUTHENTIK_POSTGRESQL__PASSWORD=akpass -e AUTHENTIK_POSTGRESQL__NAME=authentik
        -e AUTHENTIK_BOOTSTRAP_PASSWORD=ak-e2e-admin-pw -e AUTHENTIK_BOOTSTRAP_TOKEN="$AK_BOOT_TOKEN"
        -e AUTHENTIK_LISTEN__HTTP="127.0.0.1:${AK_HTTP}" -e AUTHENTIK_LISTEN__HTTPS="127.0.0.1:19443"
        -e AUTHENTIK_LISTEN__METRICS="127.0.0.1:19300" -e AUTHENTIK_LISTEN__DEBUG="127.0.0.1:19900"
        -e AUTHENTIK_ERROR_REPORTING__ENABLED=false -e AUTHENTIK_DISABLE_UPDATE_CHECK=true
        -e SPIRE_POSTURE_TOKEN="$SPIRE_CONNECTOR_TOKEN")
docker rm -f "$AKC" "$AKW" >/dev/null 2>&1 || true
docker run -d --name "$AKC" --network host "${AK_ENV[@]}" "$AK_IMAGE" server >/dev/null
docker run -d --name "$AKW" --network host "${AK_ENV[@]}" -e AUTHENTIK_LISTEN__METRICS="127.0.0.1:19301" "$AK_IMAGE" worker >/dev/null
AK="http://127.0.0.1:${AK_HTTP}"
echo "  waiting for authentik to migrate and start (can take several minutes)..."
for i in $(seq 1 120); do
    c="$(curl -s -o /dev/null -w '%{http_code}' "$AK/-/health/ready/" || true)"
    [[ "$c" == 2?? ]] && break
    sleep 5
    if [[ "$i" == 120 ]]; then echo "authentik did not become ready"; docker logs --tail 30 "$AKC"; exit 1; fi
done
ak() { # ak METHOD PATH [XFF] [BODY]
    local args=(-s --max-time 60 -X "$1" -H "Authorization: Bearer $AK_BOOT_TOKEN" -H "Content-Type: application/json")
    [[ -n "${3:-}" ]] && args+=(-H "X-Forwarded-For: $3")
    [[ -n "${4:-}" ]] && args+=(-d "$4")
    curl "${args[@]}" "$AK$2"
}
cat > "$WORK/build.py" <<'PY'
import json, sys
# build.py KIND SPIRE_URL NAME [TOKEN_ENV]  -> JSON body for POST /api/v3/policies/expression/
src = open("contrib/authentik/spire_posture_policy.py").read()
src = src.replace('SPIRE_URL = "https://spire.example.internal"', 'SPIRE_URL = "%s"' % sys.argv[2])
if len(sys.argv) > 4:
    src = src.replace('TOKEN_ENV = "SPIRE_POSTURE_TOKEN"', 'TOKEN_ENV = "%s"' % sys.argv[4])
print(json.dumps({"name": sys.argv[3], "expression": src, "execution_logging": True}))
PY
cat > "$WORK/jq.py" <<'PY'
import json, sys
# jq.py FIELD  (reads JSON on stdin-less: file path argv[2])
d = json.load(open(sys.argv[2]))
v = d
for part in sys.argv[1].split("."):
    v = v[int(part)] if part.isdigit() else v.get(part)
print(json.dumps(v) if isinstance(v, (list, dict)) else v)
PY

echo "== create policies through the authentik API"
UPK=""
for i in $(seq 1 60); do   # the bootstrap user and token are created just after the server reports ready
    ak GET "/api/v3/core/users/?username=akadmin" > "$WORK/u.json" || true
    UPK="$(python3 "$WORK/jq.py" results.0.pk "$WORK/u.json" 2>/dev/null || true)"
    [[ -n "$UPK" && "$UPK" != "None" ]] && break
    sleep 5
done
[[ -n "$UPK" && "$UPK" != "None" ]] || { echo "authentik API not usable: $(head -c 300 "$WORK/u.json")"; exit 1; }
mkpol() { # mkpol NAME SPIRE_URL [TOKEN_ENV] -> prints pk
    local body; body="$(python3 "$WORK/build.py" x "$2" "$1" ${3:+"$3"})"
    ak POST /api/v3/policies/expression/ "" "$body" > "$WORK/pol-$1.json"
    python3 "$WORK/jq.py" pk "$WORK/pol-$1.json"
}
POL="$(mkpol spire-posture "http://127.0.0.1:${SRV_PORT}")"
POL_DEADURL="$(mkpol spire-dead-url "http://127.0.0.1:1")"
POL_NOTOKEN="$(mkpol spire-no-token "http://127.0.0.1:${SRV_PORT}" SPIRE_TOKEN_NOT_SET)"
[[ -n "$POL" && "$POL" != "None" ]] && ok "policy created (pk $POL)" || { bad "policy creation failed: $(cat "$WORK/pol-spire-posture.json")"; exit 1; }

evalpol() { # evalpol PK CLIENT_IP -> sets PASSING and writes $WORK/res.json
    ak POST "/api/v3/policies/all/$1/test/" "$2" "{\"user\": $UPK, \"context\": {}}" > "$WORK/res.json"
    PASSING="$(python3 "$WORK/jq.py" passing "$WORK/res.json")"
}

echo "== evaluate with authentik's policy test endpoint (client address via X-Forwarded-For from a trusted peer)"
evalpol "$POL" 127.0.0.2; [[ "$PASSING" == "True" ]] && ok "compliant device address passes" || bad "compliant address: $(cat "$WORK/res.json")"
evalpol "$POL" 127.0.0.3; [[ "$PASSING" == "False" ]] && ok "noncompliant device address is denied" || bad "noncompliant: $(cat "$WORK/res.json")"
grep -q "does not meet the security requirements" "$WORK/res.json" && ok "deny carries the user-visible message" || bad "no deny message: $(cat "$WORK/res.json")"
evalpol "$POL" 127.0.0.4; [[ "$PASSING" == "False" ]] && ok "unknown address is denied" || bad "unknown: $(cat "$WORK/res.json")"
evalpol "$POL" 127.0.0.5; [[ "$PASSING" == "False" ]] && ok "two devices on the address (ambiguous) is denied" || bad "ambiguous: $(cat "$WORK/res.json")"
evalpol "$POL_DEADURL" 127.0.0.2; [[ "$PASSING" == "False" ]] && ok "SpireUEM unreachable fails closed" || bad "dead url: $(cat "$WORK/res.json")"
evalpol "$POL_NOTOKEN" 127.0.0.2; [[ "$PASSING" == "False" ]] && ok "missing token fails closed" || bad "no token: $(cat "$WORK/res.json")"
grep -q "spire_sa_" "$WORK/res.json" && bad "token leaked into the policy result" || ok "token not present in the policy result"

echo "== posture change is seen on the next evaluation"
DEVB="$(docker exec -i "$PGC" psql -U spire -d spire_uem --tuples-only --no-align --command="SELECT id FROM devices WHERE hostname='e2e-noncompliant'")"
docker exec -i "$PGC" psql -U spire -d spire_uem --command="UPDATE device_posture SET state='COMPLIANT' WHERE device_id='$DEVB'" >/dev/null
evalpol "$POL" 127.0.0.3; [[ "$PASSING" == "True" ]] && ok "device became COMPLIANT -> pass" || bad "after fix: $(cat "$WORK/res.json")"
docker exec -i "$PGC" psql -U spire -d spire_uem --command="UPDATE device_posture SET state='QUARANTINED' WHERE device_id='$DEVB'" >/dev/null
evalpol "$POL" 127.0.0.3; [[ "$PASSING" == "False" ]] && ok "device QUARANTINED -> deny" || bad "after quarantine: $(cat "$WORK/res.json")"

echo
echo "authentik E2E: ${PASSES} passed, ${FAILS} failed"
[[ "$FAILS" == 0 ]]
