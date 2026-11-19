#!/usr/bin/env bash
# End-to-end test of the RADIUS / NAC connector against REAL FreeRADIUS 3.2 and a SpireUEM
# server built from this tree. Everything binds to loopback or the Docker bridge address and
# is removed afterwards. Needs: docker, go, curl, python3.
#
# Proves, with radclient inside the FreeRADIUS container:
#   - MAB for a compliant device (weak identity enabled) -> Access-Accept with VLAN attributes
#   - non-compliant -> remediation VLAN / reject, per configuration
#   - unknown MAC -> Access-Reject
#   - weak identity disabled -> MAC request rejected
#   - SpireUEM down -> Access-Reject (fail closed)
# and, for CoA, that a posture change makes SpireUEM send a Disconnect-Request which a real
# FreeRADIUS (acting as the NAS) validates and ACKs, and that a wrong shared secret is not acked.
#
# Usage: scripts/test_radius.sh            (PG_NAME / PG_PORT / API_PORT can be overridden)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PG_NAME="${PG_NAME:-spire-radius-test-pg}"
PG_PORT="${PG_PORT:-55453}"
API_PORT="${API_PORT:-18453}"
FR_PORT=11812
FR_IMAGE="${FR_IMAGE:-freeradius/freeradius-server:3.2.7}"
FR_NAME="spire-radius-test-fr"
DB="radius_e2e_$$"
WORK="$(mktemp -d "${KIROCREW_SCRATCH:-${TMPDIR:-/tmp}}/radius-e2e.XXXXXX")"
ADMINPW="radius-e2e-breakglass-pw"
SERVER_PID=""
STARTED_PG=0
PASS=0
FAIL=0

say() { printf '%s\n' "$*"; }
ok() { PASS=$((PASS + 1)); say "  PASS  $*"; }
bad() { FAIL=$((FAIL + 1)); say "  FAIL  $*"; }

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  docker rm -f "$FR_NAME" >/dev/null 2>&1
  if [ "$STARTED_PG" = 1 ]; then docker rm -f "$PG_NAME" >/dev/null 2>&1; else
    docker exec "$PG_NAME" psql -U spire -d postgres --command="DROP DATABASE IF EXISTS $DB" >/dev/null 2>&1
  fi
}
trap cleanup EXIT

sql() { docker exec -i "$PG_NAME" psql -U spire -d "$DB" -v ON_ERROR_STOP=1 --tuples-only --no-align --command="$1"; }

# radius <attrs>: send an Access-Request from inside the FreeRADIUS container, print the reply.
radius() { printf '%s\n' "$1" | docker exec -i "$FR_NAME" radclient -x -t 5 -r 1 "127.0.0.1:$FR_PORT" auth testing123 2>&1; }

expect_accept() { # name attrs [needle...]
  local name="$1" attrs="$2"; shift 2
  local out; out="$(radius "$attrs")"
  if ! grep -q "Received Access-Accept" <<<"$out"; then bad "$name: expected Access-Accept"; say "$out" | sed 's/^/        /'; return; fi
  for needle in "$@"; do
    if ! grep -q -- "$needle" <<<"$out"; then bad "$name: reply lacks '$needle'"; say "$out" | sed 's/^/        /'; return; fi
  done
  ok "$name"
}
expect_reject() { # name attrs
  local out; out="$(radius "$2")"
  if grep -q "Received Access-Reject" <<<"$out"; then ok "$1"; else bad "$1: expected Access-Reject"; say "$out" | sed 's/^/        /'; fi
}

admin() { # method path json
  local body="${3-}"
  [ -n "$body" ] || body='{}'
  curl -sS -u "admin:$ADMINPW" -H 'Content-Type: application/json' -H 'Accept: application/json' \
    -X "$1" "http://127.0.0.1:$API_PORT$2" -d "$body"
}

# ---------------------------------------------------------------- prerequisites
for bin in docker go curl python3; do command -v "$bin" >/dev/null || { say "missing: $bin"; exit 2; }; done
BRIDGE_IP="$(ip -4 -o addr show docker0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
if [ -z "$BRIDGE_IP" ]; then say "no docker0 address; the CoA part needs a private address the server may send to"; exit 2; fi
say "== workdir $WORK  database $DB  NAS address $BRIDGE_IP"

# ---------------------------------------------------------------- database
if [ -z "$(docker ps -q -f "name=^${PG_NAME}\$")" ]; then
  docker run -d --name "$PG_NAME" -e POSTGRES_USER=spire -e POSTGRES_PASSWORD=spirepassword -e POSTGRES_DB=postgres \
    -p "127.0.0.1:${PG_PORT}:5432" postgres:16-alpine >/dev/null || exit 2
  STARTED_PG=1
fi
for _ in $(seq 1 40); do docker exec "$PG_NAME" pg_isready -U spire >/dev/null 2>&1 && break; sleep 1; done
docker exec "$PG_NAME" psql -U spire -d postgres --command="CREATE DATABASE $DB" >/dev/null || exit 2

# ---------------------------------------------------------------- SpireUEM server
say "== building spire-server"
( cd "$ROOT" && go build -o "$WORK/spire-server" ./cmd/spire-server ) || exit 2
start_server() {
  DATABASE_URL="postgres://spire:spirepassword@127.0.0.1:${PG_PORT}/${DB}?sslmode=disable" \
  SPIRE_LISTEN_ADDR="127.0.0.1:${API_PORT}" SPIRE_MIGRATIONS_PATH="$ROOT/migrations/000001_init_schema.up.sql" \
  SPIRE_SESSION_SECRET="radius-e2e-session-secret-key-32b-fixed" SPIRE_ADMIN_PASSWORD="$ADMINPW" \
  SPIRE_ALLOW_INSECURE_HTTP=1 SPIRE_KEK_PATH="$WORK/kek.pem" SPIRE_APT_REPO_DIR="$WORK/apt" \
  SPIRE_BUNDLE_STORAGE_DIR="$WORK/bundles" SPIRE_WIPE_SIGNING_KEY_PATH="$WORK/wipe.key" \
  "$WORK/spire-server" >>"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 60); do
    curl -fsS "http://127.0.0.1:${API_PORT}/api/admin/v1/openapi.json" >/dev/null 2>&1 && return 0
    kill -0 "$SERVER_PID" 2>/dev/null || { say "server exited; log:"; tail -20 "$WORK/server.log"; return 1; }
    sleep 1
  done
  return 1
}
start_server || exit 2

# Connector credential: a service account with ONLY posture:read.
SA_JSON="$(admin POST /admin/service-accounts '{"name":"freeradius","role":"AUDITOR","scopes":["posture:read"]}')"
TOKEN="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d.get("secret") or "")' "$SA_JSON")"
case "$TOKEN" in spire_sa_*) ok "service account token created";; *) bad "no service account token: $SA_JSON"; exit 1;; esac

# Test devices, posture rows (the posture engine is the only real writer; the test writes
# them directly, as the connector tests do).
sql "INSERT INTO devices (hardware_uuid, hostname, status) VALUES
  ('rad-e2e-ok','rad-e2e-ok','APPROVED'),('rad-e2e-bad','rad-e2e-bad','APPROVED'),
  ('rad-e2e-quar','rad-e2e-quar','APPROVED'),('rad-e2e-stale','rad-e2e-stale','APPROVED')" >/dev/null || exit 1
for pair in "ok:02:aa:00:00:00:01" "bad:02:aa:00:00:00:02" "quar:02:aa:00:00:00:03" "stale:02:aa:00:00:00:04"; do
  name="${pair%%:*}"; mac="${pair#*:}"
  sql "INSERT INTO device_attributes (device_id,key,value_type,value,source)
       SELECT id,'net.primary_mac','string',to_jsonb('$mac'::text),'inventory' FROM devices WHERE hardware_uuid='rad-e2e-$name'" >/dev/null
done
sql "INSERT INTO device_posture (device_id,state,valid_until) SELECT id,
       CASE hardware_uuid WHEN 'rad-e2e-ok' THEN 'COMPLIANT' WHEN 'rad-e2e-bad' THEN 'NONCOMPLIANT'
            WHEN 'rad-e2e-quar' THEN 'QUARANTINED' ELSE 'COMPLIANT' END,
       CASE hardware_uuid WHEN 'rad-e2e-stale' THEN NOW() - interval '1 minute' ELSE NOW() + interval '1 day' END
     FROM devices WHERE hardware_uuid LIKE 'rad-e2e-%'" >/dev/null || exit 1

# ---------------------------------------------------------------- FreeRADIUS
say "== starting FreeRADIUS ($FR_IMAGE)"
FR="$WORK/fr"; mkdir -p "$FR"
docker run --rm --entrypoint cat "$FR_IMAGE" /etc/freeradius/radiusd.conf >"$FR/radiusd.conf.orig" || exit 2
{ echo '$INCLUDE /etc/freeradius/spire_token.conf'; cat "$FR/radiusd.conf.orig"; } >"$FR/radiusd.conf"
printf 'spire_token = "%s"\n' "$TOKEN" >"$FR/spire_token.conf"
sed "s#https://spire.example.com#http://127.0.0.1:${API_PORT}#g" "$ROOT/contrib/freeradius/mods-available/spire" >"$FR/spire.mod"
# Test-only edits of the example site: listen on loopback:$FR_PORT, plus a CoA/Disconnect
# listener on the bridge address so FreeRADIUS can play the NAS.
sed -e "s#ipaddr = \*#ipaddr = 127.0.0.1#" -e "s#port   = 0#port   = ${FR_PORT}#" \
  "$ROOT/contrib/freeradius/sites-available/spire-nac" >"$FR/site"
cat >"$FR/coa-site" <<EOF
server nas-coa {
	listen {
		type = coa
		ipaddr = ${BRIDGE_IP}
		port = 3799
	}
	recv-coa {
		ok
	}
	send-coa {
		ok
	}
}
EOF
cat >"$FR/clients.conf" <<EOF
client localhost {
	ipaddr = 127.0.0.1
	secret = testing123
}
# SpireUEM's source address towards the bridge address depends on the host routing, so the
# test NAS accepts the CoA secret from any source.
client coa-sender {
	ipaddr = 0.0.0.0/0
	secret = coa-e2e-secret
}
EOF
docker rm -f "$FR_NAME" >/dev/null 2>&1
docker run -d --name "$FR_NAME" --network host \
  -v "$FR/radiusd.conf:/etc/freeradius/radiusd.conf:ro" \
  -v "$FR/spire_token.conf:/etc/freeradius/spire_token.conf:ro" \
  -v "$FR/clients.conf:/etc/freeradius/clients.conf:ro" \
  -v "$FR/spire.mod:/etc/freeradius/mods-enabled/spire:ro" \
  -v "$ROOT/contrib/freeradius/policy.d/spire_nac:/etc/freeradius/policy.d/spire_nac:ro" \
  -v "$FR/site:/etc/freeradius/sites-enabled/default:ro" \
  -v "$FR/coa-site:/etc/freeradius/sites-enabled/nas-coa:ro" \
  "$FR_IMAGE" -X >/dev/null || exit 2
sleep 4
if ! docker logs "$FR_NAME" 2>&1 | grep -q "Ready to process requests"; then
  say "FreeRADIUS did not start:"; docker logs "$FR_NAME" 2>&1 | tail -30; exit 2
fi
ok "FreeRADIUS started with the contrib rest module, policy and site"

MAB_OK='User-Name = "02-aa-00-00-00-01", Calling-Station-Id = "02-aa-00-00-00-01", NAS-IP-Address = 10.9.9.9, NAS-Port = 7'
MAB_BAD='User-Name = "02-aa-00-00-00-02", Calling-Station-Id = "02-aa-00-00-00-02", NAS-IP-Address = 10.9.9.9'
MAB_QUAR='User-Name = "02-aa-00-00-00-03", Calling-Station-Id = "02-aa-00-00-00-03", NAS-IP-Address = 10.9.9.9'
MAB_STALE='User-Name = "02-aa-00-00-00-04", Calling-Station-Id = "02-aa-00-00-00-04", NAS-IP-Address = 10.9.9.9'
MAB_UNKNOWN='User-Name = "02-aa-00-00-00-99", Calling-Station-Id = "02-aa-00-00-00-99", NAS-IP-Address = 10.9.9.9'

say "== MAB decisions"
# Defaults: weak identity is OFF, so even a compliant device's MAC is refused.
expect_reject "weak identity disabled (default): compliant MAC rejected" "$MAB_OK"
admin POST /admin/radius/settings '{"allow_weak_identity":true,"compliant_vlan":"10","remediation_vlan":"20"}' >/dev/null
expect_accept "compliant MAC accepted with VLAN attributes" "$MAB_OK" 'Tunnel-Private-Group-Id:0 = "10"' 'Tunnel-Type:0 = VLAN' 'Tunnel-Medium-Type:0 = IEEE-802'
expect_accept "non-compliant MAC -> remediation VLAN" "$MAB_BAD" 'Tunnel-Private-Group-Id:0 = "20"'
expect_reject "quarantined MAC with no quarantine VLAN rejected" "$MAB_QUAR"
admin POST /admin/radius/settings '{"allow_weak_identity":true,"compliant_vlan":"10"}' >/dev/null
expect_reject "non-compliant MAC with no remediation VLAN rejected" "$MAB_BAD"
admin POST /admin/radius/settings '{"allow_weak_identity":true,"compliant_vlan":"10","quarantine_vlan":"666"}' >/dev/null
expect_accept "quarantined MAC -> quarantine VLAN" "$MAB_QUAR" 'Tunnel-Private-Group-Id:0 = "666"'
expect_reject "unknown MAC rejected" "$MAB_UNKNOWN"
expect_reject "stale COMPLIANT verdict (past valid_until) rejected" "$MAB_STALE"
expect_reject "User-Name that is not a MAC rejected by the policy" 'User-Name = "alice", Calling-Station-Id = "02-aa-00-00-00-01"'
expect_reject "User-Name and Calling-Station-Id disagree" 'User-Name = "02-aa-00-00-00-01", Calling-Station-Id = "02-aa-00-00-00-02"'

say "== certificate identity (HTTP-level: no EAP supplicant available)"
sql "INSERT INTO device_certificates (device_id, serial, fingerprint_sha256, not_before, not_after)
     SELECT id, '48879', repeat('ab',32), NOW() - interval '1 hour', NOW() + interval '1 day' FROM devices WHERE hardware_uuid='rad-e2e-ok'" >/dev/null
CERT_BODY='{"TLS-Client-Cert-Serial":{"type":"string","value":["BEEF"]},"User-Name":{"type":"string","value":["host/x"]}}'
code="$(curl -sS -o "$WORK/cert.out" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:${API_PORT}/api/admin/v1/access/radius/authorize" -d "$CERT_BODY")"
if [ "$code" = 200 ] && grep -q spire-accept "$WORK/cert.out" && grep -q '"control:Tmp-String-1":"strong"' "$WORK/cert.out"; then ok "cert serial BEEF (=48879) resolves to the compliant device, strong identity"; else bad "cert request: $code $(cat "$WORK/cert.out")"; fi
code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:${API_PORT}/api/admin/v1/access/radius/authorize" -d '{"TLS-Client-Cert-Serial":{"value":["DEAD"]},"Calling-Station-Id":{"value":["02-aa-00-00-00-01"]}}')"
[ "$code" = 403 ] && ok "unknown cert serial is rejected even with a compliant MAC alongside" || bad "unknown cert + good MAC: $code"

say "== CoA / Disconnect (FreeRADIUS plays the NAS on ${BRIDGE_IP}:3799)"
NAS_JSON="$(admin POST /admin/radius/nas "{\"name\":\"e2e-nas\",\"address\":\"${BRIDGE_IP}\",\"secret\":\"coa-e2e-secret\"}")"
NAS_ID="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["nas_client"]["id"])' "$NAS_JSON" 2>/dev/null)"
[ -n "$NAS_ID" ] && ok "NAS client registered (secret sealed, not echoed)" || { bad "NAS create: $NAS_JSON"; }
case "$NAS_JSON" in *coa-e2e-secret*) bad "NAS create response echoed the secret";; *) ok "NAS create response does not contain the secret";; esac
expect_accept "compliant MAC from the registered NAS opens a tracked session" \
  "User-Name = \"02-aa-00-00-00-01\", Calling-Station-Id = \"02-aa-00-00-00-01\", NAS-IP-Address = ${BRIDGE_IP}, NAS-Identifier = \"sw-e2e\"" 'Tunnel-Private-Group-Id:0 = "10"'
n="$(sql "SELECT count(*) FROM radius_sessions WHERE nas_address='${BRIDGE_IP}'")"
if [ "$n" = 1 ]; then ok "one session recorded"; else bad "sessions recorded: $n"; docker logs "$FR_NAME" 2>&1 | grep -i "NAS-IP\|Sending JSON\|POST data" | tail -6 | sed 's/^/        /'; fi
# The posture changes (the posture engine's job; the test does what UpsertDevicePosture does).
sql "UPDATE device_posture SET state='NONCOMPLIANT', state_changed_at=NOW(), evaluated_at=NOW()
     WHERE device_id=(SELECT id FROM devices WHERE hardware_uuid='rad-e2e-ok')" >/dev/null
status=""
for _ in $(seq 1 30); do
  status="$(sql "SELECT status FROM radius_coa_deliveries WHERE nas_address='${BRIDGE_IP}' ORDER BY created_at DESC LIMIT 1")"
  [ "$status" = ACKED ] && break
  sleep 1
done
[ "$status" = ACKED ] && ok "SpireUEM's Disconnect-Request was ACKed by FreeRADIUS (signature + Message-Authenticator verified by a third party)" || { bad "delivery status: '$status'"; sql "SELECT status, attempts, last_error FROM radius_coa_deliveries WHERE nas_address='${BRIDGE_IP}'" | sed 's/^/        /'; docker logs "$FR_NAME" 2>&1 | grep -i -B2 -A12 "disconnect\|coa" | tail -30 | sed 's/^/        /'; }
if docker logs "$FR_NAME" 2>&1 | grep -q "Received Disconnect-Request"; then ok "FreeRADIUS logged the Disconnect-Request"; else bad "FreeRADIUS never logged a Disconnect-Request"; fi
docker logs "$FR_NAME" 2>&1 | grep -A8 "Received Disconnect-Request" | head -10 | sed 's/^/        /'
sleep 7
n="$(sql "SELECT count(*) FROM radius_coa_deliveries WHERE nas_address='${BRIDGE_IP}'")"
[ "$n" = 1 ] && ok "exactly one delivery for one posture change" || bad "deliveries: $n"

# Wrong shared secret on the NAS side: FreeRADIUS drops the request, SpireUEM must not report success.
admin POST "/admin/radius/nas/${NAS_ID}" "{\"name\":\"e2e-nas\",\"address\":\"${BRIDGE_IP}\",\"enabled\":true,\"secret\":\"not-the-right-secret\"}" >/dev/null
sql "UPDATE device_posture SET state='COMPLIANT', state_changed_at=NOW() WHERE device_id=(SELECT id FROM devices WHERE hardware_uuid='rad-e2e-ok')" >/dev/null
expect_accept "device re-admitted (session tracked again)" \
  "User-Name = \"02-aa-00-00-00-01\", Calling-Station-Id = \"02-aa-00-00-00-01\", NAS-IP-Address = ${BRIDGE_IP}" 'Tunnel-Private-Group-Id:0 = "10"'
sleep 1
sql "UPDATE device_posture SET state='QUARANTINED', state_changed_at=NOW() WHERE device_id=(SELECT id FROM devices WHERE hardware_uuid='rad-e2e-ok')" >/dev/null
for _ in $(seq 1 40); do
  status="$(sql "SELECT status FROM radius_coa_deliveries WHERE nas_address='${BRIDGE_IP}' AND posture_state='QUARANTINED' ORDER BY created_at DESC LIMIT 1")"
  case "$status" in ACKED|FAILED|NAKED) break;; esac
  sleep 2
done
case "$status" in ACKED) bad "a Disconnect signed with the wrong secret was reported ACKED";; *) ok "wrong shared secret: not acknowledged (status '${status:-PENDING}')";; esac

say "== SpireUEM down -> reject"
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=""
sleep 1
expect_reject "SpireUEM unreachable: compliant MAC rejected" "$MAB_OK"
start_server || exit 2
expect_accept "SpireUEM back: access restored" "$MAB_OK" 'Tunnel-Private-Group-Id:0'

say ""
say "== result: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
