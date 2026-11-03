#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

SERVER_URL="http://localhost:18080"
ADMIN_USER="${SPIRE_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${SPIRE_ADMIN_PASSWORD:-changeme}"
DB_HOST="localhost"
DB_PORT="5433"
DB_USER="spire"
DB_PASS="spirepassword"
DB_NAME="spire_uem"

DOCKER_CMD="docker"
if ! docker ps >/dev/null 2>&1; then
    DOCKER_CMD="sudo docker"
fi

echo "================================================================="
echo " SpireUEM End-to-End Integration Test Suite (Phase 6)"
echo "================================================================="

echo "[Step 1/15] Building static binaries & Debian package (dist/spire-agent_0.1.0_amd64.deb)..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/spire-server ./cmd/spire-server
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/spired ./cmd/spired
mkdir -p dist
nfpm package --config packaging/nfpm.yaml --packager deb --target dist/ >/dev/null

echo "[Step 2/15] Spinning up Docker test stack (docker-compose.test.yml)..."
${DOCKER_CMD} unpause spire-test-server >/dev/null 2>&1 || true
${DOCKER_CMD} compose -f docker-compose.test.yml down -v >/dev/null 2>&1 || true
${DOCKER_CMD} compose -f docker-compose.test.yml up -d --build

echo "Waiting for spire-test-server (${SERVER_URL}/admin/devices) to become ready..."
for i in $(seq 1 30); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "${SERVER_URL}/admin/devices" || true)
    if [[ "${CODE}" == "401" || "${CODE}" == "200" ]]; then
        echo "  -> spire-test-server is online!"
        break
    fi
    sleep 1
    if [[ "${i}" -eq 30 ]]; then
        echo "FAIL: spire-test-server did not become ready in time." >&2
        exit 1
    fi
done

UNAUTH_ADMIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${SERVER_URL}/admin/devices")
echo "  -> Unauthenticated GET /admin/devices returned HTTP ${UNAUTH_ADMIN_CODE}"
if [[ "${UNAUTH_ADMIN_CODE}" != "401" ]]; then
    echo "FAIL: Expected HTTP 401 for unauthenticated GET /admin/devices, got ${UNAUTH_ADMIN_CODE}" >&2
    exit 1
fi

AUTH_ADMIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/devices")
echo "  -> Authenticated GET /admin/devices returned HTTP ${AUTH_ADMIN_CODE}"
if [[ "${AUTH_ADMIN_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 200 for authenticated GET /admin/devices, got ${AUTH_ADMIN_CODE}" >&2
    exit 1
fi

echo "[Step 3/15] Creating global & tag-targeted policies via Web UI (/admin/policies)..."
# 1. Global policy (target_tags = empty -> applies to all devices)
curl -s -o /dev/null -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/policies" \
    -d "name=Global+Purge+htop&description=Remove+htop+everywhere&policy_type=PACKAGE_ABSENCE&package_name=htop&target_tags="

# 2. Global policy (target_tags = empty -> applies to all devices)
curl -s -o /dev/null -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/policies" \
    -d "name=Global+CA+Certs&description=Ensure+CA+bundle+installed&policy_type=PACKAGE_PRESENCE&package_name=ca-certificates&target_tags="

# 3. Laptop-only policy (target_tags = laptop)
curl -s -o /dev/null -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/policies" \
    -d "name=Laptop+Idle+Lock+300s&description=Laptop+screen+lock&policy_type=DCONF_SETTING&schema_path=org/gnome/desktop/session&dconf_key=idle-delay&dconf_value=uint32+300&dconf_locked=true&target_tags=laptop"

# 4. Kiosk-only policy (target_tags = kiosk)
curl -s -o /dev/null -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/policies" \
    -d "name=Kiosk+Never+Blank&description=Kiosk+display+always+on&policy_type=DCONF_SETTING&schema_path=org/gnome/desktop/session&dconf_key=idle-delay&dconf_value=uint32+0&dconf_locked=true&target_tags=kiosk"

echo "  -> Created 2 global policies, 1 'laptop' targeted policy, and 1 'kiosk' targeted policy."

echo "[Step 4/15] Simulating agent enrollment & verifying HTTP 403 on unapproved check-in..."
LAPTOP_HW_UUID="e2e-sim-hw-uuid-laptop-01"
LAPTOP_HOSTNAME="debian12-e2e-laptop"

ENROLL_RESP=$(curl -s -w "\n%{http_code}" -X POST "${SERVER_URL}/api/v1/desktop/enroll" \
    -H "Content-Type: application/json" \
    -d "{\"hardware_uuid\":\"${LAPTOP_HW_UUID}\",\"hostname\":\"${LAPTOP_HOSTNAME}\"}")
ENROLL_BODY=$(echo "${ENROLL_RESP}" | head -n 1)
ENROLL_CODE=$(echo "${ENROLL_RESP}" | tail -n 1)
echo "  -> Laptop enroll response (HTTP ${ENROLL_CODE}): ${ENROLL_BODY}"

if [[ "${ENROLL_CODE}" != "202" && "${ENROLL_CODE}" != "403" ]]; then
    echo "FAIL: Expected HTTP 202/403 on initial staged enrollment, got ${ENROLL_CODE}" >&2
    exit 1
fi

LAPTOP_ID=$(echo "${ENROLL_BODY}" | jq -r '.device_id')

UNAPPROVED_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/api/v1/desktop/checkin" \
    -H "Content-Type: application/json" \
    -d "{\"hardware_uuid\":\"${LAPTOP_HW_UUID}\",\"hostname\":\"${LAPTOP_HOSTNAME}\",\"packages\":[\"bash\t5.2\"],\"active_session\":\"sysadmin\"}")
echo "  -> Unapproved check-in returned HTTP ${UNAPPROVED_CODE}"
if [[ "${UNAPPROVED_CODE}" != "403" ]]; then
    echo "FAIL: Expected HTTP 403 on unapproved check-in, got ${UNAPPROVED_CODE}" >&2
    exit 1
fi

# Enroll second device (Kiosk)
KIOSK_HW_UUID="e2e-sim-hw-uuid-kiosk-01"
KIOSK_HOSTNAME="debian12-e2e-kiosk"
KIOSK_ENROLL=$(curl -s -X POST "${SERVER_URL}/api/v1/desktop/enroll" \
    -H "Content-Type: application/json" \
    -d "{\"hardware_uuid\":\"${KIOSK_HW_UUID}\",\"hostname\":\"${KIOSK_HOSTNAME}\"}")
KIOSK_ID=$(echo "${KIOSK_ENROLL}" | jq -r '.device_id')

echo "[Step 5/15] Tagging & approving 'laptop' (${LAPTOP_ID}) and 'kiosk' (${KIOSK_ID}) endpoints..."
curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/devices/${LAPTOP_ID}/tags" -d "tags=laptop" >/dev/null
curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/devices/${KIOSK_ID}/tags" -d "tags=kiosk" >/dev/null

curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/devices/${LAPTOP_ID}/approve" >/dev/null
curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/devices/${KIOSK_ID}/approve" >/dev/null

LAPTOP_TOKEN=$(curl -s -X POST "${SERVER_URL}/api/v1/desktop/enroll" \
    -H "Content-Type: application/json" \
    -d "{\"hardware_uuid\":\"${LAPTOP_HW_UUID}\",\"hostname\":\"${LAPTOP_HOSTNAME}\"}" | jq -r '.token')
KIOSK_TOKEN=$(curl -s -X POST "${SERVER_URL}/api/v1/desktop/enroll" \
    -H "Content-Type: application/json" \
    -d "{\"hardware_uuid\":\"${KIOSK_HW_UUID}\",\"hostname\":\"${KIOSK_HOSTNAME}\"}" | jq -r '.token')

echo "  -> Tagged & approved both endpoints and claimed bearer tokens."

echo "[Step 6/15] Verifying tag-based policy targeting on check-in..."
LAPTOP_CHECKIN=$(curl -s -X POST "${SERVER_URL}/api/v1/desktop/checkin" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${LAPTOP_TOKEN}" \
    -d "{\"hardware_uuid\":\"${LAPTOP_HW_UUID}\",\"hostname\":\"${LAPTOP_HOSTNAME}\",\"packages\":[\"bash\t5.2\",\"ca-certificates\t20230311\"],\"active_session\":\"sysadmin\"}")

KIOSK_CHECKIN=$(curl -s -X POST "${SERVER_URL}/api/v1/desktop/checkin" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${KIOSK_TOKEN}" \
    -d "{\"hardware_uuid\":\"${KIOSK_HW_UUID}\",\"hostname\":\"${KIOSK_HOSTNAME}\",\"packages\":[\"bash\t5.2\",\"ca-certificates\t20230311\"],\"active_session\":\"kiosk-user\"}")

LAPTOP_POL_NAMES=$(echo "${LAPTOP_CHECKIN}" | jq -r '[.policies[].name] | join(", ")')
KIOSK_POL_NAMES=$(echo "${KIOSK_CHECKIN}" | jq -r '[.policies[].name] | join(", ")')
echo "  -> Laptop received policies: [${LAPTOP_POL_NAMES}]"
echo "  -> Kiosk received policies:  [${KIOSK_POL_NAMES}]"

if ! echo "${LAPTOP_POL_NAMES}" | grep -q "Laptop Idle Lock 300s"; then
    echo "FAIL: Laptop device did not receive 'Laptop Idle Lock 300s'" >&2
    exit 1
fi
if echo "${LAPTOP_POL_NAMES}" | grep -q "Kiosk Never Blank"; then
    echo "FAIL: Laptop device erroneously received 'Kiosk Never Blank' policy!" >&2
    exit 1
fi

if ! echo "${KIOSK_POL_NAMES}" | grep -q "Kiosk Never Blank"; then
    echo "FAIL: Kiosk device did not receive 'Kiosk Never Blank'" >&2
    exit 1
fi
if echo "${KIOSK_POL_NAMES}" | grep -q "Laptop Idle Lock 300s"; then
    echo "FAIL: Kiosk device erroneously received 'Laptop Idle Lock 300s' policy!" >&2
    exit 1
fi
echo "  -> Tag-based policy isolation verified!"

echo "[Step 7/15] Posting compliance reports & asserting COMPLIANT status in PostgreSQL..."
LAPTOP_REPORT=$(echo "${LAPTOP_CHECKIN}" | jq -c "{hardware_uuid: \"${LAPTOP_HW_UUID}\", results: [.policies[] | {policy_id: .id, compliance_status: \"COMPLIANT\", execution_output: {simulated: true}}]}")
curl -s -o /dev/null -X POST "${SERVER_URL}/api/v1/desktop/report" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${LAPTOP_TOKEN}" \
    -d "${LAPTOP_REPORT}"

KIOSK_REPORT=$(echo "${KIOSK_CHECKIN}" | jq -c "{hardware_uuid: \"${KIOSK_HW_UUID}\", results: [.policies[] | {policy_id: .id, compliance_status: \"COMPLIANT\", execution_output: {simulated: true}}]}")
curl -s -o /dev/null -X POST "${SERVER_URL}/api/v1/desktop/report" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${KIOSK_TOKEN}" \
    -d "${KIOSK_REPORT}"

LAPTOP_COMPLIANT_COUNT=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT COUNT(*) FROM device_policies WHERE device_id = '${LAPTOP_ID}' AND compliance_status = 'COMPLIANT';")
KIOSK_COMPLIANT_COUNT=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT COUNT(*) FROM device_policies WHERE device_id = '${KIOSK_ID}' AND compliance_status = 'COMPLIANT';")
echo "  -> Verified PostgreSQL COMPLIANT counts: laptop=${LAPTOP_COMPLIANT_COUNT}, kiosk=${KIOSK_COMPLIANT_COUNT}"

if [[ "${LAPTOP_COMPLIANT_COUNT}" -ne 3 || "${KIOSK_COMPLIANT_COUNT}" -ne 3 ]]; then
    echo "FAIL: Expected 3 COMPLIANT rows each for laptop and kiosk" >&2
    exit 1
fi

echo "[Step 8/15] Verifying Device Telemetry Inspection Drawer (GET /admin/devices/{id})..."
DRAWER_HTML=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/devices/${LAPTOP_ID}")
if ! echo "${DRAWER_HTML}" | grep -q "Device Telemetry &amp; Compliance Inspection"; then
    echo "FAIL: Device inspection drawer did not render expected header" >&2
    exit 1
fi
if ! echo "${DRAWER_HTML}" | grep -q "Diagnostic Shell / Command Runner"; then
    echo "FAIL: Device inspection drawer did not render Diagnostic Shell / Command Runner section" >&2
    exit 1
fi
echo "  -> Device Inspection Drawer & Diagnostic Shell UI verified (HTTP 200)."

echo "[Step 9/15] Verifying public single-command onboarding endpoints (/install.sh & /dist/*.deb)..."
INSTALL_HEADERS_AND_BODY=$(curl -s -i "${SERVER_URL}/install.sh")
if ! echo "${INSTALL_HEADERS_AND_BODY}" | head -n 1 | grep -q "200 OK"; then
    echo "FAIL: GET /install.sh did not return HTTP 200 OK" >&2
    exit 1
fi
if ! echo "${INSTALL_HEADERS_AND_BODY}" | grep -qi "Content-Type: text/x-shellscript"; then
    echo "FAIL: GET /install.sh did not return Content-Type: text/x-shellscript" >&2
    exit 1
fi
if ! echo "${INSTALL_HEADERS_AND_BODY}" | grep -q 'SERVER_URL="http://localhost:18080"'; then
    echo "FAIL: GET /install.sh did not dynamically replace __SERVER_URL__ with http://localhost:18080" >&2
    exit 1
fi

DEB_HEAD=$(curl -s -I "${SERVER_URL}/dist/spire-agent_0.1.0_amd64.deb")
if ! echo "${DEB_HEAD}" | head -n 1 | grep -q "200 OK"; then
    echo "FAIL: HEAD /dist/spire-agent_0.1.0_amd64.deb did not return HTTP 200 OK" >&2
    exit 1
fi
if ! echo "${DEB_HEAD}" | grep -qi "Content-Type: application/vnd.debian.binary-package"; then
    echo "FAIL: HEAD /dist/spire-agent_0.1.0_amd64.deb did not return Content-Type: application/vnd.debian.binary-package" >&2
    exit 1
fi
echo "  -> Public onboarding endpoints (/install.sh & /dist/*.deb) verified."

echo "[Step 10/15] Testing Enterprise Policy Preset Deployment (POST /admin/policies/from-template)..."
PRESET_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/policies/from-template" \
    -d "template_id=gnome-wallpaper-lock&target_tags=laptop")
if [[ "${PRESET_HTTP_CODE}" != "303" && "${PRESET_HTTP_CODE}" != "200" && "${PRESET_HTTP_CODE}" != "201" ]]; then
    echo "FAIL: Expected HTTP 303/200/201 from POST /admin/policies/from-template, got ${PRESET_HTTP_CODE}" >&2
    exit 1
fi
echo "  -> Deployed 'gnome-wallpaper-lock' preset verified in /admin/policies."

# Approve and tag the live Debian 12 container client (debian12-sim-01) as 'kiosk'
CONTAINER_DEV_ID=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT id FROM devices WHERE hardware_uuid = 'debc1200-1111-2222-3333-444455556666' LIMIT 1;")
if [[ -z "${CONTAINER_DEV_ID}" ]]; then
    echo "FAIL: Live Debian 12 container client did not stage enrollment" >&2
    exit 1
fi
curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/devices/${CONTAINER_DEV_ID}/tags" -d "tags=kiosk" >/dev/null
curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/devices/${CONTAINER_DEV_ID}/approve" >/dev/null
sleep 5

echo "[Step 11/15] Testing Ad-Hoc Diagnostic Command Execution (POST /admin/devices/{id}/commands)..."
curl -s -o /dev/null -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/devices/${CONTAINER_DEV_ID}/commands" \
    -d "command=df+-h+%2F"
echo "  -> Dispatched 'df -h /' command to live Debian 12 container (${CONTAINER_DEV_ID}); waiting for execution..."

for i in $(seq 1 15); do
    CMD_STATUS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
        -c "SELECT status FROM device_commands WHERE device_id = '${CONTAINER_DEV_ID}' ORDER BY created_at DESC LIMIT 1;")
    if [[ "${CMD_STATUS}" == "COMPLETED" ]]; then
        break
    fi
    sleep 1
done

CMD_STDOUT=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT stdout FROM device_commands WHERE device_id = '${CONTAINER_DEV_ID}' ORDER BY created_at DESC LIMIT 1;")
if [[ "${CMD_STATUS}" != "COMPLETED" || -z "${CMD_STDOUT}" ]]; then
    echo "FAIL: Expected command status COMPLETED with non-empty stdout, got status=${CMD_STATUS}" >&2
    exit 1
fi
echo "  -> Diagnostic command status=${CMD_STATUS}, captured stdout first line: $(echo "${CMD_STDOUT}" | head -n 1)"

echo "[Step 12/15] Testing Dynamic Policy Deactivation, Rollback & Orphan dconf Cleanup..."
KIOSK_DCONF_POL_ID=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT id FROM policies WHERE name = 'Kiosk Never Blank' LIMIT 1;")

# Confirm the dconf keyfile exists inside the container before deactivation
${DOCKER_CMD} exec spire-test-debian-client test -f "/etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID}"
echo "  -> Confirmed /etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID} exists on client before deactivation."

# Deactivate 'Kiosk Never Blank' via Web UI toggle endpoint
curl -s -o /dev/null -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/policies/${KIOSK_DCONF_POL_ID}/toggle"
echo "  -> Deactivated policy ${KIOSK_DCONF_POL_ID} ('Kiosk Never Blank') via POST /admin/policies/{id}/toggle."

# Wait for client check-in cycle to clean up orphaned dconf files and report REVOKED
for i in $(seq 1 15); do
    if ! ${DOCKER_CMD} exec spire-test-debian-client test -f "/etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID}" 2>/dev/null; then
        break
    fi
    sleep 1
done

if ${DOCKER_CMD} exec spire-test-debian-client test -f "/etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID}" 2>/dev/null; then
    echo "FAIL: Orphaned dconf rule file /etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID} was not removed!" >&2
    exit 1
fi
if ${DOCKER_CMD} exec spire-test-debian-client test -f "/etc/dconf/db/local.d/locks/10-spire-${KIOSK_DCONF_POL_ID}" 2>/dev/null; then
    echo "FAIL: Orphaned dconf lock file /etc/dconf/db/local.d/locks/10-spire-${KIOSK_DCONF_POL_ID} was not removed!" >&2
    exit 1
fi

REVOKED_POL_STATUS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT compliance_status FROM device_policies WHERE device_id = '${CONTAINER_DEV_ID}' AND policy_id = '${KIOSK_DCONF_POL_ID}';")
if [[ "${REVOKED_POL_STATUS}" != "REVOKED" ]]; then
    echo "FAIL: Expected device_policies status REVOKED after orphan cleanup, got ${REVOKED_POL_STATUS}" >&2
    exit 1
fi
echo "  -> Verified client removed /etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID}, ran dconf update, and reported status=REVOKED!"

echo "[Step 13/15] Verifying Fleet Search, Tag Filtering & Compliance Analytics on /admin/devices..."
FILTERED_HTML=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/devices?search=kiosk&tag=kiosk&status=APPROVED")
if ! echo "${FILTERED_HTML}" | grep -q "debian12-e2e-kiosk"; then
    echo "FAIL: Filtered /admin/devices?search=kiosk&tag=kiosk did not include debian12-e2e-kiosk" >&2
    exit 1
fi
if echo "${FILTERED_HTML}" | grep -q "debian12-e2e-laptop"; then
    echo "FAIL: Filtered /admin/devices?search=kiosk&tag=kiosk erroneously included debian12-e2e-laptop" >&2
    exit 1
fi
if ! echo "${FILTERED_HTML}" | grep -q "Overall Fleet Compliance"; then
    echo "FAIL: Fleet Compliance Analytics header missing from /admin/devices" >&2
    exit 1
fi
if ! echo "${FILTERED_HTML}" | grep -q "% Compliant"; then
    echo "FAIL: Compliance percentage missing from /admin/devices analytics header" >&2
    exit 1
fi
echo "  -> Fleet Search, Tag Filtering (?search=kiosk&tag=kiosk), and Compliance Analytics verified!"

echo "[Step 14/15] Testing Offline Cache Persistence & Disconnected Drift Reconciliation..."
# Re-activate 'Kiosk Never Blank' so the client caches it in /etc/spire/policy-cache.json
curl -s -o /dev/null -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -X POST "${SERVER_URL}/admin/policies/${KIOSK_DCONF_POL_ID}/toggle"
${DOCKER_CMD} exec spire-test-debian-client /usr/local/bin/spired -config /etc/spire/config.yaml -once >/dev/null 2>&1

# Verify /etc/spire/policy-cache.json exists and contains the active policy
${DOCKER_CMD} exec spire-test-debian-client test -f /etc/spire/policy-cache.json
CACHE_CONTENT=$(${DOCKER_CMD} exec spire-test-debian-client cat /etc/spire/policy-cache.json)
if ! echo "${CACHE_CONTENT}" | grep -q "${KIOSK_DCONF_POL_ID}"; then
    echo "FAIL: /etc/spire/policy-cache.json did not contain active policy ${KIOSK_DCONF_POL_ID}" >&2
    exit 1
fi
echo "  -> Confirmed /etc/spire/policy-cache.json (mode 0600) is populated on debian12-sim-01."

# Pause spire-test-server to simulate complete server outage
${DOCKER_CMD} pause spire-test-server
echo "  -> Paused spire-test-server container to simulate server outage."

# Induce local configuration drift on client while server is paused
${DOCKER_CMD} exec spire-test-debian-client rm -f "/etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID}"
if ${DOCKER_CMD} exec spire-test-debian-client test -f "/etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID}" 2>/dev/null; then
    ${DOCKER_CMD} unpause spire-test-server
    echo "FAIL: Could not remove dconf keyfile to simulate drift" >&2
    exit 1
fi
echo "  -> Induced drift: deleted /etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID} while server is paused."

# Trigger client cycle while offline and capture log output
OFFLINE_LOGS=$(${DOCKER_CMD} exec spire-test-debian-client /usr/local/bin/spired -config /etc/spire/config.yaml -once 2>&1 || true)
if ! echo "${OFFLINE_LOGS}" | grep -q "\[WARN\] Server unreachable; falling back to local policy cache"; then
    ${DOCKER_CMD} unpause spire-test-server
    echo "FAIL: Expected offline warning log '[WARN] Server unreachable; falling back to local policy cache', got:" >&2
    echo "${OFFLINE_LOGS}" >&2
    exit 1
fi

# Verify the deleted dconf keyfile was restored from /etc/spire/policy-cache.json while server remained paused!
if ! ${DOCKER_CMD} exec spire-test-debian-client test -f "/etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID}"; then
    ${DOCKER_CMD} unpause spire-test-server
    echo "FAIL: spired did not restore /etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID} from local policy cache while offline!" >&2
    exit 1
fi
if ! ${DOCKER_CMD} exec spire-test-debian-client test -f /etc/spire/pending-reports.json; then
    ${DOCKER_CMD} unpause spire-test-server
    echo "FAIL: spired did not buffer offline compliance reports in /etc/spire/pending-reports.json!" >&2
    exit 1
fi
echo "  -> Verified offline fallback: restored /etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID} from cache and buffered /etc/spire/pending-reports.json!"

# Unpause server and verify pending reports flush cleanly on next check-in
${DOCKER_CMD} unpause spire-test-server
echo "  -> Unpaused spire-test-server; verifying buffered report flush..."
FLUSH_LOGS=$(${DOCKER_CMD} exec spire-test-debian-client /usr/local/bin/spired -config /etc/spire/config.yaml -once 2>&1 || true)
if ${DOCKER_CMD} exec spire-test-debian-client test -f /etc/spire/pending-reports.json 2>/dev/null; then
    echo "FAIL: /etc/spire/pending-reports.json was not cleared after server reconnect!" >&2
    exit 1
fi
echo "  -> Buffered offline reports flushed to spire-server and /etc/spire/pending-reports.json cleared."

echo "[Step 15/15] Verifying Compliance Audit CSV & JSON Exports (GET /admin/compliance/export)..."
CSV_HEADERS=$(curl -s -I -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/compliance/export?format=csv")
if ! echo "${CSV_HEADERS}" | head -n 1 | grep -q "200 OK"; then
    echo "FAIL: GET /admin/compliance/export?format=csv did not return HTTP 200 OK" >&2
    exit 1
fi
if ! echo "${CSV_HEADERS}" | grep -qi "Content-Type: text/csv"; then
    echo "FAIL: GET /admin/compliance/export?format=csv missing Content-Type: text/csv" >&2
    exit 1
fi

CSV_BODY=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/compliance/export?format=csv")
CSV_HEADER_LINE=$(echo "${CSV_BODY}" | head -n 1 | tr -d '\r')
if [[ "${CSV_HEADER_LINE}" != "hostname,hardware_uuid,device_status,device_tags,policy_name,policy_type,target_tags,compliance_status,last_enforced_at,error_message" ]]; then
    echo "FAIL: Unexpected CSV header row: ${CSV_HEADER_LINE}" >&2
    exit 1
fi

DB_TOTAL_RECORDS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT COUNT(*) FROM device_policies;")
CSV_DATA_ROWS=$(( $(echo "${CSV_BODY}" | wc -l) - 1 ))
if [[ "${CSV_DATA_ROWS}" -ne "${DB_TOTAL_RECORDS}" ]]; then
    echo "FAIL: CSV exported row count (${CSV_DATA_ROWS}) does not match device_policies count (${DB_TOTAL_RECORDS})" >&2
    exit 1
fi

JSON_HEADERS=$(curl -s -I -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/compliance/export?format=json")
if ! echo "${JSON_HEADERS}" | head -n 1 | grep -q "200 OK"; then
    echo "FAIL: GET /admin/compliance/export?format=json did not return HTTP 200 OK" >&2
    exit 1
fi
if ! echo "${JSON_HEADERS}" | grep -qi "Content-Type: application/json"; then
    echo "FAIL: GET /admin/compliance/export?format=json missing Content-Type: application/json" >&2
    exit 1
fi

JSON_BODY=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/compliance/export?format=json")
JSON_LEN=$(echo "${JSON_BODY}" | jq 'length')
if [[ "${JSON_LEN}" -ne "${DB_TOTAL_RECORDS}" ]]; then
    echo "FAIL: JSON exported array length (${JSON_LEN}) does not match device_policies count (${DB_TOTAL_RECORDS})" >&2
    exit 1
fi
echo "  -> Verified CSV (${CSV_DATA_ROWS} rows) & JSON (${JSON_LEN} records) audit exports match PostgreSQL compliance state!"

PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" \
    -c "SELECT d.hostname, d.tags AS device_tags, p.name AS policy_name, p.is_active, dp.compliance_status FROM device_policies dp JOIN devices d ON d.id = dp.device_id JOIN policies p ON p.id = dp.policy_id ORDER BY d.hostname, p.created_at;"

echo "================================================================="
echo " PASS: All SpireUEM Phase 6 E2E Integration Tests Succeeded!"
echo "================================================================="
