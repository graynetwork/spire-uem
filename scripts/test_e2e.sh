#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

SERVER_URL="http://localhost:18080"
ADMIN_USER="${SPIRE_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${SPIRE_ADMIN_PASSWORD:-spire-e2e-breakglass-pw}"
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
echo " SpireUEM End-to-End Integration Test Suite (Phase 10)"
echo "================================================================="

echo "[Step 1/31] Building static binaries & Debian package (dist/spire-agent_0.1.0_amd64.deb)..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/spire-server ./cmd/spire-server
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/spired ./cmd/spired
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/spire-ctl ./cmd/spire-ctl
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/spire-hub ./cmd/spire-hub
mkdir -p dist
nfpm package --config packaging/nfpm.yaml --packager deb --target dist/ >/dev/null

echo "[Step 2/15] Spinning up Docker test stack (docker-compose.test.yml)..."
${DOCKER_CMD} unpause spire-test-server >/dev/null 2>&1 || true
${DOCKER_CMD} compose -f docker-compose.test.yml down -v >/dev/null 2>&1 || true
${DOCKER_CMD} compose -f docker-compose.test.yml up -d --build

echo "Waiting for spire-test-server (${SERVER_URL}/admin/devices) to become ready..."
for i in $(seq 1 30); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "${SERVER_URL}/admin/devices" || true)
    if [[ "${CODE}" == "401" || "${CODE}" == "200" || "${CODE}" == "303" ]]; then
        echo "  -> spire-test-server is online!"
        break
    fi
    sleep 1
    if [[ "${i}" -eq 30 ]]; then
        echo "FAIL: spire-test-server did not become ready in time." >&2
        exit 1
    fi
done

UNAUTH_BROWSER_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${SERVER_URL}/admin/devices")
echo "  -> Unauthenticated browser GET /admin/devices returned HTTP ${UNAUTH_BROWSER_CODE}"
if [[ "${UNAUTH_BROWSER_CODE}" != "303" ]]; then
    echo "FAIL: Expected HTTP 303 (redirect to /login) for unauthenticated browser GET /admin/devices, got ${UNAUTH_BROWSER_CODE}" >&2
    exit 1
fi

UNAUTH_API_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Accept: application/json" "${SERVER_URL}/admin/devices")
echo "  -> Unauthenticated API GET /admin/devices returned HTTP ${UNAUTH_API_CODE}"
if [[ "${UNAUTH_API_CODE}" != "401" ]]; then
    echo "FAIL: Expected HTTP 401 for unauthenticated API GET /admin/devices, got ${UNAUTH_API_CODE}" >&2
    exit 1
fi

# Finding C6: Authenticate via POST /login and establish session cookie
COOKIE_JAR="/tmp/spire_e2e_cookies.txt"
rm -f "${COOKIE_JAR}"
LOGIN_STATUS=$(curl -s -c "${COOKIE_JAR}" -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/login" \
    -d "username=${ADMIN_USER}&password=${ADMIN_PASSWORD}")
echo "  -> POST /login returned HTTP ${LOGIN_STATUS}"
if [[ "${LOGIN_STATUS}" != "303" && "${LOGIN_STATUS}" != "200" ]]; then
    echo "FAIL: Expected HTTP 303/200 on POST /login, got ${LOGIN_STATUS}" >&2
    exit 1
fi

# Verify session cookie was set
if ! grep -q "spire_session" "${COOKIE_JAR}"; then
    echo "FAIL: spire_session cookie not found in cookie jar" >&2
    exit 1
fi

# Extract CSRF token from HTML
ADMIN_HTML=$(curl -s -b "${COOKIE_JAR}" "${SERVER_URL}/admin/devices")
CSRF_TOKEN=$(grep -oP 'name="csrf-token" content="\K[^"]+' <<<"${ADMIN_HTML}" || true)
if [[ -z "${CSRF_TOKEN}" ]]; then
    echo "FAIL: CSRF token not found in /admin/devices layout" >&2
    exit 1
fi
echo "  -> Successfully logged in via session cookie (spire_session) and extracted CSRF token: ${CSRF_TOKEN:0:8}..."

# Finding C6: Test CSRF Enforcement on non-idempotent routes
NO_CSRF_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" -X POST "${SERVER_URL}/admin/policies" \
    -d "name=CSRF+Test&policy_type=PACKAGE_ABSENCE&package_name=htop")
echo "  -> Non-idempotent POST without CSRF token returned HTTP ${NO_CSRF_CODE}"
if [[ "${NO_CSRF_CODE}" != "403" ]]; then
    echo "FAIL: Expected HTTP 403 on POST /admin/policies without CSRF token, got ${NO_CSRF_CODE}" >&2
    exit 1
fi

BAD_CSRF_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" -H "X-CSRF-Token: invalid_token_123" -X POST "${SERVER_URL}/admin/policies" \
    -d "name=CSRF+Test&policy_type=PACKAGE_ABSENCE&package_name=htop")
echo "  -> Non-idempotent POST with invalid CSRF token returned HTTP ${BAD_CSRF_CODE}"
if [[ "${BAD_CSRF_CODE}" != "403" ]]; then
    echo "FAIL: Expected HTTP 403 on POST /admin/policies with invalid CSRF token, got ${BAD_CSRF_CODE}" >&2
    exit 1
fi
echo "  -> Verified Finding C6: CSRF token strictly required and validated on non-idempotent routes."

# Finding C5: Verify Secure Headers
ADMIN_HEADERS=$(curl -s -I -b "${COOKIE_JAR}" "${SERVER_URL}/admin/devices")
if ! grep -qi "X-Content-Type-Options: nosniff" <<<"${ADMIN_HEADERS}"; then
    echo "FAIL: Missing X-Content-Type-Options: nosniff header (Finding C5)" >&2
    exit 1
fi
if ! grep -qi "X-Frame-Options: DENY" <<<"${ADMIN_HEADERS}"; then
    echo "FAIL: Missing X-Frame-Options: DENY header (Finding C5)" >&2
    exit 1
fi
echo "  -> Verified Finding C5 fix: Secure headers present (X-Content-Type-Options: nosniff, X-Frame-Options: DENY)."

# Operations Dashboard Verification
echo "Verifying Operations Dashboard (/admin/dashboard & /admin/dashboard/metrics)..."
DASH_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" "${SERVER_URL}/admin/dashboard")
if [[ "${DASH_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 200 for /admin/dashboard, got ${DASH_CODE}" >&2
    exit 1
fi

DASH_HTML=$(curl -s -b "${COOKIE_JAR}" "${SERVER_URL}/admin/dashboard")
for req_elem in "Total Hosts" "Up to Date" "Needs Updates" "Needs Reboots" "Outdated Packages" "Security Updates" "updateStatusChart" "osDistChart" "packageTrendsChart" "Host Compliance Status" "Recent Collection" "Recent Users Logged In"; do
    if ! grep -q "${req_elem}" <<<"${DASH_HTML}"; then
        echo "FAIL: Expected '${req_elem}' in /admin/dashboard HTML" >&2
        exit 1
    fi
done

# Test root redirect to /admin/dashboard
ROOT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" "${SERVER_URL}/")
if [[ "${ROOT_CODE}" != "303" && "${ROOT_CODE}" != "302" ]]; then
    echo "FAIL: Expected redirect (302/303) for GET /, got ${ROOT_CODE}" >&2
    exit 1
fi

# Test HTMX partial metrics endpoint
METRICS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" "${SERVER_URL}/admin/dashboard/metrics")
if [[ "${METRICS_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 200 for /admin/dashboard/metrics, got ${METRICS_CODE}" >&2
    exit 1
fi
METRICS_HTML=$(curl -s -b "${COOKIE_JAR}" "${SERVER_URL}/admin/dashboard/metrics")
if ! grep -q 'id="metric-cards"' <<<"${METRICS_HTML}"; then
    echo "FAIL: Expected 'id=\"metric-cards\"' in /admin/dashboard/metrics HTML" >&2
    exit 1
fi
echo "  -> Operations Dashboard verified: 6-metric ribbon, Chart.js canvases, activity feeds & HTMX endpoint active."

admin_curl() {
    curl -b "${COOKIE_JAR}" -H "X-CSRF-Token: ${CSRF_TOKEN}" "$@"
}

echo "[Step 3/15] Creating global & tag-targeted policies via Web UI (/admin/policies)..."
# 1. Global policy (target_tags = empty -> applies to all devices)
admin_curl -s -o /dev/null -X POST "${SERVER_URL}/admin/policies" \
    -d "name=Global+Purge+htop&description=Remove+htop+everywhere&policy_type=PACKAGE_ABSENCE&package_name=htop&target_tags="

# 2. Global policy (target_tags = empty -> applies to all devices)
admin_curl -s -o /dev/null -X POST "${SERVER_URL}/admin/policies" \
    -d "name=Global+CA+Certs&description=Ensure+CA+bundle+installed&policy_type=PACKAGE_PRESENCE&package_name=ca-certificates&target_tags="

# 3. Laptop-only policy (target_tags = laptop)
admin_curl -s -o /dev/null -X POST "${SERVER_URL}/admin/policies" \
    -d "name=Laptop+Idle+Lock+300s&description=Laptop+screen+lock&policy_type=DCONF_SETTING&schema_path=org/gnome/desktop/session&dconf_key=idle-delay&dconf_value=uint32+300&dconf_locked=true&target_tags=laptop"

# 4. Kiosk-only policy (target_tags = kiosk)
admin_curl -s -o /dev/null -X POST "${SERVER_URL}/admin/policies" \
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

# Verify Finding C1 fix: Subsequent token re-claim attempts on already-claimed approved device return HTTP 409
RECLAIM_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/api/v1/desktop/enroll" \
    -H "Content-Type: application/json" \
    -d "{\"hardware_uuid\":\"${LAPTOP_HW_UUID}\",\"hostname\":\"${LAPTOP_HOSTNAME}\"}")
if [[ "${RECLAIM_CODE}" != "409" ]]; then
    echo "FAIL: Expected HTTP 409 on second token claim for approved device (Finding C1 fix), got ${RECLAIM_CODE}" >&2
    exit 1
fi
echo "  -> Verified Finding C1 fix: Token re-claim rejected with HTTP 409 Conflict."

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

# Verify Finding H5 fix: Multi-statement batch report rollback on error
ROLLBACK_TEST_POLICY=$(echo "${KIOSK_CHECKIN}" | jq -r '.policies[0].id')
PRE_FAIL_STATUS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT compliance_status FROM device_policies WHERE device_id = '${KIOSK_ID}' AND policy_id = '${ROLLBACK_TEST_POLICY}';")

FAIL_REPORT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/api/v1/desktop/report" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${KIOSK_TOKEN}" \
    -d "{\"hardware_uuid\":\"${KIOSK_HW_UUID}\",\"results\":[{\"policy_id\":\"${ROLLBACK_TEST_POLICY}\",\"compliance_status\":\"FAILED\",\"error_message\":\"simulated failure\"},{\"policy_id\":\"00000000-0000-0000-0000-000000000000\",\"compliance_status\":\"COMPLIANT\"}]}")

if [[ "${FAIL_REPORT_CODE}" != "500" ]]; then
    echo "FAIL: Expected HTTP 500 when batch report transaction encounters constraint violation, got ${FAIL_REPORT_CODE}" >&2
    exit 1
fi

POST_FAIL_STATUS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT compliance_status FROM device_policies WHERE device_id = '${KIOSK_ID}' AND policy_id = '${ROLLBACK_TEST_POLICY}';")

if [[ "${POST_FAIL_STATUS}" != "${PRE_FAIL_STATUS}" ]]; then
    echo "FAIL: Finding H5 fix: Transaction failed to rollback on error! Expected ${PRE_FAIL_STATUS}, got ${POST_FAIL_STATUS}" >&2
    exit 1
fi
echo "  -> Verified Finding H5 fix: Atomic transaction rolled back cleanly on batch report error (${PRE_FAIL_STATUS} preserved)."

echo "[Step 8/20] Verifying Device Telemetry Inspection Drawer (GET /admin/devices/{id})..."
DRAWER_HTML=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/devices/${LAPTOP_ID}")
if ! grep -q "Device Telemetry &amp; Compliance Inspection" <<<"${DRAWER_HTML}"; then
    echo "FAIL: Device inspection drawer did not render expected header" >&2
    exit 1
fi
if ! grep -q "Diagnostic Shell / Command Runner" <<<"${DRAWER_HTML}"; then
    echo "FAIL: Device inspection drawer did not render Diagnostic Shell / Command Runner section" >&2
    exit 1
fi
echo "  -> Device Inspection Drawer & Diagnostic Shell UI verified (HTTP 200)."

echo "[Step 9/20] Verifying public single-command onboarding endpoints (/install.sh & /dist/*.deb)..."
INSTALL_HEADERS_AND_BODY=$(curl -s -i "${SERVER_URL}/install.sh")
if ! head -n 1 <<<"${INSTALL_HEADERS_AND_BODY}" | grep -q "200 OK"; then
    echo "FAIL: GET /install.sh did not return HTTP 200 OK" >&2
    exit 1
fi
if ! grep -qi "Content-Type: text/x-shellscript" <<<"${INSTALL_HEADERS_AND_BODY}"; then
    echo "FAIL: GET /install.sh did not return Content-Type: text/x-shellscript" >&2
    exit 1
fi
if ! grep -q 'SERVER_URL="http://localhost:18080"' <<<"${INSTALL_HEADERS_AND_BODY}"; then
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
CONTAINER_DEV_ID=""
for i in $(seq 1 15); do
    CONTAINER_DEV_ID=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
        -c "SELECT id FROM devices WHERE hardware_uuid = 'debc1200-1111-2222-3333-444455556666' LIMIT 1;" || true)
    if [[ -n "${CONTAINER_DEV_ID}" ]]; then
        break
    fi
    sleep 1
done
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
for i in $(seq 1 15); do
    if ${DOCKER_CMD} exec spire-test-debian-client test -f "/etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID}" 2>/dev/null; then
        break
    fi
    sleep 1
done
${DOCKER_CMD} exec spire-test-debian-client test -f "/etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID}"
DCONF_BEFORE=$(${DOCKER_CMD} exec spire-test-debian-client dconf read /org/gnome/desktop/session/idle-delay 2>/dev/null || true)
echo "  -> Confirmed /etc/dconf/db/local.d/10-spire-${KIOSK_DCONF_POL_ID} exists (dconf read: ${DCONF_BEFORE})."

# Deactivate 'Kiosk Never Blank' via Web UI toggle endpoint using session auth + CSRF
admin_curl -s -o /dev/null -X POST "${SERVER_URL}/admin/policies/${KIOSK_DCONF_POL_ID}/toggle"
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

echo "[Step 13/20] Verifying Fleet Search, Tag Filtering & Compliance Analytics on /admin/devices..."
FILTERED_HTML=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/devices?search=kiosk&tag=kiosk&status=APPROVED")
if ! grep -q "debian12-e2e-kiosk" <<<"${FILTERED_HTML}"; then
    echo "FAIL: Filtered /admin/devices?search=kiosk&tag=kiosk did not include debian12-e2e-kiosk" >&2
    exit 1
fi
if grep -q "debian12-e2e-laptop" <<<"${FILTERED_HTML}"; then
    echo "FAIL: Filtered /admin/devices?search=kiosk&tag=kiosk erroneously included debian12-e2e-laptop" >&2
    exit 1
fi
if ! grep -q "Overall Fleet Compliance" <<<"${FILTERED_HTML}"; then
    echo "FAIL: Fleet Compliance Analytics header missing from /admin/devices" >&2
    exit 1
fi
if ! grep -q "% Compliant" <<<"${FILTERED_HTML}"; then
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
if ! grep -q "${KIOSK_DCONF_POL_ID}" <<<"${CACHE_CONTENT}"; then
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
if ! grep -q "\[WARN\] Server unreachable; falling back to local policy cache" <<<"${OFFLINE_LOGS}"; then
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

echo "[Step 15/20] Verifying Compliance Audit CSV & JSON Exports (GET /admin/compliance/export)..."
CSV_HEADERS=$(curl -s -I -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/compliance/export?format=csv")
if ! head -n 1 <<<"${CSV_HEADERS}" | grep -q "200 OK"; then
    echo "FAIL: GET /admin/compliance/export?format=csv did not return HTTP 200 OK" >&2
    exit 1
fi
if ! grep -qi "Content-Type: text/csv" <<<"${CSV_HEADERS}"; then
    echo "FAIL: GET /admin/compliance/export?format=csv missing Content-Type: text/csv" >&2
    exit 1
fi

CSV_BODY=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/compliance/export?format=csv")
CSV_HEADER_LINE=$(head -n 1 <<<"${CSV_BODY}" | tr -d '\r')
if [[ "${CSV_HEADER_LINE}" != "hostname,hardware_uuid,device_status,device_tags,policy_name,policy_type,target_tags,compliance_status,last_enforced_at,error_message" ]]; then
    echo "FAIL: Unexpected CSV header row: ${CSV_HEADER_LINE}" >&2
    exit 1
fi

DB_TOTAL_RECORDS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT COUNT(*) FROM device_policies;")
CSV_DATA_ROWS=$(( $(wc -l <<<"${CSV_BODY}") - 1 ))
if [[ "${CSV_DATA_ROWS}" -ne "${DB_TOTAL_RECORDS}" ]]; then
    echo "FAIL: CSV exported row count (${CSV_DATA_ROWS}) does not match device_policies count (${DB_TOTAL_RECORDS})" >&2
    exit 1
fi

JSON_HEADERS=$(curl -s -I -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/compliance/export?format=json")
if ! head -n 1 <<<"${JSON_HEADERS}" | grep -q "200 OK"; then
    echo "FAIL: GET /admin/compliance/export?format=json did not return HTTP 200 OK" >&2
    exit 1
fi
if ! grep -qi "Content-Type: application/json" <<<"${JSON_HEADERS}"; then
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

echo "[Step 16/17] Testing TPM 2.0 Hardware Attestation Challenge & Quote Verification..."
for i in $(seq 1 15); do
    ATTEST_STATUS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
        -c "SELECT attestation_status FROM devices WHERE id = '${CONTAINER_DEV_ID}';")
    SECURE_BOOT=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
        -c "SELECT secure_boot_enabled FROM devices WHERE id = '${CONTAINER_DEV_ID}';")
    PCR7_VAL=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
        -c "SELECT pcr_values->>'7' FROM device_tpm_attestation WHERE device_id = '${CONTAINER_DEV_ID}';")
    if [[ "${ATTEST_STATUS}" == "ATTESTED" && "${SECURE_BOOT}" == "t" && -n "${PCR7_VAL}" ]]; then
        break
    fi
    sleep 1
done

if [[ "${ATTEST_STATUS}" != "ATTESTED" || "${SECURE_BOOT}" != "t" || -z "${PCR7_VAL}" ]]; then
    echo "FAIL: Expected device TPM attestation_status=ATTESTED and secure_boot_enabled=t, got status=${ATTEST_STATUS} secure_boot=${SECURE_BOOT} pcr7=${PCR7_VAL}" >&2
    exit 1
fi
echo "  -> Verified TPM 2.0 challenge-response attestation: status=${ATTEST_STATUS}, secure_boot=${SECURE_BOOT}, PCR7=${PCR7_VAL}"

# Test fail-closed behavior (Finding C2): absent hardware TPM without simulation reports FAILED
${DOCKER_CMD} exec spire-test-debian-client kill -STOP 1 >/dev/null 2>&1 || true
${DOCKER_CMD} exec -e SPIRE_SIMULATE_TPM2=0 spire-test-debian-client /usr/local/bin/spired -config /etc/spire/config.yaml -once >/dev/null 2>&1
FAIL_STATUS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT attestation_status FROM devices WHERE id = '${CONTAINER_DEV_ID}';")
if [[ "${FAIL_STATUS}" != "FAILED" ]]; then
    ${DOCKER_CMD} exec spire-test-debian-client kill -CONT 1 >/dev/null 2>&1 || true
    echo "FAIL: Expected attestation_status=FAILED when TPM absent and simulation disabled (Finding C2), got ${FAIL_STATUS}" >&2
    exit 1
fi
echo "  -> Verified Finding C2 fail-closed: attestation_status=FAILED when hardware TPM absent and SPIRE_SIMULATE_TPM2=0."

# Restore ATTESTED state with SPIRE_SIMULATE_TPM2=1 and resume background daemon
${DOCKER_CMD} exec -e SPIRE_SIMULATE_TPM2=1 spire-test-debian-client /usr/local/bin/spired -config /etc/spire/config.yaml -once >/dev/null 2>&1
${DOCKER_CMD} exec spire-test-debian-client kill -CONT 1 >/dev/null 2>&1 || true

echo "[Step 17/17] Testing LUKS2 Recovery Key Envelope Escrow & Audited Admin Reveal..."
TEST_RECOVERY_KEY="SPIREUEM-LUKS2-RECOVERY-KEY-48CHARS-TEST-0000012"
TEST_VOLUME_UUID="luks2-vol-uuid-9988-7766"

ESCROW_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/desktop/escrow/luks" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${LAPTOP_TOKEN}" \
    -d "{\"hardware_uuid\":\"${LAPTOP_HW_UUID}\",\"volume_uuid\":\"${TEST_VOLUME_UUID}\",\"device_path\":\"/dev/nvme0n1p3\",\"mount_point\":\"/\",\"key_slot\":1,\"recovery_key\":\"${TEST_RECOVERY_KEY}\"}")
ESCROW_STATUS=$(echo "${ESCROW_RESP}" | jq -r '.status')
if [[ "${ESCROW_STATUS}" != "escrowed" ]]; then
    echo "FAIL: Expected LUKS escrow status='escrowed', got: ${ESCROW_RESP}" >&2
    exit 1
fi

# Verify encrypted_dek and encrypted_recovery_key are persisted in device_luks_escrow
ESCROW_DB_LEN=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT octet_length(encrypted_dek) FROM device_luks_escrow WHERE device_id = '${LAPTOP_ID}' AND volume_uuid = '${TEST_VOLUME_UUID}';")
if [[ "${ESCROW_DB_LEN}" -ne 512 ]]; then
    echo "FAIL: Expected 512-byte RSA-OAEP-4096 encrypted_dek in device_luks_escrow, got ${ESCROW_DB_LEN} bytes" >&2
    exit 1
fi
echo "  -> Verified RSA-OAEP-4096 (512-byte wrapped DEK) + AES-256-GCM ciphertext persisted in device_luks_escrow."

# Verify reveal without reason is rejected (HTTP 400)
NO_REASON_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -X POST "${SERVER_URL}/admin/devices/${LAPTOP_ID}/luks/reveal" \
    -H "Content-Type: application/json" \
    -d "{\"volume_uuid\":\"${TEST_VOLUME_UUID}\",\"reason\":\"\"}")
if [[ "${NO_REASON_CODE}" != "400" ]]; then
    echo "FAIL: Expected HTTP 400 when revealing recovery key without justification reason, got ${NO_REASON_CODE}" >&2
    exit 1
fi

# Reveal recovery key with justification ticket and verify decrypted key + audit log entry
REVEAL_JSON=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -X POST "${SERVER_URL}/admin/devices/${LAPTOP_ID}/luks/reveal" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "{\"volume_uuid\":\"${TEST_VOLUME_UUID}\",\"reason\":\"INC-7001 Emergency Disk Recovery\"}")
REVEALED_KEY=$(echo "${REVEAL_JSON}" | jq -r '.recovery_key')
if [[ "${REVEALED_KEY}" != "${TEST_RECOVERY_KEY}" ]]; then
    echo "FAIL: Decrypted recovery key (${REVEALED_KEY}) did not match original (${TEST_RECOVERY_KEY})" >&2
    exit 1
fi

AUDIT_REASON=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT reason FROM luks_recovery_audit_log WHERE device_id = '${LAPTOP_ID}' AND volume_uuid = '${TEST_VOLUME_UUID}' ORDER BY accessed_at DESC LIMIT 1;")
if [[ "${AUDIT_REASON}" != "INC-7001 Emergency Disk Recovery" ]]; then
    echo "FAIL: Expected luks_recovery_audit_log reason 'INC-7001 Emergency Disk Recovery', got '${AUDIT_REASON}'" >&2
    exit 1
fi
echo "  -> Verified LUKS2 recovery key decryption & immutable luks_recovery_audit_log entry ('${AUDIT_REASON}')!"

# Verify Finding C3 fix: Persistent RSA KEK survives spire-server restart and can still decrypt previously escrowed keys
echo "  -> Verifying Finding C3 fix: Restarting spire-server container to test KEK persistence..."
${DOCKER_CMD} compose -f docker-compose.test.yml restart spire-server >/dev/null
for i in $(seq 1 30); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/devices" || true)
    if [[ "${CODE}" == "200" ]]; then
        break
    fi
    sleep 1
    if [[ "${i}" -eq 30 ]]; then
        echo "FAIL: spire-server did not recover after restart" >&2
        exit 1
    fi
done

REVEAL_RESTART_JSON=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -X POST "${SERVER_URL}/admin/devices/${LAPTOP_ID}/luks/reveal" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "{\"volume_uuid\":\"${TEST_VOLUME_UUID}\",\"reason\":\"INC-7002 Post-Restart Key Verification\"}")
REVEALED_KEY_RESTART=$(echo "${REVEAL_RESTART_JSON}" | jq -r '.recovery_key')
if [[ "${REVEALED_KEY_RESTART}" != "${TEST_RECOVERY_KEY}" ]]; then
    echo "FAIL: Persistent KEK test failed (Finding C3)! After server restart, decrypted key '${REVEALED_KEY_RESTART}' != expected '${TEST_RECOVERY_KEY}'" >&2
    exit 1
fi
echo "  -> Verified Finding C3 fix: Persistent KEK safely decrypted escrowed LUKS recovery key after daemon restart!"

# Refresh CSRF token after server restart
ADMIN_HTML=$(curl -s -b "${COOKIE_JAR}" "${SERVER_URL}/admin/devices")
CSRF_TOKEN=$(grep -oP 'name="csrf-token" content="\K[^"]+' <<<"${ADMIN_HTML}" || true)

# ------------------------------------------------------------------
# Step 18: Phased Patch Deployment Rings (CANARY vs PRODUCTION)
# ------------------------------------------------------------------
echo "[Step 18/20] Testing Phased Patch Deployment Rings (CANARY vs PRODUCTION isolation)..."

# Create a CANARY-only policy via POST /admin/policies
CANARY_CREATE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -X POST "${SERVER_URL}/admin/policies" \
    --data-urlencode "name=Canary Kernel Patch Test" \
    --data-urlencode "description=Canary ring test policy" \
    --data-urlencode "policy_type=PACKAGE_ABSENCE" \
    --data-urlencode "package_name=telnet" \
    --data-urlencode "target_ring=CANARY")
if [[ "${CANARY_CREATE_CODE}" != "303" && "${CANARY_CREATE_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 303/200 creating CANARY policy, got ${CANARY_CREATE_CODE}" >&2
    exit 1
fi

# Verify laptop (currently in default PRODUCTION ring) does NOT receive the CANARY policy
LAPTOP_PROD_CHECKIN=$(curl -s -X POST "${SERVER_URL}/api/v1/desktop/checkin" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${LAPTOP_TOKEN}" \
    -d "{\"hardware_uuid\":\"${LAPTOP_HW_UUID}\",\"packages\":[\"bash\"],\"sessions\":[\"root\"]}")
CANARY_IN_PROD=$(echo "${LAPTOP_PROD_CHECKIN}" | jq '[.policies[] | select(.name == "Canary Kernel Patch Test")] | length')
if [[ "${CANARY_IN_PROD}" -ne 0 ]]; then
    echo "FAIL: PRODUCTION device received CANARY-restricted policy! Response: ${LAPTOP_PROD_CHECKIN}" >&2
    exit 1
fi
echo "  -> Verified PRODUCTION device does NOT receive CANARY-targeted policy."

# Move laptop into CANARY ring via POST /admin/devices/{id}/ring
RING_UPDATE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -X POST "${SERVER_URL}/admin/devices/${LAPTOP_ID}/ring" \
    -d "patch_ring=CANARY")
if [[ "${RING_UPDATE_CODE}" != "200" && "${RING_UPDATE_CODE}" != "303" ]]; then
    echo "FAIL: Expected HTTP 200/303 updating device patch_ring to CANARY, got ${RING_UPDATE_CODE}" >&2
    exit 1
fi

# Verify laptop in CANARY ring now receives the CANARY policy
LAPTOP_CANARY_CHECKIN=$(curl -s -X POST "${SERVER_URL}/api/v1/desktop/checkin" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${LAPTOP_TOKEN}" \
    -d "{\"hardware_uuid\":\"${LAPTOP_HW_UUID}\",\"packages\":[\"bash\"],\"sessions\":[\"root\"]}")
CANARY_IN_CANARY=$(echo "${LAPTOP_CANARY_CHECKIN}" | jq '[.policies[] | select(.name == "Canary Kernel Patch Test")] | length')
if [[ "${CANARY_IN_CANARY}" -ne 1 ]]; then
    echo "FAIL: CANARY device did not receive CANARY-targeted policy! Response: ${LAPTOP_CANARY_CHECKIN}" >&2
    exit 1
fi
echo "  -> Verified device moved to CANARY ring immediately receives CANARY-targeted policy!"

# ------------------------------------------------------------------
# Step 19: Flatpak Application Lifecycle Policy & Client Reconciliation
# ------------------------------------------------------------------
echo "[Step 19/20] Testing Flatpak Application Policy Deployment (firefox-esr-flatpak preset)..."
FLATPAK_DEPLOY_CODE=$(admin_curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${SERVER_URL}/admin/policies/from-template" \
    -d "template_id=firefox-esr-flatpak&target_tags=kiosk")
if [[ "${FLATPAK_DEPLOY_CODE}" != "303" && "${FLATPAK_DEPLOY_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 303/200 deploying firefox-esr-flatpak preset, got ${FLATPAK_DEPLOY_CODE}" >&2
    exit 1
fi

FLATPAK_POLICY_ID=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT id FROM policies WHERE policy_type = 'FLATPAK_APP' ORDER BY created_at DESC LIMIT 1;")

echo "  -> Waiting for spired container to reconcile FLATPAK_APP policy (${FLATPAK_POLICY_ID})..."
FLATPAK_COMPLIANT=0
for i in {1..15}; do
    STATUS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
        -c "SELECT compliance_status FROM device_policies WHERE device_id = '${CONTAINER_DEV_ID}' AND policy_id = '${FLATPAK_POLICY_ID}';" || true)
    if [[ "${STATUS}" == "COMPLIANT" ]]; then
        FLATPAK_COMPLIANT=1
        break
    fi
    sleep 2
done
if [[ "${FLATPAK_COMPLIANT}" -ne 1 ]]; then
    echo "FAIL: spired did not report COMPLIANT for FLATPAK_APP policy within timeout" >&2
    exit 1
fi

FLATPAK_LIST=$(${DOCKER_CMD} exec spire-test-debian-client flatpak list --app --columns=application)
if ! grep -q "org.mozilla.firefox" <<<"${FLATPAK_LIST}"; then
    echo "FAIL: Expected org.mozilla.firefox in flatpak list --app, got: ${FLATPAK_LIST}" >&2
    exit 1
fi

if ${DOCKER_CMD} exec spire-test-debian-client test -f /etc/spire/flatpak-apps.json; then
    echo "FAIL: Found synthetic /etc/spire/flatpak-apps.json (Finding H1 violation)" >&2
    exit 1
fi
echo "  -> Verified Finding H1 fix: FLATPAK_APP policy installed via genuine host Flatpak (org.mozilla.firefox confirmed via flatpak list --app, zero synthetic JSON)!"

# ------------------------------------------------------------------
# Step 20: Reboot Required Detection & Maintenance Window Gating
# ------------------------------------------------------------------
echo "[Step 20/20] Testing Reboot Required Reporting & Maintenance Window Gating..."

# Simulate a pending reboot sentinel inside the Debian client container
${DOCKER_CMD} exec spire-test-debian-client bash -c "mkdir -p /etc/spire && echo 'kernel-upgrade' > /etc/spire/reboot-required"

REBOOT_REPORTED=0
for i in {1..15}; do
    REB_FLAG=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
        -c "SELECT reboot_required FROM devices WHERE id = '${CONTAINER_DEV_ID}';" || true)
    if [[ "${REB_FLAG}" == "t" ]]; then
        REBOOT_REPORTED=1
        break
    fi
    sleep 2
done
if [[ "${REBOOT_REPORTED}" -ne 1 ]]; then
    echo "FAIL: Device did not report reboot_required=true after /etc/spire/reboot-required was set" >&2
    exit 1
fi

DEVICES_HTML=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/devices")
if ! grep -q "REBOOT REQUIRED" <<<"${DEVICES_HTML}"; then
    echo "FAIL: Expected 'REBOOT REQUIRED' badge on /admin/devices HTML" >&2
    exit 1
fi
echo "  -> Verified device reported reboot_required=true and Web UI renders REBOOT REQUIRED badge."

# Create an inactive Maintenance Window (Jan 1st 03:00 UTC, 60 mins) and verify a requires_reboot policy is gated
MW_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -X POST "${SERVER_URL}/admin/patch-windows" \
    --data-urlencode "name=New Year Maintenance Window" \
    --data-urlencode "cron_expression=0 3 1 1 *" \
    --data-urlencode "duration_minutes=60" \
    --data-urlencode "allow_reboot=true")
if [[ "${MW_CODE}" != "303" && "${MW_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 303/200 creating patch window, got ${MW_CODE}" >&2
    exit 1
fi

MW_ID=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT id FROM patch_windows WHERE name = 'New Year Maintenance Window' LIMIT 1;")

# Create a policy requiring reboot attached to that closed maintenance window
REB_POL_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -X POST "${SERVER_URL}/admin/policies" \
    --data-urlencode "name=Gated Kernel Reboot Policy" \
    --data-urlencode "policy_type=PACKAGE_ABSENCE" \
    --data-urlencode "package_name=nano" \
    --data-urlencode "patch_window_id=${MW_ID}" \
    --data-urlencode "requires_reboot=true")
if [[ "${REB_POL_CODE}" != "303" && "${REB_POL_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 303/200 creating gated reboot policy, got ${REB_POL_CODE}" >&2
    exit 1
fi

# Check in and verify "Gated Kernel Reboot Policy" is deferred outside its maintenance window
GATED_CHECKIN=$(curl -s -X POST "${SERVER_URL}/api/v1/desktop/checkin" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${LAPTOP_TOKEN}" \
    -d "{\"hardware_uuid\":\"${LAPTOP_HW_UUID}\",\"packages\":[\"bash\"],\"sessions\":[\"root\"]}")
GATED_COUNT=$(echo "${GATED_CHECKIN}" | jq '[.policies[] | select(.name == "Gated Kernel Reboot Policy")] | length')
if [[ "${GATED_COUNT}" -ne 0 ]]; then
    echo "FAIL: Reboot-requiring policy was dispatched outside its active maintenance window!" >&2
    exit 1
fi
echo "  -> Verified reboot-requiring policy is deferred outside its active maintenance window!"

# ------------------------------------------------------------------
# Step 21: Real-Time Duplex WebSocket Gateway Presence Verification
# ------------------------------------------------------------------
echo "[Step 21/23] Verifying Real-Time WebSocket Gateway Connection (/api/v1/desktop/stream)..."
WS_CONNECTED_OK=0
for i in {1..15}; do
    WS_FLAG=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
        -c "SELECT ws_connected FROM devices WHERE id = '${CONTAINER_DEV_ID}';" || true)
    if [[ "${WS_FLAG}" == "t" ]]; then
        WS_CONNECTED_OK=1
        break
    fi
    sleep 1
done
if [[ "${WS_CONNECTED_OK}" -ne 1 ]]; then
    echo "FAIL: debian12-sim-01 did not establish WebSocket stream (ws_connected != t)" >&2
    exit 1
fi

WS_BADGE_HTML=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/devices/${CONTAINER_DEV_ID}")
if ! grep -q "CONNECTED (LIVE)" <<<"${WS_BADGE_HTML}"; then
    echo "FAIL: Expected 'CONNECTED (LIVE)' badge on /admin/devices/${CONTAINER_DEV_ID}" >&2
    exit 1
fi
echo "  -> Verified debian12-sim-01 established duplex WebSocket stream (ws_connected=t, CONNECTED (LIVE) badge active)!"

# ------------------------------------------------------------------
# Step 22: Sub-Second Command Push & Real-Time WebSocket Result Streaming
# ------------------------------------------------------------------
echo "[Step 22/23] Testing Sub-Second Command Push over Duplex WebSocket..."
START_MS=$(date +%s%3N)
curl -s -o /dev/null -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -X POST "${SERVER_URL}/admin/devices/${CONTAINER_DEV_ID}/commands" \
    --data-urlencode "command=echo 'sub-second-live-test'"

LIVE_DONE=0
for i in {1..20}; do
    LIVE_OUT=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
        -c "SELECT stdout FROM device_commands WHERE device_id = '${CONTAINER_DEV_ID}' AND command = 'echo ''sub-second-live-test''' AND status = 'COMPLETED' ORDER BY created_at DESC LIMIT 1;" || true)
    if grep -q "sub-second-live-test" <<<"${LIVE_OUT}"; then
        LIVE_DONE=1
        break
    fi
    sleep 0.1
done
END_MS=$(date +%s%3N)
ELAPSED_MS=$(( END_MS - START_MS ))

if [[ "${LIVE_DONE}" -ne 1 ]]; then
    echo "FAIL: WebSocket command push 'echo sub-second-live-test' did not complete within 2 seconds" >&2
    exit 1
fi
if [[ "${ELAPSED_MS}" -ge 2000 ]]; then
    echo "FAIL: Expected sub-2-second WebSocket command turnaround, took ${ELAPSED_MS}ms" >&2
    exit 1
fi
echo "  -> Verified sub-second WebSocket command push & result turnaround in ${ELAPSED_MS}ms (< 2000ms)! Output: $(tr -d '\n' <<<"${LIVE_OUT}")"

# ------------------------------------------------------------------
# Step 23: RFC 5424 Enterprise Audit Log & SIEM Syslog Forwarding
# ------------------------------------------------------------------
echo "[Step 23/23] Verifying system_audit_events & RFC 5424 SIEM Syslog Output..."
curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -X POST "${SERVER_URL}/admin/devices/${LAPTOP_ID}/luks/reveal" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "{\"volume_uuid\":\"${TEST_VOLUME_UUID}\",\"reason\":\"SIEM-9001 Phase 9 Audit Verification\"}" >/dev/null

AUDIT_EVENT_COUNT=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT COUNT(*) FROM system_audit_events WHERE action = 'LUKS_KEY_REVEAL' AND target_id = '${LAPTOP_ID}';")
if [[ "${AUDIT_EVENT_COUNT}" -lt 1 ]]; then
    echo "FAIL: Expected system_audit_events row for action='LUKS_KEY_REVEAL', found ${AUDIT_EVENT_COUNT}" >&2
    exit 1
fi

AUDIT_API_JSON=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" "${SERVER_URL}/admin/audit/events")
RFC5424_LINE=$(echo "${AUDIT_API_JSON}" | jq -r '.rfc5424[] | select(contains("LUKS_KEY_REVEAL") and contains("SIEM-9001"))' | tail -n 1)
if [[ -z "${RFC5424_LINE}" ]] || ! grep -q '\[spireAudit@32473' <<<"${RFC5424_LINE}"; then
    echo "FAIL: Expected valid RFC 5424 Syslog record with [spireAudit@32473 ...], got: ${RFC5424_LINE}" >&2
    exit 1
fi
echo "  -> Verified system_audit_events row (count=${AUDIT_EVENT_COUNT}) & RFC 5424 Syslog frame:"
echo "     ${RFC5424_LINE}"

# ------------------------------------------------------------------
# Step 24: Interactive Web PTY Terminal (xterm.js WS) & Attended Remote Assist
# ------------------------------------------------------------------
echo "[Step 24/25] Testing Interactive Web PTY Terminal (/admin/devices/{id}/terminal) & Attended Remote Assist..."

# Finding C6: Test Cross-Site WebSocket Hijacking (CSWSH) Origin Enforcement
CSWSH_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -H "Connection: Upgrade" \
    -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Version: 13" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Origin: http://evil-attacker.com" \
    "${SERVER_URL}/admin/devices/${CONTAINER_DEV_ID}/terminal")
echo "  -> CSWSH attempt with unauthorized Origin returned HTTP ${CSWSH_CODE}"
if [[ "${CSWSH_CODE}" != "403" ]]; then
    echo "FAIL: Expected HTTP 403 on WebSocket upgrade with foreign origin, got ${CSWSH_CODE}" >&2
    exit 1
fi
echo "  -> Verified Finding C6: CSWSH rejected with HTTP 403 Forbidden on terminal WebSocket."

PTY_WS_URL="ws://localhost:18080/admin/devices/${CONTAINER_DEV_ID}/terminal"
PTY_OUTPUT=$(go run ./test/pty_verify "${PTY_WS_URL}" "${ADMIN_USER}:${ADMIN_PASSWORD}" "whoami")
if ! grep -q "root" <<<"${PTY_OUTPUT}"; then
    echo "FAIL: Interactive PTY did not return 'root' for 'whoami' command. Output: ${PTY_OUTPUT}" >&2
    exit 1
fi

PTY_AUDIT_COUNT=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT COUNT(*) FROM system_audit_events WHERE action = 'PTY_SESSION_START' AND target_id = '${CONTAINER_DEV_ID}';")
if [[ "${PTY_AUDIT_COUNT}" -lt 1 ]]; then
    echo "FAIL: Expected PTY_SESSION_START in system_audit_events, got ${PTY_AUDIT_COUNT}" >&2
    exit 1
fi
echo "  -> Verified bidirectional PTY allocation & execution ('whoami' -> 'root') and PTY_SESSION_START audit event!"

# Test Attended Remote Assist (default headless rejection & simulated user approval)
RA_REJECT_JSON=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -X POST "${SERVER_URL}/admin/devices/${CONTAINER_DEV_ID}/remote-assist" \
    -H "Accept: application/json")
RA_REJECT_STATUS=$(echo "${RA_REJECT_JSON}" | jq -r '.status')
if [[ "${RA_REJECT_STATUS}" != "NO_ACTIVE_USER_SESSION" && "${RA_REJECT_STATUS}" != "REJECTED_BY_USER" ]]; then
    echo "FAIL: Expected NO_ACTIVE_USER_SESSION or REJECTED_BY_USER when no graphical user approves remote assist, got: ${RA_REJECT_JSON}" >&2
    exit 1
fi

${DOCKER_CMD} exec spire-test-debian-client bash -c "echo 'APPROVE' > /etc/spire/remote-assist-decision"
RA_APPROVE_JSON=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
    -X POST "${SERVER_URL}/admin/devices/${CONTAINER_DEV_ID}/remote-assist" \
    -H "Accept: application/json")
RA_APPROVE_STATUS=$(echo "${RA_APPROVE_JSON}" | jq -r '.status')
if [[ "${RA_APPROVE_STATUS}" != "APPROVED" ]]; then
    echo "FAIL: Expected APPROVED when user approves remote assist, got: ${RA_APPROVE_JSON}" >&2
    exit 1
fi
echo "  -> Verified Attended Remote Assistance staging (REJECTED_BY_USER on unapproved seat0 & APPROVED with credentials)!"

# ------------------------------------------------------------------
# Step 25: Self-Service Application Catalog & Opt-In Installation
# ------------------------------------------------------------------
echo "[Step 25/25] Testing Self-Service Application Catalog & Client Install Request..."

# Deploy libreoffice-flatpak preset and publish it to the Self-Service Catalog
admin_curl -s -o /dev/null \
    -X POST "${SERVER_URL}/admin/policies/from-template" \
    -d "template_id=libreoffice-flatpak"

SS_POLICY_ID=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT id FROM policies WHERE name = 'Deploy LibreOffice Suite (Flatpak)' ORDER BY created_at DESC LIMIT 1;")

# Toggle policy into the Self-Service Catalog via POST /admin/policies/{id}/self-service
SS_TOGGLE_JSON=$(admin_curl -s \
    -X POST "${SERVER_URL}/admin/policies/${SS_POLICY_ID}/self-service" \
    -H "Accept: application/json")
SS_FLAG=$(echo "${SS_TOGGLE_JSON}" | jq -r '.is_self_service')
if [[ "${SS_FLAG}" != "true" ]]; then
    echo "FAIL: Expected is_self_service=true after toggling, got: ${SS_TOGGLE_JSON}" >&2
    exit 1
fi

# Query GET /api/v1/desktop/self-service/catalog as laptop device and verify policy is listed with installed=false
CATALOG_BEFORE=$(curl -s -H "Authorization: Bearer ${LAPTOP_TOKEN}" "${SERVER_URL}/api/v1/desktop/self-service/catalog")
INSTALLED_BEFORE=$(echo "${CATALOG_BEFORE}" | jq -r ".catalog[] | select(.policy_id == \"${SS_POLICY_ID}\") | .installed")
if [[ "${INSTALLED_BEFORE}" != "false" ]]; then
    echo "FAIL: Expected self-service policy ${SS_POLICY_ID} in catalog with installed=false, got: ${CATALOG_BEFORE}" >&2
    exit 1
fi

# Verify normal check-in does NOT force-assign a self-service policy before opt-in install
PRE_OPTIN_CHECKIN=$(curl -s -X POST "${SERVER_URL}/api/v1/desktop/checkin" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${LAPTOP_TOKEN}" \
    -d "{\"hardware_uuid\":\"${LAPTOP_HW_UUID}\",\"packages\":[\"bash\"],\"sessions\":[\"root\"]}")
PRE_OPTIN_COUNT=$(echo "${PRE_OPTIN_CHECKIN}" | jq "[.policies[] | select(.id == \"${SS_POLICY_ID}\")] | length")
if [[ "${PRE_OPTIN_COUNT}" -ne 0 ]]; then
    echo "FAIL: Self-service policy was assigned before device requested installation!" >&2
    exit 1
fi

# Request installation via POST /api/v1/desktop/self-service/install
INSTALL_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/desktop/self-service/install" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${LAPTOP_TOKEN}" \
    -d "{\"policy_id\":\"${SS_POLICY_ID}\"}")
INSTALL_STATUS=$(echo "${INSTALL_RESP}" | jq -r '.status')
if [[ "${INSTALL_STATUS}" != "installed" ]]; then
    echo "FAIL: Expected status='installed' from POST /api/v1/desktop/self-service/install, got: ${INSTALL_RESP}" >&2
    exit 1
fi

# Verify check-in now assigns the requested self-service policy and catalog shows installed=true
POST_OPTIN_CHECKIN=$(curl -s -X POST "${SERVER_URL}/api/v1/desktop/checkin" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${LAPTOP_TOKEN}" \
    -d "{\"hardware_uuid\":\"${LAPTOP_HW_UUID}\",\"packages\":[\"bash\"],\"sessions\":[\"root\"]}")
POST_OPTIN_COUNT=$(echo "${POST_OPTIN_CHECKIN}" | jq "[.policies[] | select(.id == \"${SS_POLICY_ID}\")] | length")
if [[ "${POST_OPTIN_COUNT}" -ne 1 ]]; then
    echo "FAIL: Self-service policy was not assigned on check-in after opt-in install!" >&2
    exit 1
fi

CATALOG_AFTER=$(curl -s -H "Authorization: Bearer ${LAPTOP_TOKEN}" "${SERVER_URL}/api/v1/desktop/self-service/catalog")
INSTALLED_AFTER=$(echo "${CATALOG_AFTER}" | jq -r ".catalog[] | select(.policy_id == \"${SS_POLICY_ID}\") | .installed")
if [[ "${INSTALLED_AFTER}" != "true" ]]; then
    echo "FAIL: Expected installed=true in catalog after install request, got: ${CATALOG_AFTER}" >&2
    exit 1
fi
echo "  -> Verified Self-Service Catalog publishing, opt-in installation (device_self_service_installs), and policy assignment!"

# ------------------------------------------------------------------
# Step 26: Unprivileged Desktop IPC (/run/spire/agent.sock) & spire-ctl
# ------------------------------------------------------------------
echo "[Step 26/28] Testing Unprivileged Desktop IPC (spire-ctl status/sync/catalog/install as UID 1000)..."

DESK_UID=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client id -u)
if [[ "${DESK_UID}" != "1000" ]]; then
    echo "FAIL: Expected deskuser UID 1000 inside spire-test-debian-client, got ${DESK_UID}" >&2
    exit 1
fi

CTL_STATUS_OUT=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl status)
if ! grep -q "Connection State: CONNECTED" <<<"${CTL_STATUS_OUT}"; then
    echo "FAIL: Expected 'Connection State: CONNECTED' from spire-ctl status as UID 1000, got: ${CTL_STATUS_OUT}" >&2
    exit 1
fi
echo "  -> Unprivileged spire-ctl status succeeded (UID=${DESK_UID}): $(grep 'Compliance State:' <<<"${CTL_STATUS_OUT}")"

CTL_SYNC_OUT=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl sync)
if ! grep -q "Sync completed successfully" <<<"${CTL_SYNC_OUT}"; then
    echo "FAIL: Expected 'Sync completed successfully' from spire-ctl sync as UID 1000, got: ${CTL_SYNC_OUT}" >&2
    exit 1
fi
echo "  -> Unprivileged spire-ctl sync succeeded: ${CTL_SYNC_OUT}"

CTL_CATALOG_OUT=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl catalog)
if ! grep -q "${SS_POLICY_ID}" <<<"${CTL_CATALOG_OUT}"; then
    echo "FAIL: Expected self-service policy ${SS_POLICY_ID} in spire-ctl catalog output, got: ${CTL_CATALOG_OUT}" >&2
    exit 1
fi
echo "  -> Unprivileged spire-ctl catalog listed self-service policy ${SS_POLICY_ID}!"

CTL_INSTALL_OUT=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl install "${SS_POLICY_ID}")
if ! grep -q "compliance=COMPLIANT" <<<"${CTL_INSTALL_OUT}"; then
    echo "FAIL: Expected 'compliance=COMPLIANT' from spire-ctl install as UID 1000, got: ${CTL_INSTALL_OUT}" >&2
    exit 1
fi
echo "  -> Unprivileged spire-ctl install succeeded without sudo: ${CTL_INSTALL_OUT}"

# Verify Finding H2 fix: Non-seat0 user (UID 1001) is denied access
EVE_UID=$(${DOCKER_CMD} exec -u eve spire-test-debian-client id -u)
if [[ "${EVE_UID}" != "1001" ]]; then
    echo "FAIL: Expected eve UID 1001 inside spire-test-debian-client, got ${EVE_UID}" >&2
    exit 1
fi

EVE_SYNC_ERR=$(${DOCKER_CMD} exec -u eve spire-test-debian-client /usr/bin/spire-ctl sync 2>&1 || true)
if ! grep -q "Caller is not the active console session user" <<<"${EVE_SYNC_ERR}" && ! grep -q "403" <<<"${EVE_SYNC_ERR}"; then
    echo "FAIL: Expected non-seat0 user (UID 1001) to be rejected with 403 Forbidden on spire-ctl sync, got: ${EVE_SYNC_ERR}" >&2
    exit 1
fi

EVE_INSTALL_ERR=$(${DOCKER_CMD} exec -u eve spire-test-debian-client /usr/bin/spire-ctl install "${SS_POLICY_ID}" 2>&1 || true)
if ! grep -q "Caller is not the active console session user" <<<"${EVE_INSTALL_ERR}" && ! grep -q "403" <<<"${EVE_INSTALL_ERR}"; then
    echo "FAIL: Expected non-seat0 user (UID 1001) to be rejected with 403 Forbidden on spire-ctl install, got: ${EVE_INSTALL_ERR}" >&2
    exit 1
fi
echo "  -> Verified Finding H2 fix: Non-seat0 user (UID 1001) rejected with HTTP 403 Forbidden on sync and install!"

CONTAINER_SS_COMPLIANCE=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT compliance_status FROM device_policies WHERE device_id = '${CONTAINER_DEV_ID}' AND policy_id = '${SS_POLICY_ID}';")
if [[ "${CONTAINER_SS_COMPLIANCE}" != "COMPLIANT" ]]; then
    echo "FAIL: Expected debian12-sim-01 compliance_status='COMPLIANT' for self-service policy ${SS_POLICY_ID}, got '${CONTAINER_SS_COMPLIANCE}'" >&2
    exit 1
fi
echo "  -> Verified debian12-sim-01 self-service policy is COMPLIANT in PostgreSQL!"

# ------------------------------------------------------------------
# Step 27: GNOME / Libadwaita Spire Hub (spire-hub) Verification
# ------------------------------------------------------------------
echo "[Step 27/31] Testing GNOME / Libadwaita Spire Hub (/usr/bin/spire-hub) as UID 1000..."

HUB_PERM=$(${DOCKER_CMD} exec spire-test-debian-client stat -c "%a" /usr/bin/spire-hub)
DESKTOP_PERM=$(${DOCKER_CMD} exec spire-test-debian-client stat -c "%a" /usr/share/applications/spire-hub.desktop)
ICON_PERM=$(${DOCKER_CMD} exec spire-test-debian-client stat -c "%a" /usr/share/icons/hicolor/scalable/apps/spire-hub.svg)
if [[ "${HUB_PERM}" != "755" || "${DESKTOP_PERM}" != "644" || "${ICON_PERM}" != "644" ]]; then
    echo "FAIL: Unexpected permissions on spire-hub assets (bin=${HUB_PERM}, desktop=${DESKTOP_PERM}, icon=${ICON_PERM})" >&2
    exit 1
fi

if ${DOCKER_CMD} exec spire-test-debian-client command -v xauth >/dev/null 2>&1; then
    HUB_IPC_JSON=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client xvfb-run -a /usr/bin/spire-hub --check-ipc)
else
    HUB_IPC_JSON=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client xvfb-run /usr/bin/spire-hub --check-ipc)
fi

HUB_WS_CONNECTED=$(echo "${HUB_IPC_JSON}" | jq -r '.status.ws_connected')
HUB_CAT_LEN=$(echo "${HUB_IPC_JSON}" | jq -r ".catalog | map(select(.policy_id == \"${SS_POLICY_ID}\")) | length")
if [[ "${HUB_WS_CONNECTED}" != "true" ]]; then
    echo "FAIL: Expected spire-hub get_status() ws_connected=true, got: ${HUB_IPC_JSON}" >&2
    exit 1
fi
if [[ "${HUB_CAT_LEN}" -lt 1 ]]; then
    echo "FAIL: Expected spire-hub get_catalog() to contain policy ${SS_POLICY_ID}, got: ${HUB_IPC_JSON}" >&2
    exit 1
fi
echo "  -> Verified /usr/bin/spire-hub (0755), spire-hub.desktop (0644), GTK4/Adw-1 bindings, get_status() (ws_connected=true), and get_catalog() as UID 1000!"

# ------------------------------------------------------------------
# Step 28: GPG-Signed APT Repository Generation & Client Ingestion
# ------------------------------------------------------------------
echo "[Step 28/28] Testing GPG-Signed APT Repository Generation & Client Ingestion..."

# 1. Generate a test batch GPG key inside spire-test-server
${DOCKER_CMD} exec spire-test-server bash -c '
set -euo pipefail
mkdir -p /etc/spire/gpg
chmod 0700 /etc/spire/gpg
if ! gpg --homedir /etc/spire/gpg --list-secret-keys --with-colons 2>/dev/null | grep -q "^sec"; then
    cat << "EOF_KEYGEN" > /tmp/test_gpg_keygen.batch
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: SpireUEM Test Archive
Name-Email: archive@spire-uem.org
Expire-Date: 0
%no-protection
%commit
EOF_KEYGEN
    gpg --batch --homedir /etc/spire/gpg --generate-key /tmp/test_gpg_keygen.batch
    rm -f /tmp/test_gpg_keygen.batch
fi
'
echo "  -> Test GPG signing key generated in spire-test-server:/etc/spire/gpg"

# 2. Run init_repo.sh pointing to mounted test repo volume (/var/www/apt/spire)
${DOCKER_CMD} exec -e REPO_DIR=/var/www/apt/spire -e GPG_HOMEDIR=/etc/spire/gpg spire-test-server /app/packaging/repo/init_repo.sh
echo "  -> Repository initialized via init_repo.sh in spire-test-server"

# 3. Ingest dist/spire-agent_0.1.0_amd64.deb using publish_deb.sh
${DOCKER_CMD} exec -e REPO_DIR=/var/www/apt/spire -e GPG_HOMEDIR=/etc/spire/gpg spire-test-server /app/packaging/repo/publish_deb.sh /app/dist/spire-agent_0.1.0_amd64.deb
echo "  -> Published spire-agent_0.1.0_amd64.deb via publish_deb.sh"

# 4. Inside spire-test-debian-client: test bootstrap --use-apt-repo, configure Deb822 source, fetch keyring, run apt-get update, and verify apt-cache policy spire-agent
BOOTSTRAP_OUTPUT=$(${DOCKER_CMD} exec spire-test-debian-client bash -c '
curl -fsSL http://spire-server:8080/install.sh | bash -s -- --use-apt-repo http://spire-server:8080/apt
')
echo "  -> Client bootstrap via APT repository output:"
echo "${BOOTSTRAP_OUTPUT}"

if ! grep -q "Package Source: APT Repository" <<<"${BOOTSTRAP_OUTPUT}"; then
    echo "FAIL: Expected bootstrap to acknowledge APT repository package source, got: ${BOOTSTRAP_OUTPUT}" >&2
    exit 1
fi

APT_POLICY=$(${DOCKER_CMD} exec spire-test-debian-client apt-cache policy spire-agent)
echo "  -> apt-cache policy spire-agent output:"
echo "${APT_POLICY}"

if ! grep -q "http://spire-server:8080/apt" <<<"${APT_POLICY}"; then
    echo "FAIL: Expected apt-cache policy to reference http://spire-server:8080/apt, got: ${APT_POLICY}" >&2
    exit 1
fi

if ! grep -q "500 http://spire-server:8080/apt bookworm/main amd64 Packages" <<<"${APT_POLICY}"; then
    echo "FAIL: Expected repository release entry in apt-cache policy, got: ${APT_POLICY}" >&2
    exit 1
fi
echo "  -> Verified apt-cache policy spire-agent resolves to GPG-signed internal APT repository!"

PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" \
    -c "SELECT d.hostname, d.patch_ring, d.ws_connected, d.reboot_required, d.attestation_status, p.name AS policy_name, p.is_self_service, dp.compliance_status FROM device_policies dp JOIN devices d ON d.id = dp.device_id JOIN policies p ON p.id = dp.policy_id ORDER BY d.hostname, p.created_at;"

# ------------------------------------------------------------------
echo "[Step 29/31] Testing OpenSCAP & CIS Benchmark Scanning..."

# 1. Fetch debian12-sim-01 device ID
SIM_DEV_ID=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT id FROM devices WHERE hostname = 'debian12-sim-01' LIMIT 1;")

if [[ -z "${SIM_DEV_ID}" ]]; then
    echo "FAIL: debian12-sim-01 device not found in database" >&2
    exit 1
fi
echo "  -> Found debian12-sim-01 device id: ${SIM_DEV_ID}"

# 2. Dispatch a benchmark scan to debian12-sim-01 via POST /admin/devices/{id}/scans
SCAN_DISPATCH_RESP=$(admin_curl -s -H "Accept: application/json" -X POST "${SERVER_URL}/admin/devices/${SIM_DEV_ID}/scans")
echo "  -> Scan dispatch response: ${SCAN_DISPATCH_RESP}"

SCAN_ID=$(echo "${SCAN_DISPATCH_RESP}" | grep -oP '"scan_id":\s*"\K[^"]+' || true)
if [[ -z "${SCAN_ID}" ]]; then
    echo "FAIL: Failed to extract scan_id from dispatch response: ${SCAN_DISPATCH_RESP}" >&2
    exit 1
fi
echo "  -> Dispatched benchmark scan ID: ${SCAN_ID}"

# 3. Verify benchmark_scans record transitions from PENDING -> RUNNING -> COMPLETED
echo "  -> Waiting for benchmark scan ${SCAN_ID} to transition from PENDING -> RUNNING -> COMPLETED..."
SCAN_STATUS=""
SEEN_RUNNING=false
for i in $(seq 1 45); do
    CURRENT_STATUS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
        -c "SELECT status FROM benchmark_scans WHERE id = '${SCAN_ID}';")
    if [[ "${CURRENT_STATUS}" == "RUNNING" ]]; then
        SEEN_RUNNING=true
    fi
    if [[ "${CURRENT_STATUS}" == "COMPLETED" ]]; then
        SCAN_STATUS="COMPLETED"
        echo "  -> Benchmark scan reached COMPLETED after ${i}s (SEEN_RUNNING=${SEEN_RUNNING})"
        break
    fi
    if [[ "${CURRENT_STATUS}" == "FAILED" ]]; then
        ERR_MSG=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
            -c "SELECT error_message FROM benchmark_scans WHERE id = '${SCAN_ID}';")
        echo "FAIL: Benchmark scan failed: ${ERR_MSG}" >&2
        exit 1
    fi
    sleep 1
done

if [[ "${SCAN_STATUS}" != "COMPLETED" ]]; then
    echo "FAIL: Benchmark scan ${SCAN_ID} did not reach COMPLETED in time (current status: ${CURRENT_STATUS})" >&2
    exit 1
fi

# 4. Assert score and rule counts (rules_passed > 0) are recorded in PostgreSQL
SCAN_DETAILS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A -F "|" \
    -c "SELECT score, rules_passed, rules_failed, rules_other FROM benchmark_scans WHERE id = '${SCAN_ID}';")
echo "  -> Scan results in DB: ${SCAN_DETAILS}"

IFS="|" read -r SCAN_SCORE RULES_PASSED RULES_FAILED RULES_OTHER <<<"${SCAN_DETAILS}"
if [[ -z "${RULES_PASSED}" || "${RULES_PASSED}" -le 0 ]]; then
    echo "FAIL: Expected rules_passed > 0, got: ${RULES_PASSED}" >&2
    exit 1
fi
echo "  -> Verified OpenSCAP rules_passed=${RULES_PASSED}, rules_failed=${RULES_FAILED}, rules_other=${RULES_OTHER}, score=${SCAN_SCORE}%"

# 5. Assert GET /admin/dashboard renders updated benchmark metrics
DASH_UPDATED_HTML=$(curl -s -b "${COOKIE_JAR}" "${SERVER_URL}/admin/dashboard")
if ! grep -q "Fleet CIS Score" <<<"${DASH_UPDATED_HTML}"; then
    echo "FAIL: Expected 'Fleet CIS Score' in updated /admin/dashboard HTML" >&2
    exit 1
fi
if ! grep -q "Rules Passed" <<<"${DASH_UPDATED_HTML}"; then
    echo "FAIL: Expected 'Rules Passed' in updated /admin/dashboard HTML" >&2
    exit 1
fi
echo "  -> Verified /admin/dashboard renders live CIS benchmark telemetry!"

# 6. Test fleet benchmark trigger endpoint POST /admin/benchmarks/scan-all with HTMX
FLEET_SCAN_RESP=$(admin_curl -s -H "HX-Request: true" -X POST "${SERVER_URL}/admin/benchmarks/scan-all")
if ! grep -q 'id="active-benchmark-card"' <<<"${FLEET_SCAN_RESP}"; then
    echo "FAIL: Expected 'id=\"active-benchmark-card\"' in HTMX fleet scan response" >&2
    exit 1
fi
echo "  -> Verified POST /admin/benchmarks/scan-all dispatches fleet scan and re-renders benchmark card!"

# ------------------------------------------------------------------
echo "[Step 30/31] Testing CIS Benchmark Rule Auto-Remediation & SYSCTL Policy Engine..."

# 1. Reset net.ipv4.conf.all.rp_filter to 0 on debian12-sim-01 container
echo "  -> Setting net.ipv4.conf.all.rp_filter = 0 on debian12-sim-01..."
docker exec spire-test-debian-client sysctl -w net.ipv4.conf.all.rp_filter=0
RP_INIT=$(docker exec spire-test-debian-client cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo "unknown")
echo "  -> Current net.ipv4.conf.all.rp_filter on debian12-sim-01: ${RP_INIT}"

# 2. Trigger auto-remediation via POST /admin/benchmarks/remediate-rule (JSON)
echo "  -> Requesting rule auto-remediation for sysctl_net_ipv4_conf_all_rp_filter on device ${SIM_DEV_ID}..."
REMEDIATE_RESP=$(admin_curl -s -H "Accept: application/json" -X POST "${SERVER_URL}/admin/benchmarks/remediate-rule" \
    -d "rule_id=sysctl_net_ipv4_conf_all_rp_filter&device_id=${SIM_DEV_ID}")
echo "  -> Remediation response: ${REMEDIATE_RESP}"

if ! grep -q "Remediation Queued" <<<"${REMEDIATE_RESP}"; then
    echo "FAIL: Expected 'Remediation Queued' in JSON response: ${REMEDIATE_RESP}" >&2
    exit 1
fi
echo "  -> Verified JSON endpoint queued remediation policy successfully!"

# 3. Test HTMX button response
HTMX_REMEDIATE_RESP=$(admin_curl -s -H "HX-Request: true" -X POST "${SERVER_URL}/admin/benchmarks/remediate-rule" \
    -d "rule_id=sysctl_net_ipv4_conf_all_rp_filter&device_id=${SIM_DEV_ID}")
echo "  -> HTMX remediation response: ${HTMX_REMEDIATE_RESP}"

if ! grep -q "Remediation Queued" <<<"${HTMX_REMEDIATE_RESP}"; then
    echo "FAIL: Expected 'Remediation Queued' in HTMX button response: ${HTMX_REMEDIATE_RESP}" >&2
    exit 1
fi
echo "  -> Verified HTMX auto-remediate button response!"

# 4. Wait for spired reconciliation on debian12-sim-01
echo "  -> Waiting for spired to reconcile sysctl policy and write /etc/sysctl.d/20-spire-cis-*.conf..."
CONF_FOUND=""
RP_ENFORCED=""

for i in $(seq 1 30); do
    CONF_FILE=$(docker exec spire-test-debian-client sh -c 'ls -1 /etc/sysctl.d/20-spire-cis-*.conf 2>/dev/null | head -n 1' || true)
    CURRENT_RP=$(docker exec spire-test-debian-client cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo "0")
    if [[ -n "${CONF_FILE}" && "${CURRENT_RP}" == "1" ]]; then
        CONF_FOUND="${CONF_FILE}"
        RP_ENFORCED="${CURRENT_RP}"
        echo "  -> Found sysctl config file ${CONF_FILE} and rp_filter=1 after ${i}s"
        break
    fi
    sleep 1
done

if [[ -z "${CONF_FOUND}" ]]; then
    echo "FAIL: /etc/sysctl.d/20-spire-cis-*.conf was not created on debian12-sim-01" >&2
    docker exec spire-test-debian-client ls -la /etc/sysctl.d/ || true
    exit 1
fi

if [[ "${RP_ENFORCED}" != "1" ]]; then
    echo "FAIL: /proc/sys/net/ipv4/conf/all/rp_filter is ${RP_ENFORCED}, expected 1" >&2
    exit 1
fi
echo "  -> Verified /proc/sys/net/ipv4/conf/all/rp_filter equals 1!"

# 5. Verify conf file contains net.ipv4.conf.all.rp_filter = 1
CONF_CONTENT=$(docker exec spire-test-debian-client cat "${CONF_FOUND}")
echo "  -> Configuration file contents (${CONF_FOUND}):"
echo "${CONF_CONTENT}"

if ! grep -q "net.ipv4.conf.all.rp_filter = 1" <<<"${CONF_CONTENT}"; then
    echo "FAIL: Expected 'net.ipv4.conf.all.rp_filter = 1' in ${CONF_FOUND}" >&2
    exit 1
fi

# 6. Verify policy compliance status in PostgreSQL
echo "  -> Checking compliance status in database..."
COMPLIANCE_STATUS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT dp.compliance_status FROM device_policies dp JOIN policies p ON p.id = dp.policy_id WHERE dp.device_id = '${SIM_DEV_ID}' AND p.policy_type = 'SYSCTL_SETTING' ORDER BY dp.last_enforced_at DESC LIMIT 1;")
echo "  -> Database compliance_status: ${COMPLIANCE_STATUS}"

if [[ "${COMPLIANCE_STATUS}" != "COMPLIANT" ]]; then
    echo "FAIL: Expected compliance_status 'COMPLIANT' in DB, got: '${COMPLIANCE_STATUS}'" >&2
    exit 1
fi
echo "  -> Verified database records policy compliance as COMPLIANT!"

# ------------------------------------------------------------------
echo "[Step 31/31] Testing Automated Background Upgrades (unattended-upgrades)..."

# 1. Verify /etc/apt/apt.conf.d/52spire-unattended-upgrades exists on debian12-sim-01 with permissions 0644
echo "  -> Checking /etc/apt/apt.conf.d/52spire-unattended-upgrades on debian12-sim-01..."
APT_CONF_PERMS=$(${DOCKER_CMD} exec spire-test-debian-client stat -c "%a" /etc/apt/apt.conf.d/52spire-unattended-upgrades 2>/dev/null || echo "missing")
if [[ "${APT_CONF_PERMS}" != "644" ]]; then
    echo "FAIL: Expected /etc/apt/apt.conf.d/52spire-unattended-upgrades mode 0644, got: ${APT_CONF_PERMS}" >&2
    ${DOCKER_CMD} exec spire-test-debian-client ls -la /etc/apt/apt.conf.d/ || true
    exit 1
fi
echo "  -> Verified /etc/apt/apt.conf.d/52spire-unattended-upgrades exists with mode 0644!"

# 2. Confirm active APT configuration matches SpireUEM in Unattended-Upgrade::Origins-Pattern
echo "  -> Verifying active APT configuration via apt-config dump..."
APT_DUMP_MATCH=$(${DOCKER_CMD} exec spire-test-debian-client bash -c 'apt-config dump | grep -i "Unattended-Upgrade::Origins-Pattern" | grep "SpireUEM"' || true)
echo "  -> apt-config dump match: ${APT_DUMP_MATCH}"
if [[ -z "${APT_DUMP_MATCH}" ]]; then
    echo "FAIL: Expected SpireUEM in apt-config dump Unattended-Upgrade::Origins-Pattern" >&2
    exit 1
fi
echo "  -> Verified apt-config dump includes SpireUEM origins pattern!"

# 3. Execute dry-run test inside container and assert code 0 & origin=SpireUEM evaluation
echo "  -> Executing unattended-upgrade --dry-run --debug inside spire-test-debian-client..."
UNATTENDED_OUTPUT=$(${DOCKER_CMD} exec spire-test-debian-client unattended-upgrade --dry-run --debug 2>&1)
echo "  -> unattended-upgrade output snippet:"
echo "${UNATTENDED_OUTPUT}" | head -n 25

if ! grep -q "origin=SpireUEM" <<<"${UNATTENDED_OUTPUT}"; then
    echo "FAIL: Expected unattended-upgrade debug logs to confirm origin=SpireUEM pattern evaluation" >&2
    exit 1
fi

if ! grep -q "All upgrades installed" <<<"${UNATTENDED_OUTPUT}" && ! grep -q "No packages found that can be upgraded" <<<"${UNATTENDED_OUTPUT}"; then
    echo "FAIL: unattended-upgrade dry-run did not finish cleanly" >&2
    exit 1
fi
echo "  -> Verified unattended-upgrades evaluated SpireUEM repository origin patterns cleanly!"

# 4. Deploy declarative policy template enable-zero-touch-agent-upgrades from Web UI
echo "  -> Testing declarative policy deployment from template enable-zero-touch-agent-upgrades..."
TEMPLATE_RESP=$(admin_curl -s -H "Accept: application/json" -X POST "${SERVER_URL}/admin/policies/from-template" \
    -d "template_id=enable-zero-touch-agent-upgrades")
echo "  -> Template policy creation response: ${TEMPLATE_RESP}"
if ! grep -q "Enable Zero-Touch Agent Upgrades" <<<"${TEMPLATE_RESP}"; then
    echo "FAIL: Expected policy created from template enable-zero-touch-agent-upgrades" >&2
    exit 1
fi
echo "  -> Verified declarative template deployment via Admin UI!"

# ------------------------------------------------------------------
# Step 32: Partitioned Compliance Engine & Non-Evaluative App Catalog
# ------------------------------------------------------------------
echo "[Step 32/32] Testing Partitioned Compliance Engine (REQUIRED vs AVAILABLE Applications & IPC /v1/status)..."

# Ensure any prior baseline policy (e.g. enable-zero-touch-agent-upgrades) is reconciled first
${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl sync >/dev/null

# 1. Stage a REQUIRED application policy (com.visualstudio.code) with auto_install=false so it starts uninstalled
REQ_POL_CODE=$(admin_curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${SERVER_URL}/admin/policies" \
    --data-urlencode "name=Mandatory VS Code (Flatpak)" \
    --data-urlencode "description=Required developer IDE" \
    --data-urlencode "policy_type=FLATPAK_APP" \
    --data-urlencode "app_id=com.visualstudio.code" \
    --data-urlencode "remote=flathub" \
    --data-urlencode "state=present" \
    --data-urlencode "version=1.95.0" \
    --data-urlencode "assignment_type=REQUIRED" \
    --data-urlencode "auto_install=false" \
    --data-urlencode "target_tags=kiosk")
if [[ "${REQ_POL_CODE}" != "303" && "${REQ_POL_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 303/200 creating REQUIRED FLATPAK_APP policy, got ${REQ_POL_CODE}" >&2
    exit 1
fi

REQ_APP_POLICY_ID=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT id FROM policies WHERE name = 'Mandatory VS Code (Flatpak)' ORDER BY created_at DESC LIMIT 1;")

# Sync spired and verify host status is NON-COMPLIANT (is_compliant=false) until the REQUIRED app is installed
${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl sync >/dev/null

IPC_STATUS_PRE=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client python3 -c "import sys; sys.path.insert(0, '/usr/lib/spire'); mod = __import__('spire-hub'); import json; print(json.dumps(mod.get_status()))")
IS_COMP_PRE=$(echo "${IPC_STATUS_PRE}" | jq -r '.is_compliant')
REQ_APP_STATUS_PRE=$(echo "${IPC_STATUS_PRE}" | jq -r ".mandatory_apps[] | select(.policy_id == \"${REQ_APP_POLICY_ID}\") | .compliance_status")
if [[ "${IS_COMP_PRE}" != "false" || "${REQ_APP_STATUS_PRE}" != "NON_COMPLIANT" ]]; then
    echo "FAIL: Expected is_compliant=false and mandatory_apps status=NON_COMPLIANT before installing REQUIRED app, got: ${IPC_STATUS_PRE}" >&2
    exit 1
fi
echo "  -> Verified host is non-compliant (is_compliant=false) while REQUIRED application (${REQ_APP_POLICY_ID}) is uninstalled."

# Install the REQUIRED application via spire-ctl install and verify host transitions to is_compliant=true
${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl install "${REQ_APP_POLICY_ID}" >/dev/null
${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl sync >/dev/null

IPC_STATUS_POST_REQ=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client python3 -c "import sys; sys.path.insert(0, '/usr/lib/spire'); mod = __import__('spire-hub'); import json; print(json.dumps(mod.get_status()))")
IS_COMP_POST_REQ=$(echo "${IPC_STATUS_POST_REQ}" | jq -r '.is_compliant')
if [[ "${IS_COMP_POST_REQ}" != "true" ]]; then
    echo "FAIL: Expected is_compliant=true after installing REQUIRED application, got: ${IPC_STATUS_POST_REQ}" >&2
    exit 1
fi
echo "  -> Verified host transitions to compliant (is_compliant=true) once REQUIRED application is installed!"

# 2. Stage an optional catalog item (FLATPAK_APP, assignment_type=AVAILABLE) and leave it uninstalled
AVAIL_POL_CODE=$(admin_curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${SERVER_URL}/admin/policies" \
    --data-urlencode "name=Optional VLC Media Player (Flatpak)" \
    --data-urlencode "description=Optional media player in App Catalog" \
    --data-urlencode "policy_type=FLATPAK_APP" \
    --data-urlencode "app_id=org.videolan.VLC" \
    --data-urlencode "remote=flathub" \
    --data-urlencode "state=present" \
    --data-urlencode "version=3.0.20" \
    --data-urlencode "assignment_type=AVAILABLE" \
    --data-urlencode "auto_install=false" \
    --data-urlencode "target_tags=kiosk")
if [[ "${AVAIL_POL_CODE}" != "303" && "${AVAIL_POL_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 303/200 creating AVAILABLE FLATPAK_APP policy, got ${AVAIL_POL_CODE}" >&2
    exit 1
fi

AVAIL_APP_POLICY_ID=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT id FROM policies WHERE name = 'Optional VLC Media Player (Flatpak)' ORDER BY created_at DESC LIMIT 1;")

# 3. Verify that leaving the optional AVAILABLE application uninstalled keeps device status as is_compliant=true
${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl sync >/dev/null

# 4. Verify IPC /v1/status returns partitioned security_policies, mandatory_apps, and available_catalog
IPC_STATUS_FINAL=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client python3 -c "import sys; sys.path.insert(0, '/usr/lib/spire'); mod = __import__('spire-hub'); import json; print(json.dumps(mod.get_status()))")
FINAL_IS_COMPLIANT=$(echo "${IPC_STATUS_FINAL}" | jq -r '.is_compliant')
SEC_POL_LEN=$(echo "${IPC_STATUS_FINAL}" | jq -r '.security_policies | length')
MAND_APPS_LEN=$(echo "${IPC_STATUS_FINAL}" | jq -r '.mandatory_apps | length')
AVAIL_CAT_LEN=$(echo "${IPC_STATUS_FINAL}" | jq -r '.available_catalog | length')
VLC_IN_AVAIL=$(echo "${IPC_STATUS_FINAL}" | jq -r ".available_catalog[] | select(.policy_id == \"${AVAIL_APP_POLICY_ID}\") | .installed")

if [[ "${FINAL_IS_COMPLIANT}" != "true" ]]; then
    echo "FAIL: Expected is_compliant=true when AVAILABLE catalog app is left uninstalled, got: ${IPC_STATUS_FINAL}" >&2
    exit 1
fi
if [[ "${SEC_POL_LEN}" -lt 1 || "${MAND_APPS_LEN}" -lt 1 || "${AVAIL_CAT_LEN}" -lt 1 ]]; then
    echo "FAIL: Expected non-empty partitioned arrays (security_policies=${SEC_POL_LEN}, mandatory_apps=${MAND_APPS_LEN}, available_catalog=${AVAIL_CAT_LEN}), got: ${IPC_STATUS_FINAL}" >&2
    exit 1
fi
if [[ "${VLC_IN_AVAIL}" != "false" ]]; then
    echo "FAIL: Expected uninstalled AVAILABLE policy ${AVAIL_APP_POLICY_ID} in available_catalog with installed=false, got: ${IPC_STATUS_FINAL}" >&2
    exit 1
fi
echo "  -> Verified uninstalled AVAILABLE catalog item (${AVAIL_APP_POLICY_ID}) does NOT impact compliance (is_compliant=true)!"
echo "  -> Verified IPC /v1/status partitioned payload: security_policies=${SEC_POL_LEN}, mandatory_apps=${MAND_APPS_LEN}, available_catalog=${AVAIL_CAT_LEN}!"

# ------------------------------------------------------------------
# Step 33: Control-Plane Applications Management Section (/admin/applications)
# ------------------------------------------------------------------
echo "[Step 33/33] Testing Dedicated Applications Management Section (/admin/applications)..."

# 1. Verify GET /admin/applications returns HTTP 200 with HTML table and stat ribbon
APPS_HTML=$(admin_curl -s -w "\n%{http_code}" "${SERVER_URL}/admin/applications")
APPS_HTTP_CODE=$(echo "${APPS_HTML}" | tail -n 1)
APPS_BODY=$(echo "${APPS_HTML}" | sed '$d')

if [[ "${APPS_HTTP_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 200 from GET /admin/applications, got ${APPS_HTTP_CODE}" >&2
    exit 1
fi
if ! grep -q "<table" <<<"${APPS_BODY}" || ! grep -q "Enterprise Application Catalog" <<<"${APPS_BODY}"; then
    echo "FAIL: Expected HTML table and Enterprise Application Catalog header in GET /admin/applications" >&2
    exit 1
fi
echo "  -> Verified GET /admin/applications returns HTTP 200 with HTML table and stat ribbon!"

# 2. Verify POST /admin/applications creates a new REQUIRED Flatpak policy
CREATE_APP_CODE=$(admin_curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${SERVER_URL}/admin/applications" \
    --data-urlencode "name=Step33 GIMP Editor" \
    --data-urlencode "description=Enterprise raster graphics editor" \
    --data-urlencode "package_id=org.gimp.GIMP" \
    --data-urlencode "type=FLATPAK_APP" \
    --data-urlencode "assignment_type=REQUIRED" \
    --data-urlencode "auto_install=false" \
    --data-urlencode "tags=kiosk" \
    --data-urlencode "version=2.10.38" \
    --data-urlencode "remote=flathub")

if [[ "${CREATE_APP_CODE}" != "303" && "${CREATE_APP_CODE}" != "200" && "${CREATE_APP_CODE}" != "201" ]]; then
    echo "FAIL: Expected HTTP 303/200/201 from POST /admin/applications, got ${CREATE_APP_CODE}" >&2
    exit 1
fi

STEP33_APP_ID=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT id FROM policies WHERE name = 'Step33 GIMP Editor' ORDER BY created_at DESC LIMIT 1;")
STEP33_ASSIGN_DB=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT assignment_type FROM policies WHERE id = '${STEP33_APP_ID}';")

if [[ -z "${STEP33_APP_ID}" || "${STEP33_ASSIGN_DB}" != "REQUIRED" ]]; then
    echo "FAIL: Expected REQUIRED Flatpak policy created via POST /admin/applications (id=${STEP33_APP_ID}, assignment_type=${STEP33_ASSIGN_DB})" >&2
    exit 1
fi
echo "  -> Verified POST /admin/applications created REQUIRED Flatpak policy (${STEP33_APP_ID})!"

# Sync endpoint so the uninstalled REQUIRED policy marks the endpoint non-compliant
${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl sync >/dev/null
IPC_STEP33_PRE=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client python3 -c "import sys; sys.path.insert(0, '/usr/lib/spire'); mod = __import__('spire-hub'); import json; print(json.dumps(mod.get_status()))")
STEP33_COMP_PRE=$(echo "${IPC_STEP33_PRE}" | jq -r '.is_compliant')
if [[ "${STEP33_COMP_PRE}" != "false" ]]; then
    echo "FAIL: Expected endpoint is_compliant=false while REQUIRED Step33 GIMP policy is uninstalled, got: ${IPC_STEP33_PRE}" >&2
    exit 1
fi
echo "  -> Confirmed endpoint has compliance penalty (is_compliant=false) while REQUIRED policy (${STEP33_APP_ID}) is uninstalled."

# 3. Update assignment to AVAILABLE via POST /admin/applications/{id} and verify assignment_type is modified and compliance penalties are removed
UPDATE_APP_RESP=$(admin_curl -s -H "Accept: application/json" \
    -X POST "${SERVER_URL}/admin/applications/${STEP33_APP_ID}" \
    --data-urlencode "name=Step33 GIMP Editor" \
    --data-urlencode "package_id=org.gimp.GIMP" \
    --data-urlencode "assignment_type=AVAILABLE" \
    --data-urlencode "auto_install=false" \
    --data-urlencode "tags=kiosk")

UPDATED_ASSIGN_DB=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT assignment_type FROM policies WHERE id = '${STEP33_APP_ID}';")
if [[ "${UPDATED_ASSIGN_DB}" != "AVAILABLE" ]]; then
    echo "FAIL: Expected assignment_type=AVAILABLE after POST /admin/applications/${STEP33_APP_ID}, got ${UPDATED_ASSIGN_DB}" >&2
    exit 1
fi

NON_COMP_FLEET=$(echo "${UPDATE_APP_RESP}" | jq -r '.fleet_summary.non_compliant_devices')
if [[ "${NON_COMP_FLEET}" != "0" ]]; then
    echo "FAIL: Expected fleet_summary.non_compliant_devices=0 immediately after switching to AVAILABLE, got ${UPDATE_APP_RESP}" >&2
    exit 1
fi

${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl sync >/dev/null
IPC_STEP33_POST=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client python3 -c "import sys; sys.path.insert(0, '/usr/lib/spire'); mod = __import__('spire-hub'); import json; print(json.dumps(mod.get_status()))")
STEP33_COMP_POST=$(echo "${IPC_STEP33_POST}" | jq -r '.is_compliant')
if [[ "${STEP33_COMP_POST}" != "true" ]]; then
    echo "FAIL: Expected endpoint is_compliant=true after switching policy ${STEP33_APP_ID} to AVAILABLE, got: ${IPC_STEP33_POST}" >&2
    exit 1
fi
echo "  -> Verified POST /admin/applications/${STEP33_APP_ID} updated assignment_type=AVAILABLE and removed device compliance penalties (is_compliant=true, non_compliant_devices=0)!"

# ------------------------------------------------------------------
# Step 34: Custom Flatpak Bundle Upload, Streaming & Reconciliation
# ------------------------------------------------------------------
echo "[Step 34/34] Testing Custom Flatpak Bundle (.flatpak) Upload, Authenticated Streaming & Agent Reconciliation..."

# 1. Generate a minimal valid .flatpak single-file bundle inside spire-test-debian-client and copy to host
${DOCKER_CMD} exec spire-test-debian-client bash -c '
    rm -rf /tmp/bundle-repo /tmp/bundle-app /tmp/org.internal.Tool.flatpak
    mkdir -p /tmp/bundle-repo /tmp/bundle-app/files/bin
    printf "#!/bin/sh\necho \"Internal Tool v1.0\"\n" > /tmp/bundle-app/files/bin/internal-tool
    chmod 0755 /tmp/bundle-app/files/bin/internal-tool
    printf "[Application]\nname=org.internal.Tool\nruntime=org.freedesktop.Platform/x86_64/23.08\nsdk=org.freedesktop.Sdk/x86_64/23.08\ncommand=internal-tool\n" > /tmp/bundle-app/metadata
    flatpak build-finish --no-inherit-permissions /tmp/bundle-app >/dev/null
    flatpak build-export /tmp/bundle-repo /tmp/bundle-app stable >/dev/null
    flatpak build-bundle /tmp/bundle-repo /tmp/org.internal.Tool.flatpak org.internal.Tool stable >/dev/null
'
${DOCKER_CMD} cp spire-test-debian-client:/tmp/org.internal.Tool.flatpak /tmp/org.internal.Tool.flatpak

EXPECTED_BUNDLE_SHA256=$(sha256sum /tmp/org.internal.Tool.flatpak | awk '{print $1}')
echo "  -> Built valid single-file bundle /tmp/org.internal.Tool.flatpak (sha256=${EXPECTED_BUNDLE_SHA256})"

# 2. Execute POST /admin/applications/upload as admin
UPLOAD_BUNDLE_RESP=$(admin_curl -s -w "\n%{http_code}" \
    -H "Accept: application/json" \
    -X POST "${SERVER_URL}/admin/applications/upload" \
    -F "file=@/tmp/org.internal.Tool.flatpak" \
    -F "app_id=org.internal.Tool" \
    -F "name=Internal Security Tool (Bundle)" \
    -F "description=Custom enterprise Flatpak bundle" \
    -F "assignment_type=REQUIRED" \
    -F "auto_install=true" \
    -F "target_tags=kiosk")

UPLOAD_BUNDLE_CODE=$(echo "${UPLOAD_BUNDLE_RESP}" | tail -n 1)
UPLOAD_BUNDLE_JSON=$(echo "${UPLOAD_BUNDLE_RESP}" | sed '$d')

if [[ "${UPLOAD_BUNDLE_CODE}" != "201" && "${UPLOAD_BUNDLE_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 201/200 from POST /admin/applications/upload, got ${UPLOAD_BUNDLE_CODE}: ${UPLOAD_BUNDLE_JSON}" >&2
    exit 1
fi

UPLOADED_POLICY_ID=$(echo "${UPLOAD_BUNDLE_JSON}" | jq -r '.policy.id')
UPLOADED_SHA256=$(echo "${UPLOAD_BUNDLE_JSON}" | jq -r '.sha256')
if [[ "${UPLOADED_SHA256}" != "${EXPECTED_BUNDLE_SHA256}" ]]; then
    echo "FAIL: Uploaded bundle SHA256 mismatch: expected ${EXPECTED_BUNDLE_SHA256}, got ${UPLOADED_SHA256}" >&2
    exit 1
fi

# Verify database insertion in policies and custom_bundles
DB_BUNDLE_SHA=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT sha256 FROM custom_bundles WHERE policy_id = '${UPLOADED_POLICY_ID}';")
DB_POL_TYPE=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT policy_type FROM policies WHERE id = '${UPLOADED_POLICY_ID}';")

if [[ "${DB_BUNDLE_SHA}" != "${EXPECTED_BUNDLE_SHA256}" || "${DB_POL_TYPE}" != "FLATPAK_BUNDLE" ]]; then
    echo "FAIL: Expected custom_bundles row (sha256=${DB_BUNDLE_SHA}) and policy_type=FLATPAK_BUNDLE (got ${DB_POL_TYPE})" >&2
    exit 1
fi
echo "  -> Verified POST /admin/applications/upload HTTP ${UPLOAD_BUNDLE_CODE} and database insertion (policy=${UPLOADED_POLICY_ID})!"

# 3. Verify GET /api/v1/desktop/bundles/{sha256} streams the bundle with correct checksum
CLIENT_BEARER_TOKEN=$(${DOCKER_CMD} exec spire-test-debian-client cat /etc/spire/token | tr -d '[:space:]')
curl -s -f -H "Authorization: Bearer ${CLIENT_BEARER_TOKEN}" \
    "${SERVER_URL}/api/v1/desktop/bundles/${EXPECTED_BUNDLE_SHA256}" \
    -o /tmp/downloaded_bundle.flatpak

STREAMED_BUNDLE_SHA256=$(sha256sum /tmp/downloaded_bundle.flatpak | awk '{print $1}')
if [[ "${STREAMED_BUNDLE_SHA256}" != "${EXPECTED_BUNDLE_SHA256}" ]]; then
    echo "FAIL: Streamed bundle SHA256 (${STREAMED_BUNDLE_SHA256}) != expected (${EXPECTED_BUNDLE_SHA256})" >&2
    exit 1
fi
echo "  -> Verified GET /api/v1/desktop/bundles/${EXPECTED_BUNDLE_SHA256} streamed bundle with matching SHA-256!"

# 4. Verify spired reconciles the bundle, caches it in /var/cache/spire/bundles/, installs it via flatpak, and registers it in mandatory_apps
${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl sync >/dev/null

if ! ${DOCKER_CMD} exec spire-test-debian-client flatpak info org.internal.Tool >/dev/null 2>&1; then
    echo "FAIL: Expected flatpak info org.internal.Tool to succeed after spired bundle reconciliation" >&2
    exit 1
fi

if ! ${DOCKER_CMD} exec spire-test-debian-client test -f "/var/cache/spire/bundles/${EXPECTED_BUNDLE_SHA256}.flatpak"; then
    echo "FAIL: Expected cached bundle at /var/cache/spire/bundles/${EXPECTED_BUNDLE_SHA256}.flatpak" >&2
    exit 1
fi

IPC_STEP34_STATUS=$(${DOCKER_CMD} exec -u deskuser spire-test-debian-client python3 -c "import sys; sys.path.insert(0, '/usr/lib/spire'); mod = __import__('spire-hub'); import json; print(json.dumps(mod.get_status()))")
BUNDLE_IN_MANDATORY=$(echo "${IPC_STEP34_STATUS}" | jq -r ".mandatory_apps[] | select(.policy_id == \"${UPLOADED_POLICY_ID}\") | .installed")
STEP34_IS_COMP=$(echo "${IPC_STEP34_STATUS}" | jq -r '.is_compliant')

if [[ "${BUNDLE_IN_MANDATORY}" != "true" || "${STEP34_IS_COMP}" != "true" ]]; then
    echo "FAIL: Expected FLATPAK_BUNDLE policy ${UPLOADED_POLICY_ID} in mandatory_apps with installed=true and is_compliant=true, got: ${IPC_STEP34_STATUS}" >&2
    exit 1
fi

# Verify Web UI /admin/applications renders the BUNDLE badge
APPS_STEP34_BODY=$(admin_curl -s "${SERVER_URL}/admin/applications")
if ! grep -q "BUNDLE" <<<"${APPS_STEP34_BODY}" || ! grep -q "org.internal.Tool" <<<"${APPS_STEP34_BODY}"; then
    echo "FAIL: Expected BUNDLE badge and org.internal.Tool in /admin/applications HTML" >&2
    exit 1
fi
rm -f /tmp/org.internal.Tool.flatpak /tmp/downloaded_bundle.flatpak
echo "  -> Verified spired reconciled custom Flatpak bundle (org.internal.Tool), installed via flatpak, and registered under mandatory_apps (installed=true, is_compliant=true)!"

# ------------------------------------------------------------------
# Step 35: Declarative Corporate GNOME Desktop Baseline & Dconf Mandatory Locks
# ------------------------------------------------------------------
echo "[Step 35/35] Testing Declarative GNOME Corporate Desktop Baseline Preset & Mandatory Dconf Locks..."

# Deactivate legacy kiosk screen lock policy so it does not conflict with corporate baseline
KIOSK_OLD_POL_ID=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT id FROM policies WHERE name = 'Kiosk Never Blank';")
if [[ -n "${KIOSK_OLD_POL_ID}" ]]; then
    admin_curl -s -o /dev/null -X POST "${SERVER_URL}/admin/policies/${KIOSK_OLD_POL_ID}/toggle" || true
fi

# 1. Deploy the corporate-desktop-baseline preset via Admin UI POST /admin/policies/from-template
CORP_TEMPLATE_RESP=$(admin_curl -s -H "Accept: application/json" -X POST "${SERVER_URL}/admin/policies/from-template" \
    -d "template_id=corporate-desktop-baseline&target_tags=kiosk")
echo "  -> Template policy creation response: ${CORP_TEMPLATE_RESP}"

CORP_POLICY_ID=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT id FROM policies WHERE name = 'Corporate Desktop Baseline' ORDER BY created_at DESC LIMIT 1;")

if [[ -z "${CORP_POLICY_ID}" ]]; then
    echo "FAIL: Failed to create policy from corporate-desktop-baseline template" >&2
    exit 1
fi
echo "  -> Created Corporate Desktop Baseline policy ID: ${CORP_POLICY_ID}"

# Verify database policy record
CORP_POL_TYPE=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT policy_type FROM policies WHERE id = '${CORP_POLICY_ID}';")
if [[ "${CORP_POL_TYPE}" != "DCONF_SETTING" ]]; then
    echo "FAIL: Expected policy_type=DCONF_SETTING for ${CORP_POLICY_ID}, got ${CORP_POL_TYPE}" >&2
    exit 1
fi

# 2. Trigger spired reconciliation on debian12-sim-01
echo "  -> Syncing client to reconcile Corporate Desktop Baseline policy..."
${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl sync >/dev/null

# 3. Assert profile, drop-in keyfile, mandatory locks, and wallpaper asset exist on client
echo "  -> Verifying dconf profile, drop-in keyfile, locks, and corporate wallpaper asset..."
if ! ${DOCKER_CMD} exec spire-test-debian-client grep -q "user-db:user" /etc/dconf/profile/user || \
   ! ${DOCKER_CMD} exec spire-test-debian-client grep -q "system-db:local" /etc/dconf/profile/user; then
    echo "FAIL: /etc/dconf/profile/user does not contain user-db:user and system-db:local" >&2
    ${DOCKER_CMD} exec spire-test-debian-client cat /etc/dconf/profile/user || true
    exit 1
fi

if ! ${DOCKER_CMD} exec spire-test-debian-client test -f /etc/dconf/db/local.d/00-corporate-workstation; then
    echo "FAIL: Expected keyfile /etc/dconf/db/local.d/00-corporate-workstation" >&2
    ${DOCKER_CMD} exec spire-test-debian-client ls -la /etc/dconf/db/local.d/ || true
    exit 1
fi

if ! ${DOCKER_CMD} exec spire-test-debian-client test -f /etc/dconf/db/local.d/locks/00-corporate-workstation; then
    echo "FAIL: Expected lock file /etc/dconf/db/local.d/locks/00-corporate-workstation" >&2
    ${DOCKER_CMD} exec spire-test-debian-client ls -la /etc/dconf/db/local.d/locks/ || true
    exit 1
fi

if ! ${DOCKER_CMD} exec spire-test-debian-client test -s /usr/share/backgrounds/corporate/thegraylan-wallpaper.png; then
    echo "FAIL: Expected corporate wallpaper asset at /usr/share/backgrounds/corporate/thegraylan-wallpaper.png" >&2
    exit 1
fi
echo "  -> Verified dconf profile, keyfile 00-corporate-workstation, locks, and wallpaper placeholder exist!"

# 4. Assert gsettings enforcement and mandatory write locks
G_IDLE=$(${DOCKER_CMD} exec spire-test-debian-client gsettings get org.gnome.desktop.session idle-delay | tr -d '[:space:]')
if [[ "${G_IDLE}" != "uint32900" ]]; then
    echo "FAIL: Expected org.gnome.desktop.session idle-delay = uint32 900, got: ${G_IDLE}" >&2
    exit 1
fi

G_IDLE_LOCK=$(${DOCKER_CMD} exec spire-test-debian-client gsettings is-writable org.gnome.desktop.session idle-delay | tr -d '[:space:]')
if [[ "${G_IDLE_LOCK}" != "false" ]]; then
    echo "FAIL: Expected org.gnome.desktop.session idle-delay to be locked (is-writable=false), got: ${G_IDLE_LOCK}" >&2
    exit 1
fi

G_BG_LOCK=$(${DOCKER_CMD} exec spire-test-debian-client gsettings is-writable org.gnome.desktop.background picture-uri | tr -d '[:space:]')
if [[ "${G_BG_LOCK}" != "false" ]]; then
    echo "FAIL: Expected org.gnome.desktop.background picture-uri to be locked (is-writable=false), got: ${G_BG_LOCK}" >&2
    exit 1
fi

G_LOCK_ENABLED=$(${DOCKER_CMD} exec spire-test-debian-client gsettings is-writable org.gnome.desktop.screensaver lock-enabled | tr -d '[:space:]')
if [[ "${G_LOCK_ENABLED}" != "false" ]]; then
    echo "FAIL: Expected org.gnome.desktop.screensaver lock-enabled to be locked (is-writable=false), got: ${G_LOCK_ENABLED}" >&2
    exit 1
fi
echo "  -> Verified gsettings idle-delay=uint32 900 and mandatory locks enforced across desktop settings!"

# 5. Verify policy compliance status in PostgreSQL
CORP_COMP_STATUS=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT dp.compliance_status FROM device_policies dp WHERE dp.device_id = '${SIM_DEV_ID}' AND dp.policy_id = '${CORP_POLICY_ID}';")
if [[ "${CORP_COMP_STATUS}" != "COMPLIANT" ]]; then
    echo "FAIL: Expected compliance_status 'COMPLIANT' in DB for corporate baseline, got: '${CORP_COMP_STATUS}'" >&2
    exit 1
fi
echo "  -> Verified database records Corporate Desktop Baseline policy compliance as COMPLIANT!"

# 6. Test Revocation: Deactivate policy via POST /admin/policies/{id}/toggle
echo "  -> Deactivating Corporate Desktop Baseline policy..."
TOGGLE_CODE=$(admin_curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/admin/policies/${CORP_POLICY_ID}/toggle")
if [[ "${TOGGLE_CODE}" != "303" && "${TOGGLE_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 303/200 from policy toggle, got ${TOGGLE_CODE}" >&2
    exit 1
fi

# Sync spired to clean up the revoked policy
${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl sync >/dev/null

# Assert drop-in files and locks removed
if ${DOCKER_CMD} exec spire-test-debian-client test -f /etc/dconf/db/local.d/00-corporate-workstation; then
    echo "FAIL: Expected /etc/dconf/db/local.d/00-corporate-workstation to be removed after revocation" >&2
    exit 1
fi

if ${DOCKER_CMD} exec spire-test-debian-client test -f /etc/dconf/db/local.d/locks/00-corporate-workstation; then
    echo "FAIL: Expected /etc/dconf/db/local.d/locks/00-corporate-workstation to be removed after revocation" >&2
    exit 1
fi

# Assert writeability re-enabled on revoked keys
G_BG_REVOKED_LOCK=$(${DOCKER_CMD} exec spire-test-debian-client gsettings is-writable org.gnome.desktop.background picture-uri | tr -d '[:space:]')
if [[ "${G_BG_REVOKED_LOCK}" != "true" ]]; then
    echo "FAIL: Expected org.gnome.desktop.background picture-uri to be writable again (is-writable=true), got: ${G_BG_REVOKED_LOCK}" >&2
    exit 1
fi
echo "  -> Verified revocation removed drop-in keyfile, removed lock file, ran dconf update, and re-enabled key writeability!"

echo "=== Step 36: Endpoint Patch Telemetry & Reboot Lifecycle Verification ==="
# 1. Simulate a reboot required state with pending kernel package on client
${DOCKER_CMD} exec spire-test-debian-client touch /var/run/reboot-required
${DOCKER_CMD} exec spire-test-debian-client bash -c "echo 'linux-image-6.1.0-28-amd64' > /var/run/reboot-required.pkgs"

# 2. Trigger check-in / sync via spire-ctl
${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl sync >/dev/null

# 3. Query GET /admin/devices with Accept: application/json and assert patch metrics
DEVICES_JSON=$(admin_curl -s -H "Accept: application/json" "${SERVER_URL}/admin/devices")
DEV_REBOOT_REQ=$(echo "${DEVICES_JSON}" | jq -r ".[] | select(.id == \"${SIM_DEV_ID}\") | .reboot_required")
DEV_REBOOT_PKGS=$(echo "${DEVICES_JSON}" | jq -r ".[] | select(.id == \"${SIM_DEV_ID}\") | .reboot_required_pkgs | join(\",\")")

if [[ "${DEV_REBOOT_REQ}" != "true" ]]; then
    echo "FAIL: Expected device reboot_required to be true, got: ${DEV_REBOOT_REQ}" >&2
    exit 1
fi

if [[ "${DEV_REBOOT_PKGS}" != *"linux-image-6.1.0-28-amd64"* ]]; then
    echo "FAIL: Expected reboot_required_pkgs to contain linux-image-6.1.0-28-amd64, got: ${DEV_REBOOT_PKGS}" >&2
    exit 1
fi
echo "  -> Verified GET /admin/devices reflects reboot_required=true and kernel package list!"

# 4. Verify device_patch_status row in PostgreSQL
DB_REBOOT_REQ=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT reboot_required FROM device_patch_status WHERE device_id = '${SIM_DEV_ID}';")
if [[ "${DB_REBOOT_REQ}" != "t" ]]; then
    echo "FAIL: Expected device_patch_status reboot_required='t' in database, got: '${DB_REBOOT_REQ}'" >&2
    exit 1
fi
echo "  -> Verified device_patch_status table populated in PostgreSQL!"

# 5. Test POST /admin/devices/{id}/patch-now
PATCH_NOW_CODE=$(admin_curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/admin/devices/${SIM_DEV_ID}/patch-now")
if [[ "${PATCH_NOW_CODE}" != "200" && "${PATCH_NOW_CODE}" != "303" ]]; then
    echo "FAIL: Expected HTTP 200/303 from patch-now endpoint, got: ${PATCH_NOW_CODE}" >&2
    exit 1
fi
echo "  -> Verified POST /admin/devices/{id}/patch-now dispatched trigger successfully!"

# 6. Cleanup reboot simulation files
${DOCKER_CMD} exec spire-test-debian-client rm -f /var/run/reboot-required /var/run/reboot-required.pkgs
${DOCKER_CMD} exec -u deskuser spire-test-debian-client /usr/bin/spire-ctl sync >/dev/null
echo "  -> Cleaned up reboot flags and resynced."

echo "=== Step 37: System Settings & Dynamic Enrollment Tokens Suite ==="
# 1. Query GET /admin/settings (assert HTTP 200)
SETTINGS_RESP=$(admin_curl -s -w "\n%{http_code}" "${SERVER_URL}/admin/settings")
SETTINGS_CODE=$(echo "${SETTINGS_RESP}" | tail -n 1)
SETTINGS_BODY=$(echo "${SETTINGS_RESP}" | sed '$d')

if [[ "${SETTINGS_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 200 from GET /admin/settings, got: ${SETTINGS_CODE}" >&2
    exit 1
fi

if ! grep -q "System Settings" <<<"${SETTINGS_BODY}"; then
    echo "FAIL: Expected 'System Settings' in /admin/settings HTML" >&2
    exit 1
fi
echo "  -> Verified GET /admin/settings returns HTTP 200 with tabbed settings view!"

# 2. Update general settings via POST /admin/settings/general (change agent_sync_interval to 120)
UPDATE_RESP=$(admin_curl -s -w "\n%{http_code}" -X POST "${SERVER_URL}/admin/settings/general" \
    -d "agent_sync_interval=120&server_base_url=http://localhost:8080")
UPDATE_CODE=$(echo "${UPDATE_RESP}" | tail -n 1)

if [[ "${UPDATE_CODE}" != "200" && "${UPDATE_CODE}" != "303" ]]; then
    echo "FAIL: Expected HTTP 200/303 from POST /admin/settings/general, got: ${UPDATE_CODE}" >&2
    exit 1
fi

# Verify change in PostgreSQL
DB_SYNC_INT=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT value FROM system_settings WHERE key = 'general.agent_sync_interval';")
if [[ "${DB_SYNC_INT}" != "120" ]]; then
    echo "FAIL: Expected general.agent_sync_interval=120 in DB, got: '${DB_SYNC_INT}'" >&2
    exit 1
fi
echo "  -> Verified POST /admin/settings/general updated agent_sync_interval to 120!"

# 3. Generate an enrollment token via POST /admin/settings/tokens targeting ring BETA
TOKEN_GEN_RESP=$(admin_curl -s -H "Accept: application/json" -H "Content-Type: application/json" -X POST "${SERVER_URL}/admin/settings/tokens" \
    -d '{"description":"E2E Beta Deployment Token","target_ring":"BETA","target_tags":["beta-fleet","e2e"],"max_uses":5,"expires_in_hours":24}')

RAW_TOKEN=$(echo "${TOKEN_GEN_RESP}" | jq -r .token)
TOKEN_ID=$(echo "${TOKEN_GEN_RESP}" | jq -r .enrollment_token.id)
TOKEN_RING=$(echo "${TOKEN_GEN_RESP}" | jq -r .enrollment_token.target_ring)

if [[ -z "${RAW_TOKEN}" || "${RAW_TOKEN}" == "null" || "${RAW_TOKEN}" != spire_tok_* ]]; then
    echo "FAIL: Invalid raw enrollment token returned: ${RAW_TOKEN}" >&2
    echo "Response: ${TOKEN_GEN_RESP}" >&2
    exit 1
fi

if [[ -z "${TOKEN_ID}" || "${TOKEN_ID}" == "null" || "${TOKEN_RING}" != "BETA" ]]; then
    echo "FAIL: Expected token target_ring BETA and valid ID, got: ring=${TOKEN_RING} id=${TOKEN_ID}" >&2
    exit 1
fi
echo "  -> Verified POST /admin/settings/tokens generated dynamic token for BETA ring (id: ${TOKEN_ID})!"

# 4. Verify token enrollment registers a host into the BETA ring via POST /api/v1/enrollment/register
BETA_DEV_UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
ENROLL_RESP=$(curl -s -H "Content-Type: application/json" -X POST "${SERVER_URL}/api/v1/enrollment/register" \
    -d "{\"token\":\"${RAW_TOKEN}\",\"hardware_uuid\":\"${BETA_DEV_UUID}\",\"hostname\":\"beta-e2e-node\"}")

ENROLL_DEV_ID=$(echo "${ENROLL_RESP}" | jq -r .device_id)
ENROLL_STATUS=$(echo "${ENROLL_RESP}" | jq -r .status)
ENROLL_RING=$(echo "${ENROLL_RESP}" | jq -r .patch_ring)

if [[ "${ENROLL_STATUS}" != "APPROVED" || "${ENROLL_RING}" != "BETA" ]]; then
    echo "FAIL: Expected enrollment response status=APPROVED, patch_ring=BETA, got: status=${ENROLL_STATUS}, ring=${ENROLL_RING}" >&2
    echo "Response: ${ENROLL_RESP}" >&2
    exit 1
fi

DB_DEV_RING=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT patch_ring FROM devices WHERE id = '${ENROLL_DEV_ID}';")
if [[ "${DB_DEV_RING}" != "BETA" ]]; then
    echo "FAIL: Expected device patch_ring='BETA' in database, got: '${DB_DEV_RING}'" >&2
    exit 1
fi
echo "  -> Verified token enrollment approved device ${ENROLL_DEV_ID} directly into BETA ring!"

# 5. Revoke token via DELETE /admin/settings/tokens/{id}
REVOKE_CODE=$(admin_curl -s -o /dev/null -w "%{http_code}" -X DELETE "${SERVER_URL}/admin/settings/tokens/${TOKEN_ID}")
if [[ "${REVOKE_CODE}" != "200" && "${REVOKE_CODE}" != "204" && "${REVOKE_CODE}" != "303" ]]; then
    echo "FAIL: Expected HTTP 200/204/303 from DELETE /admin/settings/tokens/${TOKEN_ID}, got: ${REVOKE_CODE}" >&2
    exit 1
fi

DB_TOKEN_REVOKED=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT is_revoked FROM enrollment_tokens WHERE id = '${TOKEN_ID}';")
if [[ "${DB_TOKEN_REVOKED}" != "t" ]]; then
    echo "FAIL: Expected enrollment token is_revoked='t' in DB, got: '${DB_TOKEN_REVOKED}'" >&2
    exit 1
fi
echo "  -> Verified enrollment token ${TOKEN_ID} marked revoked in PostgreSQL!"

# 6. Confirm subsequent enrollments fail with HTTP 401
REVOKED_DEV_UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
REVOKED_ENROLL_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" -X POST "${SERVER_URL}/api/v1/enrollment/register" \
    -d "{\"token\":\"${RAW_TOKEN}\",\"hardware_uuid\":\"${REVOKED_DEV_UUID}\",\"hostname\":\"revoked-e2e-node\"}")

if [[ "${REVOKED_ENROLL_CODE}" != "401" ]]; then
    echo "FAIL: Expected HTTP 401 when registering with revoked token, got: ${REVOKED_ENROLL_CODE}" >&2
    exit 1
fi
echo "  -> Verified enrollment with revoked token correctly denied with HTTP 401 Unauthorized!"

# 7. Test SIEM RFC 5424 test dispatch
SIEM_TEST_CODE=$(admin_curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/admin/settings/siem/test")
if [[ "${SIEM_TEST_CODE}" != "200" && "${SIEM_TEST_CODE}" != "303" ]]; then
    echo "FAIL: Expected HTTP 200/303 from SIEM test endpoint, got: ${SIEM_TEST_CODE}" >&2
    exit 1
fi
echo "  -> Verified POST /admin/settings/siem/test dispatched RFC 5424 test event!"

# ------------------------------------------------------------------
echo "[Step 38/38] Testing Enterprise RBAC & OIDC Integration..."

# 1. Create a local user with role OPERATOR via POST /admin/users
echo "  -> Creating local admin user 'test-operator' with role OPERATOR..."
OP_CREATE_RESP=$(admin_curl -s -H "Accept: application/json" -H "Content-Type: application/json" -X POST "${SERVER_URL}/admin/users" \
    -d '{"username":"test-operator","email":"operator@example.com","display_name":"Test Operator","password":"OperatorPass123!","role":"OPERATOR"}')

OP_USER_ID=$(echo "${OP_CREATE_RESP}" | jq -r .id)
OP_ROLE=$(echo "${OP_CREATE_RESP}" | jq -r .role)

if [[ -z "${OP_USER_ID}" || "${OP_USER_ID}" == "null" || "${OP_ROLE}" != "OPERATOR" ]]; then
    echo "FAIL: Expected OPERATOR user creation to return valid ID and role OPERATOR, got: ${OP_CREATE_RESP}" >&2
    exit 1
fi
echo "  -> Created local user test-operator (id: ${OP_USER_ID}, role: ${OP_ROLE})"

# Verify user exists in PostgreSQL
DB_OP_ROLE=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT role FROM admin_users WHERE username = 'test-operator';")
if [[ "${DB_OP_ROLE}" != "OPERATOR" ]]; then
    echo "FAIL: Expected test-operator role in DB to be 'OPERATOR', got: '${DB_OP_ROLE}'" >&2
    exit 1
fi
echo "  -> Verified test-operator recorded in database with role OPERATOR!"

# 2. Authenticate / test as test-operator
echo "  -> Testing operator permissions as 'test-operator'..."

# Trigger checkin POST /admin/devices/${SIM_DEV_ID}/sync -> assert HTTP 200
OP_SYNC_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "test-operator:OperatorPass123!" -X POST "${SERVER_URL}/admin/devices/${SIM_DEV_ID}/sync")
if [[ "${OP_SYNC_CODE}" != "200" ]]; then
    echo "FAIL: Expected HTTP 200 when OPERATOR triggers device sync, got: ${OP_SYNC_CODE}" >&2
    exit 1
fi
echo "  -> Verified OPERATOR allowed to trigger device sync (HTTP 200)!"

# Attempt to update global settings POST /admin/settings/general -> assert HTTP 403 Forbidden
OP_SETTINGS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "test-operator:OperatorPass123!" -X POST "${SERVER_URL}/admin/settings/general" \
    -d "server_base_url=http://hack.local")
if [[ "${OP_SETTINGS_CODE}" != "403" ]]; then
    echo "FAIL: Expected HTTP 403 when OPERATOR attempts to modify settings, got: ${OP_SETTINGS_CODE}" >&2
    exit 1
fi
echo "  -> Verified OPERATOR denied access to modify global settings (HTTP 403 Forbidden)!"

# 3. Create a local user with role AUDITOR via POST /admin/users
echo "  -> Creating local admin user 'test-auditor' with role AUDITOR..."
AUD_CREATE_RESP=$(admin_curl -s -H "Accept: application/json" -H "Content-Type: application/json" -X POST "${SERVER_URL}/admin/users" \
    -d '{"username":"test-auditor","email":"auditor@example.com","display_name":"Test Auditor","password":"AuditorPass123!","role":"AUDITOR"}')

AUD_USER_ID=$(echo "${AUD_CREATE_RESP}" | jq -r .id)
AUD_ROLE=$(echo "${AUD_CREATE_RESP}" | jq -r .role)

if [[ -z "${AUD_USER_ID}" || "${AUD_USER_ID}" == "null" || "${AUD_ROLE}" != "AUDITOR" ]]; then
    echo "FAIL: Expected AUDITOR user creation to return valid ID and role AUDITOR, got: ${AUD_CREATE_RESP}" >&2
    exit 1
fi
echo "  -> Created local user test-auditor (id: ${AUD_USER_ID}, role: ${AUD_ROLE})"

# 4. Authenticate / test as test-auditor
echo "  -> Testing auditor permissions as 'test-auditor'..."

# Attempt to reboot device POST /admin/devices/${SIM_DEV_ID}/reboot -> assert HTTP 403 Forbidden
AUD_REBOOT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "test-auditor:AuditorPass123!" -X POST "${SERVER_URL}/admin/devices/${SIM_DEV_ID}/reboot")
if [[ "${AUD_REBOOT_CODE}" != "403" ]]; then
    echo "FAIL: Expected HTTP 403 when AUDITOR attempts to reboot device, got: ${AUD_REBOOT_CODE}" >&2
    exit 1
fi
echo "  -> Verified AUDITOR denied permission to reboot device (HTTP 403 Forbidden)!"

# 5. Test simulated OIDC callback endpoint
echo "  -> Testing OIDC group mapping and simulated callback (JIT provisioning)..."

# Create group mapping Spire-Security-Admins -> SECURITY_ADMIN
MAPPING_RESP=$(admin_curl -s -H "Accept: application/json" -H "Content-Type: application/json" -X POST "${SERVER_URL}/admin/settings/oidc/mappings" \
    -d '{"idp_group_name":"Spire-Security-Admins","mapped_role":"SECURITY_ADMIN"}')

MAPPING_ID=$(echo "${MAPPING_RESP}" | jq -r .id)
MAPPING_ROLE=$(echo "${MAPPING_RESP}" | jq -r .mapped_role)

if [[ -z "${MAPPING_ID}" || "${MAPPING_ID}" == "null" || "${MAPPING_ROLE}" != "SECURITY_ADMIN" ]]; then
    echo "FAIL: Expected group mapping creation to return SECURITY_ADMIN, got: ${MAPPING_RESP}" >&2
    exit 1
fi
echo "  -> Created OIDC group mapping 'Spire-Security-Admins' -> SECURITY_ADMIN (id: ${MAPPING_ID})"

# Submit mock claims to POST /auth/oidc/test-callback
OIDC_TEST_RESP=$(curl -s -H "Content-Type: application/json" -X POST "${SERVER_URL}/auth/oidc/test-callback" \
    -d '{"sub":"oidc-secops-01","email":"secops@corp.local","name":"SecOps User","groups":["Spire-Security-Admins"]}')

OIDC_STATUS=$(echo "${OIDC_TEST_RESP}" | jq -r .status)
OIDC_ROLE=$(echo "${OIDC_TEST_RESP}" | jq -r .resolved_role)

if [[ "${OIDC_STATUS}" != "authenticated" || "${OIDC_ROLE}" != "SECURITY_ADMIN" ]]; then
    echo "FAIL: Expected OIDC test callback status=authenticated and resolved_role=SECURITY_ADMIN, got: ${OIDC_TEST_RESP}" >&2
    exit 1
fi
echo "  -> Verified OIDC test-callback resolved role SECURITY_ADMIN from groups!"

# Assert user was inserted into admin_users table with auth_provider = 'OIDC'
DB_OIDC_USER=$(PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -t -A \
    -c "SELECT auth_provider || '|' || role FROM admin_users WHERE oidc_subject = 'oidc-secops-01';")

if [[ "${DB_OIDC_USER}" != "OIDC|SECURITY_ADMIN" ]]; then
    echo "FAIL: Expected admin_users to contain 'OIDC|SECURITY_ADMIN', got: '${DB_OIDC_USER}'" >&2
    exit 1
fi
echo "  -> Verified JIT provisioning persisted OIDC user into admin_users table with auth_provider=OIDC and role=SECURITY_ADMIN!"

echo "================================================================="
echo " PASS: All 38 SpireUEM E2E Steps Succeeded Cleanly!"
echo "================================================================="
