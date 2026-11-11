#!/usr/bin/env bash
# ==============================================================================
# SpireUEM — Bare-Metal Hardware Qualification & Security Validation Suite
# Target OS: Debian 12 (Bookworm) x86_64 Workstation with TPM 2.0, UEFI Secure Boot,
#            LUKS2 Full-Disk Encryption, and GNOME Desktop (Wayland / X11)
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# CLI Flags & Configuration Defaults
# ------------------------------------------------------------------------------
DRY_RUN=0
SKIP_REBOOT=0
VERBOSE=0
SERVER_URL="${SPIRE_SERVER_URL:-}"
ADMIN_USER="${SPIRE_ADMIN_USER:-admin}"
ADMIN_PASS="${SPIRE_ADMIN_PASS:-spire-admin-secret}"
FLATPAK_APP_ID="${SPIRE_TEST_FLATPAK_ID:-org.videolan.VLC}"
TICKET_ID="HW-PILOT-001"

# Counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0

# ANSI Color Palette
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: sudo ./scripts/test_baremetal.sh [OPTIONS]

SpireUEM Bare-Metal Hardware Qualification & Security Validation Suite.

Options:
  --dry-run              Inspect and print planned validation/mutation actions without modifying kernel, LUKS, or Flatpak state.
  --skip-reboot          Skip cold-boot / reboot-dependent persistence prompts during field validation.
  --verbose              Print detailed command outputs, raw JSON responses, and journal traces.
  --server-url <URL>     Override SpireUEM control plane URL (default: auto-detected from /etc/spire/agent.yaml).
  --admin-user <USER>    Admin username for control-plane API verification (default: admin).
  --admin-pass <PASS>    Admin password for control-plane API verification.
  --flatpak-app <ID>     Curated Flatpak application ID to test in Phase 5 (default: org.videolan.VLC).
  -h, --help             Display this help message and exit.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --skip-reboot)
            SKIP_REBOOT=1
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        --server-url)
            SERVER_URL="$2"
            shift 2
            ;;
        --admin-user)
            ADMIN_USER="$2"
            shift 2
            ;;
        --admin-pass)
            ADMIN_PASS="$2"
            shift 2
            ;;
        --flatpak-app)
            FLATPAK_APP_ID="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}[ERROR] Unknown argument: $1${NC}" >&2
            usage
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------------------------
# Logging & Assertion Helpers
# ------------------------------------------------------------------------------
banner() {
    echo -e "\n${BLUE}${BOLD}======================================================================${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}======================================================================${NC}"
}

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "  ${GREEN}${BOLD}[PASS]${NC} $1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "  ${RED}${BOLD}[FAIL]${NC} $1"
}

warn() {
    WARN_COUNT=$((WARN_COUNT + 1))
    echo -e "  ${YELLOW}${BOLD}[WARN]${NC} $1"
}

skip() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    echo -e "  ${CYAN}${BOLD}[SKIP]${NC} $1"
}

info() {
    echo -e "  ${BLUE}[INFO]${NC} $1"
}

vlog() {
    if [[ "$VERBOSE" -eq 1 ]]; then
        echo -e "         ${CYAN}↳ $*${NC}"
    fi
}

# Detect server URL from /etc/spire/agent.yaml if not explicitly provided
detect_server_url() {
    if [[ -n "$SERVER_URL" ]]; then
        return
    fi
    if [[ -f /etc/spire/agent.yaml ]]; then
        local parsed
        parsed="$(awk -F'"' '/server_url:/ {print $2}' /etc/spire/agent.yaml 2>/dev/null || true)"
        if [[ -z "$parsed" ]]; then
            parsed="$(awk '/server_url:/ {print $2}' /etc/spire/agent.yaml 2>/dev/null | tr -d '"' || true)"
        fi
        if [[ -n "$parsed" ]]; then
            SERVER_URL="$parsed"
            return
        fi
    fi
    SERVER_URL="http://localhost:8080"
}

# Resolve target device UUID on control plane
resolve_device_id() {
    local hw_uuid=""
    if [[ -r /sys/class/dmi/id/product_uuid ]]; then
        hw_uuid="$(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_uuid | tr -d '[:space:]')"
    elif [[ -r /etc/machine-id ]]; then
        hw_uuid="$(tr '[:upper:]' '[:lower:]' < /etc/machine-id | tr -d '[:space:]')"
    fi

    local devices_html
    devices_html="$(curl -fsSL -u "${ADMIN_USER}:${ADMIN_PASS}" "${SERVER_URL}/admin/devices" 2>/dev/null || true)"
    if [[ -z "$devices_html" ]]; then
        echo ""
        return
    fi

    local dev_id=""
    if [[ -n "$hw_uuid" ]]; then
        dev_id="$(echo "$devices_html" | grep -B 5 -A 15 -i "$hw_uuid" | grep -oE '/admin/devices/[0-9a-fA-F-]{36}' | head -n1 | sed 's|/admin/devices/||' || true)"
    fi
    if [[ -z "$dev_id" ]]; then
        local host_short
        host_short="$(hostname -s 2>/dev/null || hostname)"
        dev_id="$(echo "$devices_html" | grep -B 5 -A 15 -i "$host_short" | grep -oE '/admin/devices/[0-9a-fA-F-]{36}' | head -n1 | sed 's|/admin/devices/||' || true)"
    fi
    echo "$dev_id"
}

# ==============================================================================
# PRE-FLIGHT: Root & User Session Environment Checks
# ==============================================================================
banner "PRE-FLIGHT: Root Privileges, Block Devices, TPM 2.0 & UEFI Secure Boot"

detect_server_url
info "Target Control Plane URL : ${SERVER_URL}"
info "Operating Mode           : DRY_RUN=${DRY_RUN}, SKIP_REBOOT=${SKIP_REBOOT}, VERBOSE=${VERBOSE}"

if [[ "$EUID" -ne 0 ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
        warn "Running as non-root UID=${EUID} in --dry-run mode (hardware inspection may be limited)"
    else
        fail "This qualification suite must be executed as root (use sudo ./scripts/test_baremetal.sh)"
        exit 1
    fi
else
    pass "Executing with root privileges (UID=0)"
fi

# 1. Detect target block devices using lsblk and identify root LUKS2 device mapper
LUKS_BACKING_DEV=""
LUKS_MAPPER_NAME=""
if command -v lsblk >/dev/null 2>&1; then
    LSBLK_OUT="$(lsblk -f -n -l 2>/dev/null || true)"
    vlog "lsblk output: $(echo "$LSBLK_OUT" | tr '\n' ' ')"
    LUKS_DEV_NAME="$(lsblk -f -n -l -o NAME,FSTYPE 2>/dev/null | awk '$2 == "crypto_LUKS" {print $1; exit}' || true)"
    if [[ -n "$LUKS_DEV_NAME" ]]; then
        LUKS_BACKING_DEV="/dev/${LUKS_DEV_NAME}"
        LUKS_MAPPER_NAME="$(lsblk -n -l -o NAME,TYPE "/dev/${LUKS_DEV_NAME}" 2>/dev/null | awk '$2 == "crypt" {print $1; exit}' || true)"
        pass "Detected LUKS backing block device ${LUKS_BACKING_DEV} (mapper: ${LUKS_MAPPER_NAME:-unopened})"
    else
        warn "No crypto_LUKS partition detected via lsblk on this host"
    fi
else
    fail "lsblk utility not found in PATH"
fi

# 2. Verify /dev/tpmrm0 character device exists with tss or root permissions
if [[ -c /dev/tpmrm0 ]]; then
    TPM_OWNER="$(stat -c '%U:%G (%a)' /dev/tpmrm0 2>/dev/null || echo 'unknown')"
    TPM_USER="$(stat -c '%U' /dev/tpmrm0 2>/dev/null || echo '')"
    TPM_GROUP="$(stat -c '%G' /dev/tpmrm0 2>/dev/null || echo '')"
    if [[ "$TPM_USER" == "tss" || "$TPM_USER" == "root" || "$TPM_GROUP" == "tss" || "$TPM_GROUP" == "root" ]]; then
        pass "TPM 2.0 resource manager /dev/tpmrm0 character device present (${TPM_OWNER})"
    else
        fail "/dev/tpmrm0 has unexpected ownership: ${TPM_OWNER} (expected root or tss)"
    fi
else
    if [[ "$DRY_RUN" -eq 1 ]]; then
        skip "DRY-RUN: /dev/tpmrm0 character device not present on this host"
    else
        fail "TPM 2.0 resource manager /dev/tpmrm0 character device is missing"
    fi
fi

# 3. Validate UEFI Secure Boot is active via /sys/firmware/efi/efivars/SecureBoot-* or mokutil --sb-state
SB_ACTIVE=0
shopt -s nullglob
SB_VARS=(/sys/firmware/efi/efivars/SecureBoot-*)
shopt -u nullglob

if [[ ${#SB_VARS[@]} -gt 0 ]]; then
    SB_HEX="$(od -An -t u1 "${SB_VARS[0]}" 2>/dev/null | awk '{print $NF}' || echo "0")"
    vlog "EFI variable ${SB_VARS[0]} last byte: ${SB_HEX}"
    if [[ "$SB_HEX" == "1" ]]; then
        SB_ACTIVE=1
        pass "UEFI Secure Boot verified ACTIVE via efivars (${SB_VARS[0]}=1)"
    fi
fi

if [[ "$SB_ACTIVE" -eq 0 ]] && command -v mokutil >/dev/null 2>&1; then
    MOK_OUT="$(mokutil --sb-state 2>/dev/null || true)"
    vlog "mokutil --sb-state: ${MOK_OUT}"
    if echo "$MOK_OUT" | grep -qi "SecureBoot enabled"; then
        SB_ACTIVE=1
        pass "UEFI Secure Boot verified ACTIVE via mokutil --sb-state"
    fi
fi

if [[ "$SB_ACTIVE" -eq 0 ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
        skip "DRY-RUN: UEFI Secure Boot is not enabled on this test environment"
    else
        fail "UEFI Secure Boot is DISABLED or legacy BIOS boot is active"
    fi
fi

# ==============================================================================
# PHASE 1: Hardware Integrity Check (TPM 2.0 & LUKS2 Header Inspection)
# ==============================================================================
banner "PHASE 1: Hardware Integrity Check (TPM 2.0 Capabilities, PCRs 0/2/4/7 & LUKS2)"

if [[ "$DRY_RUN" -eq 1 ]] && [[ ! -c /dev/tpmrm0 ]]; then
    skip "DRY-RUN: Would execute 'tpm2_getcap properties-fixed' and 'tpm2_pcrread sha256:0,2,4,7'"
else
    if command -v tpm2_getcap >/dev/null 2>&1; then
        TPM_PROPS="$(tpm2_getcap properties-fixed 2>/dev/null || true)"
        if echo "$TPM_PROPS" | grep -qE "TPM2_PT_FAMILY_INDICATOR|TPM2_PT_MANUFACTURER"; then
            TPM_VENDOR="$(echo "$TPM_PROPS" | awk '/TPM2_PT_VENDOR_STRING_1/ {getline; print $2}' | tr -d '"' || echo "TPM2")"
            pass "tpm2_getcap properties-fixed succeeded (Family: 2.0, Vendor: ${TPM_VENDOR:-Hardware})"
            vlog "$TPM_PROPS"
        else
            fail "tpm2_getcap properties-fixed failed to return TPM 2.0 fixed properties"
        fi
    else
        fail "tpm2_getcap binary not found (install tpm2-tools)"
    fi

    if command -v tpm2_pcrread >/dev/null 2>&1; then
        PCR_OUT="$(tpm2_pcrread sha256:0,2,4,7 2>/dev/null || true)"
        vlog "$PCR_OUT"
        PCR_VALID=1
        for pcr_idx in 0 2 4 7; do
            pcr_val="$(echo "$PCR_OUT" | awk -v idx="${pcr_idx}:" '$1 == idx {print $2}' || true)"
            if [[ -z "$pcr_val" ]] || echo "$pcr_val" | grep -qE '^0x0+$'; then
                PCR_VALID=0
                fail "SHA-256 PCR bank ${pcr_idx} is empty or all-zeros (${pcr_val:-missing})"
            fi
        done
        if [[ "$PCR_VALID" -eq 1 ]]; then
            pass "SHA-256 PCR banks 0, 2, 4, and 7 contain valid non-zero hardware measurements"
        fi
    else
        fail "tpm2_pcrread binary not found (install tpm2-tools)"
    fi
fi

if [[ -n "$LUKS_BACKING_DEV" ]] && command -v cryptsetup >/dev/null 2>&1; then
    if [[ "$DRY_RUN" -eq 1 && "$EUID" -ne 0 ]]; then
        skip "DRY-RUN: Would run 'cryptsetup luksDump ${LUKS_BACKING_DEV}'"
    else
        LUKS_DUMP="$(cryptsetup luksDump "$LUKS_BACKING_DEV" 2>/dev/null || true)"
        if echo "$LUKS_DUMP" | grep -qE '^Version:[[:space:]]+2'; then
            pass "cryptsetup luksDump confirmed LUKS Version 2 header on ${LUKS_BACKING_DEV}"
        else
            fail "Volume ${LUKS_BACKING_DEV} is not formatted with LUKS Version 2"
        fi
        if echo "$LUKS_DUMP" | grep -qE '0:[[:space:]]+luks2'; then
            pass "Primary user passphrase Keyslot 0 is active on ${LUKS_BACKING_DEV}"
        else
            warn "Keyslot 0 not detected in luksDump output for ${LUKS_BACKING_DEV}"
        fi
    fi
else
    if [[ "$DRY_RUN" -eq 1 ]]; then
        skip "DRY-RUN: Would inspect LUKS2 header via 'cryptsetup luksDump <device>'"
    else
        fail "No LUKS2 block device available for cryptsetup luksDump inspection"
    fi
fi

# ==============================================================================
# PHASE 2: Bootstrap & Dynamic Attestation
# ==============================================================================
banner "PHASE 2: Deb822 Bootstrap & Dynamic TPM 2.0 Attestation"

# 1. Verify spire.sources in /etc/apt/sources.list.d/ and key validity in /etc/apt/keyrings/spire.gpg
if [[ -f /etc/apt/sources.list.d/spire.sources ]]; then
    if grep -q "Signed-By: /etc/apt/keyrings/spire.gpg" /etc/apt/sources.list.d/spire.sources; then
        pass "Deb822 repository configuration verified at /etc/apt/sources.list.d/spire.sources"
    else
        fail "/etc/apt/sources.list.d/spire.sources is missing Signed-By directive"
    fi
else
    if [[ "$DRY_RUN" -eq 1 ]]; then
        skip "DRY-RUN: Would verify /etc/apt/sources.list.d/spire.sources"
    else
        fail "/etc/apt/sources.list.d/spire.sources not found"
    fi
fi

if [[ -s /etc/apt/keyrings/spire.gpg ]]; then
    if command -v gpg >/dev/null 2>&1 && gpg --show-keys /etc/apt/keyrings/spire.gpg >/dev/null 2>&1; then
        pass "GPG keyring verified valid at /etc/apt/keyrings/spire.gpg"
    else
        pass "GPG keyring file present and non-empty at /etc/apt/keyrings/spire.gpg"
    fi
else
    if [[ "$DRY_RUN" -eq 1 ]]; then
        skip "DRY-RUN: Would verify /etc/apt/keyrings/spire.gpg"
    else
        fail "GPG keyring /etc/apt/keyrings/spire.gpg is missing or empty"
    fi
fi

# 2. Inspect journalctl -u spired for TPM 2.0 EK, AK, PCR quotes, and ATTESTED status
if command -v journalctl >/dev/null 2>&1; then
    SPIRED_LOGS="$(journalctl -u spired --no-pager -n 500 2>/dev/null || true)"
else
    SPIRED_LOGS=""
fi

if [[ -z "$SPIRED_LOGS" && -f /var/log/spired.log ]]; then
    SPIRED_LOGS="$(tail -n 500 /var/log/spired.log 2>/dev/null || true)"
fi

if [[ -z "$SPIRED_LOGS" ]] || echo "$SPIRED_LOGS" | grep -q "^-- No entries --$"; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
        skip "DRY-RUN: Would inspect 'journalctl -u spired' for EK certificate, AK provisioning, signed PCR quotes, and ATTESTED response"
    else
        fail "No spired service logs found via journalctl -u spired"
    fi
else
    if echo "$SPIRED_LOGS" | grep -qiE "EK|endorsement|challenge nonce|TPM 2.0 attestation"; then
        pass "Journal verified TPM 2.0 EK certificate / challenge processing"
    else
        fail "Journal missing TPM 2.0 EK certificate / challenge log entries"
    fi

    if echo "$SPIRED_LOGS" | grep -qiE "AK|attestation|quote"; then
        pass "Journal verified Attestation Key (AK) & signed PCR quote generation"
    else
        fail "Journal missing AK / signed PCR quote log entries"
    fi

    if echo "$SPIRED_LOGS" | grep -qiE "status=ATTESTED|HTTP 200.*attestation"; then
        pass "Journal confirmed HTTP 200 / status=ATTESTED response from spire-server"
    else
        fail "Journal did not record status=ATTESTED from spire-server (check Secure Boot / PCR 7)"
    fi
fi

# ==============================================================================
# PHASE 3: LUKS2 Key Escrow & Cold-Boot Verification
# ==============================================================================
banner "PHASE 3: LUKS2 Keyslot 1 Escrow & Break-Glass Reveal Verification"

VOLUME_UUID=""
if [[ -n "$LUKS_BACKING_DEV" ]] && command -v cryptsetup >/dev/null 2>&1; then
    VOLUME_UUID="$(cryptsetup luksUUID "$LUKS_BACKING_DEV" 2>/dev/null || true)"
    LUKS_DUMP_P3="$(cryptsetup luksDump "$LUKS_BACKING_DEV" 2>/dev/null || true)"
    if echo "$LUKS_DUMP_P3" | awk '/^Keyslots:/,/^Tokens:/' | grep -qE '^[[:space:]]*1:[[:space:]]+luks2'; then
        if echo "$LUKS_DUMP_P3" | awk '/^[[:space:]]*1:[[:space:]]+luks2/,/^[[:space:]]*[2-9]:|Tokens:/' | grep -qiE 'pbkdf2|argon2id|argon2i'; then
            pass "LUKS2 Keyslot 1 allocated with PBKDF2/Argon2 KDF on ${LUKS_BACKING_DEV} (UUID=${VOLUME_UUID})"
        else
            pass "LUKS2 Keyslot 1 allocated on ${LUKS_BACKING_DEV} (UUID=${VOLUME_UUID})"
        fi
    else
        if [[ "$DRY_RUN" -eq 1 ]]; then
            skip "DRY-RUN: Would verify Keyslot 1 allocation on ${LUKS_BACKING_DEV}"
        else
            fail "LUKS2 Keyslot 1 is not allocated on ${LUKS_BACKING_DEV}"
        fi
    fi
else
    if [[ "$DRY_RUN" -eq 1 ]]; then
        skip "DRY-RUN: Would verify LUKS2 Keyslot 1 PBKDF2/Argon2id allocation"
    else
        fail "Cannot verify Keyslot 1 without a detected LUKS2 volume"
    fi
fi

DEVICE_ID="$(resolve_device_id)"
vlog "Resolved Device ID on control plane: ${DEVICE_ID:-none}"

if [[ "$DRY_RUN" -eq 1 ]]; then
    skip "DRY-RUN: Would query POST ${SERVER_URL}/api/v1/auth/recovery-key with justification ticket '${TICKET_ID}'"
elif [[ -z "$DEVICE_ID" ]]; then
    fail "Could not resolve enrolled Device ID from ${SERVER_URL}/admin/devices"
else
    REVEAL_PAYLOAD="$(printf '{"device_id":"%s","volume_uuid":"%s","reason":"%s","ticket":"%s"}' \
        "$DEVICE_ID" "$VOLUME_UUID" "$TICKET_ID" "$TICKET_ID")"

    REVEAL_RESP="$(curl -fsSL -u "${ADMIN_USER}:${ADMIN_PASS}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -X POST "${SERVER_URL}/api/v1/auth/recovery-key" \
        -d "$REVEAL_PAYLOAD" 2>/dev/null || true)"

    if [[ -z "$REVEAL_RESP" ]]; then
        REVEAL_RESP="$(curl -fsSL -u "${ADMIN_USER}:${ADMIN_PASS}" \
            -H "Content-Type: application/json" \
            -H "Accept: application/json" \
            -X POST "${SERVER_URL}/admin/devices/${DEVICE_ID}/luks/reveal" \
            -d "$REVEAL_PAYLOAD" 2>/dev/null || true)"
    fi

    vlog "Reveal response: ${REVEAL_RESP}"

    if echo "$REVEAL_RESP" | grep -q '"recovery_key"'; then
        pass "Break-glass recovery key decrypted and returned for ticket ${TICKET_ID}"
    else
        fail "Failed to retrieve LUKS2 recovery key for device ${DEVICE_ID}"
    fi

    AUDIT_RESP="$(curl -fsSL -u "${ADMIN_USER}:${ADMIN_PASS}" \
        "${SERVER_URL}/admin/audit/events" 2>/dev/null || true)"
    if echo "$AUDIT_RESP" | grep -q "LUKS_KEY_REVEAL" && echo "$AUDIT_RESP" | grep -q "$TICKET_ID"; then
        pass "Immutable LUKS_KEY_REVEAL audit event verified in control plane SIEM log (ticket=${TICKET_ID})"
    else
        fail "LUKS_KEY_REVEAL audit event with ticket ${TICKET_ID} not found in /admin/audit/events"
    fi
fi

if [[ "$SKIP_REBOOT" -eq 1 ]]; then
    skip "Skipping cold-boot initramfs passphrase unlock verification (--skip-reboot active)"
fi

# ==============================================================================
# PHASE 4: Live OpenSCAP CIS Evaluation & Remediation Drift
# ==============================================================================
banner "PHASE 4: Live OpenSCAP CIS Evaluation & Kernel Sysctl Drift Remediation"

if [[ "$DRY_RUN" -eq 1 ]]; then
    skip "DRY-RUN: Would dispatch POST ${SERVER_URL}/admin/devices/<id>/scans and wait for COMPLETED"
    skip "DRY-RUN: Would write 0 to /proc/sys/net/ipv4/conf/all/rp_filter, invoke POST /admin/benchmarks/remediate-rule, and run spire-ctl sync"
elif [[ -z "$DEVICE_ID" ]]; then
    fail "Skipping Phase 4 because Device ID could not be resolved on ${SERVER_URL}"
else
    # 1. Dispatch benchmark scan via POST /admin/devices/{id}/scans
    SCAN_TRIGGER="$(curl -fsSL -u "${ADMIN_USER}:${ADMIN_PASS}" \
        -H "Accept: application/json" \
        -X POST "${SERVER_URL}/admin/devices/${DEVICE_ID}/scans" \
        -d "profile=xccdf_org.ssgproject.content_profile_standard" 2>/dev/null || true)"
    vlog "Scan trigger response: ${SCAN_TRIGGER}"

    if echo "$SCAN_TRIGGER" | grep -q '"scan_id"'; then
        pass "Dispatched live OpenSCAP benchmark scan to endpoint (device=${DEVICE_ID})"
    else
        fail "Failed to dispatch benchmark scan via POST /admin/devices/${DEVICE_ID}/scans"
    fi

    # 2. Wait for scan status to transition to COMPLETED and score > 0%
    SCAN_COMPLETED=0
    for _ in $(seq 1 36); do
        CARD_HTML="$(curl -fsSL -u "${ADMIN_USER}:${ADMIN_PASS}" \
            "${SERVER_URL}/admin/dashboard/benchmark-card" 2>/dev/null || true)"
        if ! echo "$CARD_HTML" | grep -qE "Scanning|PENDING|RUNNING"; then
            if echo "$CARD_HTML" | grep -qE "[1-9][0-9]*(\.[0-9]+)?%"; then
                SCAN_COMPLETED=1
                break
            fi
        fi
        sleep 5
    done

    if [[ "$SCAN_COMPLETED" -eq 1 ]]; then
        pass "OpenSCAP CIS evaluation transitioned to COMPLETED with score > 0%"
    else
        fail "OpenSCAP CIS scan did not complete with score > 0% within timeout"
    fi

    # 3. Trigger compliance drift by writing 0 to net.ipv4.conf.all.rp_filter
    sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
    DRIFT_VAL="$(cat /proc/sys/net/ipv4/conf/all/rp_filter)"
    if [[ "$DRIFT_VAL" == "0" ]]; then
        pass "Induced kernel sysctl drift: net.ipv4.conf.all.rp_filter=${DRIFT_VAL}"
    else
        fail "Failed to set net.ipv4.conf.all.rp_filter to 0 (got ${DRIFT_VAL})"
    fi

    # 4. Invoke POST /admin/benchmarks/remediate-rule for sysctl_net_ipv4_conf_all_rp_filter
    REM_RESP="$(curl -fsSL -u "${ADMIN_USER}:${ADMIN_PASS}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -X POST "${SERVER_URL}/admin/benchmarks/remediate-rule" \
        -d '{"rule_id":"xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_rp_filter"}' 2>/dev/null || true)"
    vlog "Remediate rule response: ${REM_RESP}"

    if echo "$REM_RESP" | grep -qiE "remediated|policy_id|20-spire-cis"; then
        pass "Created declarative remediation policy via POST /admin/benchmarks/remediate-rule"
    else
        fail "POST /admin/benchmarks/remediate-rule failed: ${REM_RESP}"
    fi

    # 5. Run spire-ctl sync and assert /proc/sys/net/ipv4/conf/all/rp_filter equals 1
    if command -v spire-ctl >/dev/null 2>&1; then
        spire-ctl sync >/dev/null 2>&1 || true
    fi
    sleep 2
    REMEDIATED_VAL="$(cat /proc/sys/net/ipv4/conf/all/rp_filter)"
    if [[ "$REMEDIATED_VAL" == "1" ]]; then
        pass "spire-ctl sync reconciled drift: /proc/sys/net/ipv4/conf/all/rp_filter=${REMEDIATED_VAL}"
    else
        fail "Kernel parameter net.ipv4.conf.all.rp_filter remained ${REMEDIATED_VAL} after spire-ctl sync (expected 1)"
    fi
fi

# ==============================================================================
# PHASE 5: Unprivileged Desktop IPC & Spire Hub
# ==============================================================================
banner "PHASE 5: Unprivileged Desktop Session (seat0), IPC Socket & Spire Hub"

# 1. Query active session via loginctl to confirm seat0 and Type=wayland or Type=x11
SEAT0_UID=""
SEAT0_USER=""
SEAT0_TYPE=""
if command -v loginctl >/dev/null 2>&1; then
    while read -r sess_id sess_uid sess_user sess_seat _rest; do
        if [[ "$sess_seat" == "seat0" ]]; then
            SEAT0_UID="$sess_uid"
            SEAT0_USER="$sess_user"
            SEAT0_TYPE="$(loginctl show-session "$sess_id" -p Type --value 2>/dev/null || echo "")"
            break
        fi
    done < <(loginctl list-sessions --no-legend 2>/dev/null || true)
fi

if [[ -n "$SEAT0_UID" ]] && [[ "$SEAT0_TYPE" == "wayland" || "$SEAT0_TYPE" == "x11" ]]; then
    pass "Active graphical seat0 session detected: user=${SEAT0_USER} (UID=${SEAT0_UID}, Type=${SEAT0_TYPE})"
else
    if [[ "$DRY_RUN" -eq 1 ]]; then
        skip "DRY-RUN: No interactive seat0 graphical session active (would verify Type=wayland or Type=x11)"
    else
        warn "No active seat0 graphical session detected via loginctl (Type=${SEAT0_TYPE:-none})"
    fi
fi

# 2. Connect to /run/spire/agent.sock as non-root seat0 user and verify status & catalog
SOCKET_PATH="/run/spire/agent.sock"
if [[ ! -S "$SOCKET_PATH" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
        skip "DRY-RUN: Would query ${SOCKET_PATH} (/v1/status, /v1/catalog, /v1/install)"
    else
        fail "Local IPC Unix socket ${SOCKET_PATH} does not exist"
    fi
else
    RUN_PREFIX=()
    if [[ -n "$SEAT0_USER" && "$EUID" -eq 0 ]]; then
        RUN_PREFIX=(sudo -u "$SEAT0_USER")
    fi

    STATUS_JSON="$("${RUN_PREFIX[@]}" curl -fsSL --unix-socket "$SOCKET_PATH" http://localhost/v1/status 2>/dev/null || true)"
    vlog "GET /v1/status: ${STATUS_JSON}"
    if echo "$STATUS_JSON" | grep -q '"compliance_state"'; then
        pass "Unprivileged SO_PEERCRED GET /v1/status succeeded via ${SOCKET_PATH}"
    else
        fail "Unprivileged GET /v1/status failed on ${SOCKET_PATH}"
    fi

    CATALOG_JSON="$("${RUN_PREFIX[@]}" curl -fsSL --unix-socket "$SOCKET_PATH" http://localhost/v1/catalog 2>/dev/null || true)"
    vlog "GET /v1/catalog: ${CATALOG_JSON}"
    if echo "$CATALOG_JSON" | grep -q '"catalog"'; then
        pass "Unprivileged SO_PEERCRED GET /v1/catalog succeeded via ${SOCKET_PATH}"
    else
        fail "Unprivileged GET /v1/catalog failed on ${SOCKET_PATH}"
    fi

    # 3. Trigger install of a curated Flatpak and verify presence in flatpak list
    if [[ "$DRY_RUN" -eq 1 ]]; then
        skip "DRY-RUN: Would install curated Flatpak '${FLATPAK_APP_ID}' via POST ${SOCKET_PATH} /v1/install"
    else
        INSTALL_RESP="$("${RUN_PREFIX[@]}" curl -fsSL --unix-socket "$SOCKET_PATH" \
            -H "Content-Type: application/json" \
            -X POST http://localhost/v1/install \
            -d "{\"policy_id\":\"${FLATPAK_APP_ID}\"}" 2>/dev/null || true)"
        vlog "POST /v1/install response: ${INSTALL_RESP}"

        if command -v flatpak >/dev/null 2>&1 && flatpak list --app 2>/dev/null | grep -qi "$FLATPAK_APP_ID"; then
            pass "Verified curated Flatpak '${FLATPAK_APP_ID}' installed and present in 'flatpak list'"
        else
            fail "Curated Flatpak '${FLATPAK_APP_ID}' not found in 'flatpak list' after self-service install"
        fi
    fi
fi

# ==============================================================================
# SUMMARY REPORT
# ==============================================================================
banner "BARE-METAL QUALIFICATION SUMMARY"
echo -e "  ${GREEN}Passed : ${PASS_COUNT}${NC}"
echo -e "  ${RED}Failed : ${FAIL_COUNT}${NC}"
echo -e "  ${YELLOW}Warned : ${WARN_COUNT}${NC}"
echo -e "  ${CYAN}Skipped: ${SKIP_COUNT}${NC}"
echo -e "${BLUE}${BOLD}======================================================================${NC}"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo -e "${RED}${BOLD}[RESULT] QUALIFICATION FAILED (${FAIL_COUNT} failed assertions)${NC}"
    exit 1
fi

echo -e "${GREEN}${BOLD}[RESULT] QUALIFICATION PASSED${NC}"
exit 0
