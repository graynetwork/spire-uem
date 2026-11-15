#!/usr/bin/env bash
# SpireUEM Single-Command Endpoint Onboarding Bootstrap Script
set -euo pipefail

SERVER_URL="__SERVER_URL__"
DEB_PACKAGE="spire-agent_0.1.0_amd64.deb"
DEB_URL="${SERVER_URL}/dist/${DEB_PACKAGE}"
TMP_DEB="/tmp/${DEB_PACKAGE}"

USE_APT_REPO="${SPIRE_USE_APT_REPO:-0}"
APT_REPO_URL="${SPIRE_APT_REPO_URL:-}"
ALLOW_INSECURE_HTTP="${SPIRE_AGENT_ALLOW_INSECURE_HTTP:-0}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --use-apt-repo)
            USE_APT_REPO="1"
            if [[ $# -gt 1 && ! "$2" =~ ^-- ]]; then
                APT_REPO_URL="$2"
                shift 2
            else
                shift 1
            fi
            ;;
        --server-url)
            SERVER_URL="$2"
            shift 2
            ;;
        --allow-insecure-http)
            ALLOW_INSECURE_HTTP="1"
            shift 1
            ;;
        *)
            shift 1
            ;;
    esac
done

# The agent sends its device token, receives network secrets and pins the server's
# wipe-signing key over this URL, so plain HTTP is refused unless explicitly allowed.
case "${SERVER_URL}" in
    https://*) ;;
    http://localhost|http://localhost:*|http://127.0.0.1|http://127.0.0.1:*) ;;
    http://*)
        if [[ "${ALLOW_INSECURE_HTTP}" != "1" && "${ALLOW_INSECURE_HTTP}" != "true" ]]; then
            echo "ERROR: ${SERVER_URL} uses plain HTTP. Serve SpireUEM over HTTPS, or re-run with" >&2
            echo "       --allow-insecure-http on a lab network only." >&2
            exit 1
        fi
        echo "WARNING: enrolling over plain HTTP (--allow-insecure-http). Lab use only." >&2
        ;;
    *)
        echo "ERROR: unsupported server URL ${SERVER_URL}" >&2
        exit 1
        ;;
esac

if [[ "${USE_APT_REPO}" == "1" || "${USE_APT_REPO}" == "true" ]]; then
    if [[ -z "${APT_REPO_URL}" ]]; then
        APT_REPO_URL="${SERVER_URL}/apt"
    fi
fi

echo "================================================================="
echo " SpireUEM Endpoint Onboarding Bootstrap"
echo " Server URL: ${SERVER_URL}"
if [[ "${USE_APT_REPO}" == "1" || "${USE_APT_REPO}" == "true" ]]; then
    echo " Package Source: APT Repository (${APT_REPO_URL})"
else
    echo " Package Source: Direct DEB Download (${DEB_URL})"
fi
echo "================================================================="

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: This bootstrap script must be executed as root (e.g., curl -sSL ${SERVER_URL}/install.sh | sudo bash)." >&2
    exit 1
fi

ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
if [[ "${ARCH}" != "amd64" && "${ARCH}" != "x86_64" ]]; then
    echo "Error: Unsupported architecture '${ARCH}'. Only amd64 is supported." >&2
    exit 1
fi

if [[ "${USE_APT_REPO}" == "1" || "${USE_APT_REPO}" == "true" ]]; then
    echo "[1/4] Configuring GPG keyring and Deb822 repository (${APT_REPO_URL})..."
    KEYRING_DIR="/etc/apt/keyrings"
    KEYRING_FILE="${KEYRING_DIR}/spire-archive-keyring.gpg"
    mkdir -p "${KEYRING_DIR}"
    chmod 0755 "${KEYRING_DIR}"

    KEYRING_URL="${APT_REPO_URL%/}/spire-archive-keyring.gpg"
    echo "  -> Downloading keyring: ${KEYRING_URL} -> ${KEYRING_FILE}"
    curl -fsSL "${KEYRING_URL}" -o "${KEYRING_FILE}"
    chmod 0644 "${KEYRING_FILE}"

    SOURCES_DIR="/etc/apt/sources.list.d"
    SOURCES_FILE="${SOURCES_DIR}/spire.sources"
    mkdir -p "${SOURCES_DIR}"
    cat <<EOF > "${SOURCES_FILE}"
Types: deb
URIs: ${APT_REPO_URL}
Suites: bookworm
Components: main
Architectures: amd64
Signed-By: ${KEYRING_FILE}
EOF
    chmod 0644 "${SOURCES_FILE}"

    echo "[2/4] Updating APT package index and installing spire-agent..."
    apt-get update
    apt-get install -y spire-agent
    apt-get install -y unattended-upgrades apt-config-auto-update

    echo "  -> Configuring automated background upgrades (unattended-upgrades)..."
    cat << 'EOF' > /etc/apt/apt.conf.d/52spire-unattended-upgrades
// Allow zero-touch automated updates from the internal Spire repository
Unattended-Upgrade::Origins-Pattern {
    "origin=SpireUEM,codename=${distro_codename},label=SpireUEM";
    "origin=SpireUEM,suite=stable,label=SpireUEM";
};

// Ensure daemon restart occurs without requiring a host reboot
Unattended-Upgrade::Automatic-Reboot "false";

// Non-interactive upgrade defaults (prevent debconf/needrestart prompts)
Dpkg::Options {
    "--force-confdef";
    "--force-confold";
};
EOF
    chmod 0644 /etc/apt/apt.conf.d/52spire-unattended-upgrades
    chown root:root /etc/apt/apt.conf.d/52spire-unattended-upgrades

    cat << 'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    chmod 0644 /etc/apt/apt.conf.d/20auto-upgrades
    chown root:root /etc/apt/apt.conf.d/20auto-upgrades
else
    echo "[1/4] Downloading SpireUEM agent package from ${DEB_URL}..."
    curl -fSL "${DEB_URL}" -o "${TMP_DEB}"

    echo "[2/4] Installing ${DEB_PACKAGE} via dpkg..."
    dpkg -i "${TMP_DEB}"
    rm -f "${TMP_DEB}"
fi

echo "[3/4] Writing /etc/spire/config.yaml (mode 0600)..."
mkdir -p /etc/spire
chmod 0700 /etc/spire
cat <<EOF > /etc/spire/config.yaml
# SpireUEM Agent Configuration (auto-generated by bootstrap)
agent:
  server_url: "${SERVER_URL}"
  token_path: "/etc/spire/token"
  checkin_interval: "5m"
  poll_interval: "10s"
EOF
if [[ "${ALLOW_INSECURE_HTTP}" == "1" || "${ALLOW_INSECURE_HTTP}" == "true" ]]; then
    echo '  allow_insecure_http: true' >> /etc/spire/config.yaml
fi
chmod 0600 /etc/spire/config.yaml

echo "[4/4] Reloading systemd and starting spired.service..."
if [[ -d /run/systemd/system ]]; then
    systemctl daemon-reload
    systemctl enable spired.service
    systemctl restart spired.service
    echo "spired.service is enabled and running."
    if [[ "${USE_APT_REPO}" == "1" || "${USE_APT_REPO}" == "true" ]]; then
        systemctl enable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
    fi
else
    echo "Note: systemd not detected in this environment; run /usr/local/bin/spired manually."
fi

echo "================================================================="
echo " SpireUEM Onboarding Complete! Approve this host in the Admin UI:"
echo " ${SERVER_URL}/admin/devices"
echo "================================================================="
