#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BINARY_SRC="${REPO_ROOT}/bin/spired"
BINARY_DST="/usr/local/bin/spired"
CONFIG_DIR="/etc/spire"
CONFIG_Example="${REPO_ROOT}/packaging/config.example.yaml"
SERVICE_SRC="${REPO_ROOT}/packaging/spired.service"
SERVICE_DST="/etc/systemd/system/spired.service"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: packaging/install.sh must be run as root (or via sudo)." >&2
    exit 1
fi

if [[ ! -f "${BINARY_SRC}" ]]; then
    echo "Error: ${BINARY_SRC} not found. Build it first with: go build -o bin/spired ./cmd/spired" >&2
    exit 1
fi

echo "[1/4] Installing ${BINARY_SRC} -> ${BINARY_DST} (0755)..."
install -m 0755 "${BINARY_SRC}" "${BINARY_DST}"

echo "[2/4] Creating ${CONFIG_DIR} (0700)..."
install -d -m 0700 "${CONFIG_DIR}"
if [[ -f "${CONFIG_Example}" && ! -f "${CONFIG_DIR}/config.yaml" ]]; then
    install -m 0600 "${CONFIG_Example}" "${CONFIG_DIR}/config.yaml"
fi

echo "[3/4] Installing systemd unit ${SERVICE_DST}..."
install -m 0644 "${SERVICE_SRC}" "${SERVICE_DST}"

echo "[4/4] Reloading systemd daemon and enabling spired.service..."
systemctl daemon-reload
systemctl enable spired.service

echo "SpireUEM agent installation complete."
