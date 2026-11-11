#!/usr/bin/env bash
set -euo pipefail

DEB_FILE="${1:-${DEB_FILE:-}}"
CODENAME="${2:-${CODENAME:-bookworm}}"
REPO_DIR="${REPO_DIR:-/var/www/apt/spire}"
GPG_HOMEDIR="${GPG_HOMEDIR:-/etc/spire/gpg}"

if [[ -z "${DEB_FILE}" ]]; then
    echo "Usage: $0 <path-to-deb> [codename] or set DEB_FILE environment variable" >&2
    exit 1
fi

if [[ ! -f "${DEB_FILE}" ]]; then
    echo "Error: Debian package file '${DEB_FILE}' not found." >&2
    exit 1
fi

if [[ ! -f "${REPO_DIR}/conf/distributions" ]]; then
    echo "Repository configuration '${REPO_DIR}/conf/distributions' not found. Auto-initializing repository..."
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_DIR="${REPO_DIR}" GPG_HOMEDIR="${GPG_HOMEDIR}" "${SCRIPT_DIR}/init_repo.sh"
fi

echo "Ingesting ${DEB_FILE} into repository ${REPO_DIR} (${CODENAME})..."

# Extract package name for graceful collision handling
PKG_NAME=$(dpkg-deb -f "${DEB_FILE}" Package 2>/dev/null || echo "spire-agent")

# Ingest package via reprepro; if pool file hash mismatch occurs on rebuilds, clear unreferenced files and retry
if ! GNUPGHOME="${GPG_HOMEDIR}" reprepro -b "${REPO_DIR}" includedeb "${CODENAME}" "${DEB_FILE}"; then
    echo "Notice: Reprepro detected existing pool file or version collision. Removing old ${PKG_NAME} entry and retrying..."
    GNUPGHOME="${GPG_HOMEDIR}" reprepro -b "${REPO_DIR}" remove "${CODENAME}" "${PKG_NAME}" >/dev/null 2>&1 || true
    GNUPGHOME="${GPG_HOMEDIR}" reprepro -b "${REPO_DIR}" deleteunreferenced >/dev/null 2>&1 || true
    GNUPGHOME="${GPG_HOMEDIR}" reprepro -b "${REPO_DIR}" includedeb "${CODENAME}" "${DEB_FILE}"
fi

# Verify metadata files and signatures
INRELEASE_FILE="${REPO_DIR}/dists/${CODENAME}/InRelease"
RELEASE_GPG_FILE="${REPO_DIR}/dists/${CODENAME}/Release.gpg"
PACKAGES_GZ_FILE="${REPO_DIR}/dists/${CODENAME}/main/binary-amd64/Packages.gz"

if [[ ! -f "${INRELEASE_FILE}" ]]; then
    echo "Error: Verification failed - InRelease file not found at ${INRELEASE_FILE}" >&2
    exit 1
fi

if [[ ! -f "${RELEASE_GPG_FILE}" ]]; then
    echo "Error: Verification failed - Release.gpg file not found at ${RELEASE_GPG_FILE}" >&2
    exit 1
fi

if [[ ! -f "${PACKAGES_GZ_FILE}" ]]; then
    echo "Error: Verification failed - Packages.gz file not found at ${PACKAGES_GZ_FILE}" >&2
    exit 1
fi

# Verify signature validity
if [[ -d "${GPG_HOMEDIR}" ]]; then
    GNUPGHOME="${GPG_HOMEDIR}" gpg --homedir "${GPG_HOMEDIR}" --verify "${RELEASE_GPG_FILE}" "${REPO_DIR}/dists/${CODENAME}/Release" >/dev/null 2>&1 || {
        echo "Error: Signature verification failed for ${RELEASE_GPG_FILE} against Release file." >&2
        exit 1
    }
fi

echo "Repository successfully updated and verified: InRelease, Release.gpg, and Packages.gz are present and signed."
