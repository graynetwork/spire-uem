#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-/var/www/apt/spire}"
GPG_HOMEDIR="${GPG_HOMEDIR:-/etc/spire/gpg}"
KEY_ID="${KEY_ID:-}"

# If KEY_ID is not provided, attempt to auto-detect the primary secret key from GPG_HOMEDIR
if [[ -z "${KEY_ID}" ]]; then
    if [[ -d "${GPG_HOMEDIR}" ]]; then
        KEY_ID=$(gpg --homedir "${GPG_HOMEDIR}" --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^sec/{print $5; exit}' || true)
    fi
fi

# If still not found, generate a batch non-interactive signing key in GPG_HOMEDIR
if [[ -z "${KEY_ID}" ]]; then
    echo "No GPG key specified or found in ${GPG_HOMEDIR}. Generating a new SpireUEM signing key..."
    mkdir -p "${GPG_HOMEDIR}"
    chmod 0700 "${GPG_HOMEDIR}"
    cat << 'EOF_GPG' > "${GPG_HOMEDIR}/keygen.batch"
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: SpireUEM Release Signing Key
Name-Email: release@spire-uem.org
Expire-Date: 0
%no-protection
%commit
EOF_GPG
    gpg --batch --homedir "${GPG_HOMEDIR}" --generate-key "${GPG_HOMEDIR}/keygen.batch"
    rm -f "${GPG_HOMEDIR}/keygen.batch"
    KEY_ID=$(gpg --homedir "${GPG_HOMEDIR}" --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^sec/{print $5; exit}')
    echo "Generated SpireUEM signing key ID: ${KEY_ID}"
fi

echo "Initializing APT repository in ${REPO_DIR} with GPG Key ${KEY_ID}..."

# Create directory tree with mode 0755
mkdir -p "${REPO_DIR}"/{conf,dists,pool,db}
chmod 0755 "${REPO_DIR}" "${REPO_DIR}"/{conf,dists,pool,db}

# Generate conf/distributions
cat <<EOF > "${REPO_DIR}/conf/distributions"
Origin: SpireUEM
Label: SpireUEM
Suite: stable
Codename: bookworm
Version: 12.0
Architectures: amd64
Components: main
Description: SpireUEM Endpoint Agent Repository
SignWith: ${KEY_ID}
EOF
chmod 0644 "${REPO_DIR}/conf/distributions"

# Export de-armored public key to spire-archive-keyring.gpg (mode 0644)
gpg --homedir "${GPG_HOMEDIR}" --export "${KEY_ID}" > "${REPO_DIR}/spire-archive-keyring.gpg"
chmod 0644 "${REPO_DIR}/spire-archive-keyring.gpg"

# Run reprepro export to initialize dists metadata structure
GNUPGHOME="${GPG_HOMEDIR}" reprepro -b "${REPO_DIR}" export bookworm

echo "APT repository initialized successfully at ${REPO_DIR}."
