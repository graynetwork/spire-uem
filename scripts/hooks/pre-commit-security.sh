#!/usr/bin/env bash
# ==============================================================================
# SpireUEM Pre-Commit Security Hook
# ==============================================================================
# Triggers the security auditor on staged modifications before git commit.
# Fails closed if any CRITICAL or HIGH severity issues are detected.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "==> Running SpireUEM pre-commit security review on staged files..."
AUDIT_OUTPUT=$("${REPO_ROOT}/scripts/security_audit.sh" --staged)

echo "${AUDIT_OUTPUT}"

if grep -q "REJECT (Changes Required)" <<<"${AUDIT_OUTPUT}"; then
    echo "==================================================================" >&2
    echo " COMMIT REJECTED: Security violations detected in staged changes! " >&2
    echo " Resolve all Critical and High severity findings before commit.  " >&2
    echo "==================================================================" >&2
    exit 1
fi

echo "==> Pre-commit security review passed cleanly."
exit 0
