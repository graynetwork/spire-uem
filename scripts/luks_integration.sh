#!/usr/bin/env bash
# Runs the real-cryptsetup LUKS rotation + crypto-erase integration test against a throwaway
# 64 MiB loop device. Run as root on a LAB machine only, from a directory containing the test
# binary built with:
#
#   go test -c -tags luksintegration -o luks.test ./internal/engine/
#
# Usage: sudo ./luks_integration.sh ./luks.test
# It creates everything under /tmp/spire-luks-test/ and removes it on exit. It touches no
# existing disk and never powers the machine off.
set -euo pipefail

TEST_BIN="$(realpath "${1:?usage: $0 <path-to-luks.test>}")"
DIR=/tmp/spire-luks-test
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
command -v cryptsetup >/dev/null || { echo "cryptsetup not installed" >&2; exit 1; }

rm -rf "$DIR"
mkdir -m 0700 "$DIR"
LOOP=""
cleanup() {
    [[ -n "$LOOP" ]] && losetup -d "$LOOP" 2>/dev/null || true
    rm -rf "$DIR"
}
trap cleanup EXIT

truncate -s 64M "$DIR/disk.img"
LOOP="$(losetup --find --show "$DIR/disk.img")"
head -c 64 /dev/urandom | base64 -w0 > "$DIR/master.key"
OLD_KEY="$(head -c 36 /dev/urandom | base64 -w0)"

# Slot 0: master (provisioning) keyfile. Slot 1: the recovery key an admin "revealed".
# Small PBKDF settings keep the test fast; production volumes use cryptsetup defaults.
cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --key-slot 0 --key-file "$DIR/master.key" "$LOOP"
printf '%s' "$OLD_KEY" | cryptsetup luksAddKey --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --key-slot 1 --key-file "$DIR/master.key" "$LOOP" -

SPIRE_LUKS_TEST_DEVICE="$LOOP" SPIRE_LUKS_TEST_MASTER_KEY="$DIR/master.key" \
SPIRE_LUKS_TEST_OLD_KEY="$OLD_KEY" \
    "$TEST_BIN" -test.v -test.run TestLUKSIntegration
