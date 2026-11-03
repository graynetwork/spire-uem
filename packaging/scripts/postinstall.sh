#!/bin/sh
set -e

mkdir -p /etc/spire
chmod 0700 /etc/spire

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable spired.service || true
    systemctl start spired.service || true
fi
