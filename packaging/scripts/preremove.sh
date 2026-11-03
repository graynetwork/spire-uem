#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl stop spired.service || true
    systemctl disable spired.service || true
fi
