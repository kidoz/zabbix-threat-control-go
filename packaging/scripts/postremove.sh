#!/bin/sh
set -e

# Reload systemd on removal/upgrade so it picks up unit file changes.
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
