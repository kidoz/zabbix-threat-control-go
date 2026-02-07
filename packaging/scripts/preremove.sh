#!/bin/sh
set -e

# Skip systemd cleanup during upgrades — only run on full removal.
# RPM: $1 = 0 means removal, $1 >= 1 means upgrade.
# DEB: $1 = "remove" means removal, $1 = "upgrade" means upgrade.
case "${1:-}" in
  0|remove)
    # Full removal — stop and disable the timer
    if [ -d /run/systemd/system ]; then
      systemctl stop ztc-scan.timer  >/dev/null 2>&1 || true
      systemctl disable ztc-scan.timer >/dev/null 2>&1 || true
    fi
    ;;
  *)
    # Upgrade — leave the timer running
    ;;
esac
