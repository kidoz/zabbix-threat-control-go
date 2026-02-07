#!/bin/sh
# Direct fix helper for the Go version.
#
# Usage: fix.sh <real-hostname>
#
# IMPORTANT: The argument must be a real monitored host name (as shown in
# Zabbix host list), NOT a virtual host like vulners.packages.
#
# Do NOT wire this into Zabbix actions using {HOST.HOST} — that macro
# resolves to the virtual host, not the target machine.
HOST_NAME="${1:-}"
if [ -z "$HOST_NAME" ]; then
    echo "Usage: fix.sh <real-hostname>" >&2
    echo "" >&2
    echo "WARNING: Do NOT use {HOST.HOST} macro — it resolves to the" >&2
    echo "virtual host, not the target machine." >&2
    exit 1
fi
exec /usr/bin/ztc fix --host-name "$HOST_NAME" --force
