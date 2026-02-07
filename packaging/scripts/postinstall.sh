#!/bin/sh
set -e

# Detect upgrade from the Python zabbix-threat-control package.
# Old Python scripts live in /opt/monitoring/zabbix-threat-control/scan.py;
# the Go binary installs to /usr/bin/ztc with a symlink back.
LEGACY_DIR="/opt/monitoring/zabbix-threat-control"
LEGACY_CONF="$LEGACY_DIR/ztc.conf"
NEW_CONF="/etc/ztc.yaml"
UPGRADING_FROM_PYTHON=false

if [ -f "$LEGACY_DIR/scan.py" ] || [ -f "$LEGACY_DIR/config.py" ]; then
  UPGRADING_FROM_PYTHON=true
fi

# Create legacy directory (may already exist from the Python package)
mkdir -p "$LEGACY_DIR"
chown zabbix:zabbix "$LEGACY_DIR" 2>/dev/null || true

# Config handling:
# - If the old INI ztc.conf exists, keep it — the Go binary reads INI natively.
# - If no config exists at all, create a YAML config from the example.
if [ ! -f "$LEGACY_CONF" ] && [ ! -f "$NEW_CONF" ]; then
  if [ -f /etc/ztc.yaml.example ]; then
    cp /etc/ztc.yaml.example "$NEW_CONF"
    chmod 0640 "$NEW_CONF"
    chown root:zabbix "$NEW_CONF" 2>/dev/null || true
  fi
fi

# Enable (but don't start) the daily scan timer
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable ztc-scan.timer >/dev/null 2>&1 || true
fi

# Print migration hints when upgrading from the Python version
if [ "$UPGRADING_FROM_PYTHON" = true ]; then
  cat >&2 <<'EOF'

  ================================================================
  Upgraded from Python zabbix-threat-control to Go version (ztc).

  * Your existing config is preserved and will be read as-is.
    To convert it to YAML:  ztc migrate-config --output /etc/ztc.yaml

  * Run "ztc prepare --force" to recreate Zabbix templates and virtual
    hosts with the new key schema. This is REQUIRED — the Go version
    uses a different package key format (3-part: name,version,arch)
    and different template items (system.sw.os/system.sw.packages
    instead of system.run with report.py).

  * The old Zabbix "service item" (system.run[scan.py,nowait]) on the
    Statistics host is no longer needed — scheduling is now handled by
    the systemd timer ztc-scan.timer. You may disable that item in
    the Zabbix UI.

  * The zabbix-threat-control-host package on monitored hosts is no
    longer required — ztc uses built-in Zabbix agent items
    (system.sw.os, system.sw.packages). You can uninstall it.

  * The legacy fix.py action format (fix.py {HOST.HOST} {TRIGGER.ID}
    {EVENT.ID}) is NOT supported. TrustedZabbixUsers checks are not
    implemented. Remove old fix actions and use "ztc fix" directly.

  * "ztc prepare" with no flags now defaults to --all (creates all
    objects). The Python version required explicit flags (-uvtd).

  * "ztc fix" generates generic package manager commands (e.g.
    apt-get install --only-upgrade / yum update) instead of the
    Vulners-provided version-pinned commands used by fix.py.
    It does NOT require a Vulners API key (only queries Zabbix).

  * VulnersProxyHost / VulnersProxyPort are not supported. If you
    route Vulners API traffic through a proxy, set the standard
    HTTP_PROXY / HTTPS_PROXY environment variables instead.
  ================================================================

EOF
fi
