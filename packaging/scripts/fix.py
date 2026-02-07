#!/bin/sh
# Legacy compatibility stub for Python fix.py action invocation.
#
# The Python version was called by Zabbix actions as:
#   fix.py {HOST.HOST} {TRIGGER.ID} {EVENT.ID}
#
# IMPORTANT: {HOST.HOST} here is the virtual host (e.g. vulners.packages),
# NOT the actual target machine. The Python version derived target hosts
# from trigger/event context and performed trust/ack checks
# (TrustedZabbixUsers). Neither feature is implemented in the Go version.
#
# This stub refuses to execute to prevent accidental remediation against
# the wrong host (virtual hosts have 127.0.0.1 loopback interfaces).
#
# MIGRATION:
#   1. Remove the old Zabbix action that calls fix.py.
#   2. Use the Go CLI to fix specific hosts manually:
#        ztc fix --host-name <real-hostname> --dry-run   # preview
#        ztc fix --host-name <real-hostname> --force      # execute
#   3. Or create a new Zabbix action that calls:
#        /usr/bin/ztc fix --host-name <real-hostname> --force
#      (the hostname must be a real monitored host, NOT {HOST.HOST})

echo "ERROR: Legacy fix.py action format is not supported by the Go version." >&2
echo "" >&2
echo "The Python fix.py derived target hosts from trigger/event context" >&2
echo "and checked TrustedZabbixUsers. The Go version does not implement" >&2
echo "these features." >&2
echo "" >&2
echo "IMPORTANT: {HOST.HOST} resolves to a virtual host (e.g. vulners.packages)," >&2
echo "NOT the actual target machine. Do NOT pass it to ztc fix." >&2
echo "" >&2
echo "To fix a specific host, run:" >&2
echo "  ztc fix --host-name <real-hostname> --dry-run   # preview" >&2
echo "  ztc fix --host-name <real-hostname> --force      # execute" >&2
echo "" >&2
echo "Arguments received: $*" >&2
exit 1
