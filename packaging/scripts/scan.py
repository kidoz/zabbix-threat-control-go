#!/bin/sh
# Compatibility shim for system.run[scan.py,nowait] service items.
# The original Python zabbix-threat-control used scan.py as the entry point.
# This wrapper forwards to the Go binary so existing Zabbix items keep working.
#
# Legacy flag mapping:
#   -n, --nopush  → --nopush  (supported, same behavior)
#   -l, --limit N → --limit N (supported, same behavior)
#   -d, --dump    → --dry-run (APPROXIMATE: prevents push but does NOT dump
#                    host data to disk as the Python version did)
#
# Use 'ztc scan --help' to see all available options.

# Rewrite legacy short flags to Go equivalents
args=""
while [ $# -gt 0 ]; do
    case "$1" in
        -n|--nopush) args="$args --nopush" ;;
        -d|--dump)
            echo "WARNING: --dump is approximated as --dry-run (no disk dump)." >&2
            args="$args --dry-run"
            ;;
        -l|--limit)  shift; args="$args --limit $1" ;;
        *)           args="$args $1" ;;
    esac
    shift
done

exec /usr/bin/ztc scan $args
