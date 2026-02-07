#!/bin/sh
# Compatibility shim for legacy Python prepare.py invocation.
#
# Python usage:  prepare.py -uvtd
# Go equivalent: ztc prepare --all
#
# Short flag mapping:
#   -u (utils)     -> -u (accepted, no-op in Go)
#   -v (vhosts)    -> -V (virtual-hosts; can't reuse -v, it's global --verbose)
#   -t (template)  -> -t (templates)
#   -d (dashboard) -> -d (dashboard)
#
# Long flag mapping:
#   --vhosts    -> --virtual-hosts
#   --template  -> --templates
#
# No-args behavior:
#   Legacy: shows help and exits (no mutation).
#   Go:     defaults to --all (creates all objects).
#   This shim matches legacy behavior — no args prints a warning and exits.

# If no arguments given, match legacy behavior: show help, don't mutate.
if [ $# -eq 0 ]; then
    echo "WARNING: prepare.py called with no arguments." >&2
    echo "Legacy behavior: show help and exit (no changes made)." >&2
    echo "" >&2
    echo "To create all Zabbix objects, run:" >&2
    echo "  ztc prepare --all" >&2
    echo "  ztc prepare --all --force   # after upgrade from Python version" >&2
    echo "" >&2
    echo "Available flags:" >&2
    echo "  -u  check utility paths (no-op in Go)" >&2
    echo "  -v  create virtual hosts" >&2
    echo "  -t  create/update templates" >&2
    echo "  -d  create dashboard" >&2
    exit 0
fi

# Rewrite args: short flags and long flags.
ARGS=""
for arg in "$@"; do
    case "$arg" in
        --vhosts)    ARGS="$ARGS --virtual-hosts" ;;
        --template)  ARGS="$ARGS --templates" ;;
        --*)         ARGS="$ARGS $arg" ;;          # pass other long flags through
        -*)          ARGS="$ARGS $(echo "$arg" | sed 's/v/V/g')" ;;  # -uvtd -> -uVtd
        *)           ARGS="$ARGS $arg" ;;          # positional args
    esac
done

# shellcheck disable=SC2086
exec /usr/bin/ztc prepare $ARGS
