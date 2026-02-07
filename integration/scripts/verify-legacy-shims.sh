#!/usr/bin/env bash
# Verify legacy Python wrapper scripts (scan.py, prepare.py, fix.py, fix.sh)
# correctly rewrite flags and reject unsupported invocations.
#
# This test does NOT require a running Zabbix instance. It creates a mock
# ztc binary that records its arguments, then runs each shim against it.
#
# Usage: bash integration/scripts/verify-legacy-shims.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SHIM_DIR="${PROJECT_ROOT}/packaging/scripts"

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# Create temp workspace
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# Mock ztc binary that records received arguments to a file
MOCK_ZTC="${TMPDIR}/ztc"
MOCK_ARGS="${TMPDIR}/args"
cat > "$MOCK_ZTC" <<'MOCK'
#!/bin/sh
# Record all args, one per line
for arg in "$@"; do echo "$arg"; done > "$MOCK_ARGS_FILE"
exit 0
MOCK
chmod +x "$MOCK_ZTC"

# Helper: run a shim with /usr/bin/ztc replaced by our mock
run_shim() {
    local shim="$1"; shift
    # Replace /usr/bin/ztc with our mock path in a temp copy
    local tmp_shim="${TMPDIR}/$(basename "$shim")"
    sed "s|/usr/bin/ztc|${MOCK_ZTC}|g" "$shim" > "$tmp_shim"
    chmod +x "$tmp_shim"
    # Clear previous args
    rm -f "$MOCK_ARGS"
    # Export args file path for the mock
    MOCK_ARGS_FILE="$MOCK_ARGS" "$tmp_shim" "$@" 2>"${TMPDIR}/stderr"
    return $?
}

# Helper: check that mock received expected args
check_args() {
    local description="$1"; shift
    local expected="$1"
    if [ ! -f "$MOCK_ARGS" ]; then
        fail "$description (no args recorded)"
        return
    fi
    local got
    got="$(cat "$MOCK_ARGS" | tr '\n' ' ' | sed 's/ $//')"
    if [ "$got" = "$expected" ]; then
        pass "$description"
    else
        fail "$description (got: '$got', want: '$expected')"
    fi
}

echo "=== Legacy Shim Tests ==="
echo ""

# ─── scan.py ───────────────────────────────────────────────────────
echo "--- scan.py ---"

run_shim "${SHIM_DIR}/scan.py"
check_args "scan.py: no args → 'scan'" "scan"

run_shim "${SHIM_DIR}/scan.py" -n
check_args "scan.py: -n → 'scan --nopush'" "scan --nopush"

run_shim "${SHIM_DIR}/scan.py" --nopush
check_args "scan.py: --nopush → 'scan --nopush'" "scan --nopush"

run_shim "${SHIM_DIR}/scan.py" -d
check_args "scan.py: -d → 'scan --dry-run'" "scan --dry-run"
if grep -q "WARNING" "${TMPDIR}/stderr"; then
    pass "scan.py: -d emits WARNING on stderr"
else
    fail "scan.py: -d emits WARNING on stderr"
fi

run_shim "${SHIM_DIR}/scan.py" -l 5
check_args "scan.py: -l 5 → 'scan --limit 5'" "scan --limit 5"

run_shim "${SHIM_DIR}/scan.py" -n -l 10
check_args "scan.py: -n -l 10 → 'scan --nopush --limit 10'" "scan --nopush --limit 10"

# ─── prepare.py ────────────────────────────────────────────────────
echo ""
echo "--- prepare.py ---"

# No-args: legacy behavior = show help and exit (no mutation)
if "${SHIM_DIR}/prepare.py" 2>"${TMPDIR}/stderr"; then
    pass "prepare.py: no args exits with zero status"
else
    fail "prepare.py: no args exits with zero status"
fi
if grep -q "WARNING" "${TMPDIR}/stderr"; then
    pass "prepare.py: no args prints WARNING"
else
    fail "prepare.py: no args prints WARNING"
fi

# Short flag rewriting
run_shim "${SHIM_DIR}/prepare.py" -uvtd
check_args "prepare.py: -uvtd → 'prepare -uVtd'" "prepare -uVtd"

run_shim "${SHIM_DIR}/prepare.py" -v
check_args "prepare.py: -v → 'prepare -V'" "prepare -V"

run_shim "${SHIM_DIR}/prepare.py" --force
check_args "prepare.py: --force → 'prepare --force'" "prepare --force"

run_shim "${SHIM_DIR}/prepare.py" -vt --force
check_args "prepare.py: -vt --force → 'prepare -Vt --force'" "prepare -Vt --force"

# Long flag rewriting (legacy Python options)
run_shim "${SHIM_DIR}/prepare.py" --vhosts
check_args "prepare.py: --vhosts → 'prepare --virtual-hosts'" "prepare --virtual-hosts"

run_shim "${SHIM_DIR}/prepare.py" --template
check_args "prepare.py: --template → 'prepare --templates'" "prepare --templates"

run_shim "${SHIM_DIR}/prepare.py" --vhosts --template --force
check_args "prepare.py: --vhosts --template --force → 'prepare --virtual-hosts --templates --force'" "prepare --virtual-hosts --templates --force"

# ─── fix.py ────────────────────────────────────────────────────────
echo ""
echo "--- fix.py ---"

if ! "${SHIM_DIR}/fix.py" vulners.hosts 12345 67890 2>"${TMPDIR}/stderr"; then
    pass "fix.py: exits with non-zero status"
else
    fail "fix.py: exits with non-zero status"
fi

if grep -q "ERROR.*Legacy fix.py" "${TMPDIR}/stderr"; then
    pass "fix.py: prints error message"
else
    fail "fix.py: prints error message"
fi

if grep -q "virtual host" "${TMPDIR}/stderr"; then
    pass "fix.py: warns about virtual hosts"
else
    fail "fix.py: warns about virtual hosts"
fi

if grep -q "vulners.hosts 12345 67890" "${TMPDIR}/stderr"; then
    pass "fix.py: shows received arguments"
else
    fail "fix.py: shows received arguments"
fi

# ─── fix.sh ────────────────────────────────────────────────────────
echo ""
echo "--- fix.sh ---"

if ! "${SHIM_DIR}/fix.sh" 2>"${TMPDIR}/stderr"; then
    pass "fix.sh: no args exits with non-zero status"
else
    fail "fix.sh: no args exits with non-zero status"
fi

if grep -q "Usage:" "${TMPDIR}/stderr"; then
    pass "fix.sh: no args shows usage"
else
    fail "fix.sh: no args shows usage"
fi

run_shim "${SHIM_DIR}/fix.sh" webserver01
check_args "fix.sh: webserver01 → 'fix --host-name webserver01 --force'" "fix --host-name webserver01 --force"

# ─── Summary ───────────────────────────────────────────────────────
echo ""
echo "=== Shim Tests: ${PASS} passed, ${FAIL} failed ==="
[ "$FAIL" -eq 0 ]
