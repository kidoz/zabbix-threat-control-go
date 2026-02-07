#!/usr/bin/env bash
# Main orchestrator for ZTC integration tests.
#
# Environment variables:
#   ZABBIX_VERSION          Zabbix image tag (default: 7.0-latest)
#   ZABBIX_AGENT2_VERSION   Agent 2 image tag (default: 7.0-ubuntu-latest)
#   VULNERS_API_KEY         Vulners API key (optional; enables scan testing)
#   ZTC_BINARY              Path to ztc binary (default: ./ztc)
#   SKIP_BUILD              Skip building ztc (default: false)
#   SKIP_TEARDOWN           Skip docker compose down (default: false)
#
# Test strategy:
#   Step 2 (verify-legacy-shims.sh) tests flag rewriting in wrapper scripts
#   (scan.py, prepare.py, fix.py, fix.sh) — no Docker needed.
#   Steps 3+ test ztc directly against a real Zabbix stack. The wrappers
#   exec into ztc, so Docker tests validate the actual API interaction
#   rather than re-testing flag rewriting.
#
# Usage: bash integration/scripts/run-tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_DIR="${PROJECT_ROOT}/integration"
CONFIG_FILE="${COMPOSE_DIR}/configs/ztc-test.yaml"

ZTC_BINARY="${ZTC_BINARY:-${PROJECT_ROOT}/ztc}"
SKIP_BUILD="${SKIP_BUILD:-false}"
SKIP_TEARDOWN="${SKIP_TEARDOWN:-false}"

export ZABBIX_VERSION="${ZABBIX_VERSION:-7.0-latest}"
export ZABBIX_AGENT2_VERSION="${ZABBIX_AGENT2_VERSION:-7.0-ubuntu-latest}"

PASS_TOTAL=0
FAIL_TOTAL=0
STEPS_RUN=0

step_pass() { echo "STEP PASS: $1"; PASS_TOTAL=$((PASS_TOTAL + 1)); STEPS_RUN=$((STEPS_RUN + 1)); }
step_fail() { echo "STEP FAIL: $1"; FAIL_TOTAL=$((FAIL_TOTAL + 1)); STEPS_RUN=$((STEPS_RUN + 1)); }

cleanup() {
    if [ "$SKIP_TEARDOWN" = "true" ]; then
        echo ""
        echo "SKIP_TEARDOWN=true — leaving containers running."
        echo "Teardown manually: cd ${COMPOSE_DIR} && docker compose down -v"
        return
    fi
    echo ""
    echo "Tearing down Docker Compose stack..."
    cd "$COMPOSE_DIR" && docker compose down -v 2>/dev/null || true
}

echo "============================================"
echo "  ZTC Integration Tests"
echo "  Zabbix: ${ZABBIX_VERSION}"
echo "  Agent2: ${ZABBIX_AGENT2_VERSION}"
echo "  Vulners API key: ${VULNERS_API_KEY:+set}${VULNERS_API_KEY:-not set}"
echo "============================================"
echo ""

# ─── Step 1: Build ztc ──────────────────────────────────────────────
if [ "$SKIP_BUILD" != "true" ]; then
    echo ">>> Building ztc..."
    cd "$PROJECT_ROOT"
    CGO_ENABLED=0 go build -o ztc . || { step_fail "Build ztc"; exit 1; }
    step_pass "Build ztc"
else
    echo ">>> Skipping build (SKIP_BUILD=true)"
    if [ ! -x "$ZTC_BINARY" ]; then
        echo "ERROR: ZTC_BINARY not found at ${ZTC_BINARY}"
        exit 1
    fi
fi

# ─── Step 2: Verify legacy shims ───────────────────────────────────
echo ""
echo ">>> Testing legacy compatibility shims..."
bash "${SCRIPT_DIR}/verify-legacy-shims.sh" && step_pass "Legacy shim tests" || step_fail "Legacy shim tests"

# ─── Step 3: Start Docker Compose ───────────────────────────────────
echo ""
echo ">>> Starting Docker Compose stack..."
cd "$COMPOSE_DIR"
docker compose up -d || { step_fail "Docker Compose up"; cleanup; exit 1; }
step_pass "Docker Compose up"

# Register cleanup trap after compose is up
trap cleanup EXIT

# ─── Step 3: Wait for Zabbix API ────────────────────────────────────
echo ""
echo ">>> Waiting for Zabbix API..."
bash "${SCRIPT_DIR}/wait-for-zabbix.sh" 180 || { step_fail "Wait for Zabbix API"; exit 1; }
step_pass "Wait for Zabbix API"

# ─── Step 4: Run ztc prepare ────────────────────────────────────────
echo ""
echo ">>> Running ztc prepare..."
cd "$PROJECT_ROOT"
"$ZTC_BINARY" prepare --config "$CONFIG_FILE" --force || { step_fail "ztc prepare"; exit 1; }
step_pass "ztc prepare"

# ─── Step 5: Verify prepare ─────────────────────────────────────────
echo ""
echo ">>> Verifying prepare results..."
bash "${SCRIPT_DIR}/verify-prepare.sh" || { step_fail "Verify prepare"; exit 1; }
step_pass "Verify prepare"

# ─── Step 6: Seed test host ─────────────────────────────────────────
echo ""
echo ">>> Seeding test host..."
bash "${SCRIPT_DIR}/seed-host.sh" || { step_fail "Seed test host"; exit 1; }
step_pass "Seed test host"

# ─── Step 7: Wait for agent data ────────────────────────────────────
echo ""
echo ">>> Waiting 30s for agent data collection..."
sleep 30
step_pass "Agent data collection wait"

# ─── Step 8: Scan (conditional) ─────────────────────────────────────
if [ -n "${VULNERS_API_KEY:-}" ]; then
    echo ""
    echo ">>> Running ztc scan..."
    cd "$PROJECT_ROOT"
    ZTC_VULNERS_API_KEY="$VULNERS_API_KEY" "$ZTC_BINARY" scan --config "$CONFIG_FILE" || { step_fail "ztc scan"; exit 1; }
    step_pass "ztc scan"

    echo ""
    echo ">>> Verifying scan results..."
    bash "${SCRIPT_DIR}/verify-scan.sh" || { step_fail "Verify scan"; exit 1; }
    step_pass "Verify scan"
else
    echo ""
    echo ">>> Skipping scan (VULNERS_API_KEY not set)"
fi

# ─── Summary ─────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Summary: ${PASS_TOTAL} passed, ${FAIL_TOTAL} failed (${STEPS_RUN} steps)"
echo "============================================"

if [ "$FAIL_TOTAL" -gt 0 ]; then
    exit 1
fi
