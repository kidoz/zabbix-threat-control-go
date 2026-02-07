#!/usr/bin/env bash
# Verify that 'ztc prepare' created all expected Zabbix objects.
# Usage: ./verify-prepare.sh
set -euo pipefail

API_URL="${ZABBIX_API_URL:-http://localhost:8080/api_jsonrpc.php}"
API_USER="${ZABBIX_API_USER:-Admin}"
API_PASS="${ZABBIX_API_PASS:-zabbix}"

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "  PASS: $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "  FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# Helper: call Zabbix JSON-RPC API
zbx_api() {
    local method=$1
    local params=$2
    local auth=${3:-}

    local payload
    if [ -n "$auth" ]; then
        payload="{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"auth\":\"${auth}\",\"id\":1}"
    else
        payload="{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}"
    fi

    curl -sf -X POST "$API_URL" \
        -H 'Content-Type: application/json' \
        -d "$payload" | jq -r '.result'
}

echo "=== Verifying prepare results ==="

# Authenticate
AUTH=$(zbx_api "user.login" "{\"username\":\"${API_USER}\",\"password\":\"${API_PASS}\"}" 2>/dev/null) \
    || AUTH=$(zbx_api "user.login" "{\"user\":\"${API_USER}\",\"password\":\"${API_PASS}\"}")
AUTH=$(echo "$AUTH" | tr -d '"')

# 1. Check OS-Report template exists
echo "Checking OS-Report template..."
OSREPORT_ID=$(zbx_api "template.get" '{"filter":{"host":["tmpl.vulners.os-report"]},"output":["templateid"]}' "$AUTH" \
    | jq -r '.[0].templateid // empty')

if [ -n "$OSREPORT_ID" ]; then
    pass "Template 'tmpl.vulners.os-report' exists (ID: ${OSREPORT_ID})"

    # Check for expected items on the OS-Report template
    ITEMS=$(zbx_api "item.get" "{\"templateids\":\"${OSREPORT_ID}\",\"output\":[\"key_\"]}" "$AUTH")
    if echo "$ITEMS" | jq -e '.[] | select(.key_ == "system.sw.os")' > /dev/null 2>&1; then
        pass "OS-Report template has 'system.sw.os' item"
    else
        fail "OS-Report template missing 'system.sw.os' item"
    fi
    if echo "$ITEMS" | jq -e '.[] | select(.key_ == "system.sw.packages")' > /dev/null 2>&1; then
        pass "OS-Report template has 'system.sw.packages' item"
    else
        fail "OS-Report template missing 'system.sw.packages' item"
    fi
else
    fail "Template 'tmpl.vulners.os-report' not found"
fi

# 2. Check Vulners host group
echo "Checking Vulners host group..."
GROUP_ID=$(zbx_api "hostgroup.get" '{"filter":{"name":["Vulners"]},"output":["groupid"]}' "$AUTH" \
    | jq -r '.[0].groupid // empty')

if [ -n "$GROUP_ID" ]; then
    pass "Host group 'Vulners' exists (ID: ${GROUP_ID})"
else
    fail "Host group 'Vulners' not found"
fi

# 3. Check Vulners virtual hosts
echo "Checking virtual hosts..."
for HOST_NAME in "vulners.hosts" "vulners.packages" "vulners.bulletins" "vulners.statistics"; do
    HOST_ID=$(zbx_api "host.get" "{\"filter\":{\"host\":[\"${HOST_NAME}\"]},\"output\":[\"hostid\"]}" "$AUTH" \
        | jq -r '.[0].hostid // empty')

    if [ -n "$HOST_ID" ]; then
        pass "Virtual host '${HOST_NAME}' exists (ID: ${HOST_ID})"
    else
        fail "Virtual host '${HOST_NAME}' not found"
    fi
done

# 4. Check LLD rules on the Vulners template (via virtual hosts)
echo "Checking LLD rules..."
for HOST_NAME in "vulners.hosts" "vulners.packages" "vulners.bulletins"; do
    HOST_ID=$(zbx_api "host.get" "{\"filter\":{\"host\":[\"${HOST_NAME}\"]},\"output\":[\"hostid\"]}" "$AUTH" \
        | jq -r '.[0].hostid // empty')

    if [ -n "$HOST_ID" ]; then
        LLD_COUNT=$(zbx_api "discoveryrule.get" "{\"hostids\":\"${HOST_ID}\",\"output\":[\"itemid\"]}" "$AUTH" \
            | jq 'length')
        if [ "$LLD_COUNT" -gt 0 ]; then
            pass "LLD rules found on '${HOST_NAME}' (count: ${LLD_COUNT})"
        else
            fail "No LLD rules found on '${HOST_NAME}'"
        fi
    fi
done

# 5. Check dashboard
echo "Checking dashboard..."
DASHBOARD_ID=$(zbx_api "dashboard.get" '{"filter":{"name":["Vulners"]},"output":["dashboardid"]}' "$AUTH" \
    | jq -r '.[0].dashboardid // empty')

if [ -n "$DASHBOARD_ID" ]; then
    pass "Dashboard 'Vulners' exists (ID: ${DASHBOARD_ID})"
else
    fail "Dashboard 'Vulners' not found"
fi

# Summary
echo ""
echo "=== Prepare verification: ${PASS_COUNT} passed, ${FAIL_COUNT} failed ==="

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
