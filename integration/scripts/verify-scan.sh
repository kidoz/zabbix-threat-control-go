#!/usr/bin/env bash
# Verify that 'ztc scan' pushed data to the Zabbix virtual hosts.
# Only runs when VULNERS_API_KEY is available.
# Usage: ./verify-scan.sh
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

echo "=== Verifying scan results ==="

# Authenticate
AUTH=$(zbx_api "user.login" "{\"username\":\"${API_USER}\",\"password\":\"${API_PASS}\"}" 2>/dev/null) \
    || AUTH=$(zbx_api "user.login" "{\"user\":\"${API_USER}\",\"password\":\"${API_PASS}\"}")
AUTH=$(echo "$AUTH" | tr -d '"')

# 1. Check vulners.TotalHosts on statistics host
echo "Checking statistics data..."
STATS_HOST_ID=$(zbx_api "host.get" '{"filter":{"host":["vulners.statistics"]},"output":["hostid"]}' "$AUTH" \
    | jq -r '.[0].hostid // empty')

if [ -n "$STATS_HOST_ID" ]; then
    TOTAL_HOSTS=$(zbx_api "item.get" "{\"hostids\":\"${STATS_HOST_ID}\",\"search\":{\"key_\":\"vulners.TotalHosts\"},\"output\":[\"lastvalue\"]}" "$AUTH" \
        | jq -r '.[0].lastvalue // "0"')

    if [ "$TOTAL_HOSTS" != "0" ] && [ -n "$TOTAL_HOSTS" ]; then
        pass "vulners.TotalHosts = ${TOTAL_HOSTS}"
    else
        fail "vulners.TotalHosts is 0 or not set"
    fi
else
    fail "Statistics host 'vulners.statistics' not found"
fi

# 2. Check for discovered items on virtual hosts
echo "Checking discovered items..."
for HOST_NAME in "vulners.hosts" "vulners.packages" "vulners.bulletins"; do
    HOST_ID=$(zbx_api "host.get" "{\"filter\":{\"host\":[\"${HOST_NAME}\"]},\"output\":[\"hostid\"]}" "$AUTH" \
        | jq -r '.[0].hostid // empty')

    if [ -n "$HOST_ID" ]; then
        # Count items that are NOT LLD rule prototypes (discovered items have flags=4)
        ITEM_COUNT=$(zbx_api "item.get" "{\"hostids\":\"${HOST_ID}\",\"output\":[\"itemid\"],\"filter\":{\"flags\":\"4\"}}" "$AUTH" \
            | jq 'length')

        if [ "$ITEM_COUNT" -gt 0 ]; then
            pass "Discovered items on '${HOST_NAME}' (count: ${ITEM_COUNT})"
        else
            fail "No discovered items on '${HOST_NAME}'"
        fi
    else
        fail "Virtual host '${HOST_NAME}' not found"
    fi
done

# Summary
echo ""
echo "=== Scan verification: ${PASS_COUNT} passed, ${FAIL_COUNT} failed ==="

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
