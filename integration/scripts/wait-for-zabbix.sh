#!/usr/bin/env bash
# Wait for the Zabbix API to become ready and accept logins.
# Usage: ./wait-for-zabbix.sh [timeout_seconds]
set -euo pipefail

TIMEOUT=${1:-180}
API_URL="${ZABBIX_API_URL:-http://localhost:8080/api_jsonrpc.php}"
API_USER="${ZABBIX_API_USER:-Admin}"
API_PASS="${ZABBIX_API_PASS:-zabbix}"

elapsed=0
echo "Waiting for Zabbix API at ${API_URL} (timeout: ${TIMEOUT}s)..."

# Phase 1: wait for apiinfo.version to respond
while true; do
    if [ "$elapsed" -ge "$TIMEOUT" ]; then
        echo "TIMEOUT: Zabbix API did not respond within ${TIMEOUT}s"
        exit 1
    fi

    version=$(curl -sf -X POST "$API_URL" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1}' \
        2>/dev/null | jq -r '.result // empty' 2>/dev/null) || true

    if [ -n "$version" ]; then
        echo "Zabbix API is up — version: ${version}"
        break
    fi

    sleep 2
    elapsed=$((elapsed + 2))
done

# Phase 2: verify user.login works
echo "Verifying login as ${API_USER}..."
while true; do
    if [ "$elapsed" -ge "$TIMEOUT" ]; then
        echo "TIMEOUT: Zabbix login failed within ${TIMEOUT}s"
        exit 1
    fi

    auth=$(curl -sf -X POST "$API_URL" \
        -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"user.login\",\"params\":{\"username\":\"${API_USER}\",\"password\":\"${API_PASS}\"},\"id\":1}" \
        2>/dev/null | jq -r '.result // empty' 2>/dev/null) || true

    if [ -n "$auth" ]; then
        echo "Login successful."
        exit 0
    fi

    # Older Zabbix (<5.4) uses "user" instead of "username"
    auth=$(curl -sf -X POST "$API_URL" \
        -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"user.login\",\"params\":{\"user\":\"${API_USER}\",\"password\":\"${API_PASS}\"},\"id\":1}" \
        2>/dev/null | jq -r '.result // empty' 2>/dev/null) || true

    if [ -n "$auth" ]; then
        echo "Login successful (legacy API)."
        exit 0
    fi

    sleep 2
    elapsed=$((elapsed + 2))
done
