#!/usr/bin/env bash
# Create a test host in Zabbix linked to the OS-Report template.
# Requires: the OS-Report template must already exist (run ztc prepare first).
# Usage: ./seed-host.sh
set -euo pipefail

API_URL="${ZABBIX_API_URL:-http://localhost:8080/api_jsonrpc.php}"
API_USER="${ZABBIX_API_USER:-Admin}"
API_PASS="${ZABBIX_API_PASS:-zabbix}"
TEST_HOST="${TEST_HOST:-integration-test-host}"
AGENT_DNS="${AGENT_DNS:-zabbix-agent2}"
OS_REPORT_TEMPLATE="${OS_REPORT_TEMPLATE:-tmpl.vulners.os-report}"

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

    local result
    result=$(curl -sf -X POST "$API_URL" \
        -H 'Content-Type: application/json' \
        -d "$payload")

    local error
    error=$(echo "$result" | jq -r '.error.data // empty' 2>/dev/null)
    if [ -n "$error" ]; then
        echo "API error (${method}): $error" >&2
        echo "$result" | jq -r '.error.message // empty' >&2
        return 1
    fi

    echo "$result" | jq -r '.result'
}

echo "=== Seeding test host: ${TEST_HOST} ==="

# Authenticate
echo "Logging in..."
AUTH=$(zbx_api "user.login" "{\"username\":\"${API_USER}\",\"password\":\"${API_PASS}\"}" 2>/dev/null) \
    || AUTH=$(zbx_api "user.login" "{\"user\":\"${API_USER}\",\"password\":\"${API_PASS}\"}")
# Strip quotes from auth token
AUTH=$(echo "$AUTH" | tr -d '"')
echo "Auth token obtained."

# Look up OS-Report template
echo "Looking up template: ${OS_REPORT_TEMPLATE}..."
TEMPLATE_ID=$(zbx_api "template.get" "{\"filter\":{\"host\":[\"${OS_REPORT_TEMPLATE}\"]},\"output\":[\"templateid\"]}" "$AUTH" \
    | jq -r '.[0].templateid // empty')

if [ -z "$TEMPLATE_ID" ]; then
    echo "FAIL: Template '${OS_REPORT_TEMPLATE}' not found. Run 'ztc prepare' first."
    exit 1
fi
echo "Template ID: ${TEMPLATE_ID}"

# Look up "Linux servers" host group
echo "Looking up host group 'Linux servers'..."
GROUP_ID=$(zbx_api "hostgroup.get" "{\"filter\":{\"name\":[\"Linux servers\"]},\"output\":[\"groupid\"]}" "$AUTH" \
    | jq -r '.[0].groupid // empty')

if [ -z "$GROUP_ID" ]; then
    echo "FAIL: Host group 'Linux servers' not found."
    exit 1
fi
echo "Group ID: ${GROUP_ID}"

# Check if host already exists
EXISTING=$(zbx_api "host.get" "{\"filter\":{\"host\":[\"${TEST_HOST}\"]},\"output\":[\"hostid\"]}" "$AUTH" \
    | jq -r '.[0].hostid // empty')

if [ -n "$EXISTING" ]; then
    echo "Host '${TEST_HOST}' already exists (ID: ${EXISTING}), updating template links..."
    # Update the host to link the template
    zbx_api "host.update" "{\"hostid\":\"${EXISTING}\",\"templates\":[{\"templateid\":\"${TEMPLATE_ID}\"}]}" "$AUTH" > /dev/null
    echo "PASS: Host '${TEST_HOST}' updated with OS-Report template."
    exit 0
fi

# Create the host with agent interface pointing to the agent2 container
echo "Creating host '${TEST_HOST}'..."
HOST_RESULT=$(zbx_api "host.create" "{
    \"host\": \"${TEST_HOST}\",
    \"groups\": [{\"groupid\": \"${GROUP_ID}\"}],
    \"templates\": [{\"templateid\": \"${TEMPLATE_ID}\"}],
    \"interfaces\": [{
        \"type\": 1,
        \"main\": 1,
        \"useip\": 0,
        \"dns\": \"${AGENT_DNS}\",
        \"ip\": \"\",
        \"port\": \"10050\"
    }]
}" "$AUTH")

HOST_ID=$(echo "$HOST_RESULT" | jq -r '.hostids[0] // empty')
if [ -z "$HOST_ID" ]; then
    echo "FAIL: Could not create host. Response: ${HOST_RESULT}"
    exit 1
fi

echo "PASS: Host '${TEST_HOST}' created (ID: ${HOST_ID}) with OS-Report template."
