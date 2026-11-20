#!/bin/bash
# ============================================================
# Cyber Sentinel — Postgres SSH port-forward helper (macOS)
# ============================================================
# Same idea as ../linux/pg_tunnel.sh: postgres_db has no published port,
# only 10.10.10.9:5432 on the Docker internal network. This opens a local
# SSH forward through the host, so pgAdmin / psql on the Mac can reach it
# on localhost. Nothing is opened on the server.
#
# Mac differences:
#   - YubiKey PKCS#11 module is the Homebrew one (opensc).
#   - If the key is already in ssh-agent (`yk` in ~/.zshrc), the agent is
#     used and no PIN is asked again. Otherwise ssh loads the module itself.
#   - Prod defaults to local port 5433, so a dev and a prod tunnel can run
#     side by side and are never mixed up in pgAdmin.
#
# Usage:
#   ./pg_tunnel.sh dev            # localhost:5432 -> dev_vm
#   ./pg_tunnel.sh prod           # localhost:5433 -> rpi5-prod (SELECT only!)
#   ./pg_tunnel.sh dev 6432       # custom local port
#
# pgAdmin: Tools -> Import/Export Servers -> Import -> pgadmin-servers.json
# (this folder). Database cyber_intelligence, user postgres, password =
# vault_postgres_password from ansible/group_vars/all/vault.yml.
#
# Stop the tunnel with Ctrl+C.
# ============================================================

set -euo pipefail

# --- Inventory ---
SSH_USER="hunter"
DEV_VM_HOST="192.168.0.5"
PROD_HOST="192.168.0.2"
PKCS11_MODULE="/opt/homebrew/lib/opensc-pkcs11.so"
# -----------------

POSTGRES_CONTAINER_IP="10.10.10.9"
POSTGRES_PORT="5432"

ENV_NAME="${1:-}"

case "${ENV_NAME}" in
    dev)
        REMOTE_HOST="${DEV_VM_HOST}"
        DEFAULT_PORT="5432"
        ;;
    prod)
        REMOTE_HOST="${PROD_HOST}"
        DEFAULT_PORT="5433"
        ;;
    *)
        echo "Usage: $0 <dev|prod> [local_port]"
        exit 1
        ;;
esac

LOCAL_PORT="${2:-${DEFAULT_PORT}}"

if lsof -nP -iTCP:"${LOCAL_PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Local port ${LOCAL_PORT} is already in use:"
    lsof -nP -iTCP:"${LOCAL_PORT}" -sTCP:LISTEN
    echo "Stop that process or pass another port: $0 ${ENV_NAME} <port>"
    exit 1
fi

SSH_OPTS=(-N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30)
if ssh-add -l >/dev/null 2>&1; then
    echo "Using the key already loaded in ssh-agent."
else
    if [[ ! -f "${PKCS11_MODULE}" ]]; then
        echo "ssh-agent is empty and ${PKCS11_MODULE} is missing (brew install opensc)."
        exit 1
    fi
    echo "ssh-agent is empty — loading the YubiKey via ${PKCS11_MODULE} (PIN + touch)."
    echo "Tip: run 'yk' once per session so later tunnels don't ask again."
    SSH_OPTS+=(-I "${PKCS11_MODULE}")
fi

echo
echo "Tunneling localhost:${LOCAL_PORT} -> ${REMOTE_HOST} -> ${POSTGRES_CONTAINER_IP}:${POSTGRES_PORT} (${ENV_NAME})"
echo "pgAdmin / psql: host localhost, port ${LOCAL_PORT}, db cyber_intelligence, user postgres"
[[ "${ENV_NAME}" == "prod" ]] && echo "PROD: read-only — SELECT queries only."
echo "Leave this running. Ctrl+C to stop."
echo

exec ssh "${SSH_OPTS[@]}" -L "${LOCAL_PORT}:${POSTGRES_CONTAINER_IP}:${POSTGRES_PORT}" "${SSH_USER}@${REMOTE_HOST}"
