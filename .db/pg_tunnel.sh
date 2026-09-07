#!/bin/bash
# ============================================================
# Cyber Sentinel — Postgres SSH port-forward helper
# ============================================================
# postgres_db has no `ports:` mapping in docker-compose-postgres.yml —
# only an internal_network address (10.10.10.16:5432). It was never meant
# to be reachable from outside the Docker host (same as mysqldb, mongo,
# no host port either). This script opens a local SSH forward through the
# same SSH access you already use for Ansible, so psql on your Mint
# machine can reach it as if it were local.
#
# It does NOT open any new port on the server, doesn't touch UFW, and
# doesn't add anything to nginx (postgres_db isn't a web service — no
# reverse proxy entry makes sense for a raw TCP/Postgres wire protocol
# connection).
#
# Usage:
#   ./pg_tunnel.sh dev            # tunnel to dev_vm
#   ./pg_tunnel.sh prod           # tunnel to rpi5-prod
#   ./pg_tunnel.sh dev 5433       # use local port 5433 instead of 5432
#
# Then, in SQL Workbench/J (while this script is running), new connection:
#   Driver:   PostgreSQL
#   URL:      jdbc:postgresql://localhost:5432/cyber_intelligence
#   Username: <postgres_user>
#   Password: <vault_postgres_password>
#   (see future-roadmap.md Section 8 for the credential naming history —
#   MySQL is fully decommissioned, this is a native Postgres account now)
#
# Stop the tunnel with Ctrl+C.
# ============================================================

set -euo pipefail

# --- Your inventory ---
SSH_USER="hunter"
DEV_VM_HOST="192.168.0.5"
PROD_HOST="192.168.0.2"
# YubiKey PKCS#11 module, same as your normal SSH login
# (ssh -I /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so hunter@...)
PKCS11_MODULE="/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
# ---------------------------------------------------------------------------

POSTGRES_CONTAINER_IP="10.10.10.9"
POSTGRES_PORT="5432"

ENV_NAME="${1:-}"
LOCAL_PORT="${2:-5432}"

if [[ -z "${ENV_NAME}" ]]; then
    echo "Usage: $0 <dev|prod> [local_port]"
    exit 1
fi

case "${ENV_NAME}" in
    dev)
        REMOTE_HOST="${DEV_VM_HOST}"
        ;;
    prod)
        REMOTE_HOST="${PROD_HOST}"
        ;;
    *)
        echo "Unknown environment '${ENV_NAME}' — expected 'dev' or 'prod'"
        exit 1
        ;;
esac

echo "Tunneling localhost:${LOCAL_PORT} -> ${REMOTE_HOST} -> ${POSTGRES_CONTAINER_IP}:${POSTGRES_PORT}"
echo "Leave this running. Connect from SQL Workbench/J with:"
echo "  JDBC URL: jdbc:postgresql://localhost:${LOCAL_PORT}/cyber_intelligence"
echo "  Username: <postgres_user>   Password: <vault_postgres_password>"
echo "  (native Postgres account — MySQL fully decommissioned, see future-roadmap.md Section 8)"
echo "Ctrl+C to stop."
echo

# -N: no remote command, tunnel only. -I: PKCS#11 module for YubiKey auth,
# same as your normal SSH login. -L: local_port:target_host:target_port
# through the SSH connection to REMOTE_HOST — target_host is resolved from
# REMOTE_HOST's own network view, so 10.10.10.16 (the Docker bridge IP)
# works even though your Mint machine has no route to it directly.
ssh -I "${PKCS11_MODULE}" -N -L "${LOCAL_PORT}:${POSTGRES_CONTAINER_IP}:${POSTGRES_PORT}" "${SSH_USER}@${REMOTE_HOST}"