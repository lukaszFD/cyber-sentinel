#!/bin/bash
# ============================================================
# Cyber Sentinel — add random passwords to the encrypted vault files
# ============================================================
# Generates a password (letters and digits only — the values end up in
# SQL and .env, where quotes or $ would break them) for every KEY:LENGTH
# given, and appends it to every host's ansible/host_vars/<host>/vault.yml
# (each host gets its own value). Each file is decrypted only into a
# private temp file, re-encrypted, and the old encrypted file is kept as
# vault.yml.bak. Passwords are never printed. Keys that already exist in a
# file are left untouched there.
#
# Usage:
#   ansible/tools/vault_add_password.sh                      # browser sandbox defaults
#   ansible/tools/vault_add_password.sh vault_foo:32 vault_bar:24
#   VAULT_HOSTS="dev_vm" ansible/tools/vault_add_password.sh vault_foo:32   # one host only
#   VAULT_FILE=path/to/vault.yml ansible/tools/vault_add_password.sh ...    # one explicit file
#
# Vault password: $ANSIBLE_VAULT_PASSWORD_FILE (or ansible-vault asks).
# Read a value later:  ansible-vault view ansible/host_vars/dev_vm/vault.yml | grep vault_foo
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_VARS="$(cd "${SCRIPT_DIR}/../host_vars" && pwd -P)"

FILES=()
if [[ -n "${VAULT_FILE:-}" ]]; then
    FILES=("$VAULT_FILE")
elif [[ -n "${VAULT_HOSTS:-}" ]]; then
    for h in $VAULT_HOSTS; do FILES+=("${HOST_VARS}/${h}/vault.yml"); done
else
    for f in "${HOST_VARS}"/*/vault.yml; do [[ -f "$f" ]] && FILES+=("$f"); done
fi
[[ ${#FILES[@]} -gt 0 ]] || { echo "No vault files found under ${HOST_VARS}/<host>/vault.yml"; exit 1; }

if [[ $# -eq 0 ]]; then
    set -- vault_sandbox_db_password:32 vault_sandbox_pihole_admin_password:24
fi

AV="$(command -v ansible-vault || true)"
[[ -z "$AV" && -x "$HOME/ansible_mac_venv/bin/ansible-vault" ]] && AV="$HOME/ansible_mac_venv/bin/ansible-vault"
[[ -z "$AV" ]] && { echo "ansible-vault not found (PATH or ~/ansible_mac_venv)"; exit 1; }

gen() {  # gen LENGTH -> random [A-Za-z0-9]{LENGTH}
    local out=""
    while [[ ${#out} -lt $1 ]]; do
        out+="$(openssl rand -base64 64 | LC_ALL=C tr -dc 'A-Za-z0-9')"
    done
    printf '%s' "${out:0:$1}"
}

for spec in "$@"; do
    key="${spec%%:*}"
    len="${spec##*:}"
    [[ "$key" =~ ^vault_[a-z0-9_]+$ ]] || { echo "Bad key name: $key"; exit 1; }
    [[ "$len" =~ ^[0-9]+$ && "$len" -ge 16 && "$len" -le 128 ]] || { echo "Bad length for $key: $len (16-128)"; exit 1; }
done

umask 077
TMP=""
cleanup() { [[ -n "$TMP" && -f "$TMP" ]] && { rm -P "$TMP" 2>/dev/null || rm -f "$TMP"; }; TMP=""; }
trap cleanup EXIT INT TERM

add_to_file() {  # add_to_file VAULT_FILE KEY:LEN...
    local vf="$1"; shift
    [[ -L "$vf" ]] && vf="$(readlink "$vf")"
    [[ -f "$vf" ]] || { echo "! no vault file at $vf, skipped"; return 0; }
    echo "== $vf"
    TMP="$(mktemp "${TMPDIR:-/tmp}/vault.XXXXXX")"
    "$AV" decrypt --output "$TMP" "$vf" >/dev/null

    local added=() spec key len
    for spec in "$@"; do
        key="${spec%%:*}"
        len="${spec##*:}"
        if grep -qE "^${key}:" "$TMP"; then
            echo "= $key already exists, left unchanged"
            continue
        fi
        [[ -n "$(tail -c1 "$TMP")" ]] && echo >> "$TMP"
        printf "%s: '%s'\n" "$key" "$(gen "$len")" >> "$TMP"
        added+=("$key ($len)")
    done

    if [[ ${#added[@]} -eq 0 ]]; then
        echo "Nothing to add."
    else
        cp -p "$vf" "${vf}.bak"
        "$AV" encrypt --output "${vf}.new" "$TMP" >/dev/null
        mv "${vf}.new" "$vf"
        chmod 600 "$vf"
        local a
        for a in "${added[@]}"; do echo "+ added $a"; done
        echo "Encrypted file updated (previous version: ${vf}.bak)"
    fi
    cleanup
}

for vf in "${FILES[@]}"; do
    add_to_file "$vf" "$@"
done
