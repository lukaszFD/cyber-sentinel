# .db — database helpers

Postgres (`postgres_db`, `10.10.10.9:5432`) has no published port. These scripts open an SSH tunnel through the host (YubiKey auth), so a local client can reach it on `localhost`.

| Folder | For | YubiKey PKCS#11 module |
|---|---|---|
| `linux/` | Linux Mint workstation | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |
| `mac/` | Mac mini | `/opt/homebrew/lib/opensc-pkcs11.so` (or the key already in ssh-agent via `yk`) |

```bash
.db/mac/db_dev.sh       # dev  -> localhost:5432
.db/mac/db_prod.sh      # prod -> localhost:5433 on Mac (5432 on Linux), SELECT only
```

Connection: database `cyber_intelligence`, user `postgres`, password `vault_postgres_password` from `ansible/group_vars/all/vault.yml`.

**pgAdmin (Mac):** Tools → Import/Export Servers → Import → `.db/mac/pgadmin-servers.json`. This adds DEV (5432) and PROD (5433, red, read-only) under the *Cyber Sentinel* group. Start the matching tunnel before connecting.

SQL (shared): `db_inventory_check.sql` (inventory, safe on prod), `reset_ai_verdicts.sql` (re-queues AI verdicts, dev only).
