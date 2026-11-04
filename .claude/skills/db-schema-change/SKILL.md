---
name: db-schema-change
description: Change the Cyber Sentinel PostgreSQL schema or seed data (tables, views, functions, ai_settings, prompt versions, partitioning) in an idempotent, upgrade-safe way and test it on the dev database. Use for any edit under config/postgres/ or SQL in .db/.
---

# Database schema change

## Files and order

Rendered by Ansible (`04_3_db_postgres.yml`, Jinja2: `{{ postgres_user }}`, `{{ ai_config_db_user }}`) and run in this order on `cyber_intelligence`:

1. `db_deployment.sql` — schema `cyber_sentinel` (CTI tables, dictionaries, Grafana views).
2. `db_partitioning_retention.sql` — partitions + pg_cron retention.
3. `db_ai_pipeline.sql` — schema `cyber_sentinel_ai` (settings, prompts, queue, budget, Deep Recon).
4. `db_ai_config_editor.sql` — AI Config UI role, grants, change log.

Put the change in the file that owns the object. In `db_ai_pipeline.sql` add a new numbered `SECTION` instead of scattering edits.

## Rules

- **Idempotent, always.** `CREATE … IF NOT EXISTS`, `CREATE OR REPLACE` for views/functions, `ALTER TABLE … ADD COLUMN IF NOT EXISTS`, `INSERT … ON CONFLICT DO NOTHING` (or `WHERE NOT EXISTS`). Role creation inside `DO $$ … IF NOT EXISTS (pg_roles) …`.
- **No data loss on upgrade.** No `DROP TABLE`, no destructive `ALTER TYPE` on existing installs. If something must go, ask the user and write the upgrade step into the release notes.
- Partitioned tables: the partition key must be in the PK at `CREATE TABLE` time — see the comment in `db_deployment.sql`.
- Settings are data: new switch/limit = `ai_settings` row with a description, plus the matching entry in `config/ai_config_ui/app.py`.
- Prompts: new version = new row with `is_active = FALSE`; never edit or deactivate the active one in SQL (unique index allows one active).
- Do not break Grafana views (`v_grafana_*`) or the n8n queries; grep `config/n8n/workflows/` and `config/grafana/` for any column you rename.
- Grants: n8n role and `ai_config_db_user` need explicit grants on new objects.
- Bump `Version:` in the file header and describe the new section there.

## Test on dev

Database access:
- **Dev:** full. Tunnel with `.db/pg_tunnel.sh dev` (run in background; needs the user's YubiKey — if it prompts, ask the user to start it) and use `psql -h localhost -p 5432 -d cyber_intelligence`. Or deploy with `cd ansible && ansible-playbook -i hosts.ini 04_3_db_postgres.yml --limit vm-prox-dev`.
- **Prod:** read-only. Only `SELECT` (e.g. `.db/db_inventory_check.sql`) through `.db/pg_tunnel.sh prod`. No DDL, no DML, no deploy.

Checks:
1. Run the playbook (or the rendered scripts) **twice** on dev; the second run must succeed with no changes or errors.
2. Run `.db/db_inventory_check.sql` and compare object counts with before.
3. Exercise the change: query the new view/function, call `setting('<key>')`, confirm grants by connecting as the app role.
4. If verdict logic changed, `.db/reset_ai_verdicts.sql` can re-queue on dev — never on prod.

## Done when

SQL is idempotent (proved by two runs), header version bumped, UI/n8n/Grafana consumers updated, `docs/database.md` updated, and the upgrade commands for prod are ready for `release-docs`.
