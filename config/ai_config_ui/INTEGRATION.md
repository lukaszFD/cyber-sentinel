# AI Config Editor (`ai-config-ui`)

Web UI for everything the n8n AI pipeline reads from Postgres: settings, the versioned
AI Agent prompt, trusted infrastructure, manual allow-list + exclusions and the threat-scale
wording. Runs as its own container (`10.10.10.8`) behind `nginx-proxy` and connects as a
dedicated least-privilege role — never as `postgres` and never as the n8n role.

| Piece | Where |
|-------|-------|
| App (Flask + gunicorn), `Dockerfile` | `config/ai_config_ui/` |
| DB role, grants, audit log, prompt guards | `config/postgres/db_ai_config_editor.sql` |
| Build context staging | `04_1_prepare_stack.yml` `[04.1.2.8]` |
| Container | `docker-compose-cyber-sentinel.yml` `[SVC.UI.AI_CONFIG]` |
| DB role + rebuild of this one service | `04_5_ai_config_editor.yml` |
| Nginx vhost `ai-config.<domain_suffix>` | `05_deploy_proxy.yml` (`ai_config` entry) |
| Credentials copy in Vault | `06_1_initialize_provision_vault.yml` `[06.1.6.1]` |

## Variables

`group_vars/all/all_servers.yml`:

```yaml
ai_config_db_user: "ai_config_editor"
```

`group_vars/all/vault.yml` (ansible-vault):

```yaml
# openssl rand -hex 24 — hex only: the value lands in a SQL literal and in .env
vault_ai_config_db_password: "<48 hex chars>"
# openssl rand -hex 32
vault_ai_ui_secret_key: "<64 hex chars>"
# UI logins: plain password (>= 12 chars) or a werkzeug hash ("pbkdf2:..." / "scrypt:...")
#   python3 -c "from werkzeug.security import generate_password_hash as g; print(g('...'))"
vault_ai_ui_users:
  lukasz: "<password or hash>"
  second_user: "<password or hash>"
# TLS for nginx — certificate issued for ai-config.prod / ai-config.local
vault_ai_config_cert: |
  -----BEGIN CERTIFICATE-----
  ...
vault_ai_config_key: |
  -----BEGIN PRIVATE KEY-----
  ...
```

## `templates/env.j2`

```jinja
# --- AI config editor (ai-config-ui) ---
AI_UI_DB_USER={{ ai_config_db_user }}
AI_UI_DB_PASSWORD='{{ vault_ai_config_db_password }}'
AI_UI_SECRET_KEY='{{ vault_ai_ui_secret_key }}'
AI_UI_USERS='{{ vault_ai_ui_users | to_json | replace("'", "\\u0027") }}'
AI_UI_VT_API_KEY='{{ vault_virus_total_token }}'
AI_UI_ABUSE_API_KEY='{{ vault_abuse_api_key }}'
```

Single quotes keep `$` in werkzeug hashes literal for docker compose; the `replace` keeps a
`'` inside a password from closing the quote (`'` is still valid JSON).

## Simulator live lookups

"Fetch live data & calculate" on `/simulator` calls the same APIs as the workflow and runs a
Python port of its two reduction nodes (`live_lookup.py`): VirusTotal by IP, then ThreatFox
(by IP) and URLhaus (by FQDN) only when VirusTotal passes `vt_gate_min_malicious`.

- Keys: `vault_virus_total_token`, `vault_abuse_api_key` — already in `vault.yml` for n8n.
  Empty `AI_UI_VT_API_KEY` disables the button; the rest of the UI works without it.
- The FQDN is resolved directly against Unbound (`AI_UI_RESOLVER`, default `10.10.10.2`),
  not via Pi-hole — otherwise passive_dns would log it and the domain would enter the real
  n8n queue. Unbound's `access-control` must allow `10.10.10.0/24` (it already serves Pi-hole).
- The VirusTotal free tier (4/min, 500/day) is shared with n8n. The UI keeps its own budget:
  `AI_UI_VT_MIN_INTERVAL` (default 20 s between lookups), `AI_UI_VT_DAILY_LIMIT` (default 50/day),
  and caches each result for `AI_UI_LIVE_CACHE_SECONDS` (default 900). Counters live in the
  process and reset on container restart.
- A VirusTotal 401/429/5xx is shown as an error and nothing is calculated — same rule as the
  workflow, which never scores a failed lookup as clean.

## DNS

Add `ai-config.prod` (and `ai-config.local` for dev) pointing at the host, the same way as
the other service names.

## Deployment order (why it matters)

- 04.1 must stage `ai_config_ui/` — 04.2 builds the whole compose file, this service included.
- 04.5 must run after 04.3 — 04.3 re-grants `ALL TABLES` in `cyber_sentinel_ai` to the n8n
  role on every run; 04.5 narrows the audit log again (it is also guarded by a trigger).
- Until 04.5 creates the role on a fresh host, the login page shows "no database connection".

## What the editor role can and cannot do

| Object | Access |
|--------|--------|
| `ai_settings` | `SELECT`, `UPDATE(value)` only — no INSERT/DELETE (a missing key makes `setting()` raise and stops the workflow) |
| `prompt_templates` | full DML; the **active** version cannot be edited or deleted, and exactly one version must be active at commit (DB triggers) |
| `trusted_infrastructure`, `domain_allowlist_exclusions` | full DML |
| `domain_allowlist` | `SELECT`; changes only through `v_manual_allowlist` (`source = 'manual'` rows, `WITH CHECK OPTION`) — Tranco rows are untouchable |
| `dic_threat_levels` | `SELECT`, `UPDATE(description, action_recommended, is_malicious_flag)` — no INSERT/DELETE; malicious levels must stay a contiguous top range (deferred trigger) |
| `config_change_log` | `SELECT` only; append-only for everyone except superusers |
| `pihole_block_log` | `SELECT` only (written by n8n) — shown under Settings → Automatic blocking |
| `dns_queries`, `verdict_audit`, `threat_*`, everything else | no access |
| `CREATE` in any schema | no |

Every change made through the UI is logged with the UI user's name; changes from psql or
n8n are logged with the database user.

## Allow-list precedence

`cyber_sentinel_ai.is_allowlisted()` applies "the most specific rule wins":

- Tranco entries never override an exclusion (`evil.github.io` is analysed although `github.io` is popular).
- A **manual** entry overrides an exclusion when it has more labels than it:
  `yt3.googleusercontent.com` (manual) is skipped, `lh3.googleusercontent.com` is still analysed.
- A manual entry equal to or broader than the exclusion (e.g. manual `github.io`) does not override it;
  the UI warns when such an entry is added.

## Pi-hole auto-block

The workflow adds a domain to Pi-hole's exact denylist when `pihole_block_enabled = 1`,
VirusTotal malicious >= `pihole_block_min_vt_malicious` (default 5) and the observable is not
trusted infrastructure. Pi-hole blocks names, not IPs; the IP is kept in the log and in the
Pi-hole comment.

- Credential: a Pi-hole **application password** (not the admin password), created by playbook
  06.1 Section 7b and stored in Vault at `credentials/pihole-api` (n8n policy: read).
  Rotate with `ansible-playbook 06_1_initialize_provision_vault.yml -e pihole_api_rotate=true`.
- Pi-hole API base URL defaults to `http://10.10.10.4` (`pihole_api_base_url` in group_vars).
- Every attempt — `blocked`, `already_blocked` or `error` with the reason — is written to
  `cyber_sentinel_ai.pihole_block_log`. To unblock, remove the domain in Pi-hole (Domains → Denylist).
