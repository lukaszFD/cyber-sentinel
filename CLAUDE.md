# CLAUDE.md

Guidance for Claude (Claude Code and the Claude.ai "Cyber Sentinel" project) when working in this repository.

## What this is

Cyber Sentinel is a self-hosted, AI-driven network security stack: DNS filtering and logging (Pi-hole + recursive Unbound + passive DNS), threat-intel enrichment and AI verdicts in n8n (Gemini, VirusTotal, abuse.ch ThreatFox/URLhaus, urlscan.io, Shodan), PostgreSQL 16 + pgvector, HashiCorp Vault for secrets, Nginx TLS proxy, Prometheus/Grafana monitoring. Production runs on a Raspberry Pi 5.

There is no application build. The repo is infrastructure-as-code (Ansible + Docker Compose), plus a few Python services and SQL.

## Layout

- `ansible/` — numbered playbooks, run in order by `00_main.yml`; each one can be re-run on its own.
  - `hosts.ini` — inventory: `rpi5` (prod, `.prod`), `dev_vm` (Proxmox test VM, `.local`), `local_vm` (port 2222).
  - `group_vars/all/images.yml` — pinned container images (`cs_images.*`).
  - `group_vars/all/vault.yml` — ansible-vault encrypted secrets (gitignored, never commit or print).
  - `templates/` — Jinja2 templates (`env.j2`, Nginx config, Tranco allowlist sync).
- `docker/docker-compose-cyber-sentinel.yml` — the whole stack; templated by Ansible (`{{ cs_images.* }}`), not run directly.
- `config/` — per-service config copied to the host:
  - `ai_config_ui/` — Flask app for editing AI pipeline config (`app.py`, `live_lookup.py`).
  - `dns/` — passive DNS + `log_processor.py` that ships DNS logs to Postgres.
  - `hcv/` — Vault auto-unsealer.
  - `n8n/workflows/` — exported n8n workflows (JSON).
  - `postgres/` — schema SQL (`db_deployment.sql`, `db_ai_pipeline.sql`, partitioning/retention, AI config editor).
  - `pihole/`, `unbound/`, `prometheus/`, `grafana/provisioning/`.
- `.db/` — helper scripts: SSH tunnel to Postgres (`pg_tunnel.sh dev|prod`) and ad-hoc SQL.
- `docs/` + `mkdocs.yml` — MkDocs Material site published to https://lukaszfd.github.io/cyber-sentinel/.
- `.github/workflows/` — CodeQL, Trivy, OpenSSF Scorecard (`.trivyignore` holds accepted findings).

## Deploying

Run from `ansible/` on the control machine (needs `ansible`, `hvac`, `docker` Python libs):

```bash
ansible-playbook -i hosts.ini 00_main.yml --limit vm-prox-dev
```

- Always pass `--limit` (`vm-prox-dev`, `rpi5-prod`, `local-vm`) — every playbook targets `all_servers`, so a run without it hits prod too.
- Claude may deploy to `vm-prox-dev` only. Never run playbooks against `rpi5-prod`; give the user the commands.
- SSH (Ansible and `.db/pg_tunnel.sh`) uses the user's YubiKey; if a run needs a touch/PIN or fails on auth, hand the command to the user.
- Database: full access on dev, read-only `SELECT` on prod.
- Secrets flow: `vault.yml` (ansible-vault) → HashiCorp Vault (playbook `06_1`) → read by n8n at runtime.

## Conventions

- Add or bump container images only in `group_vars/all/images.yml`; keep them pinned.
- Stack must work on both `amd64` and `arm64`.
- Schema changes go into the matching `config/postgres/*.sql` file and must stay idempotent (re-runnable deploys).
- n8n workflows are edited in the n8n UI and exported to `config/n8n/workflows/`; keep credentials out of the JSON.
- When behaviour changes, update the related page in `docs/` (and `docs/releases.md` for a release).
- Never commit secrets, `.env`, `ansible/.vault_pass` or decrypted vault files.

## Skills (`.claude/skills/`)

- `grill-me` — interview the user about a plan until every decision is made; use before any non-trivial change.
- `add-cti-provider` — new threat-intel source end to end (Vault, SQL, n8n, prompt, UI, docs).
- `db-schema-change` — idempotent Postgres changes and dev testing.
- `add-stack-service` — new container behind Nginx TLS with a pinned multi-arch image.
- `release-docs` — release notes with upgrade path, version bumps, PR, tag and GitHub Release.

## Claude.ai project notes

<!-- Paste the custom instructions / key notes from the Claude.ai "Cyber Sentinel" project here
     so Claude Code sessions follow the same rules. -->
