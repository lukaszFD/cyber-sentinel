# Releases

All versions are on [GitHub Releases](https://github.com/lukaszFD/cyber-sentinel/releases).

| Version | Type | Date | Focus |
|---|---|---|---|
| [v2.3.0](#v230) | Stable | 16 November 2026 | API call log and usage page, VirusTotal budget from the provider's counter, Failure Guard |
| [v2.2.0](#v220) | Stable | 16 November 2026 | Own Pi-hole blocklists: AI classification, review, daily pull request to sentinel-blocklists |
| [v2.1.0](#v210) | Stable | 26 October 2026 | VirusTotal budget, urlscan.io and Shodan context, Deep Recon |
| [v2.0.0](#v200) | Stable | 7 October 2026 | PostgreSQL as the only database, AI agent pipeline, AI Config UI |
| [v1.0.3](#v103) | Release | 5 September 2026 | Local inference on Hailo-10H (removed in v2.0.0) |
| [v1.0.2-rc1](#v102-rc1) | Release candidate | 5 May 2026 | 1–5 threat scale, partitioning, unified Vault playbook |
| [v1.0.1](#v101) | Release | — | Ansible deployment |
| [v1.0.0](#v100) | Release | — | First version |

---

## v2.3.0

Counts every outgoing API request and stops a failing workflow after a few runs instead of thousands. Upgrades v2.2.0 in place; no data is lost.

### API Call Log

- New table `api_call_log` (partitioned by month, kept 6 months): one row per request to VirusTotal, Gemini, urlscan.io, Shodan, abuse.ch, RDAP and crt.sh — provider, caller, endpoint, HTTP status, outcome. `vt_lookup_log` became a view on it; its rows are moved once.
- All workflows log their calls in one *Log API calls* node; the main workflow logs VirusTotal right after the call. The VirusTotal request is no longer retried inside a run, so one claim is one call.
- The partition jobs (`sp_add_future_partitions()`, `sp_drop_old_partitions()`) handle tables of both schemas through `cyber_sentinel.partitioned_tables()`.

### VirusTotal Budget From the Provider

- New workflow **API Usage Monitor** (hourly at :05) stores VirusTotal's own counter for the key (`overall_quotas`; free, it does not use the quota). `v_vt_budget` uses the higher of this and the local count, so calls from the dev environment and manual tests reduce the budget too.
- The AI Config UI simulator goes through the same budget (`api_claim()`): same per-minute limit and reserve; its separate in-memory limit (`AI_UI_VT_MIN_INTERVAL`, `AI_UI_VT_DAILY_LIMIT`) is gone.
- One e-mail per provider and UTC day when usage crosses `api_alert_threshold_pct` (80 %) of `vt_daily_limit` / `api_daily_limit_<provider>`. Only VirusTotal is stopped by its budget.

### Failure Guard

- New workflow **Failure Guard**, set as the Error Workflow of every workflow. After `failure_guard_threshold` (10) failed runs in a row it deactivates the workflow and sends **one** e-mail per streak; a successful run resets the count.
- Works while Vault is sealed: n8n credentials only, sender and recipient in `ops_settings` (written by 04.3).
- New playbook **06.3** issues its n8n API key (rotated on every run) and activates it — n8n runs an Error Workflow only while it is active.

### AI Config UI

- **API usage** page: today per provider (local count, VirusTotal's counter, limit), per caller and per hour, the last 30 days, rate limits and errors, usage alerts and Failure Guard alerts.
- Settings step 9 *API usage and failures*.

### Upgrading from v2.2.0

The SQL scripts are idempotent; existing data stays.

```bash
cd ansible
ansible-playbook 04_3_db_postgres.yml      --limit rpi5-prod
ansible-playbook 04_5_ai_config_editor.yml --limit rpi5-prod
ansible-playbook 04_6_post_config.yml      --limit rpi5-prod \
  --start-at-task "[04.6.4.1] Verify workflow JSON exists on control host"
ansible-playbook 06_3_n8n_api_key.yml      --limit rpi5-prod
```

- 04.3 must run before 04.5: it moves `vt_lookup_log` and recreates `v_vt_budget`, whose UI grant 04.5 restores.
- 04.6 re-imports all six workflows and leaves them **inactive**: publish the main workflow, Deep Recon, both blocklist workflows and *API Usage Monitor* again in n8n. 06.3 runs after 04.6 and activates *Failure Guard* itself.
- Optional: `vault_n8n_alert_to` in `vault.yml` for a different recipient (default: the sender).

---

## v2.2.0

Own Pi-hole blocklists: domains that get through Pi-hole but should not — malicious, tracking, telemetry — are published as plain domain lists to the public repository [sentinel-blocklists](https://github.com/lukaszFD/sentinel-blocklists), which Pi-hole pulls as adlists. Upgrades v2.1.0 in place; no data is lost.

### Three Lists

- `lists/malicious.txt` — every Pi-hole auto-block of the main workflow, approved automatically. A domain stays `blocklist_malicious_ttl_days` (default 90) after its last block; a new block extends it. The backup Pi-hole gets these blocks too.
- `lists/tracking.txt`, `lists/telemetry.txt` — AI classification, approved by a human.
- Domains only, exact match, one per line: Pi-hole does not block IPs, and telemetry often shares CDN IPs with normal sites.
- The database is the source of truth; `blocklist_render()` generates the files from it.

### Blocklist Candidates (n8n, daily 03:20)

- Candidates: domains with a public IPv4 answer in the last `blocklist_lookback_days`, queried at least `blocklist_min_queries` times, whose name contains an active pattern (`telemetry`, `metrics`, `analytics`, `track`, …), not classified yet and not on any list.
- Gemini in batches (`blocklist_ai_batch_size`, at most `blocklist_ai_daily_limit` per day), **no VirusTotal calls**. Returns category (telemetry / tracking / ads / functional / unknown), vendor, confidence, breakage risk and a reason.
- Telemetry and tracking at or above `blocklist_ai_min_confidence` become review candidates; an e-mail announces them. Answers about domains that were not in the batch are dropped.
- A classified or rejected domain is never sent to the AI or proposed again.

### Blocklist Publish (n8n, daily 05:20)

- The branch `n8n/daily-update` is rebuilt from `main` on every run with the full generated files, so there is always one pull request showing the whole difference. A pull request left open after the lists became equal to `main` again is closed.
- The merge stays manual (a ruleset on `main` of sentinel-blocklists requires a pull request).
- `blocklist_publish_enabled = 0` (default) is a dry run: lists are generated, compared and logged only.
- Every run is logged in `blocklist_publish_log` (dry run / no change / published / error); a new or updated pull request and errors are e-mailed.
- A domain covered by a **manual** allow-list entry (the domain or a parent) is never published. Tranco entries and trusted infrastructure do not protect: telemetry usually sits on popular vendor domains.

### AI Config UI

- **Blocklists** page: candidates with vendor, confidence and breakage risk; approve / reject selected rows; published, expired and rejected entries per list; manual additions; last publish runs with links to the pull request; preview of the generated files.
- *Remove* on a published entry sets it to rejected, so neither the AI nor the malicious sync adds it again.
- **Name patterns** editor and a versioned **classifier prompt**.
- Settings for all `blocklist_*` keys.

### Database

New script `db_blocklists.sql` (playbook 04.3): `blocklist_entries`, `blocklist_classifications`, `blocklist_name_patterns`, `blocklist_prompt_templates`, `blocklist_publish_log`, views `v_blocklist_ai_queue` and `v_blocklist_published`, functions `blocklist_record_classifications()`, `blocklist_sync_malicious()`, `blocklist_render()`, `blocklist_is_protected()`. The AI Config UI role gets matching grants (no DELETE on `blocklist_entries`).

### Upgrading from v2.1.0

The SQL scripts are idempotent; existing data and tuned settings stay.

1. Create a fine-grained GitHub token for `lukaszFD/sentinel-blocklists` only — *Contents* and *Pull requests* read/write — and set it as `vault_github_blocklists_token` in `vault.yml`.
2. Run the playbooks:

```bash
cd ansible
ansible-playbook 06_1_initialize_provision_vault.yml --limit rpi5-prod
ansible-playbook 04_3_db_postgres.yml               --limit rpi5-prod
ansible-playbook 04_5_ai_config_editor.yml          --limit rpi5-prod
ansible-playbook 04_6_post_config.yml               --limit rpi5-prod
```

3. In n8n: publish *Blocklist Candidates* and *Blocklist Publish* (imported inactive).
4. Check a dry run in the AI Config UI (Blocklists → publish log), then set `blocklist_publish_enabled = 1`.
5. In Pi-hole, add the adlists and run a gravity update:

```
https://raw.githubusercontent.com/lukaszFD/sentinel-blocklists/main/lists/malicious.txt
https://raw.githubusercontent.com/lukaszFD/sentinel-blocklists/main/lists/tracking.txt
https://raw.githubusercontent.com/lukaszFD/sentinel-blocklists/main/lists/telemetry.txt
```

### Next

API call monitoring: counting real requests per provider and caller, VirusTotal's own quota counter, usage in the AI Config UI and alerts before the daily limit. See the [roadmap](future-roadmap.md#next-api-call-monitoring).

---

## v2.1.0

More context for each verdict and a second look at high-scored domains. Upgrades v2.0.0 in place; no data is lost.

### VirusTotal Budget

The main workflow runs every minute instead of every 3 minutes, and `claim_next_observable()` decides whether a run may call VirusTotal.

- Daily limit (500), per-minute limit (4) and a reserve kept per hour until the 00:00 UTC reset — `vt_daily_limit`, `vt_per_minute_limit`, `vt_reserve_per_hour`.
- A backlog is cleared at up to 60 observables per hour instead of 20.
- Every call is logged in `vt_lookup_log`; overlapping runs never take the same pair, and a failed run is retried after 15 minutes.
- Calls used and left today are shown in the AI Config UI settings.

### More Context in the Main Workflow

- **Shodan InternetDB** for every IP (free, no key): open ports, software, known CVEs, tags and the hostnames seen on the IP.
- **urlscan.io search** for observables above the VirusTotal gate: earlier scans of the domain's page (title, HTTP status, TLS issuer and certificate age, urlscan verdict) and other sites seen on the same IP.
- Both are context for the AI agent and the e-mail; the rule score is unchanged. Prompt version 1.2 (inactive draft) describes the new evidence.
- E-mail shows hostnames on the IP, related sites and the certificate; CVEs stay in the data for the AI only.

### Deep Recon

New hourly workflow that re-assesses verdicts scored ≥ `recon_min_score` (default 3).

- Sources: RDAP (domain age, registrar), crt.sh (certificate history), urlscan.io page scan (page text, forms, certificate, domains the page loads from).
- AI analyst without tools: confirms or contradicts the verdict and may propose a score within `recon_max_deviation`. Verdicts are never changed automatically.
- E-mail when the proposed score differs from the verdict.
- Page content is treated as untrusted: data only, scripts and comments stripped, URLs defanged.
- New table `deep_recon`, queue `v_pending_recon`, versioned prompt in `recon_prompt_templates`.

### AI Config UI

- **Deep recon** page: results, filters, re-queue, links to urlscan.io reports.
- Recon prompt editor with versions.
- Settings for the VirusTotal budget, urlscan.io, Shodan and Deep Recon with plain descriptions.

### Upgrading from v2.0.0

The SQL scripts are idempotent; existing data stays.

```bash
cd ansible
ansible-playbook 04_3_db_postgres.yml     --limit rpi5-prod
ansible-playbook 04_5_ai_config_editor.yml --limit rpi5-prod
ansible-playbook 04_6_post_config.yml      --limit rpi5-prod
```

- Set `vault_urlscanio_api_key` in `vault.yml`; if it was empty before, also run `06_1_initialize_provision_vault.yml`.
- In n8n: publish *Deep Recon* and the re-imported main workflow; delete *Site Recon* if it was ever imported.
- In the AI Config UI: activate prompt version 1.2.

---

## v2.0.0

**Stable production release.** Not a release candidate: the database schema, the AI pipeline and the deployment are complete and running in production on the Raspberry Pi 5. It replaces the v1.0.2-rc1 line, which was never promoted to a final v1.0.2.

v2.0.0 does three things: moves all data to one PostgreSQL database, turns the AI step into an agent with memory and guardrails, and moves its configuration out of the workflow into the database and a web UI.

### One Database

MySQL and MongoDB are removed. Everything now lives in **PostgreSQL 16** with `pgvector` and `pg_cron`.

- Two schemas: `cyber_sentinel` for DNS traffic and verdicts, `cyber_sentinel_ai` for the AI pipeline.
- Raw CTI responses moved from MongoDB to a JSONB table (`threat_data_raw`).
- Native declarative partitioning by month for `dns_queries`, `threat_indicators` and `network_events`; 6-month retention run by `pg_cron`.
- Foreign keys restored where PostgreSQL allows them on partitioned tables.
- Plain, idempotent SQL files applied in a fixed order by Ansible; Liquibase is no longer used.
- Separate roles for n8n and for the AI Config UI, each with only the access it needs.

Details: [Database](database.md).

### AI Pipeline

The workflow was rebuilt around a deterministic score that the AI reviews, rather than an AI that scores from scratch.

- **VirusTotal gate** — observables below `vt_gate_min_malicious` detections are closed as clean without further API calls or AI tokens.
- **Rule engine in the database** — `compute_threat_score()` returns a 1–5 score with a step-by-step trace from VirusTotal, ThreatFox and URLhaus.
- **AI agent** — Gemini reviews the evidence and the rule score and may adjust it by at most `ai_max_deviation`. Output is a fixed JSON schema with a rationale in English and Polish.
- **Vector memory** — every verdict is embedded and stored in pgvector; the agent searches similar past cases with the `historical_verdicts` tool.
- **Guardrails enforced by the workflow** — score clamped to the allowed range, rule score kept if the agent fails, CTI data treated as untrusted input.
- **Audit** — `verdict_audit` records rule score, final score, what the agent changed and why, model and prompt version.
- **Pi-hole auto-block** — domains above `pihole_block_min_vt_malicious` detections (not trusted infrastructure) are added to the Pi-hole denylist; every attempt is logged.
- **Allow-list** — Tranco top domains (weekly sync) plus manual entries are skipped; exclusions keep user-content platforms such as `github.io` under analysis.

Details: [n8n Workflow](n8n.md).

### AI Config UI

New web UI (`ai-config-ui`) for everything the pipeline reads from the database: thresholds, versioned prompts, allow-lists, trusted infrastructure and threat level wording. Includes a simulator that runs live lookups without touching the queue. Every change is logged with the user who made it.

### Simplified Stack

- Removed: MySQL, MongoDB, Hailo-10H / `hailo-ollama`, Open WebUI, local models. AI runs on Gemini only.
- All images pinned by digest.
- n8n and Vault listen on loopback only; web UIs are reached through Nginx.
- n8n credentials created automatically with fixed IDs (playbook 06.2), so the imported workflow runs without manual setup.
- Documentation rewritten and shortened.

### Upgrading from v1.x

There is no in-place migration from MySQL/MongoDB. Deploy v2.0.0 on a clean host or a clean Docker setup; historical v1 data is not carried over.

```bash
cd ansible
ansible-playbook 00_main.yml --limit rpi5-prod
```

New secrets are required in `vault.yml` — see [Deployment](deployment.md#secrets).

---

## v1.0.3

Added local inference on the Hailo-10H accelerator: `hailo-ollama` as a systemd service and Open WebUI behind Nginx. Testing showed that the 1.5–3B models available on the device were not reliable enough for multi-source threat scoring, so Gemini stayed the reasoning engine. **Removed in v2.0.0.**

## v1.0.2-rc1

Introduced the 1–5 threat scale loaded from the database, URLhaus as a supporting source only, a score cap for trusted infrastructure, monthly partitioning with 6-month retention (MySQL), severity-coloured alert emails and a single Vault lifecycle playbook. Never promoted to a final release; superseded by v2.0.0.

## v1.0.1

Moved the whole deployment to Ansible, merged the Vault playbooks and updated the Grafana dashboards.

## v1.0.0

First version: DNS capture, CTI enrichment and the first AI workflow.