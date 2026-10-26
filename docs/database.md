# Database

One PostgreSQL 16 instance (`postgres_db`) with the `pgvector` and `pg_cron` extensions. Database `cyber_intelligence`, two schemas:

| Schema | Holds | Written by |
|---|---|---|
| `cyber_sentinel` | DNS traffic, CTI results and verdicts — the data | `dns_log_processor`, n8n |
| `cyber_sentinel_ai` | Everything that drives the AI pipeline — settings, prompts, allow-lists, audit, vector memory | AI Config UI, n8n, Tranco sync |

The SQL lives in [`config/postgres/`](https://github.com/lukaszFD/cyber-sentinel/tree/main/config/postgres) and is applied in this order. Every file is idempotent and re-runs on each deployment.

| # | File | Playbook | Creates |
|---|---|---|---|
| 1 | `db_deployment.sql` | 04.3 | `cyber_sentinel` schema, app role, tables, views |
| 2 | `db_partitioning_retention.sql` | 04.3 | partitions, retention functions, pg_cron jobs |
| 3 | `db_ai_pipeline.sql` | 04.3 | `cyber_sentinel_ai` schema, scoring, allow-list, work queue, VirusTotal budget, Deep Recon |
| 4 | `db_blocklists.sql` | 04.3 | own blocklists: entries, AI classifications, name patterns, classifier prompt, publish log |
| 5 | `db_ai_config_editor.sql` | 04.5 | AI Config UI role, audit log, guard triggers |

## Schema `cyber_sentinel`

```mermaid
erDiagram
    dns_queries ||--o{ threat_indicators : "analysed as"
    ai_analysis_results ||--o{ threat_indicators : "verdict"
    dic_threat_levels ||--o{ ai_analysis_results : "score"
    dic_indicator_types ||--o{ threat_indicators : "type"
    threat_indicators ||--o{ threat_indicator_details : "per provider"
    dic_source_providers ||--o{ threat_indicator_details : "source"
    threat_data_raw ||--o{ threat_indicator_details : "raw payload"
    dns_queries ||--o{ network_events : "related"
    threat_indicators ||--o{ network_events : "related"
```

Links to and from `dns_queries`, `threat_indicators` and `network_events` are kept by the application: a partitioned table can only be a foreign-key target through its full partition key.

**Tables**

| Object | What it does |
|---|---|
| `dns_queries` | Every DNS answer seen on the network. Partitioned by month. |
| `threat_indicators` | Links a DNS query to its verdict; counts re-scans. Partitioned by month. |
| `ai_analysis_results` | Final verdict: score 1–5, label, summary in English and Polish. |
| `threat_indicator_details` | Which CTI provider contributed to a verdict, with a pointer to its raw response. |
| `threat_data_raw` | Raw JSON responses from VirusTotal, ThreatFox, URLhaus, urlscan.io, Shodan InternetDB and RDAP (JSONB). |
| `network_events` | Reserved for IDS / packet-capture events. Partitioned by month. |
| `partition_maintenance_log` | Every partition added or dropped, including failures. |

**Dictionaries**

| Object | What it does |
|---|---|
| `dic_threat_levels` | The 1–5 scale: wording, recommended action and whether the level counts as malicious. Editable in the AI Config UI. |
| `dic_indicator_types` | Observable types: FQDN, IP, HASH. |
| `dic_source_providers` | CTI providers. |

**Views**

| Object | Used by |
|---|---|
| `v_threat_scale_for_agent` | The threat scale as text, injected into the AI agent prompt. |
| `v_latest_threat_reports` | Latest verdict per DNS query; base for the Grafana views. |
| `v_grafana_*` | Dashboards: malicious stats, daily trends, hourly DNS traffic, threat alerts, threat explorer. |
| `v_pending_analysis` | Previous work queue, still read by the DNS Traffic dashboard. |
| `v_partition_info` | Rows and size per partition. |

## Schema `cyber_sentinel_ai`

```mermaid
erDiagram
    ai_analysis_results ||--|| verdict_audit : "1:1"
    ai_analysis_results ||--o{ verdict_vectors : "embedding"
    ai_analysis_results ||--o{ pihole_block_log : "block attempt"
    ai_analysis_results ||--o{ deep_recon : "second look"
    prompt_templates ||--o{ verdict_audit : "prompt_version"
    recon_prompt_templates ||--o{ deep_recon : "prompt_version"
    blocklist_prompt_templates ||--o{ blocklist_classifications : "prompt_version"
    blocklist_classifications ||--o| blocklist_entries : "fqdn (candidate)"
    pihole_block_log ||--o{ blocklist_entries : "fqdn (malicious)"
    domain_allowlist_staging ||--o{ domain_allowlist : "weekly sync"
```

`ai_analysis_results` belongs to `cyber_sentinel`. The AI schema extends each verdict without changing the CTI tables.

**Pipeline configuration** — edited in the AI Config UI

| Object | What it does |
|---|---|
| `ai_settings` | Every threshold and switch the workflows read: VirusTotal budget and gate, scoring limits, AI deviation, cache, email and Pi-hole thresholds, urlscan.io search, Shodan, Deep Recon (`recon_*`). |
| `prompt_templates` | Versioned system prompt for the AI agent. Exactly one version is active. |
| `recon_prompt_templates` | Versioned system prompt for the Deep Recon analyst. Exactly one version is active. |
| `trusted_infrastructure` | Big providers (by AS owner or domain) whose low-detection noise is ignored and whose score is capped. |
| `domain_allowlist` | Domains never sent for analysis: Tranco top list (weekly) plus manual entries. |
| `domain_allowlist_exclusions` | Platforms where anyone can publish under a subdomain (`github.io`, `ngrok.io`, …). They override Tranco entries. |
| `v_manual_allowlist` | The only way to edit the allow-list from the UI — manual rows only. |
| `blocklist_name_patterns` | Name fragments (`telemetry`, `track`, …) that make a domain a candidate for AI classification. |
| `blocklist_prompt_templates` | Versioned system prompt for the blocklist classifier. Exactly one version is active. |
| `blocklist_entries` | Own blocklists: one row per domain and list (`malicious`, `tracking`, `telemetry`) with status `candidate` / `approved` / `rejected`, source, expiry and who reviewed it. AI and the malicious sync add rows; the UI approves, rejects and adds manual ones. |

**Pipeline data** — written by n8n

| Object | What it does |
|---|---|
| `v_pending_observables` | Work queue: new domain + IP pairs, without private IPs, allow-listed domains and pairs analysed in the last `cache_ttl_days`. |
| `vt_lookup_log` | One row per VirusTotal call (kept 3 days). Counts the daily and per-minute budget and stops overlapping runs from taking the same pair. |
| `v_vt_budget` | VirusTotal calls used today and in the last minute, calls left, reserve, next reset. |
| `verdict_audit` | Per verdict: rule score, final score, what the agent changed and why, model, prompt version, evidence. Also the "already analysed" cache. |
| `verdict_vectors` | Vector memory of past verdicts (3072-dim Gemini embeddings) searched by the agent's `historical_verdicts` tool. |
| `pihole_block_log` | Every automatic Pi-hole block attempt and its result. |
| `v_pending_recon` | Deep Recon queue: verdicts with score ≥ `recon_min_score` from the last `recon_lookback_days`, without a recent recon of the same domain. Empty while `recon_enabled = 0`. |
| `deep_recon` | One row per re-assessed verdict: domain age and registrar (RDAP), certificate history (crt.sh), page scan (urlscan.io links and facts), and the analyst's result — page type, brand, credential harvesting, confirms / contradicts, proposed score and reason (`score_changed` when it differs from the verdict). |
| `v_blocklist_ai_queue` | Domains waiting for blocklist classification: pattern match, enough queries, not classified, not on a list, not manually allow-listed. |
| `blocklist_classifications` | One AI answer per domain: category, vendor, confidence, breakage risk, reason. A domain here is not sent to the AI again. |
| `v_blocklist_published` | Approved, not expired, not manually allow-listed entries — exactly what goes into the files. |
| `blocklist_publish_log` | One row per publish run: dry run, no change, published (with pull request) or error. |

**Logs**

| Object | What it does |
|---|---|
| `config_change_log` | Who changed which setting, prompt or list, with old and new values. Append-only. |
| `domain_allowlist_sync_log` | Result of each Tranco sync. |

**Functions**

| Object | What it does |
|---|---|
| `compute_threat_score()` | Deterministic 1–5 score from VirusTotal, ThreatFox and URLhaus results, with a step-by-step trace. |
| `is_allowlisted()` | Allow-list check; the most specific rule wins. |
| `setting()` | Reads one value from `ai_settings`; fails on a missing key. |
| `sp_sync_domain_allowlist()` | Applies the weekly Tranco list as a delta; aborts if the list is suspiciously short. |
| `claim_next_observable()` | Returns the next pending observable and logs the call, or nothing when the queue is empty or the VirusTotal budget is used up. |
| `recon_requeue()` | Removes one `deep_recon` row so its verdict gets a new second look; the only way the UI deletes from that table. |
| `blocklist_record_classifications()` | Stores one AI batch and turns telemetry / tracking answers into review candidates. |
| `blocklist_sync_malicious()` | Copies Pi-hole auto-blocks into the malicious list and extends their expiry. |
| `blocklist_render()` | Full content of the three list files. |
| `blocklist_is_protected()` | TRUE when a manual allow-list entry covers the domain. |

## Roles

| Role | Access |
|---|---|
| `postgres` | Superuser; runs the deployment scripts and pg_cron jobs. |
| app role (`postgres_user`) | n8n and `dns_log_processor`: read/write in both schemas, read-only on the audit log. |
| `ai_config_editor` | AI Config UI only: the configuration objects above, nothing from the data tables. Reads `deep_recon`, the recon queue and the VirusTotal budget. Guard triggers stop it from breaking the pipeline (active prompts are read-only, one prompt of each kind always active, malicious levels stay a contiguous top range). |

Passwords come from `vault.yml` and are copied to HashiCorp Vault.

## Partitioning and Retention

`dns_queries`, `threat_indicators` and `network_events` are partitioned by month (`<table>_pYYYYMM`) with a default partition catching anything outside the range. Two pg_cron jobs run on the 1st of each month:

| Job | Time | Action |
|---|---|---|
| `evt_drop_old_partitions` | 02:00 | Drops partitions older than 6 months |
| `evt_add_future_partitions` | 03:00 | Creates partitions for the next 3 months |

```sql
SELECT * FROM cyber_sentinel.v_partition_info;
SELECT * FROM cyber_sentinel.partition_maintenance_log ORDER BY executed_at DESC LIMIT 20;
SELECT * FROM cron.job_run_details ORDER BY start_time DESC LIMIT 20;
```
