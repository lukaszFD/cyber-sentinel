# Releases

All versions are on [GitHub Releases](https://github.com/lukaszFD/cyber-sentinel/releases).

| Version | Type | Date | Focus |
|---|---|---|---|
| [v2.0.0](#v200) | Stable | October 2026 | PostgreSQL as the only database, AI agent pipeline, AI Config UI |
| [v1.0.3](#v103) | Release | 5 September 2026 | Local inference on Hailo-10H (removed in v2.0.0) |
| [v1.0.2-rc1](#v102-rc1) | Release candidate | 5 May 2026 | 1–5 threat scale, partitioning, unified Vault playbook |
| [v1.0.1](#v101) | Release | — | Ansible deployment |
| [v1.0.0](#v100) | Release | — | First version |

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