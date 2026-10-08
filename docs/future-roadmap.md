# Roadmap

What is planned next. Delivered work is listed in [Releases](releases.md).

## 1. Sentinel Engram

[Sentinel Engram](https://github.com/lukaszFD/sentinel-engram) is the long-term memory of Cyber Sentinel: a separate project that loads AI verdicts, DNS activity and Pi-hole blocklists into a Vertex Synapse CTI graph, with a Neo4j view for visual analysis. It reads Cyber Sentinel's database through a read-only role and an SSH tunnel and never writes to it.

Planned on the Cyber Sentinel side:

- **Ship the export in this repo** — move `db_engram_export.sql` (role `engram_reader`, schema `engram_export`) and the `engram-tunnel` user into Cyber Sentinel's playbooks, so a dev deploy no longer removes them.
- **Graph context for the AI agent** — n8n queries Synapse (user `n8n-agent`: read, `ai.*` tags only) to give the agent history the database does not have: blocklist membership, related domains on the same IP, first-seen dates.
- **Anomaly agent** — a scheduled n8n agent compares daily device behaviour in the graph against a baseline and tags findings with `ai.*`. Device data must be anonymised before it leaves Cyber Sentinel.

## 2. Agentic Development

Goal: a system that checks itself, corrects its own mistakes and improves its own configuration, with a human approving changes instead of doing them. Each item runs as a separate n8n workflow; workflows hand work to each other through a status-driven queue table. Order below is the planned order.

1. **Health agent** — daily check of the pipeline: queue depth, VirusTotal 429 errors, failed AI analyses, pg_cron jobs, aborted Tranco syncs, and host state from Prometheus (see section 6). Sends a short daily report and alerts when the pipeline stops.
2. **Verdict review and auto-unblock** — weekly re-scan of verdicts scored 3–5 and of everything blocked in Pi-hole. Blocks get an expiry date; a domain that stays clean is unblocked, one that became malicious is raised.
3. **Analyst feedback** — mark a verdict as false positive or true positive in the AI Config UI (or with the `cs.fp` tag in Engram). Labelled verdicts go into vector memory as confirmed examples.
4. **Prompt and threshold tuning agent** — analyses `verdict_audit` and feedback: where the AI deviates from the rules and why, which rules produce false positives, how often the agent fails. Creates a new prompt version or setting change as an **inactive draft**, replays it against stored evidence from recent verdicts (no CTI API calls) and shows the difference. Activation stays manual in the AI Config UI.
5. **Retro-hunting** — daily download of new ThreatFox IOCs, searched backwards in `dns_queries`: which device contacted a domain before it was known to be malicious. Needs no VirusTotal calls; can run in parallel with the items above.
6. **Agent-chosen enrichment** — CTI sources become tools the agent picks within a budget instead of a fixed sequence. New sources: domain age (RDAP/WHOIS), certificate transparency (crt.sh), urlscan.io (already in Vault, unused).
7. **Engram tools** — the Synapse graph as an agent tool and the device anomaly agent (see section 1). Optional at run time: the Engram host is up only a few hours a day, so anomaly analysis runs in batches.
8. **Agent-decided actions** — blocking and alerting decided by the agent instead of fixed thresholds, with hard limits enforced by the workflow: never block trusted infrastructure, a daily block limit, every block with an expiry. Depends on item 2, so wrong decisions undo themselves.

Constraints for all items: VirusTotal free tier (500 requests/day), Gemini free tier limits, Raspberry Pi 5 with 8 GB RAM.

## 3. Device Attribution

- `user_devices` table mapping internal IPs to devices and owners.
- Per-device reports and alerts from n8n.
- Identity signals (Vault audit log, SSH auth log) as a later step.

## 4. Hardening

- TOTP for web UIs (n8n, Portainer, AI Config UI).
- Nginx rate limiting and security headers (HSTS, X-Frame-Options, X-Content-Type-Options).
- GeoIP blocking and port knocking for SSH.

## 5. File Integrity Monitoring

- Hashes of critical files (`sshd_config`, playbooks, compose) stored in the database.
- Scheduled comparison; an AI agent decides whether a change looks like administration or compromise and alerts.

## 6. Monitoring

- Prometheus and node_exporter become the data source for the health agent instead of something to look at: disk usage, Pi temperature, SSD SMART (playbook 07), read by n8n through the Prometheus HTTP API.
- Grafana will be removed. Its job — showing what happens in the pipeline — is taken over by the n8n agents: the health agent's daily report and alerts, plus operational views in the AI Config UI.