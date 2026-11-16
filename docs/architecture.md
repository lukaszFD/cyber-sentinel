# Architecture

Cyber Sentinel runs as one Docker Compose stack on a Raspberry Pi 5 (`arm64`); the same stack runs on `amd64` for testing. Everything is deployed with Ansible. PostgreSQL is the only database.

![Cyber Sentinel — data flow and decision points](assets/cyber_sentinel_flow.svg){ width="900" }

## 1. DNS Capture

```text
client → pihole → passive_dns → unbound → internet
```

- **Pi-hole** filters ads and known-bad domains and holds the denylist that n8n writes to.
- **passive_dns** (dnsmasq) logs every query and answer.
- **Unbound** resolves recursively, without a third-party resolver.
- **dns_log_processor** turns the log into rows in `dns_queries`.

## 2. Decision Pipeline (n8n)

One workflow, *Automated Domain & IP Reputation Guard*, runs every minute and handles one observable (domain + IP) per run, as long as the VirusTotal budget (500 calls/day, 4/min) allows it.

1. **Load configuration** — all thresholds, the active prompt and the threat scale are read from the database at the start of each run. Nothing is hard-coded in the workflow.
2. **Pick work** — the next observable from `v_pending_observables`, through `claim_next_observable()`, which also enforces the VirusTotal budget. Allow-listed domains (Tranco, manual) and pairs analysed in the last `cache_ttl_days` never get here.
3. **VirusTotal gate** — VirusTotal checks the IP. Below `vt_gate_min_malicious` the observable is closed as clean without spending further API calls or AI tokens.
4. **Enrich** — Shodan InternetDB (every IP: open ports, software, CVEs, hostnames). Above the gate also ThreatFox (IP), URLhaus (domain) and earlier urlscan.io scans of the domain's page.
5. **Rule score** — `compute_threat_score()` in PostgreSQL returns a 1–5 score from fixed, auditable rules.
6. **AI agent** — a Gemini agent reviews the evidence and the rule score. It has one tool, `historical_verdicts`: a pgvector search over earlier verdicts. It can move the score by at most `ai_max_deviation` points and must answer in a fixed JSON schema (score, label, rationale in English and Polish).
7. **Persist** — raw CTI payloads (JSONB), the verdict and an audit record of what the agent changed and why. Successful verdicts are embedded and stored back into vector memory.
8. **Act** — an email for scores ≥ `email_min_score`; an automatic Pi-hole denylist entry when VirusTotal detections reach `pihole_block_min_vt_malicious` and the IP is not trusted infrastructure. Every block attempt is logged.

A second workflow, *Deep Recon*, runs hourly and re-assesses verdicts scored ≥ `recon_min_score` with context the main workflow does not collect: domain registration (RDAP), certificate history (crt.sh) and the web page, which urlscan.io loads from its own infrastructure. An AI analyst without tools says whether this confirms the verdict and may propose a score within `recon_max_deviation`. Verdicts are not changed automatically: the result is stored in `deep_recon` and e-mailed when the proposed score differs.

Two daily workflows build own Pi-hole blocklists: *Blocklist Candidates* lets Gemini classify domains whose names look like telemetry or tracking, and *Blocklist Publish* turns approved entries plus the Pi-hole auto-blocks into list files in the public repository sentinel-blocklists, through one pull request that is merged by hand.

## 3. AI Configuration

The pipeline's behaviour lives in the `cyber_sentinel_ai` schema and is changed only through the **AI Config** web UI (`ai-config-ui`):

- settings — thresholds and switches used in the steps above,
- prompts — versioned, with diff; exactly one version is active,
- trusted infrastructure, manual allow-list and exclusions,
- threat level wording,
- simulator — runs live lookups and shows the score without touching the n8n queue,
- Deep Recon — results, re-queue and the versioned recon prompt,
- own blocklists — review queue, list contents, name patterns, the versioned classifier prompt and the publish log,
- VirusTotal calls used and left today.

The UI connects with its own least-privilege role; every change is written to `config_change_log`. Details: [AI Config UI integration](https://github.com/lukaszFD/cyber-sentinel/blob/main/config/ai_config_ui/INTEGRATION.md).

## 4. Platform

| Area | Components |
|------|------------|
| Secrets | HashiCorp Vault — API keys and credentials are read by n8n at runtime; nothing secret in the repo or the workflow |
| Data | PostgreSQL 16 + pgvector; high-volume tables partitioned with automatic retention ([Database](database.md)) |
| Access | Nginx with TLS in front of every web UI, UFW, Fail2Ban |
| Monitoring | Prometheus, Node Exporter — host metrics for the planned health agent |
| Operations | Portainer; images pinned by digest in `group_vars/all/images.yml` |