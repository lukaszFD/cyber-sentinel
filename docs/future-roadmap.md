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

1. **Health agent** — daily check of the pipeline: queue depth, failed AI analyses, pg_cron jobs, aborted Tranco syncs, and host state from Prometheus (see section 6). API usage and 429s come from `api_call_log`, and stopped workflows from Failure Guard (both in [v2.3.0](releases.md#v230)). Sends a short daily report.
2. **Verdict review and auto-unblock** — weekly re-scan of verdicts scored 3–5 and of everything blocked in Pi-hole. Blocks get an expiry date; a domain that stays clean is unblocked, one that became malicious is raised.
3. **Analyst feedback** — mark a verdict as false positive or true positive in the AI Config UI (or with the `cs.fp` tag in Engram). Labelled verdicts go into vector memory as confirmed examples.
4. **Prompt and threshold tuning agent** — analyses `verdict_audit` and feedback: where the AI deviates from the rules and why, which rules produce false positives, how often the agent fails. Creates a new prompt version or setting change as an **inactive draft**, replays it against stored evidence from recent verdicts (no CTI API calls) and shows the difference. Activation stays manual in the AI Config UI.
5. **Retro-hunting** — daily download of new ThreatFox IOCs, searched backwards in `dns_queries`: which device contacted a domain before it was known to be malicious. Needs no VirusTotal calls; can run in parallel with the items above.
6. **Agent-chosen enrichment** — CTI sources become tools the agent picks within a budget instead of a fixed sequence. Already in place: urlscan.io search and Shodan InternetDB in the main workflow; RDAP, crt.sh and urlscan.io page scans in Deep Recon. Next: Shodan host details and pivots (needs a paid Shodan membership) as a Deep Recon source.
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

## 7. Own Blocklists — Follow-ups

The first version shipped in [v2.2.0](releases.md#v220): name patterns, AI classification, review in the AI Config UI and a daily pull request to [sentinel-blocklists](https://github.com/lukaszFD/sentinel-blocklists) — see [n8n Workflows](n8n.md#own-blocklists). Still open:

- **Query-interval pre-filter** — regular query intervals per device as a second candidate signal next to name patterns. Real client IPs are in `dns_queries` since [v2.4.0](releases.md#v240).
- **Category from the main workflow** — optional: the main workflow's AI returns the same category (telemetry / tracking) for domains it already analyses and adds hits to the review queue.

## 8. SDLC and Testing

Most building blocks are already in place: dev → prod environments (new versions go to `dev_vm` first), images pinned by digest, Ansible + Docker Compose with n8n workflows exported to the repo, CodeQL, Trivy, OpenSSF Scorecard, branch rulesets, Prometheus/Grafana and the MkDocs site. What is missing is one gate that ties them together: **PR → CI → release → deploy → verification**.

Planned order (the first three give the most value):

1. Branch protection and all changes through pull requests
2. pre-commit hooks
3. CI with an SQL migration test
4. Renovate
5. release-please
6. Smoke tests after deploy

### Planning and design

- GitHub Issues and a Project board, with issue templates: feature, bug, security.
- `docs/adr/` — short architecture decision records (e.g. dropping Liquibase, a queue table instead of webhooks).
- A half-page STRIDE threat model for larger features.

### Development

- Feature branch → PR → `main`, also when working solo. No direct pushes to `main`; green checks required.
- `.pre-commit-config.yaml`: ansible-lint, yamllint, shellcheck, hadolint, gitleaks, sqlfluff.
- Conventional Commits, so the changelog can be generated.
- PR template with a Definition of Done checklist: tested on dev, docs updated, SQL migration, n8n JSON exported.

### CI — `.github/workflows/ci.yml`

- The pre-commit linters run in CI as well.
- SQL migration test: a pgvector container runs all numbered schema files in order.
- AI Config UI: build and unit tests.
- Trivy scan of images and compose files.
- n8n workflow JSON validation: no leaked credentials or instance IDs.
- Actions pinned by SHA.
- Image builds on both amd64 and arm64 (`ubuntu-24.04-arm` runner).

### Dependencies and release

- Renovate for image digests in `group_vars/all/images.yml` and compose; its PRs go through CI.
- SemVer and `CHANGELOG.md` from release-please: a release draft is created automatically and approved manually.
- SBOM (syft) attached to each GitHub Release; optionally signed tags.

### Deploy and operate

- Prod deploys only from a tag, preceded by `ansible-playbook --check --diff`, followed by a smoke test.
- Deploys stay manual from the control machine — no self-hosted runner with access to the home network.
- `SECURITY.md` and an incident runbook in the docs. The health agent (section 2) closes this phase.
- **PostgreSQL backup** — there is none today. A storage failure on the Pi would lose the verdict history and the data vector memory is built from.

### Tests

Unit tests (every PR):

- **DNS log processor** — fixtures with `pihole.log` lines: parsing, filtering, edge cases (IDN, empty lines, truncated log).
- **AI Config UI** — config validation, reads and writes against a mocked database (pytest).
- **Deterministic scoring** — URLhaus +1 modifier, 1–5 thresholds, VirusTotal budget pacing. Needs the logic moved out of n8n Code nodes into JS files tested in Node (vitest); this changes the workflows and needs a separate decision.
- **SQL** — pgTAP: constraints, foreign keys, partitions, functions.

Integration tests (CI, Docker Compose):

- Test stack: PostgreSQL + pgvector, AI Config UI, n8n, Vault in `-dev` mode.
- Migrations and seed data → AI Config UI API tests → rows checked in the database.
- n8n: workflows loaded with `n8n import:workflow`; external APIs (VirusTotal, ThreatFox, urlscan.io, Gemini) replaced by a mock server.
- Scenario: insert a row into the queue table → run the workflow → check the status transitions and the result in `threat_indicators`.

LLM tests (separate, not on PRs):

- Contract test: the Gemini response matches the JSON schema (score, rationale EN/PL).
- Golden set of ~30 domains with an expected score range, run manually or weekly (free tier limits, non-determinism). Doubles as the regression suite for the prompt tuning agent (section 2, item 4).

Smoke / E2E (after each deploy to dev and prod):

- `dig` a test domain → row in `dns_queries` → the domain goes through the whole pipeline.

Rules: no chasing coverage percentages — what matters is parsing, scoring, config validation and migrations. First batch: pytest for the DNS log processor and the migration test in CI.
