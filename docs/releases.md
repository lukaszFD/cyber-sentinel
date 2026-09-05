# Project Releases

All official versions of the [**Cyber Sentinel**](https://github.com/lukaszFD/cyber-sentinel) project are available on [GitHub Releases](https://github.com/lukaszFD/cyber-sentinel/releases).

| Version | Status | Date | Tag |
|---------|--------|------|-----|
| [v1.0.3](#v103) | 🟢 Released | 2026-09-05 | [`v1.0.3`](https://github.com/lukaszFD/cyber-sentinel/releases/tag/v1.0.3) |
| [v1.0.2-rc1](#v102-rc1) | 🟡 Pre-release (RC) | 2026-05-05 | [`v1.0.2-rc1`](https://github.com/lukaszFD/cyber-sentinel/releases/tag/v1.0.2-rc1) |
| [v1.0.1-alpha](#v101-alpha) | 🟢 Released | — | [`v1.0.1`](https://github.com/lukaszFD/cyber-sentinel/tree/v1.0.1) |
| [v1.0.0](#v100) | 🟢 Released | — | [`v1.0.0`](https://github.com/lukaszFD/cyber-sentinel/releases/tag/v1.0.0) |

---

## [v1.0.3](https://github.com/lukaszFD/cyber-sentinel/releases/tag/v1.0.3)

🖥️ **Local AI Inference on Hailo-10H NPU** — Released 5 September 2026 · [Tree at tag](https://github.com/lukaszFD/cyber-sentinel/tree/v1.0.3) · [Compare to main](https://github.com/lukaszFD/cyber-sentinel/compare/v1.0.3...main)

Adds on-device generative AI inference to Cyber Sentinel via the Hailo-10H AI accelerator, running natively on the Raspberry Pi 5 host. This release fully automates deployment and lifecycle of the inference service and its web interface, integrated with the existing [Vault](ansible-06-vault.md), [firewall](ansible-02-security.md), and [reverse-proxy](ansible-05-proxy.md) layers. It also concludes an evaluation of on-device model suitability for the production [AI Workflow](n8n.md) — see [Findings](#model-evaluation-findings) below.

### Highlights

- **Native systemd service, not a container** — `hailo-ollama` (Hailo's own Ollama-compatible API server, built on HailoRT) runs directly on the host rather than in Docker, matching Hailo's own deployment guidance and the device's PCIe access model.
- **Three models provisioned and verified** — `deepseek_r1_distill_qwen:1.5b`, `qwen2.5-coder:1.5b`, `llama3.2:3b`, confirmed against the live device rather than assumed from Hailo's published catalog (which didn't fully match what's actually installed).
- **Open WebUI with zero-touch admin provisioning** — a new containerized chat interface auto-creates its admin account from [Vault](ansible-06-vault.md)-managed secrets on first start, no manual signup step.
- **Full network integration** — reachable through the existing [Nginx reverse proxy](ansible-05-proxy.md) at `open-webui.prod`; the host firewall now scopes `hailo-ollama`'s port to the internal Docker network only.
- **Environment isolation by inventory group** — every Hailo-related service, firewall rule, and compose file is scoped to the `rpi5-prod` group, so none of it is ever scheduled on the Dev environment (Dell Optiplex 7050) used for the upcoming Postgres migration work.
- **Local CPU-Ollama path abandoned** — the original `04_5_deploy_AI.yml` CPU-only path is retired in favor of Hailo-10H as the sole local-inference investment going forward. See [Future Roadmap](future-roadmap.md#2-local-llm-integration-cpu-ollama-abandoned).

---

### 🖥️ Hailo-10H Native Inference Service

- `hailo-ollama` runs as a systemd unit (`hailo-ollama.service`), staged, enabled, and started by the new [Ansible playbook 04.7](ansible-04-hailo.md).
- The playbook verifies the NPU device is actually in use inside the running service (not silently idling or falling back), rather than only checking that the process is alive.
- Models are pulled through the service's own REST API (`/api/pull`), not `docker exec` — there is no container to exec into.
- Device access: `/dev/hailo0` is passed through directly; the PCIe kernel driver (`hailo1x`) and firmware installation remain a manual prerequisite, not yet captured in this repo's IaC — playbook 04.7 verifies but does not install them.
- Confirmed operating port is **8000**, not Ollama's conventional 11434 — an earlier design assumption corrected during this release. `hailo-ollama`'s API paths (`/api/chat`, `/api/pull`, `/hailo/v1/list`) also differ from a stock Ollama's, though `/api/tags` is supported for compatibility.

### 💬 Open WebUI

- Deployed via a dedicated compose addon file (`docker-compose-hailo.yml`), merged into the main stack only on `rpi5-prod` via a second `-f` flag on `docker compose up` — not a Jinja2 conditional inside the shared compose file, which proved fragile during development (whitespace handling around block tags silently corrupted rendered YAML indentation).
- `WEBUI_ADMIN_EMAIL` / `WEBUI_ADMIN_PASSWORD` / `WEBUI_ADMIN_NAME` environment variables trigger automatic first-run admin account creation and disable further self-signup — no REST API call needed, unlike the [n8n](n8n.md) and Portainer owner-setup flows.
- Connects to `hailo-ollama` via the Docker bridge network's gateway address, not `host.docker.internal` — the latter resolves to the *default* bridge's gateway on Linux and is unreachable from containers on a custom-IPAM network like this stack's `internal_network`.

### 🔐 Vault — New Secrets

Four new secrets are now provisioned through the existing [unified Vault lifecycle playbook](ansible-06-vault.md):

- `vault_webui_secret_key` — open-webui's session-signing key (stored under `cyber-sentinel/api-keys/open-webui/secret-key`); without a fixed value, open-webui generates a new one on every container restart, invalidating all active sessions.
- `webui_admin_email` / `vault_webui_admin_password` — the auto-provisioned admin account (stored under `cyber-sentinel/credentials/open_webui`).
- `vault_open_webui_cert` / `vault_open_webui_key` — TLS certificate pair for the Nginx vhost.
- Playbook 01's pre-flight validation (`[01.0.1]`) was extended to fail fast if any of these are missing from `group_vars`, before `.env` is rendered — consistent with the fail-fast pattern already used for the database and Grafana secrets.

### 🌐 Network & Firewall

- New UFW rule opens `8000/tcp` to `10.10.10.0/24` only (the internal Docker network) — not to the LAN or the internet. Without it, `open-webui` could not reach `hailo-ollama` even though both were running correctly; the connection hung until the rule was added.
- New Nginx vhost at `open-webui.prod`, using a dedicated `hostname` field distinct from the Vault-lookup-safe `open_webui` service name — Nginx `server_name` / TLS SNI cannot contain underscores, and the two naming needs (a valid Ansible variable segment vs. a valid DNS hostname) conflict for this specific service name.

### 📊 Model Evaluation Findings

Manual testing against structured, multi-source threat-scoring prompts — the same shape of data (VirusTotal + ThreatFox + URLHaus) the production [n8n AI Agent](n8n.md) consumes — surfaced consistent reliability issues across all four available on-device models at this 1.5–3B parameter scale:

- Factual confabulation delivered with high confidence (an incorrect TLD attribution, a fabricated RFC citation, a malware family name silently substituted with an invented one).
- Direct contradiction of provided input data in one case — asserting ThreatFox showed no active threat when the input explicitly stated otherwise.
- Internally inconsistent structured output — e.g. a `threat_score` and `is_malicious` pairing that violates the scoring policy stated in the very same prompt.
- A generation timeout on the largest available model when given a full-length, production-style prompt.

**Conclusion:** Gemini remains the primary reasoning engine for the [n8n AI Agent pipeline](n8n.md). Local Hailo-10H inference is not currently wired into n8n and is not recommended for unattended multi-source scoring decisions at this model scale. Better-fit candidates identified for future work: single-source tool-output summarization (e.g. Kali command output that was already executed and captured, not model-selected) and lower-stakes triage without cross-field logical constraints. Full detail in the [Future Roadmap](future-roadmap.md#2b-hailo-10h-npu-inference).

---

### 🐛 Known Issues / Pending

- Hailo-10H models are **not yet wired into the n8n AI Agent pipeline** — reachable only through Open WebUI for manual testing. See [Model Evaluation Findings](#model-evaluation-findings) above for why this isn't a near-term priority as originally scoped.
- `hailo-ollama` binary installation (HailoRT + `hailo1x` driver + the binary itself) predates this repo's IaC and is not yet automated — playbook 04.7 manages the service once installed, but does not bootstrap a clean host.
- Embedding model host for the future RAG pipeline (Section 8 of the [Future Roadmap](future-roadmap.md)) is now an open question — the original plan assumed CPU-Ollama, which this release abandons; whether `nomic-embed-text` is available on Hailo-10H is unconfirmed.

---

### 📂 Deployment Command

```bash
# Master playbook deploys the entire stack, including the new Hailo-10H inference service
ansible-playbook -i hosts.ini ansible/00_main.yml \
  --vault-password-file ansible/.vault_pass
```

Hardware and secrets prerequisites are listed in full on the [GitHub release page](https://github.com/lukaszFD/cyber-sentinel/releases/tag/v1.0.3).

---

## [v1.0.2-rc1](https://github.com/lukaszFD/cyber-sentinel/releases/tag/v1.0.2-rc1)

🛡️ **Detection-First AI Scoring & Database Hardening** — Released 5 May 2026 · [Tree at tag](https://github.com/lukaszFD/cyber-sentinel/tree/v1.0.2-rc1) · [Compare to main](https://github.com/lukaszFD/cyber-sentinel/compare/v1.0.2-rc1...main)

!!! warning "Release Candidate"
This is a **pre-release**. The architecture and APIs are now frozen — pending real-world validation, this RC will be promoted to the final v1.0.2. Test on staging before deploying to production. Issues found during RC testing should be opened with the `rc-feedback` label on the [issue tracker](https://github.com/lukaszFD/cyber-sentinel/issues).

The largest functional overhaul since the project began. The release refines how Cyber Sentinel reasons about threats, hardens the data layer for long-term operation, and modernizes operator-facing components. Changes touch the [AI agent](n8n.md), the [MySQL schema](db.md), the [Vault provisioning workflow](ansible-06-vault.md), and the [alerting pipeline](n8n.md).

### Highlights

- **New 1–5 threat scale** — replaces the previous 1–10 scale. Score levels are no longer hardcoded in the AI prompt; they are loaded dynamically from the database at every invocation via [`v_threat_scale_for_agent`](db.md), paving the way for a future self-healing AI workflow.
- **URLhaus reweighted as a supporting source** — primary scoring now relies on [VirusTotal](https://www.virustotal.com/) and [ThreatFox](https://threatfox.abuse.ch/). [URLhaus](https://urlhaus.abuse.ch/) may add at most `+1` to the score, and only when a primary source has already flagged the indicator. Eliminates false positives on legitimate platforms ([GitHub](https://github.com/), Bitbucket, Pastebin, etc.).
- **Partitioned core tables** — [`dns_queries`, `network_events`, `threat_indicators`](db.md) now use [monthly RANGE partitioning](https://dev.mysql.com/doc/refman/8.0/en/partitioning-range.html) with automated 6-month retention.
- **Color-graded alert emails** — score 1–2 renders as green INFO, score 3 as amber REVIEW, score 4–5 as red ALERT. No more red exclamation marks for clean traffic.
- **Unified Vault lifecycle playbook** — initialization, unsealing, and provisioning are now handled by [a single idempotent playbook](ansible-06-vault.md).

---

### 🧠 AI Agent — Detection-First Scoring (v3.0)

- Threat scale reduced from 1–10 to **1–5** for clearer operator action mapping:

  | Score | Action |
      |-------|--------|
  | 1 | `Allow` |
  | 2 | `Monitor` |
  | 3 | `Review` |
  | 4 | `Block` |
  | 5 | `Block + Alert` |

- Scale is now loaded from [`dic_threat_levels`](db.md) at runtime via the new [`v_threat_scale_for_agent`](db.md) view. Future workflows can update the scale without touching the prompt.
- Source weighting:
    - **Primary:** [VirusTotal](https://www.virustotal.com/), [ThreatFox](https://threatfox.abuse.ch/)
    - **Supporting:** [URLhaus](https://urlhaus.abuse.ch/) (max `+1` modifier, never a sole driver)
- **Big Player guard** hardened: trusted infrastructure ([AWS](https://aws.amazon.com/), [Cloudflare](https://www.cloudflare.com/), Google, Microsoft) is capped at score `2` unless ThreatFox confirms a specific malware family.
- New `scoring_rationale` field in agent output — explains why the score was assigned, intended as audit input for the future self-healing meta-agent.

---

### 🗄️ Database — Schema v3.0

See the dedicated [Database Schema page](db.md) for the full v3.0 reference.

- **Threat scale migration:** [`dic_threat_levels`](db.md) rewritten with a 1–5 scale and `is_malicious_flag` driving downstream logic. Historical scores in `ai_analysis_results` are preserved via deterministic remapping (see [Migration Notes](#migration-notes-v101-v102-rc1)).
- **[Composite primary keys](db.md)** on partitioned tables ([`dns_queries`](db.md), [`network_events`](db.md), [`threat_indicators`](db.md)) — required by [MySQL](https://dev.mysql.com/doc/refman/8.0/en/partitioning-limitations-partitioning-keys-unique-keys.html) when partitioning by a non-PK column.
- **`threat_indicators` UNIQUE KEY extended** to include `last_scan`, allowing the same `(dns_query, analysis_result)` pair to be scanned multiple times over its lifetime.
- **Foreign keys removed** from partitioned tables ([MySQL constraint](https://dev.mysql.com/doc/refman/8.0/en/partitioning-limitations.html#partitioning-limitations-foreign-keys)). Relational integrity is now enforced at the [n8n workflow](n8n.md) layer.
- **Grafana views updated** — [`v_grafana_malicious_stats`](db.md), [`v_grafana_daily_trends`](db.md), [`v_grafana_threat_explorer`](db.md), and [`v_grafana_threat_alerts`](db.md) now use `is_malicious_flag` instead of a hardcoded `score > 5` threshold.

#### Partitioning & Retention

- Monthly partitions for `dns_queries`, `network_events`, `threat_indicators`. Full DDL and procedures documented on the [Database Schema page](db.md) and applied by [Ansible playbook 04.6](ansible-04-db.md).
- Automated maintenance via the [MySQL Event Scheduler](https://dev.mysql.com/doc/refman/8.0/en/events-overview.html):
    - [`evt_drop_old_partitions`](db.md) — runs monthly at 02:00, drops partitions older than 6 months.
    - [`evt_add_future_partitions`](db.md) — runs monthly at 03:00, ensures 3 months of forward partitions exist.
- All maintenance actions logged to [`partition_maintenance_log`](db.md) (success and failure paths).
- [Stored procedures](db.md): [`sp_drop_old_partitions`](db.md) iterates [`INFORMATION_SCHEMA.PARTITIONS`](https://dev.mysql.com/doc/refman/8.0/en/information-schema-partitions-table.html) to drop every monthly partition past the cutoff in a single run; [`sp_add_future_partitions`](db.md) reorganizes `p_future` to materialize the next 3 monthly partitions, skipping months that already exist.

---

### 📧 Alert Email — Severity-Aware Rendering

Email styling now adapts to the severity score, surfaced from [`dic_threat_levels.action_recommended`](db.md):

| Score | Accent | Header | Badge |
|-------|--------|--------|-------|
| 1–2 | 🟢 Green | `✅ INFO` | `Clean / Monitor` |
| 3 | 🟡 Amber | `⚠️ REVIEW` | `Suspicious` |
| 4–5 | 🔴 Red | `🚨 ALERT` | `Malicious / Critical` |

- Severity label is displayed beneath the score for instant context.
- Accent colour is consistently applied across the top border, header background, score number, analysis side bar, and action button — no more red ALARM banners for clean traffic.

---

### 🔐 Vault — Unified Lifecycle Playbook

The previously separate `06_1_initialize_vault.yml` and `06_2_provision_vault.yml` have been merged into a single [`06_initialize_provision_vault.yml`](https://github.com/lukaszFD/cyber-sentinel/blob/main/ansible/06_initialize_provision_vault.yml). Full reference on the [Vault & Secrets page](ansible-06-vault.md).

- **[Pre-flight validation](ansible-06-vault.md)** — playbook fails fast if any required variable (API keys, DB passwords, certs) is missing, before any secret is written.
- **Idempotent dual-mode operation:**
    - **First run** → initializes Vault, captures fresh credentials, [auto-unseals](ansible-06-vault.md), provisions [all secrets](ansible-06-vault.md).
    - **Re-run** → detects existing Vault, unseals from [`group_vars`](ansible-01-secrets.md) if sealed, updates secrets in place.
- **[Secure key handling](ansible-06-vault.md)** — [Unseal Keys](https://developer.hashicorp.com/vault/docs/concepts/seal) are never written to Vault itself (chicken-and-egg problem). They are displayed exactly once at first init and must be saved by the operator to an external secure location.
- **Final-message logic:** first init shows root token + unseal keys with a save-now warning; re-runs only confirm success without exposing any sensitive material.

---

### ⚠️ Migration Notes (v1.0.1 → v1.0.2-rc1)

This release contains **breaking changes** to the database schema. Read this section before upgrading an existing deployment.

#### Threat Scale: 1–10 → 1–5

If your [`cyber_intelligence`](db.md) database already contains historical analysis data, the score migration is required. Score remapping:

| Old (1–10) | New (1–5) | Action |
|------------|-----------|--------|
| 1, 2 | 1 | `Allow` |
| 3, 4 | 2 | `Monitor` |
| 5 | 3 | `Review` |
| 6, 7 | 4 | `Block` |
| 8, 9, 10 | 5 | `Block + Alert` |

- Use [`migration_threat_scale_v3_fixed.sql`](https://github.com/lukaszFD/cyber-sentinel/blob/main/config/mysql/migration_threat_scale_v3_fixed.sql) for in-place migration of existing data.
- For fresh deployments, use [`db_deployment.sql`](https://github.com/lukaszFD/cyber-sentinel/blob/main/config/mysql/db_deployment.sql) directly — it includes the new scale.

!!! danger "Backup first"
**Always back up your database before running either script.** The migration includes irreversible schema changes (composite PKs, dropped FKs).

#### Schema Changes Requiring Rebuild

The following changes cannot be applied with a simple [`ALTER`](https://dev.mysql.com/doc/refman/8.0/en/alter-table.html) on a populated table:

- [Composite primary keys](db.md) on `dns_queries`, `network_events`, `threat_indicators`
- [Removal of foreign keys](https://dev.mysql.com/doc/refman/8.0/en/partitioning-limitations.html#partitioning-limitations-foreign-keys) from partitioned tables
- Extension of [`threat_indicators`](db.md) UNIQUE KEY with `last_scan`

For environments with existing data, the recommended path is: **dump → drop database → recreate with the v3.0 deployment script → reload data**. For fresh deployments no action is needed.

#### Deployment Order

```bash
# 1. Database
mysql -u root -p < db_deployment.sql
mysql -u root -p < db_partitioning_retention.sql

# 2. Vault (idempotent — safe to re-run)
ansible-playbook -i hosts.ini ansible/06_initialize_provision_vault.yml \
  --vault-password-file ansible/.vault_pass

# 3. Master playbook (full stack)
ansible-playbook -i hosts.ini ansible/00_main.yml \
  --vault-password-file ansible/.vault_pass
```

The same commands are also documented as Ansible playbooks: [04.3 — DB create](ansible-04-db.md), [04.6 — Partitioning](ansible-04-db.md), and [06 — Vault](ansible-06-vault.md). The recommended path is to use the master [`00_main.yml`](https://github.com/lukaszFD/cyber-sentinel/blob/main/ansible/00_main.yml) which sequences all of them.

#### n8n Workflow Update

The [AI agent](n8n.md) prompt and email template must be updated in [n8n](https://n8n.io/) to match the new schema. **This is delivered separately** — workflow JSON updates will follow shortly after this RC ships (see [Known Issues](#known-issues-pending)).

---

### ✅ What's Frozen for Stable v1.0.2

The following are now considered stable and will not change between this RC and the final release (unless a critical bug is found):

- [Database schema](db.md) (tables, views, partitioning strategy)
- AI agent prompt structure and output JSON schema
- Email template variable contracts
- [Vault playbook](ansible-06-vault.md) variable names and [secret paths](ansible-06-vault.md)

If you find an issue during RC testing, please open a [GitHub issue](https://github.com/lukaszFD/cyber-sentinel/issues/new) tagged `rc-feedback` so it can be addressed before promotion to stable.

---

### 🐛 Known Issues / Pending

- [n8n workflow](n8n.md) JSON has not yet been republished — coming in a follow-up commit.
- Self-healing AI meta-agent (auto-tuning of [`dic_threat_levels`](db.md)) is scoped for v1.1.0 — see [Future Roadmap](future-roadmap.md).
- No automated test suite for the SQL migration path — manual validation only.

---

### 📂 Deployment Command

```bash
# Master playbook deploys the entire stack including the unified Vault module
ansible-playbook -i hosts.ini ansible/00_main.yml \
  --vault-password-file ansible/.vault_pass
```

For a fresh deploy, run the database scripts first as shown in the [Migration Notes](#migration-notes-v101-v102-rc1) section above.

---

## [v1.0.1-alpha](https://github.com/lukaszFD/cyber-sentinel/tree/v1.0.1)

- **Unified Vault Orchestration:** Merged separate [HashiCorp Vault](https://developer.hashicorp.com/vault) playbooks into one master configuration for simplified secret management.
- **Enhanced Grafana Dashboards:** Updated dashboard configurations for better visibility into CTI metrics and AI-driven threat verdicts.
- **Streamlined [Ansible](https://docs.ansible.com/ansible/latest/) Logic:** Refactored roles to ensure a faster and more reliable deployment of the entire stack.
- **Initial Automated Deployment:** Transitioned to a full Infrastructure as Code (IaC) workflow using Ansible.

---

## [v1.0.0](https://github.com/lukaszFD/cyber-sentinel/releases/tag/v1.0.0)

- First stable release of the project.
- Implementation of core scanning mechanisms.
- Initial integration with AI workflows.

---
