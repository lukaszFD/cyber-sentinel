# Future Roadmap: Project Development

This document outlines the planned technical improvements and new features for the **Cyber Sentinel** project. Items are tracked against actual releases — see [Project Releases](releases.md) for the full changelog.

## Status Overview

| Area | Item | Status | Delivered in | Notes |
|------|------|:------:|:------------:|-------|
| **1. Database** | Transition to PostgreSQL | 🔵 Planned | — | Reconsidered — see notes below |
| **1. Database** | Monthly partitioning + retention policy | 🟢 Delivered | v1.0.2-rc1 | MySQL RANGE partitioning, 6-month auto-retention via Event Scheduler — see [Database Schema](db.md) |
| **1. Database** | User-Device correlation (`user_devices`) | 🔵 Planned | — | — |
| **1. Database** | Integrity Hash Storage (FIM) | 🔵 Planned | — | Tied to Section 4 |
| **1. Database** | Schema versioning (Liquibase) | 🔵 Planned | — | Currently versioned via SQL files in `config/mysql/` |
| **2. Local LLM** | Ollama deployment with CPU/RAM limits | 🟢 Delivered | v1.0.1-alpha | See `04_5_ai_suite.yml` |
| **2. Local LLM** | Llama 3.2 3b for security analysis | 🔵 Planned | — | Model deployed; analysis workflow pending |
| **3. Hardening** | MFA / Hardware keys (YubiKey) | 🔵 Planned | — | — |
| **3. Hardening** | TOTP for web interfaces | 🔵 Planned | — | — |
| **3. Hardening** | Port Knocking | 🔵 Planned | — | — |
| **3. Hardening** | GeoIP Blocking | 🔵 Planned | — | — |
| **3. Hardening** | Nginx rate limiting + security headers | 🔵 Planned | — | — |
| **4. FIM** | Automated integrity checks | 🔵 Planned | — | — |
| **4. FIM** | AI agent triage of file changes | 🔵 Planned | — | — |
| **5. Grafana** | Threat Attribution Dashboard | 🟡 Partial | v1.0.2-rc1 | Backing views ready (`v_grafana_malicious_stats`, `v_grafana_threat_explorer`, `v_grafana_threat_alerts`); per-user attribution still pending |
| **5. Grafana** | Per-User Analytics | 🔵 Planned | — | Depends on `user_devices` mapping (Section 1) |
| **5. Grafana** | Real-Time Alerting | 🟡 Partial | v1.0.2-rc1 | Severity-graded alert email shipped via [n8n](n8n.md); native Grafana alerts not yet wired |
| **6. AI Workflow** | Detection-first scoring (1–5 scale) | 🟢 Delivered | v1.0.2-rc1 | Dynamic threat scale loaded from `dic_threat_levels` at runtime |
| **6. AI Workflow** | Long-Term Memory (MongoDB/MySQL) | 🟡 Partial | v1.0.0 | Dual storage already in place — MongoDB for raw payloads, MySQL for verdicts. Trend analysis on top still pending |
| **6. AI Workflow** | Self-healing meta-agent | 🔵 Planned | — | Scoped for v1.1.0 — see [Known Issues in v1.0.2-rc1](releases.md) |
| **6. AI Workflow** | Autonomous network reconnaissance | 🔵 Planned | — | — |
| **6. AI Workflow** | CVE correlation against discovered assets | 🔵 Planned | — | — |
| **7. IaC & Backup** | Ansible-driven stack deployment | 🟢 Delivered | v1.0.1-alpha | Full IaC pipeline (`00_main.yml`) covers OS hardening, Docker stack, Vault, DB |
| **7. IaC & Backup** | Unified Vault lifecycle playbook | 🟢 Delivered | v1.0.2-rc1 | Single idempotent `06_initialize_provision_vault.yml` |
| **7. IaC & Backup** | Terraform for Proxmox VM provisioning | 🔵 Planned | — | — |
| **7. IaC & Backup** | Off-site backup to external SSD | 🔵 Planned | — | — |
| **7. IaC & Backup** | Retention policy (6 months) | 🟢 Delivered | v1.0.2-rc1 | Implemented at the database layer for `dns_queries`, `network_events`, `threat_indicators` |

Legend: 🟢 Delivered · 🟡 Partial · 🔵 Planned

---

## 1. Database Infrastructure Migration & Analytics

* **Transition to PostgreSQL** 🔵 — under reconsideration. The original motivation was advanced security analytics; with monthly partitioning and the new analytical views in MySQL 8.0, the case for migration is weaker. Decision deferred until per-user analytics (below) lands and we can profile real query patterns.
* 🟢 **Monthly partitioning + 6-month retention policy** — *delivered in v1.0.2-rc1.* `dns_queries`, `network_events`, and `threat_indicators` use RANGE partitioning by month with automated drop/add via the MySQL Event Scheduler. Maintenance is logged to `partition_maintenance_log`. Documented on the [Database Schema](db.md) page.
* **User-Device Correlation Logic** 🔵
  * Implement a mapping schema (`user_devices`) to link internal IP addresses to specific users.
  * Develop advanced SQL queries to join DNS logs with threat intelligence, attributed to specific network participants.
* **Integrity Hash Storage** 🔵 — store master hashes of critical system and configuration files for the File Integrity Monitoring (FIM) system.
* **Database Versioning** 🔵 — manage schema changes via Liquibase for consistent deployments across Proxmox and RPi 5. Currently the schema is versioned through plain SQL files in `config/mysql/`.

---

## 2. Local LLM Integration (Ollama)

* 🟢 **Resource-Aware Ansible Playbook** — *delivered in v1.0.1-alpha.* `04_5_ai_suite.yml` deploys Ollama with strict hardware limits suitable for Raspberry Pi 5 (CPU pinned to 2 cores, RAM capped at 4 GB).
* **Llama 3.2 3b for security analysis** 🔵 — model is deployed, but the analysis workflow that leverages it for automated vulnerability identification is still pending.

---

## 3. Advanced Security Hardening (IaC driven)

* **Multi-Factor Authentication (MFA/2FA)** 🔵
  * **Hardware Keys**: YubiKey 5 Series integration for Proxmox, Vault, and SSH.
  * **TOTP Support**: 6-digit code generation for web interfaces (Grafana, n8n, Portainer).
* **Network Defense** 🔵
  * **Port Knocking**: stealth SSH access via port-hit sequences.
  * **GeoIP Blocking**: drop traffic from high-risk geographic regions using Ansible-managed firewall rules.
* **Nginx Reverse Proxy Optimization** 🔵
  * **Rate Limiting**: protection against DDoS and brute-force by limiting requests per IP.
  * **Security Headers**: HSTS, X-Frame-Options, X-Content-Type-Options.

---

## 4. File Integrity Monitoring (FIM) & AI Audit

* **Automated Integrity Checks** 🔵 — monitor changes in critical files (e.g. `/etc/ssh/sshd_config`, Ansible playbooks).
* **AI Agent Integration (n8n)** 🔵
  * The AI agent will periodically compare current file hashes with master hashes stored in the database.
  * **Automated Triage**: if a mismatch is detected, the AI agent analyzes the change to determine if it was a legitimate administrative action or a potential compromise.
  * **Alerting**: instant notification via preferred channels if unauthorized modifications are found.

---

## 5. Visual Analytics & Monitoring (Grafana)

* 🟡 **Threat Attribution Dashboard** — *partially delivered in v1.0.2-rc1.* The backing views are in place: `v_grafana_malicious_stats`, `v_grafana_daily_trends`, `v_grafana_dns_hourly_traffic`, `v_grafana_threat_explorer`, and the new `v_grafana_threat_alerts`. They all use `is_malicious_flag` instead of the legacy hardcoded threshold. The Grafana dashboards themselves have been updated to consume them, but per-user attribution panels are blocked on Section 1's `user_devices` mapping.
* **Per-User Analytics** 🔵 — filter security events by device/user. Depends on `user_devices` (Section 1).
* 🟡 **Real-Time Alerting** — *partially delivered in v1.0.2-rc1.* Severity-graded alert email is now shipped through the n8n workflow (green INFO / amber REVIEW / red ALERT). Native Grafana alert rules driven by `is_malicious_flag` are still on the to-do list.

---

## 6. Advanced AI Workflow (n8n)

* 🟢 **Detection-first scoring** — *delivered in v1.0.2-rc1.* The 1–5 threat scale is now loaded dynamically from `dic_threat_levels` via `v_threat_scale_for_agent` at every AI invocation. URLHaus reweighted as a supporting source. See the [n8n Workflow](n8n.md) page for the full prompt and email pipeline.
* 🟡 **Long-Term Memory** — *partially delivered (v1.0.0 / v1.0.2-rc1).* Dual storage is already in production: MongoDB holds raw CTI payloads, MySQL holds normalized verdicts. What remains is leveraging this corpus for trend analysis and historical context inside the AI prompt.
* **Self-healing meta-agent** 🔵 — auto-tuning of `dic_threat_levels` based on operator feedback and false-positive patterns. Scoped for v1.1.0.
* **Autonomous Security Agent** 🔵 — n8n agent with a toolset for network reconnaissance and FIM auditing.
* **Vulnerability Mapping** 🔵 — real-time CVE correlation based on discovered assets and software versions.

---

## 7. Infrastructure as Code & Backups

* 🟢 **Ansible-driven full stack deployment** — *delivered in v1.0.1-alpha.* The master playbook `00_main.yml` covers OS hardening, Docker engine, the full container stack, the database, and post-config in a single pass. Each numbered playbook (00 → 06) is documented separately.
* 🟢 **Unified Vault lifecycle** — *delivered in v1.0.2-rc1.* The previously split `06_1_initialize_vault.yml` and `06_2_provision_vault.yml` are now a single idempotent playbook with pre-flight validation and `no_log` discipline.
* 🟢 **Database retention policy** — *delivered in v1.0.2-rc1.* 6-month rolling window for `dns_queries`, `network_events`, and `threat_indicators` is enforced automatically by the MySQL Event Scheduler.
* **Terraform for Proxmox** 🔵 — automate VM provisioning on Proxmox alongside the existing Ansible-managed OS / Docker layer.
* **Off-site Backup** 🔵 — daily cron-based backup (02:00 AM) to external Patriot 512 GB M.2 SSD.
* **DB backup rotation** 🔵 — 30-day rolling rotation for database backups (separate from the 6-month retention applied to the live tables).