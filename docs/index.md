# Cyber Sentinel

<div style="margin: 1.5rem 0 2rem; padding-bottom: 1.5rem; border-bottom: 1px solid var(--md-default-fg-color--lightest);">

  <p style="font-size: 1.05rem; margin: 0 0 1.4rem; line-height: 1.6; color: var(--md-default-fg-color);">
    Automated, AI-driven security ecosystem for network monitoring, threat intelligence gathering, and incident response.
  </p>

  <p style="margin: 0 0 0.5rem; font-size: 0.75rem; font-weight: 600; color: var(--md-default-fg-color--light); text-transform: uppercase; letter-spacing: 0.08em;">
    Project
  </p>
  <p style="margin: 0 0 1.2rem; line-height: 1.9;">
    <a href="https://github.com/lukaszFD/cyber-sentinel/releases/tag/v1.0.3" target="_blank"><img alt="version" src="https://img.shields.io/static/v1?label=version&message=v1.0.3&color=ff9800&style=flat-square"></a>
    <a href="https://github.com/lukaszFD/cyber-sentinel/blob/main/LICENSE" target="_blank"><img alt="license" src="https://img.shields.io/github/license/lukaszFD/cyber-sentinel?style=flat-square&color=blue" style="margin-left:6px;"></a>
    <a href="https://github.com/lukaszFD/cyber-sentinel/commits/main" target="_blank"><img alt="last commit" src="https://img.shields.io/github/last-commit/lukaszFD/cyber-sentinel?style=flat-square&color=brightgreen" style="margin-left:6px;"></a>
    <a href="https://github.com/lukaszFD/cyber-sentinel/stargazers" target="_blank"><img alt="stars" src="https://img.shields.io/github/stars/lukaszFD/cyber-sentinel?style=flat-square&logo=github" style="margin-left:6px;"></a>
  </p>

  <p style="margin: 0 0 0.5rem; font-size: 0.75rem; font-weight: 600; color: var(--md-default-fg-color--light); text-transform: uppercase; letter-spacing: 0.08em;">
    Security &amp; Compliance
  </p>
  <p style="margin: 0 0 1.2rem; line-height: 1.9;">
    <img alt="Dependabot" src="https://img.shields.io/badge/Dependabot-enabled-025E8C?style=flat-square&logo=dependabot&logoColor=white" style="margin-left:6px;">
    <a href="https://securityscorecards.dev/viewer/?uri=github.com/lukaszFD/cyber-sentinel" target="_blank">
      <img alt="OpenSSF Scorecard" src="https://api.securityscorecards.dev/projects/github.com/lukaszFD/cyber-sentinel/badge" style="margin-left:6px;">
    </a>
    <a href="https://github.com/lukaszFD/cyber-sentinel/actions/workflows/trivy.yml" target="_blank">
      <img alt="Trivy" src="https://img.shields.io/github/actions/workflow/status/lukaszFD/cyber-sentinel/trivy.yml?branch=main&style=flat-square&logo=aquasec&logoColor=white&label=Trivy" style="margin-left:6px;">
    </a>
    <a href="https://github.com/lukaszFD/cyber-sentinel/security/code-scanning" target="_blank"><img alt="CodeQL" src="https://img.shields.io/github/actions/workflow/status/lukaszFD/cyber-sentinel/codeql.yml?branch=main&style=flat-square&logo=github&label=CodeQL"></a>
  </p>

  <p style="margin: 0 0 0.5rem; font-size: 0.75rem; font-weight: 600; color: var(--md-default-fg-color--light); text-transform: uppercase; letter-spacing: 0.08em;">
    Tech Stack
  </p>
  <p style="margin: 0; line-height: 1.9;">
    <img alt="Python" src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white">
    <img alt="ansible" src="https://img.shields.io/badge/IaC-Ansible-EE0000?style=flat-square&logo=ansible&logoColor=white" style="margin-left:6px;">
    <img alt="docker" src="https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white" style="margin-left:6px;">
    <img alt="vault" src="https://img.shields.io/badge/Secrets-HashiCorp%20Vault-FFCA00?style=flat-square&logoColor=black" style="margin-left:6px;">
    <img alt="PostgreSQL" src="https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white" style="margin-left:6px;">
    <img alt="pgvector" src="https://img.shields.io/badge/Vector-pgvector-336791?style=flat-square&logo=postgresql&logoColor=white" style="margin-left:6px;">
    <img alt="n8n" src="https://img.shields.io/badge/Workflow-n8n-EA4B71?style=flat-square&logo=n8n&logoColor=white" style="margin-left:6px;">
    <img alt="Prometheus" src="https://img.shields.io/badge/Metrics-Prometheus-E6522C?style=flat-square&logo=prometheus&logoColor=white" style="margin-left:6px;">
    <img alt="Raspberry Pi" src="https://img.shields.io/badge/Raspberry%20Pi-5-A22846?style=flat-square&logo=raspberrypi&logoColor=white" style="margin-left:6px;">
  </p>

</div>

## 🎯 Project Purpose

Cyber Sentinel turns raw DNS traffic into decisions. Every new domain seen on the network is checked against threat intelligence, scored by an AI agent and — if malicious — blocked, without anyone reading logs.

### 🛡️ Problems Solved

* **Analysis fatigue:** thousands of DNS queries a day are filtered and scored automatically; only real threats reach a human.
* **Scattered CTI:** VirusTotal, ThreatFox and URLhaus results are combined into one 1–5 score with a rationale in English and Polish.
* **Slow response:** confirmed malicious domains are added to the Pi-hole denylist and reported by email straight away.
* **Exposed secrets:** all API keys and credentials live in [**HashiCorp Vault**](https://www.hashicorp.com/en/products/vault), not in containers or the repo.

### ⚙️ How It Works

* **Rules first, AI second:** a rule-based score is computed in PostgreSQL; a **Gemini** AI agent in **n8n** reviews it, using past verdicts from **pgvector** memory, within limits set in the database.
* **Noise filtering:** Tranco top domains, a manual allow-list and trusted infrastructure are skipped before any API call.
* **Configuration outside the workflow:** thresholds, prompts (versioned), allow-lists and threat levels are edited in the **AI Config** web UI and stored in the database — the workflow only reads them. Every change is audited.
* **Hardened infrastructure:** Raspberry Pi 5, Docker images pinned by digest, Nginx with TLS in front of every service, deployed end-to-end with Ansible.

---

## 📚 Documentation

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 1rem 0 1.5rem;">

  <div style="padding: 1rem 1.1rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px;">
    <strong>🏗️ <a href="architecture/">Architecture</a></strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">Containerized stack, DNS pipeline, service dependency map</span>
  </div>

  <div style="padding: 1rem 1.1rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px;">
    <strong>🚀 <a href="deployment/">Deployment</a></strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">Ansible IaC — one command, modular playbooks</span>
  </div>

  <div style="padding: 1rem 1.1rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px;">
    <strong>🐳 <a href="docker-compose/">Docker Compose</a></strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">Services, IPs, exposed ports, hardening, volumes</span>
  </div>

  <div style="padding: 1rem 1.1rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px;">
    <strong>🤖 <a href="n8n/">n8n Workflow</a></strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">AI agent pipeline: enrichment, scoring, alerts, auto-block</span>
  </div>

  <div style="padding: 1rem 1.1rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px;">
    <strong>🗄️ <a href="db/">Database Schema</a></strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">PostgreSQL + pgvector, partitioning &amp; retention</span>
  </div>

  <div style="padding: 1rem 1.1rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px;">
    <strong>🔐 <a href="deployment/#secrets">Vault &amp; Secrets</a></strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">Zero-secrets policy, KV v2 provisioning via Ansible</span>
  </div>

</div>

---

## 👤 Author

<div style="display: flex; align-items: center; gap: 16px; padding: 1rem 1.25rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 10px; margin-top: 0.5rem; background: var(--md-code-bg-color);">
  <img src="https://2.gravatar.com/avatar/899e3f874a1a7769cd71e95dd589dc400344ebd1fcdf7c6347cef7e8551ff466?s=256&d=initials"
       alt="Lukasz Dejko"
       style="width: 68px; height: 68px; border-radius: 50%; border: 1.5px solid var(--md-default-fg-color--lighter); flex-shrink: 0;">
  <div>
    <strong style="font-size: 1rem;">Łukasz Dejko</strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">
      Automation Engineer · Backend Developer
    </span><br>
    <span style="font-size: 0.875rem; margin-top: 6px; display: inline-block;">
      <a href="https://www.linkedin.com/in/lukaszfd84/"          target="_blank">LinkedIn</a> ·
      <a href="https://github.com/lukaszFD"                       target="_blank">GitHub</a> ·
      <a href="https://lukaszfd.github.io/ICYB_PW/"              target="_blank">Cybersecurity Blog</a> ·
      <a href="https://gravatar.com/tenderlywonderland56f0a5c722" target="_blank">Gravatar</a>
    </span>
  </div>
</div>