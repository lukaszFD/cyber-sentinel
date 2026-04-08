# Cyber Sentinel

<div style="display: flex; align-items: center; gap: 24px; margin: 1.5rem 0 2rem; padding-bottom: 1.5rem; border-bottom: 1px solid var(--md-default-fg-color--lightest);">
  <div>
    <p style="font-size: 1.05rem; margin: 0 0 0.6rem; line-height: 1.6; color: var(--md-default-fg-color);">
      Automated, AI-driven security ecosystem for network monitoring, threat intelligence gathering, and incident response.
    </p>
    <p style="margin: 0;">
      <img alt="version"  src="https://img.shields.io/badge/version-v1.0.1--alpha-4caf50?style=flat-square">
      <img alt="ansible"  src="https://img.shields.io/badge/IaC-Ansible-EE0000?style=flat-square&logo=ansible&logoColor=white"      style="margin-left:6px;">
      <img alt="docker"   src="https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white"     style="margin-left:6px;">
      <img alt="gemini"   src="https://img.shields.io/badge/AI-Google%20Gemini-8E75B2?style=flat-square"                             style="margin-left:6px;">
      <img alt="vault"    src="https://img.shields.io/badge/Secrets-HashiCorp%20Vault-FFCA00?style=flat-square&logoColor=black"      style="margin-left:6px;">
    </p>
  </div>
</div>

## 🎯 Project Purpose

**Cyber Sentinel** is an AI-native security orchestration platform designed to bridge the gap between raw network telemetry and autonomous threat response. It transforms passive monitoring into an active, intelligent defense layer.

### 🛡️ Core Problems Solved
* **Analysis Fatigue:** Automates the evaluation of thousands of DNS queries, using AI to identify malicious patterns that traditional signature-based systems miss.
* **Data Fragmentation:** Consolidates disparate CTI (Cyber Threat Intelligence) sources into a unified, AI-ready intelligence pool.
* **Manual Response Lag:** Eliminates the "human-in-the-loop" delay by triggering autonomous security playbooks the moment a threat is verified by AI.
* **Secrets:** Solves the risk of exposed API keys and credentials across distributed containers by centralizing all sensitive data in [**HashiCorp Vault**](https://www.hashicorp.com/en/products/vault).

### 🚀 The Evolution of Sentinel
By orchestrating a high-performance Docker stack, the system provides a structured pipeline where DNS traffic is captured, processed, and enriched. The key pillars of this version are:

* **AI engine:** The system is not limited to simply storing logs, but treats data as a ‘Neural Lake’. It uses analysis based on LLM models (via Gemini/n8n) to create behavioural profiles and generate bilingual security assessments (English/Polish) for each detected indicator.
* **Autonomous coordination:** Centralises the entire threat lifecycle — from detection to mitigation — within **n8n** workflows, acting as a modular SOAR (Security Orchestration, Automation, and Response) system.
* **Predictive CTI:** Transforms raw, passive DNS logs into predictive intelligence, identifying potential infrastructure before it is used in an active attack.
* **Hardened infrastructure:** Secured by **HashiCorp Vault** for enterprise-grade secret lifecycle management and **Nginx SSL Proxy** to ensure encrypted communication across all service nodes.


---

## 📚 Documentation

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 1rem 0 1.5rem;">

  <div style="padding: 1rem 1.1rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px;">
    <strong>🏗️ <a href="architecture/">Architecture</a></strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">Containerized stack, DNS pipeline, service dependency map</span>
  </div>

  <div style="padding: 1rem 1.1rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px;">
    <strong>🚀 <a href="deployment/">Deployment</a></strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">Full Ansible IaC — one command, 10 playbooks</span>
  </div>

  <div style="padding: 1rem 1.1rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px;">
    <strong>🐳 <a href="components/">Components</a></strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">13 Docker services documented with config snippets</span>
  </div>

  <div style="padding: 1rem 1.1rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px;">
    <strong>🤖 <a href="n8n/">n8n Workflow</a></strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">AI threat enrichment pipeline explained step by step</span>
  </div>

  <div style="padding: 1rem 1.1rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px;">
    <strong>🗄️ <a href="db/">Database Schema</a></strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">MySQL tables, dictionaries, and analytical views</span>
  </div>

  <div style="padding: 1rem 1.1rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px;">
    <strong>🔐 <a href="ansible-06-vault/">Vault & Secrets</a></strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">Zero-secrets policy, KV v2 provisioning via Ansible</span>
  </div>

</div>

---

## 🛠️ Tech Stack

`n8n` · `Google Gemini` · `VirusTotal API` · `ThreatFox` · `URLHaus` · `urlscan.io` · `MySQL 8.0` · `MongoDB 4.4` · `HashiCorp Vault` · `Grafana` · `Prometheus` · `Pi-hole` · `Unbound` · `Nginx` · `Docker` · `Ansible` · `Python` · `Ollama` · `Raspberry Pi 5`

---

## 💻 Supported Platforms

| Architecture | Docker tag | Hardware |
|---|---|---|
| `x86_64` | `amd64` | Standard PC / VM / cloud server |
| `aarch64` | `arm64` | Raspberry Pi 4 / 5, ARM server |

---

## 👤 Author

<div style="display: flex; align-items: center; gap: 16px; padding: 1rem 1.25rem; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 10px; margin-top: 0.5rem; background: var(--md-code-bg-color);">
  <img src="https://2.gravatar.com/avatar/899e3f874a1a7769cd71e95dd589dc400344ebd1fcdf7c6347cef7e8551ff466?s=256&d=initials"
       alt="Lukasz Dejko"
       style="width: 68px; height: 68px; border-radius: 50%; border: 1.5px solid var(--md-default-fg-color--lighter); flex-shrink: 0;">
  <div>
    <strong style="font-size: 1rem;">Łukasz Dejko</strong><br>
    <span style="font-size: 0.875rem; color: var(--md-default-fg-color--light);">
      Automation Engineer · Backend Developer · Standard Chartered Bank · Poland
    </span><br>
    <span style="font-size: 0.875rem; margin-top: 6px; display: inline-block;">
      <a href="https://www.linkedin.com/in/lukaszfd84/"          target="_blank">LinkedIn</a> ·
      <a href="https://github.com/lukaszFD"                       target="_blank">GitHub</a> ·
      <a href="https://lukaszfd.github.io/ICYB_PW/"              target="_blank">Cybersecurity Blog</a> ·
      <a href="https://gravatar.com/tenderlywonderland56f0a5c722" target="_blank">Gravatar</a>
    </span>
  </div>
</div>

---

*Documentation is being added successively as the project evolves. Check back often for updates on AI workflows, database schemas, and Ansible automation.*