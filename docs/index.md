
## Welcome to the official documentation of [**Cyber Sentinel**](https://github.com/lukaszFD/cyber-sentinel).

A distributed Cyber Threat Intelligence (CTI) and Passive DNS monitoring system.

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
