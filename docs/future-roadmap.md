# Future Roadmap: Project Development

This document outlines the planned technical improvements and new features for the **Cyber Sentinel** project.

## 1. Database Infrastructure Migration & Analytics
* **Transition to PostgreSQL**: Replace MySQL with PostgreSQL for advanced security analytics and performance.
* **User-Device Correlation Logic**:
    * Implement a mapping schema (`user_devices`) to link internal IP addresses to specific users.
    * Develop advanced SQL queries to join DNS logs with threat intelligence, attributed to specific network participants.
* **Integrity Hash Storage**: Use PostgreSQL to store master hashes of critical system and configuration files for the File Integrity Monitoring (FIM) system.
* **Database Versioning**: Manage schema changes via Liquibase for consistent deployments across Proxmox and RPi 5.

## 2. Local LLM Integration (Ollama)
* **Model Deployment**: Implement **Llama 3.2 3b** via Ollama for automated security analysis and vulnerability identification.
* **Resource-Aware Ansible Playbook**: New playbook to deploy Ollama with strict hardware limits for Raspberry Pi 5:
    * **CPU Limit**: Restricted to 2 cores.
    * **RAM Limit**: Maximum 4GB RAM allocation.

## 3. Advanced Security Hardening (IaC driven)
* **Multi-Factor Authentication (MFA/2FA)**:
    * **Hardware Keys**: Integrate **YubiKey 5 Series (5C, Nano, NFC)** for hardware-backed authentication (Proxmox, Vault, SSH).
    * **TOTP Support**: 6-digit code generation for web interfaces (Grafana, n8n, Portainer).
* **Network Defense**:
    * **Port Knocking**: Stealth SSH access via port-hit sequences.
    * **GeoIP Blocking**: Drop traffic from high-risk geographic regions using Ansible-managed firewall rules.
* **Nginx Reverse Proxy Optimization**:
    * **Rate Limiting**: Protection against DDoS and brute-force by limiting requests per IP.
    * **Security Headers**: Implementation of HSTS, X-Frame-Options, and X-Content-Type-Options.

## 4. File Integrity Monitoring (FIM) & AI Audit
* **Automated Integrity Checks**: Implement a system to monitor changes in critical files (e.g., `/etc/ssh/sshd_config`, Ansible playbooks).
* **AI Agent Integration (n8n)**:
    * The AI agent will periodically compare current file hashes with master hashes stored in PostgreSQL.
    * **Automated Triage**: If a mismatch is detected, the AI agent analyzes the change to determine if it was a legitimate administrative action or a potential compromise.
    * **Alerting**: Instant notification via preferred channels if unauthorized modifications are found.

## 5. Visual Analytics & Monitoring (Grafana)
* **Threat Attribution Dashboard**: Visualize malicious and suspicious DNS queries.
* **Per-User Analytics**: Filter security events by device/user to identify risky behavior or targeted devices within the network.
* **Real-Time Alerting**: Configure Grafana to trigger alerts based on "suspicious" tags provided by the LLM analysis.

## 6. Advanced AI Workflow (n8n)
* **Autonomous Security Agent**: Develop an n8n agent with a toolset for network reconnaissance and FIM auditing.
* **Vulnerability Mapping**: Real-time CVE correlation based on discovered assets and software versions.
* **Long-Term Memory**: Link PostgreSQL/MongoDB as memory sources for historical trend analysis.

## 7. Infrastructure as Code & Backups
* **Terraform & Ansible**: Automate VM provisioning on Proxmox and maintain OS hardening/Docker orchestration.
* **Automated Off-site Backup**: Daily cron-based backup (02:00 AM) to external Patriot 512GB M.2 SSD.
* **Retention Policy**: 6-month window for security logs and 30-day rolling rotation for DB backups.