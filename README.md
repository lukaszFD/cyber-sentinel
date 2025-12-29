# Cyber AI Sentinel - Local Network Guardian

A distributed Cyber Threat Intelligence (CTI) and Passive DNS monitoring system.

## 🎯 Project Purpose
This project was specifically created to **automate AI-driven workflows in n8n**. By orchestrating these Docker containers, the system provides a structured pipeline where DNS traffic is captured, processed, and enriched, allowing n8n to perform intelligent security analysis and automated threat response.

## 🏗️ Architecture Overview

The system is deployed on a **Debian** Virtual Machine (VM) and managed via **Ansible** and **Docker Compose**.

* **DNS Protection:** Pi-hole handles blocking and Unbound acts as a recursive resolver.
* **Passive DNS:** A custom container monitors DNS traffic and logs it for analysis.
* **Log Processing:** A Python-based `log_processor.py` tails DNS logs and populates the MySQL database.
* **Databases:**
    * **MySQL 8.0:** Stores structured threat indicators and DNS query history.
    * **MongoDB 8.2:** Acts as the `threat_data_lake` for storing raw JSON reports from external providers like VirusTotal.

## 📂 Project Structure

```text
cyber-sentinel/
├── ansible/
│   ├── group_vars/
│   │   └── all/
│   │       ├── all_servers.yml
│   │       └── vault.yml
│   ├── templates/
│   │   └── env.j2
│   ├── ansible.cfg
│   ├── copy-env.yml
│   ├── deploy-cyber-ai-sentinel.yml
│   ├── deploy_docker.yml
│   └── hosts.ini
├── config/
│   ├── dns/
│   │   ├── 01-passive.conf
│   │   ├── Dockerfile.log_processor
│   │   ├── Dockerfile.pdns
│   │   └── log_processor.py
│   ├── mongo/
│   │   └── init_mongo.js
│   ├── mysql/
│   │   └── db_deployment.sql
│   └── unbound/
│       └── unbound.conf
└── docker/
    └── docker-compose-cyber-sentinel.yml
```

## 📡 Connectivity & Port Mapping

The environment is accessible via the host (127.0.0.1) using the following port forwarding rules:

| Service | Host Port | Guest Port | Access / Description                 |
| :--- | :--- | :--- |:-------------------------------------|
| **SSH** | `2222` | `22` | `ssh hunter@127.0.0.1 -p 2222`       |
| **MySQL** | `3306` | `3306` | Operational DB: `cyber_intelligence` |
| **n8n** | `5678` | `5678` | Workflow Automation                  |
| **Pi-hole** | `8080` | `80` | DNS Admin UI                         |
| **Firefox** | `4000` | `3000` | Isolated VNC Browser                 |
| **Portainer** | `9443` | `9010` | Docker Management                    |


## 🔐 Secrets Management

Deployment secrets (database passwords, API keys) are managed using **Ansible Vault**. To view or edit the secrets:

```bash
# View encrypted variables
EDITOR=cat ~/ansible_mint_venv/bin/ansible-vault view ansible/group_vars/all/vault.yml --vault-password-file ansible/.vault_pass