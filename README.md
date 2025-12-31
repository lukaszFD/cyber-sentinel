# Cyber AI Sentinel - Local Network Guardian

A distributed Cyber Threat Intelligence (CTI) and Passive DNS monitoring system.

## 🎯 Project Purpose
This project is an advanced evolution of the [home-network-guardian](https://github.com/lukaszFD/home-network-guardian) repository. While the previous project focused on network monitoring and visibility, **Cyber AI Sentinel** is specifically designed to **automate AI-driven workflows in n8n**.

By orchestrating these Docker containers, the system provides a structured pipeline where DNS traffic is captured, processed, and enriched. The key differences in this version are:
* **AI Focus:** Dedicated integration with MongoDB as a Threat Data Lake for AI analysis.
* **Streamlined Management:** Simplifying the process by allowing service management and threat response directly from the **n8n** level.
* **Automated CTI:** Transforming raw DNS logs into actionable intelligence for automated security playbooks.

## 🏗️ Architecture Overview

The system is deployed on a **VirtualBox Virtual Machine** running the official **Debian** distribution. The entire stack is managed via **Ansible** and **Docker Compose**.

* **DNS Protection:** Pi-hole handles blocking and Unbound acts as a recursive resolver.
* **Passive DNS:** A custom container monitors DNS traffic and logs it for analysis.
* **Log Processing:** A Python-based `log_processor.py` tails DNS logs and populates the MySQL database.
* **Databases:**
    * **MySQL 8.0:** Stores structured threat indicators and DNS query history.
    * **MongoDB 8.2:** Acts as the `threat_data_lake` for storing raw JSON reports from external providers like VirusTotal.

## 📂 Project Structure Explained

```text
cyber-sentinel/
├── ansible/                        # Infrastructure as Code (IaC) layer
│   ├── group_vars/
│   │   └── all/
│   │       ├── all_servers.yml     # Non-sensitive global variables and ports
│   │       └── vault.yml           # 🔐 Encrypted secrets (Passwords, API Keys). See below ‘Secrets and Access Management’.
│   ├── templates/
│   │   └── env.j2                  # Jinja2 template for Docker environment files
│   ├── .vault_pass                 # 🔐 You must generate it yourself. See below ‘Secrets and Access Management’.
│   ├── ansible.cfg                 # Ansible runtime configuration
│   ├── copy-env.yml                # Playbook for syncing environment variables
│   ├── deploy-cyber-ai-sentinel.yml # Main deployment playbook for the entire stack
│   ├── deploy_docker.yml           # Baseline Docker engine installation playbook
│   └── hosts.ini                   # Inventory file (Debian VM at 127.0.0.1:2222)
├── config/                         # Service-specific configurations
│   ├── dns/
│   │   ├── 01-passive.conf         # Passive DNS capture settings
│   │   ├── Dockerfile.log_processor # Python environment for log tailing
│   │   ├── Dockerfile.pdns         # Container definition for DNS sniffing
│   │   └── log_processor.py        # Core Python script (Log extraction to MySQL)
│   ├── mongo/
│   │   └── init_mongo.js           # Database & Collection initialization script
│   ├── mysql/
│   │   └── db_deployment.sql       # SQL Schema and analytic views/tbl 
│   └── unbound/
│       └── unbound.conf            # Recursive DNS resolver configuration
└── docker/
    └── docker-compose-cyber-sentinel.yml # Main Docker orchestration file
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

## 🚀 Deployment & Operations
```bash
# Full Environment Deployment -> local_vm
~/ansible_mint_venv/bin/ansible-playbook -i hosts.ini deploy-cyber-ai-sentinel.yml --limit local_vm
```

## 🔐 Secrets and Access Management

Deployment secrets (database passwords, API keys) are managed using **Ansible Vault**. To view or edit the secrets:

```bash
# View encrypted variables
EDITOR=cat ~/ansible_mint_venv/bin/ansible-vault view ansible/group_vars/all/vault.yml --vault-password-file ansible/.vault_pass

# Edit existing encrypted variables
ansible-vault edit ansible/group_vars/all/vault.yml --vault-password-file ansible/.vault_pass

# Encrypt a new string for use in variables (e.g., a new API Key)
ansible-vault encrypt_string 'your_secret_api_key' --name 'vt_api_key' --vault-password-file ansible/.vault_pass
```

## 🔍 Troubleshooting & Logs

Check if services are running and healthy:
```bash
# Check container status
ssh hunter@127.0.0.1 -p 2222 "docker ps -a"

# Follow logs of the DNS Log Processor (Python)
ssh hunter@127.0.0.1 -p 2222 "docker logs -f dns_log_processor"

# Access MongoDB Shell from host
docker exec -it mongo mongosh -u "hunter" -p "your_password" --authenticationDatabase admin

# Monitor incoming DNS queries in MySQL
watch -n 5 'mysql -h 127.0.0.1 -P 3306 -u hunter -p"password" -e "SELECT * FROM cyber_intelligence.v_pending_analysis;"'
```