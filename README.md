# Cyber AI Sentinel - Local Network Guardian

A distributed Cyber Threat Intelligence (CTI) and Passive DNS monitoring system.

## 🎯 Project Purpose

This project is an advanced evolution of the [home-network-guardian](https://github.com/lukaszFD/home-network-guardian) repository. While the previous project focused on network monitoring and visibility, **Cyber AI Sentinel** is specifically designed to **automate AI-driven workflows in n8n**.

By orchestrating these Docker containers, the system provides a structured pipeline where DNS traffic is captured, processed, and enriched. The key differences in this version are:
* **AI Focus:** Dedicated integration with MongoDB as a Threat Data Lake for AI analysis.
* **Streamlined Management:** Centralized service management and threat response directly from the **n8n** level.
* **Automated CTI:** Transforming raw DNS logs into actionable intelligence for automated security playbooks.
* **Security First:** Integration with **HashiCorp Vault** for enterprise-grade secrets management and 
* **Nginx SSL Proxy** for secure service access.

## 🏗️ Architecture Overview

The system follows a hybrid deployment strategy, managed entirely via **Ansible** and **Docker Compose**. It distinguishes between development and production environments to ensure stability:

* **Development & Testing:** Deployed on a **Proxmox Virtual Machine [vm-prox-dev]** running **Debian**. This is where new AI workflows in n8n and security hardening rules are tested before rollout.
* **Production:** Deployed on a **Raspberry Pi 5 [rpi5-prod]**. This is the primary environment handling real-time network traffic and long-term CTI (Cyber Threat Intelligence) data storage.

### Core Components:

* **Traffic Routing & Security:** 
  * **Nginx Reverse Proxy:** Acts as the single entry point, providing SSL termination and subdomain-based routing (e.g., `n8n.local`, `grafana.local`).
  * **HashiCorp Vault:** Centralized vault for storing sensitive credentials, API tokens (VirusTotal), and SSL certificates.
* **DNS Protection:** Pi-hole handles blocking and Unbound acts as a recursive resolver.
* **Passive DNS:** A custom container monitors DNS traffic and logs it for analysis.
* **Log Processing:** A Python-based `log_processor.py` tails DNS logs and populates the MySQL database.
* **Databases:**
    * **MySQL 8.0:** Stores structured threat indicators and DNS query history.
    * **MongoDB 8.2:** Acts as the `threat_data_lake` for storing raw JSON reports from external providers like VirusTotal.
* **Monitoring:** Grafana dashboards provisioned automatically to visualize VirusTotal scans and DNS traffic patterns.

## 📂 Project Structure Explained

```text
cyber-sentinel/
├── ansible/                        # Infrastructure as Code (IaC) layer
│   ├── .vault_pass                 # 🔐 Ansible Vault encrypted bootstrap secrets - > README_VAULT.md
│   ├── 00_main.yml                 # Master playbook orchestrating the full deployment
│   ├── 01_setup_secrets.yml        # Task: Environment and local secret preparation
│   ├── 02_setup_security.yml       # Task: UFW Firewall and system hardening
│   ├── 03_setup_system.yml         # Task: Docker Engine and prerequisite installation
│   ├── 04_1_prepare_stack.yml      # Task: Directory structure and config sync
│   ├── 04_2_deploy_containers.yml  # Task: Docker Compose stack deployment
│   ├── 04_3_db_create.yml          # Task: MySQL schema and user provisioning
│   ├── 04_4_post_config.yml        # Task: Service initialization (Pi-hole, n8n, Portainer)
│   ├── 05_deploy_proxy.yml         # Task: Nginx Reverse Proxy & SSL certificates deployment
│   ├── 06_1_initialize_vault.yml   # Task: HashiCorp Vault initialization 
│   ├── 06_2_provision_vault.yml    # Task: HashiCorp Vault secret injection
│   ├── ansible.cfg                 # Ansible runtime configuration
│   ├── group_vars/
│   │   └── all/
│   │       ├── all_servers.yml     # Non-sensitive global variables and service definitions
│   │       └── vault.yml           # 🔐 Ansible Vault encrypted bootstrap secrets - > README_VAULT.md
│   ├── hosts.ini                   # Inventory file (Proxmox VM: 192.168.0.5)
│   └── templates/
│       ├── env.j2                  # Template for Docker containers' .env files
│       └── nginx_service.conf.j2   # Dynamic Nginx proxy configuration per service
├── config/                         # Service-specific configurations & logic
│   ├── dns/
│   │   ├── 01-passive.conf         # Passive DNS capture settings
│   │   ├── Dockerfile.log_processor # Python environment for log tailing
│   │   ├── Dockerfile.pdns         # Container definition for DNS sniffing
│   │   └── log_processor.py        # Core Python script (Log extraction to MySQL)
│   ├── grafana/                    # Monitoring & Visualisation
│   │   └── provisioning/           # Automated Dashboard and Datasource setup
│   │       ├── dashboards/         # Threat Intelligence & DNS Dashboards (JSON)
│   │       └── datasources/        # Automatic MySQL/Mongo connection setup
│   ├── mongo/
│   │   └── init_mongo.js           # Threat Data Lake initialization script
│   ├── mysql/
│   │   └── db_deployment.sql       # SQL Schema and analytic views (CTI logic)
│   ├── pihole/
│   │   └── adlists.txt             # Pre-configured blocklists for DNS filtering
│   └── unbound/
│       └── unbound.conf            # Recursive DNS resolver configuration
├── docker/
│   └── docker-compose-cyber-sentinel.yml # Main Docker orchestration file (Sentinel Stack)
└── README.md                       # Project documentation and setup guide
```
## 📊 Monitoring & Dashboards

The system includes pre-configured **Grafana** dashboards to visualize threat intelligence data. Dashboards are automatically provisioned from `config/grafana/provisioning/dashboards`.

**Available Dashboards:**
* **VirusTotal Scans:** Real-time monitoring of domain reputation checks and threat scores.
* **DNS Queries Analysis:** Visualization of total queries per hour and traffic patterns.

Access via: `https://grafana.local` (Requires local DNS entry or Pi-hole configuration).

## 📡 Connectivity & Access Management

The project has moved from local port forwarding to a professional **Nginx Reverse Proxy** setup on the **Proxmox VM [vm-prox-dev]**. Services are now accessible via subdomains using the `.local` (or `.prod`) suffix.

### Service Access Table

| Service | Protocol | Access URL (Local) | Authentication |
| :--- | :--- | :--- | :--- |
| **Pi-hole** | HTTPS | `https://pihole.local` | Vault: `pihole_admin_password` |
| **n8n** | HTTPS | `https://n8n.local` | Vault: `n8n_password` |
| **Grafana** | HTTPS | `https://grafana.local` | Vault: `grafana_password` |
| **Portainer** | HTTPS | `https://portainer.local` | Vault: `portainer_password` |
| **Vault UI** | HTTPS | `https://hashicorp_vault.local` | Root Token (Initial Setup) |
| **Firefox (VNC)**| HTTPS | `https://firefox.local` | No Auth (Isolated Browser) |

> **Note:** Ensure your local `/etc/hosts` or Pi-hole DNS points these domains to `192.168.0.5`.

## 🚀 Deployment & Operations
```bash
# Full Environment Deployment -> local_vm
~/ansible_mint_venv/bin/ansible-playbook -i hosts.ini deploy-cyber-ai-sentinel.yml --limit local_vm
```

## 🔐 Secrets and Access Management

🔐 Ansible Vault encrypted bootstrap secrets -> [README_VAULT.md](README_VAULT.md).

Deployment secrets (database passwords, API keys) are managed using **Ansible Vault**. To view or edit the secrets:

```bash
# View encrypted variables
EDITOR=nano ~/ansible_mint_venv/bin/ansible-vault view ansible/group_vars/all/vault.yml --vault-password-file ansible/.vault_pass

# Edit existing encrypted variables
EDITOR=nano ~/ansible_mint_venv/bin/ansible-vault edit ansible/group_vars/all/vault.yml --vault-password-file ansible/.vault_pass

# Encrypt a new string for use in variables (e.g., a new API Key)
ansible-vault encrypt_string 'your_secret_api_key' --name 'vt_api_key' --vault-password-file ansible/.vault_pass
```
his project integrates **HashiCorp Vault** for secure storage of sensitive data (API keys, database passwords, and certificates).

* **Vault Address:** `http://192.168.0.5:8200`
* **Provisioning:** Handled via Ansible (`04_3_provision_vault.yml`), which writes credentials to `secret/data/cyber-sentinel/credentials`.
* **Usage:** Playbooks dynamically retrieve secrets during deployment (e.g., `mysql_root_password`, `vt_token`).

## 🔍 Troubleshooting & Logs
clear
Check if services are running and healthy:
```bash
# Check container status
ssh hunter@127.0.0.1 "docker ps -a"

# Follow logs of the DNS Log Processor (Python)
ssh hunter@127.0.0.1 "docker logs -f dns_log_processor"

# Access MongoDB Shell from host
docker exec -it mongo mongo -u "hunter" -p "your_password" --authenticationDatabase admin
---------------
show dbs
use threat_data_lake
show collections

mongodb://hunter:PASS@10.10.10.8:27017/threat_data_lake?authSource=admin

# Clear all data
db.virustotal_raw.deleteMany({})
# Get total number of analyzed threats.
db.virustotal_raw.countDocuments({})
# Find detailed analysis for a specific indicator.
db.virustotal_raw.find({resource: "IP"})`
# Delete a specific record by its ID
db.virustotal_raw.deleteOne({ "_id": ObjectId("your_id_here") });
# Delete all records for a specific IP
db.virustotal_raw.deleteMany({ "resource": "1.2.3.4" });

# Monitor incoming DNS queries in MySQL
docker exec -t mysql_db mysql -u root -p"password" -e "SELECT * FROM cyber_intelligence.v_pending_analysis;"
docker exec -t mysql_db mysql -u root -p"password" -e "SELECT * FROM cyber_intelligence.v_security_alerts;"
docker exec -t mysql_db mysql -u root -p"password" -e "SELECT * FROM cyber_intelligence.dns_queries;"

watch -n 5 'mysql -h 127.0.0.1 -P 3306 -u hunter -p "password" -e "SELECT * FROM cyber_intelligence.v_pending_analysis;"'
```

## 🔐 Secure Database Access (SSH Tunneling)

To maintain a high security posture, database ports (MySQL and MongoDB) are not exposed directly to the host's public interfaces and are blocked by UFW. To connect from your local machine (e.g., using IntelliJ IDEA or MongoDB Compass), you must use an SSH tunnel.

### MySQL Connection (Operational DB)
Run this command on your ThinkPad to forward local port `3307` to the MySQL container inside the internal network:

```bash
# Formula: ssh -L [local_port]:[container_internal_ip]:[db_port] [user]@[host] -p [ssh_port]
ssh -L 3307:10.10.10.9:3306 hunter@192.168.0.2 -p 22