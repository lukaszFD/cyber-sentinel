# Cyber Sentinel

Welcome to the official documentation of **Cyber Sentinel**.

A distributed Cyber Threat Intelligence (CTI) and Passive DNS monitoring system.

## 🎯 Project Purpose

This project is an advanced evolution of the [home-network-guardian](https://github.com/lukaszFD/home-network-guardian) repository. While the previous project focused on network monitoring and visibility, **Cyber AI Sentinel** is specifically designed to **automate AI-driven workflows in n8n**.

By orchestrating these Docker containers, the system provides a structured pipeline where DNS traffic is captured, processed, and enriched. The key differences in this version are:
* **AI Focus:** Dedicated integration with MongoDB as a Threat Data Lake for AI analysis.
* **Streamlined Management:** Centralized service management and threat response directly from the **n8n** level.
* **Automated CTI:** Transforming raw DNS logs into actionable intelligence for automated security playbooks.
* **Security First:** Integration with **HashiCorp Vault** for enterprise-grade secrets management and
* **Nginx SSL Proxy** for secure service access.

## 🤖 AI Workflow Automation (n8n)

The system uses **n8n** as its central security orchestration engine, which automates the process from the detection of a DNS query to the final AI verdict.

### Pipeline Overview
[<img src="assets/n8n.png" width="450" alt="n8n Workflow Preview">](assets/n8n.png)
*Click the image to enlarge.*

* **Orchestration & Data Ingestion:** Fetches pending tasks from the `v_pending_analysis` view and securely retrieves API keys from **HashiCorp Vault**.
* **Multi-Source Enrichment:** Performs parallel reputation lookups for domains and IP addresses across CTI providers such as VirusTotal, ThreatFox, and URLhaus.
* **Dual-Layer Persistence:** Stores raw JSON reports in the **MongoDB Threat Data Lake** while updating operational statuses in the **MySQL** relational database.
* **AI Synthesis:** Leverages the **Google Gemini** model to perform technical analysis of the gathered data and generate bilingual (EN/PL) summaries.
* **Incident Reporting:** Automatically triggers email alerts for high-priority threats based on the `is_malicious_flag` threshold.

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

## 🏗️ Database Logic & 3NF Architecture

The **Cyber AI Sentinel** database is designed for scalability and analytical depth, moving away from flat tables to a structured **3NF (Third Normal Form)** relational model.

### 1. Relational Intelligence Layer
Instead of storing repetitive AI summaries, the system uses the `ai_analysis_results` table.
* **Efficiency:** This allows the **Gemini AI** to generate a single technical verdict that can be referenced by multiple network events if the same threat is detected across different timeframes.
* **Rich Content:** Fields like `verdict_summary_en` and `analysis_pl` are stored as **TEXT** to accommodate long-form technical reports and reference URLs.

### 2. The Threat Correlation Engine
* **threat_indicators:** This is the central hub. It links a specific `dns_query_id` to a unique `analysis_result_id`.
* **threat_indicator_details:** This table bridges the SQL and NoSQL worlds. It stores the `mongo_ref_id`, allowing you to jump from a MySQL record directly to the raw, unformatted JSON report stored in the **MongoDB Threat Data Lake**.

### 3. Automated Scoring & Alerting
The system implements a standardized scoring policy via `dic_threat_levels`:
* **Scores 1-5:** Classified as low risk or suspicious but not inherently malicious (`is_malicious_flag = FALSE`).
* **Scores 6-10:** Classified as malicious or critical threats (`is_malicious_flag = TRUE`).
* **Automation:** Any record reaching this threshold triggers **automated email alerts** in the **n8n** workflow.

### 4. Analytical Views for Grafana
The `views/` directory contains pre-calculated logic to offload processing from the dashboarding layer:
* **v_pending_analysis:** A dynamic queue that identifies new DNS queries that haven't been scanned by CTI providers yet.
* **v_grafana_threat_explorer:** A complex join that provides a **"Security Analyst View"**, combining domain names, source IPs, threat scores, and the names of providers that flagged the indicator.

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