## 1. Architecture Overview

The **Cyber Sentinel** ecosystem is built on a containerized microservices architecture, ensuring modularity, scalability, and high security. The entire lifecycle of the project—from infrastructure provisioning to service configuration—is managed through **Ansible**, providing a consistent and reproducible deployment process.

## 2. Core Technology Stack

* **Containerization (Docker):** Every component of the system, including the AI engine, databases, and network guards, runs as a dedicated Docker container. This ensures environment isolation and simplifies dependency management.
* **Infrastructure as Code (Ansible):** All deployment tasks, firewall rules (UFW), and system hardening are fully automated via Ansible playbooks, ensuring the environment is secure and consistent.
* **Secrets Management (HashiCorp Vault):** To maintain a "zero-secrets" policy within the code and n8n workflows, all sensitive data (API keys, database credentials) is stored and retrieved dynamically from **HashiCorp Vault**.
* **Advanced DNS Layer:** The system implements a multi-stage DNS filtering and analysis mechanism:
    * **Pi-hole:** Acts as the primary DNS sinkhole for ad-blocking and initial filtering.
    * **Unbound:** Provides recursive DNS resolution for increased privacy and security.
    * **Passive DNS:** Intercepts and logs DNS traffic to feed the CTI (Cyber Threat Intelligence) analysis pipeline.
* **Data Persistence Layer:**
    * **MySQL:** Stores relational data, including the work queue for analysis, network event logs, and final AI-generated threat verdicts.
    * **MongoDB:** Serves as a high-capacity Data Lake for storing raw JSON responses from CTI providers (VirusTotal, ThreatFox, etc.) for deep forensics.

## 3. Data Flow: End-to-End

The following describes the complete path from a network event to a security verdict:

1. **DNS capture** — `firefox` or any network client sends a DNS query → resolved by `pihole` → forwarded to `passive_dns` → upstream to `unbound`.
2. **Log ingestion** — `dns_log_processor` tails `/var/log/dns.log` produced by `passive_dns` and writes structured records into `mysqldb` (`dns_queries` table).
3. **Enrichment trigger** — `n8n` runs every 15 minutes, reads new unanalyzed observables from `v_pending_analysis` view in `mysqldb`.
4. **CTI enrichment** — `n8n` calls VirusTotal, ThreatFox, URLHaus APIs (credentials from `vault`) and stores raw JSON responses in `mongo` (`threat_data_raw` collection).
5. **AI analysis** — `n8n` normalizes CTI data and sends it to Google Gemini; the AI verdict (score 1–10, bilingual summary) is written back to `mysqldb` (`ai_analysis_results`, `threat_indicators`).
6. **Visualization** — `grafana` reads `mysqldb` views (`v_grafana_*`) and `mongo` to render threat intelligence and DNS traffic dashboards.

##  3. Project Structure Explained

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
│   │   ├── db_deployment.sql           # Master initialization script (Schema, Users, Privileges)
│   │   ├── table/                      # Core relational table definitions
│   │   │   ├── ai_analysis_results.sql # AI-generated verdicts, scores, and bilingual summaries
│   │   │   ├── dic_indicator_types.sql # Dictionary for FQDN, IP, and HASH types
│   │   │   ├── dic_source_providers.sql# Dictionary for CTI sources (VT, ThreatFox, URLhaus)
│   │   │   ├── dic_threat_levels.sql   # Scoring policy definitions (1-10) and malicious flags
│   │   │   ├── dns_queries.sql         # Passive DNS history captured from network traffic
│   │   │   ├── network_events.sql      # High-level security events (IDS alerts, intercepted URLs)
│   │   │   ├── threat_indicators.sql   # Main bridge linking DNS queries to AI analysis results
│   │   │   └── threat_indicator_details.sql # CTI metadata linking MySQL records to MongoDB raw JSON
│   │   └── views/                      # Analytical layer for Grafana and n8n orchestration
│   │       ├── v_grafana_daily_trends.sql     # Aggregated daily scan statistics and risk trends
│   │       ├── v_grafana_dns_hourly_traffic.sql# Time-series data for network intensity monitoring
│   │       ├── v_grafana_malicious_stats.sql  # High-level KPIs: Total scans vs. Malicious ratio
│   │       ├── v_grafana_threat_explorer.sql  # Deep-dive view for security event investigation
│   │       ├── v_latest_threat_reports.sql    # Filters the most recent scan per unique indicator
│   │       └── v_pending_analysis.sql         # Work queue for n8n to identify non-scanned observables
│   ├── n8n/                    
│   │   └── workflows/           
│   │       └── Automated Domain & IP Reputation Guard with HashiCorp Vault.json
│   ├── pihole/
│   │   └── adlists.txt             # Pre-configured blocklists for DNS filtering
│   └── unbound/
│       └── unbound.conf            # Recursive DNS resolver configuration
├── docker/
│   └── docker-compose-cyber-sentinel.yml # Main Docker orchestration file (Sentinel Stack)
└── README.md                       # Project documentation and setup guide
```