## 🏗️ Architecture Overview

The system follows a hybrid deployment strategy, managed entirely via **Ansible** and **Docker Compose**. It distinguishes between development and production environments to ensure stability:

* **Development & Testing:** Deployed on a **Proxmox Virtual Machine [vm-prox-dev]** running **Debian**. This is where new AI workflows in n8n and security hardening rules are tested before rollout.
* **Production:** Deployed on a **Raspberry Pi 5 [rpi5-prod]**. This is the primary environment handling real-time network traffic and long-term CTI (Cyber Threat Intelligence) data storage.

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