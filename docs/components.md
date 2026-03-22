# Components

This page documents every Docker service defined in `docker/docker-compose-cyber-sentinel.yml`. All containers run on a shared bridge network (`internal_network: 10.10.10.0/24`) and use **Pi-hole** (`10.10.10.4`) as their DNS resolver unless noted otherwise.

---

## 1. unbound

**Role:** Recursive DNS resolver. Acts as the upstream DNS server for the entire stack, providing privacy-preserving resolution without relying on external public resolvers (e.g. Google, Cloudflare).

| Parameter | Value |
|-----------|-------|
| Image | `klutchell/unbound:latest` |
| Container name | `unbound` |
| IP | `10.10.10.2` |
| Port | `53` (internal only) |
| Restart policy | `unless-stopped` |
| Config volume | `./config/unbound/unbound.conf:/etc/unbound/unbound.conf` |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
unbound:
  image: klutchell/unbound:latest
  container_name: unbound
  hostname: unbound
  networks:
    internal_network:
      ipv4_address: 10.10.10.2
  volumes:
    - './config/unbound/unbound.conf:/etc/unbound/unbound.conf'
  restart: unless-stopped
```

---

## 2. passive_dns

**Role:** DNS traffic sniffer and logger. Runs `dnsmasq` in passive capture mode — all DNS queries passing through the stack are logged to `/var/log/dns.log`. This log file is the primary data source for the `dns_log_processor` service. The container is built from a custom Dockerfile (`Dockerfile.pdns`).

| Parameter | Value |
|-----------|-------|
| Build | `Dockerfile.pdns` (custom image) |
| Container name | `passive_dns` |
| IP | `10.10.10.3` |
| Port | none (internal only) |
| Restart policy | `unless-stopped` |
| Log volume | `./config/dns/var-log:/var/log` |
| Upstream DNS | `10.10.10.2#53` (unbound) |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
passive_dns:
  build:
    context: .
    dockerfile: Dockerfile.pdns
  container_name: passive_dns
  hostname: passive_dns
  networks:
    internal_network:
      ipv4_address: 10.10.10.3
  volumes:
    - './config/dns/dnsmasq.d:/etc/dnsmasq.d'
    - './config/dns/var-log:/var/log'
  restart: unless-stopped
  command: ["dnsmasq", "-k", "--no-resolv", "--server=10.10.10.2#53",
            "--log-queries", "--log-facility=/var/log/dns.log"]
```

---

## 3. pihole

**Role:** Primary DNS server for the entire container network. Provides ad-blocking, domain filtering via pre-configured blocklists (`config/pihole/adlists.txt`), and routes all resolved queries through `passive_dns` and `unbound`. Every container in the stack uses Pi-hole (`10.10.10.4`) as its DNS resolver.

| Parameter | Value |
|-----------|-------|
| Image | `pihole/pihole:latest` |
| Container name | `pihole` |
| IP | `10.10.10.4` |
| Ports | `53/tcp`, `53/udp` (host-exposed) |
| Timezone | `Europe/Warsaw` |
| Restart policy | `unless-stopped` |
| Depends on | `unbound`, `passive_dns` |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
pihole:
  image: pihole/pihole:latest
  container_name: pihole
  networks:
    internal_network:
      ipv4_address: 10.10.10.4
  environment:
    TZ: "Europe/Warsaw"
  volumes:
    - './pihole:/etc/pihole'
    - './dnsmasq.d:/etc/dnsmasq.d'
  ports:
    - "53:53/tcp"
    - "53:53/udp"
  restart: unless-stopped
  depends_on:
    - unbound
    - passive_dns
```

---

## 4. firefox

**Role:** Isolated browser container. Provides a sandboxed Firefox instance for safe browsing and URL investigation — all DNS queries from Firefox are resolved through Pi-hole, ensuring they pass through the passive DNS logging pipeline.

| Parameter | Value |
|-----------|-------|
| Image | `lscr.io/linuxserver/firefox:latest` |
| Container name | `firefox` |
| IP | `10.10.10.5` |
| DNS | `10.10.10.4` (pihole) |
| PUID / PGID | `1000 / 1000` |
| Timezone | `Europe/Warsaw` |
| Shared memory | `2gb` |
| Security | `seccomp=unconfined` |
| Config storage | `tmpfs` (ephemeral, no persistence) |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
firefox:
  image: lscr.io/linuxserver/firefox:latest
  container_name: firefox
  hostname: firefox
  tmpfs:
    - /config
  networks:
    internal_network:
      ipv4_address: 10.10.10.5
  dns: 10.10.10.4
  environment:
    - PUID=1000
    - PGID=1000
    - TZ=Europe/Warsaw
    - FIREFOX_CLI=https://www.linuxserver.io/
  security_opt:
    - seccomp=unconfined
  shm_size: 2gb
  restart: unless-stopped
```

---

## 5. dns_log_processor

**Role:** Core data ingestion component. A Python service (`log_processor.py`) that continuously tails `/var/log/dns.log` produced by `passive_dns` and writes structured DNS records into the `dns_queries` table in MySQL. This is the entry point of the CTI analysis pipeline. Built from a custom Dockerfile (`Dockerfile.log_processor`).

| Parameter | Value |
|-----------|-------|
| Build | `Dockerfile.log_processor` (custom image) |
| Container name | `dns_log_processor` |
| IP | `10.10.10.6` |
| DNS | `10.10.10.4` (pihole) |
| Log volume | `./config/dns/var-log:/var/log/dns` (read-only) |
| Depends on | `mysqldb` |
| Restart policy | `unless-stopped` |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
dns_log_processor:
  build:
    context: .
    dockerfile: Dockerfile.log_processor
  container_name: dns_log_processor
  depends_on:
    - mysqldb
  networks:
    internal_network:
      ipv4_address: 10.10.10.6
  dns: 10.10.10.4
  volumes:
    - './config/dns/var-log:/var/log/dns:ro'
  restart: unless-stopped
```

---

## 6. n8n

**Role:** AI-powered workflow automation engine. Runs the core threat intelligence pipeline — every 15 minutes it reads unanalyzed DNS observables from MySQL (`v_pending_analysis` view), enriches them via VirusTotal, ThreatFox, and URLHaus APIs, stores raw responses in MongoDB, and sends the aggregated data to Google Gemini for AI-based threat scoring. Final verdicts are written back to MySQL. All API credentials are fetched dynamically from HashiCorp Vault.

| Parameter | Value |
|-----------|-------|
| Image | `n8nio/n8n:latest` |
| Container name | `n8n-server` |
| IP | `10.10.10.7` |
| Port | `5678` (host-exposed) |
| DNS | `10.10.10.4` (pihole) |
| User | `1000:1000` |
| Data volume | `n8n_data:/home/node/.n8n` |
| Timezone | `Europe/Warsaw` |
| Protocol | `https` (via Nginx reverse proxy) |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
n8n:
  image: n8nio/n8n:latest
  container_name: n8n-server
  networks:
    internal_network:
      ipv4_address: 10.10.10.7
  dns: 10.10.10.4
  ports:
    - "5678:5678"
  volumes:
    - n8n_data:/home/node/.n8n
  user: "1000:1000"
  environment:
    - N8N_HOST=n8n.{{ domain_suffix }}
    - N8N_PORT=5678
    - N8N_PROTOCOL=https
    - NODE_ENV=production
    - N8N_SECURE_COOKIE=false
    - WEBHOOK_URL=https://n8n.{{ domain_suffix }}/
    - GENERIC_TIMEZONE=Europe/Warsaw
    - N8N_RUNNERS_ENABLED=true
    - N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS=true
  restart: unless-stopped
```

!!! note "Ansible template"
The `{{ domain_suffix }}` placeholder is replaced by Ansible during deployment using the `env.j2` template.

---

## 7. mongo

**Role:** CTI raw data lake. Stores complete, unprocessed JSON responses from all external threat intelligence providers (VirusTotal, ThreatFox, URLHaus) in the `threat_data_raw` collection. Each document is linked back to MySQL via `mongo_ref_id` in the `threat_indicator_details` table, enabling full forensic traceability.

| Parameter | Value |
|-----------|-------|
| Image | `mongo:4.4` |
| Container name | `mongo` |
| IP | `10.10.10.8` |
| DNS | `10.10.10.4` (pihole) |
| Database | `threat_data_lake` |
| Data volume | `mongo_data:/data/db` |
| Init script | `./config/mongo/init_mongo.js` |
| Credentials | `${MONGODB_USERNAME}` / `${MONGODB_PASSWORD}` (from `.env`) |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
mongo:
  image: mongo:4.4
  container_name: mongo
  hostname: mongo
  environment:
    MONGO_INITDB_ROOT_USERNAME: "${MONGODB_USERNAME}"
    MONGO_INITDB_ROOT_PASSWORD: "${MONGODB_PASSWORD}"
    MONGO_INITDB_DATABASE: threat_data_lake
  volumes:
    - mongo_data:/data/db
    - './config/mongo:/docker-entrypoint-initdb.d:ro'
  networks:
    internal_network:
      ipv4_address: 10.10.10.8
  dns: 10.10.10.4
  restart: unless-stopped
```

---

## 8. mysqldb

**Role:** Primary relational database. Stores all structured threat intelligence data — DNS query history, AI-generated verdicts, threat indicator metadata, and analytical views used by both n8n (for workflow orchestration) and Grafana (for dashboards). The schema is initialized automatically from `config/mysql/db_deployment.sql` on first run.

| Parameter | Value |
|-----------|-------|
| Image | `mysql:8.0` |
| Container name | `mysql_db` |
| IP | `10.10.10.9` |
| DNS | `10.10.10.4` (pihole) |
| Database | `cyber_intelligence` |
| Data volume | `mysql_data:/var/lib/mysql` |
| Init scripts | `./config/mysql:/docker-entrypoint-initdb.d` (read-only) |
| Root host | `%` (all hosts within the network) |
| Root password | `${MYSQL_ROOT_PASSWORD}` (from `.env`) |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
mysqldb:
  image: mysql:8.0
  container_name: mysql_db
  restart: unless-stopped
  environment:
    MYSQL_ROOT_PASSWORD: "${MYSQL_ROOT_PASSWORD}"
    MYSQL_DATABASE: cyber_intelligence
    MYSQL_ROOT_HOST: "%"
  volumes:
    - mysql_data:/var/lib/mysql
    - ./config/mysql:/docker-entrypoint-initdb.d:ro
  networks:
    internal_network:
      ipv4_address: 10.10.10.9
  dns: 10.10.10.4
```

---

## 9. portainer

**Role:** Docker container management UI. Provides a web-based interface for monitoring container status, logs, resource usage, and performing management operations. Accesses the Docker daemon directly via the Unix socket. Exposed externally through the Nginx reverse proxy.

| Parameter | Value |
|-----------|-------|
| Image | `portainer/portainer-ce:latest` |
| Container name | `portainer` |
| IP | `10.10.10.10` |
| DNS | `10.10.10.4` (pihole) |
| Docker socket | `/var/run/docker.sock:/var/run/docker.sock` |
| Data volume | `./portainer_data:/data` |
| Restart policy | `unless-stopped` |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
portainer:
  image: portainer/portainer-ce:latest
  container_name: portainer
  hostname: portainer
  networks:
    internal_network:
      ipv4_address: 10.10.10.10
  dns: 10.10.10.4
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
    - ./portainer_data:/data
  restart: unless-stopped
```

---

## 10. grafana

**Role:** Visualization and monitoring dashboard. Auto-provisioned with two pre-configured dashboards: DNS traffic intensity and threat intelligence trends. Both MySQL (`v_grafana_*` views) and MongoDB are configured as datasources automatically via files in `config/grafana/provisioning/datasources/`.

| Parameter | Value |
|-----------|-------|
| Image | `grafana/grafana:latest` |
| Container name | `grafana` |
| IP | `10.10.10.11` |
| DNS | `10.10.10.4` (pihole) |
| Admin password | `${GRAFANA_PASSWORD}` (from `.env`) |
| Provisioning | `./config/grafana/provisioning:/etc/grafana/provisioning` |
| Dashboards | `./config/grafana/dashboards:/etc/grafana/dashboards` |
| Data volume | `grafana_data:/var/lib/grafana` |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
grafana:
  image: grafana/grafana:latest
  container_name: grafana
  networks:
    internal_network:
      ipv4_address: 10.10.10.11
  dns: 10.10.10.4
  environment:
    - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    - MYSQL_PASSWORD=${MYSQL_PASSWORD}
  volumes:
    - './config/grafana/provisioning:/etc/grafana/provisioning'
    - './config/grafana/dashboards:/etc/grafana/dashboards'
    - 'grafana_data:/var/lib/grafana'
  restart: unless-stopped
```

---

## 11. vault

**Role:** Secrets management. Implements a zero-secrets policy across the entire stack — all sensitive values (API tokens for VirusTotal, ThreatFox, URLHaus, Gemini, and database credentials for MySQL and MongoDB) are stored in Vault and fetched at runtime by n8n workflows. Initialized and provisioned automatically via Ansible playbooks (`06_1_initialize_vault.yml`, `06_2_provision_vault.yml`).

| Parameter | Value |
|-----------|-------|
| Image | `hashicorp/vault:latest` |
| Container name | `hashicorp_vault` |
| IP | `10.10.10.12` |
| Port | `8200` (host-exposed) |
| DNS | `10.10.10.4` (pihole) |
| Storage backend | File (`/vault/file`) |
| TLS | Disabled (TLS terminated by Nginx) |
| UI | Enabled (`VAULT_UI=true`) |
| Capability | `IPC_LOCK` (prevents secrets from being swapped to disk) |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
vault:
  image: hashicorp/vault:latest
  container_name: hashicorp_vault
  ports:
    - "8200:8200"
  environment:
    VAULT_LOCAL_CONFIG: >
      {"storage": {"file": {"path": "/vault/file"}},
       "listener": {"tcp": {"address": "0.0.0.0:8200", "tls_disable": 1}}}
    VAULT_ADDR: "http://0.0.0.0:8200"
    VAULT_UI: "true"
  cap_add:
    - IPC_LOCK
  volumes:
    - ./config/vault/data:/vault/file
    - ./config/vault/config:/vault/config
  command: server
  networks:
    internal_network:
      ipv4_address: 10.10.10.12
  dns: 10.10.10.4
  restart: unless-stopped
```

!!! warning "TLS note"
TLS is disabled at the Vault listener level (`tls_disable: 1`). HTTPS encryption is handled upstream by the Nginx reverse proxy, which terminates SSL before forwarding traffic to Vault on port 8200.

---

## 12. prometheus

**Role:** Metrics collection and time-series database. Scrapes host-level metrics from `node_exporter` and stores them for use in Grafana dashboards. Configuration is managed via `config/prometheus/prometheus.yml`.

| Parameter | Value |
|-----------|-------|
| Image | `prom/prometheus:latest` |
| Container name | `prometheus` |
| IP | `10.10.10.13` |
| DNS | `10.10.10.4` (pihole) |
| Config volume | `./config/prometheus:/etc/prometheus` |
| Data volume | `prometheus_data:/prometheus` |
| Config file | `prometheus.yml` |
| Restart policy | `unless-stopped` |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
prometheus:
  image: prom/prometheus:latest
  container_name: prometheus
  volumes:
    - ./config/prometheus:/etc/prometheus
    - prometheus_data:/prometheus
  command:
    - '--config.file=/etc/prometheus/prometheus.yml'
    - '--storage.tsdb.path=/prometheus'
  networks:
    internal_network:
      ipv4_address: 10.10.10.13
  dns: 10.10.10.4
  restart: unless-stopped
```

---

## 13. node_exporter

**Role:** Host system metrics exporter. Exposes CPU, memory, disk, and network metrics from the underlying Linux host to Prometheus. Mounts the host's `/proc`, `/sys`, and root filesystem in read-only mode to collect OS-level statistics without modifying the host.

| Parameter | Value |
|-----------|-------|
| Image | `quay.io/prometheus/node-exporter:latest` |
| Container name | `node_exporter` |
| IP | `10.10.10.14` |
| DNS | `10.10.10.4` (pihole) |
| Host mounts | `/proc`, `/sys`, `/` (all read-only) |
| Filesystem exclusions | `sys`, `proc`, `dev`, `host`, `etc` |
| Restart policy | `unless-stopped` |

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
node_exporter:
  image: quay.io/prometheus/node-exporter:latest
  container_name: node_exporter
  volumes:
    - /proc:/host/proc:ro
    - /sys:/host/sys:ro
    - /:/rootfs:ro
  command:
    - '--path.procfs=/host/proc'
    - '--path.rootfs=/rootfs'
    - '--path.sysfs=/host/sys'
    - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
  networks:
    internal_network:
      ipv4_address: 10.10.10.14
  dns: 10.10.10.4
  restart: unless-stopped
```

---

## 14. Network & Volumes

### Docker network

All services share a single bridge network with a static `/24` subnet:

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
networks:
  internal_network:
    driver: bridge
    ipam:
      config:
        - subnet: 10.10.10.0/24
```

### Named volumes

Persistent data for stateful services is stored in named Docker volumes:

```yaml title="docker-compose-cyber-sentinel.yml" linenums="1"
volumes:
  n8n_data:       # n8n workflow definitions and credentials
  mysql_data:     # MySQL database files
  mongo_data:     # MongoDB data files
  grafana_data:   # Grafana dashboards and user settings
  prometheus_data: # Prometheus time-series database
```

## 15. Service Dependency Map

All services run on a shared Docker bridge network (`internal_network: 10.10.10.0/24`). The tables below list every container grouped by functional layer, with its assigned IP, port, role and key connections.

> **Legend:** `→` write / send &nbsp;|&nbsp; `←` read / pull &nbsp;|&nbsp; `⇢` DNS only

### 15.1 Layer 1 — DNS

| # | Container | IP | Port | Role | Connections |
|---|-----------|-----|------|------|-------------|
| 1 | `pihole` | `10.10.10.4` | `53/tcp+udp` | Primary DNS sinkhole, ad-block | `→ passive_dns` (depends_on) · `→ unbound` (depends_on) |
| 2 | `passive_dns` | `10.10.10.3` | — | dnsmasq DNS sniffer, writes `/var/log/dns.log` | `→ unbound :53` (upstream) |
| 3 | `unbound` | `10.10.10.2` | `53` | Recursive DNS resolver | — (upstream terminus) |

---

### 15.2 Layer 2 — Ingestion & Orchestration 

| # | Container | IP | Port | Role | Connections |
|---|-----------|-----|------|------|-------------|
| 4 | `dns_log_processor` | `10.10.10.6` | — | Python: tails `dns.log`, writes `dns_queries` | `← passive_dns` (log file) · `→ mysqldb` (write) · `⇢ pihole` |
| 5 | `firefox` | `10.10.10.5` | — | Isolated browser client (LinuxServer) | `⇢ pihole` (DNS) |
| 6 | `n8n` | `10.10.10.7` | `5678` | AI workflow engine, runs every 15 min | `← mysqldb` (v_pending_analysis) · `→ mongo` (CTI JSON) · `→ mysqldb` (verdicts) · `← vault` (secrets) · `⇢ pihole` |

---

### 15.3 Layer 3 — Data Storage

| # | Container | IP | Port | Role | Connections |
|---|-----------|-----|------|------|-------------|
| 7 | `mongo` | `10.10.10.8` | — | MongoDB 4.4 — CTI raw JSON data lake (`threat_data_raw`) | `← n8n` (insert) · `← grafana` (read) |
| 8 | `mysqldb` | `10.10.10.9` | — | MySQL 8.0 — relational store (`cyber_intelligence`) | `← dns_log_processor` · `← n8n` (read + write) · `← grafana` (read) |
| 9 | `vault` | `10.10.10.12` | `8200` | HashiCorp Vault — zero-secrets policy, UI enabled | `← n8n` (fetch API keys + DB creds) |

---

### 15.4 Layer 4 — Monitoring & Management 

| # | Container | IP | Port | Role | Connections |
|---|-----------|-----|------|------|-------------|
| 10 | `portainer` | `10.10.10.10` | — | Portainer CE — Docker management via socket | mounts `/var/run/docker.sock` · `⇢ pihole` |
| 11 | `grafana` | `10.10.10.11` | — | Grafana — threat + DNS dashboards, auto-provisioned | `← mysqldb` (v_grafana_* views) · `← mongo` (CTI lake) · `⇢ pihole` |
| 12 | `prometheus` | `10.10.10.13` | — | Prometheus — metrics collection | `← node_exporter` (scrape) · `⇢ pihole` |
| 13 | `node_exporter` | `10.10.10.14` | — | Host OS metrics (CPU, RAM, disk, net) | mounts `/proc`, `/sys`, `/` (read-only) |
