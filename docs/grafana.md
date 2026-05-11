# Grafana Dashboards

This page documents the [Grafana](https://grafana.com/docs/grafana/latest/) layer of Cyber Sentinel — the visual analytics surface that sits on top of the [MySQL views](db.md#5-grafana-views) and turns IoC enrichment results into operator-facing dashboards. It complements two existing pages: the [container definition](components.md#10-grafana) covers infrastructure parameters (image, IP, volumes), and the [Grafana views section](db.md#5-grafana-views) of the Database Schema covers the SQL layer. This page describes what is rendered on screen and how it gets there.

---

## 1. Overview

Grafana is deployed as part of the Sentinel Docker stack and reachable from the host network through the Nginx reverse proxy. It is provisioned **file-based**, meaning that on every container start Grafana scans `/etc/grafana/provisioning` for declarative YAML manifests (datasources, dashboard providers) and `/etc/grafana/dashboards` for dashboard JSON files. There is no manual click-through setup — the entire visualization layer is reproducible from the Git repository.

The role of Grafana in the IoC analysis pipeline is twofold:

- **Operational telemetry** — answer questions like "how many IPs have we scanned in the last 30 days, how many were flagged, what is the malicious ratio". This is the focus of this page.
- **Host telemetry** — CPU, RAM, disk and network metrics scraped by [Prometheus](components.md#12-prometheus) from `node_exporter`, rendered by the imported `node_exporter_full.json` dashboard.

The IoC dashboards consume the `v_grafana_*` views documented in [Database Schema section 5](db.md#5-grafana-views). All views respect the `is_malicious_flag` policy from `dic_threat_levels`, so any change to the 1–5 scoring scale propagates to Grafana without redeploying dashboards.

---

## 2. Provisioning Architecture

Grafana provisioning is split into two concerns: **datasources** (where to read data from) and **dashboards** (what to render). Both are file-based and live under `config/grafana/` in the repository.

### 2.1 Repository Layout

```
config/grafana/
└── provisioning/
    ├── dashboards/
    │   ├── dashboard-provider.yml          # Provider manifest
    │   ├── node_exporter_full.json         # Host telemetry
    │   ├── Threat_Intelligence_Explorer.json
    │   ├── Total_IP_scans.json
    │   ├── Total_IP_scans_2.json
    │   └── Total-New-DNS-queries_per_hour.json
    └── datasources/
        ├── ds_mysql.yml                    # MySQL → cyber_intelligence
        └── prometheus.yml                  # Prometheus → metrics
```

### 2.2 Deployment Flow

The Ansible playbook `04_1_prepare_stack.yml` ([playbook 04.1](ansible-04-stack.md)) is responsible for copying these files onto the target host. There is one non-obvious detail in the deployment: dashboard JSONs are copied to **two destinations**.

| Source (repo) | Destination (host) | Purpose |
|---|---|---|
| `config/grafana/provisioning/` | `/.../config/grafana/provisioning/` | Datasources + the dashboard provider manifest |
| `config/grafana/provisioning/dashboards/` | `/.../config/grafana/dashboards/` | Actual dashboard JSON files |

The second copy exists because Grafana's file-based provisioning expects dashboard JSONs in a path **separate** from the provider manifest. The provider manifest points to that path (see section 2.4), and Grafana refuses to load dashboards from the same directory as the manifest itself. Keeping the source of truth in one repository folder and duplicating into two host paths avoids symlinks and keeps the Ansible logic simple.

Inside the container, the two paths map via Docker volumes (see [components.md section 10](components.md#10-grafana)):

```
./config/grafana/provisioning  →  /etc/grafana/provisioning
./config/grafana/dashboards    →  /etc/grafana/dashboards
```

### 2.3 Datasources

Datasources are declared via two YAML files in `config/grafana/provisioning/datasources/`. Both are picked up automatically on container start — no UI configuration required.

#### 2.3.1 MySQL — `ds_mysql.yml`

The primary datasource for all IoC dashboards. Points at the `mysqldb` container on the internal Docker network and reads from the `cyber_intelligence` database using the non-privileged `hunter` application user (the same user provisioned by [Ansible playbook 04.3](ansible-04-db.md)).

```yaml title="config/grafana/provisioning/datasources/ds_mysql.yml" linenums="1"
apiVersion: 1
datasources:
  - name: MySQL
    type: mysql
    access: proxy
    url: mysqldb:3306
    database: cyber_intelligence
    user: hunter
    uid: PCF4C4661FE7E0A44
    jsonData:
      maxOpenConns: 0
      maxIdleConns: 2
      connMaxLifetime: 14400
    secureJsonData:
      password: "${MYSQL_PASSWORD}"
    editable: true
```

| Parameter | Value | Notes |
|---|---|---|
| `name` | `MySQL` | Display name shown in the Grafana UI |
| `type` | `mysql` | Built-in MySQL plugin |
| `access` | `proxy` | Grafana backend proxies queries (browser never connects directly) |
| `url` | `mysqldb:3306` | Container DNS name on `internal_network` |
| `database` | `cyber_intelligence` | Default schema for queries |
| `user` | `hunter` | App user with `SELECT/INSERT/UPDATE/DELETE` on `cyber_intelligence.*` (see [Database Schema section 6](db.md#6-user-management)) |
| `uid` | `PCF4C4661FE7E0A44` | **Pinned datasource UID** — dashboard JSONs reference this exact value |
| `connMaxLifetime` | `14400` (4h) | Connection recycle window |
| `password` | `${MYSQL_PASSWORD}` | Substituted from `.env` at container start |

!!! info "Why a pinned UID matters"
Grafana panels reference their datasource by `uid`, not by name. Pinning the UID in the provisioning file means that exported dashboard JSONs work on every fresh deployment without manual rewiring. The same UID literal appears in every `Total_IP_scans*.json` and `Threat_Intelligence_Explorer.json` panel definition under `"datasource": { "name": "PCF4C4661FE7E0A44" }`.

#### 2.3.2 Prometheus — `prometheus.yml`

Reads host metrics from the Prometheus container. Used exclusively by `node_exporter_full.json`.

```yaml title="config/grafana/provisioning/datasources/prometheus.yml" linenums="1"
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://10.10.10.13:9090
    isDefault: true
```

| Parameter | Value | Notes |
|---|---|---|
| `url` | `http://10.10.10.13:9090` | Fixed IP of the Prometheus container on `internal_network` |
| `isDefault` | `true` | Default datasource for new panels created interactively |

### 2.4 Dashboard Provider — `dashboard-provider.yml`

Tells Grafana **where to look for dashboard JSON files** and into which folder to organize them in the UI.

```yaml title="config/grafana/provisioning/dashboards/dashboard-provider.yml" linenums="1"
apiVersion: 1
providers:
  - name: 'CyberSentinelDashboards'
    orgId: 1
    folder: 'Cyber Sentinel'
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /etc/grafana/dashboards
```

| Parameter | Value | Notes |
|---|---|---|
| `folder` | `Cyber Sentinel` | All provisioned dashboards land in this folder in the UI |
| `type` | `file` | File-based provisioning (vs. URL or API) |
| `editable` | `true` | Operators can tweak panels in the UI; changes are not persisted back to the repo |
| `path` | `/etc/grafana/dashboards` | Container-side path; mapped from `./config/grafana/dashboards` on the host |

---

## 3. Dashboards

The repository ships five dashboards. Four are IoC-focused (consume `v_grafana_*` views via the MySQL datasource), one is host telemetry (consumes Prometheus).

| Dashboard | Datasource | Purpose |
|---|---|---|
| [Threat Intelligence Explorer](#31-threat-intelligence-explorer) | MySQL | Full forensic view of malicious indicators |
| [Total IP scans](#32-total-ip-scans) | MySQL | Aggregate scan volume + malicious counters |
| [Total IP scans 2](#33-total-ip-scans-2) | MySQL | Detection-focused variant with daily bar chart and threat-score gauge |
| [Total New DNS queries per hour](#34-total-new-dns-queries-per-hour) | MySQL | DNS traffic intensity over time |
| [node_exporter_full](#35-node_exporter_full) | Prometheus | Host CPU/RAM/disk/network |

The detailed walkthroughs for the four MySQL dashboards (3.1, 3.2, 3.4) follow the same template as 3.3 below — they will be filled in as the dashboards stabilize.

### 3.1 Threat Intelligence Explorer

*Documentation pending. Reads from [`v_grafana_threat_explorer`](db.md#54-v_grafana_threat_explorer).*

### 3.2 Total IP scans

*Documentation pending. Sibling of 3.3 below.*

### 3.3 Total IP scans 2

**File:** `config/grafana/provisioning/dashboards/Total_IP_scans_2.json`  
**Title:** `Total IP scans 2`  
**Folder:** `Cyber Sentinel`  
**Default time range:** last 30 days (`now-30d` to `now`)  
**Auto-refresh:** 5s  
**Datasource:** MySQL (`uid: PCF4C4661FE7E0A44`)

Detection-focused operator view. Four panels arranged on a 24-column grid: a small reference table top-left, two summary widgets in the top row, and a wide daily bar chart at the bottom.

#### 3.3.1 Layout

| Panel | Type | Grid position (x, y, w, h) | Title |
|---|---|---|---|
| `panel-6` | Table | (0, 0, 3, 4) | Last malicious scans |
| `panel-3` | Stat | (3, 0, 10, 4) | Total malicious scans |
| `panel-5` | Gauge | (13, 0, 11, 4) | Threat score |
| `panel-4` | Bar chart | (0, 4, 24, 14) | Total positive flags per day |

#### 3.3.2 Panel details

**Panel 3 — Total malicious scans** (stat). Pulls global counters from the aggregated view:

```sql title="panel-3.sql"
SELECT
    total_scans,
    total_malicious_scans,
    malicious_percentage
FROM v_grafana_malicious_stats
WHERE $__timeFilter(last_scan);
```

The view returns a single row of global statistics, so the panel renders three big-number tiles side by side. Thresholds: green at 0, red at 80. Reference: [`v_grafana_malicious_stats`](db.md#51-v_grafana_malicious_stats).

**Panel 4 — Total positive flags per day** (bar chart). Daily time-series of total vs. positive scans:

```sql title="panel-4.sql"
SELECT
    time_sec,
    total_scans_per_day,
    total_positives_per_day
FROM v_grafana_daily_trends
WHERE $__timeFilter(scan_date)
ORDER BY time_sec ASC;
```

`time_sec` is the UNIX timestamp surfaced by the view for Grafana's time-axis binding. Bars are non-stacked with a 45° x-axis label rotation. Reference: [`v_grafana_daily_trends`](db.md#52-v_grafana_daily_trends).

**Panel 5 — Threat score** (gauge). Score envelope across currently-flagged indicators:

```sql title="panel-5.sql"
SELECT
    AVG(threat_score),
    MAX(threat_score),
    MIN(threat_score)
FROM cyber_intelligence.v_grafana_threat_alerts
LIMIT 50;
```

Reads from the alert-ready view filtered on `is_malicious_flag = TRUE`. Reference: [`v_grafana_threat_alerts`](db.md#55-v_grafana_threat_alerts).

**Panel 6 — Last malicious scans** (table). Timestamp reference column:

```sql title="panel-6.sql"
SELECT last_scan
FROM cyber_intelligence.v_grafana_malicious_stats
LIMIT 50;
```

Sorted by `last_scan` descending.

#### 3.3.3 Reading the dashboard

The top row gives an at-a-glance answer to "are we still seeing threats". `Total malicious scans` shows the cumulative count and percentage; `Threat score` shows the severity envelope (min/avg/max across currently-malicious indicators); `Last malicious scans` anchors everything in time. The bottom bar chart breaks the totals down per day, so a spike in `total_positives_per_day` against a flat `total_scans_per_day` is the visual signature of an active campaign — same volume of observables, more of them flagged.

### 3.4 Total New DNS queries per hour

*Documentation pending. Reads from [`v_grafana_dns_hourly_traffic`](db.md#53-v_grafana_dns_hourly_traffic).*

### 3.5 node_exporter_full

Imported from [Grafana Labs dashboard #1860](https://grafana.com/grafana/dashboards/1860-node-exporter-full/). Consumes the Prometheus datasource. Not Cyber Sentinel-specific — documented here for completeness.

---

## 4. Adding a New Dashboard

The workflow for shipping a new dashboard into the repository:

1. **Build interactively** in the running Grafana UI. The `editable: true` flag on the provider means panels can be created and tweaked live.
2. **Export to JSON** via *Dashboard settings → JSON Model* (or *Share → Export* in older Grafana versions). Make sure datasource references in panels resolve to `PCF4C4661FE7E0A44` (MySQL) or `Prometheus`, not to a randomly-generated UID — otherwise the dashboard breaks on fresh deployments.
3. **Drop the JSON** into `config/grafana/provisioning/dashboards/` in the repo.
4. **Re-run** [Ansible playbook 04.1](ansible-04-stack.md) to copy the file to the target host, or `docker compose restart grafana` if the host already has the latest repo snapshot.

Grafana picks up new and modified dashboards on container start. No API calls, no reimport, no UI clicks.

!!! tip "Backing view first"
If the new dashboard needs a query that does not fit any existing `v_grafana_*` view cleanly, add a new view in `config/mysql/views/` and document it in [Database Schema section 5](db.md#5-grafana-views) **before** writing the panel SQL. Keeping query logic in views (not in panel JSON) means policy changes — like the `is_malicious_flag` migration — propagate to every dashboard via a single `ALTER VIEW`.