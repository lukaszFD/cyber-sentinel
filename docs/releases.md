# Releases

All versions are on [GitHub Releases](https://github.com/lukaszFD/cyber-sentinel/releases).

| Version | Type | Date | Focus |
|---|---|---|---|
| [v2.5.0](#v250) | Stable | 20 November 2026 | Browser sandbox: isolated ungoogled-chromium behind mitmproxy and its own Pi-hole, data in `cyber_sentinel_sandbox`, abuse.ch / urlscan.io checks, Sandbox page; Firefox removed |
| [v2.4.0](#v240) | Stable | 18 November 2026 | Pi-hole query log as the DNS source: real client IPs, cached and blocked answers, `passive_dns` removed, 3-month retention |
| [v2.3.0](#v230) | Stable | 16 November 2026 | API call log and usage page, VirusTotal budget from the provider's counter, Failure Guard |
| [v2.2.0](#v220) | Stable | 16 November 2026 | Own Pi-hole blocklists: AI classification, review, daily pull request to sentinel-blocklists |
| [v2.1.0](#v210) | Stable | 26 October 2026 | VirusTotal budget, urlscan.io and Shodan context, Deep Recon |
| [v2.0.0](#v200) | Stable | 7 October 2026 | PostgreSQL as the only database, AI agent pipeline, AI Config UI |
| [v1.0.3](#v103) | Release | 5 September 2026 | Local inference on Hailo-10H (removed in v2.0.0) |
| [v1.0.2-rc1](#v102-rc1) | Release candidate | 5 May 2026 | 1–5 threat scale, partitioning, unified Vault playbook |
| [v1.0.1](#v101) | Release | — | Ansible deployment |
| [v1.0.0](#v100) | Release | — | First version |

---

## v2.5.0

Adds a browser sandbox for opening suspicious links: an isolated ungoogled-chromium whose whole traffic goes through mitmproxy and its own Pi-hole. Every request and DNS query lands in a separate schema, `cyber_sentinel_sandbox`, and is checked against abuse.ch and urlscan.io; hits are e-mailed and shown on a new Sandbox page. Upgrades v2.4.0 in place; no data is lost. **The `firefox` container is removed** — the sandbox replaces it.

### Highlights

- **Browser sandbox** at `https://sandbox.<suffix>` — ungoogled-chromium in the Selkies web viewer, profile on tmpfs, wiped by `sudo sandbox-reset` and every night at 04:00.
- **Every request recorded** — mitmproxy is the only way out; one record per request, error or blocked attempt (headers, redirects, server IP, body SHA-256, upstream certificate).
- **Own Pi-hole without adlists** at `https://sandbox-dns.<suffix>/admin`, with its own password.
- **Sandbox data in Postgres** — new schema `cyber_sentinel_sandbox`, filled by the new container `sandbox_log_processor`.
- **CTI checks** — new n8n workflow **Sandbox Scan**: abuse.ch (URLhaus, ThreatFox, MalwareBazaar) for hosts, IPs, URLs and payload hashes; urlscan.io search and private scans for top-level pages; e-mail on hits.
- **Sandbox page** in the AI Config UI: sessions, requests, DNS, observables and their checks.
- **Sandbox hits blocked for the LAN** — the full host of every hit goes to the own malicious blocklist and into the daily pull request in sentinel-blocklists.
- **Isolated** — the sandbox never reaches the LAN, the stack or the main Pi-hole; none of its traffic lands in `cyber_sentinel.dns_queries` or the main queue.
- **Firefox removed** — container, Nginx entry and certificate files.

### Browser Sandbox

- Containers: `sandbox-browser` (`linuxserver/ungoogled-chromium`), `sandbox-mitmproxy` (`mitmproxy/mitmproxy` 12.3.1), `sandbox-pihole` (same pin as the main Pi-hole), `sandbox_log_processor` (built, `python:3.12-slim`). Images pinned by digest in `images.yml`, all multi-arch.
- Networks: `sandbox_network` `10.10.20.0/24` is `internal: true` (no route out; Nginx joins it only to serve the viewer); `sandbox_egress` `10.10.21.0/24` holds only mitmproxy. `sandbox_log_processor` sits on `internal_network` (`.5`, formerly firefox) and is not reachable from the sandbox.
- Chromium is forced through the proxy by a managed policy (`ProxySettings`, no bypass; WebRTC only through the proxy).
- The mitmproxy addon `config/sandbox/sandbox_logger.py` refuses any destination that resolves to a non-public address and pins the checked IP, so DNS rebinding cannot reach the LAN. Refused attempts are logged as `blocked`.
- TLS is intercepted with mitmproxy's own CA (created on the host, private key 0600); 04.7 puts the public certificate into the Chromium policy. Upstream certificates are not enforced, but each chain is verified and the result stored.
- Memory limits: browser 1.5 GB (+512 MB shared memory), mitmproxy 384 MB, Pi-hole 256 MB, log processor 128 MB.

### Sandbox Data and CTI

- `db_sandbox.sql` (new, playbook 04.3): `url_events` and `dns_queries` (monthly partitions, 3 months, added to `partitioned_tables()`), `observables`, `observable_checks`, `ingest_state`, queue and session views, settings `sandbox_*` in `ai_settings`.
- `sandbox_log_processor`: exactly-once ingest (batch and file position in one transaction, resumes across rotation), role `sandbox_ingest` with EXECUTE on four ingest functions only, non-root, read-only file system, no capabilities, only its own `SANDBOX_DB_*` variables.
- Noise filter: allow-listed hosts (Tranco top N, manual) and their URLs are never looked up; static assets are not stored as URL observables; hashes only for payload types, whatever the host.
- Top-level pages whose server failed (`error`, e.g. a dead phishing site) are still URL observables, so urlscan.io search can show older scans.
- **Blocklist:** view `v_blocklist_hits`; `blocklist_sync_malicious()` (Blocklist Publish) adds those hosts to `blocklist_entries` as `malicious`, `approved`, new source `sandbox` (check constraint widened in `db_blocklists.sql`).
- **Sandbox Scan** (every 2 minutes): `claim_checks()` → one HTTP node for all lookups → `record_checks()`; private urlscan.io scans capped by `sandbox_urlscan_daily_limit` (20) and fetched by a later run; every request in `api_call_log` (caller `sandbox`); Failure Guard as Error Workflow.

### AI Config UI

- New **Sandbox** page (read-only): counters, urlscan budget, ingest heartbeat, sessions, the requests and DNS of a session with hits marked, observables with their latest checks. Only urlscan.io and abuse.ch report links are rendered; URLs from browsed sites are shown as text.
- Settings step 10 *Browser sandbox*.

### Ansible

- New playbook **04.7** (`04_7_browser_sandbox.yml`, in `00_main.yml` as `[00.2.7]`): CA policy for Chromium, sandbox Pi-hole without adlists and its password, `/usr/local/bin/sandbox-reset` and its 04:00 cron.
- 04.1 stages `config/sandbox/*` and the processor's build context; 04.2 removes the retired `firefox` container (with `passive_dns`); 04.3 runs `db_sandbox.sql`; 04.5 grants the UI read access; 04.6 imports *Sandbox Scan*.
- 05: new entries `sandbox` and `sandbox_dns` with their own certificates (`vault_sandbox_*`, `vault_sandbox_dns_*`); while those are empty the old firefox pair and pihole's are used. The old `firefox.conf` and its cert files are deleted.
- 01: `.env` gets `SANDBOX_DB_USER` / `SANDBOX_DB_PASSWORD`.

### Per-host Vault Files

- Dev and prod run separate HashiCorp Vaults, so each host now has **one complete** ansible-vault file, `ansible/host_vars/<host>/vault.yml` (`rpi5`, `dev_vm`): all shared keys (API keys, Gmail, passwords, certificates) plus that host's `vault_root_token`, `vault_unseal_keys`, `vault_n8n_vault_token` and `vault_n8n_token_accessor`. `group_vars/all/vault.yml` is gone. Templates with every key: `host_vars/<host>/vault.yml.example` (the Proxmox keys of playbook 00.1 only for `dev_vm`; 00.1 reads them from the dev host); `group_vars/all/vault.yml.example` is removed. All `vault.yml` files are git-ignored.
- `ansible/tools/vault_add_password.sh` generates passwords (letters and digits) and adds them to every host's file without printing them, a separate value per host.
- 06.1 checks the root token against the host's Vault (`[06.1.2.4]`) and stops with a clear message instead of a hidden 403.
- 04.2 pulls registry images in a separate, retried step (`[04.2.1.0a]`): the sandbox browser image is about 5 GB and a slow registry could time out the whole `up`.

### Performance Fix

- `v_pending_observables` (main workflow, every minute) and `v_blocklist_ai_queue` (Blocklists page, Blocklist Candidates) group a week of `dns_queries`. Postgres pushed the allow-list checks (`is_allowlisted()`, `blocklist_is_protected()`) below the `GROUP BY`, so they ran for every raw DNS row instead of once per domain. With the Pi-hole log as the source (v2.4.0) that is ~750k rows a week on prod: 51 s and 55 s per call, Postgres at 100% CPU, and the Blocklists page returned 503 (the UI role times out at 15 s). The grouping CTE is now `MATERIALIZED`: 3.9 s and 2.6 s on the same data, same results. Ships with 04.3 (`db_ai_pipeline.sql` 2.6, `db_blocklists.sql` 1.1); run 04.5 after it.

### Database Helpers

- `.db/` split by OS: `.db/mac/` (Homebrew YubiKey module, uses ssh-agent after `yk`, prod on local port 5433, `pgadmin-servers.json` for pgAdmin) and `.db/linux/` (previous scripts). See `.db/README.md`.

### Upgrading from v2.4.0

New keys in `ansible/host_vars/rpi5/vault.yml` (letters and digits only — they end up in SQL and `.env`):

| Key | Required | Value |
|---|---|---|
| `vault_sandbox_db_password` | yes | 32 random characters (`openssl rand -hex 16`) |
| `vault_sandbox_pihole_admin_password` | no | 24+ characters; the main Pi-hole's password is used while empty |
| `vault_sandbox_cert` / `vault_sandbox_key` | no | certificate for `sandbox.<suffix>`; the firefox pair is used while empty |
| `vault_sandbox_dns_cert` / `vault_sandbox_dns_key` | no | certificate for `sandbox-dns.<suffix>`; pihole's pair is used while empty |

1. **Vault file.** Move the prod secrets into one file: copy the old `group_vars/all/vault.yml` to `ansible/host_vars/rpi5/vault.yml` (still encrypted, same `.vault_pass`), make sure it holds prod's `vault_root_token`, `vault_unseal_keys`, `vault_n8n_vault_token` and `vault_n8n_token_accessor` (with the accessor set, 06.1 renews the n8n token instead of minting a new one on every run), then remove `group_vars/all/vault.yml`. Add the keys above (`VAULT_HOSTS=rpi5 ansible/tools/vault_add_password.sh` generates the two passwords). Check that Ansible sees it:

    ```bash
    cd ansible && ansible-inventory -i hosts.ini --host rpi5 | grep -c '"vault_'
    ```

2. **RPi memory limits.** Docker ignores the sandbox memory limits (browser 1.5 GB) unless the memory cgroup is on. Append `cgroup_enable=memory cgroup_memory=1` to the single line in `/boot/firmware/cmdline.txt`, reboot, then check:

    ```bash
    ssh <user>@<host> 'docker info 2>/dev/null | grep -i "no memory limit" || echo "memory limits OK"'
    ```

3. **Disk space.** The sandbox browser image is about 5 GB; keep at least 8 GB free on `/` before 04.2 (`ssh <user>@<host> 'df -h /'`; `docker image prune` frees old layers).
4. Add two Local DNS records in the main Pi-hole pointing at the host: `sandbox.<suffix>` and `sandbox-dns.<suffix>`. The `firefox.<suffix>` record can go. On a Mac, names ending in `.local` are resolved by mDNS and never reach Pi-hole: put them in `/etc/hosts` instead (not needed for `.prod`).
5. Render `.env`, stage the files, create the schema, start the containers (this also removes `firefox`), grant the UI, import the workflow, configure the sandbox and update Nginx:

```bash
cd ansible
ansible-playbook -i hosts.ini 01_setup_secrets.yml       --limit rpi5-prod
ansible-playbook -i hosts.ini 04_1_prepare_stack.yml     --limit rpi5-prod
ansible-playbook -i hosts.ini 04_3_db_postgres.yml       --limit rpi5-prod
ansible-playbook -i hosts.ini 04_2_deploy_containers.yml --limit rpi5-prod
ansible-playbook -i hosts.ini 04_5_ai_config_editor.yml  --limit rpi5-prod
ansible-playbook -i hosts.ini 04_6_post_config.yml       --limit rpi5-prod
ansible-playbook -i hosts.ini 04_7_browser_sandbox.yml   --limit rpi5-prod
ansible-playbook -i hosts.ini 05_deploy_proxy.yml        --limit rpi5-prod
ansible-playbook -i hosts.ini 06_3_n8n_api_key.yml       --limit rpi5-prod
```

04.3 runs before 04.2 so the processor finds its role and functions when it starts (it waits and retries otherwise).

6. 04.6 re-imports all workflows and leaves them **inactive**: publish the main workflow, Deep Recon, Blocklist Candidates, Blocklist Publish, API Usage Monitor and the new **Sandbox Scan** in n8n. 06.3 re-activates Failure Guard.
7. Check:

```bash
ssh <user>@<host> 'docker ps --filter name=sandbox --format "{{.Names}} {{.Status}}"'   # four containers, Up
ssh <user>@<host> 'docker logs --tail 5 sandbox_log_processor'                         # Connected to Postgres, following both logs
```

Open `https://sandbox.<suffix>`, load any HTTPS site, then:

```sql
SELECT event, count(*) FROM cyber_sentinel_sandbox.url_events WHERE ts > now() - interval '15 minutes' GROUP BY 1;
SELECT kind, status, verdict, count(*) FROM cyber_sentinel_sandbox.observables GROUP BY 1, 2, 3;
```

Within a few minutes the observables get a verdict, and the AI Config UI → Sandbox shows the session.

### Fresh Installs

Create `ansible/host_vars/<host>/vault.yml` with every key (templates above) and, on a Raspberry Pi, turn on the memory cgroup (step 2). `00_main.yml` runs every playbook above; afterwards copy the Vault credentials 06.1 prints into the host's file. The `firefox` removal in 04.2 and 05 does nothing on a new host.

### Tested

- Dev (2026-11-23): full `00_main.yml`. Sandbox: Chromium viewer, traffic only through mitmproxy (direct egress refused), `http://192.168.0.1` blocked, `urls.jsonl` with server IP and upstream TLS, nothing in the main `dns_queries`, processor following both logs, rows in `url_events` / `dns_queries` / `observables`, allow-listed hosts `skipped_trusted`. Sandbox Scan: URLhaus / ThreatFox `no_hit` and a private urlscan.io scan for a clean page; two offline URLhaus entries → `hit` on host and URL, e-mail flagged, both hosts in `v_blocklist_hits` and on the rendered malicious list (sync tested in a rolled-back transaction; publishing is off on dev). A dead phishing page (`error`) now gives a URL observable and an urlscan.io search hit. View fix: same results, Blocklists queries pass under the UI role's 15 s limit. Open: `sandbox-reset` (needs sudo) and the Sandbox page in the browser.
- Prod (RPi 5): _to be filled in after the upgrade._

---

## v2.4.0

`dns_queries` is now filled from Pi-hole's own query log instead of a separate dnsmasq container. Every row carries the real client IP, answers from Pi-hole's cache and blocked answers are captured, and the stack runs one container less. Upgrades v2.3.0 in place. **Retention is shortened from 6 to 3 months**: the next monthly partition job deletes data older than that.

### Highlights

- **Real client IPs** — `source_ip` is the device that asked (e.g. `192.168.0.69`), for queries and answers. Before, every query came from `10.10.10.4` (Pi-hole) and every answer had `'N/A'`.
- **Cached and blocked answers** — new `query_type` values `cached` (answered from Pi-hole's cache) and `blocked` (gravity / denylist), next to `query` and `reply`.
- **`passive_dns` removed** — Pi-hole forwards straight to Unbound (`10.10.10.2#53`); `Dockerfile.pdns` and the dnsmasq container are gone.
- **LAN clients accepted** — Pi-hole `dns.listeningMode = ALL`, so devices on the LAN are answered and logged.
- **3-month retention** for all partitioned tables.

### DNS Pipeline

- Chain: LAN client → Pi-hole → Unbound. Pi-hole writes `pihole.log`; `config/pihole/log` on the host is bind-mounted into `pihole` (rw) and `dns_log_processor` (ro).
- Playbook 04.6 reads four Pi-hole settings and writes only those that differ: `dns.upstreams = ["10.10.10.2#53"]`, `dns.queryLogging = true`, `misc.extraLogging = true` (each line carries the query id and client, so answers are attributed to the device that asked), `dns.listeningMode = ALL`.
- **Port 53 is published on the host: the host must not be reachable from the internet on port 53**, otherwise Pi-hole becomes an open resolver.

### dns_log_processor

- Rewritten; Python 3.12 (`python:3.12-slim`, pinned in `cs_base_images`), only `psycopg2-binary` as dependency.
- Writes one row per query and per answer: `query`, `reply`, `cached`, `blocked`. An answer gets the client and record type of its query; Pi-hole v6's `UDP` / `TCP` line prefix is supported.
- Reopens the log after rotation (inode change) or truncation (`copytruncate`).
- Batched inserts (`BATCH_SIZE` 200 rows or every `FLUSH_INTERVAL` 2 s); after a Postgres restart it reconnects with backoff and keeps up to `MAX_BUFFER` rows; SIGTERM flushes the buffer.
- Skips queries Pi-hole makes itself (`127.0.0.1`, `::1`: the 30-second `pi.hole` healthcheck, reverse lookups of client names); `SKIP_CLIENTS` overrides the list.
- Starts at the end of the file, like `tail -f`: lines written while it was down are not imported.

### Database

- `sp_drop_old_partitions()` keeps **3 months** (was 6) for `dns_queries`, `network_events`, `threat_indicators` and `api_call_log`. One value for all tables, so `threat_indicators.dns_query_id` never points at a dropped row.
- No table changes. `cached` and `blocked` are new values of `dns_queries.query_type`. The queue views (`v_pending_observables`, `v_blocklist_ai_queue`) still take public IPv4 answers only, so blocked answers (`0.0.0.0`) never enter them.
- Cached answers now count towards `query_count` in the queue views, so `blocklist_min_queries` is reached sooner than before. Raise it in the AI Config UI if the blocklist queue grows too fast.

### Upgrading from v2.3.0

No new `vault.yml` keys. The SQL scripts are idempotent; existing rows stay, apart from the shorter retention.

1. **Before the upgrade:** export whatever you want to keep that is older than 3 months. The partition job on the 1st of the month at 02:00 drops it.
2. Check that port 53 of the host is not reachable from the internet (no port forward on the router).
3. Stage the new files:

```bash
cd ansible
ansible-playbook -i hosts.ini 04_1_prepare_stack.yml --limit rpi5-prod
```

4. **Switch Pi-hole to Unbound before 04.2.** 04.2 removes `passive_dns`, while Pi-hole still forwards to it (`10.10.10.3`) until 04.6 runs. Without this step the LAN has no DNS between 04.2 and 04.6:

```bash
ssh <user>@<host> 'docker exec pihole pihole-FTL --config dns.upstreams "[\"10.10.10.2#53\"]"'
```

5. Remove `passive_dns`, rebuild `dns_log_processor`, apply the retention change and set the Pi-hole options:

```bash
ansible-playbook -i hosts.ini 04_2_deploy_containers.yml --limit rpi5-prod
ansible-playbook -i hosts.ini 04_3_db_postgres.yml       --limit rpi5-prod
ansible-playbook -i hosts.ini 04_6_post_config.yml       --limit rpi5-prod
```

6. 04.6 re-imports all workflows and leaves them **inactive**: publish the main workflow, Deep Recon, Blocklist Candidates, Blocklist Publish and API Usage Monitor again in n8n. Run `06_3_n8n_api_key.yml` afterwards to re-activate Failure Guard.
7. Check:

```bash
ssh <user>@<host> 'docker logs --tail 5 dns_log_processor'   # "Following /var/log/pihole/pihole.log", "Connected to Postgres"
```

```sql
SELECT query_type, count(*), count(DISTINCT source_ip)
FROM cyber_sentinel.dns_queries
WHERE timestamp > LOCALTIMESTAMP - interval '10 minutes'
GROUP BY 1;
```

Rows written between 04.2 and 04.6 (before `extraLogging` is on) may have `source_ip = 'N/A'`; they are harmless.

### Fresh Installs

A new installation from this release needs no extra steps: `00_main.yml` sets up the Pi-hole log, the processor and the Pi-hole options. Upgrade-only code changes nothing on a new host, because each step is guarded or only removes something that is not there:

- `[04.1.2.3]` removes the leftovers of `passive_dns`; on a new host there is nothing to remove.
- `[04.2.1.0]` removes the `passive_dns` container only if it exists.
- The *Upgrade from v2.2* block in `db_ai_pipeline.sql` runs only while `vt_lookup_log` is still a table.

These steps stay for one or two releases so that older installations can upgrade, and will be removed after that.

### Tested

- Dev, fresh install of the release branch: full `00_main.yml` on a VM restored from a base backup, `failed=0`; Pi-hole options set, the processor waited for `pihole.log` and then followed it; queries from a LAN device stored as `query` / `reply` / `blocked` with its own IP and queued in `v_pending_observables`; retention function at 3 months.
- Dev, during development: real Pi-hole lines (400) parsed; every `reply` / `cached` / `blocked` row has a client IP; a query from a LAN device stored with its own IP; `v_pending_observables.source_ips` shows real clients; 04.1 and the 04.6 Pi-hole task re-run without changes; log rotation and truncation tested locally.
- Prod (RPi 5), upgrade from v2.3.0 with the steps above: within minutes `query` / `reply` / `cached` / `blocked` rows from LAN devices and containers, no new rows without a client, `v_pending_observables` filling with real client IPs.

---

## v2.3.0

Counts every outgoing API request and stops a failing workflow after a few runs instead of thousands. Upgrades v2.2.0 in place; no data is lost.

### API Call Log

- New table `api_call_log` (partitioned by month, kept 6 months): one row per request to VirusTotal, Gemini, urlscan.io, Shodan, abuse.ch, RDAP and crt.sh — provider, caller, endpoint, HTTP status, outcome. `vt_lookup_log` became a view on it; its rows are moved once.
- All workflows log their calls in one *Log API calls* node; the main workflow logs VirusTotal right after the call. The VirusTotal request is no longer retried inside a run, so one claim is one call.
- The partition jobs (`sp_add_future_partitions()`, `sp_drop_old_partitions()`) handle tables of both schemas through `cyber_sentinel.partitioned_tables()`.

### VirusTotal Budget From the Provider

- New workflow **API Usage Monitor** (hourly at :05) stores VirusTotal's own counter for the key (`overall_quotas`; free, it does not use the quota). `v_vt_budget` uses the higher of this and the local count, so calls from the dev environment and manual tests reduce the budget too.
- The AI Config UI simulator goes through the same budget (`api_claim()`): same per-minute limit and reserve; its separate in-memory limit (`AI_UI_VT_MIN_INTERVAL`, `AI_UI_VT_DAILY_LIMIT`) is gone.
- One e-mail per provider and UTC day when usage crosses `api_alert_threshold_pct` (80 %) of `vt_daily_limit` / `api_daily_limit_<provider>`. Only VirusTotal is stopped by its budget.

### Failure Guard

- New workflow **Failure Guard**, set as the Error Workflow of every workflow. After `failure_guard_threshold` (10) failed runs in a row it deactivates the workflow and sends **one** e-mail per streak; a successful run resets the count.
- Works while Vault is sealed: n8n credentials only, sender and recipient in `ops_settings` (written by 04.3).
- New playbook **06.3** issues its n8n API key (rotated on every run) and activates it — n8n runs an Error Workflow only while it is active.

### AI Config UI

- **API usage** page: today per provider (local count, VirusTotal's counter, limit), per caller and per hour, the last 30 days, rate limits and errors, usage alerts and Failure Guard alerts.
- Settings step 9 *API usage and failures*.

### Upgrading from v2.2.0

The SQL scripts are idempotent; existing data stays.

```bash
cd ansible
ansible-playbook 04_3_db_postgres.yml      --limit rpi5-prod
ansible-playbook 04_5_ai_config_editor.yml --limit rpi5-prod
ansible-playbook 04_6_post_config.yml      --limit rpi5-prod \
  --start-at-task "[04.6.4.1] Verify workflow JSON exists on control host"
ansible-playbook 06_3_n8n_api_key.yml      --limit rpi5-prod
```

- 04.3 must run before 04.5: it moves `vt_lookup_log` and recreates `v_vt_budget`, whose UI grant 04.5 restores.
- 04.6 re-imports all six workflows and leaves them **inactive**: publish the main workflow, Deep Recon, both blocklist workflows and *API Usage Monitor* again in n8n. 06.3 runs after 04.6 and activates *Failure Guard* itself.
- Optional: `vault_n8n_alert_to` in `vault.yml` for a different recipient (default: the sender).

---

## v2.2.0

Own Pi-hole blocklists: domains that get through Pi-hole but should not — malicious, tracking, telemetry — are published as plain domain lists to the public repository [sentinel-blocklists](https://github.com/lukaszFD/sentinel-blocklists), which Pi-hole pulls as adlists. Upgrades v2.1.0 in place; no data is lost.

### Three Lists

- `lists/malicious.txt` — every Pi-hole auto-block of the main workflow, approved automatically. A domain stays `blocklist_malicious_ttl_days` (default 90) after its last block; a new block extends it. The backup Pi-hole gets these blocks too.
- `lists/tracking.txt`, `lists/telemetry.txt` — AI classification, approved by a human.
- Domains only, exact match, one per line: Pi-hole does not block IPs, and telemetry often shares CDN IPs with normal sites.
- The database is the source of truth; `blocklist_render()` generates the files from it.

### Blocklist Candidates (n8n, daily 03:20)

- Candidates: domains with a public IPv4 answer in the last `blocklist_lookback_days`, queried at least `blocklist_min_queries` times, whose name contains an active pattern (`telemetry`, `metrics`, `analytics`, `track`, …), not classified yet and not on any list.
- Gemini in batches (`blocklist_ai_batch_size`, at most `blocklist_ai_daily_limit` per day), **no VirusTotal calls**. Returns category (telemetry / tracking / ads / functional / unknown), vendor, confidence, breakage risk and a reason.
- Telemetry and tracking at or above `blocklist_ai_min_confidence` become review candidates; an e-mail announces them. Answers about domains that were not in the batch are dropped.
- A classified or rejected domain is never sent to the AI or proposed again.

### Blocklist Publish (n8n, daily 05:20)

- The branch `n8n/daily-update` is rebuilt from `main` on every run with the full generated files, so there is always one pull request showing the whole difference. A pull request left open after the lists became equal to `main` again is closed.
- The merge stays manual (a ruleset on `main` of sentinel-blocklists requires a pull request).
- `blocklist_publish_enabled = 0` (default) is a dry run: lists are generated, compared and logged only.
- Every run is logged in `blocklist_publish_log` (dry run / no change / published / error); a new or updated pull request and errors are e-mailed.
- A domain covered by a **manual** allow-list entry (the domain or a parent) is never published. Tranco entries and trusted infrastructure do not protect: telemetry usually sits on popular vendor domains.

### AI Config UI

- **Blocklists** page: candidates with vendor, confidence and breakage risk; approve / reject selected rows; published, expired and rejected entries per list; manual additions; last publish runs with links to the pull request; preview of the generated files.
- *Remove* on a published entry sets it to rejected, so neither the AI nor the malicious sync adds it again.
- **Name patterns** editor and a versioned **classifier prompt**.
- Settings for all `blocklist_*` keys.

### Database

New script `db_blocklists.sql` (playbook 04.3): `blocklist_entries`, `blocklist_classifications`, `blocklist_name_patterns`, `blocklist_prompt_templates`, `blocklist_publish_log`, views `v_blocklist_ai_queue` and `v_blocklist_published`, functions `blocklist_record_classifications()`, `blocklist_sync_malicious()`, `blocklist_render()`, `blocklist_is_protected()`. The AI Config UI role gets matching grants (no DELETE on `blocklist_entries`).

### Upgrading from v2.1.0

The SQL scripts are idempotent; existing data and tuned settings stay.

1. Create a fine-grained GitHub token for `lukaszFD/sentinel-blocklists` only — *Contents* and *Pull requests* read/write — and set it as `vault_github_blocklists_token` in `vault.yml`.
2. Run the playbooks:

```bash
cd ansible
ansible-playbook 06_1_initialize_provision_vault.yml --limit rpi5-prod
ansible-playbook 04_3_db_postgres.yml               --limit rpi5-prod
ansible-playbook 04_5_ai_config_editor.yml          --limit rpi5-prod
ansible-playbook 04_6_post_config.yml               --limit rpi5-prod
```

3. In n8n: publish *Blocklist Candidates* and *Blocklist Publish* (imported inactive).
4. Check a dry run in the AI Config UI (Blocklists → publish log), then set `blocklist_publish_enabled = 1`.
5. In Pi-hole, add the adlists and run a gravity update:

```
https://raw.githubusercontent.com/lukaszFD/sentinel-blocklists/main/lists/malicious.txt
https://raw.githubusercontent.com/lukaszFD/sentinel-blocklists/main/lists/tracking.txt
https://raw.githubusercontent.com/lukaszFD/sentinel-blocklists/main/lists/telemetry.txt
```

### Next

API call monitoring: counting real requests per provider and caller, VirusTotal's own quota counter, usage in the AI Config UI and alerts before the daily limit. Delivered in [v2.3.0](#v230).

---

## v2.1.0

More context for each verdict and a second look at high-scored domains. Upgrades v2.0.0 in place; no data is lost.

### VirusTotal Budget

The main workflow runs every minute instead of every 3 minutes, and `claim_next_observable()` decides whether a run may call VirusTotal.

- Daily limit (500), per-minute limit (4) and a reserve kept per hour until the 00:00 UTC reset — `vt_daily_limit`, `vt_per_minute_limit`, `vt_reserve_per_hour`.
- A backlog is cleared at up to 60 observables per hour instead of 20.
- Every call is logged in `vt_lookup_log`; overlapping runs never take the same pair, and a failed run is retried after 15 minutes.
- Calls used and left today are shown in the AI Config UI settings.

### More Context in the Main Workflow

- **Shodan InternetDB** for every IP (free, no key): open ports, software, known CVEs, tags and the hostnames seen on the IP.
- **urlscan.io search** for observables above the VirusTotal gate: earlier scans of the domain's page (title, HTTP status, TLS issuer and certificate age, urlscan verdict) and other sites seen on the same IP.
- Both are context for the AI agent and the e-mail; the rule score is unchanged. Prompt version 1.2 (inactive draft) describes the new evidence.
- E-mail shows hostnames on the IP, related sites and the certificate; CVEs stay in the data for the AI only.

### Deep Recon

New hourly workflow that re-assesses verdicts scored ≥ `recon_min_score` (default 3).

- Sources: RDAP (domain age, registrar), crt.sh (certificate history), urlscan.io page scan (page text, forms, certificate, domains the page loads from).
- AI analyst without tools: confirms or contradicts the verdict and may propose a score within `recon_max_deviation`. Verdicts are never changed automatically.
- E-mail when the proposed score differs from the verdict.
- Page content is treated as untrusted: data only, scripts and comments stripped, URLs defanged.
- New table `deep_recon`, queue `v_pending_recon`, versioned prompt in `recon_prompt_templates`.

### AI Config UI

- **Deep recon** page: results, filters, re-queue, links to urlscan.io reports.
- Recon prompt editor with versions.
- Settings for the VirusTotal budget, urlscan.io, Shodan and Deep Recon with plain descriptions.

### Upgrading from v2.0.0

The SQL scripts are idempotent; existing data stays.

```bash
cd ansible
ansible-playbook 04_3_db_postgres.yml     --limit rpi5-prod
ansible-playbook 04_5_ai_config_editor.yml --limit rpi5-prod
ansible-playbook 04_6_post_config.yml      --limit rpi5-prod
```

- Set `vault_urlscanio_api_key` in `vault.yml`; if it was empty before, also run `06_1_initialize_provision_vault.yml`.
- In n8n: publish *Deep Recon* and the re-imported main workflow; delete *Site Recon* if it was ever imported.
- In the AI Config UI: activate prompt version 1.2.

---

## v2.0.0

**Stable production release.** Not a release candidate: the database schema, the AI pipeline and the deployment are complete and running in production on the Raspberry Pi 5. It replaces the v1.0.2-rc1 line, which was never promoted to a final v1.0.2.

v2.0.0 does three things: moves all data to one PostgreSQL database, turns the AI step into an agent with memory and guardrails, and moves its configuration out of the workflow into the database and a web UI.

### One Database

MySQL and MongoDB are removed. Everything now lives in **PostgreSQL 16** with `pgvector` and `pg_cron`.

- Two schemas: `cyber_sentinel` for DNS traffic and verdicts, `cyber_sentinel_ai` for the AI pipeline.
- Raw CTI responses moved from MongoDB to a JSONB table (`threat_data_raw`).
- Native declarative partitioning by month for `dns_queries`, `threat_indicators` and `network_events`; 6-month retention run by `pg_cron`.
- Foreign keys restored where PostgreSQL allows them on partitioned tables.
- Plain, idempotent SQL files applied in a fixed order by Ansible; Liquibase is no longer used.
- Separate roles for n8n and for the AI Config UI, each with only the access it needs.

Details: [Database](database.md).

### AI Pipeline

The workflow was rebuilt around a deterministic score that the AI reviews, rather than an AI that scores from scratch.

- **VirusTotal gate** — observables below `vt_gate_min_malicious` detections are closed as clean without further API calls or AI tokens.
- **Rule engine in the database** — `compute_threat_score()` returns a 1–5 score with a step-by-step trace from VirusTotal, ThreatFox and URLhaus.
- **AI agent** — Gemini reviews the evidence and the rule score and may adjust it by at most `ai_max_deviation`. Output is a fixed JSON schema with a rationale in English and Polish.
- **Vector memory** — every verdict is embedded and stored in pgvector; the agent searches similar past cases with the `historical_verdicts` tool.
- **Guardrails enforced by the workflow** — score clamped to the allowed range, rule score kept if the agent fails, CTI data treated as untrusted input.
- **Audit** — `verdict_audit` records rule score, final score, what the agent changed and why, model and prompt version.
- **Pi-hole auto-block** — domains above `pihole_block_min_vt_malicious` detections (not trusted infrastructure) are added to the Pi-hole denylist; every attempt is logged.
- **Allow-list** — Tranco top domains (weekly sync) plus manual entries are skipped; exclusions keep user-content platforms such as `github.io` under analysis.

Details: [n8n Workflow](n8n.md).

### AI Config UI

New web UI (`ai-config-ui`) for everything the pipeline reads from the database: thresholds, versioned prompts, allow-lists, trusted infrastructure and threat level wording. Includes a simulator that runs live lookups without touching the queue. Every change is logged with the user who made it.

### Simplified Stack

- Removed: MySQL, MongoDB, Hailo-10H / `hailo-ollama`, Open WebUI, local models. AI runs on Gemini only.
- All images pinned by digest.
- n8n and Vault listen on loopback only; web UIs are reached through Nginx.
- n8n credentials created automatically with fixed IDs (playbook 06.2), so the imported workflow runs without manual setup.
- Documentation rewritten and shortened.

### Upgrading from v1.x

There is no in-place migration from MySQL/MongoDB. Deploy v2.0.0 on a clean host or a clean Docker setup; historical v1 data is not carried over.

```bash
cd ansible
ansible-playbook 00_main.yml --limit rpi5-prod
```

New secrets are required in `vault.yml` — see [Deployment](deployment.md#secrets).

---

## v1.0.3

Added local inference on the Hailo-10H accelerator: `hailo-ollama` as a systemd service and Open WebUI behind Nginx. Testing showed that the 1.5–3B models available on the device were not reliable enough for multi-source threat scoring, so Gemini stayed the reasoning engine. **Removed in v2.0.0.**

## v1.0.2-rc1

Introduced the 1–5 threat scale loaded from the database, URLhaus as a supporting source only, a score cap for trusted infrastructure, monthly partitioning with 6-month retention (MySQL), severity-coloured alert emails and a single Vault lifecycle playbook. Never promoted to a final release; superseded by v2.0.0.

## v1.0.1

Moved the whole deployment to Ansible, merged the Vault playbooks and updated the Grafana dashboards.

## v1.0.0

First version: DNS capture, CTI enrichment and the first AI workflow.