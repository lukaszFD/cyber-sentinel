# Using & Testing

## Logging in

| What | Where |
|---|---|
| Browser | `https://sandbox.<suffix>` (no password, LAN only) |
| Sandbox Pi-hole UI | `https://sandbox-dns.<suffix>/admin` — `vault_sandbox_pihole_admin_password` (the main Pi-hole's while that is empty) |
| Results | AI Config UI → **Sandbox**: sessions, requests, DNS, observables and CTI checks |
| Database | schema `cyber_sentinel_sandbox` (pgAdmin: `.db/mac/pgadmin-servers.json`) |

Certificates: `vault_sandbox_cert/key` and `vault_sandbox_dns_cert/key`. While they are empty, playbook 05 uses the old firefox pair and pihole's, and the browser warns that the name does not match. Add both names to Local DNS records (or `/etc/hosts`) pointing at the host.

After a session, wipe the browser (profile, tabs, cookies, cache) on the host:

```bash
sudo sandbox-reset
```

Cron runs the same at 04:00 every night. mitmproxy, the sandbox Pi-hole and the logs are kept.

## Logs

| Log | Host path | Format |
|---|---|---|
| URLs | `config/sandbox/logs/urls.jsonl` | JSON Lines, rotated at midnight, 14 days kept (`urls.jsonl.YYYY-MM-DD`) |
| DNS | `config/sandbox/pihole/log/pihole.log` | Pi-hole query log (extra logging on); the client is always mitmproxy |

One URL record per HTTP flow, error or blocked attempt:

| Field | Meaning |
|---|---|
| `ts` | UTC timestamp |
| `event` | `http`, `error`, `blocked`, `client_tls_failed` |
| `method`, `url`, `scheme`, `host`, `port`, `http_version` | Request |
| `server_ip` | Address actually connected to |
| `status`, `reason`, `content_type`, `redirect_location` | Response |
| `referer`, `user_agent` | Request headers, copied out |
| `req_headers`, `resp_headers` | All headers; `Cookie`, `Set-Cookie`, `Authorization`, `Proxy-Authorization` redacted |
| `size`, `sha256` | Decoded body size and SHA-256; bodies over 20 MB are streamed and not hashed (`streamed: true`). Bodies are never stored |
| `upstream_tls` | Real upstream certificate: subject, issuer, expiry, SHA-256, `verified`, `error` |
| `error` | Error or block reason |


## Test scenarios

Run these after a deployment (dev first). `<suffix>` is `local` on dev.

| # | Do | Expect |
|---|---|---|
| 1 | Open `https://sandbox.<suffix>` | Chromium in the browser tab, no login |
| 2 | In the sandbox, open any HTTPS site | Page loads, no certificate error inside the sandbox (mitmproxy CA is trusted by policy) |
| 3 | Open `https://sandbox-dns.<suffix>/admin`, log in, Query Log | Queries of that site, client = mitmproxy, nothing blocked; Adlists empty |
| 4 | On the host: `tail -n 3 ~/config/sandbox/logs/urls.jsonl` | New `"event": "http"` lines with `server_ip`, `status`, `upstream_tls` |
| 5 | In the sandbox, open `http://192.168.0.1` | Refused; a `"event": "blocked"` line in `urls.jsonl` |
| 6 | Main Pi-hole Query Log / `cyber_sentinel.dns_queries` | No queries of the site from scenario 2 — sandbox traffic stays out of the main pipeline |
| 7 | On the host: `sudo sandbox-reset`, reopen the viewer | Fresh browser: no tabs, history or cookies |
| 8 | `docker logs --tail 5 sandbox_log_processor` | `Connected to Postgres`, `[urls] following /logs/urls.jsonl`, `[dns] following …` |
| 9 | SQL below, after scenario 2 | Rows in `url_events` and `dns_queries`; the site's host, URL and IP in `observables` |
| 10 | Wait 2–4 minutes (Sandbox Scan published in n8n) | `checked_at` and `verdict` filled; `observable_checks` rows from `urlhaus` / `threatfox`; the page: a `urlscan` row (`no_hit` / `hit`, or `pending` then a result) |
| 11 | Open a known-bad test URL from URLhaus (inside the sandbox only) | Verdict `hit`, an e-mail, red tag on the Sandbox page |
| 12 | AI Config UI → Sandbox | The session with its requests, DNS and observables; report links open urlscan.io / abuse.ch |

```sql
-- what arrived (last 15 minutes)
SELECT event, count(*), count(*) FILTER (WHERE is_navigation) AS pages
FROM cyber_sentinel_sandbox.url_events WHERE ts > now() - interval '15 minutes' GROUP BY 1;
SELECT query_type, count(*) FROM cyber_sentinel_sandbox.dns_queries
WHERE ts > now() - interval '15 minutes' GROUP BY 1;

-- observables and their checks
SELECT kind, status, verdict, count(*) FROM cyber_sentinel_sandbox.observables GROUP BY 1, 2, 3 ORDER BY 1, 2, 3;
SELECT o.kind, left(o.value, 80) AS value, c.provider, c.outcome, c.summary
FROM cyber_sentinel_sandbox.observable_checks c JOIN cyber_sentinel_sandbox.observables o ON o.id = c.observable_id
ORDER BY c.checked_at DESC LIMIT 30;

-- sessions, ingest position, queue
SELECT * FROM cyber_sentinel_sandbox.v_sessions ORDER BY session_start DESC LIMIT 5;
SELECT * FROM cyber_sentinel_sandbox.ingest_state;
SELECT count(*) FROM cyber_sentinel_sandbox.v_pending_checks;
```
