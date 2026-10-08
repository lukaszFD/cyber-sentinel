# Docker Compose

The whole stack is defined in [`docker/docker-compose-cyber-sentinel.yml`](https://github.com/lukaszFD/cyber-sentinel/blob/main/docker/docker-compose-cyber-sentinel.yml). Playbook 04.1 renders it as a Jinja2 template, 04.2 starts it. Secrets come from `.env` (playbook 01); image versions from `ansible/group_vars/all/images.yml`, pinned by digest.

## Services

All containers share one bridge network, `internal_network` (`10.10.10.0/24`), with static IPs. Except Unbound and Pi-hole, they use Pi-hole as DNS.

| IP | Service | Image | Role |
|---|---|---|---|
| `.2` | `unbound` | registry | Recursive resolver — the end of the DNS chain |
| `.3` | `passive_dns` | built (dnsmasq) | Logs every query to `dns.log`, forwards to Unbound |
| `.4` | `pihole` | registry | DNS for the LAN, ad-block, denylist written by n8n |
| `.5` | `firefox` | registry | Isolated browser; profile on tmpfs |
| `.6` | `dns_log_processor` | built (Python) | `dns.log` → `dns_queries` |
| `.7` | `n8n` | registry | AI decision workflow |
| `.8` | `ai-config-ui` | built (Flask) | AI pipeline configuration |
| `.9` | `postgres_db` | built (pgvector + pg_cron) | The only database |
| `.10` | `portainer` | registry | Docker management |
| `.11` | `grafana` | registry | Dashboards |
| `.12` | `vault` | registry | Secrets for n8n |
| `.13` | `prometheus` | registry | Metrics |
| `.14` | `node_exporter` | registry | Host metrics |
| `.100` | `nginx-proxy` | registry | TLS reverse proxy — started by playbook 05, not by compose |

DNS path: `client → pihole → passive_dns → unbound → internet`.

## Exposure

Only DNS is published on the host network. Everything with a web UI is reached through Nginx over HTTPS.

| Published | Service | Why |
|---|---|---|
| `0.0.0.0:53` tcp/udp | `pihole` | DNS for the LAN |
| `127.0.0.1:5678` | `n8n` | Loopback only — Docker-published ports bypass UFW |
| `127.0.0.1:8200` | `vault` | Loopback only — used by playbook 06.1 |

All other services have no published ports.

## Hardening

- `ai-config-ui` — read-only filesystem, all capabilities dropped, `no-new-privileges`, 128 MB / 0.25 CPU limit; receives only its own `AI_UI_*` variables and its own least-privilege database role.
- `vault` — `IPC_LOCK` so secrets are not swapped to disk; TLS terminated by Nginx.
- `firefox` — stateless, profile in tmpfs.
- `node_exporter` — host `/proc`, `/sys` and `/` mounted read-only.
- `portainer` — has the Docker socket, i.e. full control of the host's Docker. Keep it behind Nginx.

## Data

| Volume | Holds |
|---|---|
| `postgres_data` | the `cyber_intelligence` database |
| `n8n_data` | workflows, credentials, execution history |
| `grafana_data` | users and non-provisioned dashboards |
| `prometheus_data` | metrics history |
| `./config/vault/data` | Vault storage (bind mount) |
| `./portainer_data` | Portainer settings (bind mount) |

Removing a volume deletes its data. Vault data cannot be recovered without the unseal keys.
