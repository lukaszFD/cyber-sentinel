# Deployment

The whole stack is deployed with Ansible from a control machine. One master playbook, `00_main.yml`, runs every step in order; each step can also be re-run on its own.

## Requirements

=== "Control machine"

    ```bash
    sudo apt update && sudo apt install pipx
    pipx install --include-deps ansible
    pipx inject ansible hvac docker
    ```

=== "Target server"

    | | |
    |---|---|
    | OS | Debian 12/13 or Raspberry Pi OS |
    | Architecture | `amd64` or `arm64` (detected automatically) |
    | Access | SSH key, user with `sudo` |
    | Resources | 4 GB RAM, 32 GB disk (the stack uses about 2 GB RAM) |

## Inventory

`ansible/hosts.ini` defines three environments:

| Group | Host | Purpose | Domain suffix |
|---|---|---|---|
| `rpi5-prod` | `rpi5` | production, Raspberry Pi 5 | `.prod` |
| `vm-prox-dev` | `dev_vm` | test VM on Proxmox | `.local` |
| `local-vm` | `local_vm` | local VM (port 2222) | `.prod` |

!!! warning "Always use `--limit`"
Every playbook targets `all_servers`. Without `--limit` the run hits all three environments.

## Secrets

Every host has **one** complete ansible-vault file, `ansible/host_vars/<host>/vault.yml` (`dev_vm`, `rpi5`). During deployment its secrets are copied into that host's HashiCorp Vault, where n8n reads them at runtime.

| Part of the file | Holds |
|---|---|
| Shared keys | API keys, Gmail, service and database passwords, TLS certificates — the same keys on every host; values may differ (e.g. database passwords) |
| The host's Vault | `vault_root_token`, `vault_unseal_keys`, `vault_n8n_vault_token`, `vault_n8n_token_accessor` |

There is no `group_vars/all/vault.yml`. A new key goes into **every** host's file (`ansible/tools/vault_add_password.sh` does that for generated passwords).

Dev (`dev_vm`) and prod (`rpi5`) run separate Vault instances, so their root tokens and unseal keys are different. Templates with every key: `ansible/host_vars/rpi5/vault.yml.example` and `ansible/host_vars/dev_vm/vault.yml.example` (the dev one adds the Proxmox keys). All `vault.yml` files are git-ignored.

```yaml title="ansible/host_vars/<host>/vault.yml (decrypted) — shared keys"
ansible_become_password: ""        # omit if the user has passwordless sudo

# Service logins
vault_pihole_admin_password: ""
vault_sandbox_pihole_admin_password: ""  # sandbox Pi-hole UI; falls back to the main one when empty
vault_grafana_password: ""
vault_portainer_password: ""
vault_n8n_password: ""

# PostgreSQL
vault_postgres_root_password: ""
vault_postgres_password: ""
vault_ai_config_db_password: ""    # openssl rand -hex 24 (hex only)
vault_sandbox_db_password: ""      # sandbox_log_processor; openssl rand -hex 16 (32 chars)

# AI Config UI
vault_ai_ui_secret_key: ""         # openssl rand -hex 32
vault_ai_ui_users:                 # password (>= 12 chars) or werkzeug hash
  lukasz: ""

# API keys
vault_virus_total_token: ""
vault_abuse_api_key: ""            # abuse.ch: ThreatFox + URLhaus
vault_gemini_api_key: ""
vault_urlscanio_api_key: ""        # urlscan.io: search (main workflow) + page scans (Deep Recon)
vault_github_blocklists_token: ""  # fine-grained PAT, sentinel-blocklists only: Contents + Pull requests read/write
vault_grafana_api_key: ""

# Email alerts (Gmail)
vault_n8n_user: ""                 # sender address
vault_n8n_gmail: ""                # Gmail app password
vault_n8n_alert_to: ""             # alert recipient (defaults to the sender)

# TLS: one cert/key pair per service behind Nginx
# pihole, n8n, grafana, portainer, hashicorp_vault, ai_config,
# sandbox (sandbox.<suffix>), sandbox_dns (sandbox-dns.<suffix>)
# While vault_sandbox_* / vault_sandbox_dns_* are empty, playbook 05 falls
# back to the old firefox pair and to pihole's.
vault_pihole_cert: |
  -----BEGIN CERTIFICATE-----
vault_pihole_key: |
  -----BEGIN PRIVATE KEY-----
# ...

```

```yaml title="ansible/host_vars/<host>/vault.yml (decrypted) — the same file, this host's Vault"
# Shown once by playbook 06.1 on this host's first Vault init
vault_root_token: ""
vault_unseal_keys: []
# Shown once by 06.1 when it mints the n8n token; with the accessor set,
# later runs renew the token instead of minting a new one
vault_n8n_vault_token: ""
vault_n8n_token_accessor: ""
```

Encrypt each host's file and keep the password in `ansible/.vault_pass` (ignored by git, referenced from `ansible.cfg`):

```bash
ansible-vault create ansible/host_vars/rpi5/vault.yml      # and host_vars/dev_vm/vault.yml
echo "your_passphrase" > ansible/.vault_pass && chmod 600 ansible/.vault_pass
```

!!! danger "Vault keys are shown once"
The first run of playbook 06.1 on a host initialises its HashiCorp Vault and prints `vault_root_token` and `vault_unseal_keys` exactly once, and the n8n token with its accessor. Copy them into `host_vars/<host>/vault.yml` straight away and keep an offline backup. Losing the unseal keys means losing all Vault data. On later runs 06.1 checks the root token against the host's Vault and stops with a clear message when it belongs to another host.

## Run

```bash
cd ansible
ansible-playbook 00_main.yml --limit rpi5-prod     # production
ansible-playbook 00_main.yml --limit vm-prox-dev   # dev VM
```

`ansible.cfg` already sets the inventory and the vault password file, so no extra flags are needed when running from `ansible/`.

## Playbooks

Each playbook starts with a header describing its purpose, dependencies and sections — see [`ansible/`](https://github.com/lukaszFD/cyber-sentinel/tree/main/ansible) for details.

| # | Playbook | What it does |
|---|---|---|
| 00.1 | `00_1_restore_proxmox.yml` | Restores the dev VM from its latest Proxmox backup. Runs only for `vm-prox-dev`. |
| 01 | `01_setup_secrets.yml` | Renders `.env` on the host from `vault.yml` |
| 02 | `02_setup_security.yml` | UFW firewall |
| 03 | `03_setup_system.yml` | Docker Engine, system packages, Pi 5 fan control |
| 04.1 | `04_1_prepare_stack.yml` | Copies the compose file, Dockerfiles, configs and app sources |
| 04.2 | `04_2_deploy_containers.yml` | Builds and starts the Docker Compose stack |
| 04.3 | `04_3_db_postgres.yml` | PostgreSQL schema, partitioning, AI pipeline schema |
| 04.4 | `04_4_tranco_allowlist.yml` | Tranco allow-list: initial load + weekly cron |
| 04.5 | `04_5_ai_config_editor.yml` | Database role for AI Config UI, rebuilds `ai-config-ui` |
| 04.6 | `04_6_post_config.yml` | Fail2Ban, Pi-hole, Portainer and n8n accounts, workflow import |
| 04.7 | `04_7_browser_sandbox.yml` | Browser sandbox: mitmproxy CA into the Chromium policy, sandbox Pi-hole without adlists, `sandbox-reset` + nightly cron ([details](sandbox/index.md)) |
| 05 | `05_deploy_proxy.yml` | Nginx reverse proxy with TLS |
| 06.1 | `06_1_initialize_provision_vault.yml` | Vault init/unseal, secrets, n8n token, Pi-hole API password |
| 06.2 | `06_2_n8n_bootstrap.yml` | n8n community nodes and credentials |
| 06.3 | `06_3_n8n_api_key.yml` | Failure Guard: n8n API key (rotated on every run, stored as an n8n credential) and activation. Run after every 04.6. |
| 07 | `07_setup_monitoring.yml` | SSD health metrics for Prometheus. Production only, run manually — not part of `00_main.yml`. |

Re-run a single step the same way:

```bash
ansible-playbook 04_3_db_postgres.yml --limit rpi5-prod
```

Order matters in two places: 04.1 must run before 04.2 (it stages the build contexts), and 04.5 must run after 04.3 (04.3 re-grants table privileges that 04.5 narrows again).

## Proxmox Restore (optional)

Playbook 00.1 is specific to the author's dev setup and is skipped everywhere else. To use it, add to `host_vars/dev_vm/vault.yml` (the dev host only; 00.1 reads them from there even when another host runs the task):

```yaml
proxmox_host: ""         # Proxmox VE host, API on port 8006
proxmox_user_token: ""   # user@realm!tokenid
proxmox_api_secret: ""
```

The token needs VM power, backup and config rights on the VM and allocate rights on the backup storage; in a home lab `PVEAdmin` on `/` is the simple option.

## After Deployment

Open ports (everything else is denied):

| Port | Service |
|---|---|
| 22/tcp | SSH |
| 53/tcp+udp | Pi-hole DNS |
| 80/tcp | redirect to HTTPS |
| 443/tcp | Nginx |

!!! warning "Port 53"
    Pi-hole answers every client that reaches it (`dns.listeningMode = ALL`, needed to log LAN devices with their own IP). The host must not be reachable from the internet on port 53 — no port forward on the router — otherwise Pi-hole becomes an open resolver.

Web UIs (`<suffix>` is `prod` or `local`):

| Service | URL |
|---|---|
| AI Config UI | `https://ai-config.<suffix>` |
| n8n | `https://n8n.<suffix>` |
| Pi-hole | `https://pihole.<suffix>` |
| Grafana | `https://grafana.<suffix>` |
| Portainer | `https://portainer.<suffix>` |
| Vault | `https://hashicorp_vault.<suffix>` |
| Browser sandbox | `https://sandbox.<suffix>` |
| Sandbox Pi-hole | `https://sandbox-dns.<suffix>` |

Add these names to your local DNS (Pi-hole → Local DNS records) pointing at the host.