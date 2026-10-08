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

All secrets live in `ansible/group_vars/all/vault.yml`, encrypted with ansible-vault. During deployment they are copied into HashiCorp Vault, where n8n reads them at runtime.

```yaml title="ansible/group_vars/all/vault.yml (decrypted)"
ansible_become_password: ""        # omit if the user has passwordless sudo

# Service logins
vault_pihole_admin_password: ""
vault_grafana_password: ""
vault_portainer_password: ""
vault_n8n_password: ""

# PostgreSQL
vault_postgres_root_password: ""
vault_postgres_password: ""
vault_ai_config_db_password: ""    # openssl rand -hex 24 (hex only)

# AI Config UI
vault_ai_ui_secret_key: ""         # openssl rand -hex 32
vault_ai_ui_users:                 # password (>= 12 chars) or werkzeug hash
  lukasz: ""

# API keys
vault_virus_total_token: ""
vault_abuse_api_key: ""            # abuse.ch: ThreatFox + URLhaus
vault_gemini_api_key: ""
vault_urlscanio_api_key: ""
vault_grafana_api_key: ""

# Email alerts (Gmail)
vault_n8n_user: ""                 # sender address
vault_n8n_gmail: ""                # Gmail app password
vault_n8n_alert_to: ""             # alert recipient (defaults to the sender)

# TLS: one cert/key pair per service behind Nginx
# pihole, n8n, grafana, portainer, firefox, hashicorp_vault, ai_config
vault_pihole_cert: |
  -----BEGIN CERTIFICATE-----
vault_pihole_key: |
  -----BEGIN PRIVATE KEY-----
# ...

# Filled in after the first run of playbook 06.1
vault_root_token: ""
vault_unseal_keys: []
```

Encrypt the file and keep the password in `ansible/.vault_pass` (ignored by git, referenced from `ansible.cfg`):

```bash
ansible-vault encrypt ansible/group_vars/all/vault.yml
echo "your_passphrase" > ansible/.vault_pass && chmod 600 ansible/.vault_pass
```

!!! danger "Vault keys are shown once"
The first run of playbook 06.1 initialises HashiCorp Vault and prints `vault_root_token` and `vault_unseal_keys` exactly once. Copy them into `vault.yml` straight away and keep an offline backup. Losing the unseal keys means losing all Vault data.

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
| 05 | `05_deploy_proxy.yml` | Nginx reverse proxy with TLS |
| 06.1 | `06_1_initialize_provision_vault.yml` | Vault init/unseal, secrets, n8n token, Pi-hole API password |
| 06.2 | `06_2_n8n_bootstrap.yml` | n8n community nodes and credentials |
| 07 | `07_setup_monitoring.yml` | SSD health metrics for Prometheus. Production only, run manually — not part of `00_main.yml`. |

Re-run a single step the same way:

```bash
ansible-playbook 04_3_db_postgres.yml --limit rpi5-prod
```

Order matters in two places: 04.1 must run before 04.2 (it stages the build contexts), and 04.5 must run after 04.3 (04.3 re-grants table privileges that 04.5 narrows again).

## Proxmox Restore (optional)

Playbook 00.1 is specific to the author's dev setup and is skipped everywhere else. To use it, add to `vault.yml`:

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

Web UIs (`<suffix>` is `prod` or `local`):

| Service | URL |
|---|---|
| AI Config UI | `https://ai-config.<suffix>` |
| n8n | `https://n8n.<suffix>` |
| Pi-hole | `https://pihole.<suffix>` |
| Grafana | `https://grafana.<suffix>` |
| Portainer | `https://portainer.<suffix>` |
| Vault | `https://hashicorp_vault.<suffix>` |
| Firefox (isolated browser) | `https://firefox.<suffix>` |

Add these names to your local DNS (Pi-hole → Local DNS records) pointing at the host.