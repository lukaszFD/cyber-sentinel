# Deployment Guide

This guide covers the complete deployment of **Cyber Sentinel** from a fresh Linux server to a fully operational stack. The entire process is automated through Ansible — a single master playbook (`00_main.yml`) orchestrates all steps in the correct order.

---

## Prerequisites

Before running any playbook, make sure your **control machine** (your laptop or workstation) meets the following requirements:

=== "Control machine"

    ```bash
    # Update the local package index to ensure we have the latest metadata
    sudo apt update
    
    # Install pipx to manage Python-based CLI applications in isolated environments
    sudo apt install pipx
    
    # Install Ansible along with its core dependencies using pipx for isolation
    pipx install --include-deps ansible
    
    # Inject specific Python libraries required for HashiCorp Vault (hvac) and Docker automation
    pipx inject ansible hvac docker
    ```

=== "Target server"

    The target machine must be a fresh Debian-based Linux server (Debian 11/12 or Raspberry Pi OS) accessible via SSH.

    | Requirement | Value |
    |-------------|-------|
    | OS | Debian 11 / 12 (or Raspberry Pi OS) |
    | Architecture | `x86_64` (amd64) or `aarch64` (arm64) |
    | SSH access | Key-based authentication required |
    | User | Must have `sudo` privileges |
    | Minimum RAM | 4 GB (8 GB recommended for local AI workloads) |
    | Minimum disk | 32 GB |

---

## Supported Architectures

Ansible automatically detects the target architecture and adjusts the Docker installation accordingly.

| Architecture | Docker tag | Typical hardware |
|---|---|---|
| `x86_64` | `amd64` | Standard PC / VM / cloud server |
| `aarch64` | `arm64` | Raspberry Pi 4 / 5, ARM server |


!!! note "Raspberry Pi 5 — Argon NEO 5"
If you are running on a **Raspberry Pi 5** with an **Argon NEO 5** case, playbook `03` automatically installs and configures the fan controller.

---

## Inventory Setup

Edit `ansible/hosts.ini` to point to your target server. The repository ships with three pre-configured environments:

```ini title="ansible/hosts.ini"
# --- PROD env ---
[rpi5-prod]
rpi5 ansible_host=192.168.XX.XX ansible_user=hunter

# --- DEV env ---
[vm-prox-dev]
dev_vm ansible_host=192.168.XX.XX ansible_user=hunter

# --- Local DEV VM env ---
[local-vm]
local_vm ansible_host=127.0.0.1 ansible_port=2222 ansible_user=hunter

[all_servers:children]
rpi5-prod
vm-prox-dev
local-vm
```

Use `-l` to target a specific environment: `ansible-playbook ... -l rpi5-prod`

For the full configuration reference (all_servers.yml, vault.yml, templates) see [→ Config Reference](ansible-00-config.md).

---

## Vault — Bootstrap Secrets

Cyber Sentinel uses **Ansible Vault** to protect all bootstrap secrets — sudo password, service passwords, database credentials, third-party API tokens, and TLS material for the Nginx reverse proxy. Before your first run you must provide values for the variables below in `ansible/group_vars/all/vault.yml`.

### Ansible controller — sudo password

Every playbook runs with `become: yes`, so Ansible needs the target user's sudo password unless that user has passwordless sudo (`NOPASSWD: ALL`) configured.

```yaml title="ansible/group_vars/all/vault.yml (decrypted view)"
ansible_become_password: "your_sudo_password_here"
```

When Ansible sees `ansible_become_password` in group vars it uses it automatically — no `--ask-become-pass` / `-K` flag needed.

!!! tip "Passwordless sudo alternative"
If you prefer not to store the sudo password at all, configure the deployment user for passwordless sudo on the target host:
`echo "hunter ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/hunter`.
Then `ansible_become_password` can be omitted from `vault.yml`.

### Service passwords

```yaml
vault_pihole_admin_password: ""
vault_grafana_password:      ""
vault_portainer_password:    ""
vault_n8n_password:          ""
```

### Database credentials

```yaml
vault_mysql_root_password: ""
vault_mysql_password:      ""
vault_mysql_app_user:      ""   # application username (typically "hunter")
vault_mongodb_password:    ""
```

### Third-party API tokens (CTI providers + AI)

```yaml
vault_virus_total_token:   ""
vault_abuse_api_key:       ""
vault_urlscanio_api_key:   ""
vault_gemini_api_key:      ""
vault_kali_gemini_api_key: ""
vault_grafana_api_key:     ""
```

### n8n SMTP alerting (Gmail)

```yaml
vault_n8n_gmail: ""   # Gmail app password
vault_n8n_user:  ""   # full Gmail address used as From: in alerts
```

### TLS certificates and keys (consumed by Nginx — playbook 05)

Playbook 05 fronts six services with Nginx, so you need one cert/key pair per service. Each variable follows the pattern `vault_<service>_cert` / `vault_<service>_key`:

```yaml
vault_pihole_cert:          ""
vault_pihole_key:           ""
vault_n8n_cert:             ""
vault_n8n_key:              ""
vault_grafana_cert:         ""
vault_grafana_key:          ""
vault_portainer_cert:       ""
vault_portainer_key:        ""
vault_firefox_cert:         ""
vault_firefox_key:          ""
vault_hashicorp_vault_cert: ""
vault_hashicorp_vault_key:  ""
```

### Vault keys (filled in after first run)

These two variables stay empty on a fresh install — they are generated by the first run of `06_initialize_provision_vault.yml` and printed exactly once. Save them immediately and paste them back into `vault.yml` (encrypted) so subsequent runs can auto-unseal:

```yaml
vault_root_token:  ""
vault_unseal_keys:
  - ""
  - ""
  - ""
```

!!! danger "These are unrecoverable"
If you lose `vault_unseal_keys` you lose all Vault data permanently — there is no recovery path. Back them up to an offline location (password manager, encrypted USB) the moment they are displayed.

### Encrypt the file

```bash
ansible-vault encrypt ansible/group_vars/all/vault.yml
```

Store the vault password in `ansible/.vault_pass` (this file is in `.gitignore`):

```bash
echo "your_vault_passphrase" > ansible/.vault_pass
chmod 600 ansible/.vault_pass
```

---

## Optional — Proxmox auto-restore for DEV

If you deploy Cyber Sentinel onto a Proxmox VE virtual machine and want each DEV deployment to start from a freshly restored snapshot, the repository ships with [`restore_proxmox.yml`](https://github.com/lukaszFD/cyber-sentinel/blob/main/ansible/restore_proxmox.yml). The master playbook imports it as the very first step, but it self-skips unless `--limit` targets the dev VM group (`vm-prox-dev` or `dev_vm`).

This is **entirely optional**. If you run on another hypervisor, a Raspberry Pi, or anywhere except Proxmox, leave the variables below undefined and the play will simply be skipped — nothing else in the pipeline depends on it.

### Required variables (only when restoring from Proxmox)

Add these to `ansible/group_vars/all/vault.yml`:

```yaml title="ansible/group_vars/all/vault.yml (decrypted view)"
proxmox_host:       "10.10.10.5"                  # Proxmox VE host or IP
proxmox_user_token: "ansible@pve!deploy-token"    # format: user@realm!tokenid
proxmox_api_secret: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

| Variable | Description |
|---|---|
| `proxmox_host` | Hostname or IP of the Proxmox VE node (port 8006 is used automatically) |
| `proxmox_user_token` | Full token ID in the `user@realm!tokenid` format expected by the Proxmox API |
| `proxmox_api_secret` | Token secret value (UUID-shaped string shown once at token creation) |

### Required Proxmox API token privileges

The token must have the following privileges on the target VM and backup storage. For a home lab the simplest path is to grant `PVEAdmin` on `/` with **Privilege Separation OFF** when creating the token — that covers everything below in one go.

- On VM path (`/vms/<vmid>`): `VM.Audit`, `VM.PowerMgmt`, `VM.Backup`, `VM.Allocate`, `VM.Config.Disk`, `VM.Config.HWType`, `VM.Config.Memory`, `VM.Config.CPU`, `VM.Config.Network`, `VM.Config.Options`
- On storage path (`/storage/<storage>`): `Datastore.Audit`, `Datastore.AllocateSpace`

See the playbook header in [`restore_proxmox.yml`](https://github.com/lukaszFD/cyber-sentinel/blob/main/ansible/restore_proxmox.yml) for the full list of error messages and their root causes.

### Triggering the restore

The restore runs automatically as part of the master playbook when the DEV VM is in scope:

```bash
# Triggers Proxmox restore + full deployment on DEV
ansible-playbook ansible/00_main.yml --limit vm-prox-dev

# Skips Proxmox restore, deploys to production RPi5
ansible-playbook ansible/00_main.yml --limit rpi5-prod
```

---

## Running the Full Deployment

Execute the master playbook to run all steps end-to-end:

```bash
ansible-playbook ansible/00_main.yml \
  -i ansible/hosts.ini \
  --vault-password-file ansible/.vault_pass
```

This single command runs all playbooks in sequence:

```yaml title="ansible/00_main.yml"
- import_playbook: 01_setup_secrets.yml
- import_playbook: 02_setup_security.yml
- import_playbook: 03_setup_system.yml
- import_playbook: 04_1_prepare_stack.yml
- import_playbook: 04_2_deploy_containers.yml
- import_playbook: 04_3_db_create.yml
- import_playbook: 04_4_post_config.yml
# This module is currently under testing and not yet fully deployed
#- import_playbook: 04_5_deploy_AI.yml
- import_playbook: 05_deploy_proxy.yml
- import_playbook: 06_initialize_provision_vault.yml
```

---

## Common Run Patterns

The full-deployment command shown above is one of several equivalent forms. All three patterns below are valid — pick whichever fits your shell habits.

### From the repo root (most explicit)

```bash
ansible-playbook ansible/00_main.yml \
  -i ansible/hosts.ini \
  --vault-password-file ansible/.vault_pass
```

### From the `ansible/` directory (shortest)

`ansible/ansible.cfg` is auto-loaded when you run from inside that directory, and it already defines `inventory = hosts.ini` and `vault_password_file = .../.vault_pass`. Both flags become optional:

```bash
cd ansible/
ansible-playbook 00_main.yml
```

### From a Python virtualenv (instead of pipx / system Ansible)

If you installed Ansible into a venv rather than via `pipx`, call the binary by its absolute path:

```bash
cd ~/IdeaProjects/cyber-sentinel/ansible
~/ansible_mint_venv/bin/ansible-playbook -i hosts.ini 00_main.yml --limit dev_vm
```

### Targeting a specific host or group with `--limit`

`--limit` accepts either a **host alias** (left-hand column in `hosts.ini`) or a **group name** (header in square brackets). Both forms are valid:

| Target type | Example | Matches |
|---|---|---|
| Host alias | `--limit dev_vm` | The single `dev_vm` line in `[vm-prox-dev]` |
| Group name | `--limit vm-prox-dev` | All hosts in the `[vm-prox-dev]` group |
| Multiple | `--limit dev_vm,rpi5` | Comma-separated list |

```bash
# Deploy only to the dev VM (host alias)
ansible-playbook 00_main.yml --limit dev_vm

# Deploy only to production (group name)
ansible-playbook 00_main.yml --limit rpi5-prod
```

!!! note "Proxmox restore and --limit"
The optional [Proxmox auto-restore step](#optional-proxmox-auto-restore-for-dev) only fires when `--limit` matches `vm-prox-dev` or `dev_vm`. Any other target — or no `--limit` at all in a non-DEV inventory — skips the restore cleanly.

---

## Deployment Pipeline

The full deployment consists of **9 playbooks** executed in order. Each playbook is self-contained and can also be run individually for partial re-deployments.

| Step | Playbook | Description                              | Details |
|------|----------|------------------------------------------|---------|
| 1 | `01_setup_secrets.yml` | Generate `.env` from Ansible Vault secrets | [→ Playbook 01](ansible-01-secrets.md) |
| 2 | `02_setup_security.yml` | Configure UFW firewall rules             | [→ Playbook 02](ansible-02-security.md) |
| 3 | `03_setup_system.yml` | Install Docker Engine + system packages  | [→ Playbook 03](ansible-03-system.md) |
| 4 | `04_1_prepare_stack.yml` | Create directories, copy configs and Dockerfiles | [→ Playbook 04.1](ansible-04-stack.md) |
| 5 | `04_2_deploy_containers.yml` | Pull images and start Docker Compose stack | [→ Playbook 04.2](ansible-04-stack.md#42-deploy-containers) |
| 6 | `04_3_db_create.yml` | Initialize MySQL schema and users        | [→ Playbook 04.3](ansible-04-db.md) |
| 7 | `04_4_post_config.yml` | Post-start: Fail2Ban, Pi-hole, accounts  | [→ Playbook 04.4](ansible-04-post-config.md) |
| 7.5 | `04_5_deploy_AI.yml` | Deploy Ollama + local AI models (optional) | [→ Playbook 04.5](ansible-04-ai.md) |
| 8 | `05_deploy_proxy.yml` | Deploy Nginx reverse proxy + SSL certificates | [→ Playbook 05](ansible-05-proxy.md) |
| 9 | `06_initialize_provision_vault.yml` | Initialize and provision HashiCorp Vault | [→ Playbook 06](ansible-06-vault.md) |

---

## Running Individual Playbooks

You can re-run any single playbook without going through the full pipeline:

```bash
# Example: re-deploy only the Docker stack
ansible-playbook ansible/04_2_deploy_containers.yml \
  -i ansible/hosts.ini \
  --vault-password-file ansible/.vault_pass

# Example: re-apply firewall rules only
ansible-playbook ansible/02_setup_security.yml \
  -i ansible/hosts.ini \
  --vault-password-file ansible/.vault_pass
```

---

## Firewall — Open Ports After Deployment

After playbook `02` completes, the following ports are open on the target server:

| Port | Protocol | Service |
|------|----------|---------|
| `22` | TCP | SSH management |
| `80` | TCP | Nginx HTTP (redirect to HTTPS) |
| `443` | TCP | Nginx HTTPS reverse proxy |
| `53` | UDP | Pi-hole DNS |
| `53` | TCP | Pi-hole DNS |

All other incoming traffic is **denied by default** (UFW default policy: `deny`).

---

## Post-Deployment Access

Once the full pipeline completes, services are accessible via the Nginx reverse proxy using subdomains of your configured `domain_suffix`:

| Service | URL |
|---------|-----|
| n8n | `https://n8n.<domain_suffix>` |
| Grafana | `https://grafana.<domain_suffix>` |
| Portainer | `https://portainer.<domain_suffix>` |
| Vault UI | `https://vault.<domain_suffix>` |