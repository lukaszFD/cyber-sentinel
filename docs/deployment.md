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
If you are running on a **Raspberry Pi 5** with an **Argon NEO 5** case, playbook `03` automatically installs and configures the fan controller with thresholds optimised for AI workloads (`55°C → 50%`, `65°C → 100%`).

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

Cyber Sentinel uses **Ansible Vault** to protect bootstrap secrets (passwords injected into `.env` before containers start). Before your first run you must provide values for the following variables in `ansible/group_vars/all/vault.yml`:

```yaml title="ansible/group_vars/all/vault.yml (decrypted view)"
vault_grafana_password: "your_grafana_password"
vault_mongodb_password: "your_mongodb_password"
vault_mysql_root_password: "your_mysql_root_password"
```

Encrypt the file:

```bash
ansible-vault encrypt ansible/group_vars/all/vault.yml
```

Store the vault password in `ansible/.vault_pass` (this file is in `.gitignore`):

```bash
echo "your_vault_passphrase" > ansible/.vault_pass
chmod 600 ansible/.vault_pass
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