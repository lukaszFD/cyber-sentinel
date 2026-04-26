# Ansible Configuration Reference

This page documents all static configuration files used by the Ansible layer of Cyber Sentinel. These files define the runtime environment, target hosts, global variables, and Jinja2 templates that the playbooks depend on.

```text
ansible/
├── ansible.cfg                     # Ansible runtime settings
├── hosts.ini                       # Inventory — target environments
├── group_vars/
│   └── all/
│       ├── all_servers.yml         # Non-sensitive global variables
│       └── vault.yml               # 🔐 Ansible Vault encrypted secrets
└── templates/
    ├── env.j2                      # Docker .env file template
    └── nginx_service.conf.j2       # Per-service Nginx proxy config template
```

---

## 1. ansible.cfg

**Path:** `ansible/ansible.cfg`

The Ansible runtime configuration file. Sets default inventory, disables SSH host key verification for internal hosts, and points to the Vault password file for automatic secret decryption.

```ini title="ansible/ansible.cfg" linenums="1"
[defaults]
inventory = hosts.ini
host_key_checking = False
interpreter_python = auto_silent
vault_password_file = /home/hunter/IdeaProjects/cyber-sentinel/ansible/.vault_pass
```

| Parameter | Value | Description |
|-----------|-------|-------------|
| `inventory` | `hosts.ini` | Default inventory file loaded automatically |
| `host_key_checking` | `False` | Skips SSH fingerprint verification for internal/dev hosts |
| `interpreter_python` | `auto_silent` | Auto-detects Python interpreter without warnings |
| `vault_password_file` | `.vault_pass` | Path to the file containing the Ansible Vault passphrase |

!!! warning "vault_password_file path"
The `vault_password_file` path is absolute and points to the **control machine** (Linux Mint). If you clone the repository to a different path or user, update this value before running any playbook. The `.vault_pass` file must exist and must not be committed to version control.

---

## 2. hosts.ini

**Path:** `ansible/hosts.ini`

The Ansible inventory file. Defines three target environments: production Raspberry Pi 5, a Proxmox development VM, and a local VM accessible via SSH port forwarding. All three environments are collected under the `all_servers` parent group used by every playbook.

```ini title="ansible/hosts.ini" linenums="1"
# --- PROD env ---
[rpi5-prod]
rpi5 ansible_host=192.168.XX.XX ansible_user=hunter

# --- DEV env ---
[vm-prox-dev]
dev_vm ansible_host=192.168.XX.XX ansible_user=hunter

# --- Local DEV VM env ---
[local-vm]
local_vm ansible_host=127.0.0.1 ansible_port=2222 ansible_user=hunter

# --- Group combining all hosts ---
[all_servers:children]
rpi5-prod
vm-prox-dev
local-vm
```

### Environments

| Group | Host alias | IP              | Port | Description |
|-------|----------|-----------------|------|-------------|
| `rpi5-prod` | `rpi5` | `192.168.XX.XX` | `22` | Production — Raspberry Pi 5 |
| `vm-prox-dev` | `dev_vm` | `192.168.XX.XX` | `22` | Development — Proxmox VM |
| `local-vm` | `local_vm` | `127.0.0.1`     | `2222` | Local VM via SSH port forward |
| `all_servers` | *(parent)* | —               | — | All three environments combined |

!!! note "domain_suffix logic"
In playbook `05_deploy_proxy.yml`, the variable `domain_suffix` is set to `local` when the target host is in the `vm-prox-dev` group, and `prod` otherwise. This controls which subdomain pattern Nginx uses for SSL virtual hosts.

### Targeting a specific environment

You can limit execution to a single environment by passing `-l` (limit) to `ansible-playbook`:

```bash
# Run only on production RPi 5
ansible-playbook ansible/00_main.yml -i ansible/hosts.ini -l rpi5-prod \
  --vault-password-file ansible/.vault_pass

# Run only on the dev VM
ansible-playbook ansible/00_main.yml -i ansible/hosts.ini -l vm-prox-dev \
  --vault-password-file ansible/.vault_pass
```

---

## 3. group_vars/all/all_servers.yml

**Path:** `ansible/group_vars/all/all_servers.yml`

Non-sensitive global variables shared across all hosts and all playbooks. Loaded automatically by Ansible before any playbook runs. Defines paths, usernames, database parameters, and service account names.

```yaml title="ansible/group_vars/all/all_servers.yml" linenums="1"
# Local source directory on the controller host (Linux Mint)
main_repo_source_dir: "/home/hunter/IdeaProjects/cyber-sentinel"

# Base directory on the remote host for deployment
remote_deploy_base: "/home/{{ ansible_user }}"

# Owner and group for all copied files and directories
deployment_user: "{{ ansible_user }}"

# MongoDB
mongodb_username: "hunter"

# MySQL
mysql_host: "mysqldb"
mysql_user: "hunter"
mysql_database: "cyber_intelligence"

# Service admin accounts
portainer_admin_user: "admin_sentinel"
n8n_admin_user: "n8n_manager"
n8n_admin_email: "hunter@cyber-sentinel.local"

# Vault-related references
vault_mysql_database: "{{ mysql_database }}"
vault_mysql_app_user: "{{ mysql_user }}"
vault_address: "10.10.10.12"
```

### Variable reference

| Variable | Value | Used by |
|----------|-------|---------|
| `main_repo_source_dir` | `/home/hunter/IdeaProjects/cyber-sentinel` | All `copy` and `template` tasks — source path on controller |
| `remote_deploy_base` | `/home/{{ ansible_user }}` | All tasks — root path on target server |
| `deployment_user` | `{{ ansible_user }}` | File ownership for all copied files |
| `mongodb_username` | `hunter` | `env.j2` → `MONGODB_USERNAME` |
| `mysql_host` | `mysqldb` | `env.j2` → `MYSQL_HOST` (Docker service name) |
| `mysql_user` | `hunter` | `env.j2` → `MYSQL_USER`, Vault provisioning |
| `mysql_database` | `cyber_intelligence` | `env.j2` → `MYSQL_DATABASE` |
| `portainer_admin_user` | `admin_sentinel` | Playbook `04_4` — Portainer API init |
| `n8n_admin_user` | `n8n_manager` | Playbook `04_4` — n8n API init, Vault provisioning |
| `n8n_admin_email` | `hunter@cyber-sentinel.local` | Playbook `04_4` — n8n owner account |
| `vault_address` | `10.10.10.12` | Vault container IP reference |

!!! note "main_repo_source_dir"
This path points to the repository on the **control machine** (the machine running `ansible-playbook`). If you clone the repository to a different path, update this variable before running any playbook.

---

## 4. group_vars/all/vault.yml

**Path:** `ansible/group_vars/all/vault.yml`

Ansible Vault encrypted file containing all sensitive secrets. Never stored in plaintext. Loaded automatically alongside `all_servers.yml`. The actual values are decrypted at runtime using the passphrase from `.vault_pass`.

```bash
# Encrypt the file (first time)
ansible-vault encrypt ansible/group_vars/all/vault.yml

# Edit secrets interactively
ansible-vault edit ansible/group_vars/all/vault.yml

# View decrypted content
ansible-vault view ansible/group_vars/all/vault.yml
```

### Required variables

All variables prefixed with `vault_` must be defined in this file:

| Variable | Used in | Description |
|----------|---------|-------------|
| `vault_mongodb_password` | `env.j2`, `04_1`, `06_2` | MongoDB root password |
| `vault_mysql_password` | `env.j2`, `06_2` | MySQL application user password |
| `vault_mysql_root_password` | `env.j2`, `04_3`, `06_2` | MySQL root password |
| `vault_grafana_password` | `env.j2`, `04_1`, `06_2` | Grafana admin password |
| `vault_root_token` | `env.j2`, `06_2` | HashiCorp Vault root token (after init) |
| `vault_pihole_admin_password` | `04_4`, `06_2` | Pi-hole web UI password |
| `vault_portainer_password` | `04_4`, `06_2` | Portainer admin password |
| `vault_n8n_password` | `04_4`, `06_2` | n8n owner account password |
| `vault_n8n_gmail` | `06_2` | Gmail app password for n8n alerting |
| `vault_unseal_keys` | `06_2` | List of Vault unseal keys (from `06_1` init output) |
| `vault_virus_total_token` | `06_2` | VirusTotal API token |
| `vault_gemini_api_key` | `06_2` | Google Gemini API key (home network) |
| `vault_kali_gemini_api_key` | `06_2` | Google Gemini API key (Kali environment) |
| `vault_abuse_api_key` | `06_2` | Abuse.ch API key (ThreatFox + URLHaus) |
| `vault_grafana_api_key` | `06_2` | Grafana API key |
| `vault_urlscanio_api_key` | `06_2` | urlscan.io API key |
| `vault_<name>_cert` | `05`, `06_2` | SSL certificate PEM for each proxied service |
| `vault_<name>_key` | `05`, `06_2` | SSL private key PEM for each proxied service |

!!! warning "vault_unseal_keys and vault_root_token"
These two variables are only available **after** running playbook `06_1_initialize_vault.yml` for the first time. Save the `vault operator init` output immediately, then add these values to `vault.yml` before running `06_2_provision_vault.yml`.

---

## 5. templates/env.j2

**Path:** `ansible/templates/env.j2`

Jinja2 template rendered by playbook `01_setup_secrets.yml` (Task 1.1) into `.env` at the deployment root. This file is consumed by Docker Compose to inject environment variables into all containers at startup.

```jinja title="ansible/templates/env.j2" linenums="1"
# MongoDB
MONGODB_PASSWORD={{ vault_mongodb_password }}
MONGODB_USERNAME={{ mongodb_username }}

# MySQL
MYSQL_HOST={{ mysql_host }}
MYSQL_USER={{ mysql_user }}
MYSQL_PASSWORD={{ vault_mysql_password }}
MYSQL_DATABASE={{ mysql_database }}
MYSQL_ROOT_PASSWORD={{ vault_mysql_root_password }}

# Grafana
GRAFANA_PASSWORD={{ vault_grafana_password }}

# HashiCorp Vault
VAULT_ROOT_TOKEN={{ vault_root_token }}
```

### Variable mapping

| `.env` key | Jinja2 source | Origin |
|---|---|---|
| `MONGODB_PASSWORD` | `vault_mongodb_password` | `vault.yml` (encrypted) |
| `MONGODB_USERNAME` | `mongodb_username` | `all_servers.yml` |
| `MYSQL_HOST` | `mysql_host` | `all_servers.yml` — Docker service name `mysqldb` |
| `MYSQL_USER` | `mysql_user` | `all_servers.yml` |
| `MYSQL_PASSWORD` | `vault_mysql_password` | `vault.yml` (encrypted) |
| `MYSQL_DATABASE` | `mysql_database` | `all_servers.yml` — `cyber_intelligence` |
| `MYSQL_ROOT_PASSWORD` | `vault_mysql_root_password` | `vault.yml` (encrypted) |
| `GRAFANA_PASSWORD` | `vault_grafana_password` | `vault.yml` (encrypted) |
| `VAULT_ROOT_TOKEN` | `vault_root_token` | `vault.yml` (encrypted) |

!!! note "File permissions"
The rendered `.env` file is written with `mode: '0600'` by playbook `01`. The same restriction is enforced again in playbook `04_1` via `lineinfile`. Never commit the rendered `.env` to version control — it is listed in `.gitignore`.

---

## 6. templates/nginx_service.conf.j2

**Path:** `ansible/templates/nginx_service.conf.j2`

Jinja2 template rendered once per proxied service by playbook `05_deploy_proxy.yml` (Task 5.3). Produces a dedicated Nginx server block file (`<service_name>.conf`) in `config/nginx/conf.d/` for each entry in the `services` list variable.

```nginx title="ansible/templates/nginx_service.conf.j2" linenums="1"
server {
    listen 80;
    server_name {{ item.name }}.{{ domain_suffix }};
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name {{ item.name }}.{{ domain_suffix }};

    ssl_certificate     /etc/nginx/certs/{{ item.name }}.crt;
    ssl_certificate_key /etc/nginx/certs/{{ item.name }}.key;

    resolver 127.0.0.11 valid=30s;

    location / {
        resolver 127.0.0.11 valid=30s;
        set $upstream_host {{ item.internal_host }};
        proxy_pass http://$upstream_host:{{ item.port }};

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (required for n8n and Portainer)
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "Upgrade";
    }
}
```

### Template variable mapping

| Jinja2 variable | Source | Example value |
|---|---|---|
| `item.name` | `services` list in `05_deploy_proxy.yml` | `n8n`, `grafana`, `pihole` |
| `item.internal_host` | `services` list | `n8n-server`, `grafana`, `pihole` |
| `item.port` | `services` list | `5678`, `3000`, `80` |
| `domain_suffix` | Computed in `05_deploy_proxy.yml` | `local` (dev) or `prod` |

### Generated output example

For service `n8n` in a dev environment (`domain_suffix=local`), the template produces `config/nginx/conf.d/n8n.conf`:

```nginx title="generated: config/nginx/conf.d/n8n.conf"
server {
    listen 80;
    server_name n8n.local;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name n8n.local;

    ssl_certificate     /etc/nginx/certs/n8n.crt;
    ssl_certificate_key /etc/nginx/certs/n8n.key;

    resolver 127.0.0.11 valid=30s;

    location / {
        resolver 127.0.0.11 valid=30s;
        set $upstream_host n8n-server;
        proxy_pass http://n8n-server:5678;

        proxy_set_header Host              n8n.local;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "Upgrade";
    }
}
```

!!! note "DNS resolver 127.0.0.11"
The `resolver 127.0.0.11` directive points to Docker's internal DNS resolver. Using `set $upstream_host` with a variable (instead of a hardcoded `proxy_pass`) forces Nginx to re-resolve the hostname at request time rather than at startup — this prevents Nginx from failing to start if the upstream container is not yet running.

!!! note "WebSocket support"
The `Upgrade` and `Connection` headers are required for services that use WebSockets. In this stack, both **n8n** (real-time workflow execution UI) and **Portainer** (live container log streaming) depend on WebSocket connections.