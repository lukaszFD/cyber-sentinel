# 🔐 Ansible Vault Management guide

This guide explains how to manage sensitive secrets for the **Cyber AI Sentinel** project using Ansible Vault.

## 🛠 Required Secrets Structure

The following variables must be defined in `ansible/group_vars/all/vault.yml`. These secrets are crucial for the automated deployment and the **HashiCorp Vault** provisioning process.

### 1. Credentials & Tokens
| Variable | Description |
| :--- | :--- |
| `ansible_become_password` | Sudo password for the remote host (VM/RPi) |
| `vault_mysql_app_user` | Application user for MySQL (e.g., `hunter`) |
| `vault_mysql_password` | Password for the application MySQL user |
| `vault_mysql_root_password`| Root password for MySQL 8.0 container |
| `vault_mongodb_password` | Password for MongoDB threat data lake |
| `vault_pihole_admin_password`| Web UI password for Pi-hole |
| `vault_n8n_password` | Owner account password for n8n |
| `vault_grafana_password` | Admin password for Grafana |
| `vault_portainer_password` | Admin password for Portainer |
| `vault_root_token` | Initial Root Token for HashiCorp Vault |
| `vault_virus_total_token` | API Key for VirusTotal enrichment |

### 2. SSL Certificates (Jinja2 Multi-line)
For each service (`n8n`, `pihole`, `hashicorp_vault`, `grafana`, `portainer`, `firefox`), you must provide:
* `vault_<service_name>_cert`: Full chain certificate in PEM format.
* `vault_<service_name>_key`: Private key in PEM format.

---

## ⌨️ Operational Commands

All commands assume you are using the virtual environment on your Linux Mint laptop.

### 1. Edit the Vault
Use this command to modify passwords or update certificates:
```bash
EDITOR=nano ~/ansible_mint_venv/bin/ansible-vault edit ansible/group_vars/all/vault.yml --vault-password-file ansible/.vault_pass