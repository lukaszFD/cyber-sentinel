# 🔐 Ansible Vault Management Guide

This guide explains how to manage sensitive secrets for the **Cyber AI Sentinel** project using Ansible Vault.

## 🛠 Required Secrets Structure

The following variables must be defined in `ansible/group_vars/all/vault.yml`. These secrets are crucial for both the automated infrastructure deployment and the **HashiCorp Vault** provisioning process.

### 1. Infrastructure & App Credentials
| Variable | Description                                  |
| :--- |:---------------------------------------------|
| `ansible_become_password` | Sudo password for the remote host (VM/RPi).  |
| `vault_mysql_app_user` | Application user for MySQL (e.g., `hunter`). |
| `vault_mysql_password` | Password for the application MySQL user.     |
| `vault_mysql_root_password`| Root password for MySQL 8.0 container.       |
| `vault_mongodb_password` | Password for MongoDB threat data lake.       |
| `vault_pihole_admin_password`| Web UI password for Pi-hole.                 |
| `vault_n8n_password` | Owner account password for n8n.              |
| `vault_grafana_password` | Admin password for Grafana.                  |
| `vault_portainer_password` | Admin password for Portainer.                |
| `vault_virus_total_token` | API Key for VirusTotal enrichment.           |
| `vault_gemini_api_key`    | API Key for AI workflow.                     |
| `vault_root_token`    | HashiCorp Vault Root key.                    |
| `vault_unseal_keys`    | Keys to unseal HashiCorp Vault - a list of three                    |


### 2. HashiCorp Vault Management Keys
These keys are required for the automated unsealing and provisioning of the HashiCorp Vault container.
| Variable | Description |
| :--- | :--- |
| `vault_unseal_key` | The key used to unseal HashiCorp Vault (Shamir's key). |
| `vault_root_token` | Initial Root Token for HashiCorp Vault API. |

### 3. SSL Certificates (Jinja2 Multi-line)
For each service (`n8n`, `pihole`, `hashicorp_vault`, `grafana`, `portainer`, `firefox`), provide:
* `vault_<service_name>_cert`: Full chain certificate in PEM format.
* `vault_<service_name>_key`: Private key in PEM format.

---

## 🚀 HashiCorp Vault Setup (Lifecycle)

Since HashiCorp Vault is managed outside the main deployment flow, the initialization process is as follows:

### Step 1: Infrastructure Deployment
Run your main playbook. Docker Compose will create the `hashicorp_vault` container, but it will start in a **Sealed** state with no data.

### Step 2: Manual Initialization (One-time only)
Connect to the server and initialize Vault to obtain the master keys and root token:
```bash
docker exec -it hashicorp_vault vault operator init