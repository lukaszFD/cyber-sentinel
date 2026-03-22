# Playbook 06 — HashiCorp Vault Setup

This page covers the two Vault playbooks that together initialize and fully provision the secrets backend for the Cyber Sentinel stack.

---

## 6.1 Initialize Vault

**File:** `ansible/06_1_initialize_vault.yml`  
**Hosts:** `all_servers`  
**Privilege escalation:** No (`become` not set)

Checks whether the Vault instance is already initialized and, if not, runs `vault operator init` to generate the unseal keys and root token. This playbook must run **once** on a fresh Vault instance. On subsequent runs it detects the initialized state and skips the init task.

### Overview

| Property | Value |
|----------|-------|
| Playbook file | `ansible/06_1_initialize_vault.yml` |
| Target hosts | `all_servers` |
| Vault URL | `http://{{ ansible_host }}:8200` |
| Idempotent | Yes — checks `initialized` flag before acting |

---

### Task 0.0 — Check if Vault is initialized

Queries the Vault `/v1/sys/init` endpoint. The response contains `{ "initialized": true/false }` which is used to conditionally skip the init step.

```yaml title="ansible/06_1_initialize_vault.yml" linenums="1"
- name: Task 0.0 - Check if Vault is initialized
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/sys/init"
    method: GET
  register: vault_init_status
```

---

### Task 0.1 — Initialize Vault (only if new)

Runs `vault operator init -format=json` inside the container only when `initialized` is `false`. The output contains the **unseal keys** and **root token** — these must be saved immediately and stored securely in Ansible Vault.

```yaml title="ansible/06_1_initialize_vault.yml" linenums="1"
- name: Task 0.1 - Initialize Vault (ONLY IF NEW)
  ansible.builtin.shell:
    cmd: "docker exec hashicorp_vault vault operator init -format=json"
  register: vault_init_output
  when: not (vault_init_status.json.initialized)
  no_log: false
```

!!! warning "Save the init output immediately"
    The `vault operator init` output contains **5 unseal keys** and the **root token**. This information is only shown once. Copy the output, encrypt it with `ansible-vault encrypt_string`, and store the values in `group_vars/all/vault.yml` as `vault_unseal_keys` and `vault_root_token` before running playbook `06_2`.

---

### Task — DEBUG: Show keys (temporary)

Prints the init output to the Ansible console. This task is present during initial setup only — remove or comment it out after saving the keys.

```yaml title="ansible/06_1_initialize_vault.yml" linenums="1"
- name: DEBUG - Show Keys (Temporary)
  ansible.builtin.debug:
    var: vault_init_output.stdout_lines
  when: vault_init_output.changed
```

---

### Full Playbook 06.1

```yaml title="ansible/06_1_initialize_vault.yml" linenums="1"
---
- name: Initialize HashiCorp Vault
  hosts: all_servers
  vars:
    vault_url: "http://{{ ansible_host }}:8200"

  tasks:
    - name: Task 0.0 - Check if Vault is initialized
      ansible.builtin.uri:
        url: "{{ vault_url }}/v1/sys/init"
        method: GET
      register: vault_init_status

    - name: Task 0.1 - Initialize Vault (ONLY IF NEW)
      ansible.builtin.shell:
        cmd: "docker exec hashicorp_vault vault operator init -format=json"
      register: vault_init_output
      when: not (vault_init_status.json.initialized)
      no_log: false

    - name: DEBUG - Show Keys (Temporary)
      ansible.builtin.debug:
        var: vault_init_output.stdout_lines
      when: vault_init_output.changed
```

---

## 6.2 Provision Vault

**File:** `ansible/06_2_provision_vault.yml`  
**Hosts:** `all_servers`  
**Privilege escalation:** No (`become` not set)

Unseals Vault if needed, enables the KV v2 secrets engine, and writes all secrets required by the Cyber Sentinel stack via the Vault HTTP API. All write operations use `no_log: true`.

### Overview

| Property | Value |
|----------|-------|
| Playbook file | `ansible/06_2_provision_vault.yml` |
| Target hosts | `all_servers` |
| Vault URL | `http://{{ ansible_host }}:8200` |
| Secrets engine | KV v2 at path `secret/` |
| Auth method | Root token (`vault_root_token`) |

---

### Task 0.1 — Check Vault health

Calls `/v1/sys/health`. The response status indicates Vault's state:

```yaml title="ansible/06_2_provision_vault.yml" linenums="1"
- name: Task 0.1 - Check Vault Health
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/sys/health"
    status_code: [200, 429, 501, 503]
  register: vault_health
```

| HTTP Status | Vault state |
|-------------|-------------|
| `200` | Initialized, unsealed, active |
| `429` | Standby node |
| `501` | Not initialized |
| `503` | **Sealed** — unseal required |

---

### Task 0.2 — Auto-unseal Vault

If health returns `503` (sealed), iterates over `vault_unseal_keys` and submits each key to the unseal API. Vault requires a quorum of keys (default: 3 of 5) to unseal.

```yaml title="ansible/06_2_provision_vault.yml" linenums="1"
- name: Task 0.2 - Auto-Unseal Vault (Multiple Keys)
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/sys/unseal"
    method: POST
    body: { key: "{{ item }}" }
    body_format: json
  loop: "{{ vault_unseal_keys }}"
  when: vault_health.status == 503
  no_log: true
```

---

### Task 1.1 — Enable KV secrets engine

Mounts the KV v2 secrets engine at `secret/`. Returns `400` if already mounted — this is treated as success for idempotency.

```yaml title="ansible/06_2_provision_vault.yml" linenums="1"
- name: Task 1.1 - Ensure KV Secrets Engine is enabled
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/sys/mounts/secret"
    method: POST
    headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
    body: { type: "kv", options: { version: "2" } }
    body_format: json
    status_code: [200, 204, 400]
```

---

### API Tokens Written to Vault

All external CTI and service API tokens are written to Vault under the `cyber-sentinel/api-keys/` path:

| Vault path | Variable | Service |
|---|---|---|
| `cyber-sentinel/api-keys/virustotal` | `vault_virus_total_token` | VirusTotal IP/domain scans |
| `cyber-sentinel/api-keys/gemini/home-network-guardian` | `vault_gemini_api_key` | Google Gemini AI analysis |
| `cyber-sentinel/api-keys/gemini/kali-linux` | `vault_kali_gemini_api_key` | Gemini for Kali environment |
| `cyber-sentinel/api-keys/abuse/api-key` | `vault_abuse_api_key` | Abuse.ch (ThreatFox + URLHaus) |
| `cyber-sentinel/api-keys/grafana/api-key` | `vault_grafana_api_key` | Grafana API |
| `cyber-sentinel/api-keys/urlscanio/api-key` | `vault_urlscanio_api_key` | urlscan.io |

```yaml title="ansible/06_2_provision_vault.yml" linenums="1"
- name: Task 2.0 - Write VirusTotal Token
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/api-keys/virustotal"
    method: POST
    headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
    body: { data: { token: "{{ vault_virus_total_token }}" } }
    body_format: json
    status_code: [200, 204]
  no_log: true
```

---

### SSL Certificates Written to Vault

Certificate and key pairs for three services are stored in Vault for use by the Nginx reverse proxy playbook:

```yaml title="ansible/06_2_provision_vault.yml" linenums="1"
- name: Task 2.6 - Write Certificates for Services
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/certs/{{ item.name }}"
    method: POST
    headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
    body:
      data:
        cert: "{{ lookup('vars', 'vault_' + item.name + '_cert') }}"
        key:  "{{ lookup('vars', 'vault_' + item.name + '_key') }}"
    body_format: json
    status_code: [200, 204]
  loop:
    - { name: "pihole" }
    - { name: "n8n" }
    - { name: "grafana" }
  no_log: true
```

---

### Application Credentials Written to Vault

All service passwords and database credentials are stored under `cyber-sentinel/credentials/`:

| Vault path | User variable | Service |
|---|---|---|
| `credentials/pihole` | — | Pi-hole web UI |
| `credentials/grafana` | — | Grafana admin |
| `credentials/portainer` | `portainer_admin_user` | Portainer admin |
| `credentials/n8n` | `n8n_admin_user` | n8n owner account |
| `credentials/mysql/root` | `root` | MySQL root |
| `credentials/mysql/app_manager` | `vault_mysql_app_user` | MySQL application user |
| `credentials/mongodb/admin` | `admin` | MongoDB root |
| `credentials/gmail/l94524506` | `l94524506` | Gmail credentials for n8n alerting |

```yaml title="ansible/06_2_provision_vault.yml" linenums="1"
- name: Task 3.0 - Provision Separated Application Secrets
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/credentials/{{ item.path }}"
    method: POST
    headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
    body:
      data:
        user: "{{ item.user | default('admin') }}"
        password: "{{ item.value }}"
    body_format: json
    status_code: [200, 204]
  no_log: true
  loop:
    - { path: "pihole",          value: "{{ vault_pihole_admin_password }}" }
    - { path: "grafana",         value: "{{ vault_grafana_password }}" }
    - { path: "portainer",       value: "{{ vault_portainer_password }}", user: "{{ portainer_admin_user }}" }
    - { path: "n8n",             value: "{{ vault_n8n_password }}",       user: "{{ n8n_admin_user }}" }
    - { path: "mysql/root",      value: "{{ vault_mysql_root_password }}", user: "root" }
    - { path: "mysql/app_manager",value: "{{ vault_mysql_password }}",    user: "{{ vault_mysql_app_user }}" }
    - { path: "mongodb/admin",   value: "{{ vault_mongodb_password }}",   user: "admin" }
    - { path: "gmail/l94524506", value: "{{ vault_n8n_gmail }}",          user: "l94524506" }
```

---

### Full Playbook 06.2

```yaml title="ansible/06_2_provision_vault.yml" linenums="1"
---
- name: Provision HashiCorp Vault (Persistence & Separation)
  hosts: all_servers
  vars:
    vault_url: "http://{{ ansible_host }}:8200"
    mysql_host: "10.10.10.9"
    mongo_host: "10.10.10.8"

  tasks:
    - name: Task 0.1 - Check Vault Health
      ansible.builtin.uri:
        url: "{{ vault_url }}/v1/sys/health"
        status_code: [200, 429, 501, 503]
      register: vault_health

    - name: Task 0.2 - Auto-Unseal Vault (Multiple Keys)
      ansible.builtin.uri:
        url: "{{ vault_url }}/v1/sys/unseal"
        method: POST
        body: { key: "{{ item }}" }
        body_format: json
      loop: "{{ vault_unseal_keys }}"
      when: vault_health.status == 503
      no_log: true

    - name: Task 1.1 - Ensure KV Secrets Engine is enabled
      ansible.builtin.uri:
        url: "{{ vault_url }}/v1/sys/mounts/secret"
        method: POST
        headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
        body: { type: "kv", options: { version: "2" } }
        body_format: json
        status_code: [200, 204, 400]

    - name: Task 2.0 - Write VirusTotal Token
      ansible.builtin.uri:
        url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/api-keys/virustotal"
        method: POST
        headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
        body: { data: { token: "{{ vault_virus_total_token }}" } }
        body_format: json
        status_code: [200, 204]
      no_log: true

    - name: Task 2.1 - Write Gemini API Token
      ansible.builtin.uri:
        url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/api-keys/gemini/home-network-guardian"
        method: POST
        headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
        body: { data: { token: "{{ vault_gemini_api_key }}" } }
        body_format: json
        status_code: [200, 204]
      no_log: true

    - name: Task 2.2 - Write Kali Gemini API Token
      ansible.builtin.uri:
        url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/api-keys/gemini/kali-linux"
        method: POST
        headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
        body: { data: { token: "{{ vault_kali_gemini_api_key }}" } }
        body_format: json
        status_code: [200, 204]
      no_log: true

    - name: Task 2.3 - Write Abuse API Token
      ansible.builtin.uri:
        url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/api-keys/abuse/api-key"
        method: POST
        headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
        body: { data: { token: "{{ vault_abuse_api_key }}" } }
        body_format: json
        status_code: [200, 204]
      no_log: true

    - name: Task 2.4 - Write Grafana API Token
      ansible.builtin.uri:
        url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/api-keys/grafana/api-key"
        method: POST
        headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
        body: { data: { token: "{{ vault_grafana_api_key }}" } }
        body_format: json
        status_code: [200, 204]
      no_log: true

    - name: Task 2.4 - Write urlscan.io API Token
      ansible.builtin.uri:
        url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/api-keys/urlscanio/api-key"
        method: POST
        headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
        body: { data: { token: "{{ vault_urlscanio_api_key }}" } }
        body_format: json
        status_code: [200, 204]
      no_log: true

    - name: Task 2.6 - Write Certificates for Services
      ansible.builtin.uri:
        url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/certs/{{ item.name }}"
        method: POST
        headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
        body:
          data:
            cert: "{{ lookup('vars', 'vault_' + item.name + '_cert') }}"
            key:  "{{ lookup('vars', 'vault_' + item.name + '_key') }}"
        body_format: json
        status_code: [200, 204]
      loop:
        - { name: "pihole" }
        - { name: "n8n" }
        - { name: "grafana" }
      no_log: true

    - name: Task 3.0 - Provision Separated Application Secrets
      ansible.builtin.uri:
        url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/credentials/{{ item.path }}"
        method: POST
        headers: { X-Vault-Token: "{{ vault_root_token | trim }}" }
        body:
          data:
            user: "{{ item.user | default('admin') }}"
            password: "{{ item.value }}"
        body_format: json
        status_code: [200, 204]
      no_log: true
      loop:
        - { path: "pihole",           value: "{{ vault_pihole_admin_password }}" }
        - { path: "grafana",          value: "{{ vault_grafana_password }}" }
        - { path: "portainer",        value: "{{ vault_portainer_password }}", user: "{{ portainer_admin_user }}" }
        - { path: "n8n",              value: "{{ vault_n8n_password }}",       user: "{{ n8n_admin_user }}" }
        - { path: "mysql/root",       value: "{{ vault_mysql_root_password }}", user: "root" }
        - { path: "mysql/app_manager",value: "{{ vault_mysql_password }}",     user: "{{ vault_mysql_app_user }}" }
        - { path: "mongodb/admin",    value: "{{ vault_mongodb_password }}",   user: "admin" }
        - { path: "gmail/l94524506",  value: "{{ vault_n8n_gmail }}",          user: "l94524506" }
```
