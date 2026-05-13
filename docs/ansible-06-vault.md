# Playbook 06 — HashiCorp Vault Setup

This page covers the unified [HashiCorp Vault](https://developer.hashicorp.com/vault) lifecycle playbook that initializes, unseals, and provisions the secrets backend for the [Cyber Sentinel](https://github.com/lukaszFD/cyber-sentinel) stack in a single run.

!!! info "Consolidated playbook"
Previously split into `06_1_initialize_vault.yml` and `06_2_provision_vault.yml`, the Vault setup is now a single end-to-end playbook ([`06_initialize_provision_vault.yml`](https://github.com/lukaszFD/cyber-sentinel/blob/main/ansible/06_initialize_provision_vault.yml)) that detects whether Vault is fresh or already initialized and adapts its behaviour accordingly.

**Related pages:**
[Deployment overview](deployment.md) ·
[Config Reference](ansible-00-config.md) ·
[Secrets & Env](ansible-01-secrets.md) ·
[Stack & Containers](ansible-04-stack.md) ·
[Nginx & SSL](ansible-05-proxy.md) ·
[Architecture](architecture.md) ·
[Components](components.md)

---

## Overview

**File:** [`ansible/06_initialize_provision_vault.yml`](https://github.com/lukaszFD/cyber-sentinel/blob/main/ansible/06_initialize_provision_vault.yml)
**Hosts:** `all_servers`
**Privilege escalation:** No ([`become`](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_privilege_escalation.html) not set)

| Property | Value |
|----------|-------|
| Playbook file | [`ansible/06_initialize_provision_vault.yml`](https://github.com/lukaszFD/cyber-sentinel/blob/main/ansible/06_initialize_provision_vault.yml) |
| Target hosts | `all_servers` |
| Vault URL | `http://{{ ansible_host }}:8200` |
| Secrets engine | [KV v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2) at path `secret/` |
| Auth method | Root token (auto-generated on first run, `vault_root_token` on re-run) |
| Idempotent | Yes — safe to re-run on a provisioned Vault |

### Behaviour by mode

The playbook automatically detects the state of Vault via the [`/v1/sys/init`](https://developer.hashicorp.com/vault/api-docs/system/init) endpoint and chooses one of two modes:

=== "First run (fresh Vault)"

    1. Initializes Vault and captures `root_token` + `unseal_keys`.
    2. Auto-unseals using the freshly generated keys.
    3. Provisions all secrets, certificates, and credentials.
    4. **Displays root token and unseal keys exactly once** at the end — the operator must save them manually.

=== "Re-run (initialized Vault)"

    1. Skips initialization.
    2. Auto-unseals from `group_vars` (`vault_unseal_keys`) if Vault is sealed.
    3. Provisions or updates secrets using `vault_root_token` from `group_vars`.
    4. Confirms success without re-displaying any sensitive values.

!!! danger "Unseal keys are never stored in Vault"
By design, the unseal keys are **never written to Vault itself** (chicken-and-egg problem). Save them to a [password manager](https://bitwarden.com/), encrypted vault, or sealed envelope — losing them means permanent loss of access to all Vault data. See the official [Seal/Unseal documentation](https://developer.hashicorp.com/vault/docs/concepts/seal) for background.

---

## Pipeline stages

The playbook is organized into seven sequential stages, each with a clear responsibility:

| Stage | Name | Purpose |
|-------|------|---------|
| 0 | **PRE** | Pre-flight checks: detect Vault state, validate required variables, verify cert/key pairs |
| 1 | **INIT** | Initialize Vault (only on first run) |
| 2 | **UNSEAL** | Auto-unseal Vault using the appropriate key set |
| 3 | **KV** | Enable the [KV v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2) secrets engine at `secret/` |
| 4 | **API** | Provision external API tokens |
| 5 | **CERTS** | Provision TLS certificate / key pairs |
| 6 | **CREDS** | Provision application and database credentials |
| 7 | **DONE** | Final message — credential display (first run) or confirmation (re-run) |

---

## Stage 0 — Pre-flight checks

### Vault state detection

Queries [`/v1/sys/init`](https://developer.hashicorp.com/vault/api-docs/system/init) using the [`ansible.builtin.uri`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/uri_module.html) module and stores the result in `vault_already_initialized` via [`ansible.builtin.set_fact`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/set_fact_module.html). This single fact drives the conditional logic for the rest of the play.

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
- name: "[PRE] Check Vault initialization status"
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/sys/init"
    method: GET
  register: vault_init_check

- name: "[PRE] Set fact — is Vault already initialized"
  ansible.builtin.set_fact:
    vault_already_initialized: "{{ vault_init_check.json.initialized }}"
```

### Variable validation (fail-fast)

Required variables are split into two categories and validated using [`ansible.builtin.assert`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/assert_module.html). The **always-required** set must be defined for any provisioning run, while the **re-run** set is only enforced once Vault is initialized (because the first run generates these values itself).

| Group | When enforced | Variables |
|-------|---------------|-----------|
| `required_vars_always` | Every run | API tokens, app passwords, DB passwords, user names |
| `required_vars_rerun` | Only when Vault is already initialized | `vault_root_token`, `vault_unseal_keys` |

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
- name: "[PRE] Verify always-required variables are defined"
  ansible.builtin.assert:
    that:
      - vars[item] is defined
      - vars[item] | string | length > 0
    fail_msg: "Required variable '{{ item }}' is missing or empty. Define it in group_vars."
    quiet: true
  loop: "{{ required_vars_always }}"

- name: "[PRE] Verify re-run variables are defined (only if Vault already initialized)"
  ansible.builtin.assert:
    that:
      - vars[item] is defined
      - vars[item] | string | length > 0
    fail_msg: "Required variable '{{ item }}' is missing. Vault is already initialized; you must provide existing root_token and unseal_keys in group_vars."
    quiet: true
  loop: "{{ required_vars_rerun }}"
  when: vault_already_initialized
```

!!! tip "Storing variables securely"
All sensitive values must be encrypted with [`ansible-vault encrypt_string`](https://docs.ansible.com/ansible/latest/vault_guide/vault_encrypting_content.html#encrypting-individual-variables-with-ansible-vault) before being committed to [`group_vars/`](ansible-01-secrets.md). See the [Secrets & Env page](ansible-01-secrets.md) for the standard project layout.

### Cert/key pair validation

For each service in `required_cert_services` (`pihole`, `n8n`, `grafana`), the playbook verifies that both `vault_<service>_cert` and `vault_<service>_key` are defined and non-empty using the [`lookup('vars', ...)`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/vars_lookup.html) plugin.

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
- name: "[PRE] Verify cert/key pairs exist for each service"
  ansible.builtin.assert:
    that:
      - lookup('vars', 'vault_' + item + '_cert', default='') | length > 0
      - lookup('vars', 'vault_' + item + '_key',  default='') | length > 0
    fail_msg: "Missing cert/key for service '{{ item }}'. Expected vars: vault_{{ item }}_cert and vault_{{ item }}_key."
    quiet: true
  loop: "{{ required_cert_services }}"
```

The TLS material itself is generated and consumed by the [Nginx & SSL playbook (05)](ansible-05-proxy.md).

---

## Stage 1 — Initialize (first run only)

Runs [`vault operator init`](https://developer.hashicorp.com/vault/docs/commands/operator/init) inside the [`hashicorp_vault`](components.md) container with the `-format=json` flag, parses the JSON output, and stores it in `vault_creds` (with [`no_log: true`](https://docs.ansible.com/ansible/latest/reference_appendices/logging.html) to keep secrets out of the Ansible log).

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
- name: "[INIT] Initialize Vault (generates root_token + unseal_keys)"
  ansible.builtin.shell:
    cmd: "docker exec hashicorp_vault vault operator init -format=json"
  register: vault_init_raw
  when: not vault_already_initialized
  changed_when: vault_init_raw.rc == 0

- name: "[INIT] Parse newly generated credentials"
  ansible.builtin.set_fact:
    vault_creds: "{{ vault_init_raw.stdout | from_json }}"
  when: not vault_already_initialized
  no_log: true
```

The [`vault operator init`](https://developer.hashicorp.com/vault/docs/commands/operator/init) command applies [Shamir's Secret Sharing](https://developer.hashicorp.com/vault/docs/concepts/seal#shamir-seals) — by default the master key is split into 5 shares with a threshold of 3.

### Unified token

To avoid branching logic in every subsequent task, the playbook computes a single `effective_root_token` fact that is used by all provisioning tasks regardless of mode:

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
- name: "[INIT] Set effective root token for this play"
  ansible.builtin.set_fact:
    effective_root_token: >-
      {{ vault_creds.root_token if not vault_already_initialized
         else vault_root_token | trim }}
  no_log: true
```

The token is later passed to Vault via the [`X-Vault-Token`](https://developer.hashicorp.com/vault/api-docs#authentication) HTTP header.

---

## Stage 2 — Unseal

After init (or on re-run), the playbook re-checks Vault's health via [`/v1/sys/health`](https://developer.hashicorp.com/vault/api-docs/system/health) and submits unseal keys to [`/v1/sys/unseal`](https://developer.hashicorp.com/vault/api-docs/system/unseal) if Vault is sealed (HTTP `503`). Two separate tasks handle the two key sources:

| HTTP Status | Vault state | Reference |
|-------------|-------------|-----------|
| `200` | Initialized, unsealed, active | [Health endpoint](https://developer.hashicorp.com/vault/api-docs/system/health) |
| `429` | Standby node | [HA mode](https://developer.hashicorp.com/vault/docs/concepts/ha) |
| `501` | Not initialized | [Init concept](https://developer.hashicorp.com/vault/docs/commands/operator/init) |
| `503` | **Sealed** — unseal required | [Seal/Unseal](https://developer.hashicorp.com/vault/docs/concepts/seal) |

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
- name: "[UNSEAL] Re-check Vault health (after potential init)"
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/sys/health"
    status_code: [200, 429, 501, 503]
  register: vault_health

- name: "[UNSEAL] Auto-unseal using freshly generated keys (first run)"
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/sys/unseal"
    method: POST
    body: { key: "{{ item }}" }
    body_format: json
  loop: "{{ vault_creds.unseal_keys_b64 }}"
  when:
    - not vault_already_initialized
    - vault_health.status == 503
  no_log: true

- name: "[UNSEAL] Auto-unseal using group_vars keys (re-run, if sealed)"
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/sys/unseal"
    method: POST
    body: { key: "{{ item }}" }
    body_format: json
  loop: "{{ vault_unseal_keys | default([]) }}"
  when:
    - vault_already_initialized
    - vault_health.status == 503
  no_log: true
```

!!! note "Quorum"
Vault requires a [quorum of unseal keys](https://developer.hashicorp.com/vault/docs/concepts/seal#unsealing) (default: 3 of 5) to unseal. The playbook submits all available keys in the loop — Vault itself ignores any beyond the required threshold.

---

## Stage 3 — Enable KV secrets engine

Mounts the [KV v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2) secrets engine at `secret/` via [`/v1/sys/mounts`](https://developer.hashicorp.com/vault/api-docs/system/mounts). HTTP `400` is treated as success because it indicates the engine is already mounted (idempotent).

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
- name: "[KV] Ensure KV v2 secrets engine is enabled at /secret"
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/sys/mounts/secret"
    method: POST
    headers: { X-Vault-Token: "{{ effective_root_token }}" }
    body: { type: "kv", options: { version: "2" } }
    body_format: json
    status_code: [200, 204, 400]   # 400 = already enabled
  no_log: true
```

!!! info "KV v1 vs KV v2"
[KV v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2) adds versioning and soft-delete on top of [KV v1](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v1). The data path becomes `secret/data/<path>` instead of `secret/<path>` — note the extra `data/` segment in all subsequent stages.

---

## Stage 4 — API tokens

All external [Cyber Threat Intelligence](architecture.md) and service API tokens are written under `cyber-sentinel/api-keys/` in a single looped task using the [KV v2 write endpoint](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#create-update-secret).

| Vault path | Variable | Service | Provider docs |
|---|---|---|---|
| `cyber-sentinel/api-keys/virustotal` | `vault_virus_total_token` | [VirusTotal](https://www.virustotal.com/) IP/domain scans | [API v3](https://docs.virustotal.com/reference/overview) |
| `cyber-sentinel/api-keys/gemini/home-network-guardian` | `vault_gemini_api_key` | [Google Gemini](https://gemini.google.com/) AI analysis | [Gemini API](https://ai.google.dev/gemini-api/docs) |
| `cyber-sentinel/api-keys/gemini/kali-linux` | `vault_kali_gemini_api_key` | Gemini for Kali environment | [Gemini API](https://ai.google.dev/gemini-api/docs) |
| `cyber-sentinel/api-keys/abuse/api-key` | `vault_abuse_api_key` | [Abuse.ch](https://abuse.ch/) ([ThreatFox](https://threatfox.abuse.ch/) + [URLHaus](https://urlhaus.abuse.ch/)) | [Auth-Key docs](https://abuse.ch/api/) |
| `cyber-sentinel/api-keys/grafana/api-key` | `vault_grafana_api_key` | [Grafana](https://grafana.com/) API | [Service accounts](https://grafana.com/docs/grafana/latest/administration/service-accounts/) |
| `cyber-sentinel/api-keys/urlscanio/api-key` | `vault_urlscanio_api_key` | [urlscan.io](https://urlscan.io/) | [API docs](https://urlscan.io/docs/api/) |

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
- name: "[API] Provision external API tokens"
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/api-keys/{{ item.path }}"
    method: POST
    headers: { X-Vault-Token: "{{ effective_root_token }}" }
    body: { data: { token: "{{ item.value }}" } }
    body_format: json
    status_code: [200, 204]
  no_log: true
  loop:
    - { path: "virustotal",                     value: "{{ vault_virus_total_token }}" }
    - { path: "gemini/home-network-guardian",   value: "{{ vault_gemini_api_key }}" }
    - { path: "gemini/kali-linux",              value: "{{ vault_kali_gemini_api_key }}" }
    - { path: "abuse/api-key",                  value: "{{ vault_abuse_api_key }}" }
    - { path: "grafana/api-key",                value: "{{ vault_grafana_api_key }}" }
    - { path: "urlscanio/api-key",              value: "{{ vault_urlscanio_api_key }}" }
```

These tokens are consumed by the [n8n threat enrichment workflow](n8n.md) at runtime.

---

## Stage 5 — TLS certificates

Certificate / key pairs for every TLS-fronted service are stored under `cyber-sentinel/certs/<service>` for later consumption by the [Nginx reverse proxy playbook (05)](ansible-05-proxy.md). The list of services iterated by this stage is driven by the `required_cert_services` variable.

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
- name: "[CERTS] Provision TLS certs/keys for services"
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/certs/{{ item }}"
    method: POST
    headers: { X-Vault-Token: "{{ effective_root_token }}" }
    body:
      data:
        cert: "{{ lookup('vars', 'vault_' + item + '_cert') }}"
        key:  "{{ lookup('vars', 'vault_' + item + '_key') }}"
    body_format: json
    status_code: [200, 204]
  loop: "{{ required_cert_services }}"
  no_log: true
```
---

## Stage 6 — Application & database credentials

All service passwords and database credentials are stored under `cyber-sentinel/credentials/` in a single looped task. Each entry stores both the user and the password, with `admin` as the default user when none is specified (via the [`default` filter](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_filters.html#providing-default-values)).

| Vault path | User | Service | Reference |
|---|---|---|---|
| `credentials/pihole` | `admin` (default) | Pi-hole web UI | [Pi-hole admin](https://docs.pi-hole.net/main/post-install/) |
| `credentials/grafana` | `admin` (default) | Grafana admin | [Grafana auth](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/) |
| `credentials/portainer` | `portainer_admin_user` | Portainer admin | [Portainer auth](https://docs.portainer.io/admin/authentication) |
| `credentials/n8n` | `n8n_admin_user` | n8n owner account | [n8n auth](https://docs.n8n.io/hosting/authentication/) |
| `credentials/mysql/root` | `root` | MySQL root | [MySQL 8.0](https://dev.mysql.com/doc/refman/8.0/en/) |
| `credentials/mysql/app_manager` | `vault_mysql_app_user` | MySQL application user | [Database init (04.3)](ansible-04-db.md) |
| `credentials/mongodb/admin` | `admin` | MongoDB root | [MongoDB 4.4](https://www.mongodb.com/docs/v4.4/) |
| `credentials/gmail` | `vault_n8n_user` | Gmail credentials for n8n alerting | [Google App Passwords](https://support.google.com/accounts/answer/185833) |

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
- name: "[CREDS] Provision application and database credentials"
  ansible.builtin.uri:
    url: "{{ vault_url }}/v1/secret/data/cyber-sentinel/credentials/{{ item.path }}"
    method: POST
    headers: { X-Vault-Token: "{{ effective_root_token }}" }
    body:
      data:
        user: "{{ item.user | default('admin') }}"
        password: "{{ item.value }}"
    body_format: json
    status_code: [200, 204]
  no_log: true
  loop:
    # App passwords
    - { path: "pihole",            value: "{{ vault_pihole_admin_password }}" }
    - { path: "grafana",           value: "{{ vault_grafana_password }}" }
    - { path: "portainer",         value: "{{ vault_portainer_password }}", user: "{{ portainer_admin_user }}" }
    - { path: "n8n",               value: "{{ vault_n8n_password }}",       user: "{{ n8n_admin_user }}" }
    # Database roots
    - { path: "mysql/root",        value: "{{ vault_mysql_root_password }}", user: "root" }
    - { path: "mysql/app_manager", value: "{{ vault_mysql_password }}",      user: "{{ vault_mysql_app_user }}" }
    - { path: "mongodb/admin",     value: "{{ vault_mongodb_password }}",    user: "admin" }
    # Email
    - { path: "gmail",             value: "{{ vault_n8n_gmail }}",           user: "{{ vault_n8n_user }}" }
```

---

## Stage 7 — Final message

The final stage diverges by mode using the [`ansible.builtin.debug`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/debug_module.html) module.

### First-init credential display

On a fresh install, the playbook prints the freshly generated root token and unseal keys **exactly once**. Save them immediately — they will not be displayed again.

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
- name: "[DONE] First-init credential display (SAVE THESE NOW — shown only once)"
  ansible.builtin.debug:
    msg:
      - "============================================================"
      - "  VAULT INITIALIZED SUCCESSFULLY — SAVE THE FOLLOWING NOW"
      - "============================================================"
      - ""
      - "  Root Token: {{ vault_creds.root_token }}"
      - ""
      - "  Unseal Keys (need 3 of 5 to unseal):"
      - "{{ vault_creds.unseal_keys_b64 | to_nice_yaml(indent=4) }}"
      - ...
  when: not vault_already_initialized
```

!!! warning "Action required after the first run"
1. Copy the root token and unseal keys to a secure offline location (password manager, encrypted vault, sealed envelope).
2. Add `vault_root_token` and `vault_unseal_keys` to your [`group_vars`](ansible-01-secrets.md), encrypted with [`ansible-vault encrypt_string`](https://docs.ansible.com/ansible/latest/vault_guide/vault_encrypting_content.html#encrypting-individual-variables-with-ansible-vault).
3. These keys will **never** be displayed again. Lose them and you lose access to all Vault data permanently — see the [Seal/Unseal recovery docs](https://developer.hashicorp.com/vault/docs/concepts/seal).

### Re-run confirmation

On subsequent runs, the playbook prints a brief confirmation without exposing anything sensitive. The Vault [Web UI](https://developer.hashicorp.com/vault/docs/ui) is reachable at `{{ vault_url }}/ui`.

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
- name: "[DONE] Re-run completion message"
  ansible.builtin.debug:
    msg:
      - "============================================================"
      - "  Vault provisioning completed successfully"
      - "============================================================"
      - "  Mode:    RE-RUN on existing Vault"
      - "  Host:    {{ vault_url }}"
      - "  Action:  Use your stored Root Token to log in via UI or CLI"
      - "           and back up Unseal Keys if needed."
      - "  Login:   {{ vault_url }}/ui"
      - "============================================================"
  when: vault_already_initialized
```

---

## Security posture

The unified playbook tightens several aspects of the previous two-playbook flow:

- **No persistent credential debug output.** The temporary `DEBUG - Show Keys` task from the old `06_1` is gone. The first-init display is now an intentional, gated, one-time event with explicit operator instructions.
- **[`no_log: true`](https://docs.ansible.com/ansible/latest/reference_appendices/logging.html) on every secret-bearing task.** This includes the parsed `vault_creds`, the `effective_root_token` fact, and all [`uri`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/uri_module.html) calls that carry tokens, passwords, or keys.
- **Fail-fast pre-flight.** Missing variables or cert pairs abort the run before any secret is written, preventing partial / inconsistent state.
- **Unseal keys never written to Vault.** Storing unseal keys inside the very system they unseal is a chicken-and-egg violation. They remain entirely in operator-controlled storage. See the [Seal concept](https://developer.hashicorp.com/vault/docs/concepts/seal) for the reasoning.
- **Defence in depth.** Combined with the [UFW firewall (02)](ansible-02-security.md) and [Nginx TLS proxy (05)](ansible-05-proxy.md), Vault is reachable only over the internal network with encrypted transport.

Further reading: [Vault production hardening](https://developer.hashicorp.com/vault/tutorials/operations/production-hardening) ·
[Project Security Policy](SECURITY.md).

---

## Variables reference

Variables consumed by the playbook, grouped by purpose. All sensitive variables should be encrypted with [`ansible-vault encrypt_string`](https://docs.ansible.com/ansible/latest/vault_guide/vault_encrypting_content.html#encrypting-individual-variables-with-ansible-vault) before being committed to [`group_vars/`](ansible-01-secrets.md). For the project-wide convention see the [Config Reference](ansible-00-config.md).

### Always required

| Variable | Purpose | Provider |
|----------|---------|----------|
| `vault_virus_total_token` | VirusTotal API token | [virustotal.com](https://www.virustotal.com/) |
| `vault_gemini_api_key` | Gemini API key (Home Network Guardian) | [Google AI Studio](https://aistudio.google.com/app/apikey) |
| `vault_kali_gemini_api_key` | Gemini API key (Kali) | [Google AI Studio](https://aistudio.google.com/app/apikey) |
| `vault_abuse_api_key` | Abuse.ch API key | [auth.abuse.ch](https://auth.abuse.ch/) |
| `vault_grafana_api_key` | Grafana API key | [Grafana service accounts](https://grafana.com/docs/grafana/latest/administration/service-accounts/) |
| `vault_urlscanio_api_key` | urlscan.io API key | [urlscan.io](https://urlscan.io/user/profile/) |
| `vault_pihole_admin_password` | Pi-hole admin password | — |
| `vault_grafana_password` | Grafana admin password | — |
| `vault_portainer_password` | Portainer admin password | — |
| `vault_n8n_password` | n8n owner password | — |
| `vault_mysql_root_password` | MySQL root password | — |
| `vault_mysql_password` | MySQL app-user password | — |
| `vault_mongodb_password` | MongoDB admin password | — |
| `vault_n8n_gmail` | Gmail app password for n8n alerting | [Google App Passwords](https://support.google.com/accounts/answer/185833) |
| `vault_n8n_user` | Gmail username for n8n alerting | — |
| `portainer_admin_user` | Portainer admin username | — |
| `n8n_admin_user` | n8n admin username | — |
| `vault_mysql_app_user` | MySQL application username | — |
| `vault_<service>_cert` / `vault_<service>_key` | TLS material for `pihole`, `n8n`, `grafana`, `portainer`, `firefox`, `hashicorp_vault` (consumed by playbook 05) | [Nginx playbook (05)](ansible-05-proxy.md) |

### Required only on re-runs

| Variable | Purpose | Source |
|----------|---------|--------|
| `vault_root_token` | Root token from the first-init output | [`vault operator init`](https://developer.hashicorp.com/vault/docs/commands/operator/init) |
| `vault_unseal_keys` | List of unseal keys (base64) from the first-init output | [`vault operator init`](https://developer.hashicorp.com/vault/docs/commands/operator/init) |

---

## Full Playbook 06

```yaml title="ansible/06_initialize_provision_vault.yml" linenums="1"
---
- name: Cyber Sentinel — Vault Full Lifecycle (Init + Unseal + Provision)
  hosts: all_servers
  gather_facts: false

  vars:
    vault_url: "http://{{ ansible_host }}:8200"
    mysql_host: "10.10.10.9"
    mongo_host: "10.10.10.8"

    required_vars_rerun:
      - vault_root_token
      - vault_unseal_keys

    required_vars_always:
      - vault_virus_total_token
      - vault_gemini_api_key
      - vault_kali_gemini_api_key
      - vault_abuse_api_key
      - vault_grafana_api_key
      - vault_urlscanio_api_key
      - vault_pihole_admin_password
      - vault_grafana_password
      - vault_portainer_password
      - vault_n8n_password
      - vault_mysql_root_password
      - vault_mysql_password
      - vault_mongodb_password
      - vault_n8n_gmail
      - portainer_admin_user
      - n8n_admin_user
      - vault_mysql_app_user

    required_cert_services:
      - pihole
      - n8n
      - grafana

  tasks:
  # See sections above for the full task breakdown across stages 0-7.
  # Canonical source:
  # https://github.com/lukaszFD/cyber-sentinel/blob/main/ansible/06_initialize_provision_vault.yml
```

---