# Playbook 01 — Secret & Environment Management

**File:** `ansible/01_setup_secrets.yml`  
**Hosts:** `all_servers`  
**Privilege escalation:** `sudo`

This is the first playbook executed in the pipeline. Its sole responsibility is to prepare the deployment directory and generate the `.env` file that all Docker containers rely on for sensitive configuration values. Secrets are never stored in plaintext — they are decrypted from Ansible Vault at runtime and written to the target server with restricted file permissions (`0600`).

---

## Overview

| Property | Value |
|----------|-------|
| Playbook file | `ansible/01_setup_secrets.yml` |
| Target hosts | `all_servers` |
| `become` | Yes (`sudo`) |
| Output file | `{{ remote_deploy_base }}/.env` |
| File permissions | `0600` (owner read/write only) |

---

## 1. Task 1.0 — Create base deployment directory

Creates the root deployment directory on the remote server if it does not already exist. Ownership is set to the `deployment_user` variable defined in `group_vars/all/all_servers.yml`.

```yaml title="ansible/01_setup_secrets.yml" linenums="1"
- name: Task 1.0 - Create base deployment directory if it doesn't exist
  ansible.builtin.file:
    path: "{{ remote_deploy_base }}"
    state: directory
    owner: "{{ deployment_user }}"
    group: "{{ deployment_user }}"
    mode: '0755'
```

| Variable | Description |
|----------|-------------|
| `remote_deploy_base` | Root path on the remote server (e.g. `/home/pi/cyber-sentinel`) |
| `deployment_user` | OS user that owns all project files |

---

## 2. Task 1.1 — Generate `.env` from Ansible Vault template

Renders the `templates/env.j2` Jinja2 template using values decrypted from Ansible Vault and writes the result to `.env` at the deployment root. The file is created with `0600` permissions so only the owner can read it.

```yaml title="ansible/01_setup_secrets.yml" linenums="1"
- name: Task 1.1 - Generate .env from template with decrypted secrets
  ansible.builtin.template:
    src: "templates/env.j2"
    dest: "{{ remote_env_file }}"
    owner: "{{ deployment_user }}"
    group: "{{ deployment_user }}"
    mode: '0600'
```

The `env.j2` template injects all secrets needed by Docker Compose at container startup, including database passwords, API tokens, and service credentials. The actual values come from `ansible/group_vars/all/vault.yml` (Ansible Vault encrypted).

!!! warning "Security"
    The `.env` file is written with `mode: '0600'`. Never commit this file to version control. The `.gitignore` already excludes it.

---

## Full Playbook

```yaml title="ansible/01_setup_secrets.yml" linenums="1"
---
- name: 01 - Secret & Environment Management
  hosts: all_servers
  become: yes
  become_method: sudo

  vars:
    remote_env_file: "{{ remote_deploy_base }}/.env"

  tasks:
    - name: Task 1.0 - Create base deployment directory if it doesn't exist
      ansible.builtin.file:
        path: "{{ remote_deploy_base }}"
        state: directory
        owner: "{{ deployment_user }}"
        group: "{{ deployment_user }}"
        mode: '0755'

    - name: Task 1.1 - Generate .env from template with decrypted secrets
      ansible.builtin.template:
        src: "templates/env.j2"
        dest: "{{ remote_env_file }}"
        owner: "{{ deployment_user }}"
        group: "{{ deployment_user }}"
        mode: '0600'
```
