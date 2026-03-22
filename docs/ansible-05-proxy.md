# Playbook 05 — Nginx Reverse Proxy & SSL

**File:** `ansible/05_deploy_proxy.yml`  
**Hosts:** `all`  
**Privilege escalation:** `sudo`

Deploys an **Nginx reverse proxy** container that exposes all Cyber Sentinel web services over HTTPS. SSL certificates and private keys are written from Ansible Vault to the server, per-service Nginx configs are rendered from a Jinja2 template, and the Nginx container is started on `10.10.10.100` within the internal network with ports `80` and `443` mapped to the host.

---

## Overview

| Property | Value |
|----------|-------|
| Playbook file | `ansible/05_deploy_proxy.yml` |
| Target hosts | `all` |
| `become` | Yes (`sudo`) |
| Nginx image | `nginx:latest` |
| Container IP | `10.10.10.100` |
| Ports | `80:80`, `443:443` (host-exposed) |
| Config template | `templates/nginx_service.conf.j2` |
| Cert storage | `config/nginx/certs/` (mode `0600`) |

---

## Proxied Services

The following services are exposed through Nginx. The `domain_suffix` variable is set to `local` for dev inventory (`vm-prox-dev`) and `prod` otherwise.

| Service name | Internal host | Internal port | Public URL |
|---|---|---|---|
| `pihole` | `pihole` | `80` | `https://pihole.<domain_suffix>` |
| `n8n` | `n8n-server` | `5678` | `https://n8n.<domain_suffix>` |
| `portainer` | `portainer` | `9000` | `https://portainer.<domain_suffix>` |
| `firefox` | `firefox` | `3000` | `https://firefox.<domain_suffix>` |
| `grafana` | `grafana` | `3000` | `https://grafana.<domain_suffix>` |
| `hashicorp_vault` | `hashicorp_vault` | `8200` | `https://hashicorp_vault.<domain_suffix>` |

---

## Tasks

### 1. Task 5.0 — Ensure directories exist

Creates the `conf.d` and `certs` directories inside the Nginx config tree if they do not already exist.

```yaml title="ansible/05_deploy_proxy.yml" linenums="1"
- name: Task 5.0 - Ensure directories exist
  ansible.builtin.file:
    path: "{{ item }}"
    state: directory
    owner: "{{ deployment_user }}"
    mode: '0755'
  loop:
    - "{{ remote_deploy_base }}/config/nginx/conf.d"
    - "{{ remote_deploy_base }}/config/nginx/certs"
```

---

### 2. Task 5.1 — Write SSL certificates

Iterates over the `services` list and writes each service's SSL certificate (`.crt`) from Ansible Vault to the `certs/` directory. Uses `no_log: true` to suppress certificate content from Ansible output.

```yaml title="ansible/05_deploy_proxy.yml" linenums="1"
- name: Task 5.1 - Save Certificate files (.crt)
  ansible.builtin.copy:
    content: "{{ lookup('vars', 'vault_' + item.name + '_cert') }}"
    dest: "{{ remote_deploy_base }}/config/nginx/certs/{{ item.name }}.crt"
    owner: "{{ deployment_user }}"
    mode: '0600'
  loop: "{{ services }}"
  no_log: true
```

The variable name pattern is `vault_<service_name>_cert` — for example, `vault_n8n_cert`, `vault_grafana_cert`. These must exist in `group_vars/all/vault.yml`.

---

### 3. Task 5.2 — Write SSL private keys

Same pattern as above but for `.key` files (`vault_<service_name>_key`).

```yaml title="ansible/05_deploy_proxy.yml" linenums="1"
- name: Task 5.2 - Save Private Key files (.key)
  ansible.builtin.copy:
    content: "{{ lookup('vars', 'vault_' + item.name + '_key') }}"
    dest: "{{ remote_deploy_base }}/config/nginx/certs/{{ item.name }}.key"
    owner: "{{ deployment_user }}"
    mode: '0600'
  loop: "{{ services }}"
  no_log: true
```

!!! warning "Key file permissions"
    Both certificate and key files are written with `mode: '0600'`. Nginx requires the key files to be readable only by the process owner. Do not change these permissions.

---

### 4. Task 5.3 — Render Nginx config per service

Renders `templates/nginx_service.conf.j2` once for each service in the `services` list, producing a dedicated `.conf` file in `config/nginx/conf.d/`. Each config includes the service's subdomain, internal proxy target (`internal_host:port`), and paths to its certificate and key.

```yaml title="ansible/05_deploy_proxy.yml" linenums="1"
- name: Task 5.3 - Deploy Nginx Templates
  ansible.builtin.template:
    src: templates/nginx_service.conf.j2
    dest: "{{ remote_deploy_base }}/config/nginx/conf.d/{{ item.name }}.conf"
  loop: "{{ services }}"
```

---

### 5. Task 5.4 — Start Nginx proxy container

Starts (or recreates) the Nginx container, mounting the `conf.d` and `certs` directories as read-only volumes, attached to the internal Docker network at `10.10.10.100`, with host ports `80` and `443` exposed.

```yaml title="ansible/05_deploy_proxy.yml" linenums="1"
- name: Task 5.4 - Run Nginx Proxy Container
  community.docker.docker_container:
    name: nginx-proxy
    image: nginx:latest
    state: started
    recreate: yes
    restart_policy: always
    networks:
      - name: cyber-sentinel_internal_network
        ipv4_address: 10.10.10.100
    volumes:
      - "{{ remote_deploy_base }}/config/nginx/conf.d:/etc/nginx/conf.d:ro"
      - "{{ remote_deploy_base }}/config/nginx/certs:/etc/nginx/certs:ro"
    ports:
      - "443:443"
      - "80:80"
```

| Parameter | Value | Note |
|-----------|-------|------|
| `recreate: yes` | Always re-creates the container | Ensures config changes are applied on re-run |
| `ipv4_address` | `10.10.10.100` | Fixed IP outside the `.2–.14` service range |
| `conf.d` volume | read-only | Nginx reads configs but never writes them |
| `certs` volume | read-only | Keys are mounted read-only for security |

---

## Full Playbook

```yaml title="ansible/05_deploy_proxy.yml" linenums="1"
---
- name: 05 - Deploy Nginx Reverse Proxy with SSL
  hosts: all
  become: yes
  vars:
    domain_suffix: "{{ 'local' if inventory_hostname in groups['vm-prox-dev'] else 'prod' }}"
    services:
      - { name: "pihole",          port: 80,   internal_host: "pihole" }
      - { name: "n8n",             port: 5678, internal_host: "n8n-server" }
      - { name: "portainer",       port: 9000, internal_host: "portainer" }
      - { name: "firefox",         port: 3000, internal_host: "firefox" }
      - { name: "grafana",         port: 3000, internal_host: "grafana" }
      - { name: "hashicorp_vault", port: 8200, internal_host: "hashicorp_vault" }

  tasks:
    - name: Task 5.0 - Ensure directories exist
      ansible.builtin.file:
        path: "{{ item }}"
        state: directory
        owner: "{{ deployment_user }}"
        mode: '0755'
      loop:
        - "{{ remote_deploy_base }}/config/nginx/conf.d"
        - "{{ remote_deploy_base }}/config/nginx/certs"

    - name: Task 5.1 - Save Certificate files (.crt)
      ansible.builtin.copy:
        content: "{{ lookup('vars', 'vault_' + item.name + '_cert') }}"
        dest: "{{ remote_deploy_base }}/config/nginx/certs/{{ item.name }}.crt"
        owner: "{{ deployment_user }}"
        mode: '0600'
      loop: "{{ services }}"
      no_log: true

    - name: Task 5.2 - Save Private Key files (.key)
      ansible.builtin.copy:
        content: "{{ lookup('vars', 'vault_' + item.name + '_key') }}"
        dest: "{{ remote_deploy_base }}/config/nginx/certs/{{ item.name }}.key"
        owner: "{{ deployment_user }}"
        mode: '0600'
      loop: "{{ services }}"
      no_log: true

    - name: Task 5.3 - Deploy Nginx Templates
      ansible.builtin.template:
        src: templates/nginx_service.conf.j2
        dest: "{{ remote_deploy_base }}/config/nginx/conf.d/{{ item.name }}.conf"
      loop: "{{ services }}"

    - name: Task 5.4 - Run Nginx Proxy Container
      community.docker.docker_container:
        name: nginx-proxy
        image: nginx:latest
        state: started
        recreate: yes
        restart_policy: always
        networks:
          - name: cyber-sentinel_internal_network
            ipv4_address: 10.10.10.100
        volumes:
          - "{{ remote_deploy_base }}/config/nginx/conf.d:/etc/nginx/conf.d:ro"
          - "{{ remote_deploy_base }}/config/nginx/certs:/etc/nginx/certs:ro"
        ports:
          - "443:443"
          - "80:80"
```
