# Playbook 02 — Security & Firewall (UFW)

**File:** `ansible/02_setup_security.yml`  
**Hosts:** `all`  
**Privilege escalation:** `sudo`

Configures the **UFW (Uncomplicated Firewall)** on the target server. Resets all existing rules to a clean state, applies a strict deny-all default incoming policy, and then opens only the ports required by the Cyber Sentinel stack. This playbook runs before any service is deployed.

---

## Overview

| Property | Value |
|----------|-------|
| Playbook file | `ansible/02_setup_security.yml` |
| Target hosts | `all` |
| `become` | Yes (`sudo`) |
| Default incoming policy | `deny` |
| Default outgoing policy | `allow` (UFW default) |

---

## Open Ports

The following ports are explicitly allowed after this playbook runs. All other incoming traffic is blocked.

| Port | Protocol | Purpose |
|------|----------|---------|
| `22` | TCP | SSH management |
| `80` | TCP | Nginx HTTP (redirect to HTTPS) |
| `443` | TCP | Nginx HTTPS reverse proxy |
| `53` | UDP | Pi-hole DNS (UDP) |
| `53` | TCP | Pi-hole DNS (TCP) |

---

## Tasks

### 1. Install UFW

Installs UFW via `apt` with `update_cache: yes` to ensure the package index is current.

```yaml title="ansible/02_setup_security.yml" linenums="1"
- name: Install UFW
  apt:
    name: ufw
    state: present
    update_cache: yes
```

---

### 2. Reset UFW to default

Resets UFW to a clean state, removing all existing rules. This ensures that any previous custom rules or leftover configurations from other tools do not interfere with the Cyber Sentinel firewall policy.

```yaml title="ansible/02_setup_security.yml" linenums="1"
- name: Reset UFW to default (Deny all incoming)
  ufw:
    state: reset
```

!!! warning
    This task removes **all existing firewall rules** before applying the new policy. If you re-run this playbook on a server with custom rules, those rules will be lost.

---

### 3. Allow defined ports

Iterates over the `allow_ports` list variable and opens each port/protocol combination.

```yaml title="ansible/02_setup_security.yml" linenums="1"
vars:
  allow_ports:
    - { port: 22,  proto: "tcp", comment: "SSH Management" }
    - { port: 80,  proto: "tcp", comment: "Nginx HTTP Redirect" }
    - { port: 443, proto: "tcp", comment: "Nginx HTTPS Proxy" }
    - { port: 53,  proto: "udp", comment: "Pi-hole DNS UDP" }
    - { port: 53,  proto: "tcp", comment: "Pi-hole DNS TCP" }

tasks:
  - name: Allow defined ports
    ufw:
      rule: allow
      port: "{{ item.port | string }}"
      proto: "{{ item.proto }}"
      comment: "{{ item.comment }}"
    loop: "{{ allow_ports }}"
```

---

### 4. Enable UFW with deny-all policy

Activates UFW and sets the default incoming policy to `deny`. All traffic not explicitly allowed by the rules above is dropped.

```yaml title="ansible/02_setup_security.yml" linenums="1"
- name: Enable UFW
  ufw:
    state: enabled
    policy: deny
```

---

## Full Playbook

```yaml title="ansible/02_setup_security.yml" linenums="1"
---
- name: 02 - Configure Firewall (UFW)
  hosts: all
  become: yes
  vars:
    allow_ports:
      - { port: 22,  proto: "tcp", comment: "SSH Management" }
      - { port: 80,  proto: "tcp", comment: "Nginx HTTP Redirect" }
      - { port: 443, proto: "tcp", comment: "Nginx HTTPS Proxy" }
      - { port: 53,  proto: "udp", comment: "Pi-hole DNS UDP" }
      - { port: 53,  proto: "tcp", comment: "Pi-hole DNS TCP" }

  tasks:
    - name: Install UFW
      apt:
        name: ufw
        state: present
        update_cache: yes

    - name: Reset UFW to default (Deny all incoming)
      ufw:
        state: reset

    - name: Allow defined ports
      ufw:
        rule: allow
        port: "{{ item.port | string }}"
        proto: "{{ item.proto }}"
        comment: "{{ item.comment }}"
      loop: "{{ allow_ports }}"

    - name: Enable UFW
      ufw:
        state: enabled
        policy: deny
```
