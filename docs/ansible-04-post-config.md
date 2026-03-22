# Playbook 04.4 — Post-Configuration

**File:** `ansible/04_4_post_config.yml`  
**Hosts:** `all_servers`  
**Privilege escalation:** `sudo`

Performs all first-run configuration tasks that require the containers to already be running. Divided into three sections: hardening SSH with Fail2Ban, configuring Pi-hole with a password and blocklists, and initializing the admin accounts for Portainer and n8n via their REST APIs.

---

## Overview

| Property | Value |
|----------|-------|
| Playbook file | `ansible/04_4_post_config.yml` |
| Target hosts | `all_servers` |
| `become` | Yes (`sudo`) |
| Prerequisite | All containers from `04_2` must be running |

---

## Section 1 — Fail2Ban

Protects SSH from brute-force attacks by configuring Fail2Ban with a strict lockout policy.

### Task 1.1 — Configure Fail2Ban for SSH

Writes a `jail.local` configuration file that enables the SSH jail with the following policy:

```yaml title="ansible/04_4_post_config.yml" linenums="1"
- name: Task 1.1 - Configure Fail2Ban for SSH
  ansible.builtin.copy:
    dest: /etc/fail2ban/jail.local
    content: |
      [sshd]
      enabled = true
      port = ssh
      maxretry = 3
      bantime = 1h
      findtime = 10m
    owner: root
    group: root
    mode: '0644'
```

| Parameter | Value | Description |
|-----------|-------|-------------|
| `maxretry` | `3` | Failed attempts before ban |
| `bantime` | `1h` | Duration of IP ban |
| `findtime` | `10m` | Window in which retries are counted |

### Task 1.2 — Ensure Fail2Ban is running

Restarts Fail2Ban and ensures it is enabled on boot to apply the new configuration.

```yaml title="ansible/04_4_post_config.yml" linenums="1"
- name: Task 1.2 - Ensure Fail2Ban is running
  ansible.builtin.service:
    name: fail2ban
    state: restarted
    enabled: yes
```

---

## Section 2 — Pi-hole DNS

Configures the Pi-hole container: sets the admin web UI password and imports custom blocklists from the repository.

### Task 2.1 — Set Pi-hole admin password

Calls `pihole setpassword` inside the running container via `docker exec`. Uses `no_log: true` to prevent the password from appearing in Ansible output.

```yaml title="ansible/04_4_post_config.yml" linenums="1"
- name: Task 2.1 - Set Pi-hole admin password from Vault
  ansible.builtin.shell:
    cmd: "docker exec pihole pihole setpassword '{{ vault_pihole_admin_password }}'"
  register: pihole_pass_result
  no_log: true
  changed_when: "'New password set' in pihole_pass_result.stdout"
```

### Task 2.3 — Add blocklists to Pi-hole database

Reads `config/pihole/adlists.txt` line by line and inserts each URL into Pi-hole's `gravity.db` SQLite database using `INSERT OR IGNORE` — making the task fully idempotent.

```yaml title="ansible/04_4_post_config.yml" linenums="1"
- name: Task 2.3 - Add Adlists to Pi-hole database (via Host)
  ansible.builtin.shell:
    cmd: >
      sqlite3 {{ remote_deploy_base }}/pihole/gravity.db
      "INSERT OR IGNORE INTO adlist (address, enabled, comment)
      VALUES ('{{ item.strip() }}', 1, 'Added by Ansible Sentinel');"
  loop: "{{ lookup('file', main_repo_source_dir + '/config/pihole/adlists.txt').splitlines() }}"
  when: item.strip() | length > 0
  register: adlist_result
  changed_when: adlist_result.rc == 0
```

### Task 2.4 — Update Pi-hole gravity

Triggers a Pi-hole gravity update (`pihole -g`) only when new blocklists were actually inserted, downloading and compiling all blocklist domains into the local database.

```yaml title="ansible/04_4_post_config.yml" linenums="1"
- name: Task 2.4 - Update Pi-hole Gravity
  ansible.builtin.shell:
    cmd: "docker exec pihole pihole -g"
  run_once: true
  when: adlist_result.changed
```

---

## Section 3 — Initial Account Configuration

Initializes the admin accounts for Portainer and n8n through their REST APIs. Both tasks use a retry loop since the containers may still be loading when this section runs.

### Task 3.1 — Initialize Portainer admin account

Sends a `POST` request to the Portainer API to create the initial owner account. Returns `200` on success or `409` if the account already exists — both are treated as success to ensure idempotency.

```yaml title="ansible/04_4_post_config.yml" linenums="1"
- name: Task 3.1 - Initialize Portainer Owner Account via API
  ansible.builtin.uri:
    url: "http://10.10.10.10:9000/api/users/admin/init"
    method: POST
    body_format: json
    body:
      username: "{{ portainer_admin_user }}"
      password: "{{ vault_portainer_password }}"
    status_code: [200, 409]
  register: portainer_init
  until: portainer_init.status in [200, 409]
  retries: 12
  delay: 5
  changed_when: portainer_init.status == 200
```

| HTTP Status | Meaning |
|-------------|---------|
| `200` | Account created successfully |
| `409` | Account already exists — idempotent |

### Task 3.2 — Initialize n8n owner account

Sends a `POST` request to the n8n `owner/setup` endpoint to create the first admin user. Retries up to 15 times with 10-second delays to handle n8n's slower startup time.

```yaml title="ansible/04_4_post_config.yml" linenums="1"
- name: Task 3.2 - Initialize n8n Owner Account via API
  ansible.builtin.uri:
    url: "http://localhost:5678/rest/owner/setup"
    method: POST
    body_format: json
    body:
      email: "{{ n8n_admin_email }}"
      password: "{{ vault_n8n_password }}"
      firstName: "Hunter"
      lastName: "Sentinel"
    status_code: [200, 409]
  register: n8n_init
  until: n8n_init.status in [200, 409]
  retries: 15
  delay: 10
```

---

## Full Playbook

```yaml title="ansible/04_4_post_config.yml" linenums="1"
---
- name: 04.4 - Post config
  hosts: all_servers
  become: yes

  tasks:
    - name: Section 1 - Fail2Ban
      block:
        - name: Task 1.1 - Configure Fail2Ban for SSH
          ansible.builtin.copy:
            dest: /etc/fail2ban/jail.local
            content: |
              [sshd]
              enabled = true
              port = ssh
              maxretry = 3
              bantime = 1h
              findtime = 10m
            owner: root
            group: root
            mode: '0644'

        - name: Task 1.2 - Ensure Fail2Ban is running
          ansible.builtin.service:
            name: fail2ban
            state: restarted
            enabled: yes

    - name: Section 2 - Pihole DNS
      block:
        - name: Task 2.1 - Set Pi-hole admin password from Vault
          ansible.builtin.shell:
            cmd: "docker exec pihole pihole setpassword '{{ vault_pihole_admin_password }}'"
          register: pihole_pass_result
          no_log: true
          changed_when: "'New password set' in pihole_pass_result.stdout"

        - name: Task 2.2 - Debug Pi-hole password update
          ansible.builtin.debug:
            msg: "Pi-hole web interface password has been updated successfully."
          when: pihole_pass_result.changed

        - name: Task 2.3 - Add Adlists to Pi-hole database (via Host)
          ansible.builtin.shell:
            cmd: >
              sqlite3 {{ remote_deploy_base }}/pihole/gravity.db
              "INSERT OR IGNORE INTO adlist (address, enabled, comment)
              VALUES ('{{ item.strip() }}', 1, 'Added by Ansible Sentinel');"
          loop: "{{ lookup('file', main_repo_source_dir + '/config/pihole/adlists.txt').splitlines() }}"
          when: item.strip() | length > 0
          register: adlist_result
          changed_when: adlist_result.rc == 0

        - name: Task 2.4 - Update Pi-hole Gravity
          ansible.builtin.shell:
            cmd: "docker exec pihole pihole -g"
          run_once: true
          when: adlist_result.changed

    - name: Section 3 - Initial Account Configuration
      block:
        - name: Task 3.1 - Initialize Portainer Owner Account via API
          ansible.builtin.uri:
            url: "http://10.10.10.10:9000/api/users/admin/init"
            method: POST
            body_format: json
            body:
              username: "{{ portainer_admin_user }}"
              password: "{{ vault_portainer_password }}"
            status_code: [200, 409]
          register: portainer_init
          until: portainer_init.status in [200, 409]
          retries: 12
          delay: 5
          changed_when: portainer_init.status == 200

        - name: Task 3.2 - Initialize n8n Owner Account via API
          ansible.builtin.uri:
            url: "http://localhost:5678/rest/owner/setup"
            method: POST
            body_format: json
            body:
              email: "{{ n8n_admin_email }}"
              password: "{{ vault_n8n_password }}"
              firstName: "Hunter"
              lastName: "Sentinel"
            status_code: [200, 409]
          register: n8n_init
          until: n8n_init.status in [200, 409]
          retries: 15
          delay: 10
```
