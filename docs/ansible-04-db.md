# Playbook 04.3 — Database Initialization

**File:** `ansible/04_3_db_create.yml`  
**Hosts:** `all_servers`  
**Privilege escalation:** `sudo`

Initializes the `cyber_intelligence` MySQL database by rendering the SQL deployment script with real credentials (via Ansible Vault), executing it inside the running `mysql_db` container, and then securely removing the rendered file from disk. Includes a retry loop to handle cases where MySQL is still starting up when this playbook runs.

---

## Overview

| Property | Value |
|----------|-------|
| Playbook file | `ansible/04_3_db_create.yml` |
| Target hosts | `all_servers` |
| `become` | Yes (`sudo`) |
| Source SQL | `config/mysql/db_deployment.sql` |
| Rendered SQL | `{{ remote_deploy_base }}/init_db_rendered.sql` (temporary, `0600`) |
| Execution log | `{{ remote_deploy_base }}/mysql_init.log` |
| Retries | 10 × 10 s delay |

---

## 1. Task 4.1 — Render SQL script with actual credentials

Uses `ansible.builtin.template` to render `db_deployment.sql` as a Jinja2 template. This replaces all `{{ mysql_user }}` and `{{ vault_mysql_password }}` placeholders with decrypted values from Ansible Vault. The output file is written with `mode: '0600'` to prevent other system users from reading it.

```yaml title="ansible/04_3_db_create.yml" linenums="1"
- name: Task 4.1 - Render SQL script with actual credentials
  ansible.builtin.template:
    src: "{{ source_mysql_script }}"
    dest: "{{ remote_deploy_base }}/init_db_rendered.sql"
    owner: "{{ deployment_user }}"
    mode: '0600'
```

| Variable | Description |
|----------|-------------|
| `source_mysql_script` | Path to `config/mysql/db_deployment.sql` on the control machine |
| `remote_deploy_base` | Root deployment directory on the target server |

---

## 2. Task 4.2 — Execute SQL and log output

Pipes the rendered SQL file into `mysql` running inside the `mysql_db` container via `docker exec`. Output and errors are appended to `mysql_init.log` with a timestamp header. The retry loop (`until` + `retries: 10`) handles situations where MySQL container is still initializing when this task runs.

```yaml title="ansible/04_3_db_create.yml" linenums="1"
- name: Task 4.2 - Execute SQL and log output
  ansible.builtin.shell:
    cmd: |
      echo "--- Execution Date: $(date) ---" >> {{ mysql_init_log }}
      docker exec -i mysql_db mysql -u root -p'{{ vault_mysql_root_password }}' \
        < {{ remote_deploy_base }}/init_db_rendered.sql >> {{ mysql_init_log }} 2>&1
  register: db_init_result
  until: (db_init_result.rc | default(-1)) == 0 or
         (db_init_result.stderr | default('') is search('ERROR 1007'))
  retries: 10
  delay: 10
```

| Condition | Meaning |
|-----------|---------|
| `rc == 0` | SQL executed successfully |
| `ERROR 1007` | Database already exists — idempotent, treated as success |
| `retries: 10, delay: 10` | Wait up to 100 seconds for MySQL to become ready |

!!! warning "Credentials in shell"
    The MySQL root password is passed as a shell argument (`-p'...'`). Ansible masks this value in logs because it comes from a Vault variable. The rendered SQL file is also removed in the next task. Never commit `init_db_rendered.sql` to version control.

---

## 3. Task 4.3 — Cleanup rendered SQL script

Removes the temporary rendered SQL file from the target server after execution, ensuring no plaintext credentials remain on disk.

```yaml title="ansible/04_3_db_create.yml" linenums="1"
- name: Task 4.3 - Cleanup rendered SQL script
  ansible.builtin.file:
    path: "{{ remote_deploy_base }}/init_db_rendered.sql"
    state: absent
```

---

## Full Playbook

```yaml title="ansible/04_3_db_create.yml" linenums="1"
---
- name: 04.3 - DB create
  hosts: all_servers
  become: yes

  vars:
    source_mysql_script: "{{ main_repo_source_dir }}/config/mysql/db_deployment.sql"
    mysql_init_log: "{{ remote_deploy_base }}/mysql_init.log"

  tasks:
    - name: Task 4.1 - Render SQL script with actual credentials
      ansible.builtin.template:
        src: "{{ source_mysql_script }}"
        dest: "{{ remote_deploy_base }}/init_db_rendered.sql"
        owner: "{{ deployment_user }}"
        mode: '0600'

    - name: Task 4.2 - Execute SQL and log output
      ansible.builtin.shell:
        cmd: |
          echo "--- Execution Date: $(date) ---" >> {{ mysql_init_log }}
          docker exec -i mysql_db mysql -u root -p'{{ vault_mysql_root_password }}' \
            < {{ remote_deploy_base }}/init_db_rendered.sql >> {{ mysql_init_log }} 2>&1
      register: db_init_result
      until: (db_init_result.rc | default(-1)) == 0 or
             (db_init_result.stderr | default('') is search('ERROR 1007'))
      retries: 10
      delay: 10

    - name: Task 4.3 - Cleanup rendered SQL script
      ansible.builtin.file:
        path: "{{ remote_deploy_base }}/init_db_rendered.sql"
        state: absent
```
