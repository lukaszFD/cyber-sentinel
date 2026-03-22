# Playbook 04 — Stack Preparation & Container Deployment

This page covers two consecutive playbooks that together build the Docker environment on the target server.

---

## 4.1 Prepare Sentinel Stack

**File:** `ansible/04_1_prepare_stack.yml`  
**Hosts:** `all_servers`  
**Privilege escalation:** `sudo`

Creates the full directory structure, copies all configuration files, Dockerfiles, and Python scripts to the remote server, and injects secrets into the `.env` file. After this playbook completes the server is ready to launch the Docker Compose stack.

### Overview

| Property | Value |
|----------|-------|
| Playbook file | `ansible/04_1_prepare_stack.yml` |
| Target hosts | `all_servers` |
| `become` | Yes (`sudo`) |
| Project name | `cyber-sentinel` |
| Compose file | `docker-compose-cyber-sentinel.yml` |

---

### 1. Create required directories

Creates the full directory tree under `remote_deploy_base` in one loop. All directories are owned by `deployment_user` with mode `0755`.

```yaml title="ansible/04_1_prepare_stack.yml" linenums="1"
- name: Create required directories
  ansible.builtin.file:
    path: "{{ remote_deploy_base }}/{{ item }}"
    state: directory
    owner: "{{ deployment_user }}"
    group: "{{ deployment_user }}"
    mode: '0755'
  loop:
    - "config/prometheus"
    - "config/nginx/conf.d"
    - "config/nginx/certs"
    - "config/nginx/html"
    - "config/mongo"
    - "config/mysql"
    - "config/unbound"
    - "config/dns/dnsmasq.d"
    - "config/dns/var-log"
    - "config/kali"
    - "portainer_data"
    - "n8n_data"
    - "config/vault/data"
    - "config/vault/config"
    - "config/grafana/provisioning/datasources"
    - "config/grafana/provisioning/dashboards"
    - "config/grafana/dashboards"
```

---

### 2. Copy Docker Compose and Dockerfiles

Copies the main `docker-compose-cyber-sentinel.yml` file and both custom Dockerfiles (`Dockerfile.pdns` for `passive_dns`, `Dockerfile.log_processor` for `dns_log_processor`) to the remote deployment root.

```yaml title="ansible/04_1_prepare_stack.yml" linenums="1"
- name: Copy docker-compose file
  ansible.builtin.copy:
    src: "{{ source_docker_compose_file }}"
    dest: "{{ remote_docker_compose_file }}"
    owner: "{{ deployment_user }}"
    mode: '0644'

- name: Copy Dockerfile for Passive DNS
  ansible.builtin.copy:
    src: "{{ main_repo_source_dir }}/config/dns/Dockerfile.pdns"
    dest: "{{ remote_deploy_base }}/Dockerfile.pdns"
    owner: "{{ deployment_user }}"
    mode: '0644'

- name: Copy Dockerfile for DNS Log Processor
  ansible.builtin.copy:
    src: "{{ main_repo_source_dir }}/config/dns/Dockerfile.log_processor"
    dest: "{{ remote_deploy_base }}/Dockerfile.log_processor"
    owner: "{{ deployment_user }}"
    mode: '0644'

- name: Copy python script for DNS Log Processor
  ansible.builtin.copy:
    src: "{{ main_repo_source_dir }}/config/dns/log_processor.py"
    dest: "{{ remote_deploy_base }}/log_processor.py"
    owner: "{{ deployment_user }}"
    mode: '0644'
```

---

### 3. Inject secrets into `.env`

Uses `lineinfile` to write the three sensitive passwords into the `.env` file. The task uses `no_log: true` to prevent secrets from appearing in Ansible output or logs.

```yaml title="ansible/04_1_prepare_stack.yml" linenums="1"
- name: Ensure Secrets are in .env (Vault)
  ansible.builtin.lineinfile:
    path: "{{ remote_deploy_base }}/.env"
    regexp: "^{{ item.key }}="
    line: "{{ item.key }}={{ item.value }}"
    create: yes
    owner: "{{ deployment_user }}"
    mode: '0600'
  loop:
    - { key: 'GRAFANA_PASSWORD',      value: "{{ vault_grafana_password }}" }
    - { key: 'MONGODB_PASSWORD',       value: "{{ vault_mongodb_password }}" }
    - { key: 'MYSQL_ROOT_PASSWORD',    value: "{{ vault_mysql_root_password }}" }
  no_log: true
```

| Variable | Docker service |
|----------|----------------|
| `vault_grafana_password` | `grafana` — `GF_SECURITY_ADMIN_PASSWORD` |
| `vault_mongodb_password` | `mongo` — `MONGO_INITDB_ROOT_PASSWORD` |
| `vault_mysql_root_password` | `mysqldb` — `MYSQL_ROOT_PASSWORD` |

---

### 4. Copy service configuration files

Copies configuration files for each service that requires them: Unbound DNS resolver config, MongoDB init script, Grafana provisioning (datasources + dashboard JSON files), and Prometheus config.

```yaml title="ansible/04_1_prepare_stack.yml" linenums="1"
- name: Copy Unbound configuration file
  ansible.builtin.copy:
    src: "{{ main_repo_source_dir }}/config/unbound/unbound.conf"
    dest: "{{ remote_deploy_base }}/config/unbound/unbound.conf"
    owner: "{{ deployment_user }}"
    mode: '0644'

- name: Copy MongoDB initialization script
  ansible.builtin.copy:
    src: "{{ main_repo_source_dir }}/config/mongo/init_mongo.js"
    dest: "{{ remote_deploy_base }}/config/mongo/db_init.js"
    owner: "{{ deployment_user }}"
    mode: '0644'

- name: Copy Grafana Provisioning (Dashboards & Datasources)
  ansible.builtin.copy:
    src: "{{ main_repo_source_dir }}/config/grafana/provisioning/"
    dest: "{{ remote_deploy_base }}/config/grafana/provisioning/"
    owner: "{{ deployment_user }}"
    group: "{{ deployment_user }}"
    mode: '0644'
    directory_mode: '0755'

- name: Copy Prometheus configuration file
  ansible.builtin.copy:
    src: "{{ main_repo_source_dir }}/config/prometheus/prometheus.yml"
    dest: "{{ remote_deploy_base }}/config/prometheus/prometheus.yml"
    owner: "{{ deployment_user }}"
    group: "{{ deployment_user }}"
    mode: '0644'
```

---

### 5. Set critical file permissions

Two files require non-standard permissions that differ from the deployment user:

```yaml title="ansible/04_1_prepare_stack.yml" linenums="1"
- name: Prepare DNS log file with correct permissions
  ansible.builtin.file:
    path: "{{ remote_deploy_base }}/config/dns/var-log/dns.log"
    state: touch
    owner: "1000"
    group: "1000"
    mode: '0666'

- name: Set permissions for Vault data directory
  ansible.builtin.file:
    path: "{{ remote_deploy_base }}/config/vault/data"
    owner: "100"
    group: "1000"
    mode: '0700'
```

| Path | Owner | Mode | Reason |
|------|-------|------|--------|
| `config/dns/var-log/dns.log` | `1000:1000` | `0666` | `passive_dns` container writes as UID 1000; `dns_log_processor` reads it |
| `config/vault/data` | `100:1000` | `0700` | HashiCorp Vault container runs as UID 100 (`vault` user) |

---

### Full Playbook 04.1

```yaml title="ansible/04_1_prepare_stack.yml" linenums="1"
---
- name: 04.1 - Prepare Sentinel Stack environment
  hosts: all_servers
  become: yes

  vars:
    project_name: "cyber-sentinel"
    docker_compose_file_name: "docker-compose-cyber-sentinel.yml"
    source_docker_compose_file: "{{ main_repo_source_dir }}/docker/{{ docker_compose_file_name }}"
    remote_docker_compose_file: "{{ remote_deploy_base }}/{{ docker_compose_file_name }}"
    source_mysql_script: "{{ main_repo_source_dir }}/config/mysql/db_deployment.sql"
    mysql_init_log: "{{ remote_deploy_base }}/mysql_init.log"

  tasks:
    - name: Create required directories
      ansible.builtin.file:
        path: "{{ remote_deploy_base }}/{{ item }}"
        state: directory
        owner: "{{ deployment_user }}"
        group: "{{ deployment_user }}"
        mode: '0755'
      loop:
        - "config/prometheus"
        - "config/nginx/conf.d"
        - "config/nginx/certs"
        - "config/nginx/html"
        - "config/mongo"
        - "config/mysql"
        - "config/unbound"
        - "config/dns/dnsmasq.d"
        - "config/dns/var-log"
        - "config/kali"
        - "portainer_data"
        - "n8n_data"
        - "config/vault/data"
        - "config/vault/config"
        - "config/grafana/provisioning/datasources"
        - "config/grafana/provisioning/dashboards"
        - "config/grafana/dashboards"

    - name: Copy docker-compose file
      ansible.builtin.copy:
        src: "{{ source_docker_compose_file }}"
        dest: "{{ remote_docker_compose_file }}"
        owner: "{{ deployment_user }}"
        group: "{{ deployment_user }}"
        mode: '0644'

    - name: Copy Dockerfile for Passive DNS
      ansible.builtin.copy:
        src: "{{ main_repo_source_dir }}/config/dns/Dockerfile.pdns"
        dest: "{{ remote_deploy_base }}/Dockerfile.pdns"
        owner: "{{ deployment_user }}"
        mode: '0644'

    - name: Copy Dockerfile for DNS Log Processor
      ansible.builtin.copy:
        src: "{{ main_repo_source_dir }}/config/dns/Dockerfile.log_processor"
        dest: "{{ remote_deploy_base }}/Dockerfile.log_processor"
        owner: "{{ deployment_user }}"
        mode: '0644'

    - name: Copy python script for DNS Log Processor
      ansible.builtin.copy:
        src: "{{ main_repo_source_dir }}/config/dns/log_processor.py"
        dest: "{{ remote_deploy_base }}/log_processor.py"
        owner: "{{ deployment_user }}"
        mode: '0644'

    - name: Ensure Secrets are in .env (Vault)
      ansible.builtin.lineinfile:
        path: "{{ remote_deploy_base }}/.env"
        regexp: "^{{ item.key }}="
        line: "{{ item.key }}={{ item.value }}"
        create: yes
        owner: "{{ deployment_user }}"
        mode: '0600'
      loop:
        - { key: 'GRAFANA_PASSWORD',   value: "{{ vault_grafana_password }}" }
        - { key: 'MONGODB_PASSWORD',   value: "{{ vault_mongodb_password }}" }
        - { key: 'MYSQL_ROOT_PASSWORD',value: "{{ vault_mysql_root_password }}" }
      no_log: true

    - name: Copy Unbound configuration file
      ansible.builtin.copy:
        src: "{{ main_repo_source_dir }}/config/unbound/unbound.conf"
        dest: "{{ remote_deploy_base }}/config/unbound/unbound.conf"
        owner: "{{ deployment_user }}"
        mode: '0644'

    - name: Copy MongoDB initialization script
      ansible.builtin.copy:
        src: "{{ main_repo_source_dir }}/config/mongo/init_mongo.js"
        dest: "{{ remote_deploy_base }}/config/mongo/db_init.js"
        owner: "{{ deployment_user }}"
        mode: '0644'

    - name: Copy Grafana Provisioning (Dashboards & Datasources)
      ansible.builtin.copy:
        src: "{{ main_repo_source_dir }}/config/grafana/provisioning/"
        dest: "{{ remote_deploy_base }}/config/grafana/provisioning/"
        owner: "{{ deployment_user }}"
        group: "{{ deployment_user }}"
        mode: '0644'
        directory_mode: '0755'

    - name: Prepare DNS log file with correct permissions
      ansible.builtin.file:
        path: "{{ remote_deploy_base }}/config/dns/var-log/dns.log"
        state: touch
        owner: "1000"
        group: "1000"
        mode: '0666'

    - name: Set permissions for Vault data directory
      ansible.builtin.file:
        path: "{{ remote_deploy_base }}/config/vault/data"
        owner: "100"
        group: "1000"
        mode: '0700'

    - name: Copy Prometheus configuration file
      ansible.builtin.copy:
        src: "{{ main_repo_source_dir }}/config/prometheus/prometheus.yml"
        dest: "{{ remote_deploy_base }}/config/prometheus/prometheus.yml"
        owner: "{{ deployment_user }}"
        group: "{{ deployment_user }}"
        mode: '0644'

    - name: Copy Dashboard JSON files to the main dashboard folder
      ansible.builtin.copy:
        src: "{{ main_repo_source_dir }}/config/grafana/provisioning/dashboards/"
        dest: "{{ remote_deploy_base }}/config/grafana/dashboards/"
        owner: "{{ deployment_user }}"
        group: "{{ deployment_user }}"
        mode: '0644'
```

---

## 4.2 Deploy Containers

**File:** `ansible/04_2_deploy_containers.yml`  
**Hosts:** `all_servers`  
**Privilege escalation:** `sudo`

Pulls all Docker images and starts the full `cyber-sentinel` Docker Compose stack using `docker compose up --build -d`. The `--build` flag ensures custom images (`passive_dns`, `dns_log_processor`) are built from their Dockerfiles on the remote server.

### Overview

| Property | Value |
|----------|-------|
| Playbook file | `ansible/04_2_deploy_containers.yml` |
| Target hosts | `all_servers` |
| `become` | Yes (`sudo`) |
| Project name | `cyber-sentinel` |
| Command | `docker compose up --build -d` |

---

### Task — Pull and Start Sentinel Stack

```yaml title="ansible/04_2_deploy_containers.yml" linenums="1"
- name: Pull and Start Sentinel Stack
  ansible.builtin.shell:
    cmd: "docker compose -f {{ docker_compose_file_name }} -p {{ project_name }} up --build -d"
    chdir: "{{ remote_deploy_base }}"
  register: deploy_output
```

| Flag | Description |
|------|-------------|
| `-f` | Specifies the compose file name |
| `-p cyber-sentinel` | Sets the Docker Compose project name |
| `--build` | Forces rebuild of custom images (`passive_dns`, `dns_log_processor`) |
| `-d` | Detached mode — containers run in the background |

---

### Full Playbook 04.2

```yaml title="ansible/04_2_deploy_containers.yml" linenums="1"
---
- name: 04.2 - Deploy Docker stack
  hosts: all_servers
  become: yes

  vars:
    project_name: "cyber-sentinel"
    docker_compose_file_name: "docker-compose-cyber-sentinel.yml"

  tasks:
    - name: Pull and Start Sentinel Stack
      ansible.builtin.shell:
        cmd: "docker compose -f {{ docker_compose_file_name }} -p {{ project_name }} up --build -d"
        chdir: "{{ remote_deploy_base }}"
      register: deploy_output
```
