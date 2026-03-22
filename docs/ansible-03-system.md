# Playbook 03 — System Setup (Docker & Packages)

**File:** `ansible/03_setup_system.yml`  
**Hosts:** `all_servers`  
**Privilege escalation:** `sudo`

Installs **Docker Engine**, the **Docker Compose plugin**, and all prerequisite system packages. Automatically detects the CPU architecture (`x86_64`, `aarch64`, `armv7l`) and configures the correct Docker APT repository. On Raspberry Pi 5 with Argon NEO 5 hardware, also installs and configures the fan controller service.

---

## Overview

| Property | Value |
|----------|-------|
| Playbook file | `ansible/03_setup_system.yml` |
| Target hosts | `all_servers` |
| `become` | Yes (`sudo`) |
| Architecture support | `x86_64` (amd64), `aarch64` (arm64), `armv7l` (armhf) |

---

## Architecture Mapping

Ansible reads `ansible_architecture` from the target host and maps it to the Docker APT architecture tag:

```yaml title="ansible/03_setup_system.yml" linenums="1"
vars:
  arch_mapping:
    x86_64: "amd64"
    aarch64: "arm64"
    armv7l: "armhf"
```

This value is used when adding the Docker APT repository to ensure the correct binary packages are installed.

---

## Tasks

### 1. Install prerequisite and monitoring packages

Installs all system-level dependencies needed before Docker can be set up, plus monitoring and utility tools used by the stack.

```yaml title="ansible/03_setup_system.yml" linenums="1"
- name: Install prerequisite and monitoring packages
  ansible.builtin.apt:
    name:
      - apt-transport-https  # HTTPS APT sources
      - ca-certificates       # SSL certificate validation
      - curl                  # HTTP client
      - gnupg                 # GPG key management
      - lsb-release           # Linux Standard Base info
      - python3-pip           # Python package manager
      - python3-docker        # Ansible Docker module
      - python3-hvac          # HashiCorp Vault Python client
      - htop                  # Interactive process viewer
      - smartmontools          # Disk health monitoring (smartctl)
      - fail2ban              # Brute-force SSH protection
      - jq                    # JSON processor (used by n8n/API scripts)
      - sqlite3               # Lightweight database utility
    state: present
    update_cache: yes
```

---

### 2. Add Docker GPG key

Downloads the official Docker GPG key to `/etc/apt/keyrings/docker.asc` using the modern keyring approach (not the legacy `apt-key`).

```yaml title="ansible/03_setup_system.yml" linenums="1"
- name: Create directory for Docker GPG key
  ansible.builtin.file:
    path: /etc/apt/keyrings
    state: directory
    mode: '0755'

- name: Add Docker official GPG key (modern way)
  ansible.builtin.get_url:
    url: https://download.docker.com/linux/debian/gpg
    dest: /etc/apt/keyrings/docker.asc
    mode: '0644'
```

---

### 3. Add Docker APT repository

Adds the Docker stable repository using the detected architecture. The `arch_mapping` variable ensures the correct package variant is selected.

```yaml title="ansible/03_setup_system.yml" linenums="1"
- name: Add Docker repository for current architecture
  ansible.builtin.apt_repository:
    repo: >
      deb [arch={{ arch_mapping[ansible_architecture] }} signed-by=/etc/apt/keyrings/docker.asc]
      https://download.docker.com/linux/debian
      {{ ansible_distribution_release }}
      stable
    state: present
```

---

### 4. Install Docker Engine and Compose plugin

Installs Docker CE, the CLI, `containerd`, and the `docker compose` plugin (V2).

```yaml title="ansible/03_setup_system.yml" linenums="1"
- name: Install Docker Engine and Compose plugin
  ansible.builtin.apt:
    name:
      - docker-ce
      - docker-ce-cli
      - containerd.io
      - docker-compose-plugin
    state: present
    update_cache: yes
```

---

### 5. Add user to docker group

Adds the Ansible connection user to the `docker` group so that `docker` commands can be run without `sudo`. Resets the SSH connection immediately to apply the group change in the same playbook run.

```yaml title="ansible/03_setup_system.yml" linenums="1"
- name: Ensure docker group exists
  ansible.builtin.group:
    name: docker
    state: present

- name: Add dynamic user from inventory to docker group
  ansible.builtin.user:
    name: "{{ ansible_user }}"
    groups: docker
    append: yes
  register: user_group_update

- name: Reset connection to apply group changes
  ansible.builtin.meta: reset_connection
```

---

### 6. Verify Docker installation

Runs `docker --version` and prints the result to the Ansible output for confirmation.

```yaml title="ansible/03_setup_system.yml" linenums="1"
- name: Verify Docker installation
  ansible.builtin.command: docker --version
  register: docker_version
  changed_when: false

- name: Show Docker version
  ansible.builtin.debug:
    msg: "Docker version on {{ inventory_hostname }} is {{ docker_version.stdout }}"
```

---

### 7. Argon NEO 5 fan control (Raspberry Pi 5 only)

This block runs **only on `aarch64`** targets. It downloads and installs the Argon NEO 5 fan controller script and configures thresholds optimised for sustained AI workloads.

```yaml title="ansible/03_setup_system.yml" linenums="1"
- name: Task - Argon NEO 5 Fan Control Setup (RPi 5)
  block:
    - name: Download Argon NEO 5 for RPi 5 script
      ansible.builtin.get_url:
        url: https://download.argon40.com/argon1.sh
        dest: /tmp/argon_rpi5.sh
        mode: '0755'
        force: yes

    - name: Run Argon NEO 5 installation script
      ansible.builtin.shell: /tmp/argon_rpi5.sh
      args:
        executable: /bin/bash
        creates: /usr/bin/argonone-config

    - name: Configure Fan Thresholds for AI Workloads
      ansible.builtin.copy:
        dest: /etc/argononed.conf
        content: |
          # Argon Fan Speed Configuration (CPU)
          55=100
          65=100
        owner: root
        group: root
        mode: '0644'
      notify: Restart Argon Service

    - name: Ensure Argon cooling service is running
      ansible.builtin.systemd:
        name: argononed
        state: started
        enabled: yes
  when: ansible_architecture == "aarch64"

handlers:
  - name: Restart Argon Service
    ansible.builtin.systemd:
      name: argononed
      state: restarted
```

Fan threshold configuration:

| CPU Temp | Fan Speed |
|----------|-----------|
| ≥ 55°C | 100% |
| ≥ 65°C | 100% |

!!! note
    Both thresholds are set to 100% to prioritise thermal headroom during continuous AI inference workloads (Google Gemini API calls in n8n).

---

## Full Playbook

```yaml title="ansible/03_setup_system.yml" linenums="1"
---
- name: 03 - Setup System (x86 & ARM)
  hosts: all_servers
  become: yes
  vars:
    arch_mapping:
      x86_64: "amd64"
      aarch64: "arm64"
      armv7l: "armhf"

  tasks:
    - name: Install prerequisite and monitoring packages
      ansible.builtin.apt:
        name:
          - apt-transport-https
          - ca-certificates
          - curl
          - gnupg
          - lsb-release
          - python3-pip
          - python3-docker
          - python3-hvac
          - htop
          - smartmontools
          - fail2ban
          - jq
          - sqlite3
        state: present
        update_cache: yes

    - name: Create directory for Docker GPG key
      ansible.builtin.file:
        path: /etc/apt/keyrings
        state: directory
        mode: '0755'

    - name: Add Docker official GPG key (modern way)
      ansible.builtin.get_url:
        url: https://download.docker.com/linux/debian/gpg
        dest: /etc/apt/keyrings/docker.asc
        mode: '0644'

    - name: Add Docker repository for current architecture
      ansible.builtin.apt_repository:
        repo: >
          deb [arch={{ arch_mapping[ansible_architecture] }} signed-by=/etc/apt/keyrings/docker.asc]
          https://download.docker.com/linux/debian
          {{ ansible_distribution_release }}
          stable
        state: present

    - name: Install Docker Engine and Compose plugin
      ansible.builtin.apt:
        name:
          - docker-ce
          - docker-ce-cli
          - containerd.io
          - docker-compose-plugin
        state: present
        update_cache: yes

    - name: Ensure docker group exists
      ansible.builtin.group:
        name: docker
        state: present

    - name: Add dynamic user from inventory to docker group
      ansible.builtin.user:
        name: "{{ ansible_user }}"
        groups: docker
        append: yes
      register: user_group_update

    - name: Reset connection to apply group changes
      ansible.builtin.meta: reset_connection

    - name: Verify Docker installation
      ansible.builtin.command: docker --version
      register: docker_version
      changed_when: false

    - name: Show Docker version
      ansible.builtin.debug:
        msg: "Docker version on {{ inventory_hostname }} is {{ docker_version.stdout }}"

    - name: Task - Argon NEO 5 Fan Control Setup (RPi 5)
      block:
        - name: Download Argon NEO 5 for RPi 5 script
          ansible.builtin.get_url:
            url: https://download.argon40.com/argon1.sh
            dest: /tmp/argon_rpi5.sh
            mode: '0755'
            force: yes

        - name: Run Argon NEO 5 installation script
          ansible.builtin.shell: /tmp/argon_rpi5.sh
          args:
            executable: /bin/bash
            creates: /usr/bin/argonone-config

        - name: Configure Fan Thresholds for AI Workloads
          ansible.builtin.copy:
            dest: /etc/argononed.conf
            content: |
              # Argon Fan Speed Configuration (CPU)
              55=100
              65=100
            owner: root
            group: root
            mode: '0644'
          notify: Restart Argon Service

        - name: Ensure Argon cooling service is running
          ansible.builtin.systemd:
            name: argononed
            state: started
            enabled: yes
      when: ansible_architecture == "aarch64"

  handlers:
    - name: Restart Argon Service
      ansible.builtin.systemd:
        name: argononed
        state: restarted
```
