# Playbook 04.5 — AI Suite Deployment (Ollama)

**File:** `ansible/04_5_deploy_AI.yml`  
**Hosts:** `all_servers`  
**Privilege escalation:** `sudo`

Deploys the **Ollama** local AI inference server and pulls two language models used for offline AI analysis within the Cyber Sentinel stack. This playbook is optional — it extends the platform with local LLM capabilities alongside the cloud-based Google Gemini integration.

---

## Overview

| Property | Value |
|----------|-------|
| Playbook file | `ansible/04_5_deploy_AI.yml` |
| Target hosts | `all_servers` |
| `become` | Yes (`sudo`) |
| Docker network | `cyber-sentinel_internal_network` |
| Ollama port | `11434` (host-exposed) |
| Memory limit | `4 GB` |

---

## AI Models

Two models are pulled automatically:

| Model | Size | Purpose |
|-------|------|---------|
| `llama3.2:3b` | ~2 GB | General-purpose reasoning and text analysis |
| `deepseek-coder:1.3b` | ~800 MB | Code analysis and script inspection |

---

## 1. Task 4.1 — Ensure Docker network exists

Verifies that the `cyber-sentinel_internal_network` bridge network is present before attempting to attach Ollama to it.

```yaml title="ansible/04_5_deploy_AI.yml" linenums="1"
- name: Task 4.1 - Ensure Docker network exists
  community.docker.docker_network:
    name: "{{ docker_network }}"
    state: present
```

---

## 2. Task 4.2 — Ensure Ollama volume exists

Creates the named Docker volume `ollama_data` that persists downloaded model weights between container restarts.

```yaml title="ansible/04_5_deploy_AI.yml" linenums="1"
- name: Task 4.2 - Ensure Ollama volume exists
  community.docker.docker_volume:
    name: ollama_data
    state: present
```

---

## 3. Task 4.3 — Run Ollama container

Starts the Ollama container with a 4 GB memory limit, attached to the Cyber Sentinel internal network, with port `11434` exposed to the host for API access.

```yaml title="ansible/04_5_deploy_AI.yml" linenums="1"
- name: Task 4.3 - Run Ollama Container
  community.docker.docker_container:
    name: ollama
    image: ollama/ollama:latest
    state: started
    restart_policy: always
    networks:
      - name: "{{ docker_network }}"
    ports:
      - "11434:11434"
    volumes:
      - "ollama_data:/root/.ollama"
    memory: 4g
```

!!! note "Memory limit"
    The `memory: 4g` cap prevents Ollama from consuming all available RAM on lower-spec hardware such as Raspberry Pi. Increase this value on servers with more RAM if you plan to run larger models.

---

## 4. Task 4.4 — Wait for Ollama API to be ready

Polls the Ollama REST API (`/api/tags`) until it returns HTTP 200, with up to 10 retries at 5-second intervals.

```yaml title="ansible/04_5_deploy_AI.yml" linenums="1"
- name: Task 4.4 - Wait for Ollama API to be ready
  ansible.builtin.uri:
    url: "http://localhost:11434/api/tags"
    status_code: 200
  register: result
  until: result.status == 200
  retries: 10
  delay: 5
```

---

## 5. Task 4.5 — Pull AI models

Pulls each model defined in the `ai_models` variable by running `ollama pull` inside the container. This downloads model weights to the `ollama_data` volume.

```yaml title="ansible/04_5_deploy_AI.yml" linenums="1"
vars:
  ai_models:
    - "llama3.2:3b"
    - "deepseek-coder:1.3b"

tasks:
  - name: Task 4.5 - Pull AI Models (Llama and DeepSeek)
    command: "docker exec ollama ollama pull {{ item }}"
    loop: "{{ ai_models }}"
    register: pull_result
    changed_when: "'success' in pull_result.stdout"
```

---

## 6. Task 4.6 — Verify models installation

Runs `ollama list` inside the container and prints the list of installed models to the Ansible output for confirmation.

```yaml title="ansible/04_5_deploy_AI.yml" linenums="1"
- name: Task 4.6 - Verify Models Installation
  command: "docker exec ollama ollama list"
  register: models_list

- name: Debug - Show Installed Models
  debug:
    msg: "Installed AI Models: {{ models_list.stdout }}"
```

---

## Full Playbook

```yaml title="ansible/04_5_deploy_AI.yml" linenums="1"
---
- name: Deploy AI Suite for Cyber Sentinel
  hosts: all_servers
  become: yes

  vars:
    docker_network: "cyber-sentinel_internal_network"
    ai_models:
      - "llama3.2:3b"
      - "deepseek-coder:1.3b"

  tasks:
    - name: Task 4.1 - Ensure Docker network exists
      community.docker.docker_network:
        name: "{{ docker_network }}"
        state: present

    - name: Task 4.2 - Ensure Ollama volume exists
      community.docker.docker_volume:
        name: ollama_data
        state: present

    - name: Task 4.3 - Run Ollama Container
      community.docker.docker_container:
        name: ollama
        image: ollama/ollama:latest
        state: started
        restart_policy: always
        networks:
          - name: "{{ docker_network }}"
        ports:
          - "11434:11434"
        volumes:
          - "ollama_data:/root/.ollama"
        memory: 4g

    - name: Task 4.4 - Wait for Ollama API to be ready
      ansible.builtin.uri:
        url: "http://localhost:11434/api/tags"
        status_code: 200
      register: result
      until: result.status == 200
      retries: 10
      delay: 5

    - name: Task 4.5 - Pull AI Models (Llama and DeepSeek)
      command: "docker exec ollama ollama pull {{ item }}"
      loop: "{{ ai_models }}"
      register: pull_result
      changed_when: "'success' in pull_result.stdout"

    - name: Task 4.6 - Verify Models Installation
      command: "docker exec ollama ollama list"
      register: models_list

    - name: Debug - Show Installed Models
      debug:
        msg: "Installed AI Models: {{ models_list.stdout }}"
```
