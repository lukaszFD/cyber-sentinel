# Playbook 04.7 — Hailo-10H Native Inference Service

**File:** [`ansible/04_7_deploy_hailo.yml`](https://github.com/lukaszFD/cyber-sentinel/blob/main/ansible/04_7_deploy_hailo.yml)
**Hosts:** `rpi5-prod`
**Privilege escalation:** [`become: yes`](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_privilege_escalation.html) (sudo)

Manages `hailo-ollama` — an Ollama-compatible API server from Hailo's public [`hailo_model_zoo_genai`](https://github.com/hailo-ai/hailo_model_zoo_genai) project, built on [HailoRT](https://github.com/hailo-ai/hailort) — as a **native [systemd](https://www.freedesktop.org/wiki/Software/systemd/) service**, not a container. Stages the unit file, enables and starts the service, verifies the [Hailo-10H](https://hailo.ai/products/ai-accelerators/hailo-10-for-generative-ai-and-edge-computing/) NPU is actually in use, and provisions the configured LLMs via the service's own REST API.

**Related pages:**
[Future Roadmap — 2b. Hailo-10H NPU Inference](future-roadmap.md#2b-hailo-10h-npu-inference) ·
[Deployment](deployment.md) ·
[Stack & Containers (04.1–2)](ansible-04-stack.md) ·
[Firewall (02)](ansible-02-security.md) ·
[Reverse Proxy (05)](ansible-05-proxy.md) ·
[Vault & Secrets (06)](ansible-06-vault.md) ·
[Architecture](architecture.md)

---

## 04.7 Overview

| Property | Value |
|----------|-------|
| Playbook file | [`ansible/04_7_deploy_hailo.yml`](https://github.com/lukaszFD/cyber-sentinel/blob/main/ansible/04_7_deploy_hailo.yml) |
| Target hosts | `rpi5-prod` only |
| `become` | Yes (`sudo`) |
| systemd unit source | `config/hailo/hailo-ollama.service` |
| Installed unit path | `/etc/systemd/system/hailo-ollama.service` |
| Service port | `8000` (confirmed via live `ss -tlnp`, not Ollama's conventional 11434) |
| API used for provisioning | `hailo-ollama`'s own REST API (`/hailo/v1/list`, `/api/pull`) — no `docker exec` |

### Dependencies

| Dependency | Why |
|------------|-----|
| `/usr/bin/hailo-ollama` already present on the host | This playbook manages the service; it does **not** install the binary — see [Known gap](#known-gap-installation-not-iacd) |
| Hailo-10H card physically installed | Section 1 fails fast otherwise |
| Host-side PCIe driver (`hailo1x`) and firmware already loaded | Verified via `lspci`, `dmesg`, and `hailortcli fw-control identify` before this playbook runs |
| [Playbook 02](ansible-02-security.md) | UFW must allow `8000/tcp` from `10.10.10.0/24` — otherwise Open WebUI cannot reach the service even though both are running correctly |

### Outputs

After a successful run:

- `/etc/systemd/system/hailo-ollama.service` installed, enabled, and started
- `hailo-ollama` reachable at `http://127.0.0.1:8000` and on the host's `internal_network` gateway address (`10.10.10.1:8000`), which is how the containerized Open WebUI reaches it
- Three models pulled and confirmed present: `deepseek_r1_distill_qwen:1.5b`, `qwen2.5-coder:1.5b`, `llama3.2:3b`

### Pipeline sections

The playbook is organised into four explicit sections; tasks are numbered hierarchically as `[04.7.S.T]`:

| Section | Name | Purpose |
|---------|------|---------|
| 1 | Host-side sanity checks | Confirm the NPU device node and the `hailo-ollama` binary both exist before touching systemd |
| 2 | systemd service | Stage the unit file, reload the daemon if it changed, enable and start the service |
| 3 | Wait for API and verify NPU use | Poll the API until responsive; pull recent logs as evidence the device was actually opened |
| 4 | Model provisioning | Query the real available model list, fail loudly on any mismatch, then pull |

---

## 04.7 Section 1 — Host-side sanity checks

Verifies two independent prerequisites before any systemd changes: the `/dev/hailo0` device node (proves the PCIe driver and firmware are loaded) and the `hailo-ollama` binary itself. Failing fast here avoids enabling a service that would only fail silently or loop-crash.

```yaml title="ansible/04_7_deploy_hailo.yml" linenums="76"
- name: "[04.7.1.1] Verify Hailo device node exists on host"
  ansible.builtin.stat:
    path: "{{ hailo_device }}"
  register: hailo_dev_stat

- name: "[04.7.1.2] Fail if Hailo device is not present"
  ansible.builtin.fail:
    msg: >
      {{ hailo_device }} not found on host. The hailo1x PCIe driver
      and SOC firmware must be loaded before this playbook runs.
      Check `lspci | grep -i hailo`, `dmesg | grep -i hailo`, and
      `hailortcli fw-control identify`.
  when: not hailo_dev_stat.stat.exists

- name: "[04.7.1.3] Verify hailo-ollama binary is installed"
  ansible.builtin.stat:
    path: "{{ hailo_ollama_bin }}"
  register: hailo_ollama_bin_stat

- name: "[04.7.1.4] Fail if hailo-ollama binary is missing"
  ansible.builtin.fail:
    msg: >
      {{ hailo_ollama_bin }} not found. This playbook manages the
      systemd service for an already-installed hailo-ollama binary
      but does not install it. Install it first — either the
      pre-built .deb from Hailo's Developer Zone, or build from
      source per https://github.com/hailo-ai/hailo_model_zoo_genai
      — then re-run this playbook.
  when: not hailo_ollama_bin_stat.stat.exists
```

---

## 04.7 Section 2 — systemd service

Copies the unit file with [`ansible.builtin.copy`](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/copy_module.html) — no [Jinja2](https://jinja.palletsprojects.com/) placeholders in this file, so `copy:` rather than `template:` is correct here (same reasoning as [04.6's SQL staging](ansible-04-db.md)). Reloads the systemd daemon only when the unit file actually changed, then enables and starts the service.

```yaml title="ansible/04_7_deploy_hailo.yml" linenums="103"
- name: "[04.7.2.1] Deploy hailo-ollama systemd unit"
  ansible.builtin.copy:
    src: "{{ main_repo_source_dir }}/config/hailo/hailo-ollama.service"
    dest: "/etc/systemd/system/hailo-ollama.service"
    owner: root
    group: root
    mode: '0644'
  register: hailo_unit_deployed

- name: "[04.7.2.2] Reload systemd daemon if unit changed"
  ansible.builtin.systemd:
    daemon_reload: yes
  when: hailo_unit_deployed.changed

- name: "[04.7.2.3] Enable and start hailo-ollama service"
  ansible.builtin.systemd:
    name: hailo-ollama
    state: started
    enabled: yes
```

```ini title="config/hailo/hailo-ollama.service"
[Unit]
Description=Hailo-Ollama — Ollama-compatible API server on Hailo-10H NPU
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/hailo-ollama
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```
---

## 04.7 Section 3 — Wait for API and verify NPU is actually in use

Polls the API rather than trusting `systemctl start` alone — a service can report `active (running)` while still failing to bind its port. Once responsive, pulls recent `journalctl` output as evidence the process actually opened the NPU device, rather than idling or silently falling back.

```yaml title="ansible/04_7_deploy_hailo.yml" linenums="122"
- name: "[04.7.3.1] Wait for hailo-ollama API to become responsive"
  ansible.builtin.uri:
    url: "http://127.0.0.1:{{ hailo_ollama_port }}/hailo/v1/list"
    status_code: 200
  register: result
  until: result.status == 200
  retries: 15
  delay: 5

- name: "[04.7.3.2] Check recent hailo-ollama logs for device errors"
  ansible.builtin.command: "journalctl -u hailo-ollama -n 50 --no-pager"
  register: hailo_logs
  changed_when: false

- name: "[04.7.3.3] Display recent hailo-ollama logs"
  ansible.builtin.debug:
    msg: "{{ hailo_logs.stdout_lines }}"
```

| Detail | Value |
|--------|-------|
| Health-check endpoint | `/hailo/v1/list` — not `/api/tags`, which this API does not implement |
| Retry budget | 15 × 5 s ≈ 75 s |
| Log source | `journalctl -u hailo-ollama`, not `docker logs` — this is a systemd service, not a container |

---

## 04.7 Section 4 — Model provisioning

Queries the real, live model catalog before attempting any pull, rather than assuming names carried over from earlier, incorrect Ollama-convention assumptions. Fails loudly — listing exactly what *is* available — if any configured model name doesn't match, instead of attempting a pull that would 404.

```yaml title="ansible/04_7_deploy_hailo.yml" linenums="140"
- name: "[04.7.4.1] Query available models from hailo-ollama"
  ansible.builtin.uri:
    url: "http://127.0.0.1:{{ hailo_ollama_port }}/hailo/v1/list"
    method: GET
    return_content: yes
  register: available_models_raw

- name: "[04.7.4.2] Parse available model list"
  ansible.builtin.set_fact:
    available_models: "{{ (available_models_raw.content | from_json).models | default([]) }}"

- name: "[04.7.4.3] Fail if any configured model is not in the available list"
  ansible.builtin.fail:
    msg: >
      Configured model '{{ item }}' was not found in hailo-ollama's
      model zoo. Available models: {{ available_models }}.
      Update ai_models in this playbook to match real model names
      before re-running.
  when: item not in available_models
  loop: "{{ ai_models }}"

- name: "[04.7.4.4] Pull configured models via hailo-ollama API"
  ansible.builtin.uri:
    url: "http://127.0.0.1:{{ hailo_ollama_port }}/api/pull"
    method: POST
    body_format: json
    body:
      model: "{{ item }}"
      stream: false
    status_code: 200
    timeout: 300
  loop: "{{ ai_models }}"
  register: pull_result

- name: "[04.7.4.5] Display pull results"
  ansible.builtin.debug:
    msg: "Pulled: {{ item.item }} — status {{ item.status }}"
  loop: "{{ pull_result.results }}"
```
---

---

## 04.7 Variables reference

| Variable | Source | Purpose |
|----------|--------|---------|
| `main_repo_source_dir` | [`group_vars`](ansible-01-secrets.md) | Local repo root on control machine |
| `hailo_ollama_bin` | playbook-local | `/usr/bin/hailo-ollama` |
| `hailo_ollama_port` | playbook-local | `8000` |
| `hailo_device` | playbook-local | `/dev/hailo0` |
| `ai_models` | playbook-local | `deepseek_r1_distill_qwen:1.5b`, `qwen2.5-coder:1.5b`, `llama3.2:3b` — verified against live `/hailo/v1/list`, not the published Hailo model catalog, which does not fully match |

---

## Related: hailo-ollama's own configuration

On this HailoRT version (5.1.1), `hailo-ollama` reads `/etc/xdg/hailo-ollama/hailo-ollama.json` on startup — not a file this repo manages, and not what earlier design assumptions (`config/hailo/config.yaml`) expected before the actual schema was confirmed on-device:

```json
{
    "server": {
        "host": "0.0.0.0",
        "port": 8000
    },
    "library": {
        "host": "dev-public.hailo.ai",
        "port": 443
    },
    "main_poll_time_ms": 200
}
```
