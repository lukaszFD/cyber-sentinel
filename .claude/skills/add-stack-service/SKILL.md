---
name: add-stack-service
description: Add a new container/service to the Cyber Sentinel Docker stack (pinned multi-arch image, compose, Nginx TLS proxy, Vault secrets, Ansible wiring, docs). Use when the user wants to deploy a new tool or self-built service alongside Pi-hole, n8n, Grafana, Vault, AI Config UI, etc.
---

# Add a service to the stack

## 0. Decide first

Start from the GitHub issue (`type:feature`, area, milestone, parent epic); branch `YYYYMMDD_<english_name>`. Ask (grill) for anything unknown: does it have a web UI, which port, which internal network/IP, persistent volumes, does it need Postgres or Vault, upstream image or our own build (`config/<svc>/Dockerfile`, like `ai_config_ui`).

## 1. Image — pinned, multi-arch (mandatory)

In `ansible/group_vars/all/images.yml`, follow the header procedure:

```bash
docker buildx imagetools inspect <repo>:<tag> | awk '/^Digest:/{print $2; exit}'
docker buildx imagetools inspect <repo>@<digest> | grep linux/arm64
```

Add `repo:tag@sha256:<index digest>`. If `linux/arm64` is missing, stop and tell the user — prod is a Raspberry Pi 5. Own builds must build on both `amd64` and `arm64`.

## 2. Compose

`docker/docker-compose-cyber-sentinel.yml` (a Jinja2 template): `image: "{{ cs_images.<svc> }}"`, `container_name`, fixed IP on the internal network (check the free ones in the file), `restart`, healthcheck, volumes under `{{ remote_deploy_base }}`. No host `ports:` for anything with a UI — it goes through Nginx.

- **Healthcheck is mandatory** — in the compose service or as `HEALTHCHECK` in an own Dockerfile (Trivy DS-0026 otherwise blocks the PR as an unresolved review thread). A worker without a port writes a heartbeat file to a `tmpfs` path and the check tests its age.
- **`mem_limit`** for anything that can grow (browsers, workers). On the RPi limits only work with the memory cgroup on (`cgroup_enable=memory cgroup_memory=1` in `/boot/firmware/cmdline.txt`); check with `docker info | grep -i "no memory limit"`.
- Hardening like the sandbox containers: non-root `user:`, `read_only: true` + `tmpfs`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]` where the image allows it.

## 3. Secrets — HashiCorp Vault (mandatory)

- New passwords/keys: `vault_<svc>_…` in every `ansible/host_vars/<host>/vault.yml` (generated passwords: `ansible/tools/vault_add_password.sh`), listed in each `vault.yml.example` and `docs/deployment.md`, provisioned to HashiCorp Vault in `ansible/06_1_initialize_provision_vault.yml`. Letters and digits only for anything that ends up in SQL or `.env`.
- `ansible/templates/env.j2` only for what the container needs at start-up and cannot read from Vault.

## 4. Nginx TLS (mandatory for any UI)

- `ansible/05_deploy_proxy.yml`: add `{ name: "<svc>", port: <p>, internal_host: "<container_name>", hostname: "<optional>" }` to `services`.
- `vault_<svc>_cert` / `vault_<svc>_key` in every `host_vars/<host>/vault.yml` (document in `docs/deployment.md`), and `<svc>` in the cert list of `06_1` `[06.1.5.1]`. Until a cert exists, a `cert_fallback` entry in 05 can reuse another service's pair (the browser then warns about the name).
- Name resolution: a Local DNS record `<hostname>.<suffix>` in the main Pi-hole of each host. macOS resolves `.local` through mDNS and never asks Pi-hole — on the Mac the dev names go into `/etc/hosts` (`192.168.0.5 …`).

## 5. Ansible wiring

Config files copied in `04_1_prepare_stack.yml`, own builds/DB init in a dedicated `04_x` playbook (pattern: `04_5_ai_config_editor.yml`), included from `00_main.yml` in the right order. Every task gets the `[NN.x.y]` name prefix like the existing ones.

## 6. Test on dev

Claude may deploy to dev only:

```bash
cd ansible && ansible-playbook -i hosts.ini 00_main.yml --limit vm-prox-dev
```

(or just the touched playbooks). SSH needs the user's YubiKey — if auth prompts or fails, hand the command over. Run deploys visibly in a terminal tab. Check the container is `healthy`, its memory limit shows in `docker stats`, and the UI answers through `https://<hostname>.local`. Prod (`rpi5-prod`): never run — give the user the commands, including any host step (cgroup, reboot → unseal Vault) and the image size if it is large (check free disk first).

## 7. Docs

`docs/docker-compose.md` (service, image, IP, volumes, limits), `docs/architecture.md` + flow SVG if relevant, `docs/releases.md` entry with the upgrade steps, `.trivyignore` only with a written justification for each accepted finding.
