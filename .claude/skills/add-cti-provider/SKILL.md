---
name: add-cti-provider
description: Add a new threat-intelligence source (API or feed) to Cyber Sentinel end to end — Vault secret, Postgres settings and provider row, n8n workflow, AI prompt, AI Config UI, docs. Use when the user wants to integrate a new CTI provider or enrichment source (like Shodan InternetDB, urlscan.io, ThreatFox, URLhaus, RDAP, crt.sh).
---

# Add a CTI provider

Reference implementation: PR #28 (`306c111`, Shodan InternetDB + urlscan.io search). Read its diff for the touched files before starting:

```bash
git show 306c111 --stat
```

## 0. Decide first (grill if unclear)

Run `grill-me` style questions for anything not stated:
- Main workflow (per observable) or a separate workflow (like *Deep Recon*)?
- **Context only, or does it change the score?** Default is context only (VirusTotal decides; others confirm or add context). If the user wants it in the score, the change to `compute_threat_score()` is part of this task — show the rule change and its effect on existing verdicts before writing it.
- API key needed? Free-tier quota (per day / per minute)? What happens when it runs out?
- Which observables: every one, or only above the VirusTotal gate (`vt_gate_min_malicious`)?

## 1. Secret (skip if no key)

- `docs/deployment.md` vault.yml example: add `vault_<provider>_api_key: ""` with a comment on what it is for.
- `ansible/06_1_initialize_provision_vault.yml`: add the var to `required_vars_always` and a line to the loop in `[06.1.4.1]` → path `cyber-sentinel/api-keys/<provider>/api-key`.
- Never write the real key anywhere in the repo.

## 2. Database (`config/postgres/`)

Follow the `db-schema-change` skill. Typically:
- `db_deployment.sql`: provider row in `cyber_sentinel.dic_source_providers` (`ON CONFLICT (name) DO NOTHING`).
- `db_ai_pipeline.sql`: a new `SECTION 7x` with:
  - **every** switch and limit as an `ai_settings` row (`<provider>_enabled`, days, daily limit, …) — no constants in the workflow;
  - storage for the results if they are kept (column or table, idempotent);
  - a new prompt version in `prompt_templates` (`is_active = FALSE`) that describes `evidence.<provider>`, its `no_data` status, and how much weight it carries.
- Bump `Version:` in the file header and list the new section.

## 3. n8n workflow (`config/n8n/workflows/`)

- Small change (parameters, one HTTP node, prompt text): edit the exported JSON directly. Keep node IDs/positions consistent; credentials stay as references, never inline.
- New branch or several nodes: describe the nodes (type, inputs, outputs, error handling) and let the user build them in the UI and export; then review the export.
- Either way check: reads the key from Vault, respects the `ai_settings` switch, handles timeout / rate-limit / empty result as `status: "no_data"` or `"error"` without failing the run, and the result is added to the agent's `evidence` and the e-mail.

## 4. AI Config UI (`config/ai_config_ui/app.py`)

Add each new `ai_settings` key to the settings dict, in the existing style: `min`, `max`, `integer`, `stage`, `switch` (for 0/1), plain-language `label`, `what`, `raise`, `lower`. Mention quota and whether it changes the score. Update `INTEGRATION.md` if the integration contract changed.

## 5. Docs

`docs/n8n.md` (what the source adds and when it is called), `docs/database.md` (new settings/tables), `docs/architecture.md` and `docs/assets/cyber_sentinel_flow.svg` if the flow changed. Release notes are done by `release-docs`.

## 6. Test on dev

- Claude may run on dev only: `cd ansible && ansible-playbook -i hosts.ini 04_3_db_postgres.yml --limit vm-prox-dev` (plus `06_1_…`, `04_5_ai_config_editor.yml`, `04_6_post_config.yml` as needed). SSH uses the user's YubiKey — if the run needs a touch/PIN or fails on auth, hand the command to the user.
- Run the SQL twice to prove idempotency (see `db-schema-change`).
- On dev the new prompt version may be activated for testing; on prod it stays an inactive draft.
- Prod (`rpi5-prod`): never run. Give the user the exact commands.

## Done when

Secret provisioned, settings in DB and UI, workflow handles all failure modes, prompt draft written, docs updated, dev deploy passed, and the list of manual steps (n8n import/publish, prompt activation, vault.yml value) is written down for the release notes.
