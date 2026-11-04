---
name: grill-me
description: Interview the user relentlessly about a plan or design until every decision is resolved, before any code is written. Use when the user says "grill me", "przepytaj mnie", asks to stress-test a plan, or before starting a non-trivial Cyber Sentinel change (new CTI provider, schema change, new service, release).
---

# Grill me

Walk the decision tree of the user's plan one branch at a time until nothing is left open. Do not write or change code during the grilling.

## How to run it

1. Restate the goal in one sentence and list the open decisions you see (short, as a tree: decisions that unlock others first).
2. Ask **one question at a time**. Each question:
   - names the decision and why it matters (one line),
   - gives your recommended answer first, with the reason,
   - offers 1–3 realistic alternatives.
   Use AskUserQuestion when the answer fits 2–4 options; otherwise ask in plain text.
3. Before asking, check whether the code answers it. If the repo already decides it (a convention in CLAUDE.md, an existing pattern in `ansible/`, `config/postgres/`, `config/n8n/workflows/`, `config/ai_config_ui/`), state what you found instead of asking.
4. After each answer, follow the branch it opens. Push back when an answer contradicts an earlier one, the repo's conventions, or creates a risk — say so plainly and ask again.
5. Keep going until every branch is closed. Do not stop early because the plan "looks fine".

## What to probe in this project

- **Scoring:** does the change affect `compute_threat_score()` or only add evidence for the AI agent and the e-mail?
- **Quotas and cost:** free-tier limits of every external API (requests/day, per minute), what happens when exhausted, and which `ai_settings` keys control it.
- **Secrets:** where each key lives (`vault.yml` → HashiCorp Vault → n8n), nothing in workflow JSON or `env.j2`.
- **Untrusted data:** page content, WHOIS/RDAP, feed text reaching the AI prompt — sanitised, defanged, treated as data.
- **Idempotency and upgrade path:** can every SQL and playbook be re-run on an existing install with no data loss? What goes into "Upgrading from" in `docs/releases.md`?
- **Architectures:** works on `arm64` (prod RPi 5) and `amd64` (dev).
- **Rollout:** what is tested on `vm-prox-dev` first, and what the user must do by hand in n8n or the AI Config UI.
- **Failure modes:** API down, timeout, empty result, rate-limit response, partial data.

## Finish

End with a summary: each decision and the chosen answer, risks accepted, and the next step (usually the matching skill: `add-cti-provider`, `db-schema-change`, `add-stack-service`, `release-docs`). Ask whether to proceed.
