---
name: release-docs
description: Prepare a Cyber Sentinel release — release notes with an upgrade path, version badges, docs pages, SQL header versions, PR in the project's naming style, and after merge the git tag and GitHub Release. Use when the user says a version is ready, asks for release notes, or wants to update docs after a feature.
---

# Release and docs

Reference: PR #29 (`2a53bb6`, docs for v2.1.0) and the `v2.1.0` section of `docs/releases.md`.

## 1. Collect what changed

```bash
git log --oneline <last tag>..HEAD
git diff --stat <last tag>..HEAD
```

Pick the version (semver): breaking upgrade or data migration → major; new feature → minor; fixes only → patch. Confirm with the user.

## 2. `docs/releases.md`

- Add a row at the top of the table: version link, type (Stable / Release / Release candidate), date (`26 October 2026` style), one-line focus.
- New `## vX.Y.Z` section above the previous one: one intro sentence (does it upgrade in place? is data lost?), then `###` per area (workflow, database, AI Config UI, …) with short bullets naming the real setting keys, tables and workflows.
- **`### Upgrading from vA.B.C` is mandatory:** exact playbook commands with `--limit rpi5-prod`, new `vault.yml` keys, manual steps in n8n (import/publish/delete workflows) and the AI Config UI (activate prompt version X).

## 3. Version everywhere

- `README.md` and `docs/index.md`: version badge (`message=vX.Y.Z`, release URL).
- SQL headers: every `config/postgres/*.sql` changed since the last tag has its `Version:` bumped and the new sections listed.
- `mkdocs.yml` nav if pages were added.

## 4. Docs pages

Update the pages for what changed: `docs/n8n.md`, `docs/database.md`, `docs/architecture.md` (+ `docs/assets/cyber_sentinel_flow.svg`), `docs/deployment.md`, `docs/docker-compose.md`, `docs/future-roadmap.md` (move done items out), `docs/security.md`. Check the site builds if mkdocs is available: `mkdocs build --strict`.

## 5. PR

- Branch, commit, PR title in the project style: `DDMMYYYY <topic>` (e.g. `26102026 doc update`) using today's date.
- PR body: summary + the upgrade section.
- Ask before pushing or opening the PR.

## 6. After merge — tag and GitHub Release

Only after the user confirms the PR is merged and says go:

```bash
git fetch origin && git tag -a vX.Y.Z origin/main -m "vX.Y.Z"
git push origin vX.Y.Z
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <section extracted from docs/releases.md>
```

Mark release candidates with `--prerelease`. Show the notes to the user before creating the release.
