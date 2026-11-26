---
name: release-docs
description: Prepare a Cyber Sentinel release — release notes with an upgrade path, version badges, docs pages, SQL header versions, the milestone, and after merge the git tag on the merge commit and the GitHub Release. Use when the user says a version is ready, asks for release notes, or wants to update docs after a feature.
---

# Release and docs

Reference: v2.5.0 (PR #39, tag on squash commit `f35c3a7`, notes `.tmp/release-v2.5.0.md`) and the `v2.5.0` section of `docs/releases.md`.

Work items live in GitHub Issues (see CLAUDE.md → *Issues and pull requests*). A release = a milestone `vX.Y.Z`: its issues are closed by PRs, each PR adds its part to `docs/releases.md`, and the release finishes that section.

## 1. Collect what changed

```bash
gh issue list --milestone vX.Y.Z --state all
git log --oneline <last tag>..origin/main
git diff --stat <last tag>..origin/main
```

Check the repository's Security tab (code scanning, Dependabot, secret scanning): open alerts should have issues (`type:security`), and anything high/critical is fixed or consciously deferred before the release — say which in the notes.

Pick the version (semver): breaking upgrade or data migration → major; new feature → minor; fixes only → patch. Confirm with the user. Open issues left in the milestone: close, or move them to the next milestone — ask.

## 2. `docs/releases.md`

- Row at the top of the table: version link, type (Stable / Release / Release candidate), date (`23 November 2026` style), one-line focus.
- `## vX.Y.Z` section above the previous one: one intro sentence (does it upgrade in place? is data lost?), then `###` per area with short bullets naming the real setting keys, tables and workflows.
- **`### Upgrading from vA.B.C` is mandatory:** exact playbook commands with `--limit rpi5-prod` in the order that works (04.3 before 04.2 when a container needs new DB objects; 04.5 always after 04.3), new keys for `ansible/host_vars/<host>/vault.yml` (every host), host steps (reboot → Vault comes back sealed: unseal before the playbooks), manual steps in n8n (04.6 imports workflows **inactive**: list what to publish) and the AI Config UI.
- `### Tested`: one line for dev, one for prod — what was actually checked. Never leave a placeholder in a published release; say what is still open instead.

## 3. Version everywhere

- `README.md` and `docs/index.md`: version badge (`message=vX.Y.Z`, release URL).
- SQL headers: every `config/postgres/*.sql` changed since the last tag has its `Version:` bumped with a one-line reason.
- `mkdocs.yml` nav if pages were added.

## 4. Docs pages

Update the pages for what changed: `docs/n8n.md`, `docs/database.md`, `docs/architecture.md` (+ `docs/assets/cyber_sentinel_flow.svg`), `docs/deployment.md`, `docs/docker-compose.md`, `docs/security.md`, `docs/sandbox/`. `docs/future-roadmap.md` holds direction only: remove delivered items and keep the links to the epics. Check the site builds if mkdocs is available: `mkdocs build --strict`.

## 5. Pull request

- Branch `YYYYMMDD_<english_name>` (e.g. `20261126_release_v2_6_0`); PR title `<type>(<area>): <summary>` (it becomes the squash commit on `main`); body with `Closes #N` and the PR template checklist.
- Rules on `main`: **linear history** — merge with *Squash* or *Rebase* only (`gh pr merge N --squash`), a merge commit is refused; **all review threads resolved**, including code scanning comments from `github-advanced-security[bot]` (Trivy, CodeQL). Fix the finding or resolve the thread with a reason; accepted findings go into `.trivyignore` with a written justification.
- Claude commits and pushes only when the user allows that step; it may open the PR (`gh pr create --head <branch>`). The user reviews and merges — Claude never runs `gh pr merge`.

## 6. After merge — tag and GitHub Release

Only after the PR is **merged** (check, do not assume):

```bash
gh pr view <N> --json state,mergeCommit --jq '{state, sha: .mergeCommit.oid}'   # state MERGED
git fetch origin --tags
git tag -a vX.Y.Z <merge-commit-sha> -m "vX.Y.Z" && git push origin vX.Y.Z
git ls-tree -r --name-only vX.Y.Z | grep <a file new in this release>      # proves the tag has the code
```

- Tag the **merge commit SHA**, not `origin/main` and not the feature branch.
- Never run `gh release create` before the tag exists on the right commit: without a tag it creates one on the current default branch HEAD, i.e. on the old code.
- Notes: the `## vX.Y.Z` section of `docs/releases.md` saved as `.tmp/release-vX.Y.Z.md` (`# vX.Y.Z — <title>` and `###` → `##`). Show it to the user, then:

```bash
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file .tmp/release-vX.Y.Z.md
gh api -X PATCH repos/lukaszFD/cyber-sentinel/milestones/<id> -f state=closed
```

Mark release candidates with `--prerelease`.

**A tag on the wrong commit:** move it right away — `git tag -f -a vX.Y.Z <merge sha> -m "vX.Y.Z" && git push -f origin vX.Y.Z`. The GitHub Release follows the tag name, so its source archives update; the notes stay.
