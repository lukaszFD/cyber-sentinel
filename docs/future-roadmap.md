---
hide:
  - toc
---

# Roadmap

This page is built live from [GitHub Issues](https://github.com/lukaszFD/cyber-sentinel/issues) each time it opens, so it is never out of date. Delivered work is listed in [Releases](releases.md).

<div class="cs-roadmap"
     data-repo="lukaszFD/cyber-sentinel"
     data-epic-label="type:epic"
     data-fix-labels="type:bug,type:security"
     data-filter-prefix="area:">
  <p class="cs-rm-status">Loading issues from GitHub…</p>
</div>

<noscript>
This page needs JavaScript. The same information is on GitHub:
<a href="https://github.com/lukaszFD/cyber-sentinel/milestones">milestones</a>,
<a href="https://github.com/lukaszFD/cyber-sentinel/issues?q=is%3Aopen+label%3Atype%3Aepic">epics</a>,
<a href="https://github.com/lukaszFD/cyber-sentinel/issues?q=is%3Aopen+label%3Atype%3Abug%2Ctype%3Asecurity">fixes</a>.
</noscript>

## How this page works

Nothing below the intro is written by hand. The page reads the public GitHub API and groups the issues:

| Section | What it shows |
|---|---|
| **Next releases** | Every open milestone (a version such as `v2.6.0`), with its progress and issues. |
| **Fixes and security** | Open issues labelled `type:bug` or `type:security` — bugs and the problems found in the repository. Security alerts become such issues automatically once [#62](https://github.com/lukaszFD/cyber-sentinel/issues/62) is done. |
| **Epics** | Every issue labelled `type:epic`: its first paragraph, its sub-issues with their status, and its planned items that have no issue yet. |
| **Not in an epic** | Open issues with no parent epic. |

The area buttons at the top filter every section by `area:*` label.

### Adding to the roadmap

- **A new direction** — open an issue labelled `type:epic` (plus `area:*` and `prio:*`). It appears here on the next page load.
- **An idea for later** — add a `- [ ] …` line to the epic's description. It shows as *planned, no issue yet*.
- **Work that is planned** — create an issue, add it as a sub-issue of the epic, set a milestone, and remove the idea line from the epic.
- **Long designs and notes** — keep them in the epic after its checklist; the page shows only the first paragraph and the checklist, and links to the issue for the rest.

The page sends three to five unauthenticated requests to `api.github.com` and keeps the answer in the browser for ten minutes. GitHub allows 60 such requests per hour per IP address; when the limit is reached, the page shows links to the same views on GitHub.
