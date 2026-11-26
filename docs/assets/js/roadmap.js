/*
 * Live roadmap for docs/future-roadmap.md.
 * Reads issues and milestones from the public GitHub API and renders them.
 * Configuration lives in data-* attributes on <div class="cs-roadmap">, so
 * nothing about epics, milestones or labels is hard-coded here.
 */
(function () {
  "use strict";

  var API = "https://api.github.com/repos/";
  var CACHE_MINUTES = 10;
  var PRIO_ORDER = { "prio:high": 0, "prio:med": 1, "prio:low": 2 };

  // ---------- helpers ----------

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  // Minimal, safe inline markdown: escape first, then add a few tags back.
  function inline(text, repo) {
    var codes = [];
    var s = esc(text).replace(/`([^`]+)`/g, function (_, c) {
      codes.push(c);
      return "\u0000" + (codes.length - 1) + "\u0000";
    });
    s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2">$1</a>')
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, "$1<em>$2</em>")
      .replace(/(^|[\s(])#(\d+)\b/g,
        '$1<a href="https://github.com/' + repo + '/issues/$2">#$2</a>');
    return s.replace(/\u0000(\d+)\u0000/g, function (_, i) {
      return "<code>" + codes[+i] + "</code>";
    });
  }

  function labelNames(issue) {
    return (issue.labels || []).map(function (l) { return typeof l === "string" ? l : l.name; });
  }

  function prioRank(issue) {
    var r = 9;
    labelNames(issue).forEach(function (n) { if (n in PRIO_ORDER) r = Math.min(r, PRIO_ORDER[n]); });
    return r;
  }

  function byPrioThenNumber(a, b) {
    return prioRank(a) - prioRank(b) || a.number - b.number;
  }

  function versionKey(title) {
    var m = /(\d+)\.(\d+)\.(\d+)/.exec(title || "");
    return m ? [+m[1], +m[2], +m[3]] : [9999, 0, 0];
  }

  function parentNumber(issue) {
    var m = /\/issues\/(\d+)$/.exec(issue.parent_issue_url || "");
    return m ? +m[1] : null;
  }

  // Epic description → first paragraph + unchecked "- [ ]" lines before any <details>.
  function parseEpicBody(body) {
    var text = String(body || "").replace(/\r/g, "").split(/<details/i)[0];
    var paras = text.split(/\n\s*\n/).map(function (p) { return p.trim(); }).filter(Boolean);
    var summary = "";
    for (var i = 0; i < paras.length; i++) {
      if (!/^(- \[|#|\||>|```)/.test(paras[i])) { summary = paras[i].replace(/\n/g, " "); break; }
    }
    var planned = [];
    text.split("\n").forEach(function (line) {
      var m = /^\s*[-*] \[ \] (.+)$/.exec(line);
      if (m) planned.push(m[1].trim());
    });
    return { summary: summary, planned: planned };
  }

  // ---------- data ----------

  function fetchJson(url) {
    return fetch(url, { headers: { Accept: "application/vnd.github+json" } }).then(function (r) {
      if (!r.ok) {
        var e = new Error("GitHub API " + r.status);
        e.status = r.status;
        e.reset = r.headers.get("x-ratelimit-reset");
        throw e;
      }
      return r.json();
    });
  }

  function fetchAllIssues(repo) {
    var all = [];
    function page(n) {
      return fetchJson(API + repo + "/issues?state=all&per_page=100&page=" + n).then(function (items) {
        all = all.concat(items.filter(function (i) { return !i.pull_request; }));
        return items.length === 100 && n < 10 ? page(n + 1) : all;
      });
    }
    return page(1);
  }

  function load(repo) {
    var key = "cs-roadmap:" + repo;
    try {
      var cached = JSON.parse(sessionStorage.getItem(key) || "null");
      if (cached && Date.now() - cached.at < CACHE_MINUTES * 60000) return Promise.resolve(cached);
    } catch (e) { /* ignore broken cache */ }
    return Promise.all([
      fetchAllIssues(repo),
      fetchJson(API + repo + "/milestones?state=open&per_page=100")
    ]).then(function (res) {
      var data = { at: Date.now(), issues: res[0], milestones: res[1] };
      try { sessionStorage.setItem(key, JSON.stringify(data)); } catch (e) { /* quota */ }
      return data;
    });
  }

  // ---------- rendering ----------

  function chips(issue, filterPrefix, skip) {
    return labelNames(issue).filter(function (n) {
      return n !== skip && (n.indexOf(filterPrefix) === 0 || n.indexOf("prio:") === 0 || n.indexOf("type:") === 0);
    }).map(function (n) {
      var cls = n.split(":")[0];
      return '<span class="cs-chip cs-chip-' + esc(cls) + " cs-" + esc(n.replace(":", "-")) + '">' +
        esc(n.split(":")[1] || n) + "</span>";
    }).join("");
  }

  function issueRow(issue, ctx, opts) {
    opts = opts || {};
    var done = issue.state === "closed";
    var ms = issue.milestone && !opts.hideMilestone
      ? '<span class="cs-chip cs-chip-ms">' + esc(issue.milestone.title) + "</span>" : "";
    return '<li class="cs-item' + (done ? " cs-done" : "") + '" data-labels="' + esc(labelNames(issue).join(" ")) + '">' +
      '<span class="cs-state" title="' + (done ? "closed" : "open") + '">' + (done ? "✓" : "○") + "</span>" +
      '<a href="' + esc(issue.html_url) + '">#' + issue.number + "</a> " +
      '<span class="cs-title">' + inline(issue.title, ctx.repo) + "</span>" +
      '<span class="cs-chips">' + ms + chips(issue, ctx.filterPrefix, ctx.epicLabel) + "</span></li>";
  }

  function progress(done, total) {
    var pct = total ? Math.round((done / total) * 100) : 0;
    return '<div class="cs-progress" title="' + done + " of " + total + ' done">' +
      '<div class="cs-bar"><span style="width:' + pct + '%"></span></div>' +
      '<span class="cs-count">' + done + " / " + total + "</span></div>";
  }

  function section(title, id, inner, emptyText) {
    return '<section class="cs-section" id="' + id + '"><h2>' + esc(title) + "</h2>" +
      (inner || '<p class="cs-empty">' + esc(emptyText) + "</p>") + "</section>";
  }

  function render(root, data, ctx) {
    var issues = data.issues;
    var byNumber = {};
    issues.forEach(function (i) { byNumber[i.number] = i; });
    var isEpic = function (i) { return labelNames(i).indexOf(ctx.epicLabel) >= 0; };
    var open = function (i) { return i.state === "open"; };
    var hasAny = function (i, list) { return labelNames(i).some(function (n) { return list.indexOf(n) >= 0; }); };

    // Area filter buttons, built from labels in use.
    var areas = {};
    issues.filter(open).forEach(function (i) {
      labelNames(i).forEach(function (n) { if (n.indexOf(ctx.filterPrefix) === 0) areas[n] = (areas[n] || 0) + 1; });
    });
    var filter = '<div class="cs-filter" role="group" aria-label="Filter by area">' +
      '<button type="button" class="cs-filter-btn cs-active" data-area="">all</button>' +
      Object.keys(areas).sort().map(function (a) {
        return '<button type="button" class="cs-filter-btn" data-area="' + esc(a) + '">' +
          esc(a.slice(ctx.filterPrefix.length)) + " <small>" + areas[a] + "</small></button>";
      }).join("") + "</div>";

    // Next releases: open milestones, lowest version first.
    var milestones = data.milestones.slice().sort(function (a, b) {
      var x = versionKey(a.title), y = versionKey(b.title);
      return x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
    });
    var releases = milestones.map(function (m) {
      var items = issues.filter(function (i) { return i.milestone && i.milestone.number === m.number; })
        .sort(function (a, b) { return (a.state === "closed") - (b.state === "closed") || byPrioThenNumber(a, b); });
      return '<div class="cs-card"><h3><a href="' + esc(m.html_url) + '">' + esc(m.title) + "</a></h3>" +
        (m.description ? '<p class="cs-summary">' + inline(m.description, ctx.repo) + "</p>" : "") +
        progress(m.closed_issues, m.open_issues + m.closed_issues) +
        '<ul class="cs-list">' + items.map(function (i) { return issueRow(i, ctx, { hideMilestone: true }); }).join("") + "</ul></div>";
    }).join("");

    // Fixes and security: open bugs and security issues.
    var fixes = issues.filter(function (i) { return open(i) && !isEpic(i) && hasAny(i, ctx.fixLabels); })
      .sort(byPrioThenNumber);
    var fixesHtml = fixes.length ? '<ul class="cs-list">' + fixes.map(function (i) { return issueRow(i, ctx); }).join("") + "</ul>" : "";

    // Epics: open first, then by priority.
    var epics = issues.filter(isEpic).sort(function (a, b) {
      return (a.state === "closed") - (b.state === "closed") || byPrioThenNumber(a, b);
    });
    var epicsHtml = epics.map(function (e) {
      var parsed = parseEpicBody(e.body);
      var children = issues.filter(function (i) { return parentNumber(i) === e.number; })
        .sort(function (a, b) { return (a.state === "closed") - (b.state === "closed") || byPrioThenNumber(a, b); });
      var sum = e.sub_issues_summary || { total: children.length, completed: children.filter(function (c) { return c.state === "closed"; }).length };
      var childLabels = children.map(function (c) { return labelNames(c).join(" "); }).join(" ");
      return '<div class="cs-card cs-epic' + (e.state === "closed" ? " cs-done" : "") + '" data-labels="' +
        esc(labelNames(e).join(" ") + " " + childLabels) + '">' +
        '<h3><a href="' + esc(e.html_url) + '">' + esc(e.title.replace(/^Epic:\s*/i, "")) + '</a> <span class="cs-num">#' + e.number + "</span>" +
        '<span class="cs-chips">' + chips(e, ctx.filterPrefix, ctx.epicLabel) + "</span></h3>" +
        (parsed.summary ? '<p class="cs-summary">' + inline(parsed.summary, ctx.repo) + "</p>" : "") +
        (sum.total ? progress(sum.completed, sum.total) : "") +
        (children.length ? '<ul class="cs-list">' + children.map(function (c) { return issueRow(c, ctx); }).join("") + "</ul>" : "") +
        (parsed.planned.length
          ? '<details class="cs-planned"><summary>Planned, no issue yet (' + parsed.planned.length + ")</summary><ul>" +
            parsed.planned.map(function (p) { return "<li>" + inline(p, ctx.repo) + "</li>"; }).join("") + "</ul></details>"
          : "") +
        "</div>";
    }).join("");

    // Open issues with no parent epic (and not epics themselves).
    var loose = issues.filter(function (i) {
      var p = parentNumber(i);
      return open(i) && !isEpic(i) && (!p || !byNumber[p]);
    }).sort(byPrioThenNumber);
    var looseHtml = loose.length ? '<ul class="cs-list">' + loose.map(function (i) { return issueRow(i, ctx); }).join("") + "</ul>" : "";

    var updated = new Date(data.at).toLocaleString();
    root.innerHTML = filter +
      section("Next releases", "next-releases", releases, "No open milestone.") +
      section("Fixes and security", "fixes-and-security", fixesHtml, "No open bugs or security issues.") +
      section("Epics", "epics", epicsHtml, "No epics yet.") +
      section("Not in an epic", "not-in-an-epic", looseHtml, "Every open issue belongs to an epic.") +
      '<p class="cs-rm-status">Source: <a href="https://github.com/' + esc(ctx.repo) + '/issues">GitHub Issues</a> · loaded ' + esc(updated) + "</p>";

    root.querySelector(".cs-filter").addEventListener("click", function (ev) {
      var btn = ev.target.closest(".cs-filter-btn");
      if (!btn) return;
      root.querySelectorAll(".cs-filter-btn").forEach(function (b) { b.classList.toggle("cs-active", b === btn); });
      var area = btn.getAttribute("data-area");
      root.querySelectorAll(".cs-item, .cs-epic").forEach(function (el) {
        var labels = " " + (el.getAttribute("data-labels") || "") + " ";
        el.hidden = !!area && labels.indexOf(" " + area + " ") < 0;
      });
    });
  }

  function renderError(root, err, ctx) {
    var base = "https://github.com/" + ctx.repo;
    var msg = err && err.status === 403
      ? "GitHub's limit of 60 requests per hour for this network is used up" +
        (err.reset ? " until " + new Date(err.reset * 1000).toLocaleTimeString() : "") + "."
      : "Could not load issues from GitHub (" + esc(err && err.message) + ").";
    root.innerHTML = '<div class="admonition warning"><p class="admonition-title">Roadmap not loaded</p><p>' + msg +
      ' The same views on GitHub: <a href="' + base + '/milestones">milestones</a>, ' +
      '<a href="' + base + '/issues?q=is%3Aopen+label%3A' + encodeURIComponent(ctx.epicLabel) + '">epics</a>, ' +
      '<a href="' + base + '/issues?q=is%3Aopen+label%3A' + encodeURIComponent(ctx.fixLabels.join(",")) + '">fixes</a>.</p></div>';
  }

  function init() {
    document.querySelectorAll(".cs-roadmap").forEach(function (root) {
      if (root.getAttribute("data-ready")) return;
      root.setAttribute("data-ready", "1");
      var ctx = {
        repo: root.getAttribute("data-repo"),
        epicLabel: root.getAttribute("data-epic-label") || "type:epic",
        fixLabels: (root.getAttribute("data-fix-labels") || "type:bug,type:security").split(",").map(function (s) { return s.trim(); }),
        filterPrefix: root.getAttribute("data-filter-prefix") || "area:"
      };
      load(ctx.repo)
        .then(function (data) { render(root, data, ctx); })
        .catch(function (err) { renderError(root, err, ctx); });
    });
  }

  // Works with and without Material's instant navigation.
  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(init);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
