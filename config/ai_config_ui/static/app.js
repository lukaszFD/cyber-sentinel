// Cyber Sentinel — AI config editor. Loaded as an external file (CSP: script-src 'self').
(function () {
  "use strict";

  // Confirmation dialogs: <form data-confirm="..."> or <button data-confirm="...">.
  document.addEventListener("submit", function (e) {
    var msg = (e.submitter && e.submitter.dataset.confirm) || e.target.dataset.confirm;
    if (msg && !window.confirm(msg)) {
      e.preventDefault();
    }
  });

  // Threat scale: confirm only when a malicious flag actually changed,
  // and keep the yes/no tag next to each checkbox in sync.
  document.querySelectorAll("form[data-confirm-malicious]").forEach(function (form) {
    var boxes = form.querySelectorAll("input[type=checkbox][data-initial]");
    boxes.forEach(function (cb) {
      cb.addEventListener("change", function () {
        var tag = cb.parentElement.querySelector(".tag");
        if (tag) { tag.textContent = cb.checked ? "yes" : "no"; tag.classList.toggle("bad", cb.checked); }
      });
    });
    form.addEventListener("submit", function (e) {
      var changed = Array.prototype.some.call(boxes, function (cb) {
        return cb.checked !== (cb.dataset.initial === "on");
      });
      if (changed && !window.confirm(form.dataset.confirmMalicious)) { e.preventDefault(); }
    });
  });

  // Line / character counter for prompt textareas.
  document.querySelectorAll("textarea[data-counter]").forEach(function (ta) {
    var out = ta.parentElement.parentElement.querySelector(".counter");
    if (!out) return;
    var update = function () {
      var v = ta.value;
      out.textContent = v.split("\n").length + " lines · " + v.length + " characters";
    };
    ta.addEventListener("input", update);
    update();
  });

  // Warn before leaving a page with unsaved edits (prompt editor, settings).
  var dirty = false;
  document.querySelectorAll("form[method=post] textarea:not([readonly]), form[method=post] input.num, form[method=post] select")
    .forEach(function (el) { el.addEventListener("input", function () { dirty = true; }); });
  document.addEventListener("submit", function () { dirty = false; });
  window.addEventListener("beforeunload", function (e) {
    if (dirty) { e.preventDefault(); e.returnValue = ""; }
  });

  // Tab inserts spaces in the prompt editor instead of leaving the field.
  document.querySelectorAll("textarea.prompt:not([readonly])").forEach(function (ta) {
    ta.addEventListener("keydown", function (e) {
      if (e.key === "Tab" && !e.shiftKey && !e.ctrlKey && !e.altKey && !e.metaKey) {
        e.preventDefault();
        var s = ta.selectionStart, end = ta.selectionEnd;
        ta.setRangeText("    ", s, end, "end");
        ta.dispatchEvent(new Event("input"));
      }
    });
  });

  // Simulator: an auto-resolved IP belongs to the FQDN it was resolved for.
  // Editing the FQDN clears it (next live lookup re-resolves); typing an IP
  // by hand marks it as manual. The server applies the same rule.
  var simFqdn = document.querySelector('input[name="fqdn"]');
  var simIp = document.querySelector('input[name="observable_ip"]');
  var simAuto = document.querySelector('input[name="ip_auto"]');
  if (simFqdn && simIp && simAuto) {
    simFqdn.addEventListener("input", function () {
      var f = simFqdn.value.trim().toLowerCase().replace(/\.$/, "");
      if (simAuto.value && simAuto.value !== f) { simIp.value = ""; }
    });
    simIp.addEventListener("input", function () { simAuto.value = ""; });
  }
})();
