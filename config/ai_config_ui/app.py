"""
Cyber Sentinel — AI config editor.

Small server-rendered web UI for the data that drives the n8n AI pipeline
(schema cyber_sentinel_ai): pipeline/scoring settings, versioned AI Agent
prompt, trusted infrastructure, manual domain allow-list + exclusions and the
threat-scale wording. Connects to Postgres as a dedicated least-privilege role
(see config/postgres/db_ai_config_editor.sql) — never as postgres or as the
n8n app role.

Every write transaction sets `cyber_sentinel_ai.actor` to the logged-in UI
user, so the audit trigger records who changed what.

Configuration (environment):
    AI_UI_SECRET_KEY        Flask session key, >= 32 chars (required)
    AI_UI_USERS             JSON object {"user": "password-or-werkzeug-hash"}
    AI_UI_DB_HOST / AI_UI_DB_PORT / AI_UI_DB_NAME
    AI_UI_DB_USER / AI_UI_DB_PASSWORD
    AI_UI_COOKIE_SECURE     "true" (default) / "false" for local http testing
    AI_UI_SESSION_HOURS     session lifetime, default 8
    AI_UI_VT_API_KEY        VirusTotal key for live simulator lookups (optional)
    AI_UI_ABUSE_API_KEY     abuse.ch key for live ThreatFox / URLhaus (optional)
    AI_UI_RESOLVER          DNS server for live lookups, default 10.10.10.2 (Unbound)
    AI_UI_VT_MIN_INTERVAL / AI_UI_VT_DAILY_LIMIT / AI_UI_LIVE_CACHE_SECONDS
                            live-lookup quota guard, see live_lookup.py
"""

import difflib
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time
from contextlib import contextmanager
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from urllib.parse import urlparse

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

import live_lookup

log = logging.getLogger("ai-config-ui")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


# ============================================================
# Configuration
# ============================================================

def _env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"Environment variable {name} is required")
    return value


def _load_users():
    raw = _env("AI_UI_USERS", required=True)
    try:
        users = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AI_UI_USERS must be a JSON object {\"user\": \"password\"}") from exc
    if not isinstance(users, dict) or not users:
        raise RuntimeError("AI_UI_USERS must contain at least one user")
    for name, secret in users.items():
        if not isinstance(secret, str) or len(secret) < 12:
            raise RuntimeError(f"AI_UI_USERS: password for '{name}' must be a string of >= 12 characters")
    return users


SECRET_KEY = _env("AI_UI_SECRET_KEY", required=True)
if len(SECRET_KEY) < 32:
    raise RuntimeError("AI_UI_SECRET_KEY must be at least 32 characters")

USERS = _load_users()

DB_PARAMS = {
    "host": _env("AI_UI_DB_HOST", "postgres_db"),
    "port": int(_env("AI_UI_DB_PORT", "5432")),
    "dbname": _env("AI_UI_DB_NAME", "cyber_intelligence"),
    "user": _env("AI_UI_DB_USER", required=True),
    "password": _env("AI_UI_DB_PASSWORD", required=True),
    "connect_timeout": 5,
    "application_name": "ai-config-ui",
    # Queries use unqualified names; pin the path here instead of relying on
    # the role-level setting alone.
    "options": "-c search_path=cyber_sentinel_ai,cyber_sentinel",
}

app = Flask(__name__)
# One proxy hop: nginx-proxy. Only trusted for X-Forwarded-For/-Proto.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_NAME="ai_cfg_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=_env("AI_UI_COOKIE_SECURE", "true").lower() != "false",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=int(_env("AI_UI_SESSION_HOURS", "8"))),
    MAX_CONTENT_LENGTH=512 * 1024,
)


# ============================================================
# Domain rules (kept in one place, used by validation + templates)
# ============================================================

KNOWN_PLACEHOLDERS = {"THREAT_SCALE", "MAX_DEVIATION"}
REQUIRED_PLACEHOLDERS = ["[[THREAT_SCALE]]", "[[MAX_DEVIATION]]"]
PLACEHOLDER_RE = re.compile(r"\[\[([A-Za-z0-9_]+)\]\]")
VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,20}$")
# Same pattern sp_sync_domain_allowlist() uses for staged Tranco rows.
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

# Help text and validation for every ai_settings key, shown on the
# Settings page. "stage" ties each key to a step of PIPELINE_STEPS.
# Keys not listed here (added later in db_ai_pipeline.sql) only have to
# be numeric. Every key currently in db_ai_pipeline.sql is cast to INT by
# its consumers, so all known keys are integer-only.
SETTING_HELP = {
    "allowlist_enabled": {
        "min": 0, "max": 1, "integer": True, "stage": 1,
        "used_by": "v_pending_observables (work queue read by n8n)",
        "what": "Switches the domain allow-list on or off. When on, every domain on the allow-list "
                "(Tranco top sites + your manual entries, minus exclusions) and all of its subdomains "
                "are dropped from the work queue before n8n ever sees them.",
        "raise": "1 — popular sites (google.com, wp.pl, ...) are never sent to VirusTotal. Saves the "
                 "free-tier quota (4 requests/min, 500/day) for unknown domains.",
        "lower": "0 — every resolved domain is queued, including the most popular sites. Quota runs out "
                 "much faster and big sites with a few noisy VirusTotal detections produce false alerts.",
    },
    "cache_ttl_days": {
        "min": 1, "max": 365, "integer": True, "stage": 1,
        "used_by": "v_pending_observables (work queue read by n8n)",
        "what": "How long a verdict stays valid. The same domain + IP pair is not analysed again within "
                "N days. Also the look-back window: only DNS queries from the last N days are queued.",
        "raise": "Fewer repeat lookups, less VirusTotal quota used — but a domain that turns malicious "
                 "after its first (clean) verdict is noticed later.",
        "lower": "Fresher verdicts, more VirusTotal requests. Very low values can exhaust the daily quota "
                 "on a busy network.",
    },
    "vt_gate_min_malicious": {
        "min": 0, "max": 100, "integer": True, "stage": 2,
        "used_by": "n8n workflow — branch after the VirusTotal lookup",
        "what": "The enrichment gate. Only observables with at least N VirusTotal 'malicious' detections "
                "are enriched with ThreatFox + URLhaus and sent to the AI Agent. Below the gate the verdict "
                "comes from the rule engine on VirusTotal data alone (ThreatFox/URLhaus 'not checked', "
                "no AI, no e-mail).",
        "raise": "Fewer Gemini calls and abuse.ch requests; only strong VirusTotal signals get AI analysis. "
                 "Threats that few engines detect yet are scored on VirusTotal alone (max score 4).",
        "lower": "More observables get ThreatFox/URLhaus context and an AI verdict + e-mail. More Gemini "
                 "cost and more noise from domains with 1–2 detections.",
    },
    "vt_low_max": {
        "min": 0, "max": 100, "integer": True, "stage": 3,
        "used_by": "compute_threat_score() — step 1 (VirusTotal level)",
        "what": "VirusTotal malicious count 1..N is level LOW. LOW alone gives base score 2 (Monitor).",
        "raise": "More observables stay LOW (score 2) instead of MEDIUM (score 3, manual review).",
        "lower": "Fewer detections are needed to reach MEDIUM — more 'Review' verdicts.",
    },
    "vt_medium_max": {
        "min": 0, "max": 100, "integer": True, "stage": 3,
        "used_by": "compute_threat_score() — step 1 (VirusTotal level)",
        "what": "VirusTotal malicious count (vt_low_max+1)..N is MEDIUM (base 3); above N is HIGH. "
                "HIGH on its own gives base 4 — 'Malicious', counted as malicious in Grafana.",
        "raise": "More detections are needed before an observable is called malicious (score 4).",
        "lower": "Observables become 'Malicious' (4) with fewer engines agreeing.",
    },
    "vt_big_player_noise_max": {
        "min": 0, "max": 100, "integer": True, "stage": 3,
        "used_by": "compute_threat_score() — step 1, only for trusted infrastructure",
        "what": "For hosts matching Trusted infra (Google, Microsoft, Cloudflare, ...), up to N "
                "VirusTotal detections are treated as noise (level CLEAN). Large shared platforms "
                "always collect a few false positives.",
        "raise": "Trusted providers tolerate more detections before they stop being 'clean'.",
        "lower": "Even 1–2 detections on a trusted provider count. Step 5 still caps them at score 2 "
                 "unless ThreatFox names a malware family.",
    },
    "tf_active_days": {
        "min": 1, "max": 3650, "integer": True, "stage": 3,
        "used_by": "n8n workflow — normalising the ThreatFox response (sets tf_active)",
        "what": "A ThreatFox IOC counts as active when its last_seen (or first_seen) is within N days. "
                "Active ThreatFox = level HIGH and, together with step 3, the only way to reach score 5.",
        "raise": "Older IOCs still count as active — more score-5 'Critical' verdicts.",
        "lower": "Only very recent IOCs count as active; old listings drop to MEDIUM.",
    },
    "tf_active_vt_min": {
        "min": 0, "max": 100, "integer": True, "stage": 3,
        "used_by": "compute_threat_score() — step 3",
        "what": "Score 5 (Critical, Block + Alert) requires an active ThreatFox IOC AND either at least "
                "N VirusTotal detections or a named malware family.",
        "raise": "Score 5 needs stronger VirusTotal confirmation (a named malware family still qualifies).",
        "lower": "An active ThreatFox IOC reaches 5 with weaker VirusTotal support.",
    },
    "ai_max_deviation": {
        "min": 0, "max": 4, "integer": True, "stage": 4,
        "used_by": "n8n workflow — [[MAX_DEVIATION]] in the prompt + clamp on the AI's proposed score",
        "what": "How far the AI Agent may move the rule-engine score, in points. The rule score is "
                "authoritative; the AI only adjusts it when the evidence clearly justifies it "
                "(sinkhole, adware/PUP only, weak engines, ...).",
        "raise": "The AI can override the rules more (e.g. 2 → 4). More judgement, less predictability.",
        "lower": "0 = the AI only explains; the final score always equals the rule score.",
    },
    "email_min_score": {
        "min": 1, "max": 5, "integer": True, "stage": 5,
        "used_by": "n8n workflow — e-mail branch",
        "what": "AI-analysed verdicts (above the VirusTotal gate) with a final score of at least N are "
                "e-mailed. Verdicts below the gate are never e-mailed.",
        "raise": "4 = only Malicious/Critical; 5 = only Critical. Fewer e-mails.",
        "lower": "3 = also 'Suspicious - manual review'. More e-mails.",
    },
}

# The n8n AI workflow, in the order an observable goes through it.
PIPELINE_STEPS = {
    1: ("Work queue", "v_pending_observables picks distinct domain + IP pairs from DNS traffic, "
                      "skipping private IPs, recent verdicts and allow-listed domains."),
    2: ("VirusTotal + gate", "n8n queries VirusTotal (the primary source). Only observables at or above "
                             "the gate are enriched with ThreatFox + URLhaus."),
    3: ("Rule engine", "compute_threat_score() turns the evidence into a deterministic 1–5 score."),
    4: ("AI Agent", "Gemini explains the score using the active prompt and may adjust it within the "
                    "allowed deviation."),
    5: ("Notify", "Verdicts are stored (Grafana) and high scores are e-mailed."),
}

TF_UH_STATUSES = ["ok", "no_data", "not_checked", "error"]
AUDITED_TABLES = [
    "cyber_sentinel_ai.ai_settings",
    "cyber_sentinel_ai.prompt_templates",
    "cyber_sentinel_ai.trusted_infrastructure",
    "cyber_sentinel_ai.domain_allowlist",
    "cyber_sentinel_ai.domain_allowlist_exclusions",
    "cyber_sentinel.dic_threat_levels",
]


# ============================================================
# Database helpers
# ============================================================

@contextmanager
def db(readonly=False):
    """One connection + one transaction per call; commits on success.

    The actor setting is transaction-local (is_local = true), so it can
    never leak into another request.
    """
    with psycopg.connect(**DB_PARAMS, row_factory=dict_row) as conn:
        with conn.transaction():
            if readonly:
                conn.execute("SET TRANSACTION READ ONLY")
            conn.execute("SELECT set_config('cyber_sentinel_ai.actor', %s, true)",
                         (session.get("user") or "anonymous",))
            yield conn


def db_error(exc):
    """Human-readable message from a psycopg error (never the full traceback)."""
    diag = getattr(exc, "diag", None)
    if diag is not None and diag.message_primary:
        msg = diag.message_primary
        if diag.message_detail:
            msg += f" ({diag.message_detail})"
        return msg
    return str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__


def fmt_num(value):
    if value is None:
        return ""
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return str(int(value))
        return format(value.normalize(), "f")
    return str(value)


def text_fingerprint(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode())
        h.update(b"\x00")
    return h.hexdigest()


# ============================================================
# Auth, CSRF, security headers
# ============================================================

_login_failures = {}
_login_lock = threading.Lock()
LOGIN_WINDOW = 15 * 60
LOGIN_MAX_FAILURES = 5


def _throttle_keys(username):
    return (f"ip:{request.remote_addr}", f"user:{username.lower()}")


def _is_throttled(username):
    now = time.time()
    with _login_lock:
        for key in _throttle_keys(username):
            recent = [t for t in _login_failures.get(key, []) if now - t < LOGIN_WINDOW]
            _login_failures[key] = recent
            if len(recent) >= LOGIN_MAX_FAILURES:
                return True
    return False


def _record_failure(username):
    with _login_lock:
        for key in _throttle_keys(username):
            _login_failures.setdefault(key, []).append(time.time())


def _check_password(username, password):
    # Constant-ish time for unknown users: always run one comparison.
    stored = USERS.get(username)
    if stored is None:
        hmac.compare_digest(password, "x" * 32)
        return False
    if stored.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(stored, password)
    return hmac.compare_digest(stored.encode(), password.encode())


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user") or session.get("user") not in USERS:
            session.clear()
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapper


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.filters["num"] = fmt_num
app.jinja_env.filters["dt"] = lambda v: v.strftime("%Y-%m-%d %H:%M") if v else "—"


@app.before_request
def _csrf_protect():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        expected = session.get("csrf", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, "Invalid CSRF token — reload the page and try again.")


@app.after_request
def _security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if resp.mimetype == "text/html":
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(400)
@app.errorhandler(404)
def _http_error(err):
    return render_template("error.html", code=err.code, message=err.description), err.code


@app.errorhandler(psycopg.OperationalError)
def _db_down(err):
    log.error("Database unavailable: %s", err)
    return render_template("error.html", code=503,
                           message="No connection to the database (postgres_db)."), 503


# ============================================================
# Routes — auth
# ============================================================

@app.route("/healthz")
def healthz():
    if request.args.get("deep") == "1":
        try:
            with psycopg.connect(**DB_PARAMS) as conn:
                conn.execute("SELECT 1")
        except psycopg.Error:
            return "db unavailable", 503
    return "ok", 200


def _is_safe_next_url(target: str) -> bool:
    if not target:
        return False
    normalized = target.replace("\\", "/")
    parsed = urlparse(normalized)
    if parsed.scheme or parsed.netloc:
        return False
    if not normalized.startswith("/") or normalized.startswith("//"):
        return False
    return True


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if _is_throttled(username):
            log.warning("Login throttled for user=%r ip=%s", username, request.remote_addr)
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
        elif _check_password(username, password):
            session.clear()
            session.permanent = True
            session["user"] = username
            csrf_token()
            log.info("Login ok user=%r ip=%s", username, request.remote_addr)
            nxt = request.args.get("next", "")
            if not _is_safe_next_url(nxt):
                nxt = url_for("dashboard")
            return redirect(nxt)
        else:
            _record_failure(username)
            log.warning("Login failed user=%r ip=%s", username, request.remote_addr)
            flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# Routes — dashboard
# ============================================================

@app.route("/")
@login_required
def dashboard():
    with db(readonly=True) as conn:
        active = conn.execute(
            "SELECT version, notes, created_at, length(system_prompt) AS chars "
            "FROM prompt_templates WHERE is_active").fetchone()
        prompt_count = conn.execute("SELECT count(*) AS n FROM prompt_templates").fetchone()["n"]
        settings = conn.execute(
            "SELECT key, value FROM ai_settings WHERE category = 'pipeline' ORDER BY key").fetchall()
        allow_stats = conn.execute(
            "SELECT source, is_active, count(*) AS n FROM domain_allowlist "
            "GROUP BY 1, 2 ORDER BY 1, 2").fetchall()
        last_sync = conn.execute(
            "SELECT * FROM domain_allowlist_sync_log ORDER BY started_at DESC LIMIT 1").fetchone()
        trusted = conn.execute(
            "SELECT count(*) FILTER (WHERE is_active) AS active, count(*) AS total "
            "FROM trusted_infrastructure").fetchone()
        changes = conn.execute(
            "SELECT changed_at, actor, table_name, operation, row_key "
            "FROM config_change_log ORDER BY changed_at DESC, id DESC LIMIT 10").fetchall()
    return render_template("dashboard.html", active=active, prompt_count=prompt_count,
                           settings=settings, allow_stats=allow_stats, last_sync=last_sync,
                           trusted=trusted, changes=changes)


# ============================================================
# Routes — settings
# ============================================================

def _validate_settings(values):
    """values: {key: Decimal}. Returns list of error strings."""
    errors = []
    for key, val in values.items():
        rule = SETTING_HELP.get(key)
        if rule is None:
            continue
        if rule["integer"] and val != val.to_integral_value():
            errors.append(f"{key}: must be a whole number")
        if not (rule["min"] <= val <= rule["max"]):
            errors.append(f"{key}: allowed range {rule['min']}–{rule['max']}")
    if {"vt_low_max", "vt_medium_max"} <= values.keys() and values["vt_low_max"] >= values["vt_medium_max"]:
        errors.append("vt_low_max must be lower than vt_medium_max (thresholds LOW < MEDIUM < HIGH)")
    if {"vt_big_player_noise_max", "vt_medium_max"} <= values.keys() \
            and values["vt_big_player_noise_max"] > values["vt_medium_max"]:
        errors.append("vt_big_player_noise_max must not exceed vt_medium_max")
    return errors


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings_page():
    if request.method == "POST":
        try:
            with db() as conn:
                rows = conn.execute("SELECT key, value FROM ai_settings FOR UPDATE").fetchall()
                current = {r["key"]: r["value"] for r in rows}
                merged = dict(current)
                changed, errors = {}, []
                for key, cur_val in current.items():
                    raw = request.form.get(f"v__{key}")
                    if raw is None:
                        continue
                    raw = raw.strip().replace(",", ".")
                    try:
                        new_val = Decimal(raw)
                    except InvalidOperation:
                        errors.append(f"{key}: '{raw}' is not a number")
                        continue
                    if not new_val.is_finite():
                        errors.append(f"{key}: invalid value")
                        continue
                    if new_val != cur_val:
                        original = request.form.get(f"o__{key}", "")
                        if original != fmt_num(cur_val):
                            errors.append(f"{key}: changed by someone else in the meantime "
                                          f"(now {fmt_num(cur_val)}) — reload the page")
                        changed[key] = new_val
                        merged[key] = new_val
                errors += _validate_settings(merged)
                if errors:
                    raise ValueError("\n".join(errors))
                for key, val in changed.items():
                    conn.execute("UPDATE ai_settings SET value = %s WHERE key = %s", (val, key))
            if changed:
                flash("Saved: " + ", ".join(f"{k} = {fmt_num(v)}" for k, v in changed.items()), "ok")
            else:
                flash("No changes.", "info")
        except ValueError as exc:
            for line in str(exc).splitlines():
                flash(line, "error")
        except psycopg.Error as exc:
            flash(f"Database error: {db_error(exc)}", "error")
        return redirect(url_for("settings_page"))

    with db(readonly=True) as conn:
        rows = conn.execute(
            "SELECT key, value, category, description, updated_at FROM ai_settings "
            "ORDER BY key").fetchall()
    stages = {n: {"title": t, "intro": i, "rows": []} for n, (t, i) in PIPELINE_STEPS.items()}
    other = []
    for r in rows:
        r["help"] = SETTING_HELP.get(r["key"])
        (stages[r["help"]["stage"]]["rows"] if r["help"] else other).append(r)
    return render_template("settings.html", stages=stages, other=other)


# ============================================================
# Routes — prompts
# ============================================================

def _threat_scale_text(conn):
    rows = conn.execute(
        "SELECT formatted_line FROM cyber_sentinel.v_threat_scale_for_agent ORDER BY score").fetchall()
    return "\n".join(r["formatted_line"] for r in rows)


def _placeholder_report(text):
    found = set(PLACEHOLDER_RE.findall(text or ""))
    missing = [p for p in REQUIRED_PLACEHOLDERS if p not in (text or "")]
    unknown = sorted(found - KNOWN_PLACEHOLDERS)
    return {"missing": missing, "unknown": unknown}


def _render_prompt(conn, text):
    max_dev = conn.execute("SELECT value FROM ai_settings WHERE key = 'ai_max_deviation'").fetchone()
    rendered = (text or "").replace("[[THREAT_SCALE]]", _threat_scale_text(conn))
    if max_dev:
        rendered = rendered.replace("[[MAX_DEVIATION]]", fmt_num(max_dev["value"]))
    return rendered


def _suggest_version(conn, base):
    existing = {r["version"] for r in conn.execute("SELECT version FROM prompt_templates").fetchall()}
    m = re.match(r"^(.*?)(\d+)$", base or "")
    if m:
        prefix, num = m.group(1), int(m.group(2))
        for i in range(num + 1, num + 1000):
            cand = f"{prefix}{i}"
            if cand not in existing and VERSION_RE.match(cand):
                return cand
    for i in range(2, 1000):
        cand = f"{base}-{i}"[:20]
        if cand not in existing and VERSION_RE.match(cand):
            return cand
    return ""


def _get_prompt(conn, version):
    row = conn.execute("SELECT * FROM prompt_templates WHERE version = %s", (version,)).fetchone()
    if row is None:
        abort(404, f"Prompt version '{version}' does not exist.")
    return row


@app.route("/prompts")
@login_required
def prompts_page():
    with db(readonly=True) as conn:
        rows = conn.execute(
            "SELECT version, is_active, notes, created_at, length(system_prompt) AS chars, "
            "array_length(string_to_array(system_prompt, E'\\n'), 1) AS lines "
            "FROM prompt_templates ORDER BY is_active DESC, created_at DESC, version DESC").fetchall()
    return render_template("prompts.html", rows=rows)


@app.route("/prompts/new", methods=["GET", "POST"])
@login_required
def prompt_new():
    if request.method == "POST":
        version = request.form.get("version", "").strip()
        text = request.form.get("system_prompt", "").replace("\r\n", "\n")
        notes = request.form.get("notes", "").strip() or None
        if not VERSION_RE.match(version):
            flash("Version name: 1–20 characters, letters, digits, dot, hyphen, underscore only.", "error")
            return render_template("prompt_new.html", version=version, text=text, notes=notes or "",
                                   source=request.form.get("source", ""))
        if not text.strip():
            flash("Prompt text must not be empty.", "error")
            return render_template("prompt_new.html", version=version, text=text, notes=notes or "",
                                   source=request.form.get("source", ""))
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO prompt_templates (version, system_prompt, is_active, notes) "
                    "VALUES (%s, %s, FALSE, %s)", (version, text, notes))
            flash(f"Utworzono szkic wersji {version}. Nie jest jeszcze aktywny.", "ok")
            return redirect(url_for("prompt_edit", version=version))
        except psycopg.errors.UniqueViolation:
            flash(f"Version '{version}' already exists.", "error")
        except psycopg.Error as exc:
            flash(f"Database error: {db_error(exc)}", "error")
        return render_template("prompt_new.html", version=version, text=text, notes=notes or "",
                               source=request.form.get("source", ""))

    source = request.args.get("from", "")
    with db(readonly=True) as conn:
        if source:
            src = _get_prompt(conn, source)
        else:
            src = conn.execute("SELECT * FROM prompt_templates WHERE is_active").fetchone()
        text = src["system_prompt"] if src else ""
        base = src["version"] if src else "1.0"
        version = _suggest_version(conn, base)
    return render_template("prompt_new.html", version=version, text=text,
                           notes=f"Na bazie {base}" if src else "", source=base if src else "")


@app.route("/prompts/<version>", methods=["GET", "POST"])
@login_required
def prompt_edit(version):
    preview = None
    row = None
    if request.method == "POST":
        action = request.form.get("action", "save")
        text = request.form.get("system_prompt", "").replace("\r\n", "\n")
        notes = request.form.get("notes", "").strip() or None
        fingerprint = request.form.get("fingerprint", "")
        try:
            with db(readonly=(action == "preview")) as conn:
                row = _get_prompt(conn, version)
                if row["is_active"]:
                    text = row["system_prompt"]  # active text is read-only
                if action == "preview":
                    preview = _render_prompt(conn, text)
                else:
                    if not text.strip():
                        raise ValueError("Prompt text must not be empty.")
                    if fingerprint != text_fingerprint(row["system_prompt"], row["notes"]):
                        raise ValueError("This version was changed by someone else in the meantime. "
                                         "Copy your edits and reload the page.")
                    conn.execute(
                        "UPDATE prompt_templates SET system_prompt = %s, notes = %s WHERE version = %s",
                        (text, notes, version))
                    flash(f"Saved version {version}.", "ok")
                    return redirect(url_for("prompt_edit", version=version))
        except ValueError as exc:
            flash(str(exc), "error")
        except psycopg.Error as exc:
            flash(f"Database error: {db_error(exc)}", "error")
        if row is None:
            return redirect(url_for("prompts_page"))
        # Re-render with what the user typed so nothing is lost on error/preview.
        row = {**row, "system_prompt": text, "notes": notes}
        return render_template("prompt_edit.html", row=row, preview=preview,
                               report=_placeholder_report(text), fingerprint=fingerprint)

    with db(readonly=True) as conn:
        row = _get_prompt(conn, version)
    return render_template("prompt_edit.html", row=row, preview=None,
                           report=_placeholder_report(row["system_prompt"]),
                           fingerprint=text_fingerprint(row["system_prompt"], row["notes"]))


@app.route("/prompts/<version>/activate", methods=["POST"])
@login_required
def prompt_activate(version):
    try:
        with db() as conn:
            row = _get_prompt(conn, version)
            if row["is_active"]:
                flash(f"Version {version} is already active.", "info")
                return redirect(url_for("prompts_page"))
            report = _placeholder_report(row["system_prompt"])
            if report["missing"]:
                raise ValueError("Not activated — placeholders required by the workflow are missing: "
                                 + ", ".join(report["missing"]))
            if report["unknown"]:
                raise ValueError("Not activated — unknown placeholders (n8n will not replace them): "
                                 + ", ".join(f"[[{p}]]" for p in report["unknown"]))
            prev = conn.execute("SELECT version FROM prompt_templates WHERE is_active").fetchone()
            # Order matters: the partial unique index forbids two active rows;
            # the deferred trigger forbids zero at COMMIT.
            conn.execute("UPDATE prompt_templates SET is_active = FALSE WHERE is_active")
            conn.execute("UPDATE prompt_templates SET is_active = TRUE WHERE version = %s", (version,))
        flash(f"Active prompt version: {version}"
              + (f" (previously {prev['version']})" if prev else "")
              + ". n8n uses it from the next workflow run.", "ok")
    except ValueError as exc:
        flash(str(exc), "error")
    except psycopg.Error as exc:
        flash(f"Database error: {db_error(exc)}", "error")
    return redirect(url_for("prompts_page"))


@app.route("/prompts/<version>/delete", methods=["POST"])
@login_required
def prompt_delete(version):
    try:
        with db() as conn:
            _get_prompt(conn, version)
            conn.execute("DELETE FROM prompt_templates WHERE version = %s", (version,))
        flash(f"Deleted version {version}.", "ok")
    except psycopg.Error as exc:
        flash(f"Database error: {db_error(exc)}", "error")
    return redirect(url_for("prompts_page"))


@app.route("/prompts/<version>/diff")
@login_required
def prompt_diff(version):
    with db(readonly=True) as conn:
        row = _get_prompt(conn, version)
        others = [r["version"] for r in conn.execute(
            "SELECT version FROM prompt_templates WHERE version <> %s "
            "ORDER BY is_active DESC, created_at DESC", (version,)).fetchall()]
        against = request.args.get("against") or (others[0] if others else None)
        base = _get_prompt(conn, against) if against else None
    lines = []
    if base:
        for line in difflib.unified_diff(base["system_prompt"].splitlines(),
                                         row["system_prompt"].splitlines(),
                                         fromfile=against, tofile=version, lineterm="", n=3):
            kind = "meta" if line.startswith(("---", "+++", "@@")) else \
                   "add" if line.startswith("+") else "del" if line.startswith("-") else "ctx"
            lines.append((kind, line))
    return render_template("prompt_diff.html", row=row, against=against, others=others, lines=lines)


# ============================================================
# Routes — trusted infrastructure
# ============================================================

def _normalize_pattern(match_type, pattern):
    pattern = (pattern or "").strip().lower()
    if match_type == "domain_suffix":
        pattern = pattern.strip(".")
        if not DOMAIN_RE.match(pattern):
            raise ValueError("domain_suffix must be a valid domain, e.g. microsoft.com")
    elif match_type == "as_owner":
        # Substring match against the VirusTotal AS owner: a very short
        # pattern ("a", "co") would cap the score of almost every host at 2.
        if len(pattern) < 4:
            raise ValueError("as_owner: pattern must be at least 4 characters "
                             "(substring match — a short pattern would match almost every AS owner)")
    else:
        raise ValueError("Unknown match type")
    return pattern


@app.route("/trusted", methods=["GET", "POST"])
@login_required
def trusted_page():
    if request.method == "POST":
        action = request.form.get("action")
        try:
            with db() as conn:
                if action == "add":
                    mt = request.form.get("match_type", "")
                    pattern = _normalize_pattern(mt, request.form.get("pattern"))
                    note = request.form.get("note", "").strip() or None
                    conn.execute("INSERT INTO trusted_infrastructure (match_type, pattern, note) "
                                 "VALUES (%s, %s, %s)", (mt, pattern, note))
                    flash(f"Added {mt} = {pattern}.", "ok")
                elif action == "toggle":
                    r = conn.execute("UPDATE trusted_infrastructure SET is_active = NOT is_active "
                                     "WHERE id = %s RETURNING pattern, is_active",
                                     (int(request.form["id"]),)).fetchone()
                    if r:
                        flash(f"{r['pattern']}: {'enabled' if r['is_active'] else 'disabled'}.", "ok")
                elif action == "note":
                    conn.execute("UPDATE trusted_infrastructure SET note = %s WHERE id = %s",
                                 (request.form.get("note", "").strip() or None, int(request.form["id"])))
                    flash("Note saved.", "ok")
                elif action == "delete":
                    r = conn.execute("DELETE FROM trusted_infrastructure WHERE id = %s RETURNING pattern",
                                     (int(request.form["id"]),)).fetchone()
                    if r:
                        flash(f"Deleted {r['pattern']}.", "ok")
                else:
                    abort(400)
        except (ValueError, KeyError) as exc:
            flash(str(exc) if isinstance(exc, ValueError) else "A required field is missing.", "error")
        except psycopg.errors.UniqueViolation:
            flash("This entry already exists.", "error")
        except psycopg.Error as exc:
            flash(f"Database error: {db_error(exc)}", "error")
        return redirect(url_for("trusted_page"))

    with db(readonly=True) as conn:
        rows = conn.execute("SELECT * FROM trusted_infrastructure "
                            "ORDER BY match_type, is_active DESC, pattern").fetchall()
    return render_template("trusted.html", rows=rows)


# ============================================================
# Routes — threat scale wording
# ============================================================

@app.route("/threat-levels", methods=["GET", "POST"])
@login_required
def threat_levels_page():
    if request.method == "POST":
        try:
            with db() as conn:
                rows = conn.execute("SELECT * FROM cyber_sentinel.dic_threat_levels "
                                    "ORDER BY score FOR UPDATE").fetchall()
                changed = []
                for r in rows:
                    sc = r["score"]
                    desc = request.form.get(f"desc_{sc}", "").strip()
                    action = request.form.get(f"action_{sc}", "").strip() or None
                    mal = request.form.get(f"mal_{sc}") == "on"
                    if not desc or len(desc) > 100:
                        raise ValueError(f"Level {sc}: description must be 1–100 characters.")
                    if action and len(action) > 50:
                        raise ValueError(f"Level {sc}: action must be at most 50 characters.")
                    if (desc, action, mal) != (r["description"], r["action_recommended"], r["is_malicious_flag"]):
                        conn.execute("UPDATE cyber_sentinel.dic_threat_levels SET description = %s, "
                                     "action_recommended = %s, is_malicious_flag = %s WHERE score = %s",
                                     (desc, action, mal, sc))
                        changed.append(str(sc))
                # Same rule as the deferred DB trigger, checked here first for a
                # readable message (the trigger stays the authority).
                flags = {r["score"]: request.form.get(f"mal_{r['score']}") == "on" for r in rows}
                malicious = [sc for sc, f in flags.items() if f]
                if not malicious:
                    raise ValueError("At least the highest level must be marked malicious.")
                if any(not flags[sc] for sc in flags if sc >= min(malicious)):
                    raise ValueError(f"Malicious levels must be a contiguous top range — every level from "
                                     f"{min(malicious)} upwards must be malicious.")
            flash(("Saved level(s) " + ", ".join(changed) + ".") if changed else "No changes.",
                  "ok" if changed else "info")
        except ValueError as exc:
            flash(str(exc), "error")
        except psycopg.Error as exc:
            flash(f"Database error: {db_error(exc)}", "error")
        return redirect(url_for("threat_levels_page"))

    with db(readonly=True) as conn:
        rows = conn.execute("SELECT * FROM cyber_sentinel.dic_threat_levels ORDER BY score").fetchall()
        scale = _threat_scale_text(conn)
    return render_template("threat_levels.html", rows=rows, scale=scale)


# ============================================================
# Routes — domain allow-list
# ============================================================

def _normalize_domain(value):
    d = (value or "").strip().lower().strip(".")
    if not DOMAIN_RE.match(d):
        raise ValueError(f"'{value}' is not a valid domain (e.g. mybank.pl).")
    return d


@app.route("/allowlist", methods=["GET", "POST"])
@login_required
def allowlist_page():
    if request.method == "POST":
        action = request.form.get("action")
        try:
            with db() as conn:
                if action == "add":
                    domain = _normalize_domain(request.form.get("domain"))
                    note = request.form.get("note", "").strip() or None
                    existing = conn.execute("SELECT source FROM domain_allowlist WHERE domain = %s",
                                            (domain,)).fetchone()
                    if existing:
                        raise ValueError(f"{domain} is already on the allow-list (source: {existing['source']}).")
                    excluded = conn.execute(
                        "SELECT domain FROM domain_allowlist_exclusions "
                        "WHERE domain = ANY (domain_suffixes(%s))", (domain,)).fetchone()
                    conn.execute("INSERT INTO v_manual_allowlist (domain, note) VALUES (%s, %s)",
                                 (domain, note))
                    flash(f"Added {domain} to the allow-list.", "ok")
                    if excluded:
                        flash(f"Note: {domain} matches the exclusion '{excluded['domain']}' — exclusions win, "
                              f"so this domain will still be analysed.", "warn")
                elif action == "toggle":
                    r = conn.execute(
                        "UPDATE v_manual_allowlist SET is_active = NOT is_active, "
                        "removed_at = CASE WHEN is_active THEN LOCALTIMESTAMP END, "
                        "updated_at = LOCALTIMESTAMP WHERE domain = %s RETURNING domain, is_active",
                        (request.form["domain"],)).fetchone()
                    if r:
                        flash(f"{r['domain']}: {'active' if r['is_active'] else 'disabled'}.", "ok")
                elif action == "delete":
                    r = conn.execute("DELETE FROM v_manual_allowlist WHERE domain = %s RETURNING domain",
                                     (request.form["domain"],)).fetchone()
                    if r:
                        flash(f"Deleted {r['domain']}.", "ok")
                elif action == "add_exclusion":
                    domain = _normalize_domain(request.form.get("domain"))
                    note = request.form.get("note", "").strip() or None
                    conn.execute("INSERT INTO domain_allowlist_exclusions (domain, note) VALUES (%s, %s)",
                                 (domain, note))
                    flash(f"Added exclusion {domain} — its subdomains will always be analysed.", "ok")
                elif action == "delete_exclusion":
                    r = conn.execute("DELETE FROM domain_allowlist_exclusions WHERE domain = %s "
                                     "RETURNING domain", (request.form["domain"],)).fetchone()
                    if r:
                        flash(f"Deleted exclusion {r['domain']}.", "ok")
                else:
                    abort(400)
        except (ValueError, KeyError) as exc:
            flash(str(exc) if isinstance(exc, ValueError) else "A required field is missing.", "error")
        except psycopg.errors.UniqueViolation:
            flash("This entry already exists.", "error")
        except psycopg.Error as exc:
            flash(f"Database error: {db_error(exc)}", "error")
        return redirect(url_for("allowlist_page"))

    check = None
    check_domain = request.args.get("check", "").strip()
    with db(readonly=True) as conn:
        if check_domain:
            try:
                d = _normalize_domain(check_domain)
                check = {
                    "domain": d,
                    "allowlisted": conn.execute("SELECT is_allowlisted(%s) AS v", (d,)).fetchone()["v"],
                    "matches": conn.execute(
                        "SELECT domain, source, rank, is_active FROM domain_allowlist "
                        "WHERE domain = ANY (domain_suffixes(%s)) ORDER BY length(domain) DESC",
                        (d,)).fetchall(),
                    "exclusions": conn.execute(
                        "SELECT domain, note FROM domain_allowlist_exclusions "
                        "WHERE domain = ANY (domain_suffixes(%s))", (d,)).fetchall(),
                    "enabled": conn.execute("SELECT setting('allowlist_enabled') AS v").fetchone()["v"] == 1,
                }
            except ValueError as exc:
                flash(str(exc), "error")
        manual = conn.execute("SELECT * FROM v_manual_allowlist ORDER BY is_active DESC, domain").fetchall()
        exclusions = conn.execute("SELECT * FROM domain_allowlist_exclusions ORDER BY domain").fetchall()
        stats = conn.execute("SELECT source, is_active, count(*) AS n FROM domain_allowlist "
                             "GROUP BY 1, 2 ORDER BY 1, 2").fetchall()
        syncs = conn.execute("SELECT * FROM domain_allowlist_sync_log "
                             "ORDER BY started_at DESC LIMIT 5").fetchall()
    return render_template("allowlist.html", manual=manual, exclusions=exclusions, stats=stats,
                           syncs=syncs, check=check, check_domain=check_domain)


# ============================================================
# Routes — scoring simulator (read-only)
# ============================================================

# Simulator presets. "Calculate" never calls VirusTotal / ThreatFox /
# URLhaus — the form holds what those services WOULD return. "Fetch live
# data" (live_lookup.py) fills the same form from the real APIs first.
SIM_FIELDS = ["fqdn", "observable_ip", "ip_auto", "vt_status", "vt_malicious", "vt_as_owner", "tf_status", "tf_ioc_count",
              "tf_active", "tf_malware_families", "uh_status", "uh_urls_online"]
SIM_PRESETS = {
    "clean": {
        "label": "Clean site",
        "hint": "Typical popular website: no detections anywhere.",
        "values": {"fqdn": "example.org", "observable_ip": "", "ip_auto": "", "vt_status": "ok", "vt_malicious": "0", "vt_as_owner": "Example Hosting",
                   "tf_status": "no_data", "tf_ioc_count": "0", "tf_active": "", "tf_malware_families": "",
                   "uh_status": "no_data", "uh_urls_online": "0"},
    },
    "big_player_noise": {
        "label": "Big provider, 2 detections",
        "hint": "Trusted infrastructure with a couple of false positives.",
        "values": {"fqdn": "cdn.example.com", "observable_ip": "", "ip_auto": "", "vt_status": "ok", "vt_malicious": "2", "vt_as_owner": "Google LLC",
                   "tf_status": "no_data", "tf_ioc_count": "0", "tf_active": "", "tf_malware_families": "",
                   "uh_status": "no_data", "uh_urls_online": "0"},
    },
    "suspicious": {
        "label": "Suspicious, below gate",
        "hint": "A few engines flag it; not enough for AI enrichment.",
        "values": {"fqdn": "odd-domain.example", "observable_ip": "", "ip_auto": "", "vt_status": "ok", "vt_malicious": "6", "vt_as_owner": "Small VPS Ltd",
                   "tf_status": "no_data", "tf_ioc_count": "0", "tf_active": "", "tf_malware_families": "",
                   "uh_status": "no_data", "uh_urls_online": "0"},
    },
    "active_c2": {
        "label": "Active C2 server",
        "hint": "Many detections + active ThreatFox IOC with a malware family.",
        "values": {"fqdn": "c2.bad.example", "observable_ip": "", "ip_auto": "", "vt_status": "ok", "vt_malicious": "14", "vt_as_owner": "Bulletproof Hosting",
                   "tf_status": "ok", "tf_ioc_count": "1", "tf_active": "on", "tf_malware_families": "AsyncRAT",
                   "uh_status": "ok", "uh_urls_online": "2"},
    },
}
SIM_DEFAULT_PRESET = "clean"


def _int_field(form, name, lo=0, hi=10_000):
    raw = form.get(name, "0").strip() or "0"
    try:
        v = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}: must be a whole number") from exc
    if not lo <= v <= hi:
        raise ValueError(f"{name}: range {lo}–{hi}")
    return v


@app.route("/simulator", methods=["GET", "POST"])
@login_required
def simulator_page():
    preset = request.args.get("preset", SIM_DEFAULT_PRESET)
    form = dict(SIM_PRESETS.get(preset, SIM_PRESETS[SIM_DEFAULT_PRESET])["values"])
    result = None
    live = None
    if request.method == "POST":
        form = {k: request.form.get(k, "") for k in SIM_FIELDS}
        try:
            if request.form.get("action") == "live":
                live = _sim_fetch_live(form)
            for st in ("tf_status", "uh_status"):
                if form[st] not in TF_UH_STATUSES:
                    raise ValueError(f"{st}: invalid value")
            if form["vt_status"] not in ("ok", "no_data"):
                raise ValueError("vt_status: invalid value")
            fqdn = form["fqdn"].strip().lower().rstrip(".")
            if fqdn and not DOMAIN_RE.match(fqdn):
                raise ValueError(f"'{form['fqdn']}' is not a valid domain")
            payload = {
                "fqdn": fqdn,
                "vt_status": form["vt_status"],
                "vt_malicious": _int_field(form, "vt_malicious", 0, 200),
                "vt_as_owner": form["vt_as_owner"].strip(),
                "tf_status": form["tf_status"],
                "tf_ioc_count": _int_field(form, "tf_ioc_count", 0, 1000),
                "tf_active": form.get("tf_active") == "on",
                "tf_malware_families": [f.strip() for f in form["tf_malware_families"].split(",") if f.strip()],
                "uh_status": form["uh_status"],
                "uh_urls_online": _int_field(form, "uh_urls_online", 0, 100_000),
            }
            with db(readonly=True) as conn:
                s = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM ai_settings").fetchall()}
                gate = s.get("vt_gate_min_malicious")
                gate_open = gate is not None and payload["vt_status"] == "ok" and payload["vt_malicious"] >= gate

                # Same as the workflow: below the gate ThreatFox / URLhaus are
                # never queried, whatever was typed into the form.
                effective = dict(payload)
                ignored_enrichment = False
                if not gate_open:
                    ignored_enrichment = (payload["tf_ioc_count"] > 0 or payload["uh_urls_online"] > 0
                                          or payload["tf_status"] == "ok" or payload["uh_status"] == "ok")
                    effective.update({"tf_status": "not_checked", "tf_ioc_count": 0, "tf_active": False,
                                      "tf_malware_families": [], "uh_status": "not_checked", "uh_urls_online": 0})

                allowlisted = bool(fqdn) and conn.execute("SELECT is_allowlisted(%s) AS v", (fqdn,)).fetchone()["v"]
                allow_match = conn.execute(
                    "SELECT domain, source, rank FROM domain_allowlist "
                    "WHERE is_active AND domain = ANY (domain_suffixes(%s)) ORDER BY length(domain) DESC LIMIT 1",
                    (fqdn,)).fetchone() if fqdn else None
                allowlist_on = s.get("allowlist_enabled") == 1

                score = conn.execute("SELECT compute_threat_score(%s) AS r", (Jsonb(effective),)).fetchone()["r"]
                level = conn.execute("SELECT * FROM cyber_sentinel.dic_threat_levels WHERE score = %s",
                                     (score["rule_score"],)).fetchone()
            max_dev = int(s.get("ai_max_deviation") or 0)
            rule = score["rule_score"]
            result = {
                "score": score, "level": level, "payload": effective,
                "skipped": allowlisted and allowlist_on,
                "allowlisted": allowlisted, "allow_match": allow_match, "allowlist_on": allowlist_on,
                "gate_open": gate_open, "gate": gate,
                "ignored_enrichment": ignored_enrichment,
                "ai_range": (max(1, rule - max_dev), min(5, rule + max_dev)) if gate_open else None,
                "max_dev": max_dev,
                "email_min": s.get("email_min_score"),
                "would_email": gate_open and s.get("email_min_score") is not None and rule >= s["email_min_score"],
            }
        except live_lookup.LiveLookupError as exc:
            flash(f"Live lookup failed — nothing was calculated: {exc}", "error")
        except ValueError as exc:
            flash(str(exc), "error")
        except psycopg.Error as exc:
            flash(f"Database error: {db_error(exc)}", "error")
    return render_template("simulator.html", form=form, result=result, live=live, statuses=TF_UH_STATUSES,
                           presets=SIM_PRESETS, preset=preset,
                           live_vt=live_lookup.vt_enabled(), live_abuse=live_lookup.abuse_enabled(),
                           vt_budget=live_lookup.vt_budget())


def _sim_fetch_live(form):
    """Fill the simulator form from the real APIs, exactly as the workflow would.

    Order and gating follow the n8n workflow: VirusTotal by IP first; ThreatFox
    (by IP) and URLhaus (by FQDN) only when VirusTotal passes the gate. Mutates
    `form` and returns the reduced evidence for the template.
    """
    if not live_lookup.vt_enabled():
        raise live_lookup.LiveLookupError("live lookups are not configured (AI_UI_VT_API_KEY is empty).")
    fqdn = form["fqdn"].strip().lower().rstrip(".")
    if not fqdn or not DOMAIN_RE.match(fqdn):
        raise ValueError("Live lookup needs a valid FQDN.")
    ip_raw = form.get("observable_ip", "").strip()
    # ip_auto = the FQDN a previous live lookup resolved the IP for. If the
    # FQDN has changed since, that IP belongs to the old domain: re-resolve.
    ip_auto = form.get("ip_auto", "").strip().lower()
    if ip_raw and ip_auto and ip_auto != fqdn:
        ip_raw = ""
    resolved = []
    if ip_raw:
        try:
            ip = str(ipaddress.IPv4Address(ip_raw))
        except ValueError as exc:
            raise ValueError(f"'{ip_raw}' is not a valid IPv4 address") from exc
    else:
        # Straight to Unbound — never via Pi-hole, so the lookup does not
        # land in dns_queries and the real n8n work queue.
        resolved = live_lookup.resolve_a(fqdn)
        ip = resolved[0]
    if not ipaddress.IPv4Address(ip).is_global:
        raise ValueError(f"{ip} is not a public address — VirusTotal has nothing to say about it.")

    # Settings in their own short transaction: no DB connection is held
    # open while waiting up to 3 × 20 s for external APIs.
    with db(readonly=True) as conn:
        s = {r["key"]: r["value"] for r in conn.execute(
            "SELECT key, value FROM ai_settings WHERE key IN ('vt_gate_min_malicious', 'tf_active_days')").fetchall()}

    vt = live_lookup.vt_lookup(ip)
    gate = s.get("vt_gate_min_malicious")
    gate_open = gate is not None and vt["status"] == "ok" and vt["malicious"] >= gate
    if gate_open:
        tf = live_lookup.threatfox_lookup(ip, s.get("tf_active_days") or 30)
        uh = live_lookup.urlhaus_lookup(fqdn)
    else:
        tf, uh = {"status": "not_checked"}, {"status": "not_checked"}

    form.update({
        "fqdn": fqdn,
        "observable_ip": ip,
        "ip_auto": fqdn if resolved else "",
        "vt_status": vt["status"],
        "vt_malicious": str(vt["malicious"]),
        "vt_as_owner": vt.get("as_owner") or "",
        "tf_status": tf["status"],
        "tf_ioc_count": str(tf.get("ioc_count", 0)),
        "tf_active": "on" if tf.get("active") else "",
        "tf_malware_families": ", ".join(tf.get("malware_families", [])),
        "uh_status": uh["status"],
        "uh_urls_online": str(uh.get("urls_online", 0)),
    })
    log.info("simulator live lookup by %s: fqdn=%s ip=%s vt=%s/%s cached=%s",
             session.get("user"), fqdn, ip, vt["status"], vt["malicious"], vt.get("cached"))
    return {"ip": ip, "resolved": resolved, "resolver": live_lookup.RESOLVER, "vt": vt, "tf": tf, "uh": uh, "gate_open": gate_open}


# ============================================================
# Routes — audit log
# ============================================================

def _changes(old, new):
    old, new = old or {}, new or {}
    out = []
    for key in sorted(set(old) | set(new)):
        a, b = old.get(key), new.get(key)
        if a == b:
            continue
        long_text = isinstance(a, str) and isinstance(b, str) and (len(a) > 200 or len(b) > 200)
        diff = None
        if long_text:
            diff = [("meta" if l.startswith(("---", "+++", "@@")) else
                     "add" if l.startswith("+") else "del" if l.startswith("-") else "ctx", l)
                    for l in difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm="", n=1)]
        out.append({"field": key, "old": a, "new": b, "diff": diff})
    return out


@app.route("/audit")
@login_required
def audit_page():
    table = request.args.get("table", "")
    if table and table not in AUDITED_TABLES:
        table = ""
    with db(readonly=True) as conn:
        rows = conn.execute(
            "SELECT * FROM config_change_log WHERE (%s = '' OR table_name = %s) "
            "ORDER BY changed_at DESC, id DESC LIMIT 200", (table, table)).fetchall()
    for r in rows:
        r["changes"] = _changes(r["old_data"], r["new_data"]) if r["operation"] == "UPDATE" else []
    return render_template("audit.html", rows=rows, table=table, tables=AUDITED_TABLES)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
