"""
Live CTI lookups for the scoring simulator.

Mirrors the n8n workflow "Automated Domain & IP Reputation Guard" node by
node, so a live simulation produces the same features the workflow would:

    VirusTotal IP Scan + "Data reduction - VirusTotal"   -> vt_lookup()
    Abuse.CH_ThreatFox request  \\
    Abuse.CH_URLHaus request     > "Data reduction - abuse.ch"
                                   -> threatfox_lookup(), urlhaus_lookup()

Differences from the workflow, all deliberate:
  * The FQDN is resolved by a minimal DNS client talking straight to Unbound
    (AI_UI_RESOLVER, default 10.10.10.2). The container's normal resolver is
    Pi-hole -> passive_dns, which logs every query into dns_queries — a
    simulation would then put the domain into the real n8n work queue.
  * VirusTotal errors (429 / 401 / 5xx) are raised as LiveLookupError and shown
    to the operator. The workflow throws too (the observable stays queued),
    so neither path ever scores an error as "clean".
  * Nothing is written anywhere. Raw payloads are dropped after reduction.

Standard library only (urllib, socket) — no extra dependency in the image.
"""

import json
import os
import random
import socket
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
TF_URL = "https://threatfox-api.abuse.ch/api/v1/"
UH_URL = "https://urlhaus-api.abuse.ch/v1/host/"
HTTP_TIMEOUT = 20  # seconds, same as the workflow's HTTP nodes
USER_AGENT = "cyber-sentinel-ai-config-ui/1.0 (simulator)"


class LiveLookupError(Exception):
    """A live lookup failed in a way the operator must see (never scored)."""


# ------------------------------------------------------------
# Configuration (all optional — live mode is disabled without keys)
# ------------------------------------------------------------

def _env(name, default=""):
    return (os.environ.get(name) or default).strip()


VT_API_KEY = _env("AI_UI_VT_API_KEY")
ABUSE_API_KEY = _env("AI_UI_ABUSE_API_KEY")
RESOLVER = _env("AI_UI_RESOLVER", "10.10.10.2")
# The VirusTotal free tier (4 requests/min, 500/day) is SHARED with n8n,
# which needs 1 request per run. The UI therefore keeps well below it.
VT_MIN_INTERVAL = int(_env("AI_UI_VT_MIN_INTERVAL", "20"))   # seconds between UI requests
VT_DAILY_LIMIT = int(_env("AI_UI_VT_DAILY_LIMIT", "50"))     # UI requests per UTC day
CACHE_TTL = int(_env("AI_UI_LIVE_CACHE_SECONDS", "900"))    # reuse a result for 15 min


def vt_enabled():
    return bool(VT_API_KEY)


def abuse_enabled():
    return bool(ABUSE_API_KEY)


# ------------------------------------------------------------
# Quota guard + cache (process-local: gunicorn runs 1 worker)
# ------------------------------------------------------------

_lock = threading.Lock()
_cache = {}            # (source, key) -> (expires_at, value)
_vt_last_call = 0.0
_vt_day = None
_vt_day_count = 0


def _cache_get(source, key):
    with _lock:
        hit = _cache.get((source, key))
        if hit and hit[0] > time.time():
            return hit[1]
        _cache.pop((source, key), None)
        return None


def _cache_put(source, key, value):
    with _lock:
        if len(_cache) > 500:  # bounded; simulator traffic is tiny
            _cache.clear()
        _cache[(source, key)] = (time.time() + CACHE_TTL, value)


def _vt_reserve():
    """Reserve one VirusTotal request or raise LiveLiveLookupError with the reason."""
    global _vt_last_call, _vt_day, _vt_day_count
    with _lock:
        now = time.time()
        today = datetime.now(timezone.utc).date()
        if _vt_day != today:
            _vt_day, _vt_day_count = today, 0
        if _vt_day_count >= VT_DAILY_LIMIT:
            raise LiveLookupError(
                f"Simulator VirusTotal budget used up for today ({VT_DAILY_LIMIT} requests, "
                "AI_UI_VT_DAILY_LIMIT). The quota is shared with n8n, so the simulator stops first.")
        wait = VT_MIN_INTERVAL - (now - _vt_last_call)
        if wait > 0:
            raise LiveLookupError(
                f"Wait {int(wait) + 1} s before the next live VirusTotal lookup "
                f"(AI_UI_VT_MIN_INTERVAL = {VT_MIN_INTERVAL} s keeps the shared free-tier quota for n8n).")
        _vt_last_call = now
        _vt_day_count += 1


def vt_budget():
    with _lock:
        today = datetime.now(timezone.utc).date()
        used = _vt_day_count if _vt_day == today else 0
    return {"used": used, "limit": VT_DAILY_LIMIT, "interval": VT_MIN_INTERVAL}


# ------------------------------------------------------------
# HTTP helper
# ------------------------------------------------------------

def _http(method, url, headers=None, data=None):
    """Return (status_code, parsed_json_or_None, error_text_or_None).

    Mirrors the workflow's `fullResponse: true, neverError: true`: HTTP error
    codes are returned, only transport failures become an error text.
    """
    req = urllib.request.Request(url, method=method, data=data,
                                 headers={"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return None, None, f"request failed: {reason}"
    try:
        body = json.loads(raw.decode("utf-8")) if raw else None
    except (ValueError, UnicodeDecodeError):
        body = None
    return status, body, None


# ------------------------------------------------------------
# DNS — minimal A-record query straight to Unbound
# ------------------------------------------------------------

def resolve_a(fqdn, server=None, timeout=3.0):
    """Return the IPv4 addresses for fqdn, asking `server` directly (UDP/53).

    Follows the answer section only (Unbound returns the CNAME chain plus the
    final A records in one response). Raises LiveLookupError on failure.
    """
    server = server or RESOLVER
    qid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1, 1 question
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in fqdn.rstrip(".").split(".")) + b"\x00"
    query = header + qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, 53))
        resp, _ = sock.recvfrom(4096)
    except OSError as exc:
        raise LiveLookupError(f"DNS: resolver {server} did not answer ({exc}). Enter the IP manually.") from exc
    finally:
        sock.close()

    if len(resp) < 12:
        raise LiveLookupError("DNS: truncated response")
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", resp[:12])
    if rid != qid:
        raise LiveLookupError("DNS: response id mismatch")
    rcode = flags & 0x000F
    if rcode == 3:
        raise LiveLookupError(f"DNS: {fqdn} does not exist (NXDOMAIN)")
    if rcode != 0:
        raise LiveLookupError(f"DNS: resolver returned rcode {rcode}")

    def skip_name(off):
        while True:
            ln = resp[off]
            if ln == 0:
                return off + 1
            if ln & 0xC0 == 0xC0:
                return off + 2
            off += 1 + ln

    off = 12
    for _ in range(qd):
        off = skip_name(off) + 4
    ips = []
    for _ in range(an):
        off = skip_name(off)
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", resp[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(resp[off:off + 4]))
        off += rdlen
    if not ips:
        raise LiveLookupError(f"DNS: {fqdn} has no IPv4 (A) record")
    return ips


# ------------------------------------------------------------
# VirusTotal — "Data reduction - VirusTotal"
# ------------------------------------------------------------

def _num(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def reduce_virustotal(status_code, body):
    """Python port of the workflow's VirusTotal reduction. Pure function."""
    if status_code == 200:
        status = "ok"
    elif status_code == 404:
        status = "no_data"  # VirusTotal has never seen this IP
    else:
        msg = ((body or {}).get("error") or {}).get("message") if isinstance(body, dict) else None
        hint = {401: " — check AI_UI_VT_API_KEY", 403: " — key not allowed",
                429: " — quota exceeded (shared with n8n, try later)"}.get(status_code, "")
        raise LiveLookupError(f"VirusTotal HTTP {status_code}: {msg or 'error'}{hint}")

    data = body.get("data") if isinstance(body, dict) else None
    attr = (data.get("attributes") if isinstance(data, dict) else None) or {}
    stats = attr.get("last_analysis_stats") or {}
    flagged = [
        {"engine": engine, "category": r.get("category"), "result": r.get("result")}
        for engine, r in (attr.get("last_analysis_results") or {}).items()
        if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious")
    ]
    flagged.sort(key=lambda f: (f["category"] != "malicious", f["engine"].lower()))
    ts = attr.get("last_analysis_date")
    return {
        "status": status,
        "malicious": _num(stats.get("malicious")),
        "suspicious": _num(stats.get("suspicious")),
        "harmless": _num(stats.get("harmless")),
        "undetected": _num(stats.get("undetected")),
        "engines_total": sum(_num(v) for v in stats.values()),
        "flagged_by": flagged[:25],
        "as_owner": attr.get("as_owner"),
        "asn": attr.get("asn"),
        "country": attr.get("country"),
        "network": attr.get("network"),
        "reputation": attr.get("reputation"),
        "tags": attr.get("tags") if isinstance(attr.get("tags"), list) else [],
        "last_analysis_date": datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None,
    }


def vt_lookup(ip):
    """Live VirusTotal IP report, reduced. Cached; guarded by the UI quota."""
    if not VT_API_KEY:
        raise LiveLookupError("VirusTotal key not configured (AI_UI_VT_API_KEY).")
    cached = _cache_get("vt", ip)
    if cached:
        return {**cached, "cached": True}
    _vt_reserve()
    status, body, err = _http("GET", VT_URL.format(ip=urllib.parse.quote(ip)), headers={"x-apikey": VT_API_KEY})
    if err:
        raise LiveLookupError(f"VirusTotal {err}")
    vt = reduce_virustotal(status, body)
    _cache_put("vt", ip, vt)
    return {**vt, "cached": False}


# ------------------------------------------------------------
# abuse.ch — "Data reduction - abuse.ch"
# ------------------------------------------------------------

def _ioc_host(ioc):
    s = str(ioc or "")
    try:
        host = urllib.parse.urlsplit(s if "://" in s else f"http://{s}").hostname
        return host.lower() if host else None
    except ValueError:
        return None


def _parse_abuse_date(value):
    # abuse.ch timestamps look like "2026-09-01 10:11:12 UTC".
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.strptime(value.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _defang(url):
    s = str(url)
    if s[:4].lower() == "http":
        s = "hxxp" + s[4:]
    return s.replace(".", "[.]")


def _count_top(values, limit):
    counts = {}
    for v in values:
        k = str(v or "").strip().lower()
        if k:
            counts[k] = counts.get(k, 0) + 1
    return [{"value": k, "count": c} for k, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]


def _outcome(status, body, err):
    if err:
        return None, err
    if status != 200:
        return None, f"HTTP {status}"
    if not isinstance(body, dict):
        return None, "non-JSON response"
    return body, None


def reduce_threatfox(status, body, err, ip, active_days, now=None):
    """Python port of the ThreatFox half of "Data reduction - abuse.ch"."""
    body, error = _outcome(status, body, err)
    if error:
        return {"status": "error", "error": error}
    if body.get("query_status") == "no_result":
        return {"status": "no_data"}
    if body.get("query_status") != "ok":
        return {"status": "error", "error": f"query_status={body.get('query_status')}"}
    # The search matches substrings (1.2.3.4 also finds 1.2.3.45:80) — keep IOCs whose host is the IP.
    iocs = [d for d in (body.get("data") or []) if isinstance(d, dict) and _ioc_host(d.get("ioc")) == ip.lower()]
    if not iocs:
        return {"status": "no_data"}
    now = now or datetime.now(timezone.utc)
    cutoff = now.timestamp() - float(active_days) * 86400
    seen = [s for s in (_parse_abuse_date(d.get("last_seen")) or _parse_abuse_date(d.get("first_seen")) for d in iocs) if s]
    families = []
    for d in iocs:
        m = d.get("malware_printable")
        if m and not str(m).lower().startswith("unknown") and m not in families:
            families.append(m)
    threat_types = []
    for d in iocs:
        t = d.get("threat_type")
        if t and t not in threat_types:
            threat_types.append(t)
    return {
        "status": "ok",
        "ioc_count": len(iocs),
        "active": any(s.timestamp() >= cutoff for s in seen),
        "malware_families": families,
        "threat_types": threat_types,
        "max_confidence": max(_num(d.get("confidence_level")) for d in iocs),
        "last_seen": max(seen).isoformat() if seen else None,
        "tags": _count_top([t for d in iocs for t in (d.get("tags") or [])], 10),
        "iocs": [{"ioc": _defang(d.get("ioc")), "threat_type": d.get("threat_type"),
                  "malware": d.get("malware_printable"), "confidence": _num(d.get("confidence_level")),
                  "first_seen": d.get("first_seen"), "last_seen": d.get("last_seen")} for d in iocs[:10]],
    }


def reduce_urlhaus(status, body, err):
    """Python port of the URLhaus half of "Data reduction - abuse.ch"."""
    body, error = _outcome(status, body, err)
    if error:
        return {"status": "error", "error": error}
    if body.get("query_status") == "no_results":
        return {"status": "no_data"}
    if body.get("query_status") != "ok":
        return {"status": "error", "error": f"query_status={body.get('query_status')}"}
    urls = body.get("urls") if isinstance(body.get("urls"), list) else []
    online = [u for u in urls if isinstance(u, dict) and u.get("url_status") == "online"]
    return {
        "status": "ok",
        "url_count": _num(body.get("url_count")) or len(urls),
        "urls_online": len(online),
        "threats": _count_top([u.get("threat") for u in urls if isinstance(u, dict)], 5),
        "tags": _count_top([t for u in urls if isinstance(u, dict) for t in (u.get("tags") or [])], 10),
        "blacklists": body.get("blacklists"),
        "online_samples": [{"url": _defang(u.get("url")), "threat": u.get("threat")} for u in online[:5]],
        "reference": body.get("urlhaus_reference"),
    }


def threatfox_lookup(ip, active_days):
    if not ABUSE_API_KEY:
        return {"status": "error", "error": "abuse.ch key not configured (AI_UI_ABUSE_API_KEY)"}
    key = f"{ip}|{active_days}"
    cached = _cache_get("tf", key)
    if cached:
        return {**cached, "cached": True}
    data = json.dumps({"query": "search_ioc", "search_term": ip}).encode()
    status, body, err = _http("POST", TF_URL, headers={"Auth-Key": ABUSE_API_KEY, "Content-Type": "application/json"},
                              data=data)
    tf = reduce_threatfox(status, body, err, ip, active_days)
    if tf["status"] != "error":
        _cache_put("tf", key, tf)
    return {**tf, "cached": False}


def urlhaus_lookup(fqdn):
    if not ABUSE_API_KEY:
        return {"status": "error", "error": "abuse.ch key not configured (AI_UI_ABUSE_API_KEY)"}
    cached = _cache_get("uh", fqdn)
    if cached:
        return {**cached, "cached": True}
    data = urllib.parse.urlencode({"host": fqdn}).encode()
    status, body, err = _http("POST", UH_URL, headers={"Auth-Key": ABUSE_API_KEY,
                                                        "Content-Type": "application/x-www-form-urlencoded"},
                              data=data)
    uh = reduce_urlhaus(status, body, err)
    if uh["status"] != "error":
        _cache_put("uh", fqdn, uh)
    return {**uh, "cached": False}
