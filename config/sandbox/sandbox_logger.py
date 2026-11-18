"""
Cyber Sentinel — browser sandbox mitmproxy addon.

Loaded by the sandbox-mitmproxy container (`mitmdump -s /addons/sandbox_logger.py`).

1. Egress guard: every upstream connection is resolved here (through the
   sandbox Pi-hole) and refused when any address is not globally routable
   (RFC 1918, loopback, link-local, CGNAT, multicast, reserved). The checked
   IP is pinned as the connect address, so a second lookup (DNS rebinding)
   cannot redirect the connection into the LAN or the stack.
2. URL log: one JSON object per line for every HTTP flow, error and blocked
   attempt, written to SANDBOX_LOG_FILE (rotated at midnight, SANDBOX_LOG_DAYS
   files kept). Cookies and credentials are redacted; bodies are never stored,
   only their size and SHA-256 (for payload lookups later).
3. Upstream TLS: mitmproxy runs with ssl_insecure (bad certificates are
   common on malicious sites and are part of the picture), so the real
   certificate chain is verified here against the certifi roots and the
   result is logged with the flow.
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import logging.handlers
import os
import socket
from datetime import datetime, timezone

from mitmproxy import http

LOG_FILE = os.environ.get("SANDBOX_LOG_FILE", "/logs/urls.jsonl")
LOG_DAYS = int(os.environ.get("SANDBOX_LOG_DAYS", "14"))
BLOCK_PREFIX = "sandbox-blocked"
REDACTED_HEADERS = {"cookie", "set-cookie", "authorization", "proxy-authorization"}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _headers(headers):
    return [
        [name, "[redacted]" if name.lower() in REDACTED_HEADERS else value]
        for name, value in headers.items(multi=True)
    ]


def _peer_ip(conn):
    addr = getattr(conn, "peername", None) if conn else None
    return addr[0] if addr else None


class _CertVerifier:
    """Verifies an upstream chain with cryptography's X.509 path validation."""

    def __init__(self):
        self.store = None
        try:
            import certifi
            from cryptography import x509
            from cryptography.x509.verification import Store

            with open(certifi.where(), "rb") as f:
                self.store = Store(x509.load_pem_x509_certificates(f.read()))
        except Exception as exc:  # best effort: logging must never stop
            logging.getLogger(__name__).warning("upstream cert verification disabled: %s", exc)

    def check(self, chain, server_name):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        leaf = chain[0]
        info = {
            "subject": leaf.subject.rfc4514_string(),
            "issuer": leaf.issuer.rfc4514_string(),
            "not_after": leaf.not_valid_after_utc.isoformat(),
            "sha256": leaf.fingerprint(hashes.SHA256()).hex(),
            "verified": None,
            "error": None,
        }
        if self.store is None or not server_name:
            return info
        try:
            from cryptography.x509.verification import PolicyBuilder

            try:
                subject = x509.IPAddress(ipaddress.ip_address(server_name))
            except ValueError:
                subject = x509.DNSName(server_name)
            verifier = PolicyBuilder().store(self.store).build_server_verifier(subject)
            verifier.verify(leaf, chain[1:])
            info["verified"] = True
        except Exception as exc:
            info["verified"] = False
            info["error"] = str(exc)[:300]
        return info


class SandboxLogger:
    def __init__(self):
        self.log = logging.getLogger("sandbox_urls")
        self.log.propagate = False
        self.log.setLevel(logging.INFO)
        self.verifier = _CertVerifier()
        self.tls_info = {}  # server connection id -> upstream cert info

    def running(self):
        if not self.log.handlers:
            os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
            handler = logging.handlers.TimedRotatingFileHandler(
                LOG_FILE, when="midnight", backupCount=LOG_DAYS, encoding="utf-8"
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self.log.addHandler(handler)

    def _write(self, record):
        self.log.info(json.dumps(record, ensure_ascii=False, separators=(",", ":")))

    # --- egress guard -------------------------------------------------

    async def server_connect(self, data):
        server = data.server
        if not server.address:
            return
        host, port = server.address
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, port, type=socket.SOCK_STREAM
            )
        except OSError as exc:
            server.error = f"dns resolution failed for {host}: {exc}"
            return
        addrs = []
        for _family, _type, _proto, _canon, sockaddr in infos:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip not in addrs:
                addrs.append(ip)
        bad = [str(ip) for ip in addrs if not ip.is_global]
        if bad or not addrs:
            server.error = f"{BLOCK_PREFIX}: {host} resolves to non-public {','.join(bad)}"
            return
        v4 = [ip for ip in addrs if ip.version == 4]  # sandbox networks are IPv4 only
        if not v4:
            server.error = f"no IPv4 address for {host}"
            return
        server.address = (str(v4[0]), port)

    # --- upstream TLS -------------------------------------------------

    def tls_established_server(self, data):
        conn = data.conn
        try:
            chain = [c.to_cryptography() for c in (conn.certificate_list or [])]
            if chain:
                self.tls_info[conn.id] = self.verifier.check(chain, conn.sni)
        except Exception as exc:
            self.tls_info[conn.id] = {"verified": None, "error": f"inspection failed: {exc}"}

    def server_disconnected(self, data):
        self.tls_info.pop(data.server.id, None)

    # --- log records --------------------------------------------------

    def _base(self, flow: http.HTTPFlow, event):
        req = flow.request
        return {
            "ts": _now(),
            "event": event,
            "client_ip": _peer_ip(flow.client_conn),
            "method": req.method,
            "url": req.pretty_url,
            "scheme": req.scheme,
            "host": req.pretty_host,
            "port": req.port,
            "http_version": req.http_version,
            "referer": req.headers.get("referer"),
            "user_agent": req.headers.get("user-agent"),
            "req_headers": _headers(req.headers),
        }

    def _tls(self, flow):
        if flow.request.scheme != "https" or not flow.server_conn:
            return None
        return self.tls_info.get(flow.server_conn.id)

    def response(self, flow: http.HTTPFlow):
        resp = flow.response
        rec = self._base(flow, "http")
        rec["server_ip"] = _peer_ip(flow.server_conn)
        rec["status"] = resp.status_code
        rec["reason"] = resp.reason
        rec["content_type"] = resp.headers.get("content-type")
        rec["redirect_location"] = (
            resp.headers.get("location") if 300 <= resp.status_code < 400 else None
        )
        rec["resp_headers"] = _headers(resp.headers)
        if resp.stream or resp.raw_content is None:
            # Larger than stream_large_bodies: passed through, not hashed.
            rec["streamed"] = True
            rec["size"] = int(resp.headers.get("content-length", 0) or 0) or None
            rec["sha256"] = None
        else:
            body = resp.get_content(strict=False) or b""
            rec["streamed"] = False
            rec["size"] = len(body)
            rec["sha256"] = hashlib.sha256(body).hexdigest() if body else None
        rec["upstream_tls"] = self._tls(flow)
        self._write(rec)

    def error(self, flow: http.HTTPFlow):
        msg = flow.error.msg if flow.error else ""
        rec = self._base(flow, "blocked" if BLOCK_PREFIX in msg else "error")
        rec["error"] = msg[:500]
        rec["upstream_tls"] = self._tls(flow)
        self._write(rec)

    def http_connect_error(self, flow: http.HTTPFlow):
        # CONNECT tunnel refused (e.g. blocked destination): not an HTTP flow error.
        self.error(flow)

    def tls_failed_client(self, data):
        # The browser refused mitmproxy's certificate (CA not trusted?).
        client = data.context.client
        self._write({
            "ts": _now(),
            "event": "client_tls_failed",
            "client_ip": _peer_ip(client),
            "host": client.sni,
            "error": str(data.conn.error)[:300] if data.conn.error else None,
        })


addons = [SandboxLogger()]
