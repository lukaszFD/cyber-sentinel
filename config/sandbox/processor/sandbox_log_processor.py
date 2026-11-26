"""
sandbox_log_processor — browser sandbox logs -> cyber_sentinel_sandbox

Follows two files (both mounted read-only) and stores them through the
ingest functions of db_sandbox.sql:

    source  file                                        function
    ------  ------------------------------------------  ------------------------------
    urls    /logs/urls.jsonl (mitmproxy addon)          ingest_events()  -> url_events, observables
    dns     /var/log/sandbox-pihole/pihole.log          ingest_dns()     -> dns_queries

The database role has EXECUTE on those functions only; every value is
validated and length-capped there as well (the data is attacker controlled).

Exactly-once: each batch is stored together with the file position (inode +
byte offset) in one transaction (ingest_state). After a restart reading
resumes at that position; when the file was rotated meanwhile
(urls.jsonl -> urls.jsonl.YYYY-MM-DD at midnight), the rest of the old file
is read first. With no saved position the current file is read from the
start.

Top-level navigations (Sec-Fetch-Mode: navigate + Sec-Fetch-Dest: document)
are flagged (is_navigation): only those go to urlscan.io. The flag comes
from the request headers alone, so a page whose server failed (event
"error", e.g. a dead phishing site) is still a navigation.

DNS lines are parsed with the Parser of dns_log_processor (same Pi-hole
format; the client is always mitmproxy).

Configuration (environment):
    POSTGRES_HOST, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DATABASE  (required)
    SANDBOX_URLS_LOG   default /logs/urls.jsonl
    SANDBOX_DNS_LOG    default /var/log/sandbox-pihole/pihole.log
    BATCH_SIZE         default 200 records
    FLUSH_INTERVAL     default 2 (seconds)
    LOG_LEVEL          default INFO
    HEARTBEAT_FILE     default /run/heartbeat/alive (tmpfs; touched every 15 s
                       while Postgres answers, checked by the Docker HEALTHCHECK)
"""

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import Json

from log_processor import Parser  # dns_log_processor's Pi-hole line parser

URLS_LOG = os.getenv("SANDBOX_URLS_LOG", "/logs/urls.jsonl")
DNS_LOG = os.getenv("SANDBOX_DNS_LOG", "/var/log/sandbox-pihole/pihole.log")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "200"))
FLUSH_INTERVAL = float(os.getenv("FLUSH_INTERVAL", "2"))
POLL_INTERVAL = 0.5
STATS_INTERVAL = 300
MAX_LINE = 1_000_000          # bytes; longer lines are skipped (never produced by the addon)
HEARTBEAT_FILE = os.getenv("HEARTBEAT_FILE", "/run/heartbeat/alive")
HEARTBEAT_INTERVAL = 15       # seconds; the Docker HEALTHCHECK allows 60

log = logging.getLogger("sandbox_log_processor")
_heartbeat_failed = False


def heartbeat():
    """Touch HEARTBEAT_FILE: the main loop runs and Postgres answers (read by HEALTHCHECK)."""
    global _heartbeat_failed
    try:
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(datetime.now(timezone.utc).isoformat())
        _heartbeat_failed = False
    except OSError as e:
        if not _heartbeat_failed:
            log.warning("Cannot write heartbeat %s (%s)", HEARTBEAT_FILE, e)
            _heartbeat_failed = True


# ------------------------------------------------------------
# Record shaping
# ------------------------------------------------------------
def header(pairs, name):
    if not isinstance(pairs, list):
        return None
    for item in pairs:
        if isinstance(item, list) and len(item) == 2 and str(item[0]).lower() == name:
            return str(item[1]).lower()
    return None


def url_record(line):
    """One urls.jsonl line -> dict for ingest_events(), or None."""
    try:
        rec = json.loads(line)
    except ValueError:
        return None
    if not isinstance(rec, dict) or "event" not in rec:
        return None
    hdrs = rec.get("req_headers")
    rec["is_navigation"] = (
        header(hdrs, "sec-fetch-mode") == "navigate"
        and header(hdrs, "sec-fetch-dest") == "document"
    )
    return rec


class DnsShaper:
    def __init__(self):
        self.parser = Parser()

    def __call__(self, line):
        row = self.parser.parse(line)
        if not row:
            return None
        _, qtype, rtype, domain, client, answer = row
        return {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "query_type": qtype, "record_type": rtype, "domain": domain,
            "client": client, "answer": answer,
        }


# ------------------------------------------------------------
# File follower with a resumable position
# ------------------------------------------------------------
class Follower:
    """Reads complete lines; position() is (inode, offset after the last line)."""

    def __init__(self, source, path):
        self.source = source
        self.path = path
        self.fh = None
        self.inode = None
        self.offset = 0
        self.backlog = None           # rotated file still to finish: (path, inode)
        self.started = False

    def _open(self, path, offset):
        try:
            fh = open(path, "rb")
        except FileNotFoundError:
            return False
        except OSError as e:
            # e.g. permission denied: keep running, the other log still flows
            log.error("[%s] cannot open %s: %s", self.source, path, e)
            return False
        if self.fh:
            self.fh.close()
        st = os.fstat(fh.fileno())
        if offset > st.st_size:
            offset = 0                 # truncated meanwhile
        fh.seek(offset)
        self.fh, self.inode, self.offset = fh, st.st_ino, offset
        log.info("[%s] following %s (inode %s, offset %s)", self.source, path, self.inode, offset)
        return True

    def start(self, saved):
        """saved = (inode, offset) from ingest_position(), or None."""
        if not os.path.exists(self.path):
            return False
        current_inode = os.stat(self.path).st_ino
        if saved and saved[0] == current_inode:
            self.started = self._open(self.path, saved[1])
            return self.started
        if saved:
            old = self._find_inode(saved[0])
            if old:
                log.info("[%s] finishing rotated file %s first", self.source, old)
                self.backlog = (self.path, None)
                self.started = self._open(old, saved[1])
                return self.started
            log.warning("[%s] saved file (inode %s) is gone; reading %s from the start",
                        self.source, saved[0], self.path)
        self.started = self._open(self.path, 0)
        return self.started

    def _find_inode(self, inode):
        directory = os.path.dirname(self.path) or "."
        base = os.path.basename(self.path)
        try:
            for name in os.listdir(directory):
                if name.startswith(base):
                    p = os.path.join(directory, name)
                    if os.stat(p).st_ino == inode:
                        return p
        except OSError:
            pass
        return None

    def position(self):
        return self.inode, self.offset

    def read(self, limit):
        """Up to `limit` complete lines (bytes). Empty list = nothing new.
        Returns (lines, switched) — switched means the file changed after
        these lines (caller flushes first)."""
        lines = []
        while len(lines) < limit:
            chunk = self.fh.readline(MAX_LINE + 1)
            if not chunk:
                break
            if not chunk.endswith(b"\n"):
                if len(chunk) > MAX_LINE:
                    # Skip to the end of this line; its tail is dropped below
                    # as one unparseable "line".
                    log.warning("[%s] over-long line skipped", self.source)
                    self.offset = self.fh.tell()
                    continue
                # The writer has not finished the line yet: read it again later.
                self.fh.seek(self.offset)
                break
            self.offset = self.fh.tell()
            if len(chunk) > MAX_LINE:
                log.warning("[%s] over-long line skipped", self.source)
                continue
            lines.append(chunk.decode("utf-8", errors="replace"))
        if lines:
            return lines, False
        return [], self._maybe_switch()

    def _maybe_switch(self):
        """At EOF: move to the next file after rotation / truncation."""
        if self.backlog:
            path, _ = self.backlog
            self.backlog = None
            log.info("[%s] rotated file finished, back to %s", self.source, path)
            return self._open(path, 0)
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return False               # between rename and create
        if st.st_ino != self.inode:
            log.info("[%s] log rotated (new inode)", self.source)
            return self._open(self.path, 0)
        if st.st_size < self.offset:
            log.info("[%s] log truncated", self.source)
            return self._open(self.path, 0)
        return False


# ------------------------------------------------------------
# Postgres
# ------------------------------------------------------------
class Db:
    def __init__(self):
        self.conn = None
        self.next_connect = 0.0
        self.backoff = 1.0

    def connected(self):
        if self.conn is not None and not self.conn.closed:
            return True
        if time.monotonic() < self.next_connect:
            return False
        try:
            self.conn = psycopg2.connect(
                host=os.getenv("POSTGRES_HOST"),
                user=os.getenv("POSTGRES_USER"),
                password=os.getenv("POSTGRES_PASSWORD"),
                dbname=os.getenv("POSTGRES_DATABASE"),
                connect_timeout=5,
                application_name="sandbox_log_processor",
            )
            self.backoff = 1.0
            log.info("Connected to Postgres")
            return True
        except psycopg2.Error as e:
            self.conn = None
            self.next_connect = time.monotonic() + self.backoff
            log.warning("Postgres unavailable (%s), retry in %.0f s", str(e).strip(), self.backoff)
            self.backoff = min(self.backoff * 2, 60)
            return False

    def ping(self):
        """Cheap round trip; an idle connection does not notice a dead server otherwise."""
        try:
            with self.conn.cursor() as cur:
                cur.execute("SELECT 1")
            self.conn.commit()
            return True
        except psycopg2.Error as e:
            log.warning("Postgres ping failed (%s)", str(e).strip())
            self.drop()
            return False

    def drop(self):
        if self.conn:
            try:
                self.conn.close()
            except psycopg2.Error:
                pass
        self.conn = None
        self.next_connect = time.monotonic() + self.backoff

    def position(self, source):
        with self.conn.cursor() as cur:
            cur.execute("SELECT inode, file_offset FROM cyber_sentinel_sandbox.ingest_position(%s)", (source,))
            row = cur.fetchone()
        self.conn.commit()
        return (int(row[0]), int(row[1])) if row else None

    def store(self, source, rows, inode, offset):
        """One transaction: rows + position. Returns rows stored."""
        fn = "ingest_events" if source == "urls" else "ingest_dns"
        with self.conn.cursor() as cur:
            if rows:
                cur.execute(f"SELECT cyber_sentinel_sandbox.{fn}(%s, %s, %s)", (Json(rows), inode, offset))
                n = cur.fetchone()[0]
            else:
                cur.execute("SELECT cyber_sentinel_sandbox.ingest_skip(%s, %s, %s)", (source, inode, offset))
                n = 0
        self.conn.commit()
        return n


class Source:
    def __init__(self, name, path, shaper):
        self.name = name
        self.follower = Follower(name, path)
        self.shaper = shaper
        self.rows = []
        self.dirty = False            # position moved since the last store
        self.last_flush = time.monotonic()
        self.stored = 0
        self.skipped = 0
        self.waiting_logged = False


def flush(db, src):
    """Store buffered rows + position. False when the database is down
    (rows stay buffered, the file is not read further)."""
    src.last_flush = time.monotonic()
    if not src.dirty:
        return True
    if not db.connected():
        return False
    inode, offset = src.follower.position()
    try:
        src.stored += db.store(src.name, src.rows, inode, offset)
    except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
        log.warning("[%s] lost Postgres connection (%s); %d rows kept", src.name, str(e).strip(), len(src.rows))
        db.drop()
        return False
    except psycopg2.Error as e:
        # Some row the database rejects: store one by one, skip the bad ones.
        log.error("[%s] batch rejected (%s); retrying row by row", src.name, str(e).strip())
        db.conn.rollback()
        good = []
        for row in src.rows:
            try:
                db.store(src.name, [row], None, None)
                good.append(row)
            except (psycopg2.OperationalError, psycopg2.InterfaceError):
                db.drop()
                return False
            except psycopg2.Error as e2:
                db.conn.rollback()
                src.skipped += 1
                log.error("[%s] skipped record: %s", src.name, str(e2).strip())
        src.stored += len(good)
        db.store(src.name, [], inode, offset)
    src.rows = []
    src.dirty = False
    return True


def main():
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    stopping = {"flag": False}

    def on_signal(signum, _frame):
        log.info("Signal %s received, flushing and exiting", signum)
        stopping["flag"] = True

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    db = Db()
    sources = [Source("urls", URLS_LOG, url_record), Source("dns", DNS_LOG, DnsShaper())]
    last_stats = time.monotonic()
    last_beat = 0.0

    while not stopping["flag"]:
        busy = False
        for src in sources:
            f = src.follower
            if not f.started:
                if not db.connected():
                    continue
                try:
                    saved = db.position(src.name)
                except psycopg2.Error as e:
                    log.warning("[%s] cannot read position (%s)", src.name, str(e).strip())
                    db.drop()
                    continue
                if not f.start(saved):
                    if not src.waiting_logged:
                        log.warning("[%s] waiting for %s", src.name, f.path)
                        src.waiting_logged = True
                    continue
            if len(src.rows) >= BATCH_SIZE and not flush(db, src):
                continue                 # database down: stop reading until it is back
            lines, switched = f.read(BATCH_SIZE - len(src.rows))
            if lines:
                busy = True
                src.dirty = True
                for line in lines:
                    rec = src.shaper(line)
                    if rec:
                        src.rows.append(rec)
            if switched:
                busy = True
            if src.dirty and (len(src.rows) >= BATCH_SIZE or switched
                              or time.monotonic() - src.last_flush >= FLUSH_INTERVAL):
                flush(db, src)
        if time.monotonic() - last_beat >= HEARTBEAT_INTERVAL:
            if db.connected() and db.ping():
                heartbeat()
            last_beat = time.monotonic()
        if time.monotonic() - last_stats >= STATS_INTERVAL:
            for src in sources:
                log.info("[%s] stored %d, buffered %d, skipped %d", src.name, src.stored, len(src.rows), src.skipped)
            last_stats = time.monotonic()
        if not busy:
            time.sleep(POLL_INTERVAL)

    for src in sources:
        if src.follower.started and not flush(db, src):
            log.warning("[%s] exiting with %d unwritten rows (re-read on next start)", src.name, len(src.rows))
    db.drop()


if __name__ == "__main__":
    main()
