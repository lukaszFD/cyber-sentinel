"""
dns_log_processor — Pi-hole query log -> cyber_sentinel.dns_queries

Follows Pi-hole's dnsmasq log (/var/log/pihole/pihole.log, mounted read-only)
and writes one row per query and per answer:

    query_type  source of the row                     source_ip   response_ip
    ----------  ------------------------------------  ----------  -----------
    query       query[A] example.com from <client>    client      NULL
    reply       answer from upstream (Unbound)        client      answer
    cached      answer from Pi-hole's cache           client      answer
    blocked     answer from gravity / denylist        client      answer (0.0.0.0, NXDOMAIN ...)

Pi-hole must log with misc.extraLogging = true (playbook 04.6): every line
then carries the query id and the client, so answers are attributed to the
device that asked. Without it answers fall back to source_ip 'N/A'.

Answer lines carry no record type; it is taken from the matching query line,
or inferred from the answer when the query was not seen.

Queries Pi-hole makes itself (client 127.0.0.1 / ::1: the container
healthcheck asking for pi.hole every 30 s, reverse lookups of client names)
are skipped — they say nothing about the network. SKIP_CLIENTS overrides
the list.

Robustness:
  * the log is reopened after rotation (inode change) or truncation
    (logrotate copytruncate),
  * rows are buffered and inserted in batches (BATCH_SIZE rows or every
    FLUSH_INTERVAL seconds, whichever comes first),
  * a lost Postgres connection is re-established with backoff; buffered rows
    are kept (up to MAX_BUFFER) and written once the database is back,
  * SIGTERM / SIGINT flush the buffer before exit.

Reading starts at the end of the file, like `tail -f`: lines written while
the processor was down are not imported.

Timestamps are the time the line was read, in the container's time zone
(UTC), the same convention the pipeline's views use (LOCALTIMESTAMP).

Configuration (environment, all optional except the POSTGRES_* ones):
    POSTGRES_HOST, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DATABASE
    DNS_LOG_PATH      default /var/log/pihole/pihole.log
    BATCH_SIZE        default 200
    FLUSH_INTERVAL    default 2 (seconds)
    MAX_BUFFER        default 50000 rows
    SKIP_CLIENTS      default 127.0.0.1,::1 (comma-separated, empty = keep all)
    LOG_LEVEL         default INFO
"""

import logging
import os
import re
import signal
import sys
import time
from collections import OrderedDict
from datetime import datetime

import psycopg2
from psycopg2.extras import execute_values

LOG_PATH = os.getenv("DNS_LOG_PATH", "/var/log/pihole/pihole.log")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "200"))
FLUSH_INTERVAL = float(os.getenv("FLUSH_INTERVAL", "2"))
MAX_BUFFER = int(os.getenv("MAX_BUFFER", "50000"))
POLL_INTERVAL = 0.5
STATS_INTERVAL = 300
QUERY_CACHE_SIZE = 20000
SKIP_CLIENTS = frozenset(c.strip() for c in os.getenv("SKIP_CLIENTS", "127.0.0.1,::1").split(",") if c.strip())

log = logging.getLogger("dns_log_processor")

# ------------------------------------------------------------
# Parsing
# ------------------------------------------------------------
# Pi-hole v6 (FTL) with extraLogging:
# "Nov 17 10:00:01 dnsmasq[193]: UDP 4711 192.168.0.10/53123 query[A] example.com from 192.168.0.10"
# "Nov 17 10:00:01 dnsmasq[193]: UDP 4711 192.168.0.10/53123 reply example.com is 93.184.216.34"
# Plain dnsmasq log-queries=extra has no protocol word; without extraLogging
# the whole "[<proto>] <id> <client>/<port> " part is missing.
LINE_RE = re.compile(
    r"\]:\s+"                                              # end of "dnsmasq[193]:"
    r"(?:(?:[A-Z]{2,5}\s+)?(?P<qid>\d+)\s+(?P<client>[0-9A-Fa-f.:]+)/\d+\s+)?"
    r"(?P<msg>.+?)\s*$"
)
QUERY_RE = re.compile(r"^query\[(?P<rtype>[^\]]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<client>\S+)$")
ANSWER_RE = re.compile(r"^(?P<action>.+?)\s+(?P<domain>\S+)\s+is\s+(?P<value>\S+)$")

# Column sizes of cyber_sentinel.dns_queries
QT_LEN, RT_LEN, IP_LEN = 10, 10, 45


def classify_answer(action):
    """Map the dnsmasq/FTL action word(s) to query_type, or None to skip."""
    if action == "reply":
        return "reply"
    if action.startswith("cached"):              # cached, cached-stale
        return "cached"
    if "blocked" in action or "denied" in action or "blacklisted" in action:
        return "blocked"                         # gravity blocked, exactly denied, regex denied ...
    return None                                  # config, /etc/hosts, special domain, DHCP ...


def infer_record_type(value):
    if value == "NXDOMAIN":
        return "N/A"
    if ":" in value:
        return "AAAA"
    if "." in value and not value.startswith("<"):
        return "A"
    return "OTHER"


class Parser:
    """Turns log lines into dns_queries rows; remembers query id -> client."""

    def __init__(self):
        self.queries = OrderedDict()             # qid -> (client, record_type)

    def remember(self, qid, client, rtype):
        self.queries[qid] = (client, rtype)
        self.queries.move_to_end(qid)
        while len(self.queries) > QUERY_CACHE_SIZE:
            self.queries.popitem(last=False)

    def parse(self, line):
        m = LINE_RE.search(line)
        if not m:
            return None
        qid, msg = m.group("qid"), m.group("msg")
        now = datetime.now()

        q = QUERY_RE.match(msg)
        if q:
            client = q.group("client")
            rtype = q.group("rtype")
            if qid:
                self.remember(qid, client, rtype)
            if client in SKIP_CLIENTS:
                return None
            return (now, "query", rtype[:RT_LEN], q.group("domain"), client[:IP_LEN], None)

        a = ANSWER_RE.match(msg)
        if not a:
            return None
        qtype = classify_answer(a.group("action"))
        if not qtype:
            return None
        value = a.group("value")
        client, rtype = self.queries.get(qid, (None, None)) if qid else (None, None)
        if not client:
            client = m.group("client") or "N/A"
        if client in SKIP_CLIENTS:
            return None
        if not rtype:
            rtype = infer_record_type(value)
        return (now, qtype, rtype[:RT_LEN], a.group("domain"), client[:IP_LEN], value[:IP_LEN])


# ------------------------------------------------------------
# Following the log across rotation
# ------------------------------------------------------------
class LogFollower:
    """tail -F: yields complete lines, or None when there is nothing new."""

    def __init__(self, path):
        self.path = path
        self.fh = None
        self.inode = None
        self.partial = ""

    def _open(self, at_end):
        try:
            fh = open(self.path, "r", encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return False
        if self.fh:
            self.fh.close()
        self.fh = fh
        self.inode = os.fstat(fh.fileno()).st_ino
        self.partial = ""
        if at_end:
            fh.seek(0, os.SEEK_END)
        log.info("Following %s (inode %s, from %s)", self.path, self.inode, "end" if at_end else "start")
        return True

    def _rotated(self):
        """Reopen when the file was replaced or truncated. Returns True if reopened."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return False                         # between rename and create; try later
        if st.st_ino != self.inode:
            log.info("Log rotated (new inode)")
            return self._open(at_end=False)
        if st.st_size < self.fh.tell():
            log.info("Log truncated")
            self.fh.seek(0)
            self.partial = ""
            return True
        return False

    def lines(self, stop):
        while not stop() and not self._open(at_end=True):
            log.warning("Waiting for %s", self.path)
            yield None
            time.sleep(5)
        while not stop():
            chunk = self.fh.readline()
            if chunk:
                if chunk.endswith("\n"):
                    yield self.partial + chunk
                    self.partial = ""
                else:
                    self.partial += chunk        # writer has not finished the line yet
                continue
            # EOF: whatever was left in the old file has been read
            if not self._rotated():
                yield None
                time.sleep(POLL_INTERVAL)


# ------------------------------------------------------------
# Postgres
# ------------------------------------------------------------
INSERT_SQL = """
    INSERT INTO cyber_sentinel.dns_queries
        (timestamp, query_type, record_type, domain, source_ip, response_ip)
    VALUES %s
"""


class Writer:
    def __init__(self):
        self.conn = None
        self.buffer = []
        self.last_flush = time.monotonic()
        self.next_connect = 0.0
        self.backoff = 1.0
        self.inserted = 0
        self.dropped = 0

    def _connect(self):
        if time.monotonic() < self.next_connect:
            return False
        try:
            self.conn = psycopg2.connect(
                host=os.getenv("POSTGRES_HOST"),
                user=os.getenv("POSTGRES_USER"),
                password=os.getenv("POSTGRES_PASSWORD"),
                dbname=os.getenv("POSTGRES_DATABASE"),
                connect_timeout=5,
                application_name="dns_log_processor",
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

    def _disconnect(self):
        if self.conn:
            try:
                self.conn.close()
            except psycopg2.Error:
                pass
        self.conn = None

    def add(self, row):
        self.buffer.append(row)
        if len(self.buffer) > MAX_BUFFER:
            excess = len(self.buffer) - MAX_BUFFER
            del self.buffer[:excess]
            self.dropped += excess
            if self.dropped % 1000 < excess:
                log.error("Buffer full, %d oldest rows dropped so far", self.dropped)

    def due(self):
        return self.buffer and (
            len(self.buffer) >= BATCH_SIZE or time.monotonic() - self.last_flush >= FLUSH_INTERVAL
        )

    def flush(self):
        self.last_flush = time.monotonic()
        if not self.buffer:
            return
        if self.conn is None or self.conn.closed:
            if not self._connect():
                return
        batch = self.buffer
        try:
            with self.conn.cursor() as cur:
                execute_values(cur, INSERT_SQL, batch, page_size=500)
            self.conn.commit()
            self.inserted += len(batch)
            self.buffer = []
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            log.warning("Lost Postgres connection (%s); %d rows kept for retry", str(e).strip(), len(batch))
            self._disconnect()
            self.next_connect = time.monotonic() + self.backoff
        except psycopg2.Error as e:
            # Data problem in some row: insert one by one, skip the bad ones.
            log.error("Batch insert failed (%s); retrying row by row", str(e).strip())
            self.conn.rollback()
            self._insert_rows_individually(batch)

    def _insert_rows_individually(self, batch):
        ok = 0
        for i, row in enumerate(batch):
            try:
                with self.conn.cursor() as cur:
                    execute_values(cur, INSERT_SQL, [row])
                self.conn.commit()
                ok += 1
            except (psycopg2.OperationalError, psycopg2.InterfaceError):
                self.buffer = batch[i:]          # keep the rest for after reconnect
                self.inserted += ok
                self._disconnect()
                return
            except psycopg2.Error as e:
                self.conn.rollback()
                log.error("Skipped row %r: %s", row, str(e).strip())
        self.inserted += ok
        self.buffer = []

    def close(self):
        self.flush()
        if self.buffer:
            log.warning("Exiting with %d unwritten rows", len(self.buffer))
        self._disconnect()


# ------------------------------------------------------------
# Main loop
# ------------------------------------------------------------
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

    parser = Parser()
    writer = Writer()
    follower = LogFollower(LOG_PATH)
    seen = 0
    last_stats = time.monotonic()

    for line in follower.lines(lambda: stopping["flag"]):
        if line is not None:
            row = parser.parse(line)
            if row:
                writer.add(row)
                seen += 1
                log.debug("%s %s %s %s -> %s", row[1], row[2], row[3], row[4], row[5])
        if writer.due():
            writer.flush()
        if time.monotonic() - last_stats >= STATS_INTERVAL:
            log.info("Rows parsed %d, inserted %d, buffered %d, dropped %d",
                     seen, writer.inserted, len(writer.buffer), writer.dropped)
            last_stats = time.monotonic()

    writer.close()


if __name__ == "__main__":
    main()
