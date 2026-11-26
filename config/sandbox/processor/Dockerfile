# ============================================================
# Cyber Sentinel — sandbox_log_processor
# ============================================================
# Follows the browser sandbox logs (mitmproxy urls.jsonl and the sandbox
# Pi-hole query log, both read-only) and stores them in
# cyber_sentinel_sandbox through the ingest functions of db_sandbox.sql.
# Reuses the Pi-hole line parser of dns_log_processor (log_processor.py,
# copied next to this file by playbook 04.1).
# Base image digest for reference: cs_base_images.sandbox_log_processor
# in ansible/group_vars/all/images.yml.
# ============================================================
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir psycopg2-binary==2.9.10 \
 && useradd --system --uid 10001 --no-create-home sandbox

COPY log_processor.py sandbox_log_processor.py ./

# Default non-root user; compose runs it as 1000:1000 so it can read the
# sandbox Pi-hole's log (owned by the pihole user, mode 0640).
USER 10001

# Healthy while the main loop runs and Postgres answers: the processor touches
# the heartbeat file every 15 s (a tmpfs in compose; the root fs is read-only).
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=2 \
  CMD ["python", "-c", "import os,sys,time; p=os.getenv('HEARTBEAT_FILE','/run/heartbeat/alive'); sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p) < 60 else 1)"]

CMD ["python", "sandbox_log_processor.py"]
