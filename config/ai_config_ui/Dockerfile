# ============================================================
# Cyber Sentinel — AI config editor (web UI)
# ============================================================
# Small Flask app (gunicorn) behind nginx-proxy. Talks to postgres_db as
# the dedicated least-privilege role created by
# config/postgres/db_ai_config_editor.sql — never as postgres / n8n role.
# psycopg[binary] ships wheels for both amd64 and arm64 (RPi 5), so no
# compiler or libpq-dev is needed in the image.
# ============================================================

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app.py live_lookup.py ./
COPY templates/ templates/
COPY static/ static/

# Unprivileged runtime user (Trivy DS-0002).
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin aiui
USER 10001

EXPOSE 8000

# Shallow check only — DB outages show up in the UI, they must not make
# Docker restart-loop the container.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

# One worker: the login throttle is in-process; threads cover concurrency
# for a two-person admin UI.
CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:8000", \
     "--access-logfile", "-", "--forwarded-allow-ips", "*", "app:app"]
