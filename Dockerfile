# ─────────────────────────────────────────────────────────────────────────────
# SBOM CVE Scanner — Self-Contained Docker Image
# Includes: MariaDB + FastAPI + supervisord (single container)
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm

# ── System packages ──────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    mariadb-server \
    mariadb-client \
    supervisor \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ───────────────────────────────────────────────────────
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ── App code ─────────────────────────────────────────────────────────────────
WORKDIR /app
COPY backend/   ./backend/
COPY frontend/  ./frontend/
COPY docs/      ./docs/

# ── DB init script ────────────────────────────────────────────────────────────
COPY docker/init-db.sh        /docker-entrypoint-initdb.d/init-db.sh
RUN chmod +x /docker-entrypoint-initdb.d/init-db.sh

# ── supervisord config ────────────────────────────────────────────────────────
COPY docker/supervisord.conf  /etc/supervisor/conf.d/supervisord.conf

# ── Entrypoint ────────────────────────────────────────────────────────────────
COPY docker/entrypoint.sh     /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── Data volume (persist MariaDB data across restarts) ────────────────────────
VOLUME ["/var/lib/mysql"]

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
