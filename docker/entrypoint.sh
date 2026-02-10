#!/bin/bash
set -e

# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint: initialise MariaDB on first boot, then hand off to supervisord
# ─────────────────────────────────────────────────────────────────────────────

DB_DATA_DIR="/var/lib/mysql"
FIRST_RUN_FLAG="${DB_DATA_DIR}/.initialized"

# ── Write .env for FastAPI if not already present ─────────────────────────────
ENV_FILE="/app/backend/.env"
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<EOF
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=sbomuser
DB_PASSWORD=${DB_PASSWORD:-sbompassword}
DB_NAME=sbom_cve
NVD_API_KEY=${NVD_API_KEY:-}
EOF
  echo "[entrypoint] Created $ENV_FILE"
fi

# ── First-run DB bootstrap ────────────────────────────────────────────────────
if [ ! -f "$FIRST_RUN_FLAG" ]; then
  echo "[entrypoint] First run — initialising MariaDB..."

  # Initialise data directory
  mysql_install_db --user=mysql --datadir="$DB_DATA_DIR" > /dev/null 2>&1

  # Start MariaDB temporarily for setup
  mysqld_safe --user=mysql --skip-networking &
  MYSQL_PID=$!

  # Wait for MariaDB to be ready
  echo "[entrypoint] Waiting for MariaDB to start..."
  for i in $(seq 1 30); do
    if mysqladmin ping --socket=/run/mysqld/mysqld.sock --silent 2>/dev/null; then
      echo "[entrypoint] MariaDB is up."
      break
    fi
    sleep 1
  done

  APP_DB_PASSWORD="${DB_PASSWORD:-sbompassword}"

  # Bootstrap: secure installation + create app user + load schema
  mysql --socket=/run/mysqld/mysqld.sock -u root <<-EOSQL
    -- Secure root
    ALTER USER 'root'@'localhost' IDENTIFIED BY '';
    DELETE FROM mysql.user WHERE User='';
    DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
    DROP DATABASE IF EXISTS test;
    DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

    -- App database & user
    CREATE DATABASE IF NOT EXISTS sbom_cve
      CHARACTER SET utf8mb4
      COLLATE utf8mb4_unicode_ci;

    CREATE USER IF NOT EXISTS 'sbomuser'@'127.0.0.1'
      IDENTIFIED BY '${APP_DB_PASSWORD}';

    GRANT ALL PRIVILEGES ON sbom_cve.* TO 'sbomuser'@'127.0.0.1';
    FLUSH PRIVILEGES;
EOSQL

  # Load schema
  mysql --socket=/run/mysqld/mysqld.sock -u root sbom_cve < /app/docs/schema.sql
  echo "[entrypoint] Schema loaded."

  # Shut down the temp MariaDB process
  echo "[entrypoint] Shutting down temporary MariaDB..."
  mysqladmin --socket=/run/mysqld/mysqld.sock -u root shutdown 2>/dev/null || true
  
  # Wait up to 10 seconds for graceful shutdown
  for i in $(seq 1 10); do
    if ! kill -0 "$MYSQL_PID" 2>/dev/null; then
      echo "[entrypoint] MariaDB stopped gracefully."
      break
    fi
    sleep 1
  done
  
  # Force kill if still running
  if kill -0 "$MYSQL_PID" 2>/dev/null; then
    echo "[entrypoint] Force killing MariaDB..."
    kill -9 "$MYSQL_PID" 2>/dev/null || true
    wait "$MYSQL_PID" 2>/dev/null || true
  fi

  # Clean up runtime files to prevent conflicts
  echo "[entrypoint] Cleaning up temporary MariaDB runtime files..."
  rm -f /run/mysqld/mysqld.sock /run/mysqld/mysqld.pid /var/run/mysqld/mysqld.sock /var/run/mysqld/mysqld.pid
  
  touch "$FIRST_RUN_FLAG"
  echo "[entrypoint] First-run initialisation complete."
else
  echo "[entrypoint] Database already initialised — skipping bootstrap."
fi

# ── Hand off to supervisord ───────────────────────────────────────────────────
echo "[entrypoint] Starting services via supervisord..."
exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf
