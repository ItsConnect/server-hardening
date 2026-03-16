#!/bin/bash
set -euo pipefail

# =============================================================================
# harden-mysql.sh — MySQL Hardening Script
# ITS Connect — https://itsconnect.com.br
#
# Secures a MySQL/MariaDB installation by binding to localhost, removing
# anonymous users, enforcing strong authentication, and tuning connections.
#
# Usage: sudo ./harden-mysql.sh
# =============================================================================

# ---- Configuration (edit these before running) ------------------------------

MYSQL_CONF="/etc/mysql/mysql.conf.d/mysqld.cnf"   # MySQL config file path
MAX_CONNECTIONS="${MAX_CONNECTIONS:-100}"            # Max simultaneous connections
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

# For MariaDB, the config path may differ:
# MYSQL_CONF="/etc/mysql/mariadb.conf.d/50-server.cnf"

# ---- Preflight checks ------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

if ! command -v mysql &>/dev/null; then
    echo "ERROR: mysql client not found. Is MySQL/MariaDB installed?" >&2
    exit 1
fi

# ---- Backup current configuration ------------------------------------------

echo "[1/5] Backing up current MySQL configuration..."
if [[ -f "$MYSQL_CONF" ]]; then
    cp "$MYSQL_CONF" "${MYSQL_CONF}${BACKUP_SUFFIX}"
    echo "      Backup saved to ${MYSQL_CONF}${BACKUP_SUFFIX}"
else
    echo "      WARNING: Config file $MYSQL_CONF not found. Will create it."
fi

# ---- Bind MySQL to 127.0.0.1 -----------------------------------------------
# By default, MySQL may listen on all interfaces (0.0.0.0), exposing the
# database to the network. Binding to 127.0.0.1 ensures only local
# connections are accepted, preventing remote exploitation.

echo "[2/5] Binding MySQL to 127.0.0.1 (localhost only)..."
if [[ -f "$MYSQL_CONF" ]]; then
    if grep -q '^bind-address' "$MYSQL_CONF"; then
        sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' "$MYSQL_CONF"
    elif grep -q '^\[mysqld\]' "$MYSQL_CONF"; then
        sed -i '/^\[mysqld\]/a bind-address = 127.0.0.1' "$MYSQL_CONF"
    else
        echo -e "\n[mysqld]\nbind-address = 127.0.0.1" >> "$MYSQL_CONF"
    fi
else
    mkdir -p "$(dirname "$MYSQL_CONF")"
    cat > "$MYSQL_CONF" <<INNEREOF
[mysqld]
bind-address = 127.0.0.1
INNEREOF
fi
echo "      MySQL bound to 127.0.0.1"

# ---- Remove anonymous users ------------------------------------------------
# Anonymous users allow anyone to connect to MySQL without credentials.
# They are created by default on some installations and pose a serious
# security risk, especially if combined with permissive grants.

echo "[3/5] Removing anonymous MySQL users..."
ANON_COUNT=$(mysql -N -e "SELECT COUNT(*) FROM mysql.user WHERE User='';" 2>/dev/null || echo "0")
if [[ "$ANON_COUNT" -gt 0 ]]; then
    mysql -e "DELETE FROM mysql.user WHERE User='';"
    mysql -e "FLUSH PRIVILEGES;"
    echo "      Removed $ANON_COUNT anonymous user(s)."
else
    echo "      No anonymous users found (already clean)."
fi

# ---- Enforce strong authentication plugin -----------------------------------
# The older mysql_native_password plugin uses SHA1 which is considered weak.
# caching_sha2_password (default in MySQL 8+) uses SHA-256 and is significantly
# more resistant to offline password cracking.

echo "[4/5] Setting default authentication plugin to caching_sha2_password..."
if grep -q '^default_authentication_plugin' "$MYSQL_CONF" 2>/dev/null; then
    sed -i 's/^default_authentication_plugin.*/default_authentication_plugin = caching_sha2_password/' "$MYSQL_CONF"
elif grep -q '^default-authentication-plugin' "$MYSQL_CONF" 2>/dev/null; then
    sed -i 's/^default-authentication-plugin.*/default-authentication-plugin = caching_sha2_password/' "$MYSQL_CONF"
else
    sed -i '/^\[mysqld\]/a default_authentication_plugin = caching_sha2_password' "$MYSQL_CONF"
fi
echo "      Default auth plugin set to caching_sha2_password"

# ---- Set max_connections ----------------------------------------------------
# Limiting connections prevents resource exhaustion from connection floods
# (intentional or accidental). The value should be tuned based on your
# server's RAM and expected workload.

echo "[5/5] Setting max_connections to ${MAX_CONNECTIONS}..."
if grep -q '^max_connections' "$MYSQL_CONF" 2>/dev/null; then
    sed -i "s/^max_connections.*/max_connections = ${MAX_CONNECTIONS}/" "$MYSQL_CONF"
else
    sed -i "/^\[mysqld\]/a max_connections = ${MAX_CONNECTIONS}" "$MYSQL_CONF"
fi
echo "      max_connections set to ${MAX_CONNECTIONS}"

# ---- Additional hardening ---------------------------------------------------

echo "      Applying additional hardening settings..."

# Disable LOCAL INFILE to prevent reading arbitrary server files via SQL
if ! grep -q '^local_infile' "$MYSQL_CONF" 2>/dev/null; then
    sed -i '/^\[mysqld\]/a local_infile = 0' "$MYSQL_CONF"
fi

# Enable slow query log for performance monitoring and anomaly detection
if ! grep -q '^slow_query_log' "$MYSQL_CONF" 2>/dev/null; then
    sed -i '/^\[mysqld\]/a slow_query_log = 1' "$MYSQL_CONF"
fi

# ---- Restart MySQL ----------------------------------------------------------

echo "      Restarting MySQL..."
systemctl restart mysql
echo "      MySQL restarted successfully."

# ---- Summary ----------------------------------------------------------------

echo ""
echo "============================================="
echo "  MySQL Hardening Complete"
echo "============================================="
echo "  Bind address:        127.0.0.1"
echo "  Anonymous users:     REMOVED"
echo "  Auth plugin:         caching_sha2_password"
echo "  Max connections:     ${MAX_CONNECTIONS}"
echo "  LOCAL INFILE:        DISABLED"
echo "  Slow query log:      ENABLED"
echo "============================================="
