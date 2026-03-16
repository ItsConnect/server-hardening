#!/bin/bash
set -euo pipefail

# =============================================================================
# harden-php.sh — PHP Hardening Script
# ITS Connect — https://itsconnect.com.br
#
# Hardens PHP-FPM configurations by disabling dangerous functions, setting
# open_basedir restrictions, hiding version info, and limiting uploads.
#
# Usage: sudo ./harden-php.sh
# =============================================================================

# ---- Configuration (edit these before running) ------------------------------

# PHP versions to harden (space-separated). Adjust to match installed versions.
PHP_VERSIONS="${PHP_VERSIONS:-8.2 8.3 8.4}"

# Upload limits — adjust based on your hosting requirements
UPLOAD_MAX_FILESIZE="${UPLOAD_MAX_FILESIZE:-64M}"
POST_MAX_SIZE="${POST_MAX_SIZE:-64M}"

# Functions to disable — these allow arbitrary command execution from PHP.
# Remove functions from this list only if your application strictly requires them.
DISABLE_FUNCTIONS="exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec,parse_ini_file,show_source,proc_close,proc_get_status,proc_nice,proc_terminate"

# ---- Preflight checks ------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

# ---- Process each PHP version -----------------------------------------------

for PHP_VER in $PHP_VERSIONS; do
    PHP_INI="/etc/php/${PHP_VER}/fpm/php.ini"
    BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

    echo ""
    echo "========================================"
    echo "  Hardening PHP ${PHP_VER}"
    echo "========================================"

    if [[ ! -f "$PHP_INI" ]]; then
        echo "  SKIP: $PHP_INI not found (PHP ${PHP_VER} FPM not installed)"
        continue
    fi

    # ---- Backup current configuration ----------------------------------------

    echo "[1/5] Backing up ${PHP_INI}..."
    cp "$PHP_INI" "${PHP_INI}${BACKUP_SUFFIX}"

    # ---- Disable dangerous functions -----------------------------------------
    # These functions allow PHP scripts to execute arbitrary system commands.
    # In a shared hosting environment, a compromised site could use these to
    # escalate privileges, install backdoors, or pivot to other sites.

    echo "[2/5] Disabling dangerous functions..."
    if grep -q '^disable_functions' "$PHP_INI"; then
        sed -i "s/^disable_functions.*/disable_functions = ${DISABLE_FUNCTIONS}/" "$PHP_INI"
    else
        echo "disable_functions = ${DISABLE_FUNCTIONS}" >> "$PHP_INI"
    fi
    echo "      Disabled: exec, passthru, shell_exec, system, proc_open, popen, ..."

    # ---- Set open_basedir per site -------------------------------------------
    # open_basedir restricts which directories PHP can access. This prevents
    # a compromised site from reading files belonging to other sites or the
    # system. In FPM pool configs, this is typically set per-pool, but we
    # set a safe default in php.ini as a fallback.
    #
    # For per-site isolation, configure open_basedir in each FPM pool:
    #   php_admin_value[open_basedir] = /home/username/htdocs:/tmp

    echo "[3/5] Setting open_basedir default..."
    if grep -q '^open_basedir' "$PHP_INI"; then
        sed -i 's|^open_basedir.*|open_basedir = /home:/tmp:/usr/share/php|' "$PHP_INI"
    elif grep -q '^;open_basedir' "$PHP_INI"; then
        sed -i 's|^;open_basedir.*|open_basedir = /home:/tmp:/usr/share/php|' "$PHP_INI"
    else
        echo "open_basedir = /home:/tmp:/usr/share/php" >> "$PHP_INI"
    fi
    echo "      open_basedir = /home:/tmp:/usr/share/php"

    # ---- Disable expose_php --------------------------------------------------
    # When enabled, PHP adds an X-Powered-By header to all responses revealing
    # the exact PHP version. Attackers use this for fingerprinting to find
    # version-specific exploits. There is no benefit to exposing it.

    echo "[4/5] Disabling expose_php..."
    sed -i 's/^expose_php.*/expose_php = Off/' "$PHP_INI"
    echo "      expose_php = Off"

    # ---- Set upload limits ---------------------------------------------------
    # Limiting upload sizes prevents abuse (large file uploads consuming disk
    # and bandwidth) and reduces the risk of denial-of-service via oversized
    # POST requests. Adjust based on your clients' needs.

    echo "[5/5] Setting upload limits..."
    sed -i "s/^upload_max_filesize.*/upload_max_filesize = ${UPLOAD_MAX_FILESIZE}/" "$PHP_INI"
    sed -i "s/^post_max_size.*/post_max_size = ${POST_MAX_SIZE}/" "$PHP_INI"
    echo "      upload_max_filesize = ${UPLOAD_MAX_FILESIZE}"
    echo "      post_max_size = ${POST_MAX_SIZE}"

    # ---- Additional hardening ------------------------------------------------

    # Disable allow_url_include — prevents remote file inclusion attacks
    sed -i 's/^allow_url_include.*/allow_url_include = Off/' "$PHP_INI"

    # Set session cookie flags for security
    sed -i 's/^session.cookie_httponly.*/session.cookie_httponly = 1/' "$PHP_INI"
    sed -i 's/^session.cookie_secure.*/session.cookie_secure = 1/' "$PHP_INI"
    sed -i 's/^session.use_strict_mode.*/session.use_strict_mode = 1/' "$PHP_INI"

    # ---- Restart PHP-FPM for this version ------------------------------------

    FPM_SERVICE="php${PHP_VER}-fpm"
    if systemctl is-active --quiet "$FPM_SERVICE" 2>/dev/null; then
        echo "      Restarting ${FPM_SERVICE}..."
        systemctl restart "$FPM_SERVICE"
        echo "      ${FPM_SERVICE} restarted."
    else
        echo "      WARNING: ${FPM_SERVICE} is not running. Skipping restart."
    fi
done

# ---- Summary ----------------------------------------------------------------

echo ""
echo "============================================="
echo "  PHP Hardening Complete"
echo "============================================="
echo "  Versions hardened:   ${PHP_VERSIONS}"
echo "  Dangerous functions: DISABLED"
echo "  open_basedir:        /home:/tmp:/usr/share/php"
echo "  expose_php:          OFF"
echo "  Upload limit:        ${UPLOAD_MAX_FILESIZE}"
echo "  allow_url_include:   OFF"
echo "  Session cookies:     httponly, secure, strict mode"
echo "============================================="
echo ""
echo "NOTE: For per-site isolation, configure open_basedir in each"
echo "FPM pool file: php_admin_value[open_basedir] = /home/USER/htdocs:/tmp"
