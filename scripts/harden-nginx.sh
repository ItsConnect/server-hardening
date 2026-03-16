#!/bin/bash
set -euo pipefail

# =============================================================================
# harden-nginx.sh — Nginx Security Hardening Script
# ITS Connect — https://itsconnect.com.br
#
# Adds security headers, disables server tokens, and configures strong SSL/TLS
# settings for Nginx. Creates reusable security snippets that can be included
# in all server blocks.
#
# Usage: sudo ./harden-nginx.sh
# =============================================================================

# ---- Configuration ----------------------------------------------------------

NGINX_CONF="/etc/nginx/nginx.conf"
SECURITY_SNIPPET="/etc/nginx/snippets/security-headers.conf"
SSL_SNIPPET="/etc/nginx/snippets/ssl-hardened.conf"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

# ---- Preflight checks ------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

if ! command -v nginx &>/dev/null; then
    echo "ERROR: Nginx is not installed." >&2
    exit 1
fi

# ---- Backup current configuration ------------------------------------------

echo "[1/5] Backing up current Nginx configuration..."
cp "$NGINX_CONF" "${NGINX_CONF}${BACKUP_SUFFIX}"
echo "      Backup saved to ${NGINX_CONF}${BACKUP_SUFFIX}"

# ---- Disable server_tokens --------------------------------------------------
# server_tokens exposes the Nginx version in response headers and error pages.
# Attackers use this to identify version-specific vulnerabilities. Disabling it
# removes the version from the "Server" header (shows "nginx" only).

echo "[2/5] Disabling server_tokens in nginx.conf..."
if grep -q '^\s*server_tokens' "$NGINX_CONF"; then
    sed -i 's/^\(\s*\)server_tokens.*/\1server_tokens off;/' "$NGINX_CONF"
elif grep -q '^\s*#\s*server_tokens' "$NGINX_CONF"; then
    sed -i 's/^\(\s*\)#\s*server_tokens.*/\1server_tokens off;/' "$NGINX_CONF"
else
    # Insert after the http { line
    sed -i '/http\s*{/a \    server_tokens off;' "$NGINX_CONF"
fi
echo "      server_tokens off"

# ---- Create security headers snippet ----------------------------------------
# These headers instruct browsers to enable security features. They are a
# critical defense-in-depth layer against XSS, clickjacking, MIME sniffing,
# and other client-side attacks.

echo "[3/5] Creating security headers snippet..."
mkdir -p /etc/nginx/snippets

cat > "$SECURITY_SNIPPET" <<'HEADERSEOF'
# =============================================================================
# Security Headers — ITS Connect
# Include this in your server blocks: include snippets/security-headers.conf;
# =============================================================================

# HSTS (HTTP Strict Transport Security)
# Forces browsers to use HTTPS for all future requests to this domain.
# max-age=31536000 = 1 year. includeSubDomains covers all subdomains.
# WARNING: Only enable after confirming HTTPS works correctly everywhere.
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# X-Frame-Options
# Prevents the site from being embedded in iframes on other domains,
# mitigating clickjacking attacks.
add_header X-Frame-Options "SAMEORIGIN" always;

# X-Content-Type-Options
# Prevents browsers from MIME-sniffing the content type, which can lead
# to XSS attacks via uploaded files (e.g., an HTML file served as image).
add_header X-Content-Type-Options "nosniff" always;

# Referrer-Policy
# Controls how much referrer information is sent with requests.
# "strict-origin-when-cross-origin" sends the origin for cross-origin
# requests but the full URL for same-origin requests.
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Permissions-Policy (replaces Feature-Policy)
# Restricts which browser features the site can use. Disabling unused
# features reduces the attack surface.
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

# X-XSS-Protection
# Legacy header for older browsers that don't support CSP.
# mode=block tells the browser to block the page rather than filter.
add_header X-XSS-Protection "1; mode=block" always;
HEADERSEOF

echo "      Created $SECURITY_SNIPPET"

# ---- Create SSL hardening snippet -------------------------------------------
# Configures TLS to only use secure protocol versions and cipher suites.
# TLS 1.0 and 1.1 have known vulnerabilities and are deprecated by all
# major browsers as of 2020.

echo "[4/5] Creating SSL hardening snippet..."

cat > "$SSL_SNIPPET" <<'SSLEOF'
# =============================================================================
# SSL/TLS Hardened Configuration — ITS Connect
# Include this in your HTTPS server blocks: include snippets/ssl-hardened.conf;
# =============================================================================

# Only allow TLS 1.2 and 1.3 — older versions have known vulnerabilities
# TLS 1.0: BEAST, POODLE  |  TLS 1.1: Deprecated, weak ciphers
ssl_protocols TLSv1.2 TLSv1.3;

# Use server's cipher preference order (not the client's)
# This ensures the strongest available cipher is always selected.
ssl_prefer_server_ciphers on;

# Strong cipher suite — ordered by preference
# Includes only AEAD ciphers (AES-GCM, ChaCha20) which provide both
# encryption and integrity in a single operation.
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

# ECDH curve for key exchange — X25519 is fastest, P-256 for compatibility
ssl_ecdh_curve X25519:secp384r1:secp256r1;

# SSL session settings — reduces handshake overhead for returning visitors
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# OCSP Stapling — server fetches certificate revocation status and sends it
# to clients, improving TLS handshake speed and privacy.
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;
SSLEOF

echo "      Created $SSL_SNIPPET"

# ---- Validate and reload Nginx ----------------------------------------------

echo "[5/5] Validating Nginx configuration..."
nginx -t
echo "      Configuration syntax is valid."

systemctl reload nginx
echo "      Nginx reloaded successfully."

# ---- Summary ----------------------------------------------------------------

echo ""
echo "============================================="
echo "  Nginx Hardening Complete"
echo "============================================="
echo "  server_tokens:       OFF"
echo "  Security headers:    $SECURITY_SNIPPET"
echo "  SSL hardening:       $SSL_SNIPPET"
echo "  TLS versions:        1.2, 1.3 only"
echo "  Ciphers:             AEAD only (AES-GCM, ChaCha20)"
echo "  OCSP Stapling:       ENABLED"
echo "============================================="
echo ""
echo "Add these lines to your server blocks:"
echo "  include snippets/security-headers.conf;"
echo "  include snippets/ssl-hardened.conf;"
