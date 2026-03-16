#!/bin/bash
set -euo pipefail

# =============================================================================
# harden-ssh.sh — SSH Hardening Script
# ITS Connect — https://itsconnect.com.br
#
# Hardens the OpenSSH server configuration by disabling insecure defaults
# and enforcing key-based authentication on a non-standard port.
#
# Usage: sudo ./harden-ssh.sh
# =============================================================================

# ---- Configuration (edit these before running) ------------------------------

SSH_PORT="${SSH_PORT:-19530}"          # Custom SSH port (change from default 22)
SSHD_CONFIG="/etc/ssh/sshd_config"    # Path to sshd configuration file
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

# ---- Preflight checks ------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "ERROR: SSH config file not found at $SSHD_CONFIG" >&2
    exit 1
fi

# ---- Backup current configuration ------------------------------------------

echo "[1/6] Backing up current SSH configuration..."
cp "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
echo "      Backup saved to ${SSHD_CONFIG}${BACKUP_SUFFIX}"

# ---- Disable root login ----------------------------------------------------
# Root login via SSH is one of the most common attack vectors. Disabling it
# forces attackers to guess both a username and a password/key.

echo "[2/6] Disabling root login..."
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"

# ---- Disable password authentication ---------------------------------------
# Password auth is vulnerable to brute-force attacks. Key-based auth is
# cryptographically stronger and not susceptible to dictionary attacks.
# IMPORTANT: Ensure you have a working SSH key configured before enabling this.

echo "[3/6] Disabling password authentication..."
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSHD_CONFIG"

# ---- Set MaxAuthTries -------------------------------------------------------
# Limits the number of authentication attempts per connection. This slows down
# brute-force attacks by disconnecting after 3 failed attempts.

echo "[4/6] Setting MaxAuthTries to 3..."
if grep -q '^#\?MaxAuthTries' "$SSHD_CONFIG"; then
    sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' "$SSHD_CONFIG"
else
    echo "MaxAuthTries 3" >> "$SSHD_CONFIG"
fi

# ---- Change the default SSH port -------------------------------------------
# Moving SSH off port 22 eliminates the vast majority of automated scanning
# and brute-force bots that target the default port.

echo "[5/6] Changing SSH port to ${SSH_PORT}..."
if grep -q '^#\?Port ' "$SSHD_CONFIG"; then
    sed -i "s/^#\?Port .*/Port ${SSH_PORT}/" "$SSHD_CONFIG"
else
    echo "Port ${SSH_PORT}" >> "$SSHD_CONFIG"
fi

# ---- Additional hardening options -------------------------------------------
# Disable empty passwords (defense in depth, even with password auth disabled)
# Disable X11 forwarding (reduces attack surface)
# Set login grace time to 30 seconds (limits idle unauthenticated connections)

echo "      Applying additional hardening options..."
sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONFIG"
sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' "$SSHD_CONFIG"

if grep -q '^#\?LoginGraceTime' "$SSHD_CONFIG"; then
    sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 30/' "$SSHD_CONFIG"
else
    echo "LoginGraceTime 30" >> "$SSHD_CONFIG"
fi

# ---- Validate and restart sshd ---------------------------------------------

echo "[6/6] Validating configuration and restarting sshd..."
sshd -t -f "$SSHD_CONFIG"
echo "      Configuration syntax is valid."

systemctl restart sshd
echo "      sshd restarted successfully."

# ---- Summary ----------------------------------------------------------------

echo ""
echo "============================================="
echo "  SSH Hardening Complete"
echo "============================================="
echo "  Port:                ${SSH_PORT}"
echo "  Root login:          DISABLED"
echo "  Password auth:       DISABLED"
echo "  MaxAuthTries:        3"
echo "  X11 Forwarding:      DISABLED"
echo "  Login Grace Time:    30s"
echo "============================================="
echo ""
echo "IMPORTANT: Make sure you can connect on port ${SSH_PORT}"
echo "with your SSH key before closing this session!"
