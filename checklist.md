# Server Hardening Checklist

A comprehensive 20-item checklist for hardening Ubuntu/Debian production servers. Each item includes a description, severity rating, verification command, and remediation steps.

---

## Severity Legend

| Level | Description |
|-------|-------------|
| **Critical** | Immediate risk of compromise if not addressed |
| **High** | Significant security weakness, should be fixed promptly |
| **Medium** | Reduces attack surface, recommended best practice |
| **Low** | Defense-in-depth measure, nice to have |

---

## 1. Disable SSH Root Login

**Severity:** Critical

**Why:** Direct root login via SSH means an attacker only needs to guess one password to gain full system control. Disabling it forces the use of a regular user account plus privilege escalation, adding an extra layer of defense.

**Check:**
```bash
grep -E '^PermitRootLogin' /etc/ssh/sshd_config
# Expected: PermitRootLogin no
```

**Fix:**
```bash
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd
```

---

## 2. Disable SSH Password Authentication

**Severity:** Critical

**Why:** Passwords are vulnerable to brute-force and dictionary attacks. SSH keys use cryptographic key pairs that are virtually impossible to brute-force.

**Check:**
```bash
grep -E '^PasswordAuthentication' /etc/ssh/sshd_config
# Expected: PasswordAuthentication no
```

**Fix:**
```bash
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd
```

> **Prerequisite:** Ensure at least one SSH key is configured before disabling password auth.

---

## 3. Change SSH Default Port

**Severity:** High

**Why:** Port 22 is targeted by millions of automated bots daily. Changing it eliminates >99% of automated scan traffic, though it is not a substitute for proper authentication controls.

**Check:**
```bash
grep -E '^Port' /etc/ssh/sshd_config
# Expected: Port <non-22-number>
```

**Fix:**
```bash
sed -i 's/^#\?Port .*/Port 19530/' /etc/ssh/sshd_config
ufw allow 19530/tcp
systemctl restart sshd
```

---

## 4. Set SSH MaxAuthTries

**Severity:** Medium

**Why:** Limits the number of authentication attempts per connection, slowing down brute-force attacks.

**Check:**
```bash
grep -E '^MaxAuthTries' /etc/ssh/sshd_config
# Expected: MaxAuthTries 3
```

**Fix:**
```bash
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
systemctl restart sshd
```

---

## 5. Enable Firewall with Default Deny

**Severity:** Critical

**Why:** Without a firewall, all listening services are exposed to the internet. A default-deny policy ensures only explicitly allowed traffic reaches the server.

**Check:**
```bash
ufw status verbose
# Expected: Status: active, Default: deny (incoming), allow (outgoing)
```

**Fix:**
```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow <ssh-port>/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
```

---

## 6. Install and Configure Fail2Ban

**Severity:** High

**Why:** Fail2Ban monitors log files for repeated failed authentication attempts and temporarily bans offending IPs. It provides real-time protection against brute-force attacks.

**Check:**
```bash
fail2ban-client status
# Expected: list of active jails (sshd, nginx-http-auth, etc.)
```

**Fix:**
```bash
apt-get install -y fail2ban
# Configure /etc/fail2ban/jail.local (see scripts/setup-firewall.sh)
systemctl enable --now fail2ban
```

---

## 7. Bind MySQL to 127.0.0.1

**Severity:** Critical

**Why:** MySQL listening on 0.0.0.0 exposes the database to the network. Remote attackers can attempt to connect directly, bypassing web application security entirely.

**Check:**
```bash
grep -E '^bind-address' /etc/mysql/mysql.conf.d/mysqld.cnf
# Expected: bind-address = 127.0.0.1
ss -tlnp | grep 3306
# Expected: 127.0.0.1:3306
```

**Fix:**
```bash
sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf
systemctl restart mysql
```

---

## 8. Remove MySQL Anonymous Users

**Severity:** High

**Why:** Anonymous users allow unauthenticated access to MySQL. Even with limited privileges, they can be used to probe database structure and escalate access.

**Check:**
```bash
mysql -e "SELECT User, Host FROM mysql.user WHERE User='';"
# Expected: Empty set
```

**Fix:**
```bash
mysql -e "DELETE FROM mysql.user WHERE User=''; FLUSH PRIVILEGES;"
```

---

## 9. Use Strong MySQL Authentication Plugin

**Severity:** Medium

**Why:** The legacy `mysql_native_password` plugin uses SHA-1, which is vulnerable to offline cracking. `caching_sha2_password` uses SHA-256 with salting and multiple rounds.

**Check:**
```bash
mysql -e "SELECT user, plugin FROM mysql.user WHERE user NOT IN ('mysql.sys','mysql.session','mysql.infoschema');"
# Expected: caching_sha2_password for all users
```

**Fix:**
```bash
ALTER USER 'username'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'new_password';
```

---

## 10. Disable PHP Dangerous Functions

**Severity:** Critical

**Why:** Functions like `exec`, `system`, and `shell_exec` allow PHP scripts to execute arbitrary OS commands. A compromised web application can use these to take over the entire server.

**Check:**
```bash
php -i | grep disable_functions
# Expected: exec,passthru,shell_exec,system,proc_open,popen,...
```

**Fix:**
```bash
# In php.ini:
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec
```

---

## 11. Set PHP open_basedir

**Severity:** High

**Why:** Without `open_basedir`, any PHP script can read any file on the server (e.g., `/etc/passwd`, other sites' config files). This setting restricts file access to the site's own directory.

**Check:**
```bash
php -i | grep open_basedir
# Expected: /home/<user>/htdocs:/tmp
```

**Fix:**
```bash
# In FPM pool config:
php_admin_value[open_basedir] = /home/username/htdocs:/tmp
```

---

## 12. Disable expose_php

**Severity:** Low

**Why:** The `X-Powered-By: PHP/x.x.x` header reveals the exact PHP version, enabling targeted exploits. No legitimate functionality depends on this header.

**Check:**
```bash
curl -sI https://example.com | grep -i x-powered-by
# Expected: no output
```

**Fix:**
```bash
# In php.ini:
expose_php = Off
```

---

## 13. Add Nginx Security Headers

**Severity:** High

**Why:** Security headers instruct browsers to enable protection mechanisms (HSTS, click-jacking prevention, MIME sniffing protection). Without them, users are vulnerable to client-side attacks.

**Check:**
```bash
curl -sI https://example.com | grep -iE 'strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy'
# Expected: all headers present
```

**Fix:**
```bash
# See scripts/harden-nginx.sh for the complete snippet
# Include in server blocks: include snippets/security-headers.conf;
```

---

## 14. Disable Nginx server_tokens

**Severity:** Medium

**Why:** `server_tokens on` exposes the exact Nginx version in response headers and error pages, enabling targeted attacks against known vulnerabilities.

**Check:**
```bash
curl -sI https://example.com | grep -i server
# Expected: Server: nginx (without version number)
```

**Fix:**
```bash
# In nginx.conf http block:
server_tokens off;
```

---

## 15. Enforce TLS 1.2+ Only

**Severity:** Critical

**Why:** TLS 1.0 and 1.1 have known vulnerabilities (BEAST, POODLE) and are officially deprecated. All modern browsers support TLS 1.2+.

**Check:**
```bash
nmap --script ssl-enum-ciphers -p 443 example.com | grep -E 'TLSv1\.[01]'
# Expected: no output (TLS 1.0/1.1 not present)
```

**Fix:**
```bash
# In Nginx:
ssl_protocols TLSv1.2 TLSv1.3;
```

---

## 16. Configure Strong SSL Ciphers

**Severity:** High

**Why:** Weak ciphers (RC4, DES, export ciphers) can be broken in real-time. Using only AEAD ciphers (AES-GCM, ChaCha20-Poly1305) ensures confidentiality and integrity.

**Check:**
```bash
nmap --script ssl-enum-ciphers -p 443 example.com
# Expected: only TLS_AES_*, TLS_CHACHA20_*, ECDHE-* ciphers
```

**Fix:**
```bash
# See scripts/harden-nginx.sh for the recommended cipher configuration
```

---

## 17. Enable Automated Backups

**Severity:** Critical

**Why:** Without backups, any incident (ransomware, disk failure, accidental deletion) results in permanent data loss. Automated backups remove human error from the process.

**Check:**
```bash
crontab -l | grep backup
ls -la /var/backups/its-connect/daily/
# Expected: recent backup files present
```

**Fix:**
```bash
# See scripts/setup-backups.sh for the complete backup system
```

---

## 18. Encrypt Backup Files

**Severity:** High

**Why:** Unencrypted backups stored on disk or transferred offsite expose all your data if the storage is compromised. AES-256 encryption makes the data unreadable without the key.

**Check:**
```bash
file /var/backups/its-connect/daily/*.enc
# Expected: "data" (encrypted, not identifiable as tar/sql)
```

**Fix:**
```bash
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -in backup.tar.gz -out backup.tar.gz.enc -pass file:/root/.backup-key
```

---

## 19. Set Correct File Permissions

**Severity:** High

**Why:** World-readable config files can expose database credentials and API keys. World-writable directories allow attackers to inject malicious code.

**Check:**
```bash
# Check for world-writable files in web directories
find /home -type f -perm -o+w -not -path '*/node_modules/*' 2>/dev/null
# Expected: no output

# Check config file permissions
stat -c '%a %n' /home/*/htdocs/*/wp-config.php 2>/dev/null
# Expected: 640 or 600
```

**Fix:**
```bash
# Set directories to 755 and files to 644
find /home/username/htdocs -type d -exec chmod 755 {} \;
find /home/username/htdocs -type f -exec chmod 644 {} \;

# Restrict sensitive config files
chmod 640 /home/username/htdocs/site/wp-config.php
```

---

## 20. Enable Automatic Security Updates

**Severity:** Medium

**Why:** Known vulnerabilities are published daily. Automatic security updates ensure critical patches are applied promptly without waiting for manual intervention.

**Check:**
```bash
apt-config dump | grep -i unattended
dpkg -l | grep unattended-upgrades
# Expected: unattended-upgrades package installed
cat /etc/apt/apt.conf.d/20auto-upgrades
# Expected: APT::Periodic::Unattended-Upgrade "1";
```

**Fix:**
```bash
apt-get install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
# Or manually:
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
```

---

## Quick Reference Table

| # | Item | Severity | Script |
|---|------|----------|--------|
| 1 | Disable SSH root login | Critical | `harden-ssh.sh` |
| 2 | Disable SSH password auth | Critical | `harden-ssh.sh` |
| 3 | Change SSH default port | High | `harden-ssh.sh` |
| 4 | Set SSH MaxAuthTries | Medium | `harden-ssh.sh` |
| 5 | Enable firewall (UFW) | Critical | `setup-firewall.sh` |
| 6 | Install Fail2Ban | High | `setup-firewall.sh` |
| 7 | Bind MySQL to localhost | Critical | `harden-mysql.sh` |
| 8 | Remove MySQL anon users | High | `harden-mysql.sh` |
| 9 | Strong MySQL auth plugin | Medium | `harden-mysql.sh` |
| 10 | Disable PHP functions | Critical | `harden-php.sh` |
| 11 | Set PHP open_basedir | High | `harden-php.sh` |
| 12 | Disable expose_php | Low | `harden-php.sh` |
| 13 | Nginx security headers | High | `harden-nginx.sh` |
| 14 | Disable server_tokens | Medium | `harden-nginx.sh` |
| 15 | Enforce TLS 1.2+ | Critical | `harden-nginx.sh` |
| 16 | Strong SSL ciphers | High | `harden-nginx.sh` |
| 17 | Automated backups | Critical | `setup-backups.sh` |
| 18 | Encrypt backups | High | `setup-backups.sh` |
| 19 | File permissions | High | Manual |
| 20 | Auto security updates | Medium | Manual |
