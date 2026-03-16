# Server Hardening — ITS Connect

Checklist and automation scripts for hardening Ubuntu/Debian production servers. Based on a real-world security audit where **18 vulnerabilities were identified and remediated** across SSH, MySQL, PHP, Nginx, firewall, and backup configurations.

These scripts and guides reflect the exact steps we took to bring a production hosting environment from a vulnerable baseline to a hardened, auditable state.

> **Blog article:** [Segurança em Servidor de Hospedagem](https://itsconnect.com.br/blog/seguranca-servidor-hospedagem)

---

## Table of Contents

- [Quick Start](#quick-start)
- [Scripts](#scripts)
- [Checklist Summary](#checklist-summary)
- [Detailed Checklist](#detailed-checklist)
- [Contributing](#contributing)
- [License](#license)

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/ItsConnect/server-hardening.git
cd server-hardening

# Make all scripts executable
chmod +x scripts/*.sh

# Run the SSH hardening script (review variables first)
sudo ./scripts/harden-ssh.sh

# Run the firewall setup
sudo ./scripts/setup-firewall.sh

# Run the full checklist audit
cat checklist.md
```

> **Warning:** Always review each script and adjust the configuration variables at the top before running in production. Test in a staging environment first.

---

## Scripts

| Script | Description |
|--------|-------------|
| [`harden-ssh.sh`](scripts/harden-ssh.sh) | Disable root login, disable password auth, limit auth retries, change default port |
| [`harden-mysql.sh`](scripts/harden-mysql.sh) | Bind to localhost, remove anonymous users, enforce strong auth plugin, tune connections |
| [`setup-firewall.sh`](scripts/setup-firewall.sh) | Configure UFW rules, install and configure Fail2Ban with sshd/nginx jails |
| [`harden-php.sh`](scripts/harden-php.sh) | Disable dangerous functions, set open_basedir, restrict uploads, hide version |
| [`harden-nginx.sh`](scripts/harden-nginx.sh) | Add security headers, disable server tokens, enforce TLS 1.2+ with strong ciphers |
| [`setup-backups.sh`](scripts/setup-backups.sh) | Automated encrypted backups with rotation (7 daily, 4 weekly) and crontab integration |

---

## Checklist Summary

| # | Item | Severity | Status |
|---|------|----------|--------|
| 1 | Disable SSH root login | Critical | ✅ |
| 2 | Disable SSH password authentication | Critical | ✅ |
| 3 | Change SSH default port | High | ✅ |
| 4 | Set SSH MaxAuthTries | Medium | ✅ |
| 5 | Enable UFW with default deny | Critical | ✅ |
| 6 | Install and configure Fail2Ban | High | ✅ |
| 7 | Bind MySQL to 127.0.0.1 | Critical | ✅ |
| 8 | Remove MySQL anonymous users | High | ✅ |
| 9 | Use strong MySQL auth plugin | Medium | ✅ |
| 10 | Disable PHP dangerous functions | Critical | ✅ |
| 11 | Set PHP open_basedir | High | ✅ |
| 12 | Disable expose_php | Low | ✅ |
| 13 | Add Nginx security headers | High | ✅ |
| 14 | Disable Nginx server_tokens | Medium | ✅ |
| 15 | Enforce TLS 1.2+ only | Critical | ✅ |
| 16 | Configure strong SSL ciphers | High | ✅ |
| 17 | Enable automated backups | Critical | ✅ |
| 18 | Encrypt backup files | High | ✅ |
| 19 | Set correct file permissions | High | ✅ |
| 20 | Enable automatic security updates | Medium | ✅ |

---

## Detailed Checklist

See [`checklist.md`](checklist.md) for the full checklist with verification commands and remediation steps for each item.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Commit your changes (`git commit -m 'Add new hardening check'`)
4. Push to the branch (`git push origin feature/new-check`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

© 2026 ITS Connect
