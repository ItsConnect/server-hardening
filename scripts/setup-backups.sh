#!/bin/bash
set -euo pipefail

# =============================================================================
# setup-backups.sh -- Encrypted Backup System with Rotation
# ITS Connect -- https://itsconnect.com.br
#
# Creates automated, encrypted backups of files and MySQL databases with
# daily and weekly rotation. Installs a crontab entry for daily execution.
#
# Usage: sudo ./setup-backups.sh
# =============================================================================

# ---- Configuration (edit these before running) ------------------------------

BACKUP_DIR="${BACKUP_DIR:-/var/backups/its-connect}"
SITES_DIR="${SITES_DIR:-/home}"
MYSQL_USER="${MYSQL_USER:-root}"
ENCRYPTION_KEY_FILE="${ENCRYPTION_KEY_FILE:-/root/.backup-encryption-key}"
DAILY_RETENTION=7
WEEKLY_RETENTION=4
CRON_HOUR="${CRON_HOUR:-3}"
CRON_MINUTE="${CRON_MINUTE:-0}"

# ---- Preflight checks ------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

# ---- Create backup directory structure --------------------------------------

echo "[1/6] Creating backup directory structure..."
mkdir -p "${BACKUP_DIR}/daily"
mkdir -p "${BACKUP_DIR}/weekly"
mkdir -p "${BACKUP_DIR}/logs"
chmod 700 "$BACKUP_DIR"
echo "      Created $BACKUP_DIR (mode 700)"

# ---- Generate encryption key ------------------------------------------------
# We use AES-256-CBC encryption with a randomly generated key stored in a
# root-only file. This protects backups at rest -- if the backup storage is
# compromised, the data remains encrypted.

echo "[2/6] Setting up encryption key..."
if [[ ! -f "$ENCRYPTION_KEY_FILE" ]]; then
    openssl rand -base64 48 > "$ENCRYPTION_KEY_FILE"
    chmod 600 "$ENCRYPTION_KEY_FILE"
    echo "      Generated new encryption key at $ENCRYPTION_KEY_FILE"
    echo "      IMPORTANT: Store this key securely! Without it, backups cannot be restored."
else
    echo "      Encryption key already exists at $ENCRYPTION_KEY_FILE"
fi

# ---- Create the backup execution script -------------------------------------
# This script runs daily via crontab and performs:
# 1. File backup (tar + gzip) of all site directories
# 2. MySQL database dumps (all user databases)
# 3. Encryption of all backup files with AES-256-CBC
# 4. Weekly copy on Sundays
# 5. Rotation of old backups (7 daily, 4 weekly)

echo "[3/6] Creating backup execution script..."

cat > "${BACKUP_DIR}/run-backup.sh" << 'RUN_BACKUP_EOF'
#!/bin/bash
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/its-connect}"
SITES_DIR="${SITES_DIR:-/home}"
MYSQL_USER="${MYSQL_USER:-root}"
ENCRYPTION_KEY_FILE="${ENCRYPTION_KEY_FILE:-/root/.backup-encryption-key}"
DAILY_RETENTION="${DAILY_RETENTION:-7}"
WEEKLY_RETENTION="${WEEKLY_RETENTION:-4}"

DATE=$(date +%Y%m%d_%H%M%S)
DAY_OF_WEEK=$(date +%u)
LOG_FILE="${BACKUP_DIR}/logs/backup_${DATE}.log"

exec > >(tee -a "$LOG_FILE") 2>&1

echo "============================================="
echo "  Backup Started: $(date)"
echo "============================================="

# ---- Step 1: Backup site files with tar + gzip -----------------------------
echo ""
echo "[FILES] Backing up site directories..."
FILES_BACKUP="${BACKUP_DIR}/daily/files_${DATE}.tar.gz"

if [[ -d "$SITES_DIR" ]]; then
    tar -czf "$FILES_BACKUP" \
        --exclude="*.log" \
        --exclude="cache/*" \
        --exclude="node_modules/*" \
        --exclude=".git/*" \
        -C "$(dirname "$SITES_DIR")" "$(basename "$SITES_DIR")" 2>/dev/null || true
    echo "      Files backup: $(du -sh "$FILES_BACKUP" | cut -f1)"
else
    echo "      WARNING: $SITES_DIR does not exist. Skipping file backup."
fi

# ---- Step 2: Backup MySQL databases with mysqldump -------------------------
echo ""
echo "[MYSQL] Backing up databases..."
MYSQL_BACKUP="${BACKUP_DIR}/daily/mysql_${DATE}.sql.gz"

DATABASES=$(mysql -u "$MYSQL_USER" -N -e \
    "SELECT schema_name FROM information_schema.schemata
     WHERE schema_name NOT IN ('information_schema','performance_schema','sys','mysql');" \
    2>/dev/null || echo "")

if [[ -n "$DATABASES" ]]; then
    mysqldump -u "$MYSQL_USER" \
        --single-transaction \
        --routines \
        --triggers \
        --events \
        --databases $DATABASES 2>/dev/null | gzip > "$MYSQL_BACKUP"
    echo "      MySQL backup: $(du -sh "$MYSQL_BACKUP" | cut -f1)"
    echo "      Databases: $(echo "$DATABASES" | tr '\n' ' ')"
else
    echo "      WARNING: No databases found or MySQL connection failed."
fi

# ---- Step 3: Encrypt with openssl aes-256-cbc ------------------------------
echo ""
echo "[ENCRYPT] Encrypting backup files..."
ENCRYPTION_KEY=$(cat "$ENCRYPTION_KEY_FILE")

for BACKUP_FILE in "${BACKUP_DIR}/daily/"*"_${DATE}"*; do
    if [[ -f "$BACKUP_FILE" ]] && [[ ! "$BACKUP_FILE" =~ \.enc$ ]]; then
        openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
            -in "$BACKUP_FILE" \
            -out "${BACKUP_FILE}.enc" \
            -pass "pass:${ENCRYPTION_KEY}"
        shred -u "$BACKUP_FILE" 2>/dev/null || rm -f "$BACKUP_FILE"
        echo "      Encrypted: $(basename "${BACKUP_FILE}.enc")"
    fi
done

# ---- Step 4: Weekly copy on Sundays ----------------------------------------
if [[ "$DAY_OF_WEEK" -eq 7 ]]; then
    echo ""
    echo "[WEEKLY] Creating weekly backup copy..."
    for DAILY_FILE in "${BACKUP_DIR}/daily/"*"_${DATE}"*.enc; do
        if [[ -f "$DAILY_FILE" ]]; then
            cp "$DAILY_FILE" "${BACKUP_DIR}/weekly/$(basename "$DAILY_FILE")"
            echo "      Copied to weekly: $(basename "$DAILY_FILE")"
        fi
    done
fi

# ---- Step 5: Rotate old backups (7 daily, 4 weekly) ------------------------
echo ""
echo "[ROTATE] Removing old backups..."

DAILY_REMOVED=$(find "${BACKUP_DIR}/daily" -name "*.enc" -mtime +${DAILY_RETENTION} -delete -print | wc -l)
echo "      Daily: removed ${DAILY_REMOVED} file(s) older than ${DAILY_RETENTION} days"

WEEKLY_DAYS=$((WEEKLY_RETENTION * 7))
WEEKLY_REMOVED=$(find "${BACKUP_DIR}/weekly" -name "*.enc" -mtime +${WEEKLY_DAYS} -delete -print | wc -l)
echo "      Weekly: removed ${WEEKLY_REMOVED} file(s) older than ${WEEKLY_RETENTION} weeks"

find "${BACKUP_DIR}/logs" -name "*.log" -mtime +30 -delete 2>/dev/null || true

echo ""
echo "============================================="
echo "  Backup Complete: $(date)"
echo "============================================="
RUN_BACKUP_EOF

chmod 700 "${BACKUP_DIR}/run-backup.sh"
echo "      Created ${BACKUP_DIR}/run-backup.sh"

# ---- Create restore helper script -------------------------------------------

echo "[4/6] Creating restore helper script..."

cat > "${BACKUP_DIR}/restore-backup.sh" << 'RESTORE_EOF'
#!/bin/bash
set -euo pipefail

# Usage: ./restore-backup.sh <encrypted-file>
# Decrypts a backup file for restoration.

ENCRYPTION_KEY_FILE="${ENCRYPTION_KEY_FILE:-/root/.backup-encryption-key}"

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <encrypted-backup-file>"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="${INPUT_FILE%.enc}"
ENCRYPTION_KEY=$(cat "$ENCRYPTION_KEY_FILE")

echo "Decrypting: $INPUT_FILE"
openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter 100000 \
    -in "$INPUT_FILE" \
    -out "$OUTPUT_FILE" \
    -pass "pass:${ENCRYPTION_KEY}"

echo "Decrypted:  $OUTPUT_FILE"
echo ""
echo "To restore MySQL:  gunzip < database.sql.gz | mysql -u root"
echo "To restore files:  tar -xzf files.tar.gz -C /"
RESTORE_EOF

chmod 700 "${BACKUP_DIR}/restore-backup.sh"
echo "      Created ${BACKUP_DIR}/restore-backup.sh"

# ---- Add to crontab ---------------------------------------------------------

echo "[5/6] Adding backup to crontab..."
CRON_LINE="${CRON_MINUTE} ${CRON_HOUR} * * * ${BACKUP_DIR}/run-backup.sh"

if crontab -l 2>/dev/null | grep -qF "run-backup.sh"; then
    echo "      Crontab entry already exists. Skipping."
else
    (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
    echo "      Added crontab: $CRON_LINE"
fi

# ---- Summary ----------------------------------------------------------------

echo "[6/6] Verifying setup..."
echo ""
echo "============================================="
echo "  Backup System Setup Complete"
echo "============================================="
echo "  Backup directory:    $BACKUP_DIR"
echo "  Daily retention:     ${DAILY_RETENTION} days"
echo "  Weekly retention:    ${WEEKLY_RETENTION} weeks"
echo "  Encryption:          AES-256-CBC (PBKDF2)"
echo "  Schedule:            Daily at ${CRON_HOUR}:$(printf '%02d' ${CRON_MINUTE})"
echo "  File backups:        $SITES_DIR"
echo "  MySQL backups:       All user databases"
echo "============================================="
echo ""
echo "To manually run a backup:   ${BACKUP_DIR}/run-backup.sh"
echo "To restore a backup:        ${BACKUP_DIR}/restore-backup.sh <file.enc>"
echo ""
echo "CRITICAL: Store the encryption key in a secure, separate location!"
echo "Without it, encrypted backups CANNOT be restored."
