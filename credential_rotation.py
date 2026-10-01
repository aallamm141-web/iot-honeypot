#!/usr/bin/env python3
"""
Decoy Credential Rotation
==========================
Rotates fake credentials in Cowrie honeypot files weekly.
Each set of credentials has a unique tracking ID so we know
exactly which file the attacker opened and when.

Files rotated:
  - credentials.txt
  - backup.sh
  - config.ini
  - readme.txt

Features:
  - Generates realistic fake credentials each rotation
  - Embeds unique tracking token in each file
  - Logs rotation history
  - Sends Telegram notification on rotation
  - Rebuilds Cowrie filesystem after rotation

Usage:
  python3 credential_rotation.py          # Rotate now
  python3 credential_rotation.py --show   # Show current credentials
  python3 credential_rotation.py --log    # Show rotation history
"""

import os
import sys
import json
import random
import string
import subprocess
import logging
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

# ==============================================================================
# CONFIG
# ==============================================================================

PROJECT_ROOT = os.getenv("PROJECT_ROOT")

if not PROJECT_ROOT:
    print("[FATAL ERROR] Missing required environment variable: PROJECT_ROOT", file=sys.stderr)
    print("[FATAL ERROR] Ensure your .env file is populated correctly.", file=sys.stderr)
    sys.exit(1)

HONEYFS_DIR    = os.path.join(PROJECT_ROOT, "cowrie/honeyfs/root")
COWRIE_DIR     = os.path.join(PROJECT_ROOT, "cowrie")
LOG_FILE       = os.path.join(PROJECT_ROOT, "logs_and_reports/credential_rotation.log")
HISTORY_FILE   = os.path.join(PROJECT_ROOT, "logs_and_reports/rotation_history.json")

TELEGRAM_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
CANARY_TOKEN_URL = os.getenv("CANARY_TOKEN_URL")

missing = []
if not TELEGRAM_TOKEN: missing.append("TELEGRAM_BOT_TOKEN")
if not TELEGRAM_CHAT_ID: missing.append("TELEGRAM_CHAT_ID")
if not CANARY_TOKEN_URL: missing.append("CANARY_TOKEN_URL")
if missing:
    print(f"[FATAL ERROR] Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
    print("[FATAL ERROR] Ensure your .env file is populated correctly.", file=sys.stderr)
    sys.exit(1)

# Decoy company/network details — not secrets, but centralized here for easy editing
FAKE_DB_HOSTS  = ["10.0.1.100", "10.0.1.101", "192.168.100.50", "172.16.0.10"]
FAKE_PLC_IPS   = ["10.0.1.200", "192.168.100.100", "172.16.0.20", "10.10.0.50"]
FAKE_COMPANIES = ["Cairo Industrial Complex", "Delta Manufacturing", "Suez Operations", "Alexandria Plant"]
FAKE_ADMINS    = ["eng.operations", "admin.scada", "sys.control", "ops.engineer"]
FAKE_DOMAINS   = ["company.local", "industrial.corp", "scada.internal", "ops.local"]
FAKE_DB_NAMES  = ["production_data", "scada_db", "plc_logs", "sensor_data", "control_system"]

# ==============================================================================
# LOGGING
# ==============================================================================

os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ==============================================================================
# CREDENTIAL GENERATION
# ==============================================================================

def generate_password(length=12):
    """Generates a realistic-looking fake password."""
    templates = [
        # Pattern: Word + Number + Special
        lambda: (
            random.choice(["Scada", "Admin", "Control", "Ops", "System", "Plant"])
            + str(random.randint(100, 999999))
            + random.choice(["!", "@", "#", "$"])
        ),
        # Pattern: Word@Year!
        lambda: (
            random.choice(["Cairo", "Delta", "Suez", "Alex", "Egypt"])
            + "@"
            + str(random.randint(2022, 2026))
            + str(random.randint(10, 99))
            + random.choice(["!", "#"])
        ),
        # Pattern: prefix_WORD_suffix
        lambda: (
            random.choice(["scada", "plc", "ops", "ctrl"])
            + "_"
            + random.choice(["Pass", "Auth", "Key", "Sec"])
            + str(random.randint(1000, 9999))
            + random.choice(["!", "@"])
        ),
    ]
    return random.choice(templates)()

def generate_tracking_id():
    """Generates a unique tracking ID for this credential set."""
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=8))

def generate_credentials():
    """Generates a complete set of fake credentials."""
    tracking_id = generate_tracking_id()
    db_host     = random.choice(FAKE_DB_HOSTS)
    plc_ip      = random.choice(FAKE_PLC_IPS)
    company     = random.choice(FAKE_COMPANIES)
    admin       = random.choice(FAKE_ADMINS)
    domain      = random.choice(FAKE_DOMAINS)
    db_name     = random.choice(FAKE_DB_NAMES)
    db_user     = f"scada_{random.choice(['admin', 'user', 'ops', 'ctrl'])}"
    db_pass     = generate_password()
    ssh_pass    = generate_password()
    api_key     = "".join(random.choices(string.hexdigits.lower(), k=32))
    mqtt_port   = random.choice([1883, 8883])
    plc_port    = random.choice([502, 102, 44818])
    created     = datetime.now().strftime("%Y-%m-%d")

    return {
        "tracking_id":      tracking_id,
        "canary_base":      CANARY_TOKEN_URL,
        "canary_creds":     f"{CANARY_TOKEN_URL}?ref={tracking_id}&file=credentials",
        "canary_backup":    f"{CANARY_TOKEN_URL}?ref={tracking_id}&file=backup",
        "canary_config":    f"{CANARY_TOKEN_URL}?ref={tracking_id}&file=config",
        "db_host":     db_host,
        "db_port":     3306,
        "db_user":     db_user,
        "db_pass":     db_pass,
        "db_name":     db_name,
        "plc_ip":      plc_ip,
        "plc_port":    plc_port,
        "ssh_pass":    ssh_pass,
        "api_key":     api_key,
        "mqtt_port":   mqtt_port,
        "company":     company,
        "admin":       admin,
        "domain":      domain,
        "created":     created,
    }

# ==============================================================================
# FILE GENERATION
# ==============================================================================

def write_credentials_txt(creds):
    """Writes the credentials.txt fake file."""
    content = f"""# {creds['company']} - System Credentials
# Generated: {creds['created']}
# Authorized personnel only - DO NOT SHARE
# Ref: {creds['tracking_id']}
# Verify: {creds['canary_creds']}

[SSH Access]
host     = 192.168.1.45
port     = 22
username = root
password = {creds['ssh_pass']}

[Database]
host     = {creds['db_host']}
port     = {creds['db_port']}
username = {creds['db_user']}
password = {creds['db_pass']}
database = {creds['db_name']}

[API]
endpoint = https://api.{creds['domain']}/v1
key      = {creds['api_key']}

[Emergency Contact]
admin    = {creds['admin']}@{creds['domain']}
phone    = +20-2-{random.randint(10000000, 99999999)}
"""
    path = os.path.join(HONEYFS_DIR, "credentials.txt")
    with open(path, "w") as f:
        f.write(content)
    log.info(f"Written: credentials.txt (tracking_id={creds['tracking_id']})")

def write_backup_sh(creds):
    """Writes the backup.sh fake file."""
    content = f"""#!/bin/bash
# {creds['company']} - SCADA Backup Script
# Author: {creds['admin']}@{creds['domain']}
# Created: {creds['created']}
# ID: {creds['tracking_id']}
# Ref: {creds['canary_backup']}

BACKUP_DIR=/opt/scada/backup
DB_HOST={creds['db_host']}
DB_USER={creds['db_user']}
DB_PASS={creds['db_pass']}
DB_NAME={creds['db_name']}
REMOTE_HOST=backup.{creds['domain']}
REMOTE_USER=backup_agent
REMOTE_PASS={generate_password()}

# Create backup
echo "[$(date)] Starting backup..."
mysqldump -h $DB_HOST -u $DB_USER -p$DB_PASS $DB_NAME > $BACKUP_DIR/backup_$(date +%Y%m%d_%H%M%S).sql

# Transfer to remote
sshpass -p $REMOTE_PASS scp $BACKUP_DIR/backup_*.sql $REMOTE_USER@$REMOTE_HOST:/backups/

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -name "*.sql" -mtime +7 -delete

echo "[$(date)] Backup completed successfully"
"""
    path = os.path.join(HONEYFS_DIR, "backup.sh")
    with open(path, "w") as f:
        f.write(content)
    log.info("Written: backup.sh")

def write_config_ini(creds):
    """Writes the config.ini fake file."""
    content = f"""# {creds['company']} - SCADA Configuration
# Last updated: {creds['created']}
# Config ID: {creds['tracking_id']}
# Verify: {creds['canary_config']}

[database]
host     = {creds['db_host']}
port     = {creds['db_port']}
user     = {creds['db_user']}
password = {creds['db_pass']}
name     = {creds['db_name']}
timeout  = 30
pool_size = 10

[plc]
ip       = {creds['plc_ip']}
port     = {creds['plc_port']}
slave_id = {random.randint(1, 5)}
timeout  = 5
retries  = 3

[mqtt]
broker   = {creds['db_host']}
port     = {creds['mqtt_port']}
topic    = scada/sensors
username = mqtt_{creds['db_user']}
password = {generate_password()}
qos      = 1

[api]
endpoint = https://api.{creds['domain']}/v1
key      = {creds['api_key']}
timeout  = 10

[logging]
level    = INFO
path     = /var/log/scada/system.log
rotation = daily
"""
    path = os.path.join(HONEYFS_DIR, "config.ini")
    with open(path, "w") as f:
        f.write(content)
    log.info("Written: config.ini")

def write_readme_txt(creds):
    """Writes the readme.txt fake file."""
    content = f"""=== {creds['company']} - SCADA Gateway ===
Last updated : {creds['created']}
System ID    : {creds['tracking_id']}
Admin        : {creds['admin']}@{creds['domain']}

-- IMPORTANT: DO NOT SHARE THIS SYSTEM --

Network Layout:
  Gateway   : 192.168.1.45
  Database  : {creds['db_host']}
  PLC       : {creds['plc_ip']}:{creds['plc_port']}
  MQTT      : {creds['db_host']}:{creds['mqtt_port']}

Credentials stored in:
  /root/credentials.txt  -- All system passwords
  /root/config.ini       -- System configuration
  /root/backup.sh        -- Automated backup script

For support contact: {creds['admin']}@{creds['domain']}
"""
    path = os.path.join(HONEYFS_DIR, "readme.txt")
    with open(path, "w") as f:
        f.write(content)
    log.info("Written: readme.txt")

# ==============================================================================
# COWRIE REBUILD
# ==============================================================================

def rebuild_cowrie():
    """Restarts the Cowrie container so it picks up the new honeyfs files."""
    log.info("Restarting Cowrie container to apply new honeyfs files...")
    try:
        # honeyfs (text files) are bind-mounted and read directly by Cowrie —
        # fs.pickle does not need to be touched.
        result = subprocess.run(
            ["docker", "restart", "cowrie"],
            capture_output=True, text=True,
            timeout=60
        )
        if result.returncode == 0:
            log.info("Cowrie container restarted successfully")
        else:
            log.error(f"Cowrie restart failed: {result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        log.error("Cowrie restart timed out after 60s")
    except Exception as e:
        log.error(f"Rebuild error: {e}")

# ==============================================================================
# HISTORY MANAGEMENT
# ==============================================================================

def load_history():
    """Loads rotation history from JSON file."""
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    return []

def save_history(history):
    """Saves rotation history to JSON file."""
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def add_to_history(creds):
    """Adds current credentials to rotation history."""
    history = load_history()
    history.append({
        "tracking_id": creds["tracking_id"],
        "rotated_at":  datetime.now(timezone.utc).isoformat(),
        "db_host":     creds["db_host"],
        "db_user":     creds["db_user"],
        "company":     creds["company"],
    })
    # Keep last 52 rotations (1 year)
    history = history[-52:]
    save_history(history)

# ==============================================================================
# TELEGRAM NOTIFICATION
# ==============================================================================

def send_telegram_notification(creds):
    """Sends Telegram notification about credential rotation."""
    msg = (
        f"<b>CREDENTIAL ROTATION COMPLETED</b>\n"
        f"{'─'*35}\n"
        f"Time        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Tracking ID : <code>{creds['tracking_id']}</code>\n"
        f"Company     : {creds['company']}\n"
        f"DB Host     : {creds['db_host']}\n"
        f"{'─'*35}\n"
        f"Files updated:\n"
        f"  - credentials.txt\n"
        f"  - backup.sh\n"
        f"  - config.ini\n"
        f"  - readme.txt\n"
        f"{'─'*35}\n"
        f"If you receive a Canary Token alert with tracking ID\n"
        f"<code>{creds['tracking_id']}</code> — attacker opened our files!"
    )
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"},
            timeout=10
        )
        log.info("Telegram notification sent")
    except Exception as e:
        log.error(f"Telegram error: {e}")

# ==============================================================================
# SHOW COMMANDS
# ==============================================================================

def show_current():
    """Shows current credentials in all files."""
    print("\n" + "="*60)
    print("  CURRENT DECOY CREDENTIALS")
    print("="*60)
    for filename in ["credentials.txt", "backup.sh", "config.ini", "readme.txt"]:
        path = os.path.join(HONEYFS_DIR, filename)
        if os.path.exists(path):
            print(f"\n--- {filename} ---")
            with open(path, "r") as f:
                print(f.read())
        else:
            print(f"\n--- {filename} --- NOT FOUND")

def show_history():
    """Shows rotation history."""
    history = load_history()
    print("\n" + "="*60)
    print("  ROTATION HISTORY")
    print("="*60)
    if not history:
        print("  No rotations yet.")
        return
    print(f"\n  {'#':<4} {'Tracking ID':<12} {'Date':<22} {'Company':<25} {'DB Host'}")
    print(f"  {'─'*80}")
    for i, entry in enumerate(reversed(history), 1):
        print(
            f"  {i:<4} "
            f"{entry['tracking_id']:<12} "
            f"{entry['rotated_at'][:19]:<22} "
            f"{entry['company']:<25} "
            f"{entry['db_host']}"
        )

# ==============================================================================
# MAIN
# ==============================================================================

def main():
    if "--show" in sys.argv:
        show_current()
        return

    if "--log" in sys.argv:
        show_history()
        return

    log.info("="*60)
    log.info("Starting Credential Rotation")
    log.info("="*60)

    # Ensure honeyfs directory exists
    os.makedirs(HONEYFS_DIR, exist_ok=True)

    # Generate new credentials
    log.info("Generating new fake credentials...")
    creds = generate_credentials()
    log.info(f"New tracking ID: {creds['tracking_id']}")
    log.info(f"Company: {creds['company']}")

    # Write all files
    write_credentials_txt(creds)
    write_backup_sh(creds)
    write_config_ini(creds)
    write_readme_txt(creds)

    # Sanity check — verify all files were actually written
    for filename in ["credentials.txt", "backup.sh", "config.ini", "readme.txt"]:
        path = os.path.join(HONEYFS_DIR, filename)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            log.error(f"VERIFICATION FAILED: {filename} missing or empty at {path}")
        else:
            log.info(f"Verified: {filename} ({os.path.getsize(path)} bytes)")

    # Save to history
    add_to_history(creds)

    # Rebuild Cowrie
    rebuild_cowrie()

    # Send Telegram notification
    send_telegram_notification(creds)

    log.info("Credential rotation completed successfully!")
    log.info(f"Tracking ID for this rotation: {creds['tracking_id']}")

    # Print summary
    print("\n" + "="*60)
    print("  ROTATION SUMMARY")
    print("="*60)
    print(f"  Tracking ID : {creds['tracking_id']}")
    print(f"  Company     : {creds['company']}")
    print(f"  DB Host     : {creds['db_host']}")
    print(f"  DB User     : {creds['db_user']}")
    print(f"  DB Pass     : {creds['db_pass']}")
    print(f"  PLC         : {creds['plc_ip']}:{creds['plc_port']}")
    print("="*60)
    print("\n  Files updated: credentials.txt, backup.sh, config.ini, readme.txt")
    print("  Cowrie rebuilt and restarted.")
    print(f"\n  If Canary Token fires with ID '{creds['tracking_id']}' = attacker opened files!\n")


if __name__ == "__main__":
    main()
