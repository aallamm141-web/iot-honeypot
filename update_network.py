#!/usr/bin/env python3
"""
Network Auto-Update Script
==========================
Detects if the honeypot VM IP has changed and automatically updates:
  - HONEYPOT_IP and OLD_HONEYPOT_IPS in .env
  - UFW rules
  - Zeek bridge IDs in crontab
  - Restarts alert.py and attacker_profiler.py to pick up the new .env values

Run as a cron job every 5 minutes:
  */5 * * * * python3 /home/allam/honeypot/update_network.py >> /home/allam/honeypot/logs_and_reports/network_update.log 2>&1
"""

import os
import sys
import time
import re
import socket
import subprocess
import logging
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ==============================================================================
# CONFIG
# ==============================================================================

PROJECT_ROOT = os.getenv("PROJECT_ROOT")

TELEGRAM_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

missing = []
if not PROJECT_ROOT: missing.append("PROJECT_ROOT")
if not TELEGRAM_TOKEN: missing.append("TELEGRAM_BOT_TOKEN")
if not TELEGRAM_CHAT_ID: missing.append("TELEGRAM_CHAT_ID")
if missing:
    print(f"[FATAL ERROR] Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
    print("[FATAL ERROR] Ensure your .env file is populated correctly.", file=sys.stderr)
    sys.exit(1)

ENV_FILE   = os.path.join(PROJECT_ROOT, ".env")
LOG_FILE   = os.path.join(PROJECT_ROOT, "logs_and_reports/network_update.log")
STATE_FILE = os.path.join(PROJECT_ROOT, "logs_and_reports/network_state.txt")

MGMT_PORT = int(os.getenv("KIBANA_PORT", 5601))

# ==============================================================================
# LOGGING
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE)
    ]
)
log = logging.getLogger(__name__)

# ==============================================================================
# IP DETECTION
# ==============================================================================

def get_current_ip():
    """Gets the current VM IP by connecting to external host."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        log.error(f"Failed to detect current IP: {e}")
        return None

def get_saved_ip():
    """Reads the last known IP from state file."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return f.read().strip()
    return None

def save_ip(ip):
    """Saves current IP to state file."""
    with open(STATE_FILE, "w") as f:
        f.write(ip)

# ==============================================================================
# .ENV UPDATE HELPERS
# ==============================================================================

def update_env_var(key, value):
    """Updates or appends a KEY=value line in the .env file."""
    if not os.path.exists(ENV_FILE):
        log.error(f".env file not found at {ENV_FILE}")
        return False

    with open(ENV_FILE, "r") as f:
        lines = f.readlines()

    pattern = re.compile(rf"^{re.escape(key)}=.*$")
    found = False
    for i, line in enumerate(lines):
        if pattern.match(line.strip()):
            lines[i] = f"{key}={value}\n"
            found = True
            break

    if not found:
        lines.append(f"{key}={value}\n")

    with open(ENV_FILE, "w") as f:
        f.writelines(lines)

    log.info(f"Updated .env: {key}={value}")
    return True

def get_env_var(key, default=""):
    """Reads a KEY=value from the .env file directly (not from process env, which may be stale)."""
    if not os.path.exists(ENV_FILE):
        return default
    with open(ENV_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1]
    return default

# ==============================================================================
# UPDATE FUNCTIONS
# ==============================================================================

def update_ufw(old_ip, new_ip):
    """Updates UFW rules for management access."""
    try:
        old_parts = old_ip.split(".")
        new_parts = new_ip.split(".")
        old_subnet = f"{old_parts[0]}.{old_parts[1]}.{old_parts[2]}.0/24"
        new_subnet = f"{new_parts[0]}.{new_parts[1]}.{new_parts[2]}.0/24"

        if old_subnet == new_subnet:
            log.info("Same subnet — UFW rules unchanged")
            return

        subprocess.run(
            ["sudo", "ufw", "delete", "allow", "from", old_subnet, "to", "any", "port", str(MGMT_PORT)],
            capture_output=True
        )
        log.info(f"Removed UFW rule for {old_subnet}:{MGMT_PORT}")

        subprocess.run(
            ["sudo", "ufw", "allow", "from", new_subnet, "to", "any", "port", str(MGMT_PORT)],
            capture_output=True
        )
        log.info(f"Added UFW rule for {new_subnet}:{MGMT_PORT}")

    except Exception as e:
        log.error(f"UFW update error: {e}")

def update_zeek_bridges():
    """
    Checks if Docker bridge IDs have changed since Zeek was last started,
    and if so, re-runs start_zeek.sh to restart Zeek on the correct interfaces.
    """
    try:
        result = subprocess.run(
            ["sh", "-c", "ip link show | grep -o 'br-[a-f0-9]*' | sort -u"],
            capture_output=True, text=True
        )
        current_bridges = set(result.stdout.strip().split("\n"))
        current_bridges.discard("")

        last_bridges = set()
        if os.path.exists(STATE_FILE + ".bridges"):
            with open(STATE_FILE + ".bridges") as f:
                last_bridges = set(f.read().strip().split("\n"))
                last_bridges.discard("")

        if current_bridges == last_bridges:
            return

        log.info(f"Bridge IDs changed: {last_bridges} -> {current_bridges}")

        lock_file = STATE_FILE + ".zeek_restart_lock"
        now = time.time()
        if os.path.exists(lock_file):
            age = now - os.path.getmtime(lock_file)
            if age < 60:
                log.info("Skipping start_zeek.sh - previous restart still in progress (%.0fs ago)" % age)
                with open(STATE_FILE + ".bridges", "w") as f2:
                    f2.write("\n".join(sorted(current_bridges)))
                return

        start_script = os.path.join(PROJECT_ROOT, "start_zeek.sh")
        if os.path.exists(start_script):
            with open(lock_file, "w") as f2:
                f2.write(str(now))
            subprocess.Popen(
                ["bash", start_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            log.info("Re-ran start_zeek.sh to apply new bridge IDs")
        else:
            log.warning(start_script + " not found - cannot auto-fix Zeek bridges")

        with open(STATE_FILE + ".bridges", "w") as f:
            f.write("\n".join(sorted(current_bridges)))

    except Exception as e:
        log.error(f"Zeek bridge update error: {e}")

def update_old_honeypot_ips(old_ip):
    """Appends old_ip to OLD_HONEYPOT_IPS in .env (comma-separated list)."""
    current = get_env_var("OLD_HONEYPOT_IPS", "")
    ips = set(ip.strip() for ip in current.split(",") if ip.strip())
    if old_ip in ips:
        return
    ips.add(old_ip)
    update_env_var("OLD_HONEYPOT_IPS", ",".join(sorted(ips)))
    log.info(f"Added {old_ip} to OLD_HONEYPOT_IPS in .env")

def restart_services():
    """Restarts alert.py and attacker_profiler.py safely so they reload .env."""
    services = [
        ("alert.py",             os.path.join(PROJECT_ROOT, "logs_and_reports/alert.log"),    True),
        ("attacker_profiler.py", os.path.join(PROJECT_ROOT, "logs_and_reports/profiler.log"), False),
    ]

    for script, logfile, needs_sudo in services:
        script_path = os.path.join(PROJECT_ROOT, script)

        # Kill existing process using exact script path matching to avoid self-killing
        subprocess.run(
            ["pkill", "-f", f"python3 {script_path}"],
            capture_output=True
        )
        log.info(f"Stopped {script}")

        cmd = (["sudo", "python3", script_path] if needs_sudo else ["python3", script_path])
        subprocess.Popen(
            cmd,
            stdout=open(logfile, "a"),
            stderr=subprocess.STDOUT,
            cwd=PROJECT_ROOT
        )
        log.info(f"Restarted {script}" + (" (sudo)" if needs_sudo else ""))

def send_telegram_notification(old_ip, new_ip):
    """Sends Telegram notification about IP change."""
    try:
        import requests

        msg = (
            f"🔄 *HONEYPOT IP CHANGED*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"Old IP: `{old_ip}`\n"
            f"New IP: `{new_ip}`\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"✅ .env updated automatically\n"
            f"✅ Services restarted\n"
            f"✅ UFW rules updated\n"
            f"✅ Zeek bridges checked"
        )

        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
            timeout=10
        )
        log.info("Telegram notification sent")
    except Exception as e:
        log.error(f"Telegram notification error: {e}")

# ==============================================================================
# MAIN
# ==============================================================================

def main():
    current_ip = get_current_ip()
    if not current_ip:
        log.error("Could not detect current IP — aborting")
        return

    saved_ip = get_saved_ip()

    if not saved_ip:
        save_ip(current_ip)
        log.info(f"First run — saved IP: {current_ip}")
        return

    update_zeek_bridges()

    if current_ip == saved_ip:
        return

    log.info(f"IP CHANGED: {saved_ip} → {current_ip}")
    log.info("Starting automatic update...")

    update_env_var("HONEYPOT_IP", current_ip)
    update_ufw(saved_ip, current_ip)
    update_zeek_bridges()
    update_old_honeypot_ips(saved_ip)
    save_ip(current_ip)
    restart_services()
    send_telegram_notification(saved_ip, current_ip)

    log.info("All updates completed successfully!")

if __name__ == "__main__":
    main()
