#!/usr/bin/env python3
"""
Dionaea -> Triage Auto-Uploader
================================
Monitors Dionaea binary drop folder and automatically submits
new malware samples to Hatching Triage (tria.ge) for dynamic analysis.
"""

import time
import requests
import os
import sys
import logging
import hashlib
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv

load_dotenv()

# --- Configuration ---
PROJECT_ROOT = os.getenv("PROJECT_ROOT")
API_KEY      = os.getenv("TRIAGE_API_KEY", "")

missing = []
if not PROJECT_ROOT: missing.append("PROJECT_ROOT")
if not API_KEY: missing.append("TRIAGE_API_KEY")
if missing:
    print(f"[FATAL ERROR] Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
    print("[FATAL ERROR] Ensure your .env file is populated correctly.", file=sys.stderr)
    sys.exit(1)

WATCH_DIRECTORY        = os.path.join(PROJECT_ROOT, "binaries/dionaea")
LOG_FILE               = os.path.join(PROJECT_ROOT, "logs_and_reports/uploader.log")
SUBMITTED_HASHES_FILE  = os.path.join(PROJECT_ROOT, "logs_and_reports/submitted_hashes.txt")

ALLOWED_EXTENSIONS = {
    '.exe', '.dll', '.bin', '.elf',
    '.sh', '.py', '.js', '.vbs',
    '.doc', '.docx', '.xls', '.pdf',
    '.zip', '.rar', '.7z'
}

# --- Logging Setup ---
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# --- Helper Functions ---
def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def is_already_submitted(file_hash):
    if not os.path.exists(SUBMITTED_HASHES_FILE):
        return False
    with open(SUBMITTED_HASHES_FILE, "r") as f:
        return file_hash in f.read()

def mark_as_submitted(file_hash):
    os.makedirs(os.path.dirname(SUBMITTED_HASHES_FILE), exist_ok=True)
    with open(SUBMITTED_HASHES_FILE, "a") as f:
        f.write(file_hash + "\n")

# --- Event Handler ---
class MalwareHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        filepath = event.src_path
        filename = os.path.basename(filepath)
        ext = os.path.splitext(filename)[1].lower()

        if ext not in ALLOWED_EXTENSIONS:
            log.info(f"[SKIP] Ignored (unsupported type): {filename}")
            return

        log.info(f"[DETECTED] New sample: {filename}")
        time.sleep(3)  # Brief pause to ensure dionaea finishes writing the file

        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            log.warning(f"[SKIP] File missing or empty: {filename}")
            return

        file_hash = get_file_hash(filepath)
        if is_already_submitted(file_hash):
            log.info(f"[SKIP] Already submitted: {filename} ({file_hash[:8]}...)")
            return

        self.upload_to_triage(filepath, file_hash)

    def upload_to_triage(self, filepath, file_hash, retry=0):
        filename = os.path.basename(filepath)
        log.info(f"[UPLOAD] Submitting: {filename}")

        url = "https://api.tria.ge/v0/samples"
        headers = {"Authorization": f"Bearer {API_KEY}"}

        # Hatching Triage API payload format
        config = {
            "kind": "file",
            "interactive": False
        }

        try:
            with open(filepath, "rb") as f:
                files = {
                    "file": (filename, f),
                    "_json": (None, json.dumps(config), "application/json")
                }
                response = requests.post(
                    url,
                    headers=headers,
                    files=files,
                    timeout=30
                )

            if response.status_code in (200, 201):
                res_data = response.json()
                sample_id = res_data.get("id", "unknown")
                log.info(f"[SUCCESS] Sample ID: {sample_id}")
                log.info(f"[REPORT]  https://tria.ge/{sample_id}")
                mark_as_submitted(file_hash)

            elif response.status_code == 429:
                if retry < 3:
                    log.warning(f"[RATE LIMIT] Waiting 60s (attempt {retry+1}/3)")
                    time.sleep(60)
                    self.upload_to_triage(filepath, file_hash, retry+1)
                else:
                    log.error("[RATE LIMIT] Max retries reached")

            else:
                log.error(f"[FAILED] Status: {response.status_code}")
                log.error(f"[DETAIL] {response.text}")

        except requests.exceptions.Timeout:
            log.error(f"[TIMEOUT] Request timed out: {filename}")
        except requests.exceptions.ConnectionError:
            log.error("[CONNECTION] Cannot reach Triage API")
        except Exception as e:
            log.error(f"[ERROR] Unexpected: {e}")

# --- Main Entry Point ---
if __name__ == "__main__":
    if not os.path.exists(WATCH_DIRECTORY):
        log.error(f"Directory not found: {WATCH_DIRECTORY}")
        sys.exit(1)

    event_handler = MalwareHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIRECTORY, recursive=False)

    log.info("=" * 52)
    log.info("    Dionaea → Triage Auto-Uploader  v2.0")
    log.info("=" * 52)
    log.info(f"Watching : {WATCH_DIRECTORY}")
    log.info(f"Log File : {LOG_FILE}")
    log.info("Press Ctrl+C to stop")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Stopping service...")
        observer.stop()
    observer.join()
    log.info("Service stopped.")
