#!/usr/bin/env python3
"""
SSH Session Replay (Secured & Cleaned)
======================================
Replays attacker SSH sessions from Cowrie JSON logs.
Shows keystrokes in real-time with timing, or instant mode.

Usage:
  python3 session_replay.py                # List all sessions
  python3 session_replay.py <session_id>       # Replay a session (real-time)
  python3 session_replay.py <session_id> -f    # Replay fast (no delays)
  python3 session_replay.py <session_id> -e    # Export to text file
"""

import json
import sys
import time
import os
import re
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()

# ==============================================================================
# CONFIG & SECURE ENV VARIABLES
# ==============================================================================

PROJECT_ROOT = os.getenv("PROJECT_ROOT")

if not PROJECT_ROOT:
    print("[FATAL ERROR] Missing required environment variable: PROJECT_ROOT", file=sys.stderr)
    print("[FATAL ERROR] Ensure your .env file is populated correctly.", file=sys.stderr)
    sys.exit(1)

COWRIE_LOG = os.getenv(
    "COWRIE_LOG_PATH",
    "/var/lib/docker/volumes/docker_cowrie-var/_data/log/cowrie/cowrie.json"
)
EXPORT_DIR = os.path.join(PROJECT_ROOT, "logs_and_reports/session_replays")
SPEED      = float(os.getenv("REPLAY_SPEED", "1.0"))

os.makedirs(EXPORT_DIR, exist_ok=True)
