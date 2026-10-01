#!/usr/bin/env python3
"""
ML-based Anomaly Detection & Behavior Clustering (Secured Version)
=================================================================
Analyzes attacker profiles from Elasticsearch using Isolation Forest & K-Means.
"""

import json
import sys
import os
import logging
import requests
import numpy as np
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

# ==============================================================================
# CONFIG & SECURE ENV VARIABLES
# ==============================================================================

PROJECT_ROOT = os.getenv("PROJECT_ROOT")

ES_URL  = os.getenv("ELASTIC_HOST", "https://localhost:9200")
ES_USER = os.getenv("ELASTIC_USER", "elastic")
ES_PASS = os.getenv("ELASTIC_PASSWORD")
ES_VERIFY_SSL = os.getenv("ES_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

ES_INDEX_PROFILES = os.getenv("ES_ATTACKER_INDEX", "attacker-profiles")
ES_INDEX_ML       = os.getenv("ES_ML_INDEX", "ml-analysis")

TELEGRAM_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

LOG_FILE = os.path.join(PROJECT_ROOT, "logs_and_reports/ml_analyzer.log") if PROJECT_ROOT else "logs_and_reports/ml_analyzer.log"

IF_CONTAMINATION        = float(os.getenv("ML_CONTAMINATION", 0.1))
IF_N_ESTIMATORS         = int(os.getenv("ML_N_ESTIMATORS", 200))
KMEANS_N_CLUSTERS       = int(os.getenv("ML_N_CLUSTERS", 4))
ANOMALY_ALERT_THRESHOLD = float(os.getenv("ML_ALERT_THRESHOLD", 0.7))

# ==============================================================================
# VALIDATION
# ==============================================================================

missing = []
if not PROJECT_ROOT:     missing.append("PROJECT_ROOT")
if not ES_PASS:          missing.append("ELASTIC_PASSWORD")
if not TELEGRAM_TOKEN:   missing.append("TELEGRAM_BOT_TOKEN")
if not TELEGRAM_CHAT_ID: missing.append("TELEGRAM_CHAT_ID")

if missing:
    print(f"[FATAL ERROR] Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
    print("[FATAL ERROR] Ensure your .env file is populated correctly.", file=sys.stderr)
    sys.exit(1)

os.makedirs(os.path.dirname(os.path.abspath(LOG_FILE)), exist_ok=True)

# ==============================================================================
# LOGGING
# ==============================================================================

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
# ELASTICSEARCH HELPERS
# ==============================================================================

def es_get(path):
    try:
        r = requests.get(f"{ES_URL}{path}", auth=(ES_USER, ES_PASS),
                         verify=ES_VERIFY_SSL, timeout=10)
        return r.json()
    except Exception as e:
        log.error(f"ES GET error: {e}")
        return {}

def es_post(path, body):
    try:
        r = requests.post(f"{ES_URL}{path}", auth=(ES_USER, ES_PASS),
                          verify=ES_VERIFY_SSL, json=body, timeout=10)
        return r.json()
    except Exception as e:
        log.error(f"ES POST error: {e}")
        return {}

def es_put(path, body):
    try:
        r = requests.put(f"{ES_URL}{path}", auth=(ES_USER, ES_PASS),
                         verify=ES_VERIFY_SSL, json=body, timeout=10)
        return r.json()
    except Exception as e:
        log.error(f"ES PUT error: {e}")
        return {}
