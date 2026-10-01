#!/usr/bin/env python3
"""
IOT Honeypot — Daily Telegram Report
=====================================
Sends a concise daily summary to Telegram covering:
  - Event counts per honeypot (last 24h)
  - Authentication stats
  - Top external attacker IPs (private/internal IPs excluded)
  - Top passwords attempted
"""

import os
import sys
import requests
import warnings
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
warnings.filterwarnings("ignore")

# ==============================================================================
# CONFIG
# ==============================================================================

TELEGRAM_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

ES_URL  = os.getenv("ELASTIC_HOST", "https://localhost:9200")
ES_USER = os.getenv("ELASTIC_USER", "elastic")
ES_PASS = os.getenv("ELASTIC_PASSWORD")

ES_VERIFY_SSL = os.getenv("ES_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

missing = []
if not TELEGRAM_TOKEN: missing.append("TELEGRAM_BOT_TOKEN")
if not TELEGRAM_CHAT_ID: missing.append("TELEGRAM_CHAT_ID")
if not ES_PASS: missing.append("ELASTIC_PASSWORD")
if missing:
    print(f"[FATAL ERROR] Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
    print("[FATAL ERROR] Ensure your .env file is populated correctly.", file=sys.stderr)
    sys.exit(1)

TIME_RANGE = "now-24h"

# IPs/subnets excluded from "Top Attacker IPs" — honeypot infrastructure,
# local network, and well-known services. Not external threat sources.
EXCLUDED_IPS = {"0.0.0.0", "127.0.0.1", "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"}

# Private/internal IPv4 ranges (RFC1918) + link-local + loopback
EXCLUDED_PREFIXES = (
    "10.",        # RFC1918
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",  # RFC1918 172.16.0.0/12
    "192.168.",   # RFC1918 — entire local subnet, not just the honeypot IP
    "127.",       # loopback
    "169.254.",   # link-local
    "fe80:",      # IPv6 link-local
    "::1",        # IPv6 loopback
)

# ==============================================================================
# ELASTICSEARCH (via requests — consistent with alert.py / attacker_profiler.py)
# ==============================================================================

_session = requests.Session()
_session.verify = ES_VERIFY_SSL
_session.auth   = (ES_USER, ES_PASS)
_session.headers.update({"Content-Type": "application/json"})


def es_count(query):
    """Returns document count matching query, or 0 on error."""
    try:
        r = _session.post(
            f"{ES_URL}/filebeat-*/_count",
            json={"query": query},
            timeout=10
        )
        r.raise_for_status()
        return r.json().get("count", 0)
    except Exception as e:
        print(f"[ERROR] es_count: {e}")
        return 0


def es_top(field, query, size=10):
    """Returns top terms for a field as [(value, count), ...], or [] on error."""
    try:
        r = _session.post(
            f"{ES_URL}/filebeat-*/_search",
            json={
                "size": 0,
                "query": query,
                "aggs": {"top": {"terms": {"field": field, "size": size}}}
            },
            timeout=10
        )
        r.raise_for_status()
        buckets = r.json().get("aggregations", {}).get("top", {}).get("buckets", [])
        return [(b["key"], b["doc_count"]) for b in buckets]
    except Exception as e:
        print(f"[ERROR] es_top: {e}")
        return []


# ==============================================================================
# HELPERS
# ==============================================================================

def is_excluded_ip(ip):
    """Returns True if IP belongs to honeypot infrastructure (not a real attacker)."""
    if not ip or ip == "?":
        return True
    if ip in EXCLUDED_IPS:
        return True
    return any(ip.startswith(p) for p in EXCLUDED_PREFIXES)


def time_filter():
    return {"range": {"@timestamp": {"gte": TIME_RANGE}}}


def with_time(must_list):
    return {"bool": {"must": [time_filter()] + must_list}}


# ==============================================================================
# TELEGRAM
# ==============================================================================

def send_telegram(message):
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=10
        )
        if r.status_code != 200:
            print(f"[ERROR] Telegram returned {r.status_code}: {r.text[:100]}")
    except Exception as e:
        print(f"[ERROR] Telegram: {e}")


# ==============================================================================
# REPORT GENERATION
# ==============================================================================

def generate_report():
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── Event counts ─────────────────────────────────────────────────────
    total    = es_count(time_filter())
    cowrie   = es_count(with_time([{"match": {"honeypot": "cowrie"}}]))
    conpot   = es_count(with_time([{"match": {"honeypot": "conpot"}}]))
    dionaea  = es_count(with_time([{"match": {"honeypot": "dionaea"}}]))
    suricata = es_count(with_time([
        {"match": {"honeypot": "suricata_ids"}},
        {"match": {"event_type": "alert"}}
    ]))

    # ── Authentication stats ────────────────────────────────────────────
    logins_ok = es_count(with_time([
        {"match": {"honeypot": "cowrie"}},
        {"match": {"eventid": "cowrie.login.success"}}
    ]))
    logins_fail = es_count(with_time([
        {"match": {"honeypot": "cowrie"}},
        {"match": {"eventid": "cowrie.login.failed"}}
    ]))
    commands = es_count(with_time([
        {"match": {"honeypot": "cowrie"}},
        {"match": {"eventid": "cowrie.command.input"}}
    ]))

    # ── Top external attacker IPs ──────────────────────────────────────
    # Restrict to Cowrie/Conpot/Dionaea only — these honeypots only log
    # inbound connections, so src_ip is always the attacker.
    raw_top_ips = es_top("src_ip", with_time([
        {"exists": {"field": "src_ip"}},
        {"terms":  {"honeypot": ["cowrie", "conpot", "dionaea"]}}
    ]), size=20)
    top_ips = [(ip, cnt) for ip, cnt in raw_top_ips if not is_excluded_ip(ip)][:5]

    # ── Top passwords attempted ─────────────────────────────────────────
    top_pass = es_top("password", with_time([
        {"match": {"honeypot": "cowrie"}},
        {"match": {"eventid": "cowrie.login.failed"}}
    ]), size=5)

    # ── Build message ────────────────────────────────────────────────────
    msg  = f"📊 <b>IOT Honeypot - Daily Report</b>\n"
    msg += f"📅 {now}\n"
    msg += f"{'─' * 30}\n\n"

    if total == 0:
        msg += "⚠️ No events recorded in the last 24 hours.\n"
        msg += "The honeypot may have been offline during this period.\n"
        send_telegram(msg)
        print(f"[SUCCESS] Daily report (empty) sent at {now}")
        return

    msg += f"📈 <b>Events Summary (Last 24h)</b>\n"
    msg += f"  Total Events: <b>{total:,}</b>\n"
    msg += f"  🐄 Cowrie SSH: {cowrie:,}\n"
    msg += f"  🏭 Conpot SCADA: {conpot:,}\n"
    msg += f"  🦠 Dionaea Malware: {dionaea:,}\n"
    msg += f"  🛡 Suricata Alerts: {suricata:,}\n\n"

    msg += f"🔐 <b>Authentication</b>\n"
    msg += f"  ✅ Successful Logins: {logins_ok}\n"
    msg += f"  ❌ Failed Attempts: {logins_fail:,}\n"
    msg += f"  ⌨️ Commands Executed: {commands}\n\n"

    if top_ips:
        msg += f"🌐 <b>Top External Attacker IPs</b>\n"
        for ip, count in top_ips:
            msg += f"  • {ip}: {count:,}\n"
        msg += "\n"
    else:
        msg += f"🌐 <b>Top External Attacker IPs</b>\n"
        msg += "  No external IPs observed in this period.\n\n"

    if top_pass:
        msg += f"🔑 <b>Top Passwords Tried</b>\n"
        for pwd, count in top_pass:
            msg += f"  • {pwd}: {count}\n"

    send_telegram(msg)
    print(f"[SUCCESS] Daily report sent at {now}")


if __name__ == "__main__":
    generate_report()
