#!/usr/bin/env python3
"""
IOT Honeypot — Alert Engine
============================
Production-grade real-time alerting system using .env dynamic configuration.

Severity Levels (SOC Standard):
  P1 CRITICAL — Immediate action required (SSH login, malware, APT)
  P2 HIGH     — Investigate within 1 hour (brute force, scanner)
  P3 MEDIUM   — Review within 24 hours (port scan, SCADA probe)
  P4 LOW      — Informational (ping sweep, single connection)
"""

import os
import re
import sys
import json
import time
import logging
import requests
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

# ==============================================================================
# CONFIG
# ==============================================================================

class Config:
    # Project Root
    PROJECT_ROOT = os.getenv("PROJECT_ROOT")

    # Telegram Secrets
    TELEGRAM_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

    # Elasticsearch
    ES_URL        = os.getenv("ELASTIC_HOST", "https://localhost:9200")
    ES_USER       = os.getenv("ELASTIC_USER", "elastic")
    ES_PASS       = os.getenv("ELASTIC_PASSWORD")
    ES_VERIFY_SSL = os.getenv("ES_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

    # Honeypot Infrastructure
    HONEYPOT_IP   = os.getenv("HONEYPOT_IP", "127.0.0.1")
    HONEYPOT_NAME = os.getenv("HONEYPOT_NAME", "IoT Security Gateway Hub")

    # Log Paths — built from PROJECT_ROOT
    LOG_FILE    = os.path.join(PROJECT_ROOT, "logs_and_reports/alert.log") if PROJECT_ROOT else "logs_and_reports/alert.log"
    STATE_FILE  = os.path.join(PROJECT_ROOT, "logs_and_reports/alert_state.json") if PROJECT_ROOT else "logs_and_reports/alert_state.json"
    COWRIE_LOG  = os.getenv("COWRIE_LOG_PATH", "/var/lib/docker/volumes/docker_cowrie-var/_data/log/cowrie/cowrie.json")
    DIONAEA_LOG = os.path.join(PROJECT_ROOT, "dionaea/var/log/dionaea/dionaea.log") if PROJECT_ROOT else "dionaea/var/log/dionaea/dionaea.log"
    CONPOT_LOG  = os.path.join(PROJECT_ROOT, "conpot/logs/conpot.log") if PROJECT_ROOT else "conpot/logs/conpot.log"
    NOTICE_LOG  = os.path.join(PROJECT_ROOT, "logs_and_reports/notice.log") if PROJECT_ROOT else "logs_and_reports/notice.log"

    # Detection & Loop Thresholds
    LOOP_INTERVAL       = int(os.getenv("LOOP_INTERVAL", 10))
    BRUTE_FORCE_MIN     = int(os.getenv("BRUTE_FORCE_MIN", 10))
    SCADA_ATTACK_MIN    = int(os.getenv("SCADA_ATTACK_MIN", 20))
    STATE_SAVE_INTERVAL = 60
    ES_TIMEOUT          = 10
    ES_RETRY_MAX        = 3
    TELEGRAM_TIMEOUT    = 10

    # IP Filters
    EXCLUDED_IPS     = set(ip.strip() for ip in os.getenv("EXCLUDED_IPS", "127.0.0.1,0.0.0.0").split(","))
    EXCLUDED_SUBNETS = ("172.", "127.", "169.", "10.0.0.")

    @classmethod
    def validate_secrets(cls):
        """Fail-fast validation to ensure required environment variables exist."""
        missing = []
        if not cls.PROJECT_ROOT:
            missing.append("PROJECT_ROOT")
        if not cls.TELEGRAM_TOKEN:
            missing.append("TELEGRAM_BOT_TOKEN")
        if not cls.TELEGRAM_CHAT_ID:
            missing.append("TELEGRAM_CHAT_ID")
        if not cls.ES_PASS:
            missing.append("ELASTIC_PASSWORD")

        if missing:
            print(f"[FATAL ERROR] Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
            print("[FATAL ERROR] Ensure your .env file is populated correctly.", file=sys.stderr)
            sys.exit(1)


# Perform validation on load
Config.validate_secrets()

# Ensure parent directory for log file exists
os.makedirs(os.path.dirname(os.path.abspath(Config.LOG_FILE)), exist_ok=True)

# ==============================================================================
# LOGGING
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("honeypot.alerts")

# ==============================================================================
# HELPERS
# ==============================================================================

def is_excluded_ip(ip):
    if not ip or ip == "?":
        return True
    if ip in Config.EXCLUDED_IPS:
        return True
    return any(ip.startswith(p) for p in Config.EXCLUDED_SUBNETS)

def local_time(utc_ts):
    try:
        ts = utc_ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts[:26] + "+00:00")
        local = dt.astimezone(timezone(timedelta(hours=3)))
        return local.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return utc_ts[:19] if utc_ts else "?"

def now_key(fmt="%Y%m%d%H"):
    return datetime.now().strftime(fmt)

def extract_ports(msg):
    m = re.search(r'Ports:\s*([\d,/tcpud ]+)', msg)
    if m:
        ports = re.findall(r'(\d+)', m.group(1))
        ports = [p for p in ports if 20 <= int(p) <= 65535]
        return ", ".join(sorted(set(ports), key=int)[:10]) if ports else "?"
    clean = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '', msg)
    ports = re.findall(r'\b(\d{2,5})\b', clean)
    ports = [p for p in ports if 20 <= int(p) <= 65535]
    return ", ".join(sorted(set(ports), key=int)[:10]) if ports else "?"

def get_zeek_field(msg, key):
    for part in msg.split("|"):
        if key in part and ":" in part:
            return part.split(":", 1)[1].strip()
    return "?"

# ==============================================================================
# STATE MANAGER
# ==============================================================================

class StateManager:
    def __init__(self):
        self._alerted   = set()
        self._positions = {}
        self._last_save = 0
        self._load()

    def _load(self):
        if os.path.exists(Config.STATE_FILE):
            try:
                with open(Config.STATE_FILE) as f:
                    data = json.load(f)
                self._alerted   = set(data.get("alerted", []))
                self._positions = data.get("positions", {})
                log.info(f"State loaded: {len(self._alerted)} dedup keys")
            except Exception as e:
                log.warning(f"State load failed, starting fresh: {e}")

    def save(self, force=False):
        now = time.time()
        if not force and now - self._last_save < Config.STATE_SAVE_INTERVAL:
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(Config.STATE_FILE)), exist_ok=True)
            with open(Config.STATE_FILE, "w") as f:
                json.dump({
                    "alerted":   list(self._alerted),
                    "positions": self._positions
                }, f)
            self._last_save = now
        except Exception as e:
            log.error(f"State save failed: {e}")

    def seen(self, key):
        return key in self._alerted

    def mark(self, key):
        self._alerted.add(key)

    def get_position(self, filepath):
        return self._positions.get(filepath, 0)

    def set_position(self, filepath, pos):
        self._positions[filepath] = pos

    def cleanup(self):
        if len(self._alerted) > 3000:
            self._alerted = set(sorted(self._alerted)[-1500:])
            log.info(f"State pruned to {len(self._alerted)} keys")

# ==============================================================================
# ELASTICSEARCH CLIENT
# ==============================================================================

class ESClient:
    def __init__(self):
        self._session = requests.Session()
        self._session.verify = Config.ES_VERIFY_SSL
        self._session.auth   = (Config.ES_USER, Config.ES_PASS)
        self._session.headers.update({"Content-Type": "application/json"})

    def search(self, body, index="filebeat-*"):
        for attempt in range(Config.ES_RETRY_MAX):
            try:
                r = self._session.post(
                    f"{Config.ES_URL}/{index}/_search",
                    json=body,
                    timeout=Config.ES_TIMEOUT
                )
                r.raise_for_status()
                return r.json()
            except requests.exceptions.ConnectionError as e:
                wait = 2 ** attempt
                log.warning(f"ES retry {attempt+1} in {wait}s: {e}")
                time.sleep(wait)
            except Exception as e:
                log.error(f"ES search error: {e}")
                return {}
        return {}

    def health_check(self):
        try:
            r = self._session.get(
                f"{Config.ES_URL}/_cluster/health",
                timeout=Config.ES_TIMEOUT
            )
            return r.status_code == 200
        except Exception as e:
            log.error(f"ES Health Check Failed: {e}")
            return False

# ==============================================================================
# TELEGRAM NOTIFIER
# ==============================================================================

class TelegramNotifier:
    PRIORITY_EMOJI = {"P1": "🔴", "P2": "🟠", "P3": "🔵", "P4": "🟡"}

    def send(self, priority, title, fields, log_path=None):
        emoji = self.PRIORITY_EMOJI.get(priority, "⚪")
        lines = [
            f"{emoji} <b>[{priority}] {title}</b>",
            "━━━━━━━━━━━━━━━━━━━━━━━━",
        ]
        for k, v in fields.items():
            if v and v != "?":
                if any(c in k.lower() for c in ["ip", "hash", "session"]):
                    lines.append(f"{k:<10}: <code>{v}</code>")
                else:
                    lines.append(f"{k:<10}: {v}")
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━")
        if log_path:
            lines.append(f"📁 {log_path}")
        self._send_raw("\n".join(lines))

    def _send_raw(self, text):
        for attempt in range(3):
            try:
                r = requests.post(
                    f"https://api.telegram.org/bot{Config.TELEGRAM_TOKEN}/sendMessage",
                    data={"chat_id": Config.TELEGRAM_CHAT_ID,
                          "text": text, "parse_mode": "HTML"},
                    timeout=Config.TELEGRAM_TIMEOUT
                )
                if r.status_code == 200:
                    log.info(f"Alert sent: {text.splitlines()[0][:60]}")
                    return True
                log.warning(f"Telegram {r.status_code}: {r.text[:80]}")
            except requests.exceptions.ConnectionError:
                time.sleep(2 ** attempt)
            except Exception as e:
                log.error(f"Telegram error: {e}")
                break
        return False

# ==============================================================================
# FILE TAILER
# ==============================================================================

class FileTailer:
    def __init__(self, state):
        self._state = state

    def read_new(self, filepath, filter_fn=None):
        if not os.path.exists(filepath):
            return []
        pos = self._state.get_position(filepath)
        try:
            with open(filepath, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size < pos:
                    log.info(f"Log rotated: {filepath}")
                    pos = 0
                f.seek(pos)
                raw     = f.read()
                new_pos = f.tell()
            self._state.set_position(filepath, new_pos)
            lines = raw.decode("utf-8", errors="ignore").splitlines()
            lines = [l for l in lines if l.strip()]
            if filter_fn:
                lines = [l for l in lines if filter_fn(l)]
            return lines
        except PermissionError:
            log.warning(f"Permission denied: {filepath}")
            return []
        except Exception as e:
            log.error(f"File read error {filepath}: {e}")
            return []

# ==============================================================================
# DETECTORS
# ==============================================================================

class SSHDetector:
    def __init__(self, es, notifier, state):
        self._es = es
        self._notifier = notifier
        self._state = state

    def check_login_success(self):
        result = self._es.search({
            "size": 10,
            "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"must": [
                {"term":  {"honeypot": "cowrie"}},
                {"term":  {"eventid":  "cowrie.login.success"}},
                {"range": {"@timestamp": {"gte": "now-1m"}}}
            ]}}
        })
        for hit in result.get("hits", {}).get("hits", []):
            src     = hit["_source"]
            session = src.get("session", "")
            key     = f"ssh-login-{session}"
            if self._state.seen(key):
                continue
            self._notifier.send(
                priority = "P1",
                title    = "SSH LOGIN SUCCESS",
                fields   = {
                    "IP":      src.get("src_ip", "?"),
                    "User":    src.get("username", "?"),
                    "Pass":    src.get("password", "?"),
                    "Session": session,
                    "Time":    local_time(src.get("timestamp", "")),
                },
                log_path = Config.COWRIE_LOG
            )
            self._state.mark(key)

    def check_brute_force(self):
        result = self._es.search({
            "size": 0,
            "query": {"bool": {"must": [
                {"term":  {"honeypot": "cowrie"}},
                {"term":  {"eventid":  "cowrie.login.failed"}},
                {"range": {"@timestamp": {"gte": "now-1m"}}}
            ]}},
            "aggs": {"by_ip": {
                "terms": {"field": "src_ip", "size": 10},
                "aggs":  {"users": {"terms": {"field": "username", "size": 5}}}
            }}
        })
        hour = now_key("%Y%m%d%H")
        for b in result.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
            if b["doc_count"] < Config.BRUTE_FORCE_MIN:
                continue
            ip  = b["key"]
            key = f"bf-{ip}-{hour}"
            if self._state.seen(key):
                continue
            users = [u["key"] for u in b.get("users", {}).get("buckets", [])]
            self._notifier.send(
                priority = "P2",
                title    = "SSH BRUTE FORCE",
                fields   = {
                    "IP":        ip,
                    "Attempts":  f"{b['doc_count']}/min",
                    "Usernames": ", ".join(users) or "?",
                },
                log_path = Config.COWRIE_LOG
            )
            self._state.mark(key)


class SCADADetector:
    def __init__(self, es, notifier, state):
        self._es = es
        self._notifier = notifier
        self._state = state

    def check_scada_attack(self):
        result = self._es.search({
            "size": 0,
            "query": {"bool": {"must": [
                {"term":  {"honeypot": "conpot"}},
                {"range": {"@timestamp": {"gte": "now-1m"}}}
            ]}},
            "aggs": {"by_ip": {"terms": {"field": "src_ip", "size": 5}}}
        })
        total = result.get("hits", {}).get("total", {}).get("value", 0)
        key   = f"scada-{now_key('%Y%m%d%H%M')[:11]}"
        if total < Config.SCADA_ATTACK_MIN or self._state.seen(key):
            return
        buckets = result.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
        top_ip  = "?"
        for b in buckets:
            if not is_excluded_ip(b["key"]):
                top_ip = b["key"]
                break
        self._notifier.send(
            priority = "P2",
            title    = "SCADA ATTACK DETECTED",
            fields   = {
                "Target":   Config.HONEYPOT_IP,
                "Attacker": top_ip,
                "Rate":     f"{total} req/min",
                "Protocol": "Modbus/S7Comm/HTTP",
            },
            log_path = Config.CONPOT_LOG
        )
        self._state.mark(key)


class MalwareDetector:
    def __init__(self, es, notifier, state):
        self._es = es
        self._notifier = notifier
        self._state = state

    def check_malware_captured(self):
        result = self._es.search({
            "size": 5,
            "query": {"bool": {"must": [
                {"term":  {"honeypot": "triage_uploader"}},
                {"match": {"message":  "SUCCESS"}},
                {"range": {"@timestamp": {"gte": "now-2m"}}}
            ]}}
        })
        for hit in result.get("hits", {}).get("hits", []):
            key = f"malware-{hit['_id']}"
            if self._state.seen(key):
                continue
            msg = hit["_source"].get("message", "")
            ts  = hit["_source"].get("@timestamp", "")
            h   = re.search(r'[a-f0-9]{64}', msg)
            sha = h.group(0)[:16] + "..." if h else "see Triage"
            self._notifier.send(
                priority = "P1",
                title    = "MALWARE CAPTURED",
                fields   = {
                    "SHA256":  sha,
                    "Source":  "Dionaea honeypot",
                    "Time":    local_time(ts),
                    "Sandbox": "https://tria.ge",
                },
                log_path = Config.DIONAEA_LOG
            )
            self._state.mark(key)


class NetworkDetector:
    NOTICE_MAP = {
        "PORT SCAN":        ("P3", "PORT SCAN DETECTED"),
        "PING SWEEP":       ("P4", "PING SWEEP DETECTED"),
        "HONEYPOT ACCESS":  ("P3", "HONEYPOT ACCESS"),
        "SSH BRUTE FORCE":  ("P2", "SSH BRUTE FORCE"),
        "MALWARE DOWNLOAD": ("P1", "MALWARE DOWNLOAD ATTEMPT"),
        "SCANNER":          ("P3", "SCANNER TOOL DETECTED"),
    }

    def __init__(self, notifier, state):
        self._notifier = notifier
        self._state    = state
        self._tailer   = FileTailer(state)

    def check_zeek_notices(self):
        lines = self._tailer.read_new(
            Config.NOTICE_LOG,
            filter_fn=lambda l: (
                not l.startswith("#") and
                ("HoneypotDetect::" in l or "Signatures::" in l)
            )
        )
        for line in lines:
            self._process_line(line)

    def _process_line(self, line):
        parts = line.split("\t")
        if len(parts) < 12:
            return
        msg      = parts[11]
        ts       = parts[0]
        line_key = f"zeek-line-{ts}"
        if self._state.seen(line_key):
            return
        self._state.mark(line_key)

        attacker = get_zeek_field(msg, "Attacker")
        if is_excluded_ip(attacker):
            return

        hour = ts[:13]
        for keyword, (priority, title) in self.NOTICE_MAP.items():
            if keyword not in msg:
                continue
            dedup_key = f"zeek-{keyword.replace(' ','-').lower()}-{attacker}-{hour}"
            if self._state.seen(dedup_key):
                return
            fields   = self._build_fields(keyword, msg, attacker, ts)
            log_path = self._get_log_path(msg)
            self._notifier.send(priority, title, fields, log_path)
            self._state.mark(dedup_key)
            return

    def _build_fields(self, keyword, msg, attacker, ts):
        fields = {"IP": attacker}
        if keyword == "PORT SCAN":
            fields["Ports"] = extract_ports(msg)
            fields["Tool"]  = "nmap/masscan"
        elif keyword == "HONEYPOT ACCESS":
            svc = get_zeek_field(msg, "Service")
            tgt = get_zeek_field(msg, "Target")
            if svc != "?": fields["Service"] = svc
            if tgt != "?": fields["Target"]  = tgt
        elif keyword == "MALWARE DOWNLOAD":
            f = get_zeek_field(msg, "File")
            if f != "?": fields["File"] = f
        elif keyword == "SCANNER":
            t = get_zeek_field(msg, "Tool")
            if t != "?": fields["Tool"] = t[:50]
        try:
            epoch = float(ts)
            dt    = datetime.fromtimestamp(epoch, tz=timezone.utc)
            local = dt.astimezone(timezone(timedelta(hours=3)))
            fields["Time"] = local.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        return fields

    def _get_log_path(self, msg):
        m = msg.lower()
        if "cowrie" in m or "ssh" in m:   return Config.COWRIE_LOG
        if "dionaea" in m or "smb" in m:   return Config.DIONAEA_LOG
        if "conpot" in m or "scada" in m:  return Config.CONPOT_LOG
        return Config.NOTICE_LOG

# ==============================================================================
# ALERT ENGINE
# ==============================================================================

class AlertEngine:
    def __init__(self):
        self._state    = StateManager()
        self._es       = ESClient()
        self._notifier = TelegramNotifier()
        self._ssh      = SSHDetector(self._es, self._notifier, self._state)
        self._scada    = SCADADetector(self._es, self._notifier, self._state)
        self._malware  = MalwareDetector(self._es, self._notifier, self._state)
        self._network  = NetworkDetector(self._notifier, self._state)

    def _startup_check(self):
        log.info("Running startup checks...")
        if not self._es.health_check():
            log.error("Elasticsearch unreachable — aborting")
            return False
        log.info("Elasticsearch: OK")
        if not os.path.exists(Config.NOTICE_LOG):
            log.warning(f"Zeek notice log missing: {Config.NOTICE_LOG}")
        if not os.access(Config.COWRIE_LOG, os.R_OK):
            log.warning(f"Cowrie log not readable (needs sudo): {Config.COWRIE_LOG}")
        return True

    def _run_once(self):
        self._network.check_zeek_notices()
        self._ssh.check_login_success()
        self._ssh.check_brute_force()
        self._scada.check_scada_attack()
        self._malware.check_malware_captured()
        self._state.cleanup()
        self._state.save()

    def run(self):
        log.info("=" * 55)
        log.info("  IOT Honeypot Alert Engine")
        log.info(f"  {Config.HONEYPOT_IP} — {Config.HONEYPOT_NAME}")
        log.info("=" * 55)

        if not self._startup_check():
            sys.exit(1)

        self._notifier.send(
            priority = "P4",
            title    = "ALERT ENGINE ONLINE",
            fields   = {
                "Honeypot": f"{Config.HONEYPOT_IP}",
                "Site":     Config.HONEYPOT_NAME,
                "Monitors": "SSH · SCADA · Malware · Network",
            }
        )
        log.info("Monitoring started.")

        while True:
            try:
                self._run_once()
            except Exception as e:
                log.error(f"Loop error: {e}", exc_info=True)
            try:
                time.sleep(Config.LOOP_INTERVAL)
            except KeyboardInterrupt:
                log.info("Shutting down gracefully...")
                self._state.save(force=True)
                break


if __name__ == "__main__":
    AlertEngine().run()
