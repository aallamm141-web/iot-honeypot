#!/usr/bin/env python3
"""
Attacker Profile Builder (Production Ready)
===========================================
Automatically collects, classifies, enriches, and scores attacker IPs
based on honeypot activity using robust environment settings.

Classification and Parsing rely on standard Python `ipaddress` module
and dynamic Elasticsearch `search_after` pagination.
"""

import json
import time
import re
import logging
import os
import sys
import socket
import html
import ipaddress
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv
from urllib3.exceptions import InsecureRequestWarning

# Load environment variables
load_dotenv()

# ==============================================================================
# CONFIG & SECRETS
# ==============================================================================

class Config:
    # Project Root
    PROJECT_ROOT = os.getenv("PROJECT_ROOT")

    # Elasticsearch
    ES_URL        = os.getenv("ELASTIC_HOST", "https://localhost:9200")
    ES_USER       = os.getenv("ELASTIC_USER", "elastic")
    ES_PASS       = os.getenv("ELASTIC_PASSWORD")
    ES_INDEX      = os.getenv("ES_ATTACKER_INDEX", "attacker-profiles")
    ES_VERIFY_SSL = os.getenv("ES_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

    # Telegram
    TELEGRAM_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

    # Threat Intelligence
    ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    GEO_API_URL   = os.getenv("GEO_API_URL", "https://ip-api.com/json/")

    INTERVAL = int(os.getenv("PROFILER_INTERVAL", 60))

    # File Paths — built from PROJECT_ROOT
    ZEEK_FILES = [
        os.path.join(PROJECT_ROOT, "logs_and_reports/notice.log") if PROJECT_ROOT else "logs_and_reports/notice.log"
    ]
    CONPOT_LOG = os.path.join(PROJECT_ROOT, "conpot/logs/conpot.log") if PROJECT_ROOT else "conpot/logs/conpot.log"
    STATE_FILE = os.path.join(PROJECT_ROOT, "logs_and_reports/profiler_state.json") if PROJECT_ROOT else "logs_and_reports/profiler_state.json"
    LOG_FILE   = os.path.join(PROJECT_ROOT, "logs_and_reports/profiler.log") if PROJECT_ROOT else "logs_and_reports/profiler.log"

    DETECT_PUBLIC_IP = os.getenv("DETECT_PUBLIC_IP", "false").lower() in ("true", "1", "yes")

    @classmethod
    def validate_secrets(cls):
        missing = []
        if not cls.PROJECT_ROOT: missing.append("PROJECT_ROOT")
        if not cls.ES_PASS: missing.append("ELASTIC_PASSWORD")
        if not cls.TELEGRAM_TOKEN: missing.append("TELEGRAM_BOT_TOKEN")
        if not cls.TELEGRAM_CHAT_ID: missing.append("TELEGRAM_CHAT_ID")

        if missing:
            print(f"[FATAL ERROR] Missing required variables in .env: {', '.join(missing)}", file=sys.stderr)
            sys.exit(1)

Config.validate_secrets()

# Disable SSL warning selectively
if not Config.ES_VERIFY_SSL:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

os.makedirs(os.path.dirname(os.path.abspath(Config.LOG_FILE)), exist_ok=True)

# ==============================================================================
# LOGGING
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("attacker.profiler")

# ==============================================================================
# ADVANCED IP CLASSIFICATION & NETWORKING
# ==============================================================================

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

HONEYPOT_IP = os.getenv("HONEYPOT_IP", get_local_ip())
HONEYPOT_NETWORK = os.getenv("HONEYPOT_NETWORK")

try:
    LOCAL_NETWORK = (
        ipaddress.ip_network(HONEYPOT_NETWORK, strict=False)
        if HONEYPOT_NETWORK
        else ipaddress.ip_network(f"{HONEYPOT_IP}/24", strict=False)
    )
except ValueError:
    LOCAL_NETWORK = None

raw_old_ips = os.getenv("OLD_HONEYPOT_IPS", "")
OLD_HONEYPOT_IPS = set(ip.strip() for ip in raw_old_ips.split(",") if ip.strip())

if Config.DETECT_PUBLIC_IP:
    try:
        _pub = requests.get("https://api.ipify.org", timeout=5).text.strip()
        if _pub:
            OLD_HONEYPOT_IPS.add(_pub)
    except Exception as e:
        log.warning(f"Could not auto-detect public IP: {e}")

raw_testers = os.getenv("KNOWN_TESTERS", "")
KNOWN_TESTERS = set(ip.strip() for ip in raw_testers.split(",") if ip.strip())

def classify_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return "exclude"

    if addr.version != 4:
        return "exclude"

    if (
        addr.is_loopback
        or addr.is_unspecified
        or addr.is_multicast
        or addr.is_link_local
        or addr.is_reserved
        or ip_str == HONEYPOT_IP
        or ip_str in OLD_HONEYPOT_IPS
    ):
        return "exclude"

    if ip_str in KNOWN_TESTERS:
        return "tester"

    if LOCAL_NETWORK and addr in LOCAL_NETWORK:
        return "local"

    return "external"

def get_ip_label(ip, kind, profile):
    if kind == "exclude": return "EXCLUDED"
    if kind == "tester":  return "TESTER"
    if kind == "local":
        total   = profile.get("total_events", 0)
        attacks = profile.get("attack_types", [])
        if total <= 20 and "malware_upload" not in attacks and "scada_access" not in attacks:
            return "TESTER"
        return "INTERNAL-THREAT"

    abuse_score = profile.get("abuse_score", 0)
    if abuse_score >= 75: return "KNOWN-MALICIOUS"
    if abuse_score >= 25: return "SUSPICIOUS"
    return "EXTERNAL"

# ==============================================================================
# THREAT SCORING & DICTIONARIES
# ==============================================================================

SCORE_WEIGHTS = {
    "malware_upload":    30,
    "ssh_login_success": 25,
    "scada_access":      20,
    "ssh_brute_force":   15,
    "smb_access":        15,
    "mysql_access":      10,
    "port_scan":         10,
    "mqtt_access":        8,
    "ping_sweep":         5,
    "any_connection":     3,
}

ZEEK_EVENT_MAP = {
    "PORT SCAN":         "port_scan",
    "PING SWEEP":        "ping_sweep",
    "SSH BRUTE FORCE":   "ssh_brute_force",
    "SSH LOGIN SUCCESS": "ssh_login_success",
    "HONEYPOT ACCESS":   "any_connection",
    "MALWARE DOWNLOAD": "malware_upload",
    "SCANNER TOOL":      "any_connection",
    "SCADA ATTACK":      "scada_access",
}

COUNTRY_MAP = {
    "EG": "Egypt",          "US": "United States",  "CN": "China",
    "RU": "Russia",         "DE": "Germany",         "FR": "France",
    "GB": "United Kingdom", "IN": "India",           "BR": "Brazil",
    "NL": "Netherlands",    "KR": "South Korea",     "JP": "Japan",
    "IR": "Iran",           "TR": "Turkey",          "UA": "Ukraine",
    "SA": "Saudi Arabia",   "AE": "UAE",             "MA": "Morocco",
}

# ==============================================================================
# STATE & ELASTICSEARCH HELPERS
# ==============================================================================

def load_state():
    if os.path.exists(Config.STATE_FILE):
        try:
            with open(Config.STATE_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            log.warning(f"Failed to load state: {e}")
    return {
        "file_positions":       {},
        "cowrie_search_after":  None,
        "dionaea_search_after": None,
    }

def save_state(state):
    """Atomic write pattern to prevent corruption during unexpected crashes."""
    try:
        state_dir = os.path.dirname(os.path.abspath(Config.STATE_FILE))
        os.makedirs(state_dir, exist_ok=True)
        temp_file = Config.STATE_FILE + ".tmp"
        
        with open(temp_file, "w") as f:
            json.dump(state, f, indent=2)
            
        os.replace(temp_file, Config.STATE_FILE)
    except Exception as e:
        log.error(f"Failed to save state: {e}")

def es_raw_request(method, path, body=None):
    """Low-level ES communicator that returns (status_code, response_json_or_dict)."""
    url = f"{Config.ES_URL}{path}"
    auth = (Config.ES_USER, Config.ES_PASS)
    try:
        if method == "GET":
            r = requests.get(url, auth=auth, verify=Config.ES_VERIFY_SSL, timeout=10)
        elif method == "POST":
            r = requests.post(url, auth=auth, json=body, verify=Config.ES_VERIFY_SSL, timeout=10)
        elif method == "PUT":
            r = requests.put(url, auth=auth, json=body, verify=Config.ES_VERIFY_SSL, timeout=10)
        else:
            return 500, {}
        
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {}
    except Exception as e:
        log.error(f"ES Network/Connection Error [{method} {path}]: {e}")
        return 0, {}

def create_index_if_needed():
    status, res = es_raw_request("GET", f"/{Config.ES_INDEX}")
    if status == 200:
        return
    
    mapping = {
        "mappings": {
            "properties": {
                "ip":                {"type": "ip"},
                "ip_label":          {"type": "keyword"},
                "threat_score":      {"type": "integer"},
                "threat_level":      {"type": "keyword"},
                "first_seen":        {"type": "date"},
                "last_seen":         {"type": "date"},
                "updated_at":        {"type": "date"},
                "total_events":      {"type": "integer"},
                "honeypots_hit":     {"type": "keyword"},
                "attack_types":      {"type": "keyword"},
                "services_hit":      {"type": "keyword"},
                "commands_run":      {"type": "keyword"},
                "credentials_tried": {
                    "type": "nested",
                    "properties": {
                        "username": {"type": "keyword"},
                        "password": {"type": "keyword"},
                    }
                },
                "country":           {"type": "keyword"},
                "country_name":      {"type": "keyword"},
                "isp":               {"type": "keyword"},
                "domain":            {"type": "keyword"},
                "abuse_score":       {"type": "integer"},
                "total_reports":     {"type": "integer"},
                "last_reported":     {"type": "keyword"},
                "is_tor":            {"type": "boolean"},
                "usage_type":        {"type": "keyword"},
                "recommendations":   {"type": "keyword"},
                "geo": {
                    "properties": {
                        "location": {"type": "geo_point"},
                        "city":     {"type": "keyword"},
                        "region":   {"type": "keyword"},
                        "country":  {"type": "keyword"},
                    }
                },
            }
        }
    }
    status, result = es_raw_request("PUT", f"/{Config.ES_INDEX}", mapping)
    log.info(f"Created index {Config.ES_INDEX}: {result.get('acknowledged', False)}")

# ==============================================================================
# PROFILE & ENRICHMENT
# ==============================================================================

def empty_profile(ip):
    return {
        "ip":               ip,
        "ip_label":         "UNKNOWN",
        "threat_score":     0,
        "threat_level":     "LOW",
        "first_seen":       None,
        "last_seen":        None,
        "updated_at":       None,
        "total_events":     0,
        "honeypots_hit":    [],
        "attack_types":     [],
        "services_hit":     [],
        "commands_run":     [],
        "credentials_tried":[],
        "country":          "",
        "country_name":     "",
        "isp":              "",
        "domain":           "",
        "abuse_score":      0,
        "total_reports":    0,
        "last_reported":    "",
        "is_tor":           False,
        "usage_type":       "",
        "recommendations":  [],
        "abuse_enriched":   False,
        "geo_enriched":     False,
        "geo":              {},
    }

def get_profile(ip):
    """
    Returns (profile_dict, status_ok)
    Distinguishes 404 (Not Found -> New) from 500/Connection Error (Do NOT overwrite).
    """
    status, result = es_raw_request("GET", f"/{Config.ES_INDEX}/_doc/{ip}")
    if status == 200 and result.get("found"):
        return result["_source"], True
    elif status == 404:
        return empty_profile(ip), True
    else:
        log.error(f"Failed to retrieve profile for {ip} due to ES Error (status {status}). Skipping mutation.")
        return None, False

def add_unique(profile, field, value):
    if value and value not in profile[field]:
        profile[field].append(value)

def update_timestamps(profile, ts):
    if not profile["first_seen"]:
        profile["first_seen"] = ts
    profile["last_seen"] = ts

def add_score(profile, event_type):
    points = SCORE_WEIGHTS.get(event_type, 0)
    if profile.get("ip") not in KNOWN_TESTERS:
        profile["threat_score"] = min(profile["threat_score"] + points, 100)
    add_unique(profile, "attack_types", event_type)

_abuse_cache = {}
_geo_cache   = {}

def enrich_geo(ip, profile):
    if profile.get("geo_enriched") or classify_ip(ip) != "external":
        profile["geo_enriched"] = True
        return
    if ip in _geo_cache:
        data = _geo_cache[ip]
    else:
        try:
            url = f"{Config.GEO_API_URL.rstrip('/')}/{ip}"
            r = requests.get(url, params={"fields": "status,country,countryCode,regionName,city,lat,lon,isp,org"}, timeout=8)
            data = r.json()
            if data.get("status") == "success":
                _geo_cache[ip] = data
            else:
                profile["geo_enriched"] = True
                return
        except Exception as e:
            log.error(f"Geo API error for {ip}: {e}")
            return

    lat, lon = data.get("lat"), data.get("lon")
    if lat and lon:
        profile["geo"] = {
            "location": {"lat": lat, "lon": lon},
            "city":     data.get("city", ""),
            "region":   data.get("regionName", ""),
            "country":  data.get("country", ""),
        }
    if not profile.get("isp"):
        profile["isp"] = data.get("isp", "") or data.get("org", "")
    if not profile.get("country_name"):
        cc = data.get("countryCode", "")
        profile["country"]      = cc
        profile["country_name"] = COUNTRY_MAP.get(cc, data.get("country", cc))
    profile["geo_enriched"] = True

def enrich_external_ip(ip, profile):
    if profile.get("abuse_enriched") or classify_ip(ip) != "external" or not Config.ABUSEIPDB_KEY:
        profile["abuse_enriched"] = True
        return
    if ip in _abuse_cache:
        data = _abuse_cache[ip]
    else:
        try:
            r = requests.get(
                Config.ABUSEIPDB_URL,
                headers={"Key": Config.ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=8
            )
            data = r.json().get("data", {})
            _abuse_cache[ip] = data
        except Exception as e:
            log.error(f"AbuseIPDB error for {ip}: {e}")
            return

    cc = data.get("countryCode", "")
    profile["country"]       = cc
    profile["country_name"]  = COUNTRY_MAP.get(cc, cc)
    profile["isp"]           = data.get("isp", "")
    profile["domain"]        = data.get("domain", "")
    profile["abuse_score"]   = data.get("abuseConfidenceScore", 0)
    profile["total_reports"] = data.get("totalReports", 0)
    profile["last_reported"] = data.get("lastReportedAt", "") or ""
    profile["is_tor"]        = data.get("isTor", False)
    profile["usage_type"]    = data.get("usageType", "")
    profile["abuse_enriched"]= True

    if profile["abuse_score"] >= 50:
        profile["threat_score"] = min(profile["threat_score"] + 10, 100)

def build_recommendations(profile):
    actions      = []
    label        = profile.get("ip_label", "")
    score        = profile.get("threat_score", 0)
    abuse_score  = profile.get("abuse_score", 0)
    total_reports= profile.get("total_reports", 0)
    attack_types = profile.get("attack_types", [])
    honeypots    = profile.get("honeypots_hit", [])
    creds        = profile.get("credentials_tried", [])
    is_tor       = profile.get("is_tor", False)

    if label == "TESTER":
        return ["Known testing device — review test coverage"]
    if label == "INTERNAL-THREAT":
        actions.extend(["CRITICAL: Attacker is on your internal network — isolate immediately", "Check all devices on local subnet"])
    if score >= 70 or abuse_score >= 50:
        actions.append("Block immediately on firewall (UFW/iptables)")
    if total_reports > 10:
        actions.append(f"Reported {total_reports}x on AbuseIPDB — highly reported IP reputation")
    if "malware_upload" in attack_types:
        actions.append("Analyze captured malware samples in Triage sandbox")
    if "scada_access" in attack_types:
        actions.append("Review Conpot logs — industrial protocol access detected")
    if "ssh_login_success" in attack_types:
        actions.append("SSH credentials accepted — attacker gained shell access")
    if "ssh_brute_force" in attack_types and creds:
        actions.append(f"Tried {len(creds)} credentials — verify none match real systems")
    if len(honeypots) >= 3:
        actions.append("Hit 3+ honeypots — automated scanner or targeted recon")
    if is_tor:
        actions.append("Using Tor exit node — real source anonymized")
    return actions or ["Low threat — monitor for escalation"]

def save_profile(ip, profile, kind):
    profile["updated_at"] = datetime.now(timezone.utc).isoformat()
    enrich_external_ip(ip, profile)
    enrich_geo(ip, profile)
    profile["ip_label"] = get_ip_label(ip, kind, profile)

    label = profile["ip_label"]
    if label == "TESTER":
        profile["threat_level"] = "TESTER"
    elif label == "INTERNAL-THREAT":
        profile["threat_level"] = "CRITICAL"
    else:
        s = profile["threat_score"]
        profile["threat_level"] = "CRITICAL" if s >= 70 else "HIGH" if s >= 50 else "MEDIUM" if s >= 20 else "LOW"

    profile["recommendations"] = build_recommendations(profile)
    status, _ = es_raw_request("PUT", f"/{Config.ES_INDEX}/_doc/{ip}", profile)
    if status not in (200, 201):
        log.error(f"Failed to index attacker profile for {ip}. HTTP Status: {status}")

def send_telegram_alert(ip, profile):
    level   = html.escape(str(profile.get("threat_level", "UNKNOWN")))
    label   = html.escape(str(profile.get("ip_label", "EXTERNAL")))
    score   = profile.get("threat_score", 0)
    country = html.escape(str(profile.get("country_name", "") or "Local Network"))
    isp     = html.escape(str(profile.get("isp", "") or "N/A"))
    city    = html.escape(str(profile.get("geo", {}).get("city", "")))
    region  = html.escape(str(profile.get("geo", {}).get("region", "")))
    loc_str = f"{city}, {region}" if city else ""
    
    abuse   = profile.get("abuse_score", 0)
    reports = profile.get("total_reports", 0)
    is_tor  = "Yes ⚠️" if profile.get("is_tor") else "No"
    creds   = len(profile.get("credentials_tried", []))
    cmds    = len(profile.get("commands_run", []))
    
    pots    = html.escape(", ".join(profile.get("honeypots_hit", [])) or "none")
    attacks = html.escape(", ".join(profile.get("attack_types", []))  or "none")
    recs    = profile.get("recommendations", [])

    emoji = {"TESTER": "🧪", "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪", "INTERNAL-THREAT": "🚨"}.get(level, "⚪")
    
    rec_text = ""
    if recs:
        formatted_recs = "\n".join(f"  • {html.escape(r)}" for r in recs)
        rec_text = f"\n<b>🛡 Recommendations:</b>\n{formatted_recs}"

    msg = (
        f"{emoji} <b>ATTACKER PROFILE — {level}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{html.escape(ip)}</code> [{label}]\n"
        f"🗺 Location: {country}{f' — {loc_str}' if loc_str else ''} | {isp}\n"
        f"⚡ Threat Score: <b>{score}/100</b>\n"
        f"😈 AbuseIPDB: {abuse}% confidence | {reports} reports\n"
        f"🧅 Tor Exit Node: {is_tor}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 Honeypots Hit: {pots}\n"
        f"⚔️ Attack Types: {attacks}\n"
        f"🔑 Credentials Tried: {creds}\n"
        f"💻 Commands Executed: {cmds}\n"
        f"📈 Total Events: {profile.get('total_events', 0)}\n"
        f"🕐 First Seen: {html.escape(str(profile.get('first_seen', 'N/A')))}\n"
        f"🕐 Last Active: {html.escape(str(profile.get('last_seen', 'N/A')))}"
        f"{rec_text}"
    )

    try:
        requests.post(
            f"https://api.telegram.org/bot{Config.TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": Config.TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"},
            timeout=10
        )
        log.info(f"Alert sent: {ip} [{label}] level={level} score={score}")
    except Exception as e:
        log.error(f"Telegram alert error: {e}")

# ==============================================================================
# DATA PROCESSING ENGINE (WITH SEARCH_AFTER PAGINATION)
# ==============================================================================

IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

def first_valid_ip(text):
    for ip in IP_PATTERN.findall(text):
        kind = classify_ip(ip)
        if kind != "exclude":
            return ip, kind
    return None, None

def extract_zeek_timestamp(line):
    try:
        first_field = line.split("\t", 1)[0].strip()
        return datetime.fromtimestamp(float(first_field), tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()

def extract_conpot_timestamp(line):
    m = re.match(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass
    return datetime.now(timezone.utc).isoformat()

def fetch_es_events_search_after(honeypot_name, last_search_after, extra_filter=None):
    """
    Paginates through ES results using search_after with [@timestamp, _id]
    to ensure zero data-loss across high-traffic bursts.
    """
    query = {
        "size": 500,
        "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
        "query": {
            "bool": {
                "must": [{"term": {"honeypot": honeypot_name}}]
            }
        }
    }

    if extra_filter:
        query["query"]["bool"]["must"].append(extra_filter)

    if last_search_after:
        query["search_after"] = last_search_after

    status, result = es_raw_request("POST", "/filebeat-*/_search", query)
    if status != 200:
        return [], last_search_after

    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        return [], last_search_after

    new_search_after = hits[-1]["sort"]
    return hits, new_search_after

def process_cowrie(state, profiles):
    search_after = state.get("cowrie_search_after")
    hits, new_search_after = fetch_es_events_search_after("cowrie", search_after)
    if not hits: return

    count = 0
    for hit in hits:
        src = hit["_source"]
        ip  = src.get("src_ip")
        kind = classify_ip(ip) if ip else "exclude"
        if kind == "exclude": continue

        ts, eventid = src.get("@timestamp", ""), src.get("eventid", "")
        if ip not in profiles:
            p, ok = get_profile(ip)
            if not ok: continue
            profiles[ip] = (p, kind)

        p = profiles[ip][0]
        update_timestamps(p, ts)
        p["total_events"] += 1
        add_unique(p, "honeypots_hit", "cowrie")

        if eventid in ("cowrie.login.failed", "cowrie.login.success"):
            cred = {"username": src.get("username", ""), "password": src.get("password", "")}
            if cred not in p["credentials_tried"]: p["credentials_tried"].append(cred)
            add_score(p, "ssh_brute_force" if eventid == "cowrie.login.failed" else "ssh_login_success")
        elif eventid == "cowrie.command.input":
            cmd = src.get("input", "")
            if cmd: add_unique(p, "commands_run", str(cmd)[:200])
        elif eventid == "cowrie.session.connect":
            add_score(p, "any_connection")
            add_unique(p, "services_hit", "ssh")

        count += 1

    state["cowrie_search_after"] = new_search_after
    if count: log.info(f"Cowrie: {count} new events processed")

def process_dionaea(state, profiles):
    search_after = state.get("dionaea_search_after")
    hits, new_search_after = fetch_es_events_search_after("dionaea", search_after, extra_filter={"match": {"message": "accepted"}})
    if not hits: return

    service_re = {
        "smb": re.compile(r"smb", re.IGNORECASE),
        "mysql": re.compile(r"mysql", re.IGNORECASE),
        "mqtt": re.compile(r"mqtt", re.IGNORECASE),
        "mssql": re.compile(r"mssql", re.IGNORECASE),
    }

    count = 0
    for hit in hits:
        src, msg, ts = hit["_source"], hit["_source"].get("message", ""), hit["_source"].get("@timestamp", "")
        ip, kind = first_valid_ip(msg)
        if not ip: continue

        if ip not in profiles:
            p, ok = get_profile(ip)
            if not ok: continue
            profiles[ip] = (p, kind)

        p = profiles[ip][0]
        update_timestamps(p, ts)
        p["total_events"] += 1
        add_unique(p, "honeypots_hit", "dionaea")

        matched = False
        for service, pattern in service_re.items():
            if pattern.search(msg):
                add_unique(p, "services_hit", service)
                score_key = f"{service}_access" if f"{service}_access" in SCORE_WEIGHTS else "any_connection"
                add_score(p, score_key)
                matched = True
                break
        if not matched: add_score(p, "any_connection")
        count += 1

    state["dionaea_search_after"] = new_search_after
    if count: log.info(f"Dionaea: {count} new events processed")

def process_zeek_files(state, profiles):
    positions, total = state.setdefault("file_positions", {}), 0
    for filepath in Config.ZEEK_FILES:
        if not os.path.exists(filepath): continue
        pos = positions.get(filepath, 0)
        try:
            with open(filepath, "r", errors="ignore") as f:
                f.seek(pos)
                for line in f:
                    line = line.strip()
                    if not line: continue

                    event_type = None
                    for keyword, etype in ZEEK_EVENT_MAP.items():
                        if keyword in line:
                            event_type = etype
                            break
                    if not event_type: continue

                    ip, kind = first_valid_ip(line)
                    if not ip: continue

                    if ip not in profiles:
                        p, ok = get_profile(ip)
                        if not ok: continue
                        profiles[ip] = (p, kind)

                    p = profiles[ip][0]
                    update_timestamps(p, extract_zeek_timestamp(line))
                    p["total_events"] += 1
                    add_unique(p, "honeypots_hit", "zeek")
                    add_score(p, event_type)
                    total += 1
                
                positions[filepath] = f.tell()
        except Exception as e:
            log.error(f"Error reading {filepath}: {e}")

    if total: log.info(f"Zeek: {total} new events processed")

def process_conpot(state, profiles):
    positions = state.setdefault("file_positions", {})
    if not os.path.exists(Config.CONPOT_LOG): return

    pos = positions.get(Config.CONPOT_LOG, 0)
    new_ips_this_cycle, count = set(), 0

    try:
        with open(Config.CONPOT_LOG, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(pos)
            for line in f:
                ip, kind = first_valid_ip(line)
                if not ip: continue

                if ip not in profiles:
                    p, ok = get_profile(ip)
                    if not ok: continue
                    profiles[ip] = (p, kind)

                p = profiles[ip][0]
                update_timestamps(p, extract_conpot_timestamp(line))
                p["total_events"] += 1
                add_unique(p, "honeypots_hit", "conpot")

                if ip not in new_ips_this_cycle:
                    add_score(p, "scada_access")
                    new_ips_this_cycle.add(ip)
                count += 1
            
            positions[Config.CONPOT_LOG] = f.tell()
    except Exception as e:
        log.error(f"Error reading Conpot log: {e}")
        return

    if count: log.info(f"Conpot: {count} events from {len(new_ips_this_cycle)} unique IPs processed")

# ==============================================================================
# MAIN LOOP
# ==============================================================================

def main():
    log.info("=" * 60)
    log.info("Attacker Profile Builder Starting...")
    log.info(f"Target ES: {Config.ES_URL} | Index: {Config.ES_INDEX}")
    log.info("=" * 60)

    create_index_if_needed()
    state = load_state()

    while True:
        try:
            profiles = {}
            process_cowrie(state, profiles)
            process_dionaea(state, profiles)
            process_zeek_files(state, profiles)
            process_conpot(state, profiles)

            for ip, (profile, kind) in profiles.items():
                old_profile, ok = get_profile(ip)
                if not ok:
                    continue  # Skip updating if Elastic call failed to prevent profile wipe
                
                old_level = old_profile.get("threat_level", "LOW")
                save_profile(ip, profile, kind)

                new_level = profile.get("threat_level", "LOW")
                if not old_profile.get("first_seen") or new_level != old_level:
                    send_telegram_alert(ip, profile)

            save_state(state)

        except Exception as e:
            log.error(f"Execution loop error: {e}", exc_info=True)

        time.sleep(Config.INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Shutting down Attacker Profile Builder...")
        sys.exit(0)
