#!/usr/bin/env python3
"""
IOT Honeypot - IOC & Threat Intelligence Report Generator
============================================================
Generates a weekly PDF report styled like a professional
SOC/Threat-Intel deliverable:

  1. Executive Summary
  2. Threat Severity Dashboard
  3. Environment Overview
  4. Threat Landscape (Top Attacker IPs + TI)
  5. Authentication Analysis
  6. Network Activity (Protocols + Zeek Alerts)
  7. Command & Behavior Analysis (MITRE mapped)
  8. Malware Analysis (Triage)
  9. MITRE ATT&CK Coverage Summary
  10. Risk Assessment & Recommendations
"""

import os
import sys
import requests
import datetime
import warnings
from elasticsearch8 import Elasticsearch
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                Table, TableStyle, HRFlowable, PageBreak)
from reportlab.lib.enums import TA_CENTER
from dotenv import load_dotenv

load_dotenv()
warnings.filterwarnings("ignore")

# ==============================================================================
# CONFIG
# ==============================================================================

PROJECT_ROOT = os.getenv("PROJECT_ROOT")

TRIAGE_API_KEY = os.getenv("TRIAGE_API_KEY")
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")  # optional — add to .env if you have one

ES_HOST = os.getenv("ELASTIC_HOST", "https://localhost:9200")
ES_USER = os.getenv("ELASTIC_USER", "elastic")
ES_PASS = os.getenv("ELASTIC_PASSWORD")
ES_VERIFY_SSL = os.getenv("ES_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

REPORT_DIR  = os.path.join(PROJECT_ROOT, "logs_and_reports/reports") if PROJECT_ROOT else "logs_and_reports/reports"
HASHES_FILE = os.path.join(PROJECT_ROOT, "logs_and_reports/submitted_hashes.txt") if PROJECT_ROOT else "logs_and_reports/submitted_hashes.txt"

HONEYPOT_NAME = os.getenv("HONEYPOT_NAME", "OT Deception Network")
DAYS = int(os.getenv("REPORT_DAYS", 7))

missing = []
if not PROJECT_ROOT: missing.append("PROJECT_ROOT")
if not ES_PASS: missing.append("ELASTIC_PASSWORD")
if missing:
    print(f"[FATAL ERROR] Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
    print("[FATAL ERROR] Ensure your .env file is populated correctly.", file=sys.stderr)
    sys.exit(1)

if not TRIAGE_API_KEY:
    print("[WARNING] TRIAGE_API_KEY not set — malware sample section will be empty.")
if not ABUSEIPDB_KEY:
    print("[WARNING] ABUSEIPDB_API_KEY not set — IP enrichment will be skipped.")

os.makedirs(REPORT_DIR, exist_ok=True)
es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS), verify_certs=ES_VERIFY_SSL)

# Private IP prefixes — excluded from IOC lists entirely
PRIVATE_PREFIXES = ("10.", "172.", "192.168.", "127.", "0.", "169.254.")

# ==============================================================================
# THREAT INTELLIGENCE
# ==============================================================================

_ti_cache = {}

COUNTRY_MAP = {
    "EG": "Egypt",          "US": "United States",  "CN": "China",
    "RU": "Russia",         "DE": "Germany",        "FR": "France",
    "GB": "United Kingdom", "IN": "India",          "BR": "Brazil",
    "NL": "Netherlands",    "KR": "South Korea",    "JP": "Japan",
    "IR": "Iran",           "TR": "Turkey",         "UA": "Ukraine",
    "SA": "Saudi Arabia",   "AE": "UAE",            "IL": "Israel",
    "PK": "Pakistan",       "BD": "Bangladesh",     "NG": "Nigeria",
    "MA": "Morocco",        "TN": "Tunisia",        "DZ": "Algeria",
    "LY": "Libya",          "SY": "Syria",          "IQ": "Iraq",
    "SG": "Singapore",      "HK": "Hong Kong",      "TW": "Taiwan",
}

def is_private_ip(ip):
    """Returns True if IP is private/local/internal — excluded from IOCs."""
    if not ip or ip in ("Unknown", "N/A", ""):
        return True
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)

def get_abuseipdb(ip):
    if is_private_ip(ip) or not ABUSEIPDB_KEY:
        return {}
    key = f"abuse_{ip}"
    if key in _ti_cache:
        return _ti_cache[key]
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=8
        )
        d  = r.json().get("data", {})
        cc = d.get("countryCode", "")
        result = {
            "abuse_score":   d.get("abuseConfidenceScore", 0),
            "country":       COUNTRY_MAP.get(cc, cc) or "Unknown",
            "isp":           d.get("isp", "Unknown"),
            "total_reports": d.get("totalReports", 0),
            "is_tor":        d.get("isTor", False),
            "usage_type":    d.get("usageType", ""),
            "domain":        d.get("domain", ""),
            "last_reported": d.get("lastReportedAt", "") or "",
        }
        _ti_cache[key] = result
        return result
    except Exception as e:
        print(f"[ERROR] AbuseIPDB ({ip}): {e}")
        return {}

def get_virustotal(ip):
    if not VIRUSTOTAL_KEY or is_private_ip(ip):
        return {}
    key = f"vt_{ip}"
    if key in _ti_cache:
        return _ti_cache[key]
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=10
        )
        d     = r.json().get("data", {})
        attrs = d.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result = {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "as_owner":   attrs.get("as_owner", ""),
        }
        _ti_cache[key] = result
        return result
    except Exception as e:
        print(f"[ERROR] VirusTotal ({ip}): {e}")
        return {}

def classify_attacker(abuse, vt, event_type=""):
    """Returns (classification, reason, severity)."""
    score   = abuse.get("abuse_score", 0)
    reports = abuse.get("total_reports", 0)
    is_tor  = abuse.get("is_tor", False)
    usage   = abuse.get("usage_type", "").lower()
    vt_mal  = vt.get("malicious", 0) if vt else 0

    if is_tor:
        return "TOR EXIT NODE", "Anonymized — real source unknown", "HIGH"
    if score >= 80 or (reports > 50 and vt_mal > 5):
        return "KNOWN MALICIOUS", f"{score}% confidence, {reports} reports", "CRITICAL"
    if "scada" in event_type.lower() or "modbus" in event_type.lower():
        if score < 20:
            return "APT CANDIDATE", "Targeted ICS/SCADA access with low previous exposure", "CRITICAL"
    if score >= 40 or reports > 10:
        return "BOTNET NODE", f"{score}% confidence, {reports} reports", "HIGH"
    if "datacenter" in usage or "hosting" in usage:
        return "SCRIPT KIDDIE", "Scanning from datacenter/VPS — automated tool", "MEDIUM"
    return "OPPORTUNISTIC", "Generic internet scanner", "LOW"

def enrich_ip(ip):
    abuse = get_abuseipdb(ip)
    vt    = get_virustotal(ip)
    if not abuse:
        return None
    classification, reason, severity = classify_attacker(abuse, vt)
    return {
        "abuse_score":   abuse.get("abuse_score", 0),
        "country":       abuse.get("country", "Unknown"),
        "isp":           abuse.get("isp", "Unknown"),
        "total_reports": abuse.get("total_reports", 0),
        "is_tor":        abuse.get("is_tor", False),
        "last_reported": abuse.get("last_reported", ""),
        "vt_malicious":  vt.get("malicious", 0) if vt else 0,
        "vt_suspicious": vt.get("suspicious", 0) if vt else 0,
        "classification": classification,
        "reason":         reason,
        "severity":       severity,
    }

# ==============================================================================
# MITRE ATT&CK MAPPING
# ==============================================================================

COMMAND_MITRE_MAP = [
    ("cat /etc/passwd",   "T1003", "OS Credential Dumping",            "Credential Access"),
    ("cat credentials",   "T1552", "Unsecured Credentials",            "Credential Access"),
    ("cat /root",         "T1552", "Unsecured Credentials",            "Credential Access"),
    ("nano credentials",  "T1552", "Unsecured Credentials",            "Credential Access"),
    ("whoami",            "T1033", "System Owner/User Discovery",      "Discovery"),
    ("uname",             "T1082", "System Information Discovery",     "Discovery"),
    ("ifconfig",          "T1016", "System Network Configuration",     "Discovery"),
    ("ip addr",           "T1016", "System Network Configuration",     "Discovery"),
    ("netstat",           "T1049", "System Network Connections",       "Discovery"),
    ("ps aux",            "T1057", "Process Discovery",                "Discovery"),
    ("ls",                "T1083", "File and Directory Discovery",     "Discovery"),
    ("cd",                "T1083", "File and Directory Discovery",     "Discovery"),
    ("find",              "T1083", "File and Directory Discovery",     "Discovery"),
    ("wget",              "T1105", "Ingress Tool Transfer",            "Command and Control"),
    ("curl",              "T1105", "Ingress Tool Transfer",            "Command and Control"),
    ("chmod +x",          "T1222", "File and Directory Permissions Mod","Defense Evasion"),
    ("crontab",           "T1053", "Scheduled Task/Job",                "Persistence"),
    ("useradd",           "T1136", "Create Account",                    "Persistence"),
    ("passwd",            "T1098", "Account Manipulation",              "Persistence"),
    ("history",           "T1552", "Unsecured Credentials",            "Credential Access"),
    ("backup.sh",         "T1005", "Data from Local System",            "Collection"),
    ("exit",              "T1659", "Content Injection",                 "—"),
]

ALERT_MITRE_MAP = {
    "PORT SCAN":         ("T1595", "Active Scanning"),
    "PING SWEEP":        ("T1595", "Active Scanning"),
    "SSH BRUTE":         ("T1110", "Brute Force"),
    "SSH LOGIN SUCCESS": ("T1078", "Valid Accounts"),
    "HONEYPOT ACCESS":   ("T1190", "Exploit Public-Facing Application"),
    "MALWARE DOWNLOAD":  ("T1105", "Ingress Tool Transfer"),
    "SCANNER":           ("T1595", "Active Scanning"),
}

def classify_command(cmd):
    """Returns (technique_id, technique_name, category) for a command, or None."""
    cmd_lower = cmd.lower().strip()
    for substr, tid, tname, cat in COMMAND_MITRE_MAP:
        if substr in cmd_lower:
            return tid, tname, cat
    return "T1059", "Command and Scripting Interpreter", "Execution"

# ==============================================================================
# ELASTICSEARCH HELPERS
# ==============================================================================

def date_filter():
    return {"range": {"@timestamp": {"gte": f"now-{DAYS}d/d", "lte": "now"}}}

def with_date(query=None):
    if query:
        return {"bool": {"must": [date_filter(), query]}}
    return date_filter()

def with_date_and(must_list):
    return {"bool": {"must": [date_filter()] + must_list}}

def es_count(query):
    try:
        return es.count(index="filebeat-*", query=query)["count"]
    except Exception:
        return 0

def es_top_terms(field, query=None, size=10):
    body = {"size": 0, "aggs": {"top": {"terms": {"field": field, "size": size}}}}
    if query:
        body["query"] = query
    try:
        result = es.search(index="filebeat-*", body=body)
        return [(b["key"], b["doc_count"]) for b in result["aggregations"]["top"]["buckets"]]
    except Exception:
        return []

def es_top_message_values(prefix, query=None, size=10):
    body = {"size": 200, "_source": ["message"]}
    if query:
        body["query"] = query
    try:
        result = es.search(index="filebeat-*", body=body)
        counts = {}
        for hit in result["hits"]["hits"]:
            msg = hit["_source"].get("message", "")
            if msg.startswith(prefix + ":"):
                val = msg[len(prefix)+1:].strip()
                if val:
                    counts[val] = counts.get(val, 0) + 1
        return sorted(counts.items(), key=lambda x: -x[1])[:size]
    except Exception:
        return []

def es_zeek_notices(size=30):
    """Fetches Zeek network detection alerts — excludes internal/private attackers."""
    try:
        result = es.search(index="filebeat-*", body={
            "size": size,
            "_source": ["message", "@timestamp"],
            "query": with_date({"match": {"honeypot": "zeek_notice"}}),
            "sort": [{"@timestamp": {"order": "desc"}}]
        })
        notices = []
        seen = set()
        for hit in result["hits"]["hits"]:
            msg = hit["_source"].get("message", "")

            attacker_ip = ""
            if "Attacker:" in msg:
                attacker_ip = msg.split("Attacker:")[-1].split("|")[0].strip()
            if attacker_ip and is_private_ip(attacker_ip):
                continue

            for keyword in ["HONEYPOT ACCESS", "PORT SCAN", "PING SWEEP",
                            "SSH BRUTE", "SSH LOGIN SUCCESS", "MALWARE DOWNLOAD", "SCANNER"]:
                if keyword in msg:
                    parts = msg.split("\t")
                    for part in parts:
                        if keyword in part:
                            key = part[:100]
                            if key not in seen:
                                seen.add(key)
                                ts = hit["_source"].get("@timestamp", "")[:19]
                                notices.append((ts, keyword, part.strip(), attacker_ip))
                    break
        return notices
    except Exception:
        return []

# ==============================================================================
# TRIAGE API
# ==============================================================================

def get_triage_samples():
    if not TRIAGE_API_KEY:
        return []
    try:
        r = requests.get(
            "https://api.tria.ge/v0/samples?limit=20",
            headers={"Authorization": f"Bearer {TRIAGE_API_KEY}"},
            timeout=30
        )
        return r.json().get("data", []) if r.status_code == 200 else []
    except Exception:
        return []

def get_triage_iocs(sample_id):
    if not TRIAGE_API_KEY:
        return {}
    try:
        r = requests.get(
            f"https://api.tria.ge/v0/samples/{sample_id}/summary",
            headers={"Authorization": f"Bearer {TRIAGE_API_KEY}"},
            timeout=30
        )
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}

# ==============================================================================
# DATA COLLECTION
# ==============================================================================

def collect_stats():
    s = {}

    s["total_events"]    = es_count(with_date())
    s["cowrie_events"]   = es_count(with_date({"match": {"honeypot": "cowrie"}}))
    s["conpot_events"]   = es_count(with_date({"match": {"honeypot": "conpot"}}))
    s["dionaea_events"]  = es_count(with_date({"match": {"honeypot": "dionaea"}}))
    s["zeek_events"]     = es_count(with_date({"match": {"honeypot": "zeek"}}))
    s["zeek_notices"]    = es_count(with_date({"match": {"honeypot": "zeek_notice"}}))
    s["suricata_alerts"] = es_count(with_date_and([
        {"match": {"honeypot": "suricata_ids"}},
        {"match": {"event_type": "alert"}}
    ]))

    s["login_failed"]   = es_count(with_date_and([
        {"match": {"honeypot": "cowrie"}},
        {"match": {"eventid": "cowrie.login.failed"}}
    ]))
    s["login_success"]  = es_count(with_date_and([
        {"match": {"honeypot": "cowrie"}},
        {"match": {"eventid": "cowrie.login.success"}}
    ]))
    s["new_sessions"]   = es_count(with_date_and([
        {"match": {"honeypot": "cowrie"}},
        {"match": {"eventid": "cowrie.session.connect"}}
    ]))
    s["commands_total"] = es_count(with_date_and([
        {"match": {"honeypot": "cowrie"}},
        {"match": {"eventid": "cowrie.command.input"}}
    ]))

    try:
        ap_result = es.search(index="attacker-profiles", body={
            "size": 50,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"last_seen": {"gte": f"now-{DAYS}d"}}}
                    ],
                    "must_not": [
                        {"term": {"ip_label": "TESTER"}},
                        {"term": {"ip_label": "LOCAL"}},
                        {"term": {"ip_label": "EXCLUDED"}}
                    ]
                }
            },
            "sort": [
                {"threat_score": {"order": "desc"}},
                {"total_events": {"order": "desc"}},
                {"last_seen":    {"order": "desc"}}
            ]
        })
        all_ips = [
            (hit["_source"]["ip"], hit["_source"].get("total_events", 0))
            for hit in ap_result["hits"]["hits"]
        ]
        if not all_ips:
            print(f"[*] No attacker profiles active in last {DAYS} days "
                  f"(all 'last_seen' older than now-{DAYS}d)")
    except Exception as e:
        print(f"[ERROR] attacker-profiles: {e}")
        all_ips = es_top_terms("src_ip",
            query=with_date({"exists": {"field": "src_ip"}}), size=30)

    s["top_ips"]      = [(ip, cnt) for ip, cnt in all_ips if not is_private_ip(ip)][:30]
    s["internal_ips"] = [(ip, cnt) for ip, cnt in all_ips if is_private_ip(ip)]

    s["top_protocols"] = es_top_terms("protocol",
        query=with_date({"exists": {"field": "protocol"}}), size=10)
    s["top_usernames"] = es_top_terms("username", query=with_date_and([
        {"match": {"honeypot": "cowrie"}},
        {"bool": {"should": [
            {"match": {"eventid": "cowrie.login.failed"}},
            {"match": {"eventid": "cowrie.login.success"}}
        ], "minimum_should_match": 1}}
    ]), size=10)
    s["top_passwords_failed"]  = es_top_terms("password", query=with_date_and([
        {"match": {"honeypot": "cowrie"}},
        {"match": {"eventid": "cowrie.login.failed"}}
    ]), size=10)
    s["top_passwords_success"] = es_top_terms("password", query=with_date_and([
        {"match": {"honeypot": "cowrie"}},
        {"match": {"eventid": "cowrie.login.success"}}
    ]), size=10)
    s["top_commands"]  = es_top_message_values("CMD", query=with_date_and([
        {"match": {"honeypot": "cowrie"}},
        {"match": {"eventid": "cowrie.command.input"}}
    ]), size=15)
    s["top_alerts"]    = es_top_terms("alert.signature", query=with_date_and([
        {"match": {"honeypot": "suricata_ids"}},
        {"match": {"event_type": "alert"}}
    ]), size=10)

    s["modbus_events"] = es_count(with_date_and([
        {"match": {"honeypot": "conpot"}},
        {"match": {"message": "Modbus"}}
    ]))
    s["smb_events"]    = es_count(with_date_and([
        {"match": {"honeypot": "dionaea"}},
        {"match": {"message": "smb"}}
    ]))
    s["mqtt_events"]   = es_count(with_date_and([
        {"match": {"honeypot": "dionaea"}},
        {"match": {"message": "mqtt"}}
    ]))
    s["zeek_notice_list"] = es_zeek_notices(size=30)

    return s

# ==============================================================================
# RISK / SEVERITY CALCULATION
# ==============================================================================

SEVERITY_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_COLOR  = {
    "CRITICAL": colors.HexColor("#922b21"),
    "HIGH":     colors.HexColor("#c0392b"),
    "MEDIUM":   colors.HexColor("#d68910"),
    "LOW":      colors.HexColor("#2471a3"),
    "INFO":     colors.HexColor("#7f8c8d"),
}

def compute_dashboard(ti_rows, alert_counts):
    """Returns dict with overall risk level + severity counts."""
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for row in ti_rows:
        sev = row[-1]
        if sev in sev_counts:
            sev_counts[sev] += 1

    for alert_type, cnt in alert_counts.items():
        if alert_type in ("SSH LOGIN SUCCESS", "MALWARE DOWNLOAD"):
            sev_counts["CRITICAL"] += 1 if cnt > 0 else 0
        elif alert_type == "SSH BRUTE":
            sev_counts["HIGH"] += 1 if cnt > 0 else 0
        elif alert_type in ("PORT SCAN", "SCANNER"):
            sev_counts["MEDIUM"] += 1 if cnt > 0 else 0
        else:
            sev_counts["LOW"] += 1 if cnt > 0 else 0

    if sev_counts["CRITICAL"] > 0:
        overall = "CRITICAL"
    elif sev_counts["HIGH"] > 0:
        overall = "HIGH"
    elif sev_counts["MEDIUM"] > 0:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    return {"severity_counts": sev_counts, "overall_risk": overall}

def build_recommendations(s, dashboard, ti_rows):
    """Builds a list of actionable recommendation strings based on collected data."""
    recs = []

    if dashboard["severity_counts"]["CRITICAL"] > 0:
        recs.append(
            "One or more CRITICAL findings were observed (successful authentication "
            "and/or malware capture). Review session replays for affected hosts and "
            "rotate any credentials that were exposed in honeyfiles."
        )

    if s["login_success"] > 0:
        recs.append(
            f"{s['login_success']} successful SSH login(s) were recorded on the Cowrie "
            "honeypot. Confirm decoy credentials are rotated on schedule and that no "
            "production systems share these credentials."
        )

    bf_count = sum(1 for r in s["zeek_notice_list"] if r[1] == "SSH BRUTE")
    if s["login_failed"] > 500 or bf_count > 0:
        recs.append(
            "High volume of SSH brute-force activity detected. Consider tightening "
            "perimeter ACLs around the OT network segment and monitoring for the same "
            "credential patterns on production-facing SSH services."
        )

    if s["modbus_events"] > 0 or s["conpot_events"] > 0:
        recs.append(
            "Industrial protocol probing (Modbus/S7Comm) was observed against the SCADA "
            "decoy. Verify that production PLCs are not reachable from the same network "
            "segments and that Modbus traffic is restricted via firewall ACLs."
        )

    if s["smb_events"] > 0:
        recs.append(
            "SMB exploitation attempts consistent with EternalBlue/WannaCry patterns were "
            "captured. Confirm MS17-010 patches are applied across the environment and "
            "that SMBv1 is disabled where not required."
        )

    if any(row[-1] in ("KNOWN MALICIOUS", "APT CANDIDATE") for row in ti_rows):
        recs.append(
            "At least one source IP was classified as KNOWN MALICIOUS or an APT candidate. "
            "Consider adding these IOCs to perimeter blocklists and cross-referencing "
            "against existing SIEM alerts for the same period."
        )

    if not recs:
        recs.append(
            "No high-severity findings were identified in this reporting period. "
            "Continue routine monitoring and maintain current decoy rotation schedule."
        )

    recs.append(
        "Continue weekly review of this report and compare attacker TTPs against the "
        "MITRE ATT&CK coverage table to identify emerging patterns over time."
    )

    return recs

# ==============================================================================
# PDF STYLES & TABLE HELPERS
# ==============================================================================

def get_styles():
    styles = getSampleStyleSheet()
    return {
        "title":    ParagraphStyle("T",  parent=styles["Title"], fontSize=20,
                                   textColor=colors.darkred,
                                   alignment=TA_CENTER, spaceAfter=4),
        "subtitle": ParagraphStyle("ST", parent=styles["Normal"], fontSize=10,
                                   textColor=colors.grey, alignment=TA_CENTER),
        "h1":       ParagraphStyle("H1", parent=styles["Heading1"], fontSize=13,
                                   textColor=colors.darkblue,
                                   spaceBefore=10, spaceAfter=5),
        "h2":       ParagraphStyle("H2", parent=styles["Heading2"], fontSize=11,
                                   textColor=colors.HexColor("#1a5276"),
                                   spaceBefore=6, spaceAfter=3),
        "normal":   styles["Normal"],
        "bullet":   ParagraphStyle("B", parent=styles["Normal"],
                                   leftIndent=15, spaceAfter=2),
        "rec":      ParagraphStyle("R", parent=styles["Normal"],
                                   leftIndent=15, spaceAfter=6, fontSize=10),
        "small":    ParagraphStyle("S", parent=styles["Normal"],
                                   fontSize=8, textColor=colors.grey),
    }

def make_table(data, col_widths, header_color=colors.darkblue):
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  header_color),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, 0),  10),
        ("GRID",           (0, 0), (-1, -1), 0.4, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#eaf4fb")]),
        ("PADDING",        (0, 0), (-1, -1), 5),
        ("FONTSIZE",       (0, 1), (-1, -1), 9),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t

def make_dashboard_table(dashboard, s):
    """Threat Severity Dashboard — first thing reviewers see."""
    sev = dashboard["severity_counts"]
    overall = dashboard["overall_risk"]

    data = [
        ["Metric", "Value"],
        ["Overall Risk Level",       overall],
        ["Total Events Collected",   f"{s['total_events']:,}"],
        ["External Source IPs",      f"{len(s['top_ips'])}"],
        ["CRITICAL Findings",        str(sev["CRITICAL"])],
        ["HIGH Findings",            str(sev["HIGH"])],
        ["MEDIUM Findings",          str(sev["MEDIUM"])],
        ["LOW Findings",             str(sev["LOW"])],
    ]
    t = Table(data, colWidths=[9*cm, 8*cm])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0), 10),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.grey),
        ("PADDING",    (0, 0), (-1, -1), 6),
        ("FONTSIZE",   (0, 1), (-1, -1), 10),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 1), (-1, 1), SEVERITY_COLOR.get(overall, colors.grey)),
        ("TEXTCOLOR",  (0, 1), (-1, 1), colors.white),
        ("FONTNAME",   (0, 1), (-1, 1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#fdecea")),
        ("BACKGROUND", (0, 5), (-1, 5), colors.HexColor("#fef5e7")),
        ("BACKGROUND", (0, 6), (-1, 6), colors.HexColor("#fef9e7")),
        ("BACKGROUND", (0, 7), (-1, 7), colors.HexColor("#eaf4fb")),
    ]
    t.setStyle(TableStyle(style_cmds))
    return t

def make_ti_table(rows):
    """Top Attacker IPs table — severity column instead of raw classification only."""
    data = [["#", "IP Address", "Country", "ISP",
             "Abuse%", "Reports", "Classification", "Severity"]]

    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0),  colors.HexColor("#922b21")),
        ("TEXTCOLOR",  (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",   (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0),  8),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.grey),
        ("PADDING",    (0, 0), (-1, -1), 4),
        ("FONTSIZE",   (0, 1), (-1, -1), 8),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]

    for i, row in enumerate(rows, 1):
        data.append(row)
        sev = row[-1]
        clr = {
            "CRITICAL": colors.HexColor("#fdecea"),
            "HIGH":     colors.HexColor("#fef5e7"),
            "MEDIUM":   colors.HexColor("#fef9e7"),
            "LOW":      colors.white,
            "INFO":     colors.HexColor("#f4f6f7"),
        }.get(sev, colors.white)
        style_cmds.append(("BACKGROUND", (0, i), (-1, i), clr))
        if sev in ("CRITICAL", "HIGH"):
            style_cmds.append(("TEXTCOLOR", (0, i), (-1, i), colors.darkred))
            style_cmds.append(("FONTNAME",  (0, i), (-1, i), "Helvetica-Bold"))

    t = Table(data, colWidths=[0.7*cm, 3.2*cm, 2.2*cm, 4*cm,
                                1.5*cm, 1.8*cm, 3.3*cm, 2.3*cm])
    t.setStyle(TableStyle(style_cmds))
    return t

def make_password_table(failed_list, success_list):
    """Username/password table with Risk column."""
    data = [["Value", "Attempts", "Result", "Risk"]]
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0),  colors.darkblue),
        ("TEXTCOLOR",  (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",   (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0),  10),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.grey),
        ("PADDING",    (0, 0), (-1, -1), 5),
        ("FONTSIZE",   (0, 1), (-1, -1), 9),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]
    row_idx = 1
    for p, cnt in failed_list:
        risk = "HIGH" if cnt > 500 else ("MEDIUM" if cnt > 50 else "LOW")
        data.append([str(p), f"{cnt:,}", "Failed", risk])
        style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#fdecea")))
        row_idx += 1
    for p, cnt in success_list:
        data.append([str(p), f"{cnt:,}", "Success", "CRITICAL"])
        style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#fdecea")))
        style_cmds.append(("TEXTCOLOR",  (0, row_idx), (-1, row_idx), colors.darkred))
        style_cmds.append(("FONTNAME",   (0, row_idx), (-1, row_idx), "Helvetica-Bold"))
        row_idx += 1
    t = Table(data, colWidths=[6*cm, 3.5*cm, 3.5*cm, 4*cm])
    t.setStyle(TableStyle(style_cmds))
    return t

def make_username_table(usernames):
    """Username attempts table with Risk column."""
    data = [["Username", "Attempts", "Risk"]]
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0),  colors.darkblue),
        ("TEXTCOLOR",  (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",   (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0),  10),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.grey),
        ("PADDING",    (0, 0), (-1, -1), 5),
        ("FONTSIZE",   (0, 1), (-1, -1), 9),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i, (u, cnt) in enumerate(usernames, 1):
        risk = "HIGH" if cnt > 1000 else ("MEDIUM" if cnt > 50 else "LOW")
        data.append([u, f"{cnt:,}", risk])
        clr = {
            "HIGH":   colors.HexColor("#fdecea"),
            "MEDIUM": colors.HexColor("#fef9e7"),
            "LOW":    colors.white,
        }[risk]
        style_cmds.append(("BACKGROUND", (0, i), (-1, i), clr))
    t = Table(data, colWidths=[8*cm, 4.5*cm, 4.5*cm])
    t.setStyle(TableStyle(style_cmds))
    return t

def make_notice_table(notices):
    """Zeek network detection alerts table — with MITRE technique column."""
    data = [["Timestamp", "Alert Type", "Source IP", "MITRE", "Details"]]
    colors_map = {
        "SSH LOGIN SUCCESS": colors.HexColor("#fdecea"),
        "SSH BRUTE":         colors.HexColor("#fef5e7"),
        "PORT SCAN":         colors.HexColor("#eaf4fb"),
        "PING SWEEP":        colors.HexColor("#eafbea"),
        "HONEYPOT ACCESS":   colors.HexColor("#f4ecf7"),
        "MALWARE DOWNLOAD":  colors.HexColor("#fdecea"),
        "SCANNER":           colors.HexColor("#fef9e7"),
    }
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0),  colors.HexColor("#1a5276")),
        ("TEXTCOLOR",  (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",   (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0),  8),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.grey),
        ("PADDING",    (0, 0), (-1, -1), 4),
        ("FONTSIZE",   (0, 1), (-1, -1), 8),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]

    for i, (ts, alert_type, detail, src_ip) in enumerate(notices, 1):
        mitre_info = ALERT_MITRE_MAP.get(alert_type, ("—", "—"))
        mitre_str = f"{mitre_info[0]}: {mitre_info[1]}" if mitre_info[0] != "—" else "—"
        short_detail = detail[:60] + "..." if len(detail) > 60 else detail
        ip_display = src_ip if src_ip else "N/A"

        data.append([ts, alert_type, ip_display, mitre_str, short_detail])
        bg = colors_map.get(alert_type, colors.white)
        style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg))

    t = Table(data, colWidths=[3.2*cm, 3.2*cm, 2.8*cm, 3.8*cm, 4*cm])
    t.setStyle(TableStyle(style_cmds))
    return t

def make_command_table(commands):
    """Command & Behavior table mapped to MITRE ATT&CK techniques."""
    data = [["Command", "Exec Count", "MITRE ID", "Technique Name", "Tactic / Category"]]
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0),  colors.HexColor("#1a5276")),
        ("TEXTCOLOR",  (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",   (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0),  8),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.grey),
        ("PADDING",    (0, 0), (-1, -1), 4),
        ("FONTSIZE",   (0, 1), (-1, -1), 8),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]

    for i, (cmd, cnt) in enumerate(commands, 1):
        tid, tname, cat = classify_command(cmd)
        data.append([cmd[:35], f"{cnt:,}", tid, tname, cat])
        clr = colors.HexColor("#fdecea") if cat in ("Credential Access", "Command and Control") else colors.white
        style_cmds.append(("BACKGROUND", (0, i), (-1, i), clr))

    t = Table(data, colWidths=[4.5*cm, 2*cm, 2.2*cm, 4.8*cm, 3.5*cm])
    t.setStyle(TableStyle(style_cmds))
    return t

def make_mitre_summary_table(commands, notices):
    """Aggregated MITRE ATT&CK coverage table across all observations."""
    tech_counts = {}

    for cmd, cnt in commands:
        tid, tname, cat = classify_command(cmd)
        key = (tid, tname, cat)
        tech_counts[key] = tech_counts.get(key, 0) + cnt

    for _, alert_type, _, _ in notices:
        if alert_type in ALERT_MITRE_MAP:
            tid, tname = ALERT_MITRE_MAP[alert_type]
            cat = "Reconnaissance / Initial Access"
            key = (tid, tname, cat)
            tech_counts[key] = tech_counts.get(key, 0) + 1

    data = [["MITRE ID", "Technique Name", "Tactic / Category", "Observations"]]
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0),  colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",  (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",   (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0),  9),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.grey),
        ("PADDING",    (0, 0), (-1, -1), 5),
        ("FONTSIZE",   (0, 1), (-1, -1), 9),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]

    sorted_techs = sorted(tech_counts.items(), key=lambda x: -x[1])
    for i, ((tid, tname, cat), cnt) in enumerate(sorted_techs, 1):
        data.append([tid, tname, cat, f"{cnt:,}"])
        bg = colors.HexColor("#eaf4fb") if i % 2 == 0 else colors.white
        style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg))

    if not sorted_techs:
        data.append(["—", "No techniques observed", "—", "0"])

    t = Table(data, colWidths=[2.5*cm, 6*cm, 5.5*cm, 3*cm])
    t.setStyle(TableStyle(style_cmds))
    return t

# ==============================================================================
# REPORT GENERATOR
# ==============================================================================

def generate_pdf():
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    date_filename = datetime.datetime.now().strftime("%Y-%m-%d")
    out_pdf = os.path.join(REPORT_DIR, f"threat_intel_report_{date_filename}.pdf")

    print("[*] Collecting Honeypot Stats from Elasticsearch...")
    s = collect_stats()

    print("[*] Enriching Attacker IPs via AbuseIPDB & VirusTotal...")
    ti_rows = []
    for idx, (ip, cnt) in enumerate(s["top_ips"][:15], 1):
        e = enrich_ip(ip)
        if e:
            ti_rows.append([
                str(idx), ip, e["country"], e["isp"][:22],
                f"{e['abuse_score']}%", str(e["total_reports"]),
                e["classification"], e["severity"]
            ])
        else:
            ti_rows.append([str(idx), ip, "Unknown", "Unknown", "0%", "0", "OPPORTUNISTIC", "LOW"])

    alert_counts = {}
    for _, alert_type, _, _ in s["zeek_notice_list"]:
        alert_counts[alert_type] = alert_counts.get(alert_type, 0) + 1

    dashboard = compute_dashboard(ti_rows, alert_counts)

    print("[*] Fetching Triage Malware Analysis Samples...")
    triage_samples = get_triage_samples()

    print("[*] Building PDF Document...")
    styles = get_styles()
    doc    = SimpleDocTemplate(out_pdf, pagesize=A4,
                               rightMargin=1.5*cm, leftMargin=1.5*cm,
                               topMargin=1.5*cm,   bottomMargin=1.5*cm)
    story  = []

    story.append(Paragraph("<b>OT THREAT INTELLIGENCE & IOC REPORT</b>", styles["title"]))
    story.append(Paragraph(f"Environment: <b>{HONEYPOT_NAME}</b> | Generated: {now_str} UTC | Window: Last {DAYS} Days", styles["subtitle"]))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.darkred))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("1. Executive Summary", styles["h1"]))
    exec_summary_text = (
        f"This report synthesizes threat intelligence and operational telemetry collected from the "
        f"<b>{HONEYPOT_NAME}</b> deception environment over the trailing {DAYS}-day window. "
        f"During this period, a total of <b>{s['total_events']:,} events</b> were processed across SSH, "
        f"SCADA/ICS, SMB, and network analysis sensors. "
        f"Overall environment risk status is evaluated as <b>{dashboard['overall_risk']}</b> based on "
        f"observed attacker techniques, authentication outcomes, and threat intelligence enrichment."
    )
    story.append(Paragraph(exec_summary_text, styles["normal"]))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("2. Threat Severity Dashboard", styles["h1"]))
    story.append(make_dashboard_table(dashboard, s))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("3. Environment Overview & Sensor Telemetry", styles["h1"]))
    env_data = [
        ["Sensor / Decoy Service", "Target Protocol / Stack", "Events Captured (7d)"],
        ["Cowrie SSH/Telnet Decoy", "SSH (22), Telnet (23)", f"{s['cowrie_events']:,}"],
        ["Conpot SCADA Decoy", "Modbus TCP (502), S7Comm (102)", f"{s['conpot_events']:,}"],
        ["Dionaea Malware Trap", "SMB (445), MQTT (1883), HTTP", f"{s['dionaea_events']:,}"],
        ["Zeek Network Monitor", "Protocol Logging & Anomaly Detection", f"{s['zeek_events']:,}"],
        ["Suricata NIDS", "Signature-Based Intrusion Detection", f"{s['suricata_alerts']:,}"],
    ]
    story.append(make_table(env_data, [6*cm, 6.5*cm, 4.5*cm]))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("4. Threat Landscape — Top External Attacker IPs & TI", styles["h1"]))
    story.append(Paragraph(
        "Source IP addresses enriched via AbuseIPDB and VirusTotal. Internal/private addresses "
        "have been excluded from this threat intelligence summary.", styles["normal"]
    ))
    story.append(Spacer(1, 0.2*cm))
    if ti_rows:
        story.append(make_ti_table(ti_rows))
    else:
        story.append(Paragraph("<i>No external attacker IPs captured in this reporting period.</i>", styles["normal"]))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("5. Authentication Analysis (Cowrie Decoy)", styles["h1"]))
    story.append(Paragraph(f"Total Session Connects: <b>{s['new_sessions']:,}</b> | Failed Logins: <b>{s['login_failed']:,}</b> | Successful Logins: <b>{s['login_success']:,}</b>", styles["normal"]))
    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph("Top Targeted Usernames", styles["h2"]))
    if s["top_usernames"]:
        story.append(make_username_table(s["top_usernames"]))
    else:
        story.append(Paragraph("<i>No username data recorded.</i>", styles["normal"]))
    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph("Top Passwords Attempted & Tested Credentials", styles["h2"]))
    if s["top_passwords_failed"] or s["top_passwords_success"]:
        story.append(make_password_table(s["top_passwords_failed"][:7], s["top_passwords_success"][:5]))
    else:
        story.append(Paragraph("<i>No password data recorded.</i>", styles["normal"]))
    story.append(Spacer(1, 0.4*cm))

    story.append(PageBreak())

    story.append(Paragraph("6. Network Activity & Zeek Detection Alerts", styles["h1"]))
    story.append(Paragraph("Zeek behavioral notices and network-layer anomaly detections:", styles["normal"]))
    story.append(Spacer(1, 0.2*cm))
    if s["zeek_notice_list"]:
        story.append(make_notice_table(s["zeek_notice_list"][:12]))
    else:
        story.append(Paragraph("<i>No Zeek network notices generated in this period.</i>", styles["normal"]))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("7. Command & Interactive Behavior Analysis", styles["h1"]))
    story.append(Paragraph("Attacker commands captured inside Cowrie SSH sessions, mapped to MITRE ATT&CK techniques:", styles["normal"]))
    story.append(Spacer(1, 0.2*cm))
    if s["top_commands"]:
        story.append(make_command_table(s["top_commands"]))
    else:
        story.append(Paragraph("<i>No interactive commands executed in this period.</i>", styles["normal"]))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("8. Malware Analysis & Triage Sandbox Integrations", styles["h1"]))
    if triage_samples:
        triage_data = [["Sample ID", "Filename / Hash", "Score", "Family / Tags"]]
        for sample in triage_samples[:8]:
            sid   = sample.get("id", "N/A")
            fname = sample.get("filename", "N/A")[:25]
            score = str(sample.get("score", 0))
            tags  = ", ".join(sample.get("tags", []))[:30] or "N/A"
            triage_data.append([sid, fname, score, tags])
        story.append(make_table(triage_data, [3.5*cm, 5.5*cm, 2*cm, 6*cm]))
    else:
        story.append(Paragraph(
            "<i>No automated malware sandbox submissions recorded for this reporting period. "
            "Ensure Hatching Triage API key is configured if malware detonation tracking is required.</i>",
            styles["normal"]
        ))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("9. MITRE ATT&CK Coverage Summary", styles["h1"]))
    story.append(Paragraph("Consolidated mapping of all adversary TTPs observed across sensors during this reporting window:", styles["normal"]))
    story.append(Spacer(1, 0.2*cm))
    story.append(make_mitre_summary_table(s["top_commands"], s["zeek_notice_list"]))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("10. Risk Assessment & Actionable Recommendations", styles["h1"]))
    recommendations = build_recommendations(s, dashboard, ti_rows)
    for rec in recommendations:
        story.append(Paragraph(f"• {rec}", styles["rec"]))
    story.append(Spacer(1, 0.4*cm))

    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "CONFIDENTIAL — Internal SOC/Threat Intelligence Deliverable. "
        "Generated automatically by OT Deception Engine.", styles["small"]
    ))

    doc.build(story)
    print(f"[+] Report generated successfully: {out_pdf}")

if __name__ == "__main__":
    generate_pdf()
