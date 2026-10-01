# IoT Deception Honeypot Network

A multi-service honeypot lab that emulates an industrial/IoT environment, collects attacker activity, and turns it into alerts, reports and a SOC-style dashboard.

## Components
- **Honeypots:** Cowrie (SSH/Telnet), Conpot (ICS/SCADA), Dionaea (SMB, MySQL, HTTP, MQTT)
- **Network monitoring:** Zeek (`zeek_detect.zeek`)
- **Pipeline:** Filebeat → Elasticsearch → Kibana
- **Analysis & reporting:** attacker profiling, ML analyzer, IOC report, daily report, session replay
- **Alerting:** real-time Telegram alerts (`alert.py`)
- **Threat intel:** AbuseIPDB, Triage sandbox
- **Dashboard:** `soc_dashboard.html` served via a localhost-only `soc_proxy.py`

## Setup
```bash
git clone <repo-url> honeypot && cd honeypot
cp .env.example .env && chmod 600 .env     # fill in your own values
```
Secrets are read from `.env` only. Nothing sensitive is stored in the repository.

Optional auto-start on Linux (systemd services + timers):
```bash
bash setup_autostart.sh
```

## Security notes
- `soc_proxy.py` binds to `127.0.0.1` and restricts CORS to a single origin. Do not expose it publicly.
- `ES_VERIFY_SSL=false` is intended for a local self-signed Elasticsearch only, not production.
- Data shown in the dashboard comes from attackers; treat it as untrusted input.
- Run the honeypots in an isolated network/VM. Never on a production network.
- Attacker data, logs, binaries and credentials are excluded via `.gitignore`.

## Disclaimer
For educational and defensive security research only.
