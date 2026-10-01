#!/usr/bin/env bash
# يولّد ويفعّل كل خدمات systemd للـ honeypot. الملف ده يفضل على جهازك ومايترفعش على GitHub.
# تشغيل:  bash setup_autostart.sh
# تخصيص:  PROJ=/path ENV_FILE=/path/.env PY=/path/python bash setup_autostart.sh
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
  echo "شغّله بـ user عادي مش root (هيطلب sudo لوحده)"; exit 1
fi

U="$(id -un)"
H="$HOME"
PROJ="${PROJ:-$H/honeypot}"
ENV_FILE="${ENV_FILE:-$PROJ/.env}"
PY="${PY:-/usr/bin/python3}"        # لو بتستخدم venv حط مساره هنا
UNITS=/etc/systemd/system
ENABLE=()

[ -d "$PROJ" ]     || { echo "مفيش مجلد $PROJ"; exit 1; }
[ -f "$ENV_FILE" ] || { echo "مفيش ملف $ENV_FILE"; exit 1; }
chmod 600 "$ENV_FILE"

# ملاحظة: EnvironmentFile في systemd ما بيفهمش "export VAR=..." ولا $VAR جوه القيم
if grep -qE '^\s*export ' "$ENV_FILE"; then
  echo "تحذير: فيه 'export' في $ENV_FILE، شيلها (سطور KEY=value بس)"
fi

put() { sudo tee "$1" >/dev/null; }

# ---------- خدمة شغالة طول الوقت ----------
svc() {  # svc <name> <script> <description>
  local n="$1" s="$2" d="$3"
  [ -f "$PROJ/$s" ] || { echo "skip: $s مش موجود"; return; }
  put "$UNITS/$n.service" <<EOF
[Unit]
Description=$d
After=network-online.target docker.service elasticsearch.service
Wants=network-online.target

[Service]
User=${4:-$U}
WorkingDirectory=$PROJ
EnvironmentFile=$ENV_FILE
ExecStart=$PY $PROJ/$s
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  ENABLE+=("$n.service")
}

# ---------- سكريبت دوري (service + timer) ----------
timer() {  # timer <name> <script> <OnCalendar> <description>
  local n="$1" s="$2" cal="$3" d="$4"
  [ -f "$PROJ/$s" ] || { echo "skip: $s مش موجود"; return; }
  put "$UNITS/$n.service" <<EOF
[Unit]
Description=$d
After=network-online.target elasticsearch.service
Wants=network-online.target

[Service]
Type=oneshot
User=$U
WorkingDirectory=$PROJ
EnvironmentFile=$ENV_FILE
ExecStart=$PY $PROJ/$s
TimeoutStartSec=1h
EOF
  put "$UNITS/$n.timer" <<EOF
[Unit]
Description=Timer: $d

[Timer]
OnCalendar=$cal
Persistent=true
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
EOF
  ENABLE+=("$n.timer")
}

# ================= الخدمات المستمرة =================
svc soc-proxy soc_proxy.py "SOC Proxy (localhost only)"
svc honeypot-alert alert.py "Honeypot real-time alerts" root   # root لأن COWRIE_LOG_PATH جوه /var/lib/docker

# ================= السكريبتات الدورية (عدّل المواعيد براحتك) =================
timer honeypot-profiler    attacker_profiler.py   "hourly"              "Attacker profiler"
timer honeypot-uploader    uploader.py            "*-*-* *:15:00"       "Uploader (hourly)"
timer honeypot-ml          ml_analyzer.py         "*-*-* 00/6:30:00"    "ML analyzer (every 6h)"
timer honeypot-daily       daily_report.py        "*-*-* 08:00:00"      "Daily report"
timer honeypot-ioc         ioc_report.py          "*-*-* 08:30:00"      "IOC report"
timer honeypot-credrot     credential_rotation.py "*-*-* 03:00:00"      "Credential rotation"

# ================= Docker stacks (Cowrie / Conpot / Dionaea) =================
STACK=""
for f in cowrie/docker-compose.yml cowrie/docker/docker-compose.yml \
         conpot/docker-compose.yml dionaea/docker-compose.yml; do
  [ -f "$PROJ/$f" ] && STACK+="ExecStart=/usr/bin/docker compose -f $PROJ/$f up -d"$'\n'
done

if [ -n "$STACK" ]; then
  put "$UNITS/honeypot-stack.service" <<EOF
[Unit]
Description=Honeypot Docker stacks
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=$U
WorkingDirectory=$PROJ
EnvironmentFile=$ENV_FILE
$STACK
[Install]
WantedBy=multi-user.target
EOF
  ENABLE+=("honeypot-stack.service")
else
  echo "تحذير: ملقيتش أي docker-compose.yml"
fi

# ================= Docker access =================
sudo systemctl enable --now docker
if ! id -nG "$U" | grep -qw docker; then
  sudo usermod -aG docker "$U"
  echo "اتضفت لجروب docker: اعمل logout/login (أو reboot) مرة واحدة"
fi

# ================= الخدمات الجاهزة (لو منصّبة) =================
for s in elasticsearch kibana filebeat; do
  if systemctl list-unit-files "$s.service" | grep -q "$s.service"; then
    sudo systemctl enable "$s"
  fi
done

# ================= تفعيل =================
sudo systemctl daemon-reload
for u in "${ENABLE[@]}"; do
  sudo systemctl enable --now "$u" || echo "فشل تفعيل $u (شوف: journalctl -u $u)"
done

echo
echo "== التايمرات =="
systemctl list-timers --all | grep honeypot || true
echo
echo "== الحالة =="
systemctl --no-pager --type=service list-units 'soc-proxy*' 'honeypot-*' || true
echo
echo "تمام. اعمل reboot للتجربة الأخيرة:  sudo reboot"
