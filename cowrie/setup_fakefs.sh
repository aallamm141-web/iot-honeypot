import os
import pickle
import time

# Canary tokens and bait files live in a folder that is NOT committed to git.
# Inside the image it ends up at /cowrie/cowrie-git/canary_assets/ (copied with the build context).
#   canary_url.txt                          -> your canarytokens.com web-bug URL (one line)
#   SCADA_Network_Credentials_2024.docx     -> optional, docx canary token
#   SCADA_Backup_Tool.ps1                   -> optional, ps1 with DNS canary
ASSETS_DIR = os.environ.get("CANARY_ASSETS_DIR", "/cowrie/cowrie-git/canary_assets")
FS_PATH = "/cowrie/cowrie-git/src/cowrie/data/fs.pickle"

DOCX_NAME = "SCADA_Network_Credentials_2024.docx"
PS1_NAME = "SCADA_Backup_Tool.ps1"


def read_asset(name, mode="rb"):
    path = os.path.join(ASSETS_DIR, name)
    if not os.path.isfile(path):
        return None
    with open(path, mode) as f:
        return f.read()


CANARY_URL = (read_asset("canary_url.txt", "r") or "").strip()
if not CANARY_URL:
    CANARY_URL = "http://canarytokens.example/REPLACE_ME"
    print("[!] canary_assets/canary_url.txt not found - using placeholder URL")

readme_content = f"""=== SCADA Gateway Configuration ===
Last updated: 2025-11-03
Admin: eng.operations@company.local
System Status: ONLINE
Access Level: RESTRICTED
For support visit: {CANARY_URL}
DO NOT SHARE THIS FILE
""".encode()

backup_content = f"""#!/bin/bash
# SCADA Backup Script v3.2
# Last modified: 2025-11-03
# Support: {CANARY_URL}
BACKUP_DIR=/opt/scada/backup
DB_HOST=192.168.1.100
DB_USER=scada_admin
DB_PASS=Sc@da#Pr0d2025!
DB_NAME=production_data
mysqldump -h $DB_HOST -u $DB_USER -p$DB_PASS $DB_NAME > $BACKUP_DIR/backup_$(date +%Y%m%d).sql
echo "[+] Backup completed"
""".encode()

config_content = f"""[database]
host=192.168.1.100
port=3306
user=scada_admin
password=Sc@da#Pr0d2025!
name=production_data
last_updated=2025-11-03

[plc]
ip=192.168.1.200
port=502
slave_id=1
firmware=v4.2.1

[mqtt]
broker=192.168.1.1
port=1883
topic=scada/sensors

[support]
url={CANARY_URL}
""".encode()

credentials_content = f"""# SCADA System Credentials
# Last updated: 2025-11-03
# Reference: {CANARY_URL}

[web_interface]
url=http://192.168.1.1:80
username=scada_admin
password=Sc@da#Pr0d2025!

[database]
host=192.168.1.100
username=scada_admin
password=Sc@da#Pr0d2025!

[plc_gateway]
ip=192.168.1.200
username=admin
password=Plc#Adm!n2025

[ssh_backup]
host=192.168.1.150
username=backup_user
password=B@ckup#2025!
""".encode()

docx_content = read_asset(DOCX_NAME)
ps1_content = read_asset(PS1_NAME)

mtime = int(time.time())


def make_entry(name, mode, content):
    return [name, 2, 0, 0, len(content), mode, mtime, [], content, None]


new_files = [
    make_entry("readme.txt", 33188, readme_content),
    make_entry("backup.sh", 33261, backup_content),
    make_entry("config.ini", 33188, config_content),
    make_entry("credentials.txt", 33188, credentials_content),
]

if docx_content:
    new_files.append(make_entry(DOCX_NAME, 33188, docx_content))
else:
    print(f"[!] {DOCX_NAME} not found in {ASSETS_DIR} - skipped")

if ps1_content:
    new_files.append(make_entry(PS1_NAME, 33188, ps1_content))
else:
    print(f"[!] {PS1_NAME} not found in {ASSETS_DIR} - skipped")

our_files = {"readme.txt", "backup.sh", "config.ini", "credentials.txt", DOCX_NAME, PS1_NAME}

with open(FS_PATH, "rb") as f:
    fs = pickle.load(f)

children = fs[7]
for item in children:
    if item[0] == "root":
        item[7] = [f for f in item[7] if f[0] not in our_files]
        item[7].extend(new_files)
        print(f"Files in /root: {[f[0] for f in item[7]]}")
        break

with open(FS_PATH, "wb") as f:
    pickle.dump(fs, f)

print("fs.pickle updated successfully!")
