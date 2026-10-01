#!/bin/bash
# Cairo Industrial Complex - SCADA Backup Script
# Author: eng.operations@company.local
# Created: 2026-06-13
# ID: pvdttz0f
# Ref: http://canarytokens.com/articles/images/traffic/2yaxyi9faf2kvzma26z02zu0k/index.html?ref=pvdttz0f&file=backup

BACKUP_DIR=/opt/scada/backup
DB_HOST=10.0.1.101
DB_USER=scada_admin
DB_PASS=Cairo@202292!
DB_NAME=control_system
REMOTE_HOST=backup.company.local
REMOTE_USER=backup_agent
REMOTE_PASS=Admin682411@

# Create backup
echo "[$(date)] Starting backup..."
mysqldump -h $DB_HOST -u $DB_USER -p$DB_PASS $DB_NAME > $BACKUP_DIR/backup_$(date +%Y%m%d_%H%M%S).sql

# Transfer to remote
sshpass -p $REMOTE_PASS scp $BACKUP_DIR/backup_*.sql $REMOTE_USER@$REMOTE_HOST:/backups/

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -name "*.sql" -mtime +7 -delete

echo "[$(date)] Backup completed successfully"
