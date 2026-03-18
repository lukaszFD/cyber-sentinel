#!/bin/bash
set -e

# --- CONFIGURATION ---
PROJECT_DIR="/home/hunter"
BACKUP_DEST="/mnt/backup_ssd"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="sentinel_full_$TIMESTAMP"
BACKUP_PATH="$BACKUP_DEST/$BACKUP_NAME"
RETENTION_COUNT=5

# Create backup directory
mkdir -p "$BACKUP_PATH"

echo "--- Starting Backup: $TIMESTAMP ---"

# 1. Database Dumps
echo "Dumping databases..."
# Note: Use your actual root password or .env variable here
docker exec mysql_db /usr/bin/mysqldump -u root --password=root_password cyber_intelligence > "$BACKUP_PATH/mysql_dump.sql" 2>/dev/null || echo "MySQL dump failed, skipping..."
docker exec mongo /usr/bin/mongodump --archive > "$BACKUP_PATH/mongo_dump.archive" 2>/dev/null || echo "Mongo dump failed, skipping..."

# 2. Stop Stack
echo "Stopping Docker stack..."
cd "$PROJECT_DIR"
docker-compose -f docker-compose-cyber-sentinel.yml down

# 3. Archive Project Files (Specific list based on your screenshot)
echo "Archiving project files (Vault, Nginx, Pihole, etc.)..."
tar -czf "$BACKUP_PATH/project_files.tar.gz" \
    -C "$PROJECT_DIR" \
    config pihole dnsmasq.d n8n_data portainer_data \
    docker-compose-cyber-sentinel.yml Dockerfile.pdns Dockerfile.log_processor \
    log_processor.py .env 2>/dev/null || echo "Some files were missing, continuing..."

# 4. Archive Named Volumes (n8n, grafana, mysql, mongo)
echo "Archiving Docker named volumes..."
# n8n_data and others are in /var/lib/docker/volumes/
for vol in n8n_data mysql_data mongo_data grafana_data; do
    tar -czf "$BACKUP_PATH/vol_$vol.tar.gz" "/var/lib/docker/volumes/$vol" 2>/dev/null || true
done

# 5. Start Stack
echo "Restarting Docker stack..."
docker-compose -f docker-compose-cyber-sentinel.yml up -d

# 6. Final Compression
cd "$BACKUP_DEST"
tar -cf "$BACKUP_NAME.tar" "$BACKUP_NAME"
rm -rf "$BACKUP_NAME"

# 7. Retention: Keep only the 5 most recent backups
echo "Cleaning up old backups..."
ls -tp "$BACKUP_DEST"/sentinel_full_*.tar | grep -v '/$' | tail -n +$((RETENTION_COUNT + 1)) | xargs -I {} rm -- {}

echo "--- Backup Completed Successfully ---"