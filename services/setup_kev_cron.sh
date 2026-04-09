#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */


set -e

echo "=========================================="
echo " KEV Sync Cron Job Setup"
echo "=========================================="
echo ""

APP_ROOT="/var/www/html"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

# Create cron job to run KEV sync daily at 2 AM
CRON_JOB="0 2 * * * www-data cd $APP_ROOT && /usr/bin/python3 $APP_ROOT/services/kev_sync_service.py >> $APP_ROOT/logs/kev_sync.log 2>&1"

# Check if cron job already exists
if crontab -u www-data -l 2>/dev/null | grep -q "kev_sync_service.py"; then
    echo "KEV sync cron job already exists"
else
    # Add cron job
    (crontab -u www-data -l 2>/dev/null; echo "$CRON_JOB") | crontab -u www-data -
    echo "✓ KEV sync cron job added (runs daily at 2 AM)"
fi

# Make service executable
chmod +x "$APP_ROOT/services/kev_sync_service.py"

# Create logs directory if it doesn't exist
mkdir -p "$APP_ROOT/logs"
chown www-data:www-data "$APP_ROOT/logs"

# Run initial sync
echo ""
echo "Running initial KEV catalog sync..."
su - www-data -s /bin/bash -c "cd $APP_ROOT && python3 $APP_ROOT/services/kev_sync_service.py" || {
    echo "WARNING: Initial sync failed. Check logs at $APP_ROOT/logs/kev_sync.log"
}

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Cron Schedule: Daily at 2:00 AM"
echo "Log File: $APP_ROOT/logs/kev_sync.log"
echo ""
echo "To manually run sync:"
echo "  sudo -u www-data python3 $APP_ROOT/services/kev_sync_service.py"
echo ""
echo "To view cron jobs:"
echo "  crontab -u www-data -l"
echo ""

