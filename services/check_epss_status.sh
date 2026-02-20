#!/bin/bash

# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# Check EPSS sync status

LOG_FILE="/var/www/html/logs/epss_sync.log"
DB_CONFIG_FILE="/var/www/html/config/database.php"

echo "=== EPSS Sync Status ==="
echo

# Check if log file exists
if [ -f "$LOG_FILE" ]; then
    echo "Last sync log entries:"
    tail -n 10 "$LOG_FILE"
    echo
else
    echo "No sync log file found at $LOG_FILE"
    echo
fi

# Check cron job
echo "Cron job status:"
crontab -u www-data -l 2>/dev/null | grep epss_sync_service.py || echo "No EPSS cron job found"
echo

# Check database sync log (if database is accessible)
if [ -f "$DB_CONFIG_FILE" ]; then
    echo "Database sync log (last 5 entries):"
    # This would require database access - placeholder for now
    echo "Database check requires manual verification"
else
    echo "Database config not found"
fi
