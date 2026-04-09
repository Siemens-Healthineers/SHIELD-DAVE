#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */


APP_ROOT="/var/www/html"
echo "=========================================="
echo " SBOM Cron Processor Setup"
echo "=========================================="

# Make the processor executable
chmod +x "$APP_ROOT/services/sbom_cron_processor.py"

# Create logs directory if it doesn't exist
mkdir -p "$APP_ROOT/logs"

# Set proper permissions
chown -R www-data:www-data "$APP_ROOT/logs"
chmod 755 "$APP_ROOT/logs"

# Create cron job to run every 2 minutes
CRON_JOB="*/2 * * * * /usr/bin/python3 $APP_ROOT/services/sbom_cron_processor.py >> $APP_ROOT/logs/sbom_cron.log 2>&1"

# Add to crontab (avoid duplicates)
(crontab -l 2>/dev/null | grep -v "sbom_cron_processor.py"; echo "$CRON_JOB") | crontab -

echo "Cron job added:"
echo "  - Runs every 2 minutes"
echo "  - Processes one SBOM per run"
echo "  - Logs to $APP_ROOT/logs/sbom_cron.log"
echo ""
echo "To view cron logs:"
echo "  tail -f $APP_ROOT/logs/sbom_cron.log"
echo ""
echo "To remove cron job:"
echo "  crontab -e  # then delete the sbom_cron_processor.py line"
echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
