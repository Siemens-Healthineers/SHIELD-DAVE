#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */


APP_ROOT="/var/www/html"
echo "=========================================="
echo " SBOM Evaluation Alternatives Setup"
echo "=========================================="
echo ""
echo "Choose your preferred approach:"
echo "1. Cron-based processing (runs every 2 minutes)"
echo "2. Async processing (immediate after upload)"
echo "3. Webhook-based processing (external trigger)"
echo "4. All three (maximum flexibility)"
echo ""

read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        echo "Setting up Cron-based processing..."
        bash "$APP_ROOT/services/setup_sbom_cron.sh"
        ;;
    2)
        echo "Setting up Async processing..."
        echo "✅ Async processing is already configured in upload-sbom.php"
        echo "✅ No additional setup required"
        ;;
    3)
        echo "Setting up Webhook-based processing..."
        echo "✅ Webhook endpoint created at /api/v1/sbom/process.php"
        echo "✅ Can be triggered via POST request"
        ;;
    4)
        echo "Setting up all three approaches..."
        bash "$APP_ROOT/services/setup_sbom_cron.sh"
        echo "✅ Async processing configured"
        echo "✅ Webhook endpoint created"
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Available approaches:"
echo ""

if [ "$choice" = "1" ] || [ "$choice" = "4" ]; then
    echo "🕒 CRON-BASED PROCESSING:"
    echo "   - Runs every 2 minutes"
    echo "   - Processes one SBOM per run"
    echo "   - View logs: tail -f $APP_ROOT/logs/sbom_cron.log"
    echo "   - Remove: crontab -e (delete sbom_cron_processor.py line)"
    echo ""
fi

if [ "$choice" = "2" ] || [ "$choice" = "4" ]; then
    echo "⚡ ASYNC PROCESSING:"
    echo "   - Starts immediately after upload"
    echo "   - No external dependencies"
    echo "   - View logs: tail -f $APP_ROOT/logs/apache2/error.log"
    echo ""
fi

if [ "$choice" = "3" ] || [ "$choice" = "4" ]; then
    echo "🔗 WEBHOOK PROCESSING:"
    echo "   - Endpoint: POST /api/v1/sbom/process.php"
    echo "   - Payload: {\"sbom_id\":\"...\",\"device_id\":\"...\",\"user_id\":\"...\"}"
    echo "   - Can be triggered externally"
    echo ""
fi

echo "All approaches work without systemd services!"
echo "Choose the one that best fits your server environment."
