#!/bin/bash

# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

set -e

echo "=========================================="
echo " SBOM Evaluation Service Installer"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

# Install Python dependencies
echo "[1/6] Installing Python dependencies..."
pip3 install psycopg2-binary requests || {
    echo "ERROR: Failed to install Python dependencies"
    exit 1
}

# Create logs directory
echo "[2/6] Creating logs directory..."
mkdir -p /var/www/html/logs
chown www-data:www-data /var/www/html/logs
chmod 755 /var/www/html/logs

# Make service script executable
echo "[3/6] Setting permissions on service script..."
chmod +x /var/www/html/services/sbom_evaluation_service.py
chown www-data:www-data /var/www/html/services/sbom_evaluation_service.py

# Apply database migrations
echo "[4/6] Applying database migrations..."
readonly APP_ROOT="/var/www/html"
source "$APP_ROOT/.env"
DB_NAME=${3:-$DB_NAME}
su - postgres -c "psql -d $DB_NAME -f /var/www/html/database/migrations/008_create_sbom_evaluation_queue.sql" || {
    echo "WARNING: Database migration may have failed. Check if tables already exist."
}

# Copy systemd service file
echo "[5/6] Installing systemd service..."
cp /var/www/html/services/dave-sbom-evaluation.service /etc/systemd/system/
chmod 644 /etc/systemd/system/dave-sbom-evaluation.service

# Reload systemd and enable service
echo "[6/6] Enabling and starting service..."
systemctl daemon-reload
systemctl enable dave-sbom-evaluation.service
systemctl start dave-sbom-evaluation.service

# Check service status
echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Service Status:"
systemctl status dave-sbom-evaluation.service --no-pager || true
echo ""
echo "Useful Commands:"
echo "  View status:   sudo systemctl status dave-sbom-evaluation"
echo "  View logs:     sudo journalctl -u dave-sbom-evaluation -f"
echo "  Restart:       sudo systemctl restart dave-sbom-evaluation"
echo "  Stop:          sudo systemctl stop dave-sbom-evaluation"
echo ""
echo "Log files are located at: /var/www/html/logs/sbom_evaluation.log"
echo ""

