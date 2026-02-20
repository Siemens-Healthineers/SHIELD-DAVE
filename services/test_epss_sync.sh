#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# Test script for EPSS sync service

echo "Testing EPSS sync service..."
echo "Logs will be written to /var/www/html/logs/epss_sync.log"
echo "Starting sync..."

/usr/bin/python3 /var/www/html/services/epss_sync_service.py

echo "EPSS sync test completed. Check the log file for details."
