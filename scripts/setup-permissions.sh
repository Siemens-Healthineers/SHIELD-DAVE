#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

echo "Setting up  file permissions and user groups..."

# Get current user
CURRENT_USER=$(whoami)
echo "Current user: $CURRENT_USER"

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "This script needs to be run with sudo privileges"
    echo "Usage: sudo bash scripts/setup-permissions.sh"
    exit 1
fi

# Add current user to www-data group if not already a member
if ! groups $SUDO_USER | grep -q "\bwww-data\b"; then
    echo "Adding $SUDO_USER to www-data group..."
    usermod -a -G www-data $SUDO_USER
    echo "✅ User $SUDO_USER added to www-data group"
    echo "⚠️  Note: You may need to log out and log back in for group changes to take effect"
else
    echo "✅ User $SUDO_USER is already in www-data group"
fi

# Set proper ownership for the application directory
echo "Setting ownership for /var/www/html..."
chown -R www-data:www-data /var/www/html

# Set proper permissions for files (664) and directories (775)
echo "Setting file permissions..."
find /var/www/html -type f -exec chmod 664 {} \;
find /var/www/html -type d -exec chmod 775 {} \;

# Set executable permissions for scripts
echo "Setting executable permissions for scripts..."
chmod +x /var/www/html/scripts/*.sh 2>/dev/null || true
chmod +x /var/www/html/.github/workflows/*.sh 2>/dev/null || true

# Create and set permissions for session directory
echo "Setting up PHP session directory..."
mkdir -p /tmp/php_sessions
chmod 777 /tmp/php_sessions
chown www-data:www-data /tmp/php_sessions

# Create and set permissions for logs directory
echo "Setting up logs directory..."
mkdir -p /var/www/html/logs
chmod 775 /var/www/html/logs
chown www-data:www-data /var/www/html/logs
touch /var/www/html/logs/.gitkeep

# Create and set permissions for uploads directory
echo "Setting up uploads directory..."
mkdir -p /var/www/html/uploads
chmod 775 /var/www/html/uploads
chown www-data:www-data /var/www/html/uploads
touch /var/www/html/uploads/.gitkeep

# Create and set permissions for temp directory
echo "Setting up temp directory..."
mkdir -p /var/www/html/temp
chmod 775 /var/www/html/temp
chown www-data:www-data /var/www/html/temp
touch /var/www/html/temp/.gitkeep

# Create and set permissions for cache directory
echo "Setting up cache directory..."
mkdir -p /var/www/html/temp/cache
chmod 775 /var/www/html/temp/cache
chown www-data:www-data /var/www/html/temp/cache

# Create and set permissions for backup directory
echo "Setting up backup directory..."
mkdir -p /var/backups/dave

# Set up group permissions for shared access (no sudo required)
# This allows both www-data and other users to manage files
chmod 2775 /var/backups/dave
chgrp www-data /var/backups/dave 2>/dev/null || true
touch /var/backups/dave/.gitkeep

# Fix permissions on existing backup files (group-based approach)
echo "Fixing permissions on existing backup files..."
# Set group ownership to www-data for all files (no sudo required)
chgrp -R www-data /var/backups/dave/ 2>/dev/null || true
chmod -R 664 /var/backups/dave/* 2>/dev/null || true
chmod 2775 /var/backups/dave/ 2>/dev/null || true

echo ""
echo "✅ Permissions setup complete!"
echo ""
echo "Summary:"
echo "  - User $SUDO_USER added to www-data group"
echo "  - Application files owned by www-data:www-data"
echo "  - File permissions set to 664"
echo "  - Directory permissions set to 775"
echo "  - Session, logs, uploads, temp, backup directories created with proper permissions"
echo ""
echo "⚠️  IMPORTANT: Log out and log back in for group changes to take effect!"
echo ""

