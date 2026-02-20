#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */


set -e

# Configuration
SCRIPT_DIR="/var/www/html/services"
LOG_DIR="/var/www/html/logs"
CRON_USER="www-data"
PYTHON_PATH="/usr/bin/python3"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================================================${NC}"
echo -e "${BLUE} EPSS Sync Service Setup${NC}"
echo -e "${BLUE}====================================================================================${NC}"

# Check if running as root or with sudo
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root or with sudo${NC}"
   exit 1
fi

# Create log directory if it doesn't exist
echo -e "${YELLOW}Creating log directory...${NC}"
mkdir -p "$LOG_DIR"
chown "$CRON_USER:$CRON_USER" "$LOG_DIR"
chmod 755 "$LOG_DIR"

# Check Python dependencies
echo -e "${YELLOW}Checking Python dependencies...${NC}"

# Check if Python 3 is available
if ! command -v "$PYTHON_PATH" &> /dev/null; then
    echo -e "${RED}Python 3 not found at $PYTHON_PATH${NC}"
    exit 1
fi

# Check if required Python packages are installed
echo -e "${YELLOW}Checking required Python packages...${NC}"

REQUIRED_PACKAGES=("requests" "psycopg2")
MISSING_PACKAGES=()

for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! "$PYTHON_PATH" -c "import $package" 2>/dev/null; then
        MISSING_PACKAGES+=("$package")
    fi
done

if [ ${#MISSING_PACKAGES[@]} -ne 0 ]; then
    echo -e "${YELLOW}Installing missing Python packages: ${MISSING_PACKAGES[*]}${NC}"
    
    # Try to install using pip3
    if command -v pip3 &> /dev/null; then
        pip3 install "${MISSING_PACKAGES[@]}"
    elif command -v pip &> /dev/null; then
        pip install "${MISSING_PACKAGES[@]}"
    else
        echo -e "${RED}pip not found. Please install the following packages manually:${NC}"
        echo -e "${RED}${MISSING_PACKAGES[*]}${NC}"
        exit 1
    fi
fi

# Verify the EPSS sync service script exists and is executable
echo -e "${YELLOW}Verifying EPSS sync service...${NC}"
if [ ! -f "$SCRIPT_DIR/epss_sync_service.py" ]; then
    echo -e "${RED}EPSS sync service not found at $SCRIPT_DIR/epss_sync_service.py${NC}"
    exit 1
fi

# Make the script executable
chmod +x "$SCRIPT_DIR/epss_sync_service.py"

# Test the script syntax
echo -e "${YELLOW}Testing EPSS sync service syntax...${NC}"
if ! "$PYTHON_PATH" -m py_compile "$SCRIPT_DIR/epss_sync_service.py"; then
    echo -e "${RED}EPSS sync service has syntax errors${NC}"
    exit 1
fi

# Create cron job entry
echo -e "${YELLOW}Setting up cron job...${NC}"

# Remove any existing EPSS sync cron jobs
crontab -u "$CRON_USER" -l 2>/dev/null | grep -v "epss_sync_service.py" | crontab -u "$CRON_USER" - 2>/dev/null || true

# Add new cron job (run daily at 2:00 AM, offset from KEV sync at 1:00 AM)
CRON_ENTRY="0 2 * * * $PYTHON_PATH $SCRIPT_DIR/epss_sync_service.py >> $LOG_DIR/epss_sync.log 2>&1"

# Add the cron job
(crontab -u "$CRON_USER" -l 2>/dev/null; echo "$CRON_ENTRY") | crontab -u "$CRON_USER" -

echo -e "${GREEN}Cron job added successfully${NC}"

# Create a test script for manual execution
echo -e "${YELLOW}Creating test script...${NC}"
cat > "$SCRIPT_DIR/test_epss_sync.sh" << 'EOF'
#!/bin/bash
# Test script for EPSS sync service

echo "Testing EPSS sync service..."
echo "Logs will be written to /var/www/html/logs/epss_sync.log"
echo "Starting sync..."

/usr/bin/python3 /var/www/html/services/epss_sync_service.py

echo "EPSS sync test completed. Check the log file for details."
EOF

chmod +x "$SCRIPT_DIR/test_epss_sync.sh"

# Create a status check script
echo -e "${YELLOW}Creating status check script...${NC}"
cat > "$SCRIPT_DIR/check_epss_status.sh" << 'EOF'
#!/bin/bash
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
EOF

chmod +x "$SCRIPT_DIR/check_epss_status.sh"

# Set proper ownership
echo -e "${YELLOW}Setting file ownership...${NC}"
chown -R "$CRON_USER:$CRON_USER" "$SCRIPT_DIR"
chown -R "$CRON_USER:$CRON_USER" "$LOG_DIR"

# Create a systemd service file (optional, for better process management)
echo -e "${YELLOW}Creating systemd service file...${NC}"
cat > "/etc/systemd/system/dave-epss-sync.service" << EOF
[Unit]
Description= EPSS Sync Service
After=network.target

[Service]
Type=oneshot
User=$CRON_USER
Group=$CRON_USER
WorkingDirectory=$SCRIPT_DIR
ExecStart=$PYTHON_PATH $SCRIPT_DIR/epss_sync_service.py
StandardOutput=append:$LOG_DIR/epss_sync.log
StandardError=append:$LOG_DIR/epss_sync.log

[Install]
WantedBy=multi-user.target
EOF

# Create a systemd timer for the service
cat > "/etc/systemd/system/dave-epss-sync.timer" << EOF
[Unit]
Description=Run  EPSS Sync daily
Requires=dave-epss-sync.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Reload systemd and enable the timer
systemctl daemon-reload
systemctl enable dave-epss-sync.timer

echo -e "${GREEN}Systemd timer created and enabled${NC}"

# Display setup summary
echo -e "${GREEN}====================================================================================${NC}"
echo -e "${GREEN}EPSS Sync Service Setup Complete${NC}"
echo -e "${GREEN}====================================================================================${NC}"
echo
echo -e "${BLUE}Setup Summary:${NC}"
echo -e "  • Log directory: $LOG_DIR"
echo -e "  • Service script: $SCRIPT_DIR/epss_sync_service.py"
echo -e "  • Cron job: Daily at 2:00 AM"
echo -e "  • Systemd timer: Enabled"
echo -e "  • Test script: $SCRIPT_DIR/test_epss_sync.sh"
echo -e "  • Status script: $SCRIPT_DIR/check_epss_status.sh"
echo
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Run the database migration: 012_add_epss_integration.sql"
echo -e "  2. Test the sync manually: $SCRIPT_DIR/test_epss_sync.sh"
echo -e "  3. Check status: $SCRIPT_DIR/check_epss_status.sh"
echo -e "  4. Monitor logs: tail -f $LOG_DIR/epss_sync.log"
echo
echo -e "${GREEN}Setup completed successfully!${NC}"
