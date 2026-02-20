#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */
#  Cron Setup Script
# Automated setup of scheduled tasks and maintenance

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_ROOT="/var/www/html"
CRON_USER="www-data"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Create cron jobs
setup_cron_jobs() {
    log "Setting up cron jobs..."
    
    # Check if .env file exists
    if [ ! -f "$APP_ROOT/.env" ]; then
        error ".env file not found!"
        error "Please copy docs/env.example to .env and configure the following required settings:"
        error "  - DB_HOST (database host)"
        error "  - DB_PORT (database port)"
        error "  - DB_NAME (database name)"
        error "  - DB_USER (database user)"
        error "  - DB_PASSWORD (database password)"
        error ""
        error "Example: cp docs/env.example .env"
        exit 1
    fi

    # Source .env file
    log "Loading database configuration from .env..."
    source "$APP_ROOT/.env"

    # Validate required environment variables
    MISSING_VARS=()
    [ -z "$DB_HOST" ] && MISSING_VARS+=("DB_HOST")
    [ -z "$DB_PORT" ] && MISSING_VARS+=("DB_PORT")
    [ -z "$DB_NAME" ] && MISSING_VARS+=("DB_NAME")
    [ -z "$DB_USER" ] && MISSING_VARS+=("DB_USER")
    [ -z "$DB_PASSWORD" ] && MISSING_VARS+=("DB_PASSWORD")

    if [ ${#MISSING_VARS[@]} -gt 0 ]; then
        error "The following required environment variables are not set in .env:"
        for var in "${MISSING_VARS[@]}"; do
            error "  - $var"
        done
        error ""
        error "Please edit .env and set all required database configuration values."
        exit 1
    fi

    # Create cron directory for www-data user
    sudo mkdir -p /var/spool/cron/crontabs
    
    # Create cron jobs file
    local cron_file="/tmp/dave_cron"
    
    cat > "$cron_file" << EOF
#  Scheduled Tasks
# Generated on $(date)

# Note: Backup operations are manual only - use Admin → Manual Tasks

# Daily system monitoring at 6:00 AM
0 6 * * * $APP_ROOT/scripts/monitor.sh --type full >> /var/www/html/logs/monitor.log 2>&1

# Hourly system monitoring
0 * * * * $APP_ROOT/scripts/monitor.sh --type resources >> /var/www/html/logs/monitor.log 2>&1

# Daily log rotation and cleanup
0 3 * * * find $APP_ROOT/logs -name "*.log" -mtime +30 -delete >> /var/www/html/logs/cleanup.log 2>&1

# Note: Update operations are manual only - use Admin → Manual Tasks

# Database maintenance (vacuum and analyze) - daily at 1:00 AM
0 1 * * * PGPASSWORD=$DB_PASSWORD psql -h localhost -U $DB_USER -d $DB_NAME -c "VACUUM ANALYZE;" >> /var/www/html/logs/db_maintenance.log 2>&1

# Check for failed services every 15 minutes
*/15 * * * * $APP_ROOT/scripts/monitor.sh --type services >> /var/www/html/logs/monitor.log 2>&1

# Note: Backup cleanup is handled by backup scripts when run manually
EOF
    
    # Install cron jobs for www-data user
    sudo cp "$cron_file" "/var/spool/cron/crontabs/$CRON_USER"
    sudo chown "$CRON_USER:$CRON_USER" "/var/spool/cron/crontabs/$CRON_USER"
    sudo chmod 600 "/var/spool/cron/crontabs/$CRON_USER"
    
    # Install cron jobs for root user (system-level tasks)
    sudo tee -a /var/spool/cron/crontabs/root > /dev/null << EOF

#  System-level Tasks
# Generated on $(date)

# Restart services if they fail (every 5 minutes)
*/5 * * * * systemctl is-active --quiet apache2 || systemctl restart apache2
*/5 * * * * systemctl is-active --quiet postgresql || systemctl restart postgresql
*/5 * * * * systemctl is-active --quiet dave-scheduler || systemctl restart dave-scheduler

# Note: System updates are manual only - use Admin → Manual Tasks
EOF
    
    # Set proper permissions for root cron
    sudo chown root:root /var/spool/cron/crontabs/root
    sudo chmod 600 /var/spool/cron/crontabs/root
    
    # Start cron service
    sudo systemctl start cron
    sudo systemctl enable cron
    
    info "Cron jobs installed successfully"
}

# Create log rotation configuration
setup_log_rotation() {
    log "Setting up log rotation..."
    
    sudo tee /etc/logrotate.d/dave > /dev/null << EOF
#  Log Rotation Configuration

$APP_ROOT/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
    postrotate
        systemctl reload dave-scheduler > /dev/null 2>&1 || true
    endscript
}

/var/www/html/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF
    
    info "Log rotation configured"
}

# Create systemd timers (alternative to cron)
setup_systemd_timers() {
    log "Setting up systemd timers..."
    
    # Create timer for daily backup
    sudo tee /etc/systemd/system/dave-backup.timer > /dev/null << EOF
[Unit]
Description= Daily Backup Timer
Requires=dave-backup.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    # Create service for daily backup
    sudo tee /etc/systemd/system/dave-backup.service > /dev/null << EOF
[Unit]
Description= Daily Backup
After=network.target

[Service]
Type=oneshot
User=www-data
Group=www-data
WorkingDirectory=$APP_ROOT
ExecStart=$APP_ROOT/scripts/backup.sh --type full
StandardOutput=journal
StandardError=journal
EOF
    
    # Create timer for monitoring
    sudo tee /etc/systemd/system/dave-monitor.timer > /dev/null << EOF
[Unit]
Description= Monitoring Timer
Requires=dave-monitor.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    # Create service for monitoring
    sudo tee /etc/systemd/system/dave-monitor.service > /dev/null << EOF
[Unit]
Description= System Monitoring
After=network.target

[Service]
Type=oneshot
User=www-data
Group=www-data
WorkingDirectory=$APP_ROOT
ExecStart=$APP_ROOT/scripts/monitor.sh --type full
StandardOutput=journal
StandardError=journal
EOF
    
    # Enable and start timers
    sudo systemctl daemon-reload
    sudo systemctl enable dave-backup.timer
    sudo systemctl enable dave-monitor.timer
    sudo systemctl start dave-backup.timer
    sudo systemctl start dave-monitor.timer
    
    info "Systemd timers configured"
}

# Create maintenance scripts
create_maintenance_scripts() {
    log "Creating maintenance scripts..."
    
    # Create daily maintenance script
    sudo tee "$APP_ROOT/scripts/daily-maintenance.sh" > /dev/null << 'EOF'
#!/bin/bash
#  Daily Maintenance Script

set -e

APP_ROOT="/var/www/html"
LOG_FILE="/var/www/html/logs/maintenance.log"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting daily maintenance..."

# Clean up old log files
find "$APP_ROOT/logs" -name "*.log" -mtime +30 -delete 2>/dev/null || true

# Clean up temporary files
find "$APP_ROOT/temp" -type f -mtime +7 -delete 2>/dev/null || true

# Clean up cache files
find "$APP_ROOT/cache" -type f -mtime +1 -delete 2>/dev/null || true

# Database maintenance
PGPASSWORD=$DB_PASSWORD psql -h localhost -U $DB_USER -d $DB_NAME -c "VACUUM ANALYZE;" 2>/dev/null || true

# Check disk space
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 85 ]; then
    log "WARNING: Disk usage is at $DISK_USAGE%"
fi

log "Daily maintenance completed"
EOF
    
    sudo chmod +x "$APP_ROOT/scripts/daily-maintenance.sh"
    
    # Create weekly maintenance script
    sudo tee "$APP_ROOT/scripts/weekly-maintenance.sh" > /dev/null << 'EOF'
#!/bin/bash
#  Weekly Maintenance Script

set -e

APP_ROOT="/var/www/html"
LOG_FILE="/var/www/html/logs/maintenance.log"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting weekly maintenance..."

# Full database maintenance
PGPASSWORD=$DB_PASSWORD psql -h localhost -U $DB_USER -d $DB_NAME -c "VACUUM FULL ANALYZE;" 2>/dev/null || true

# Clean up old backups
find /var/backups/dave -name "dave_*" -mtime +30 -delete 2>/dev/null || true

# Update system packages
apt update && apt upgrade -y 2>/dev/null || true

# Restart services
systemctl restart apache2
systemctl restart dave-scheduler

log "Weekly maintenance completed"
EOF
    
    sudo chmod +x "$APP_ROOT/scripts/weekly-maintenance.sh"
    
    info "Maintenance scripts created"
}

# Setup email notifications
setup_email_notifications() {
    log "Setting up email notifications..."
    
    # Install mailutils if not present
    if ! command -v mail &> /dev/null; then
        sudo apt install -y mailutils
    fi
    
    # Configure postfix for local mail
    sudo debconf-set-selections <<< "postfix postfix/mailname string dave.local"
    sudo debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Local only'"
    
    # Install postfix
    sudo apt install -y postfix
    
    # Configure postfix
    sudo tee -a /etc/postfix/main.cf > /dev/null << EOF

#  Email Configuration
myhostname = dave.local
mydomain = dave.local
myorigin = \$mydomain
mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = loopback-only
EOF
    
    # Restart postfix
    sudo systemctl restart postfix
    sudo systemctl enable postfix
    
    info "Email notifications configured"
}

# Main setup function
main() {
    log "Starting  cron setup..."
    
    # Parse command line arguments
    SETUP_TYPE="full"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)
                SETUP_TYPE="$2"
                shift 2
                ;;
            --cron-only)
                SETUP_TYPE="cron"
                shift
                ;;
            --timers-only)
                SETUP_TYPE="timers"
                shift
                ;;
            --email-only)
                SETUP_TYPE="email"
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --type TYPE          Setup type (full, cron, timers, email)"
                echo "  --cron-only          Setup cron jobs only"
                echo "  --timers-only        Setup systemd timers only"
                echo "  --email-only         Setup email notifications only"
                echo "  --help               Show this help message"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
    
    # Perform setup based on type
    case $SETUP_TYPE in
        "cron")
            setup_cron_jobs
            setup_log_rotation
            create_maintenance_scripts
            ;;
        "timers")
            setup_systemd_timers
            ;;
        "email")
            setup_email_notifications
            ;;
        "full")
            setup_cron_jobs
            setup_log_rotation
            setup_systemd_timers
            create_maintenance_scripts
            setup_email_notifications
            ;;
        *)
            error "Invalid setup type: $SETUP_TYPE"
            ;;
    esac
    
    log "🎉 Cron setup completed successfully!"
    info "Setup type: $SETUP_TYPE"
    info "Cron jobs are now scheduled for automated maintenance"
}

# Run main function
main "$@"
