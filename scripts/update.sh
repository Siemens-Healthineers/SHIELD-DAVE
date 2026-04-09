#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */
#  Update Script
# Automated system updates and maintenance

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_ROOT="/var/www/html"
BACKUP_DIR="/var/backups/dave"
LOG_FILE="$APP_ROOT/logs/update.log"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$LOG_FILE"
}

# Create backup before update
create_backup() {
    log "Creating backup before update..."
    
    if [ -f "$APP_ROOT/scripts/backup.sh" ]; then
        bash "$APP_ROOT/scripts/backup.sh" --type full
        info "Backup created successfully"
    else
        warning "Backup script not found, skipping backup"
    fi
}

# Update system packages
update_system() {
    log "Updating system packages..."
    
    sudo apt update -y
    sudo apt upgrade -y
    
    # Clean up
    sudo apt autoremove -y
    sudo apt autoclean
    
    info "System packages updated"
}

# Update application code
update_application() {
    log "Updating application code..."
    
    # Stop services
    sudo systemctl stop dave-scheduler
    sudo systemctl stop apache2
    
    # Create backup of current application
    local app_backup="$BACKUP_DIR/app_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    tar -czf "$app_backup" -C "$APP_ROOT" . 2>/dev/null || true
    
    # Update application files (if using git)
    if [ -d "$APP_ROOT/.git" ]; then
        cd "$APP_ROOT"
        git pull origin main
    else
        warning "Git repository not found, manual update required"
    fi
    
    # Set proper permissions
    sudo chown -R www-data:www-data "$APP_ROOT"
    sudo chmod -R 755 "$APP_ROOT"
    sudo chmod 600 "$APP_ROOT/config"/*.php 2>/dev/null || true
    
    info "Application code updated"
}

# Update Python dependencies
update_python_deps() {
    log "Updating Python dependencies..."
    
    cd "$APP_ROOT"
    source venv/bin/activate
    
    # Update pip
    pip install --upgrade pip
    
    # Update requirements
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt --upgrade
    fi
    
    info "Python dependencies updated"
}

# Update database schema
update_database() {
    log "Updating database schema..."
    
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
    
    # Use the migration script to apply migrations in correct order
    if [ -f "$APP_ROOT/scripts/apply-migrations.sh" ]; then
        bash "$APP_ROOT/scripts/apply-migrations.sh" $DB_HOST $DB_USER $DB_NAME $DB_PASSWORD
        info "Database schema updated using migration script"
    elif [ -d "$APP_ROOT/database/migrations" ]; then
        # Fallback: apply migrations in numerical order
        for migration in $(ls -1 "$APP_ROOT/database/migrations"/*.sql | sort -V); do
            if [ -f "$migration" ]; then
                log "Applying migration: $(basename "$migration")"
                PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f "$migration" || warning "Migration $(basename "$migration") completed with warnings"
            fi
        done
        info "Database schema updated"
    else
        warning "No database migrations found"
    fi
}

# Update configuration
update_config() {
    log "Updating configuration..."
    
    # Backup current configuration
    local config_backup="$BACKUP_DIR/config_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    tar -czf "$config_backup" -C "$APP_ROOT/config" . 2>/dev/null || true
    
    # Update configuration files if needed
    if [ -f "$APP_ROOT/config/config.example.php" ]; then
        if [ ! -f "$APP_ROOT/config/config.php" ]; then
            cp "$APP_ROOT/config/config.example.php" "$APP_ROOT/config/config.php"
            warning "Configuration file created from example. Please review and update settings."
        fi
    fi
    
    if [ -f "$APP_ROOT/config/database.example.php" ]; then
        if [ ! -f "$APP_ROOT/config/database.php" ]; then
            cp "$APP_ROOT/config/database.example.php" "$APP_ROOT/config/database.php"
            warning "Database configuration file created from example. Please review and update settings."
        fi
    fi
    
    info "Configuration updated"
}

# Restart services
restart_services() {
    log "Restarting services..."
    
    # Start Apache
    sudo systemctl start apache2
    sudo systemctl enable apache2
    
    # Start background service
    sudo systemctl start dave-scheduler
    sudo systemctl enable dave-scheduler
    
    # Wait for services to start
    sleep 5
    
    # Check service status
    if sudo systemctl is-active --quiet apache2; then
        info "Apache: ✅ Running"
    else
        error "Apache: ❌ Failed to start"
    fi
    
    if sudo systemctl is-active --quiet dave-scheduler; then
        info "Background Service: ✅ Running"
    else
        warning "Background Service: ⚠️ Failed to start"
    fi
}

# Verify system health
verify_system() {
    log "Verifying system health..."
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

    # Check database connection
    if PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1;" > /dev/null 2>&1; then
        info "Database Connection: ✅ Working"
    else
        error "Database Connection: ❌ Failed"
    fi
    
    # Check web server
    if curl -s -o /dev/null -w "%{http_code}" http://localhost/test.php | grep -q "200"; then
        info "Web Server: ✅ Working"
    else
        warning "Web Server: ⚠️ May have issues"
    fi
    
    # Check disk space
    local disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$disk_usage" -lt 90 ]; then
        info "Disk Space: ✅ OK ($disk_usage% used)"
    else
        warning "Disk Space: ⚠️ High usage ($disk_usage% used)"
    fi
    
    # Check memory usage
    local memory_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    if [ "$memory_usage" -lt 90 ]; then
        info "Memory Usage: ✅ OK ($memory_usage% used)"
    else
        warning "Memory Usage: ⚠️ High usage ($memory_usage% used)"
    fi
}

# Clean up old files
cleanup() {
    log "Cleaning up old files..."
    
    # Clean up old logs
    find "$APP_ROOT/logs" -name "*.log" -mtime +30 -delete 2>/dev/null || true
    
    # Clean up old backups
    find "$BACKUP_DIR" -name "dave_*" -mtime +30 -delete 2>/dev/null || true
    
    # Clean up temporary files
    find "$APP_ROOT/temp" -type f -mtime +7 -delete 2>/dev/null || true
    
    # Clean up cache
    find "$APP_ROOT/cache" -type f -mtime +1 -delete 2>/dev/null || true
    
    info "Cleanup completed"
}

# Main update function
main() {
    log "Starting  update process..."
    
    # Parse command line arguments
    UPDATE_TYPE="full"
    SKIP_BACKUP=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)
                UPDATE_TYPE="$2"
                shift 2
                ;;
            --skip-backup)
                SKIP_BACKUP=true
                shift
                ;;
            --system-only)
                UPDATE_TYPE="system"
                shift
                ;;
            --app-only)
                UPDATE_TYPE="app"
                shift
                ;;
            --deps-only)
                UPDATE_TYPE="deps"
                shift
                ;;
            --db-only)
                UPDATE_TYPE="db"
                shift
                ;;
            --config-only)
                UPDATE_TYPE="config"
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --type TYPE          Update type (full, system, app, deps, db, config)"
                echo "  --skip-backup        Skip backup creation"
                echo "  --system-only        Update system packages only"
                echo "  --app-only           Update application code only"
                echo "  --deps-only          Update dependencies only"
                echo "  --db-only           Update database schema only"
                echo "  --config-only        Update configuration only"
                echo "  --help               Show this help message"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
    
    # Create backup if not skipped
    if [ "$SKIP_BACKUP" = false ]; then
        create_backup
    fi
    
    # Perform update based on type
    case $UPDATE_TYPE in
        "system")
            update_system
            ;;
        "app")
            update_application
            restart_services
            ;;
        "deps")
            update_python_deps
            ;;
        "db")
            update_database
            ;;
        "config")
            update_config
            ;;
        "full")
            update_system
            update_application
            update_python_deps
            update_database
            update_config
            restart_services
            ;;
        *)
            error "Invalid update type: $UPDATE_TYPE"
            ;;
    esac
    
    # Verify system health
    verify_system
    
    # Clean up
    cleanup
    
    log "🎉 Update completed successfully!"
    info "Update type: $UPDATE_TYPE"
    info "Log file: $LOG_FILE"
}

# Run main function
main "$@"
