#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */
#
# This script provides comprehensive restore functionality for  including:
# - Database restoration from SQL dumps
# - Configuration file restoration
# - Upload directory restoration
# - Full system restoration
# - Backup verification before restore
# - Pre-restore safety checks
#

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
readonly BACKUP_DIR="/var/backups/dave"
readonly APP_ROOT="/var/www/html"

# Database configuration - Use main application user


# Database configuration - Use main application user with proper permissions
source "$APP_ROOT/.env"

readonly DB_HOST="${DB_HOST:-$DB_HOST}"
readonly DB_PORT="${DB_PORT:-$DB_PORT}"
readonly DB_NAME="${DB_NAME:-$DB_NAME}"
readonly DB_USER="${DB_USER:-$DB_USER}"
readonly DB_PASS="${DB_PASSWORD:-$DB_PASSWORD}"

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" >&2
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}" >&2
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}" >&2
}

# Verify backup file exists and is valid
verify_backup() {
    local backup_file="$1"
    
    if [ -z "$backup_file" ]; then
        error "Backup file not specified"
    fi
    
    if [ ! -f "$backup_file" ]; then
        error "Backup file not found: $backup_file"
    fi
    
    info "Verifying backup file: $(basename "$backup_file")"
    
    # Check file type and verify integrity
    if [[ "$backup_file" == *.gz ]] && [[ "$backup_file" != *.tar.gz ]]; then
        # Compressed SQL file
        if ! gzip -t "$backup_file" 2>/dev/null; then
            error "Backup file is corrupted (gzip): $backup_file"
        fi
        info "✓ Backup file verified (compressed SQL)"
    elif [[ "$backup_file" == *.tar.gz ]]; then
        # Tar archive
        if ! tar -tzf "$backup_file" >/dev/null 2>&1; then
            error "Backup file is corrupted (tar): $backup_file"
        fi
        info "✓ Backup file verified (tar archive)"
    elif [[ "$backup_file" == *.sql ]]; then
        # Uncompressed SQL file
        if [ ! -s "$backup_file" ]; then
            error "Backup file is empty: $backup_file"
        fi
        info "✓ Backup file verified (SQL dump)"
    else
        warning "Unknown backup file type: $backup_file"
        read -p "Continue anyway? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            exit 1
        fi
    fi
}

# Verify database connection
verify_db_connection() {
    log "Verifying database connection..."
    
    if ! command -v psql >/dev/null 2>&1; then
        error "PostgreSQL client (psql) not found. Please install postgresql-client."
    fi
    
    if ! PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "SELECT 1;" >/dev/null 2>&1; then
        error "Cannot connect to database. Please check database credentials."
    fi
    
    info "Database connection verified"
}

# Create safety backup of current state
create_safety_backup() {
    local backup_type="$1"
    local safety_dir="${BACKUP_DIR}/safety_backup_$(date +%Y%m%d_%H%M%S)"
    
    log "Creating safety backup of current $backup_type..."
    
    if ! mkdir -p "$safety_dir"; then
        warning "Failed to create safety backup directory"
        return
    fi
    
    case "$backup_type" in
        "database")
            if PGPASSWORD="$DB_PASS" pg_dump \
                --host="$DB_HOST" \
                --port="$DB_PORT" \
                --username="$DB_USER" \
                --dbname="$DB_NAME" \
                --no-owner \
                --no-privileges \
                > "${safety_dir}/database.sql" 2>/dev/null; then
                gzip "${safety_dir}/database.sql" 2>/dev/null || true
                info "Safety backup created: ${safety_dir}/database.sql.gz"
            else
                warning "Failed to create database safety backup"
            fi
            ;;
        "config")
            if [ -d "${APP_ROOT}/config" ]; then
                tar -czf "${safety_dir}/config.tar.gz" -C "$APP_ROOT" config 2>/dev/null || true
                info "Safety backup created: ${safety_dir}/config.tar.gz"
            fi
            ;;
        "uploads")
            if [ -d "${APP_ROOT}/uploads" ]; then
                tar -czf "${safety_dir}/uploads.tar.gz" -C "$APP_ROOT" uploads 2>/dev/null || true
                info "Safety backup created: ${safety_dir}/uploads.tar.gz"
            fi
            ;;
    esac
}

# Restore database
restore_database() {
    local backup_file="$1"
    
    log "Restoring database from: $(basename "$backup_file")"
    
    # Verify backup
    verify_backup "$backup_file"
    
    # Create safety backup
    create_safety_backup "database"
    
    # Verify database connection
    verify_db_connection
    
    # Determine if we need to drop/create database
    local needs_recreate=false
    
    # Check if database exists
    if ! PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" >/dev/null 2>&1; then
        needs_recreate=true
        log "Database does not exist, will create it"
    fi
    
    # Extract database name from backup if it's a full dump
    log "Preparing database for restore..."
    
    if [ "$needs_recreate" = true ]; then
        # Create database
        log "Creating database..."
        if ! PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
            -c "CREATE DATABASE ${DB_NAME};" 2>/dev/null; then
            error "Failed to create database"
        fi
        
        # Grant privileges
        PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
            -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" 2>/dev/null || true
    fi
    
    # Restore database
    log "Restoring database from backup..."
    
    # Note: We don't use ON_ERROR_STOP=1 because extension permission errors
    # (like "must be owner of extension uuid-ossp") would stop the restore,
    # even though they're non-critical. We verify the result afterward.
    
    if [[ "$backup_file" == *.gz ]]; then
        # Compressed backup
        gunzip -c "$backup_file" | PGPASSWORD="$DB_PASS" psql \
            -h "$DB_HOST" \
            -p "$DB_PORT" \
            -U "$DB_USER" \
            -d "$DB_NAME" \
            >/tmp/restore_db_$$.log 2>&1
        restore_exit_code=$?
    else
        # Uncompressed backup
        PGPASSWORD="$DB_PASS" psql \
            -h "$DB_HOST" \
            -p "$DB_PORT" \
            -U "$DB_USER" \
            -d "$DB_NAME" \
            -f "$backup_file" \
            >/tmp/restore_db_$$.log 2>&1
        restore_exit_code=$?
    fi
    
    # Check for critical errors (ignore extension ownership errors)
    if [ $restore_exit_code -ne 0 ]; then
        # Check if errors are only extension-related (non-critical)
        if grep -qi "must be owner of extension" /tmp/restore_db_$$.log; then
            warning "Extension ownership errors encountered (this is normal for non-superuser restores)"
        else
            # There are other errors - show them
            error_msg=$(tail -20 /tmp/restore_db_$$.log 2>/dev/null || echo "Unknown error")
            rm -f /tmp/restore_db_$$.log
            error "Database restore failed with errors: $error_msg"
        fi
    fi
    
    rm -f /tmp/restore_db_$$.log
    
    # Verify restoration
    log "Verifying database restoration..."
    local table_count=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null | tr -d ' ')
    
    if [ -z "$table_count" ] || [ "$table_count" = "0" ]; then
        error "Database restoration verification failed - no tables found"
    fi
    
    info "Database restored successfully ($table_count tables)"
}

# Restore configuration
restore_config() {
    local backup_file="$1"
    
    log "Restoring configuration from: $(basename "$backup_file")"
    
    # Verify backup
    verify_backup "$backup_file"
    
    # Create safety backup
    create_safety_backup "config"
    
    # Create config directory if it doesn't exist
    if [ ! -d "${APP_ROOT}/config" ]; then
        log "Creating configuration directory..."
        mkdir -p "${APP_ROOT}/config"
    fi
    
    # Extract backup
    log "Extracting configuration files..."
    
    # Backup current config first
    local current_config_backup="${BACKUP_DIR}/config_backup_before_restore_$(date +%Y%m%d_%H%M%S).tar.gz"
    if [ -d "${APP_ROOT}/config" ] && [ "$(ls -A ${APP_ROOT}/config 2>/dev/null)" ]; then
        tar -czf "$current_config_backup" -C "$APP_ROOT" config 2>/dev/null || true
        info "Current config backed up to: $(basename "$current_config_backup")"
    fi
    
    # Extract new config
    if ! tar -xzf "$backup_file" -C "$APP_ROOT" 2>/dev/null; then
        error "Failed to extract configuration backup"
    fi
    
    # Set proper permissions
    if command -v chmod >/dev/null 2>&1; then
        chmod -R 755 "${APP_ROOT}/config" 2>/dev/null || true
        chmod 600 "${APP_ROOT}/config"/*.php 2>/dev/null || true
    fi
    
    if command -v chown >/dev/null 2>&1 && [ "$(whoami)" = "root" ] || [ "$(whoami)" = "www-data" ]; then
        chown -R www-data:www-data "${APP_ROOT}/config" 2>/dev/null || true
    fi
    
    info "Configuration restored successfully"
}

# Restore uploads
restore_uploads() {
    local backup_file="$1"
    
    log "Restoring uploads from: $(basename "$backup_file")"
    
    # Verify backup
    verify_backup "$backup_file"
    
    # Create safety backup
    create_safety_backup "uploads"
    
    # Create uploads directory if it doesn't exist
    if [ ! -d "${APP_ROOT}/uploads" ]; then
        log "Creating uploads directory..."
        mkdir -p "${APP_ROOT}/uploads"
    fi
    
    # Backup current uploads
    local current_uploads_backup="${BACKUP_DIR}/uploads_backup_before_restore_$(date +%Y%m%d_%H%M%S).tar.gz"
    if [ -d "${APP_ROOT}/uploads" ] && [ "$(ls -A ${APP_ROOT}/uploads 2>/dev/null)" ]; then
        tar -czf "$current_uploads_backup" -C "$APP_ROOT" uploads 2>/dev/null || true
        info "Current uploads backed up to: $(basename "$current_uploads_backup")"
    fi
    
    # Extract backup
    log "Extracting uploads..."
    if ! tar -xzf "$backup_file" -C "$APP_ROOT" 2>/dev/null; then
        error "Failed to extract uploads backup"
    fi
    
    # Set proper permissions
    if command -v chmod >/dev/null 2>&1; then
        chmod -R 755 "${APP_ROOT}/uploads" 2>/dev/null || true
    fi
    
    if command -v chown >/dev/null 2>&1 && ([ "$(whoami)" = "root" ] || [ "$(whoami)" = "www-data" ]); then
        chown -R www-data:www-data "${APP_ROOT}/uploads" 2>/dev/null || true
    fi
    
    info "Uploads restored successfully"
}

# Restore full system
restore_full() {
    local backup_file="$1"
    
    log "Restoring full system from: $(basename "$backup_file")"
    
    # Verify backup
    verify_backup "$backup_file"
    
    # Create safety backups
    create_safety_backup "database"
    create_safety_backup "config"
    create_safety_backup "uploads"
    
    # Extract to temporary directory first
    local temp_dir="/tmp/dave_restore_$$"
    log "Extracting full backup to temporary location..."
    
    if ! mkdir -p "$temp_dir"; then
        error "Failed to create temporary directory"
    fi
    
    if ! tar -xzf "$backup_file" -C "$temp_dir" 2>/dev/null; then
        rm -rf "$temp_dir"
        error "Failed to extract full backup"
    fi
    
    # Restore components
    if [ -f "${temp_dir}/database.sql" ]; then
        log "Restoring database from full backup..."
        restore_database "${temp_dir}/database.sql"
    fi
    
    if [ -d "${temp_dir}/config" ]; then
        log "Restoring configuration from full backup..."
        if [ -d "${APP_ROOT}/config" ]; then
            rm -rf "${APP_ROOT}/config"
        fi
        cp -r "${temp_dir}/config" "${APP_ROOT}/config"
        chmod -R 755 "${APP_ROOT}/config" 2>/dev/null || true
        chmod 600 "${APP_ROOT}/config"/*.php 2>/dev/null || true
        info "Configuration restored"
    fi
    
    if [ -d "${temp_dir}/uploads" ]; then
        log "Restoring uploads from full backup..."
        if [ -d "${APP_ROOT}/uploads" ]; then
            rm -rf "${APP_ROOT}/uploads"
        fi
        cp -r "${temp_dir}/uploads" "${APP_ROOT}/uploads"
        chmod -R 755 "${APP_ROOT}/uploads" 2>/dev/null || true
        info "Uploads restored"
    fi
    
    # Clean up temp directory
    rm -rf "$temp_dir"
    
    info "Full system restored successfully"
}

# List available backups
list_backups() {
    log "Available backups:"
    echo ""
    
    if [ ! -d "$BACKUP_DIR" ]; then
        error "Backup directory not found: $BACKUP_DIR"
    fi
    
    echo "Database Backups:"
    find "$BACKUP_DIR" -name "dave_db_*.sql.gz" -type f -printf "%T@ %p\n" 2>/dev/null | \
        sort -rn | head -10 | while read timestamp filepath; do
        filename=$(basename "$filepath")
        size=$(stat -f%z "$filepath" 2>/dev/null || stat -c%s "$filepath" 2>/dev/null || echo "0")
        size_mb=$(echo "scale=2; $size / 1024 / 1024" | bc 2>/dev/null || awk "BEGIN {printf \"%.2f\", $size/1024/1024}")
        date_str=$(date -r "$timestamp" 2>/dev/null || date -d "@$timestamp" 2>/dev/null || echo "Unknown")
        echo "  $filename ($size_mb MB) - $date_str"
    done
    
    echo ""
    echo "Full System Backups:"
    find "$BACKUP_DIR" -name "dave_full_*.tar.gz" -type f -printf "%T@ %p\n" 2>/dev/null | \
        sort -rn | head -10 | while read timestamp filepath; do
        filename=$(basename "$filepath")
        size=$(stat -f%z "$filepath" 2>/dev/null || stat -c%s "$filepath" 2>/dev/null || echo "0")
        size_mb=$(echo "scale=2; $size / 1024 / 1024" | bc 2>/dev/null || awk "BEGIN {printf \"%.2f\", $size/1024/1024}")
        date_str=$(date -r "$timestamp" 2>/dev/null || date -d "@$timestamp" 2>/dev/null || echo "Unknown")
        echo "  $filename ($size_mb MB) - $date_str"
    done
}

# Interactive restore
interactive_restore() {
    log "Interactive restore mode"
    echo ""
    
    list_backups
    echo ""
    
    read -p "Enter backup file path: " backup_file
    
    if [ ! -f "$backup_file" ]; then
        error "Backup file not found: $backup_file"
    fi
    
    # Determine restore type based on filename
    local restore_type=""
    if [[ "$backup_file" == *"dave_db_"* ]]; then
        restore_type="database"
    elif [[ "$backup_file" == *"dave_full_"* ]]; then
        restore_type="full"
    elif [[ "$backup_file" == *"dave_config_"* ]]; then
        restore_type="config"
    elif [[ "$backup_file" == *"dave_uploads_"* ]]; then
        restore_type="uploads"
    else
        echo ""
        echo "Could not determine backup type. Please specify:"
        echo "  1) Database"
        echo "  2) Configuration"
        echo "  3) Uploads"
        echo "  4) Full System"
        read -p "Choice [1-4]: " choice
        
        case "$choice" in
            1) restore_type="database" ;;
            2) restore_type="config" ;;
            3) restore_type="uploads" ;;
            4) restore_type="full" ;;
            *) error "Invalid choice" ;;
        esac
    fi
    
    # Confirm restore
    echo ""
    warning "WARNING: This will restore $restore_type from: $(basename "$backup_file")"
    warning "A safety backup will be created before restoration."
    read -p "Are you sure you want to continue? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        log "Restore cancelled"
        exit 0
    fi
    
    # Perform restore
    case "$restore_type" in
        "database")
            restore_database "$backup_file"
            ;;
        "config")
            restore_config "$backup_file"
            ;;
        "uploads")
            restore_uploads "$backup_file"
            ;;
        "full")
            restore_full "$backup_file"
            ;;
    esac
    
    log "🎉 Restore completed successfully!"
}

# Main function
main() {
    log "Starting  restore process..."
    
    # Parse command line arguments
    local BACKUP_FILE=""
    local RESTORE_TYPE=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --file|-f)
                BACKUP_FILE="$2"
                shift 2
                ;;
            --database|--db)
                RESTORE_TYPE="database"
                shift
                ;;
            --config)
                RESTORE_TYPE="config"
                shift
                ;;
            --uploads)
                RESTORE_TYPE="uploads"
                shift
                ;;
            --full)
                RESTORE_TYPE="full"
                shift
                ;;
            --list|-l)
                list_backups
                exit 0
                ;;
            --interactive|-i)
                interactive_restore
                exit 0
                ;;
            --help|-h)
                cat << EOF
 Restore Utility
Usage: $0 [OPTIONS]

Options:
  --file FILE, -f FILE    Backup file to restore
  --database, --db        Restore database only
  --config                Restore configuration only
  --uploads               Restore uploads only
  --full                  Restore full system
  --list, -l              List available backups
  --interactive, -i       Interactive restore mode
  --help, -h              Show this help message

Examples:
  $0 --file /path/to/backup.sql.gz --database
  $0 --interactive
  $0 --list
EOF
                exit 0
                ;;
            *)
                error "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done
    
    # If no arguments, use interactive mode
    if [ -z "$BACKUP_FILE" ] && [ -z "$RESTORE_TYPE" ]; then
        interactive_restore
        exit 0
    fi
    
    # Validate arguments
    if [ -z "$BACKUP_FILE" ]; then
        error "Backup file not specified. Use --file option or --interactive mode."
    fi
    
    if [ -z "$RESTORE_TYPE" ]; then
        error "Restore type not specified. Use --database, --config, --uploads, or --full."
    fi
    
    # Perform restore
    case "$RESTORE_TYPE" in
        "database")
            restore_database "$BACKUP_FILE"
            ;;
        "config")
            restore_config "$BACKUP_FILE"
            ;;
        "uploads")
            restore_uploads "$BACKUP_FILE"
            ;;
        "full")
            restore_full "$BACKUP_FILE"
            ;;
        *)
            error "Invalid restore type: $RESTORE_TYPE"
            ;;
    esac
    
    log "🎉 Restore completed successfully!"
    info "Restored from: $BACKUP_FILE"
    info "Restore type: $RESTORE_TYPE"
}

# Run main function
main "$@"
