#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */
# This script provides comprehensive backup functionality for  including:
# - Full database backups using pg_dump with proper permissions
# - Configuration file backups
# - Upload directory backups
# - Full system backups combining all components
# - Automatic cleanup of old backups
# - Backup verification and reporting
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
readonly DATE=$(date +%Y%m%d_%H%M%S)
readonly RETENTION_DAYS=30

# Application paths
readonly APP_ROOT="/var/www/html"
readonly CONFIG_DIR="${APP_ROOT}/config"
readonly UPLOADS_DIR="${APP_ROOT}/uploads"
readonly LOGS_DIR="${APP_ROOT}/logs"

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

# Create backup directory with proper permissions
create_backup_dir() {
    log "Creating backup directory..."
    
    if ! mkdir -p "$BACKUP_DIR"; then
        error "Failed to create backup directory: $BACKUP_DIR"
    fi
    
    # Set proper permissions
    chmod 755 "$BACKUP_DIR" 2>/dev/null || true
    
    # Try to set group ownership for shared access
    if command -v chgrp >/dev/null 2>&1; then
        chgrp www-data "$BACKUP_DIR" 2>/dev/null || true
    fi
    
    # If running as www-data, ensure ownership
    if [ "$(whoami)" = "www-data" ]; then
        chown www-data:www-data "$BACKUP_DIR" 2>/dev/null || true
    fi
    
    info "Backup directory ready: $BACKUP_DIR"
}

# Verify database connection
verify_db_connection() {
    log "Verifying database connection..."
    
    if ! command -v psql >/dev/null 2>&1; then
        error "PostgreSQL client (psql) not found. Please install postgresql-client."
    fi
    
    if ! PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" >/dev/null 2>&1; then
        error "Cannot connect to database. Please check database credentials."
    fi
    
    info "Database connection verified"
}

# Get list of all tables in the database
get_all_tables() {
    PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;" \
        2>/dev/null | tr -d ' ' | grep -v '^$'
}

# Backup database with comprehensive options
backup_database() {
    log "Starting database backup..."
    
    local db_backup_file="${BACKUP_DIR}/dave_db_${DATE}.sql"
    local db_backup_compressed="${db_backup_file}.gz"
    
    # Get table count for verification
    local table_count=$(get_all_tables | wc -l)
    info "Found ${table_count} tables to backup"
    
    # Create database backup using pg_dump
    # Options:
    #   --verbose: Show progress
    #   --no-owner: Don't output commands to set ownership
    #   --no-privileges: Don't output commands to set privileges
    #   --clean: Include DROP statements before CREATE
    #   --if-exists: Use IF EXISTS for DROP statements
    #   --lock-wait-timeout: Wait up to 60 seconds for locks
    log "Executing pg_dump..."
    
    if ! PGPASSWORD="$DB_PASS" pg_dump \
        --host="$DB_HOST" \
        --port="$DB_PORT" \
        --username="$DB_USER" \
        --dbname="$DB_NAME" \
        --no-owner \
        --no-privileges \
        --clean \
        --if-exists \
        --lock-wait-timeout=60000 \
        --verbose \
        > "$db_backup_file" 2>/tmp/pg_dump_${DATE}.log; then
        
        local error_msg=$(cat /tmp/pg_dump_${DATE}.log 2>/dev/null || echo "Unknown error")
        rm -f /tmp/pg_dump_${DATE}.log
        error "Database backup failed: $error_msg"
    fi
    
    # Clean up log file
    rm -f /tmp/pg_dump_${DATE}.log
    
    # Verify backup file exists and has content
    if [ ! -f "$db_backup_file" ] || [ ! -s "$db_backup_file" ]; then
        error "Database backup file is empty or missing"
    fi
    
    local backup_size=$(stat -f%z "$db_backup_file" 2>/dev/null || stat -c%s "$db_backup_file" 2>/dev/null || echo "0")
    info "Database backup created: ${backup_size} bytes"
    
    # Compress backup
    log "Compressing database backup..."
    if ! gzip "$db_backup_file"; then
        error "Failed to compress database backup"
    fi
    
    # Verify compressed backup
    if [ ! -f "$db_backup_compressed" ]; then
        error "Compressed backup file not found"
    fi
    
    # Set permissions
    chmod 644 "$db_backup_compressed" 2>/dev/null || true
    chgrp www-data "$db_backup_compressed" 2>/dev/null || true
    
    local compressed_size=$(stat -f%z "$db_backup_compressed" 2>/dev/null || stat -c%s "$db_backup_compressed" 2>/dev/null || echo "0")
    local size_mb=$(echo "scale=2; $compressed_size / 1024 / 1024" | bc 2>/dev/null || awk "BEGIN {printf \"%.2f\", $compressed_size/1024/1024}")
    
    info "Database backup completed: ${db_backup_compressed} (${size_mb} MB)"
}

# Backup configuration files
backup_config() {
    log "Backing up configuration files..."
    
    if [ ! -d "$CONFIG_DIR" ]; then
        warning "Configuration directory not found: $CONFIG_DIR"
        return
    fi
    
    local config_backup="${BACKUP_DIR}/dave_config_${DATE}.tar.gz"
    
    if ! tar -czf "$config_backup" -C "$APP_ROOT" config 2>/dev/null; then
        error "Failed to create configuration backup"
    fi
    
    # Set permissions
    chmod 644 "$config_backup" 2>/dev/null || true
    chgrp www-data "$config_backup" 2>/dev/null || true
    
    local size=$(stat -f%z "$config_backup" 2>/dev/null || stat -c%s "$config_backup" 2>/dev/null || echo "0")
    local size_mb=$(echo "scale=2; $size / 1024 / 1024" | bc 2>/dev/null || awk "BEGIN {printf \"%.2f\", $size/1024/1024}")
    
    info "Configuration backup completed: ${config_backup} (${size_mb} MB)"
}

# Backup uploads directory
backup_uploads() {
    log "Backing up uploads directory..."
    
    if [ ! -d "$UPLOADS_DIR" ]; then
        warning "Uploads directory not found: $UPLOADS_DIR (creating empty directory)"
        mkdir -p "$UPLOADS_DIR"
    fi
    
    local uploads_backup="${BACKUP_DIR}/dave_uploads_${DATE}.tar.gz"
    
    if ! tar -czf "$uploads_backup" -C "$APP_ROOT" uploads 2>/dev/null; then
        error "Failed to create uploads backup"
    fi
    
    # Set permissions
    chmod 644 "$uploads_backup" 2>/dev/null || true
    chgrp www-data "$uploads_backup" 2>/dev/null || true
    
    local size=$(stat -f%z "$uploads_backup" 2>/dev/null || stat -c%s "$uploads_backup" 2>/dev/null || echo "0")
    local size_mb=$(echo "scale=2; $size / 1024 / 1024" | bc 2>/dev/null || awk "BEGIN {printf \"%.2f\", $size/1024/1024}")
    
    info "Uploads backup completed: ${uploads_backup} (${size_mb} MB)"
}

# Create full system backup
backup_full() {
    log "Creating comprehensive full system backup..."
    
    local temp_dir="/tmp/dave_full_backup_${DATE}"
    local full_backup="${BACKUP_DIR}/dave_full_${DATE}.tar.gz"
    
    # Create temporary directory
    if ! mkdir -p "$temp_dir"; then
        error "Failed to create temporary directory: $temp_dir"
    fi
    
    # Backup database to temp directory
    log "Including database backup..."
    local db_backup_file="${temp_dir}/database.sql"
    
    if ! PGPASSWORD="$DB_PASS" pg_dump \
        --host="$DB_HOST" \
        --port="$DB_PORT" \
        --username="$DB_USER" \
        --dbname="$DB_NAME" \
        --no-owner \
        --no-privileges \
        --clean \
        --if-exists \
        --lock-wait-timeout=60000 \
        > "$db_backup_file" 2>/tmp/pg_dump_full_${DATE}.log; then
        
        local error_msg=$(cat /tmp/pg_dump_full_${DATE}.log 2>/dev/null || echo "Unknown error")
        rm -f /tmp/pg_dump_full_${DATE}.log
        rm -rf "$temp_dir"
        error "Database backup failed in full backup: $error_msg"
    fi
    
    rm -f /tmp/pg_dump_full_${DATE}.log
    
    # Copy configuration
    if [ -d "$CONFIG_DIR" ]; then
        log "Including configuration files..."
        cp -r "$CONFIG_DIR" "$temp_dir/config"
    fi
    
    # Copy uploads
    if [ -d "$UPLOADS_DIR" ]; then
        log "Including uploads..."
        cp -r "$UPLOADS_DIR" "$temp_dir/uploads"
    fi
    
    # Create archive
    log "Creating backup archive..."
    if ! tar -czf "$full_backup" -C "$temp_dir" .; then
        rm -rf "$temp_dir"
        error "Failed to create full backup archive"
    fi
    
    # Clean up temp directory
    rm -rf "$temp_dir"
    
    # Set permissions
    chmod 644 "$full_backup" 2>/dev/null || true
    chgrp www-data "$full_backup" 2>/dev/null || true
    
    local size=$(stat -f%z "$full_backup" 2>/dev/null || stat -c%s "$full_backup" 2>/dev/null || echo "0")
    local size_mb=$(echo "scale=2; $size / 1024 / 1024" | bc 2>/dev/null || awk "BEGIN {printf \"%.2f\", $size/1024/1024}")
    
    info "Full system backup completed: ${full_backup} (${size_mb} MB)"
    info "Includes: Database, Configuration, and Uploads"
}

# Clean up old backups
cleanup_old_backups() {
    log "Cleaning up old backups (older than ${RETENTION_DAYS} days)..."
    
    local removed_count=0
    local freed_space=0
    
    while IFS= read -r backup_file; do
        if [ -f "$backup_file" ]; then
            local file_size=$(stat -f%z "$backup_file" 2>/dev/null || stat -c%s "$backup_file" 2>/dev/null || echo "0")
            freed_space=$((freed_space + file_size))
            
            if rm "$backup_file" 2>/dev/null; then
                removed_count=$((removed_count + 1))
            fi
        fi
    done < <(find "$BACKUP_DIR" -name "dave_*" -type f -mtime +${RETENTION_DAYS} 2>/dev/null)
    
    if [ $removed_count -gt 0 ]; then
        local freed_mb=$(echo "scale=2; $freed_space / 1024 / 1024" | bc 2>/dev/null || awk "BEGIN {printf \"%.2f\", $freed_space/1024/1024}")
        info "Removed ${removed_count} old backup(s), freed ${freed_mb} MB"
    else
        info "No old backups to clean up"
    fi
}

# Verify backup integrity
verify_backups() {
    log "Verifying backup integrity..."
    
    local backup_files=($(find "$BACKUP_DIR" -name "dave_*_${DATE}.*" -type f 2>/dev/null))
    local valid_count=0
    local invalid_count=0
    
    for backup in "${backup_files[@]}"; do
        if [[ "$backup" == *.gz ]] && [[ "$backup" != *.tar.gz ]]; then
            # Compressed SQL file
            if gzip -t "$backup" 2>/dev/null; then
                valid_count=$((valid_count + 1))
                info "✓ Valid: $(basename "$backup")"
            else
                invalid_count=$((invalid_count + 1))
                error "✗ Invalid: $(basename "$backup")"
            fi
        elif [[ "$backup" == *.tar.gz ]]; then
            # Tar archive
            if tar -tzf "$backup" >/dev/null 2>&1; then
                valid_count=$((valid_count + 1))
                info "✓ Valid: $(basename "$backup")"
            else
                invalid_count=$((invalid_count + 1))
                error "✗ Invalid: $(basename "$backup")"
            fi
        fi
    done
    
    if [ ${#backup_files[@]} -eq 0 ]; then
        warning "No backup files found for verification"
    elif [ $invalid_count -eq 0 ]; then
        info "All backups verified successfully (${valid_count} files)"
    fi
}

# Generate backup report
generate_report() {
    log "Generating backup report..."
    
    local report_file="${BACKUP_DIR}/backup_report_${DATE}.txt"
    
    {
        echo "==================================================================="
        echo " Backup Report"
        echo "==================================================================="
        echo "Date: $(date)"
        echo "Hostname: $(hostname)"
        echo "User: $(whoami)"
        echo "Database: ${DB_NAME}@${DB_HOST}:${DB_PORT}"
        echo ""
        echo "Backup Summary:"
        echo "-------------------------------------------------------------------"
        
        # List all backups created
        find "$BACKUP_DIR" -name "dave_*_${DATE}.*" -type f -exec ls -lh {} \; 2>/dev/null | \
            awk '{printf "%-50s %10s %s %s %s\n", $9, $5, $6, $7, $8}'
        
        echo ""
        echo "Backup Directory Usage:"
        echo "-------------------------------------------------------------------"
        du -sh "$BACKUP_DIR" 2>/dev/null || echo "Unable to determine size"
        
        echo ""
        echo "Total Backups:"
        echo "-------------------------------------------------------------------"
        echo "Database: $(find "$BACKUP_DIR" -name "dave_db_*.sql.gz" -type f | wc -l | tr -d ' ')"
        echo "Full: $(find "$BACKUP_DIR" -name "dave_full_*.tar.gz" -type f | wc -l | tr -d ' ')"
        echo "Config: $(find "$BACKUP_DIR" -name "dave_config_*.tar.gz" -type f | wc -l | tr -d ' ')"
        echo "Uploads: $(find "$BACKUP_DIR" -name "dave_uploads_*.tar.gz" -type f | wc -l | tr -d ' ')"
        
    } > "$report_file"
    
    # Set permissions
    chmod 644 "$report_file" 2>/dev/null || true
    chgrp www-data "$report_file" 2>/dev/null || true
    
    info "Backup report created: ${report_file}"
}

# Main function
main() {
    log "Starting  backup process..."
    
    # Parse command line arguments
    local BACKUP_TYPE="full"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)
                BACKUP_TYPE="$2"
                shift 2
                ;;
            --database-only|--db)
                BACKUP_TYPE="database"
                shift
                ;;
            --config-only)
                BACKUP_TYPE="config"
                shift
                ;;
            --uploads-only)
                BACKUP_TYPE="uploads"
                shift
                ;;
            --help|-h)
                cat << EOF
 Backup Utility
Usage: $0 [OPTIONS]

Options:
  --type TYPE          Backup type (full, database, config, uploads)
  --database-only       Backup database only
  --config-only         Backup configuration only
  --uploads-only        Backup uploads only
  --help                Show this help message

Backup Types:
  full       - Complete system backup (database + config + uploads)
  database   - Database backup only
  config     - Configuration files only
  uploads    - Uploads directory only

Examples:
  $0                          # Full backup
  $0 --database-only          # Database only
  $0 --type config            # Configuration only
EOF
                exit 0
                ;;
            *)
                error "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done
    
    # Create backup directory
    create_backup_dir
    
    # Verify database connection (for database/full backups)
    if [[ "$BACKUP_TYPE" == "database" ]] || [[ "$BACKUP_TYPE" == "full" ]]; then
        verify_db_connection
    fi
    
    # Perform backup based on type
    case "$BACKUP_TYPE" in
        "database")
            backup_database
            ;;
        "config")
            backup_config
            ;;
        "uploads")
            backup_uploads
            ;;
        "full")
            backup_full
            ;;
        *)
            error "Invalid backup type: $BACKUP_TYPE. Use --help for options."
            ;;
    esac
    
    # Clean up old backups
    cleanup_old_backups
    
    # Verify backups
    verify_backups
    
    # Generate report
    generate_report
    
    log "🎉 Backup completed successfully!"
    info "Backup location: $BACKUP_DIR"
    info "Backup type: $BACKUP_TYPE"
    info "Date: $DATE"
}

# Run main function
main "$@"
