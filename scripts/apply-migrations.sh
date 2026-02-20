#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Get database credentials from arguments or use defaults
readonly APP_ROOT="/var/www/html"
source "$APP_ROOT/.env"
DB_HOST=${1:-$DB_HOST}
DB_USER=${2:-$DB_USER}
DB_NAME=${3:-$DB_NAME}
DB_PASSWORD=${4:-$DB_PASSWORD}

log "Applying database migrations..."

# Check if migrations directory exists
MIGRATIONS_DIR="/var/www/html/database/migrations"
if [ ! -d "$MIGRATIONS_DIR" ]; then
    error "Migrations directory not found: $MIGRATIONS_DIR"
fi

# Create migration tracking table if it doesn't exist
log "Setting up migration tracking..."
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(255) PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);" 2>/dev/null || error "Failed to create migration tracking table"

# Get list of migrations sorted numerically
MIGRATIONS=$(ls -1 $MIGRATIONS_DIR/*.sql | sort -V)

APPLIED_COUNT=0
SKIPPED_COUNT=0
FAILED_COUNT=0

for migration in $MIGRATIONS; do
    if [ ! -f "$migration" ]; then
        continue
    fi
    
    MIGRATION_NAME=$(basename "$migration")
    
    # Check if migration has already been applied
    APPLIED=$(PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -t -c "
        SELECT COUNT(*) FROM schema_migrations WHERE version = '$MIGRATION_NAME';
    " 2>/dev/null | tr -d ' ')
    
    if [ "$APPLIED" = "1" ]; then
        info "Skipping already applied migration: $MIGRATION_NAME"
        SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        continue
    fi
    
    # Apply migration
    log "Applying migration: $MIGRATION_NAME"
    if PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f "$migration" > /dev/null 2>&1; then
        # Record migration as applied
        PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "
            INSERT INTO schema_migrations (version) VALUES ('$MIGRATION_NAME')
            ON CONFLICT (version) DO NOTHING;
        " > /dev/null 2>&1
        
        APPLIED_COUNT=$((APPLIED_COUNT + 1))
        info "✅ Applied: $MIGRATION_NAME"
    else
        warning "⚠️ Failed to apply: $MIGRATION_NAME (check logs for details)"
        FAILED_COUNT=$((FAILED_COUNT + 1))
        
        # Try to get error details
        ERROR_OUTPUT=$(PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f "$migration" 2>&1 || true)
        echo "$ERROR_OUTPUT" | tail -5
    fi
done

log "Migration summary:"
info "  Applied: $APPLIED_COUNT"
info "  Skipped: $SKIPPED_COUNT"
info "  Failed: $FAILED_COUNT"

if [ $FAILED_COUNT -gt 0 ]; then
    error "Some migrations failed. Please review the errors above."
fi

log "✅ All migrations applied successfully!"






