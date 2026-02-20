#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */


set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Get database credentials
readonly APP_ROOT="/var/www/html"
source "$APP_ROOT/.env"
DB_HOST=${1:-$DB_HOST}
DB_USER=${2:-$DB_USER}
DB_NAME=${3:-$DB_NAME}
DB_PASSWORD=${4:-$DB_PASSWORD}

OUTPUT_FILE="database/schema-production.sql"

log "Generating consolidated production schema..."
info "This schema includes ALL database changes in a single file for fast fresh installs"

# Check if database exists
if ! PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    error "Database $DB_NAME does not exist. Please create it first or use an existing database."
fi

# Create header
cat > "$OUTPUT_FILE" << EOF
-- ====================================================================================
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
-- ====================================================================================
--
-- INSTRUCTIONS:
-- This is a consolidated schema that includes all database changes.
-- For fresh production installations, use this file instead of applying individual migrations.
-- For existing installations, use scripts/apply-migrations.sh to apply only new migrations.
--
-- For single-instance dev setups, this is the primary schema file.
--
-- ====================================================================================

EOF

# Generate schema dump
log "Exporting database schema..."
PGPASSWORD=$DB_PASSWORD pg_dump \
    -h $DB_HOST \
    -U $DB_USER \
    -d $DB_NAME \
    --schema-only \
    --no-owner \
    --no-acl \
    --no-privileges \
    --file="$OUTPUT_FILE.tmp" 2>/dev/null || error "Failed to export schema"

# Clean up the dump file
log "Cleaning up schema dump..."

# Remove comments that are just noise, keep structure
grep -v "^--" "$OUTPUT_FILE.tmp" | \
grep -v "^$" | \
sed 's/^--.*//' > "$OUTPUT_FILE.tmp2" || true

# Rebuild with proper header and cleaned content
cat "$OUTPUT_FILE" > "$OUTPUT_FILE.new"
echo "-- Generated: $(date +'%Y-%m-%d %H:%M:%S')" >> "$OUTPUT_FILE.new"
echo "" >> "$OUTPUT_FILE.new"
cat "$OUTPUT_FILE.tmp2" >> "$OUTPUT_FILE.new"

mv "$OUTPUT_FILE.new" "$OUTPUT_FILE"
rm -f "$OUTPUT_FILE.tmp" "$OUTPUT_FILE.tmp2"

# Add migration tracking table and note
cat >> "$OUTPUT_FILE" << 'EOF'

-- ====================================================================================
-- Migration Tracking Table
-- ====================================================================================
-- This table tracks which migrations have been applied
-- For fresh installs using this consolidated schema, all migrations are considered applied

CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(255) PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Mark all migrations as applied (since they're included in this consolidated schema)
-- This prevents the migration script from trying to re-apply them

EOF

# Get list of all migrations and mark them as applied
MIGRATIONS_DIR="database/migrations"
if [ -d "$MIGRATIONS_DIR" ]; then
    echo "-- Insert migration tracking records for all included migrations:" >> "$OUTPUT_FILE"
    for migration in $(ls -1 "$MIGRATIONS_DIR"/*.sql 2>/dev/null | sort -V); do
        if [ -f "$migration" ]; then
            MIGRATION_NAME=$(basename "$migration")
            echo "INSERT INTO schema_migrations (version) VALUES ('$MIGRATION_NAME') ON CONFLICT (version) DO NOTHING;" >> "$OUTPUT_FILE"
        fi
    done
fi

log "✅ Production schema generated: $OUTPUT_FILE"
info "File size: $(wc -l < "$OUTPUT_FILE") lines"
info ""
warning "⚠️  Review the generated schema before using in production!"
info "This schema includes all database structure but no data."
info ""
info "For single-instance dev: This is your primary schema file."
info "Migrations are kept for historical reference only."
