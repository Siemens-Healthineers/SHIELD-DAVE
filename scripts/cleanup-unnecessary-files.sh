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

APP_ROOT="/var/www/html"

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# Files and directories to remove
FILES_TO_REMOVE=(
    "$APP_ROOT/diagnostics"
    "$APP_ROOT/quick-login.php"
    "$APP_ROOT/phpunit-simple.xml"
    "$APP_ROOT/audit-root.json"
    "$APP_ROOT/_CACHE_DIR"
    "$APP_ROOT/uploads/test.txt"
    "$APP_ROOT/PimpMyLog"
    "$APP_ROOT/TEST_SUITE_GITHUB_ACTIONS.md"
)

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}DAVE - Cleanup Unnecessary Files${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

log "Checking for files and directories to remove..."

# Show what will be removed
info "Files/directories to be removed:"
total_size=0
for item in "${FILES_TO_REMOVE[@]}"; do
    if [ -e "$item" ]; then
        size=$(du -sk "$item" 2>/dev/null | cut -f1)
        size_kb=$((size))
        total_size=$((total_size + size_kb))
        
        if [ -d "$item" ]; then
            echo "  📁 $item (${size_kb}KB - directory)"
        else
            echo "  📄 $item (${size_kb}KB)"
        fi
    else
        echo "  ⚠️  $item (not found, skipping)"
    fi
done

echo ""
info "Total size to free: ~${total_size}KB"

# Confirm removal
echo ""
warning "This will permanently delete the files listed above."
echo -e "${YELLOW}Do you want to continue? (yes/no)${NC}"
read -r response

if [[ ! "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    info "Cleanup cancelled."
    exit 0
fi

# Remove files
log "Removing files and directories..."
removed_count=0
skipped_count=0

for item in "${FILES_TO_REMOVE[@]}"; do
    if [ -e "$item" ]; then
        if rm -rf "$item" 2>/dev/null; then
            log "✅ Removed: $item"
            ((removed_count++))
        else
            warning "⚠️  Failed to remove: $item (may need sudo)"
            ((skipped_count++))
        fi
    else
        info "⏭️  Skipped (not found): $item"
        ((skipped_count++))
    fi
done

echo ""
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Cleanup Summary:"
log "  ✅ Removed: $removed_count items"
if [ $skipped_count -gt 0 ]; then
    warning "  ⏭️  Skipped: $skipped_count items"
fi
log "  💾 Space freed: ~${total_size}KB"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $removed_count -gt 0 ]; then
    log "✅ Cleanup completed successfully!"
else
    warning "⚠️  No files were removed."
fi

