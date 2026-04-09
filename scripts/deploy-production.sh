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
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
APP_ROOT="/var/www/html"
BACKUP_DIR="/var/backups/dave"
LOG_FILE="$APP_ROOT/logs/deployment.log"
ENV_FILE="$APP_ROOT/.env"
ENV_EXAMPLE="$APP_ROOT/docs/env.example"

# Deployment mode
DEPLOY_MODE="${1:-interactive}"  # interactive, automated, update-only

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
    mkdir -p "$(dirname "$LOG_FILE")"
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

success() {
    echo -e "${GREEN}✅ $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $1" >> "$LOG_FILE"
}

section() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root. Please run as a regular user with sudo privileges."
fi

# Check if sudo is available
if ! command -v sudo &> /dev/null; then
    error "sudo is required but not installed."
fi

# Display banner
section "DAVE Production Deployment Automation"
echo -e "${CYAN}Deployment Mode: $DEPLOY_MODE${NC}\n"

# ============================================================================
# PRE-DEPLOYMENT CHECKS
# ============================================================================
section "Pre-Deployment Checks"

check_system_requirements() {
    log "Checking system requirements..."
    
    # Check disk space (minimum 10GB)
    DISK_SPACE=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$DISK_SPACE" -lt 10 ]; then
        warning "Less than 10GB free disk space available"
    else
        info "Disk space: ${DISK_SPACE}GB free"
    fi
    
    # Check memory (minimum 2GB)
    MEMORY_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$MEMORY_GB" -lt 2 ]; then
        warning "Less than 2GB RAM available"
    else
        info "Memory: ${MEMORY_GB}GB available"
    fi
    
    # Check required commands
    local required_commands=("php" "psql" "python3" "apache2" "systemctl")
    for cmd in "${required_commands[@]}"; do
        if command -v "$cmd" &> /dev/null || systemctl list-units | grep -q "$cmd"; then
            info "$cmd: ✅ Available"
        else
            warning "$cmd: ⚠️ Not found or not running"
        fi
    done
}

check_environment_file() {
    log "Checking environment configuration..."
    
    if [ ! -f "$ENV_FILE" ]; then
        warning ".env file not found"
        
        if [ -f "$ENV_EXAMPLE" ]; then
            if [ "$DEPLOY_MODE" != "automated" ]; then
                echo -e "${YELLOW}Would you like to create .env from template? (y/n)${NC}"
                read -r response
                if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
                    cp "$ENV_EXAMPLE" "$ENV_FILE"
                    chmod 600 "$ENV_FILE"
                    warning "Please update .env file with production values before continuing!"
                    warning "Run this script again after configuring .env"
                    exit 0
                fi
            else
                cp "$ENV_EXAMPLE" "$ENV_FILE"
                chmod 600 "$ENV_FILE"
                warning "Created .env from template. Configure it before production use!"
            fi
        else
            error ".env.example template not found"
        fi
    else
        info ".env file exists"
        
        # Check if .env has production values (not defaults)
        if grep -q "your_secure_password_here\|yourdomain.com" "$ENV_FILE"; then
            warning ".env file contains placeholder values. Please update with production values!"
            if [ "$DEPLOY_MODE" != "automated" ]; then
                echo -e "${YELLOW}Continue anyway? (y/n)${NC}"
                read -r response
                if [[ ! "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
                    exit 0
                fi
            fi
        fi
    fi
}

check_ssl_certificate() {
    log "Checking SSL certificate..."
    
    if command -v certbot &> /dev/null; then
        if sudo certbot certificates 2>/dev/null | grep -q "Certificate Name"; then
            info "SSL certificates found"
        else
            warning "No SSL certificates found. HTTPS will not be available."
            if [ "$DEPLOY_MODE" != "automated" ]; then
                echo -e "${YELLOW}Install SSL certificate? (y/n)${NC}"
                read -r response
                if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
                    echo -e "${YELLOW}Enter domain name:${NC}"
                    read -r domain
                    sudo certbot --apache -d "$domain"
                fi
            fi
        fi
    else
        warning "certbot not installed. SSL certificate setup skipped."
    fi
}

# Run pre-deployment checks
check_system_requirements
check_environment_file
check_ssl_certificate

# ============================================================================
# BACKUP CREATION
# ============================================================================
section "Backup Creation"

create_backup() {
    log "Creating system backup before deployment..."
    
    if [ -f "$APP_ROOT/scripts/backup.sh" ]; then
        if sudo bash "$APP_ROOT/scripts/backup.sh" --type full; then
            success "Backup created successfully"
        else
            warning "Backup creation failed or backup script not executable"
        fi
    else
        warning "Backup script not found at $APP_ROOT/scripts/backup.sh"
    fi
}

# Create backup if not update-only mode
if [ "$DEPLOY_MODE" != "update-only" ]; then
    create_backup
fi

# ============================================================================
# DEPLOYMENT STEPS
# ============================================================================

# For fresh installations
if [ "$DEPLOY_MODE" != "update-only" ]; then
    section "Fresh Installation"
    
    # Check if install.sh should be run
    if [ ! -f "$APP_ROOT/config/config.php" ] || [ ! -d "$APP_ROOT/database" ]; then
        log "System not fully installed. Running installation script..."
        if [ -f "$APP_ROOT/scripts/install.sh" ]; then
            if sudo bash "$APP_ROOT/scripts/install.sh"; then
                success "Installation completed"
            else
                error "Installation failed"
            fi
        else
            error "Install script not found at $APP_ROOT/scripts/install.sh"
        fi
    else
        info "System appears to be already installed. Skipping installation."
    fi
fi

# For updates
if [ "$DEPLOY_MODE" == "update-only" ] || [ "$DEPLOY_MODE" == "interactive" ]; then
    section "System Update"
    
    if [ -f "$APP_ROOT/scripts/update.sh" ]; then
        log "Running system update script..."
        if sudo bash "$APP_ROOT/scripts/update.sh"; then
            success "System update completed"
        else
            warning "System update encountered issues. Review logs."
        fi
    else
        warning "Update script not found. Skipping update."
    fi
fi

# ============================================================================
# PRODUCTION CONFIGURATION
# ============================================================================
section "Production Configuration"

configure_production_settings() {
    log "Configuring production settings..."
    
    # Set debug mode to false
    if [ -f "$APP_ROOT/config/config.php" ]; then
        if grep -q "define('_DEBUG', true)" "$APP_ROOT/config/config.php" || \
           grep -q "define('_DEBUG', 'true')" "$APP_ROOT/config/config.php"; then
            info "Setting debug mode to false..."
            sudo sed -i "s/define('_DEBUG', true)/define('_DEBUG', false)/g" "$APP_ROOT/config/config.php"
            sudo sed -i "s/define('_DEBUG', 'true')/define('_DEBUG', false)/g" "$APP_ROOT/config/config.php"
            success "Debug mode disabled"
        else
            info "Debug mode already configured"
        fi
    fi
    
    # Enable HTTPS redirect in .htaccess if SSL is configured
    if command -v certbot &> /dev/null && sudo certbot certificates 2>/dev/null | grep -q "Certificate Name"; then
        if [ -f "$APP_ROOT/.htaccess" ]; then
            if grep -q "^# RewriteCond %{HTTPS} off" "$APP_ROOT/.htaccess"; then
                info "Enabling HTTPS redirect in .htaccess..."
                sudo sed -i 's/^# RewriteCond %{HTTPS} off/RewriteCond %{HTTPS} off/' "$APP_ROOT/.htaccess"
                sudo sed -i 's/^# RewriteRule.*https.*$/RewriteRule ^(.*)$ https:\/\/%{HTTP_HOST}%{REQUEST_URI} [L,R=301]/' "$APP_ROOT/.htaccess"
                success "HTTPS redirect enabled"
            else
                info "HTTPS redirect already configured"
            fi
        fi
    fi
    
    # Set secure file permissions
    log "Setting secure file permissions..."
    if [ -f "$APP_ROOT/scripts/setup-permissions.sh" ]; then
        sudo bash "$APP_ROOT/scripts/setup-permissions.sh"
        success "File permissions configured"
    else
        warning "Permission setup script not found"
        
        # Basic permission setup
        if [ -f "$ENV_FILE" ]; then
            sudo chmod 600 "$ENV_FILE"
            info "Set .env permissions to 600"
        fi
    fi
}

configure_production_settings

# ============================================================================
# DATABASE SETUP
# ============================================================================
section "Database Setup"

setup_database() {
    source "$ENV_FILE"
    log "Setting up database..."
    
    # Check if schema needs to be applied
    if [ -f "$APP_ROOT/database/schema-production.sql" ]; then
        # Check if database exists and has tables
        if PGPASSWORD="${DB_PASSWORD:-$DB_PASSWORD}" psql -h "${DB_HOST:-$DB_HOST}" -U "${DB_USER:-$DB_USER}" -d "${DB_NAME:-$DB_NAME}" -c "\dt" 2>/dev/null | grep -q "public"; then
            info "Database schema appears to be installed"
            
            # Check if migrations need to be applied
            if [ -f "$APP_ROOT/scripts/apply-migrations.sh" ]; then
                log "Checking for pending migrations..."
                sudo bash "$APP_ROOT/scripts/apply-migrations.sh" || warning "Migration check failed"
            fi
        else
            info "Applying production schema..."
            if PGPASSWORD="${DB_PASSWORD:-$DB_PASSWORD}" psql -h "${DB_HOST:-$DB_HOST}" -U "${DB_USER:-$DB_USER}" -d "${DB_NAME:-$DB_NAME}" -f "$APP_ROOT/database/schema-production.sql" 2>/dev/null; then
                success "Database schema applied"
            else
                error "Failed to apply database schema"
            fi
        fi
    else
        warning "Production schema file not found"
    fi
}

setup_database

# ============================================================================
# SERVICE CONFIGURATION
# ============================================================================
section "Service Configuration"

configure_services() {
    log "Configuring and starting services..."
    
    # Ensure Apache is running
    if sudo systemctl is-active --quiet apache2; then
        info "Apache: ✅ Running"
    else
        log "Starting Apache..."
        sudo systemctl start apache2
        sudo systemctl enable apache2
        success "Apache started and enabled"
    fi
    
    # Ensure PostgreSQL is running
    if sudo systemctl is-active --quiet postgresql; then
        info "PostgreSQL: ✅ Running"
    else
        log "Starting PostgreSQL..."
        sudo systemctl start postgresql
        sudo systemctl enable postgresql
        success "PostgreSQL started and enabled"
    fi
    
    # Setup cron jobs
    if [ -f "$APP_ROOT/scripts/setup-cron.sh" ]; then
        log "Setting up automated tasks..."
        sudo bash "$APP_ROOT/scripts/setup-cron.sh" || warning "Cron setup encountered issues"
    fi
}

configure_services

# ============================================================================
# SECURITY HARDENING
# ============================================================================
section "Security Hardening"

harden_security() {
    log "Applying security hardening..."
    
    # Verify security headers in .htaccess
    if [ -f "$APP_ROOT/.htaccess" ]; then
        if grep -q "X-Frame-Options" "$APP_ROOT/.htaccess"; then
            info "Security headers: ✅ Configured"
        else
            warning "Security headers not found in .htaccess"
        fi
    fi
    
       
    
    # Verify .env file permissions
    if [ -f "$ENV_FILE" ]; then
        PERMS=$(stat -c "%a" "$ENV_FILE")
        if [ "$PERMS" != "600" ]; then
            warning ".env file permissions are $PERMS (should be 600)"
            sudo chmod 600 "$ENV_FILE"
            info "Updated .env permissions to 600"
        fi
    fi
    
    success "Security hardening completed"
}

harden_security

# ============================================================================
# HEALTH CHECKS
# ============================================================================
section "Health Checks"

run_health_checks() {
    log "Running system health checks..."
    source "$APP_ROOT/.env"
    # Database connectivity
    if PGPASSWORD="${DB_PASSWORD:-$DB_PASSWORD}" psql -h "${DB_HOST:-$DB_HOST}" -U "${DB_USER:-$DB_USER}" -d "${DB_NAME:-$DB_NAME}" -c "SELECT 1;" > /dev/null 2>&1; then
        success "Database: ✅ Connected"
    else
        error "Database: ❌ Connection failed"
    fi
    
    # Web server
    if curl -s -o /dev/null -w "%{http_code}" http://localhost | grep -q "200\|301\|302"; then
        success "Web server: ✅ Responding"
    else
        warning "Web server: ⚠️ Not responding correctly"
    fi
    
    # Health check endpoint
    if [ -f "$APP_ROOT/scripts/health-check.php" ]; then
        info "Running detailed health check..."
        php "$APP_ROOT/scripts/health-check.php" || warning "Health check script encountered issues"
    fi
}

run_health_checks

# ============================================================================
# DEPLOYMENT SUMMARY
# ============================================================================
section "Deployment Summary"

display_summary() {
    echo -e "${CYAN}Deployment completed at $(date)${NC}\n"
    
    echo -e "${GREEN}✅ Completed Steps:${NC}"
    echo "  1. Pre-deployment checks"
    echo "  2. System backup creation"
    if [ "$DEPLOY_MODE" != "update-only" ]; then
        echo "  3. Fresh installation (if needed)"
    fi
    if [ "$DEPLOY_MODE" == "update-only" ] || [ "$DEPLOY_MODE" == "interactive" ]; then
        echo "  4. System update"
    fi
    echo "  5. Production configuration"
    echo "  6. Database setup"
    echo "  7. Service configuration"
    echo "  8. Security hardening"
    echo "  9. Health checks"
    
    echo -e "\n${YELLOW}⚠️  Important Next Steps:${NC}"
    echo "  1. Change default passwords (admin, database)"
    echo "  2. Configure API keys in .env file"
    echo "  3. Install SSL certificate (if not done): sudo certbot --apache -d yourdomain.com"
    echo "  4. Enable HTTPS redirect in .htaccess (if SSL installed)"
    echo "  5. Test all critical workflows"
    echo "  6. Configure monitoring and alerts"
    echo "  7. Set up automated backups (if not configured)"
    
    echo -e "\n${CYAN}📋 Useful Commands:${NC}"
    echo "  - View logs: tail -f $LOG_FILE"
    echo "  - System status: php $APP_ROOT/scripts/health-check.php"
    echo "  - Manual backup: sudo bash $APP_ROOT/scripts/backup.sh"
    echo "  - System update: sudo bash $APP_ROOT/scripts/update.sh"
    
    echo -e "\n${GREEN}Deployment log saved to: $LOG_FILE${NC}\n"
}

display_summary

success "Production deployment completed successfully!"

