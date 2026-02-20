#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

#  Installation Script
# Automated installation and configuration of the Device Assessment and Vulnerability Exposure


#######################################################################################
# This file and setup-permissions.sh have Windows style /r line endings.
# If you encounter issues running this script, please convert the line endings to Unix style.
# You can do this by running the following for every failing script:
# tr -d '\r' < scripts/XXX.sh > scripts/XXX.sh
#######################################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root. Please run as a regular user with sudo privileges."
fi

# Check if sudo is available
if ! command -v sudo &> /dev/null; then
    error "sudo is required but not installed. Please install sudo first."
fi

# Get script directory and resolve project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Allow override of project root via environment variable
if [ -n "$_ROOT" ]; then
    PROJECT_ROOT="$_ROOT"
fi

# Use PROJECT_ROOT for all paths
info "Project root detected: $PROJECT_ROOT"

log "Starting  Installation..."

# System information
log "Detecting system information..."
OS=$(lsb_release -si 2>/dev/null || echo "Unknown")
VERSION=$(lsb_release -sr 2>/dev/null || echo "Unknown")
ARCH=$(uname -m)

info "Operating System: $OS $VERSION"
info "Architecture: $ARCH"

# Check system requirements
log "Checking system requirements..."

# Check available memory
MEMORY_GB=$(free -g | awk '/^Mem:/{print $2}')
if [ "$MEMORY_GB" -lt 2 ]; then
    warning "System has less than 2GB RAM.  requires at least 2GB for optimal performance."
fi

# Check available disk space
DISK_SPACE=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
if [ "$DISK_SPACE" -lt 10 ]; then
    error "Insufficient disk space.  requires at least 10GB of free space."
fi

info "System requirements check passed"

# Update system packages
log "Updating system packages..."
sudo apt update -y

# Add PHP repository for latest PHP versions
log "Adding PHP repository..."
sudo apt install -y software-properties-common
sudo apt update -y

# Install required packages
log "Installing required packages..."
sudo apt install -y \
    apache2 \
    postgresql \
    postgresql-contrib \
    php8.3 \
    php8.3-pgsql \
    php8.3-curl \
    php8.3-mbstring \
    php8.3-xml \
    php8.3-zip \
    php8.3-gd \
    php8.3-cli \
    libapache2-mod-php8.3 \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget \
    git \
    unzip \
    software-properties-common \
    certbot \
    python3-certbot-apache \
    cron

# Enable Apache modules
log "Enabling Apache modules..."
sudo a2enmod rewrite
sudo a2enmod headers
sudo a2enmod ssl
sudo a2enmod deflate
sudo a2enmod expires

# Configure Apache
log "Configuring Apache..."
sudo tee /etc/apache2/sites-available/dave.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerName dave.local
    DocumentRoot $PROJECT_ROOT
    
    <Directory $PROJECT_ROOT>
        Allow from all
        AllowOverride all
        Header set Access-Control-Allow-Origin "*"
        Require all granted
    </Directory>
    
    # Security headers
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    
    # Logging
    ErrorLog \${APACHE_LOG_DIR}/dave_error.log
    CustomLog \${APACHE_LOG_DIR}/dave_access.log combined
</VirtualHost>
EOF

# Enable  site
sudo a2ensite dave.conf
sudo a2dissite 000-default.conf

# Configure PHP
log "Configuring PHP..."
sudo tee -a /etc/php/8.3/apache2/php.ini > /dev/null <<EOF

;  PHP Configuration
memory_limit = 256M
max_execution_time = 300
max_input_time = 300
upload_max_filesize = 50M
post_max_size = 50M
max_file_uploads = 20
date.timezone = UTC

; OPcache settings
opcache.enable=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=4000
opcache.revalidate_freq=2
opcache.fast_shutdown=1
EOF

# Start and enable services
log "Starting and enabling services..."
sudo systemctl start apache2
sudo systemctl enable apache2
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Check if .env file exists
if [ ! -f "$PROJECT_ROOT/.env" ]; then
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
source "$PROJECT_ROOT/.env"

# Validate required environment variables
MISSING_VARS=()
[ -z "$DB_HOST" ] && MISSING_VARS+=("DB_HOST")
[ -z "$DB_PORT" ] && MISSING_VARS+=("DB_PORT")
[ -z "$DB_NAME" ] && MISSING_VARS+=("DB_NAME")
[ -z "$DB_USER" ] && MISSING_VARS+=("DB_USER")
[ -z "$DB_PASSWORD" ] && MISSING_VARS+=("DB_PASSWORD")
[ -z "$DAVE_ADMIN_USER" ] && MISSING_VARS+=("DAVE_ADMIN_USER")
[ -z "$DAVE_ADMIN_DEFAULT_PASSWORD" ] && MISSING_VARS+=("DAVE_ADMIN_DEFAULT_PASSWORD")

if [ ${#MISSING_VARS[@]} -gt 0 ]; then
    error "The following required environment variables are not set in .env:"
    for var in "${MISSING_VARS[@]}"; do
        error "  - $var"
    done
    error ""
    error "Please edit .env and set all required database configuration values."
    exit 1
fi

# Configure PostgreSQL
log "Configuring PostgreSQL..."
sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" 2>/dev/null || true
sudo -u postgres psql -c "ALTER USER $DB_USER CREATEDB;" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" 2>/dev/null || true

# Create UUID extension
sudo -u postgres psql -d $DB_NAME -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";" 2>/dev/null || true

# Set up application directories
log "Setting up application directories..."
sudo mkdir -p "$PROJECT_ROOT/{logs,uploads,temp,cache}"
sudo mkdir -p "$PROJECT_ROOT/uploads/{sbom,reports,assets,nmap,nessus,csv}"

# Create config/database.php from template if it doesn't exist
log "Setting up database configuration..."
if [ ! -f "$PROJECT_ROOT/config/database.php" ]; then
    if [ -f "$PROJECT_ROOT/config/database.php.template" ]; then
        sudo cp "$PROJECT_ROOT/config/database.php.template" "$PROJECT_ROOT/config/database.php"
        log "Created config/database.php from template"
    else
        warning "config/database.php.template not found. Database config file may need manual creation."
    fi
fi

# Set up Python virtual environment (before changing ownership)
log "Setting up Python environment..."
cd "$PROJECT_ROOT"

# Remove existing venv if it exists (in case of reinstall)
if [ -d "$PROJECT_ROOT/venv" ]; then
    sudo rm -rf "$PROJECT_ROOT/venv"
fi

# Create venv - use sudo since directories may be root-owned
# We'll change ownership to www-data after creation
if [ -w "$PROJECT_ROOT" ]; then
    # Current user can write, create venv normally
    python3 -m venv venv
else
    # Need sudo to create venv
    sudo python3 -m venv venv
fi

# Install Python packages using the venv
if [ -w "$PROJECT_ROOT/venv" ]; then
    "$PROJECT_ROOT/venv/bin/pip" install --upgrade pip
    "$PROJECT_ROOT/venv/bin/pip" install pandas matplotlib seaborn psycopg2-binary requests schedule
    "$PROJECT_ROOT/venv/bin/pip" freeze > "$PROJECT_ROOT/requirements.txt"
else
    # Need sudo for pip installs
    sudo "$PROJECT_ROOT/venv/bin/pip" install --upgrade pip
    sudo "$PROJECT_ROOT/venv/bin/pip" install pandas matplotlib seaborn psycopg2-binary requests schedule
    sudo "$PROJECT_ROOT/venv/bin/pip" freeze | sudo tee "$PROJECT_ROOT/requirements.txt" > /dev/null
fi

#####################################################
# The app requires the python packages to be installed in the global level
# So we do this instead of installing in the venv only
# Or the DAV-E app needs to activate the venv and run the scripts from there
sudo apt install -y python3-pandas 
sudo apt install -y python3-matplotlib
sudo apt install -y python3-seaborn
sudo apt install -y python3-psycopg2
sudo apt install -y python3-requests
sudo apt install -y python3-schedule
#####################################################

# Set proper permissions
sudo chown -R www-data:www-data "$PROJECT_ROOT"
sudo chmod -R 755 "$PROJECT_ROOT"
sudo chmod 600 "$PROJECT_ROOT/config"/*.php 2>/dev/null || true

# Ensure venv has correct permissions (www-data needs to execute)
sudo chmod -R 755 "$PROJECT_ROOT/venv" 2>/dev/null || true

# Create placeholder files
sudo touch "$PROJECT_ROOT/uploads/.gitkeep"
sudo touch "$PROJECT_ROOT/logs/.gitkeep"
sudo touch "$PROJECT_ROOT/temp/.gitkeep"

# Set up cron jobs for background tasks
log "Setting up cron jobs for background tasks..."
sudo crontab -u www-data -l 2>/dev/null | grep -v "dave" | sudo crontab -u www-data - 2>/dev/null || true

# Add cron jobs (using PROJECT_ROOT variable)
(sudo crontab -u www-data -l 2>/dev/null; cat << EOF
#  Background Tasks
*/2 * * * * /usr/bin/python3 $PROJECT_ROOT/services/sbom_cron_processor.py >> $PROJECT_ROOT/logs/sbom_cron.log 2>&1
0 3 * * * /usr/bin/python3 $PROJECT_ROOT/services/cynerio_sync_processor.py >> $PROJECT_ROOT/logs/cynerio_integration.log 2>&1
0 2 * * * /usr/bin/python3 $PROJECT_ROOT/services/epss_sync_service.py >> $PROJECT_ROOT/logs/epss_sync.log 2>&1
0 1 * * * /usr/bin/python3 $PROJECT_ROOT/services/kev_sync_service.py >> $PROJECT_ROOT/logs/kev_sync.log 2>&1
30 1 * * * /usr/bin/php $PROJECT_ROOT/scripts/match-kev-vulnerabilities.php >> $PROJECT_ROOT/logs/kev_matching.log 2>&1
0 2 * * * /usr/bin/python3 $PROJECT_ROOT/services/risk_priority_service.py >> $PROJECT_ROOT/logs/risk_priority_cron.log 2>&1
EOF
) | sudo crontab -u www-data -

# Configure firewall
log "Configuring firewall..."
sudo ufw --force enable
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Run database schema
log "Setting up database schema..."

# Schema file path (PROJECT_ROOT already set at top of script)
SCHEMA_FILE="$PROJECT_ROOT/database/schema-production.sql"

# Debug: Show paths being checked
info "Checking for schema file at: $SCHEMA_FILE"
info "Current directory: $(pwd)"
info "Project root: $PROJECT_ROOT"

# Install database schema
if [ -f "$SCHEMA_FILE" ]; then
    log "Installing database schema..."
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f "$SCHEMA_FILE"
    log "Database schema installed successfully"
elif [ -f "database/schema-production.sql" ]; then
    # Fallback to relative path from current directory
    log "Installing database schema (relative path)..."
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f database/schema-production.sql
    log "Database schema installed successfully"
else
    error "schema-production.sql not found. Cannot proceed with installation."
    error ""
    error "Checked the following locations:"
    error "  - $SCHEMA_FILE"
    error "  - database/schema-production.sql (from $(pwd))"
    error ""
    error "The database schema file (schema-production.sql) is required for installation."
    error "Please ensure the file exists in the database/ directory of the repository."
fi

# Create initial admin user
log "Creating initial admin user..."

# Generate bcrypt hash for admin password using PHP
ADMIN_PASSWORD_HASH=$(php -r "echo password_hash('$DAVE_ADMIN_DEFAULT_PASSWORD', PASSWORD_BCRYPT);")

if [ -z "$ADMIN_PASSWORD_HASH" ]; then
    error "Failed to generate password hash for admin user"
fi

PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "
INSERT INTO users (username, email, password_hash, role, mfa_secret, is_active, created_at) 
VALUES ('$DAVE_ADMIN_USER', '$DAVE_ADMIN_USER@dave.local', '$ADMIN_PASSWORD_HASH', 'Admin', '', true, NOW())
ON CONFLICT (username) DO NOTHING;
" 2>/dev/null || true

# Setup permissions
log "Setting up file permissions..."
if [ -f "$PROJECT_ROOT/scripts/setup-permissions.sh" ]; then
    sudo bash "$PROJECT_ROOT/scripts/setup-permissions.sh"
else
    warning "setup-permissions.sh not found, skipping..."
fi

# Restart services
log "Restarting services..."
sudo systemctl restart apache2
sudo systemctl restart cron

# Create setup.php for initial configuration
log "Creating setup wizard..."
sudo cp "$PROJECT_ROOT/setup.php" "$PROJECT_ROOT/setup.php.bak" 2>/dev/null || true

# Final status check
log "Performing final status check..."

# Check Apache
if sudo systemctl is-active --quiet apache2; then
    info "Apache: Running"
else
    error "Apache: Not running"
fi

# Check PostgreSQL
if sudo systemctl is-active --quiet postgresql; then
    info "PostgreSQL: Running"
else
    error "PostgreSQL: Not running"
fi

# Check cron jobs
if sudo crontab -u www-data -l 2>/dev/null | grep -q "dave"; then
    info "Cron Jobs: Configured"
else
    warning "Cron Jobs: Not configured (may need manual setup)"
fi

# Test database connection
if PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1;" > /dev/null 2>&1; then
    info "Database Connection: Working"
else
    error "Database Connection: Failed"
fi

# Installation complete
log " Installation Complete!"
echo ""
echo -e "${GREEN}================================================================================${NC}"
echo -e "${GREEN} Installation Complete!${NC}"
echo -e "${GREEN}================================================================================${NC}"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo -e "1. Access the setup wizard at: ${YELLOW}http://$(hostname -I | awk '{print $1}')/setup.php${NC}"
echo -e "   or: ${YELLOW}http://localhost/setup.php${NC}"
echo ""
echo -e "2. Configure your Base URL and other settings"
echo -e "3. Complete the setup process"
echo -e "4. Access your  application"
echo ""
echo -e "${BLUE}Default Database Credentials:${NC}"
echo -e "   Host: $DB_HOST"
echo -e "   Database: $DB_NAME"
echo -e "   Username: $DB_USER"
echo -e "   Password: $DB_PASSWORD"
echo ""
echo -e "${BLUE}Default Admin User:${NC}"
echo -e "   Username: $DAVE_ADMIN_USER"
echo -e "   Password: [as configured in .env DAVE_ADMIN_DEFAULT_PASSWORD]"
echo -e "   ${YELLOW}[WARNING] Please change the default password after first login!${NC}"
echo ""
echo -e "${GREEN}================================================================================${NC}"
