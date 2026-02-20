
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# DAVE Deployment Guide

## Table of Contents

- [Deployment Overview](#deployment-overview)
- [Prerequisites](#prerequisites)
- [Installation Steps](#installation-steps)
- [Configuration](#configuration)
- [Security Setup](#security-setup)
- [Testing and Validation](#testing-and-validation)
- [Production Deployment](#production-deployment)
- [Monitoring Setup](#monitoring-setup)
- [Troubleshooting](#troubleshooting)

## Deployment Overview

This guide provides step-by-step instructions for deploying the Device Assessment and Vulnerability Exposure (DAVE) in a production environment.

### Deployment Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   Web Server    │    │   Database      │
│   (Optional)    │────│   (Apache/Nginx)│────│   (PostgreSQL)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                │
                       ┌─────────────────┐
                       │ Background      │
                       │ Services        │
                       │ (Python)        │
                       └─────────────────┘
```

### Deployment Options

#### Single Server Deployment
- All components on one server
- Suitable for small to medium organizations
- Lower complexity and cost

#### Multi-Server Deployment
- Separate servers for web, database, and background services
- Better performance and scalability
- Higher complexity and cost

#### Cloud Deployment
- Deploy on cloud platforms (AWS, Azure, GCP)
- Auto-scaling capabilities
- Managed services integration

## Prerequisites

### System Requirements

#### Minimum Requirements
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 4 GB
- **Storage**: 50 GB SSD
- **Network**: 100 Mbps
- **OS**: Ubuntu 20.04 LTS or CentOS 8
- **Python**: 3.8+ (for background services)

#### Recommended Requirements
- **CPU**: 4 cores, 3.0 GHz
- **RAM**: 8 GB
- **Storage**: 100 GB SSD
- **Python**: 3.9+ (for background services)
- **Network**: 1 Gbps
- **OS**: Ubuntu 20.04 LTS

### Software Requirements

#### Required Software
- **Web Server**: Apache 2.4+ or Nginx 1.18+
- **Database**: PostgreSQL 13+
- **PHP**: 8.0+ with required extensions
- **Python**: 3.8+ with pip (for background services)
- **Cron**: For scheduled tasks
- **SSL Certificate**: For HTTPS

#### Required PHP Extensions
- php8.0-pgsql
- php8.0-curl
- php8.0-json
- php8.0-mbstring
- php8.0-xml
- php8.0-zip
- php8.0-gd

#### Required Python Packages
- pandas
- matplotlib
- seaborn
- psycopg2
- requests
- schedule

### Network Requirements

#### Ports
- **80**: HTTP (redirect to HTTPS)
- **443**: HTTPS
- **5432**: PostgreSQL (internal)
- **22**: SSH (management)

#### Firewall Configuration
```bash
# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow SSH
sudo ufw allow 22/tcp

# Enable firewall
sudo ufw enable
```

## Installation Steps

### Automated Installation (Recommended)

The easiest way to deploy DAVE is using the automated installation script with the web-based setup wizard:

#### Step 1: Run Installation Script
```bash
# Download or extract DAVE files to /var/www/html
Create the folder /var/www/html if it doesnt exist and copy the contents of c01-csms into the html folder. 
Copy docs/env.example to .env and update the following fields with your own defaults
The values you specify here will be used by the installation scripts to create the specific accounts/databases 

   - DAVE_ADMIN_USER=<your admin user name>
   - DAVE_ADMIN_DEFAULT_PASSWORD=<your admin default password>

   - DB_HOST=localhost
   - DB_PORT=5432
   - DB_NAME=<your database name. Eg., dave_db>
   - DB_USER=<your database login. Eg., dave_user>
   - DB_PASSWORD=<your database password. Eg., dave_password>
cd /var/www/html

# Run the automated installation script
sudo bash scripts/install.sh
```

The installation script will:
- Install all required packages (Apache, PostgreSQL, PHP, Python)
- Set up the database and create default admin user
- Configure file permissions and directories
- Set up background services and cron jobs
- Create the setup wizard for configuration

#### Step 2: Complete Setup Wizard
After the installation script completes, you'll see instructions to access the setup wizard:

```
Next Steps:
1. Access the setup wizard at: http://your-server-ip/setup.php
   or: http://localhost/setup.php

2. Configure your Base URL and other settings
3. Complete the setup process
4. Access your DAVE application
```

Visit the setup wizard URL and configure:
- **Base URL**: Your application's main URL (e.g., `https://dave.yourdomain.com`)
- **Database Settings**: Verify database connection
- **Email Configuration**: Optional SMTP settings
- **Debug Mode**: Enable for development, disable for production

#### Step 3: Access Application
After completing the setup wizard, access your DAVE application at the configured Base URL.

**Default Admin Credentials:**
- Username: <admin user>
- Password: <admin password>

⚠️ **Important**: Change the default password immediately after first login!

### Manual Installation (Advanced)

If you prefer manual installation or need custom configuration:

#### Step 1: System Preparation

##### Update System
```bash
# Update package lists
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y curl wget git unzip software-properties-common
```

##### Create Application User
```bash
# Create application user
sudo useradd -m -s /bin/bash dave
sudo usermod -aG www-data dave
```

### Step 2: Database Installation

#### Install PostgreSQL
```bash
# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Start and enable PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Set PostgreSQL password
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'secure_password';"
```

#### Configure PostgreSQL
```bash
# Edit PostgreSQL configuration
sudo nano /etc/postgresql/13/main/postgresql.conf

# Set configuration parameters
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100

# Edit authentication configuration
sudo nano /etc/postgresql/13/main/pg_hba.conf

# Add local connections
local   all             all                                     md5
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5

# Restart PostgreSQL
sudo systemctl restart postgresql
```

#### Create Database and User
```bash
# Create database and user
sudo -u postgres psql
CREATE DATABASE <database name>;
CREATE USER <database user> WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE <database name> TO <database user>;
\q
```

### Step 3: Web Server Installation

#### Install Apache
```bash
# Install Apache
sudo apt install -y apache2

# Enable required modules
sudo a2enmod rewrite
sudo a2enmod headers
sudo a2enmod ssl

# Start and enable Apache
sudo systemctl start apache2
sudo systemctl enable apache2
```

#### Install PHP
```bash
# Install PHP and extensions
sudo apt install -y php8.0 php8.0-pgsql php8.0-curl php8.0-json php8.0-mbstring php8.0-xml php8.0-zip php8.0-gd php8.0-cli

# Configure PHP
sudo nano /etc/php/8.0/apache2/php.ini

# Set PHP configuration
memory_limit = 256M
max_execution_time = 300
max_input_time = 300
upload_max_filesize = 50M
post_max_size = 50M
max_file_uploads = 20
date.timezone = UTC

# Enable OPcache
opcache.enable=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=4000
opcache.revalidate_freq=2
opcache.fast_shutdown=1
```

### Step 4: Application Installation

#### Download Application
```bash
# Create application directory
sudo mkdir -p /var/www/html
cd /var/www/html

# Download application (replace with actual download method)
# git clone https://github.com/your-org/dave.git .
# or
# wget https://releases.dave.com/dave-latest.tar.gz
# tar -xzf dave-latest.tar.gz

# Set permissions
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
```

#### Create Required Directories
```bash
# Create required directories
sudo mkdir -p /var/www/html/logs
sudo mkdir -p /var/www/html/uploads
sudo mkdir -p /var/www/html/uploads/sbom
sudo mkdir -p /var/www/html/uploads/reports
sudo mkdir -p /var/www/html/uploads/assets

# Set permissions
sudo chown -R www-data:www-data /var/www/html/logs
sudo chown -R www-data:www-data /var/www/html/uploads
sudo chmod -R 755 /var/www/html/logs
sudo chmod -R 755 /var/www/html/uploads
```

### Step 5: Database Schema

#### Run Database Schema
```bash
# Run database schema
psql -h localhost -U <database user> -d <database name> -f /var/www/html/database/schema.sql

# Verify schema
psql -h localhost -U <database user> -d <database name> -c "\dt"
```

### Step 6: Python Environment

#### Install Python Dependencies
```bash
# Create Python virtual environment
cd /var/www/html
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install --upgrade pip
pip install pandas matplotlib seaborn psycopg2-binary requests schedule

# Create requirements.txt
pip freeze > requirements.txt
```

### Step 7: Background Services

#### Setup Cron Jobs
```bash
# Setup SBOM processing cron (every 2 minutes)
*/2 * * * * /usr/bin/python3 /var/www/html/services/sbom_cron_processor.py >> /var/www/html/logs/sbom_cron.log 2>&1

# Setup EPSS sync cron (daily at 2:00 AM)
0 2 * * * /usr/bin/python3 /var/www/html/services/epss_sync_service.py >> /var/www/html/logs/epss_sync.log 2>&1

# Setup KEV sync cron (daily at 1:00 AM)
0 1 * * * /usr/bin/python3 /var/www/html/services/kev_sync_service.py >> /var/www/html/logs/kev_sync.log 2>&1

# Setup risk priority updates (daily at 2:00 AM)
0 2 * * * /usr/bin/python3 /var/www/html/services/risk_priority_service.py >> /var/www/html/logs/risk_priority_cron.log 2>&1
```

#### Install Cron Jobs
```bash
# Add cron jobs to www-data user
sudo crontab -u www-data -e

# Or use the setup script
cd /var/www/html
sudo ./scripts/setup-cron.sh

# Check cron jobs
sudo crontab -u www-data -l
```

## Background Services Setup

### Python Dependencies

Install required Python packages for background services:

```bash
# Install Python dependencies
pip3 install -r /var/www/html/background_services/requirements.txt

# Or install individually
pip3 install requests psycopg2-binary
```

### Background Services Configuration

#### EPSS Service
```bash
# Configure EPSS service
sudo cp /var/www/html/background_services/epss_service.py /usr/local/bin/
sudo chmod +x /usr/local/bin/epss_service.py

# Create systemd service
sudo tee /etc/systemd/system/dave-epss.service > /dev/null <<EOF
[Unit]
Description=DAVE EPSS Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/html
ExecStart=/usr/bin/python3 /usr/local/bin/epss_service.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable dave-epss
sudo systemctl start dave-epss
```

#### KEV Service
```bash
# Configure KEV service
sudo cp /var/www/html/background_services/kev_service.py /usr/local/bin/
sudo chmod +x /usr/local/bin/kev_service.py

# Create systemd service
sudo tee /etc/systemd/system/dave-kev.service > /dev/null <<EOF
[Unit]
Description=DAVE KEV Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/html
ExecStart=/usr/bin/python3 /usr/local/bin/kev_service.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable dave-kev
sudo systemctl start dave-kev
```

#### Risk Priority Service
```bash
# Configure Risk Priority service
sudo cp /var/www/html/background_services/risk_priority_service.py /usr/local/bin/
sudo chmod +x /usr/local/bin/risk_priority_service.py

# Create systemd service
sudo tee /etc/systemd/system/dave-risk-priority.service > /dev/null <<EOF
[Unit]
Description=DAVE Risk Priority Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/html
ExecStart=/usr/bin/python3 /usr/local/bin/risk_priority_service.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable dave-risk-priority
sudo systemctl start dave-risk-priority
```

### Cron Jobs

Set up scheduled tasks for background services:

```bash
# Add cron jobs
sudo crontab -e

# Add the following lines:
# EPSS sync - daily at 2 AM
0 2 * * * /usr/bin/python3 /usr/local/bin/epss_service.py

# KEV sync - daily at 3 AM
0 3 * * * /usr/bin/python3 /usr/local/bin/kev_service.py

# Risk priority calculation - daily at 4 AM
0 4 * * * /usr/bin/python3 /usr/local/bin/risk_priority_service.py
```

### Service Monitoring

Check service status:

```bash
# Check all DAVE services
sudo systemctl status dave-epss dave-kev dave-risk-priority

# Check service logs
sudo journalctl -u dave-epss -f
sudo journalctl -u dave-kev -f
sudo journalctl -u dave-risk-priority -f
```

## Configuration

### Web-Based Configuration (Recommended)

The easiest way to configure DAVE is using the web-based setup wizard:

#### Access Setup Wizard
1. **After Installation**: Visit `http://your-server-ip/setup.php`
2. **Configure Settings**:
   - Base URL (e.g., `https://dave.yourdomain.com`)
   - Database connection settings
   - Email configuration (optional)
   - Debug mode settings
3. **Complete Setup**: The wizard will save all configuration automatically

#### Setup Wizard Features
- **Real-time Validation**: Instant validation of Base URL and database connections
- **Auto-configuration**: Automatic API URL generation and environment setup
- **Security**: Proper file permissions and secure configuration storage
- **One-time Setup**: Prevents re-running after configuration is complete

### Manual Configuration (Advanced)

If you prefer manual configuration or need to modify settings after setup:

#### Database Configuration
```bash
# Copy database configuration
sudo cp /var/www/html/config/database.example.php /var/www/html/config/database.php

# Edit database configuration
sudo nano /var/www/html/config/database.php
```

```php
<?php
define('DB_HOST', '<database host/IP>');
define('DB_NAME', '<database name>');
define('DB_USER', '<database user>');
define('DB_PASS', 'secure_password');
define('DB_PORT', '5432');
?>
```

#### Application Configuration
```bash
# Copy application configuration
sudo cp /var/www/html/config/config.example.php /var/www/html/config/config.php

# Edit application configuration
sudo nano /var/www/html/config/config.php
```

```php
<?php
define('DAVE_NAME', 'Device Assessment and Vulnerability Exposure');
define('DAVE_VERSION', '1.0.0');
define('DAVE_DEBUG', false);
define('DAVE_UPLOADS', '/var/www/html/uploads');
define('DAVE_LOGS', '/var/www/html/logs');

// Email configuration
define('EMAIL_HOST', 'smtp.yourdomain.com');
define('EMAIL_PORT', 587);
define('EMAIL_USERNAME', 'noreply@yourdomain.com');
define('EMAIL_PASSWORD', 'email_password');

// API keys
define('FDA_API_KEY', 'your_fda_api_key');
define('NVD_API_KEY', 'your_nvd_api_key');
define('MAC_OUI_API_KEY', 'your_mac_oui_api_key');
?>
```

#### Environment Configuration
For production deployments, consider using environment variables:

```bash
# Create .env file
sudo nano /var/www/html/.env
```

```env
# Core Application Settings
DAVE_ADMIN_USER=admin
DAVE_ADMIN_DEFAULT_PASSWORD=password
DAVE_BASE_URL=https://dave.yourdomain.com
DAVE_API_URL=https://dave.yourdomain.com/api
DAVE_DEBUG=false

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=dave_db
DB_USER=<database user>
DB_PASSWORD=secure_password

# Email Configuration
DAVE_SMTP_HOST=smtp.yourdomain.com
DAVE_SMTP_PORT=587
DAVE_SMTP_USERNAME=noreply@yourdomain.com
DAVE_SMTP_PASSWORD=email_password
```

See [Environment Configuration Guide](ENVIRONMENT_CONFIGURATION.md) for detailed information.

### Web Server Configuration

#### Apache Virtual Host
```bash
# Create virtual host
sudo nano /etc/apache2/sites-available/dave.conf
```

```apache
<VirtualHost *:80>
    ServerName dave.yourdomain.com
    DocumentRoot /var/www/html
    
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
    
    # Security headers
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    
    # Logging
    ErrorLog ${APACHE_LOG_DIR}/dave_error.log
    CustomLog ${APACHE_LOG_DIR}/dave_access.log combined
</VirtualHost>
```

#### Enable Site
```bash
# Enable site
sudo a2ensite dave.conf

# Disable default site
sudo a2dissite 000-default.conf

# Restart Apache
sudo systemctl restart apache2
```

### SSL Configuration

#### Install SSL Certificate
```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-apache

# Obtain SSL certificate
sudo certbot --apache -d dave.yourdomain.com

# Test automatic renewal
sudo certbot renew --dry-run
```

#### SSL Configuration
```apache
<VirtualHost *:443>
    ServerName dave.yourdomain.com
    DocumentRoot /var/www/html
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/dave.yourdomain.com/cert.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/dave.yourdomain.com/privkey.pem
    SSLCertificateChainFile /etc/letsencrypt/live/dave.yourdomain.com/chain.pem
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
    
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

## Security Setup

### Firewall Configuration

#### Configure UFW
```bash
# Enable UFW
sudo ufw enable

# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Check status
sudo ufw status
```

### Database Security

#### PostgreSQL Security
```bash
# Edit PostgreSQL configuration
sudo nano /etc/postgresql/13/main/postgresql.conf

# Set security parameters
ssl = on
ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'

# Edit authentication configuration
sudo nano /etc/postgresql/13/main/pg_hba.conf

# Restrict access
local   all             all                                     md5
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5

# Restart PostgreSQL
sudo systemctl restart postgresql
```

### Application Security

#### File Permissions
```bash
# Set secure file permissions
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
sudo chmod 600 /var/www/html/config/*.php
sudo chmod 755 /var/www/html/logs
sudo chmod 755 /var/www/html/uploads
```

#### PHP Security
```bash
# Edit PHP configuration
sudo nano /etc/php/8.0/apache2/php.ini

# Set security parameters
expose_php = Off
allow_url_fopen = Off
allow_url_include = Off
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
```

## Testing and Validation

### System Tests

#### Database Connection Test
```bash
# Test database connection
psql -h localhost -U <database user> -d <database name> -c "SELECT version();"
```

#### Web Server Test
```bash
# Test web server
curl -I http://dave.yourdomain.com
curl -I https://dave.yourdomain.com
```

#### Cron Job Test
```bash
# Test cron jobs
sudo crontab -u www-data -l

# Check cron logs
tail -f /var/www/html/logs/sbom_cron.log
tail -f /var/www/html/logs/epss_sync.log
tail -f /var/www/html/logs/kev_sync.log
tail -f /var/www/html/logs/risk_priority_cron.log
```

### Application Tests

#### Login Test
1. Navigate to `https://dave.yourdomain.com`
2. Verify login page loads
3. Test login functionality
4. Verify dashboard loads

#### Functionality Tests
1. **Asset Management**: Create, edit, delete assets
2. **Device Mapping**: Map devices to FDA records
3. **Vulnerability Scanning**: Upload SBOM and scan
4. **Recall Monitoring**: Check recall functionality
5. **Report Generation**: Generate and download reports

### Performance Tests

#### Load Testing
```bash
# Install Apache Bench
sudo apt install -y apache2-utils

# Run load test
ab -n 1000 -c 10 https://dave.yourdomain.com/
```

#### Database Performance
```sql
-- Test database performance
EXPLAIN ANALYZE SELECT * FROM assets WHERE status = 'Active';
```

## Production Deployment

### Production Checklist

#### Pre-Deployment
- [ ] All tests passing
- [ ] Security configuration complete
- [ ] SSL certificate installed
- [ ] Backup procedures in place
- [ ] Monitoring configured
- [ ] Documentation updated

#### Deployment Steps
1. **Final Testing**: Run complete test suite
2. **Backup**: Create system backup
3. **Deploy**: Deploy application
4. **Configure**: Apply production configuration
5. **Test**: Verify functionality
6. **Monitor**: Start monitoring

### Production Configuration

#### Environment Variables
```bash
# Set production environment
export DAVE_ENV=production
export DAVE_DEBUG=false
export DAVE_LOG_LEVEL=INFO
```

#### Production Settings
```php
// config/config.php
define('DAVE_DEBUG', false);
define('DAVE_LOG_LEVEL', 'INFO');
define('DAVE_ENV', 'production');
```

### Monitoring Setup

#### System Monitoring
```bash
# Install monitoring tools
sudo apt install -y htop iotop nethogs

# Monitor system resources
htop
df -h
free -h
```

#### Application Monitoring
```bash
# Monitor application logs
tail -f /var/www/html/logs/application.log
tail -f /var/www/html/logs/sbom_cron.log
```

#### Database Monitoring
```sql
-- Monitor database performance
SELECT * FROM pg_stat_activity;
SELECT * FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;
```

## Monitoring Setup

### Log Monitoring

#### Application Logs
```bash
# Monitor application logs
tail -f /var/www/html/logs/application.log
tail -f /var/www/html/logs/sbom_cron.log
tail -f /var/www/html/logs/recall_monitor.log
tail -f /var/www/html/logs/vulnerability_scanner.log
```

#### System Logs
```bash
# Monitor system logs
sudo journalctl -u apache2 -f
sudo journalctl -u postgresql -f
# Check cron service status
sudo systemctl status cron
```

### Performance Monitoring

#### Resource Monitoring
```bash
# Monitor system resources
htop
iotop
nethogs
```

#### Database Monitoring
```sql
-- Monitor database performance
SELECT * FROM pg_stat_activity;
SELECT * FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;
```

### Alerting Setup

#### Email Alerts
```bash
# Configure email alerts
sudo apt install -y mailutils

# Test email
echo "Test email" | mail -s "Test" admin@yourdomain.com
```

#### Log Rotation
```bash
# Configure log rotation
sudo nano /etc/logrotate.d/dave
```

```
/var/www/html/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
}
```

## Troubleshooting

### Common Issues

#### Database Connection Issues
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Test connection
psql -h localhost -U <database user> -d <database name>

# Check connection limits
psql -h localhost -U <database user> -d <database name> -c "SHOW max_connections;"
```

#### Web Server Issues
```bash
# Check Apache status
sudo systemctl status apache2

# Check Apache logs
sudo tail -f /var/log/apache2/error.log
sudo tail -f /var/log/apache2/access.log
```

#### Cron Job Issues
```bash
# Check cron service status
sudo systemctl status cron

# Check cron logs
tail -f /var/www/html/logs/sbom_cron.log
tail -f /var/www/html/logs/epss_sync.log
tail -f /var/www/html/logs/kev_sync.log
tail -f /var/www/html/logs/risk_priority_cron.log

# Test cron jobs manually
cd /var/www/html
python3 services/sbom_cron_processor.py
python3 services/epss_sync_service.py
python3 services/kev_sync_service.py
python3 services/risk_priority_service.py
```

#### File Permission Issues
```bash
# Check file permissions
ls -la /var/www/html/
ls -la /var/www/html/uploads/
ls -la /var/www/html/logs/

# Fix permissions
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
```

### Diagnostic Commands

#### System Diagnostics
```bash
# System information
uname -a
cat /etc/os-release
lscpu
free -h
df -h

# Network connectivity
ping google.com
nslookup yourdomain.com
telnet localhost 5432
```

#### Application Diagnostics
```bash
# Check PHP configuration
php -i

# Check Python environment
cd /var/www/html
source venv/bin/activate
pip list

# Check file permissions
find /var/www/html -type f -name "*.php" -exec ls -la {} \;
```

### Recovery Procedures

#### System Recovery
1. **Stop Services**: Stop all running services
2. **Restore Backup**: Restore from backup
3. **Verify Data**: Ensure data integrity
4. **Restart Services**: Start services in correct order
5. **Test Functionality**: Verify system functionality

#### Data Recovery
1. **Identify Lost Data**: Determine what data needs recovery
2. **Check Backups**: Verify backup availability
3. **Restore Data**: Restore from appropriate backup
4. **Verify Integrity**: Ensure data integrity
5. **Update System**: Update system with recovered data

---

**Last Updated**: January 2024  
**Version**: 1.0.0  
**For Technical Support**: Contact your system administrator or DAVE support team
