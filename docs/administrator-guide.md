
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */
# DAVE Administrator Guide

## Table of Contents

- [System Administration](#system-administration)
- [User Management](#user-management)
- [Security Configuration](#security-configuration)
- [Database Management](#database-management)
- [Background Services](#background-services)
- [Monitoring and Logging](#monitoring-and-logging)
- [Backup and Recovery](#backup-and-recovery)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)
- [Maintenance Procedures](#maintenance-procedures)

## System Administration

### System Overview

The DAVE platform consists of several key components:

- **Web Interface**: PHP-based user interface
- **API Layer**: RESTful APIs for data access
- **Background Services**: Python services for automation
- **Database**: PostgreSQL for data persistence
- **File Storage**: Local file system for uploads and reports

### System Requirements

#### Minimum Requirements
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 4 GB
- **Storage**: 50 GB SSD
- **Network**: 100 Mbps

#### Recommended Requirements
- **CPU**: 4 cores, 3.0 GHz
- **RAM**: 8 GB
- **Storage**: 100 GB SSD
- **Network**: 1 Gbps

### Installation and Setup

#### Automated Installation (Recommended)

The easiest way to install DAVE is using the automated installation script with the web-based setup wizard:

1. **Run Installation Script**
   ```bash
   # Create the folder /var/www/html if it doesnt exist and copy the contents of c01-csms into the html folder. 
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

2. **Complete Setup Wizard**
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

3. **Access Application**
   After completing the setup wizard, access your DAVE application at the configured Base URL.

   **Default Admin Credentials:**
   - Username: `admin`
   - Password: `password`

   ⚠️ **Important**: Change the default password immediately after first login!

#### Manual Installation (Advanced)

If you prefer manual installation or need custom configuration:

1. **System Preparation**
   ```bash
   # Update system packages
   sudo apt update && sudo apt upgrade -y
   
   # Install required packages
   sudo apt install -y apache2 postgresql postgresql-contrib php8.0 php8.0-pgsql php8.0-curl php8.0-json php8.0-mbstring python3 python3-pip python3-venv
   ```

2. **Database Setup**
   ```bash
   # Create database and user
   sudo -u postgres psql
   CREATE DATABASE <database name>;
   CREATE USER <database user> WITH PASSWORD 'secure_password';
   GRANT ALL PRIVILEGES ON DATABASE <database name> TO <database user>;
   \q
   ```

3. **Application Deployment**
   ```bash
   # Set proper permissions
   sudo chown -R www-data:www-data /var/www/html
   sudo chmod -R 755 /var/www/html
   
   # Create required directories
   mkdir -p /var/www/html/logs
   mkdir -p /var/www/html/uploads
   mkdir -p /var/www/html/uploads/sbom
   mkdir -p /var/www/html/uploads/reports
   ```

4. **Database Schema**
   ```bash
   # Run database schema
   psql -h localhost -U <database user> -d <database name> -f /var/www/html/database/schema.sql
   ```

5. **Configuration**
   ```bash
   # Copy and edit configuration files
   cp /var/www/html/config/config.example.php /var/www/html/config/config.php
   cp /var/www/html/config/database.example.php /var/www/html/config/database.php
   
   # Edit configuration files
   nano /var/www/html/config/config.php
   nano /var/www/html/config/database.php
   ```

   Or use the web-based setup wizard:
   - Visit: `http://your-server-ip/setup.php`
   - Configure all settings through the web interface

#### Web Server Configuration

##### Apache Configuration
```apache
<VirtualHost *:80>
    ServerName dave.local
    DocumentRoot /var/www/html
    
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
    
    # Enable mod_rewrite
    RewriteEngine On
    
    # Security headers
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
```

##### Nginx Configuration
```nginx
server {
    listen 80;
    server_name dave.local;
    root /var/www/html;
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
}
```

## User Management

### User Roles and Permissions

#### Administrator
- **Full System Access**: All features and functions
- **User Management**: Create, edit, delete users
- **System Configuration**: Configure system settings
- **Background Services**: Manage automated services
- **Database Access**: Direct database access
- **Log Access**: View all system logs
- **Security Management**: Configure security settings and monitor threats
- **API Key Management**: Create and manage API keys
- **Risk Matrix Configuration**: Configure risk calculation parameters

#### User
- **Asset Management**: View and manage assets
- **Device Mapping**: View device mappings and FDA records
- **Vulnerability Management**: View vulnerabilities and risk priorities
- **Report Generation**: Generate and view reports
- **Dashboard Access**: View dashboards and analytics
- **Read-Only System Access**: Limited system configuration access

### Creating and Managing Users

#### Creating Users
1. **Navigate to Admin → User Management**
2. **Click "Add User"**
3. **Fill in user details**:
   - Username (email address)
   - Password (temporary)
   - First Name
   - Last Name
   - Department
   - Role
   - Status (Active/Inactive)
4. **Assign permissions**
5. **Send invitation email**

#### User Account Management
- **Account Status**: Active, Inactive, Locked
- **Password Reset**: Force password reset
- **Role Changes**: Modify user roles
- **Permission Updates**: Update user permissions
- **Account Lockout**: Lock/unlock accounts

#### Bulk User Operations
- **CSV Import**: Import users from CSV file
- **Bulk Role Changes**: Change roles for multiple users
- **Bulk Status Updates**: Update status for multiple users
- **Bulk Permissions**: Update permissions for multiple users

### Authentication and Security

#### Multi-Factor Authentication (MFA)
- **TOTP Support**: Time-based one-time passwords
- **SMS Backup**: SMS-based backup codes
- **Recovery Codes**: Emergency access codes
- **MFA Enforcement**: Require MFA for all users

#### Password Policies
- **Minimum Length**: 8 characters minimum
- **Complexity Requirements**: Uppercase, lowercase, numbers, symbols
- **Password History**: Cannot reuse last 5 passwords
- **Expiration**: 90-day password expiration
- **Lockout Policy**: Account lockout after failed attempts

#### Session Management
- **Session Timeout**: 30 minutes of inactivity
- **Concurrent Sessions**: Limit concurrent sessions
- **Session Security**: Secure session handling
- **Logout**: Secure logout procedures

## Security Configuration

### Access Control

#### Role-Based Access Control (RBAC)
- **Role Definition**: Define user roles and permissions
- **Permission Matrix**: Map roles to specific permissions
- **Hierarchical Roles**: Role inheritance and hierarchy
- **Dynamic Permissions**: Runtime permission checking

#### Network Security
- **IP Whitelisting**: Restrict access by IP address
- **VPN Requirements**: Require VPN access
- **Network Segmentation**: Isolate system components
- **Firewall Rules**: Configure firewall rules

#### Data Encryption
- **Encryption at Rest**: Encrypt stored data
- **Encryption in Transit**: HTTPS/TLS encryption
- **Key Management**: Secure key storage and rotation
- **Database Encryption**: Encrypt database files

### Security Monitoring

#### Audit Logging
- **User Actions**: Log all user activities
- **System Events**: Log system events
- **Security Events**: Log security-related events
- **Data Access**: Log data access patterns

#### Intrusion Detection
- **Failed Login Attempts**: Monitor failed logins
- **Suspicious Activity**: Detect unusual patterns
- **Brute Force Protection**: Prevent brute force attacks
- **Anomaly Detection**: Detect anomalous behavior

#### Security Alerts
- **Real-time Alerts**: Immediate security notifications
- **Email Notifications**: Email security alerts
- **Dashboard Alerts**: Visual security indicators
- **Escalation Procedures**: Security incident escalation

## Database Management

### Database Schema

The system uses PostgreSQL with the following main tables:

- **assets**: Asset information and inventory
- **vulnerabilities**: CVE data and vulnerability details
- **recalls**: FDA recall information
- **patches**: Patch management and status
- **users**: User accounts and authentication
- **locations**: Physical locations and departments
- **device_mapping**: Asset-to-FDA device relationships
- **risk_priorities**: Risk calculation and prioritization
- **software_packages**: Software inventory and SBOM data
- **analytics**: System metrics and reporting data
- **sessions**: User session management
- **audit_logs**: System activity and change tracking
- **epss_data**: EPSS scores and vulnerability trends
- **kev_data**: CISA Known Exploited Vulnerabilities
- **risk_matrix**: Risk calculation configuration
- **api_keys**: API key management and authentication
- **security_settings**: Security configuration and policies
- **failed_logins**: Failed login attempt monitoring
- **incident_response**: Security incident tracking

### Database Administration

#### PostgreSQL Configuration
```sql
-- Database configuration
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
```

#### Database Maintenance
```sql
-- Regular maintenance tasks
VACUUM ANALYZE;
REINDEX DATABASE <database name>;

-- Check database size
SELECT pg_size_pretty(pg_database_size('<database name>'));

-- Check table sizes
SELECT schemaname,tablename,pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

#### Database Backup and Recovery
```bash
# Create backup
pg_dump -h localhost -U <database user> -d <database name> > backup_$(date +%Y%m%d_%H%M%S).sql

# Create compressed backup
pg_dump -h localhost -U <database user> -d <database name> | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz

# Restore backup
psql -h localhost -U <database user> -d <database name> < backup_file.sql

# Restore compressed backup
gunzip -c backup_file.sql.gz | psql -h localhost -U <database user> -d <database name>
```

### Performance Optimization

#### Database Indexing
```sql
-- Create indexes for frequently queried columns
CREATE INDEX idx_assets_status ON assets(status);
CREATE INDEX idx_assets_department ON assets(department);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_recalls_date ON recalls(recall_date);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Composite indexes
CREATE INDEX idx_assets_dept_status ON assets(department, status);
CREATE INDEX idx_vulnerabilities_severity_score ON vulnerabilities(severity, cvss_v3_score);
```

#### Query Optimization
```sql
-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM assets WHERE department = 'ICU' AND status = 'Active';

-- Update table statistics
ANALYZE assets;
ANALYZE vulnerabilities;
ANALYZE recalls;
```

## Background Services

### Cron-Based Task Management

The DAVE system uses cron jobs for automated background tasks instead of a persistent scheduler service. This approach is more reliable and doesn't require systemd service management.

#### Available Cron Jobs

**EPSS Sync** (Daily at 2:00 AM)
```bash
0 2 * * * /usr/bin/python3 /var/www/html/services/epss_sync_service.py >> /var/www/html/logs/epss_sync.log 2>&1
```

**KEV Sync** (Daily at 1:00 AM)
```bash
0 1 * * * /usr/bin/python3 /var/www/html/services/kev_sync_service.py >> /var/www/html/logs/kev_sync.log 2>&1
```

**Risk Priority Updates** (Daily at 2:00 AM)
```bash
0 2 * * * /usr/bin/python3 /var/www/html/services/risk_priority_service.py >> /var/www/html/logs/risk_priority_cron.log 2>&1
```

#### Manual Operations

**SBOM Processing** (Event-driven on upload)
- **Automatic**: Triggered immediately when SBOMs are uploaded
- **Manual**: Available via Admin → Manual Tasks → "Process SBOM Queue"

**Backup Operations** (Manual Only)
- **Full System Backups**: Available via Admin → Backup → "System Backup"
- **Database Backups**: Available via Admin → Backup → "Database Backup"
- **Configuration Backups**: Available via Admin → Backup → "Configuration Backup"

**Security Updates** (Manual Only)
- **System Package Updates**: Available via Admin → Manual Tasks → "System Update"
- **Application Updates**: Available via Admin → Manual Tasks → "Application Update"

#### Manual Task Management

Access the **Manual Tasks** page via Admin → Manual Tasks to run system maintenance tasks on-demand:

**Available Manual Tasks:**

1. **Recalculate Remediation Actions**
   - Creates missing remediation actions for vulnerabilities
   - Calculates urgency and efficiency scores for all actions
   - Recalculates device risk scores for all device-vulnerability links
   - Updates tier calculations based on new scores
   - **When to use**: After bulk vulnerability imports, system updates, or regular monitoring

2. **System Health Check**
   - Database connectivity verification
   - Disk space and memory monitoring
   - Service status checks (Apache, PostgreSQL)
   - Log file analysis for errors
   - Data integrity validation
   - **When to use**: Regular maintenance or troubleshooting

3. **Data Consistency Check**
   - Validates vulnerability counts across components
   - Verifies tier calculations
   - Checks device counts and mappings
   - Validates risk score calculations
   - **When to use**: After data imports or system changes

4. **Process SBOM Queue**
   - Processes any SBOMs that failed during upload
   - Retries stuck SBOM evaluations
   - Cleans up orphaned SBOMs
   - **When to use**: Troubleshooting SBOM processing issues

**Task Execution:**
- Tasks run in the background and show progress
- Results are displayed with success/error indicators
- Detailed logs are available for troubleshooting
- Some tasks may take several minutes to complete

#### Manual Service Operations
```bash
# Run specific tasks manually
cd /var/www/html
python3 python/services/background_scheduler.py --task monitor_recalls
python3 python/services/background_scheduler.py --task scan_vulnerabilities
python3 python/services/background_scheduler.py --task cleanup_data
python3 python/services/background_scheduler.py --task health_check
```

### Service Monitoring

#### Health Checks
- **Database Connectivity**: Verify database connections
- **External API Access**: Check FDA and NVD API access
- **File System Access**: Verify file system permissions
- **Memory Usage**: Monitor memory consumption
- **Disk Space**: Check available disk space

#### Service Logs
- **SBOM Processing Logs**: `/var/www/html/logs/sbom_evaluation.log`
- **EPSS Sync Logs**: `/var/www/html/logs/epss_sync.log`
- **KEV Sync Logs**: `/var/www/html/logs/kev_sync.log`
- **Risk Priority Logs**: `/var/www/html/logs/risk_priority_cron.log`
- **FDA Integration Logs**: `/var/www/html/logs/fda_integration.log`
- **NVD Integration Logs**: `/var/www/html/logs/nvd_integration.log`

## Monitoring and Logging

### System Monitoring

#### Resource Monitoring
```bash
# Check system resources
htop
df -h
free -h
iostat -x 1

# Check database connections
psql -h localhost -U <database user> -d <database name> -c "SELECT count(*) FROM pg_stat_activity;"

# Check web server status
sudo systemctl status apache2
sudo systemctl status nginx
```

#### Application Monitoring
- **Response Times**: Monitor API response times
- **Error Rates**: Track error rates and patterns
- **User Activity**: Monitor user activity patterns
- **Database Performance**: Track database performance metrics

### Log Management

#### Log Files
- **Application Logs**: `/var/www/html/logs/`
- **Web Server Logs**: `/var/log/apache2/` or `/var/log/nginx/`
- **Database Logs**: `/var/log/postgresql/`
- **System Logs**: `/var/log/syslog`

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

#### Log Analysis
```bash
# Analyze logs
tail -f /var/www/html/logs/application.log
grep "ERROR" /var/www/html/logs/application.log
grep "WARNING" /var/www/html/logs/application.log

# Monitor specific services
tail -f /var/www/html/logs/background_scheduler.log
tail -f /var/www/html/logs/recall_monitor.log
```

## Backup and Recovery

### Backup Strategy

#### Database Backups
```bash
# Daily database backup
#!/bin/bash
BACKUP_DIR="/var/backups/dave"
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump -h localhost -U <database user> <database name> | gzip > $BACKUP_DIR/db_backup_$DATE.sql.gz

# Keep backups for 30 days
find $BACKUP_DIR -name "db_backup_*.sql.gz" -mtime +30 -delete
```

#### File Backups
```bash
# Daily file backup
#!/bin/bash
BACKUP_DIR="/var/backups/dave"
DATE=$(date +%Y%m%d_%H%M%S)
tar -czf $BACKUP_DIR/files_backup_$DATE.tar.gz /var/www/html/uploads

# Keep backups for 30 days
find $BACKUP_DIR -name "files_backup_*.tar.gz" -mtime +30 -delete
```

#### Configuration Backups
```bash
# Backup configuration files
cp /var/www/html/config/config.php /var/backups/dave/config_backup_$(date +%Y%m%d).php
cp /var/www/html/config/database.php /var/backups/dave/database_backup_$(date +%Y%m%d).php
```

### Recovery Procedures

#### Database Recovery
```bash
# Stop services
sudo systemctl stop dave-scheduler
sudo systemctl stop apache2

# Restore database
gunzip -c /var/backups/dave/db_backup_20240101_120000.sql.gz | psql -h localhost -U <database user> -d <database name>

# Start services
sudo systemctl start apache2
sudo systemctl start dave-scheduler
```

#### File Recovery
```bash
# Stop services
sudo systemctl stop dave-scheduler

# Restore files
tar -xzf /var/backups/dave/files_backup_20240101_120000.tar.gz -C /

# Set permissions
sudo chown -R www-data:www-data /var/www/html/uploads
sudo chmod -R 755 /var/www/html/uploads

# Start services
sudo systemctl start dave-scheduler
```

## Performance Tuning

### Web Server Optimization

#### Apache Optimization
```apache
# Apache configuration
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/xml
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/x-javascript
</IfModule>

# Enable caching
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType image/png "access plus 1 month"
    ExpiresByType image/jpg "access plus 1 month"
    ExpiresByType image/jpeg "access plus 1 month"
</IfModule>
```

#### PHP Optimization
```ini
; php.ini optimization
memory_limit = 256M
max_execution_time = 300
max_input_time = 300
upload_max_filesize = 50M
post_max_size = 50M
max_file_uploads = 20

; OPcache settings
opcache.enable=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=4000
opcache.revalidate_freq=2
opcache.fast_shutdown=1
```

### Database Optimization

#### PostgreSQL Tuning
```sql
-- PostgreSQL configuration
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;
```

#### Query Optimization
```sql
-- Regular maintenance
VACUUM ANALYZE;
REINDEX DATABASE <database name>;

-- Update statistics
ANALYZE assets;
ANALYZE vulnerabilities;
ANALYZE recalls;
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

#### File Upload Issues
```bash
# Check upload directory permissions
ls -la /var/www/html/uploads

# Fix permissions
sudo chown -R www-data:www-data /var/www/html/uploads
sudo chmod -R 755 /var/www/html/uploads

# Check PHP upload settings
php -i | grep upload
```

#### Background Service Issues
```bash
# Check service status
sudo systemctl status dave-scheduler

# View service logs
sudo journalctl -u dave-scheduler -f

# Test service manually
cd /var/www/html
source venv/bin/activate
python python/services/background_scheduler.py --status
```

#### Performance Issues
```bash
# Check system resources
htop
df -h
free -h

# Check database performance
psql -h localhost -U <database user> -d <database name> -c "SELECT * FROM pg_stat_activity;"

# Check slow queries
psql -h localhost -U <database user> -d <database name> -c "SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"
```

### Diagnostic Tools

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
nslookup your-domain.com
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

## Maintenance Procedures

### Regular Maintenance Tasks

#### Daily Tasks
- **Check System Logs**: Review error logs and alerts
- **Monitor Resources**: Check CPU, memory, and disk usage
- **Verify Backups**: Ensure backups are running successfully
- **Check Services**: Verify all services are running

#### Weekly Tasks
- **Database Maintenance**: Run VACUUM and ANALYZE
- **Log Rotation**: Rotate and compress log files
- **Security Updates**: Check for and apply security updates
- **Performance Review**: Review system performance metrics

#### Monthly Tasks
- **Full System Backup**: Create complete system backup
- **Security Audit**: Review security logs and access patterns
- **Performance Optimization**: Analyze and optimize performance

#### Quarterly Tasks
- **Disaster Recovery Test**: Test backup and recovery procedures
- **Security Assessment**: Comprehensive security review
- **Capacity Planning**: Review and plan for capacity needs
- **Documentation Update**: Update system documentation

### Update Procedures

#### System Updates
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update application code
cd /var/www/html
git pull origin main

# Update Python dependencies
source venv/bin/activate
pip install -r requirements.txt

# Restart services
sudo systemctl restart apache2
sudo systemctl restart dave-scheduler
```

#### Database Updates
```bash
# Backup database before updates
pg_dump -h localhost -U <database user> -d <database name> > backup_before_update.sql

# Apply database updates
psql -h localhost -U <database user> -d <database name> -f database/updates/update_1.0.1.sql

# Verify update
psql -h localhost -U <database user> -d <database name> -c "SELECT version FROM system_info;"
```

### Emergency Procedures

#### System Recovery
1. **Assess Damage**: Determine extent of system issues
2. **Stop Services**: Stop all running services
3. **Restore Backups**: Restore from most recent backup
4. **Verify Data**: Ensure data integrity
5. **Restart Services**: Start services in correct order
6. **Test Functionality**: Verify system functionality

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
