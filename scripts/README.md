# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# DAVE Deployment Scripts

This directory contains automated deployment and configuration scripts for the Device Assessment and Vulnerability Exposure (DAVE).

## Scripts Overview

### 1. Installation Script (`install.sh`)
**Purpose**: Complete system installation and configuration
**Usage**: `./scripts/install.sh`
**Features**:
- System package installation (Apache, PostgreSQL, PHP, Python)
- Database setup and schema creation
- Web server configuration
- Security configuration
- Background service setup
- Initial admin user creation

### 2. Backup Script (`backup.sh`)
**Purpose**: Automated backup of database, files, and configuration
**Usage**: 
- `./scripts/backup.sh` - Full backup
- `./scripts/backup.sh --database-only` - Database only
- `./scripts/backup.sh --files-only` - Application files only
- `./scripts/backup.sh --config-only` - Configuration only
- `./scripts/backup.sh --uploads-only` - Uploads only

**Features**:
- Database backup with compression
- File system backup
- Configuration backup
- Automatic cleanup of old backups
- Backup integrity verification
- Detailed backup reports

### 3. Restore Script (`restore.sh`)
**Purpose**: Automated restoration from backups
**Usage**:
- `./scripts/restore.sh --interactive` - Interactive mode
- `./scripts/restore.sh --file /path/to/backup --database` - Restore database
- `./scripts/restore.sh --file /path/to/backup --files` - Restore files
- `./scripts/restore.sh --file /path/to/backup --full` - Full restore

**Features**:
- Interactive backup selection
- Database restoration
- File system restoration
- Configuration restoration
- Service restart after restore
- Backup verification

### 4. Update Script (`update.sh`)
**Purpose**: System updates and maintenance
**Usage**:
- `./scripts/update.sh` - Full update
- `./scripts/update.sh --system-only` - System packages only
- `./scripts/update.sh --app-only` - Application code only
- `./scripts/update.sh --deps-only` - Dependencies only
- `./scripts/update.sh --db-only` - Database schema only

**Features**:
- System package updates
- Application code updates
- Python dependency updates
- Database schema migrations
- Configuration updates
- Service restart
- System health verification

### 5. Monitoring Script (`monitor.sh`)
**Purpose**: System health monitoring and alerting
**Usage**:
- `./scripts/monitor.sh` - Full monitoring
- `./scripts/monitor.sh --services-only` - Services only
- `./scripts/monitor.sh --resources-only` - System resources only
- `./scripts/monitor.sh --database-only` - Database only
- `./scripts/monitor.sh --report` - Generate report

**Features**:
- Service status monitoring
- Database connectivity checks
- Web server health checks
- System resource monitoring (CPU, memory, disk)
- Application log analysis
- Database performance monitoring
- SSL certificate monitoring
- Email alerting
- Detailed monitoring reports

### 6. Cron Setup Script (`setup-cron.sh`)
**Purpose**: Automated scheduling and maintenance
**Usage**:
- `./scripts/setup-cron.sh` - Full setup
- `./scripts/setup-cron.sh --cron-only` - Cron jobs only
- `./scripts/setup-cron.sh --timers-only` - Systemd timers only
- `./scripts/setup-cron.sh --email-only` - Email notifications only

**Features**:
- Automated backup scheduling
- System monitoring scheduling
- Log rotation configuration
- Maintenance task scheduling
- Email notification setup
- Systemd timer configuration

### 7. Production Deployment Script (`deploy-production.sh`)
**Purpose**: Comprehensive production deployment automation
**Usage**:
- `./scripts/deploy-production.sh` - Interactive mode (recommended)
- `./scripts/deploy-production.sh interactive` - Interactive with prompts
- `./scripts/deploy-production.sh automated` - Automated (minimal prompts)
- `./scripts/deploy-production.sh update-only` - Update existing installation

**Quick Deployment Wrappers**:
- `./scripts/deploy-production-quick.sh` - Quick automated deployment
- `./scripts/deploy-production-update.sh` - Update existing installation

**Features**:
- Pre-deployment system checks (disk, memory, dependencies)
- Environment configuration validation
- SSL certificate detection and setup prompts
- Automated backup creation
- Fresh installation or system updates
- Production configuration (debug mode, HTTPS, permissions)
- Database schema setup and migration
- Service configuration and startup
- Security hardening (file permissions, password checks)
- Comprehensive health checks
- Deployment summary and next steps

## Quick Start

### Production Deployment (Recommended)
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Interactive production deployment (recommended for first-time setup)
./scripts/deploy-production.sh

# Quick automated deployment
./scripts/deploy-production-quick.sh

# Update existing installation
./scripts/deploy-production-update.sh
```

### Manual Installation (Alternative)
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Run full installation
./scripts/install.sh

# Setup automated maintenance
./scripts/setup-cron.sh
```

### Daily Operations
```bash
# Check system health
./scripts/monitor.sh

# Create backup
./scripts/backup.sh

# Update system
./scripts/update.sh
```

### Emergency Recovery
```bash
# List available backups
./scripts/restore.sh --list

# Restore from backup
./scripts/restore.sh --interactive
```

## Configuration

### Backup Configuration
- **Backup Directory**: `/var/backups/dave`
- **Retention Period**: 30 days
- **Compression**: Gzip compression enabled
- **Verification**: Automatic integrity checks

### Monitoring Configuration
- **Log File**: `/var/www/html/logs/monitor.log`
- **Alert Email**: `admin@dave.local`
- **CPU Threshold**: 80%
- **Memory Threshold**: 85%
- **Disk Threshold**: 90%

### Cron Jobs
- **Daily Backup**: 2:00 AM
- **Weekly Full Backup**: Sunday 1:00 AM
- **Daily Monitoring**: 6:00 AM
- **Hourly Monitoring**: Every hour
- **Database Maintenance**: 1:00 AM daily
- **Service Health Check**: Every 15 minutes

## Security Considerations

### File Permissions
- Scripts are executable by owner only
- Configuration files are protected (600 permissions)
- Database credentials are secured

### Backup Security
- Backups are stored in protected directory
- Old backups are automatically cleaned up
- Backup integrity is verified

### Monitoring Security
- Sensitive information is not logged
- Alert emails are sent to configured addresses
- Log files are rotated regularly

## Troubleshooting

### Common Issues

#### Script Permission Denied
```bash
chmod +x scripts/*.sh
```

#### Database Connection Failed
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Test connection

PGPASSWORD=<database password> psql -h <database host/IP> -U <database login> -d <database name> -c "SELECT 1;"
```

#### Service Not Running
```bash
# Check service status
sudo systemctl status apache2
sudo systemctl status dave-scheduler

# Restart services
sudo systemctl restart apache2
sudo systemctl restart dave-scheduler
```

#### Backup Failed
```bash
# Check disk space
df -h

# Check backup directory permissions
ls -la /var/backups/dave
```

### Log Files
- **Installation**: Check terminal output
- **Backup**: `/var/www/html/logs/backup.log`
- **Monitoring**: `/var/www/html/logs/monitor.log`
- **Updates**: `/var/www/html/logs/update.log`
- **Maintenance**: `/var/www/html/logs/maintenance.log`

## Advanced Usage

### Custom Backup Schedule
```bash
# Edit cron jobs
sudo crontab -e

# Add custom backup schedule
0 3 * * * /var/www/html/scripts/backup.sh --type full
```

### Custom Monitoring
```bash
# Create custom monitoring script
cat > /var/www/html/scripts/custom-monitor.sh << 'EOF'
#!/bin/bash
# Custom monitoring script
./scripts/monitor.sh --type resources
EOF

chmod +x /var/www/html/scripts/custom-monitor.sh
```

### Email Configuration
```bash
# Configure email settings
sudo nano /etc/postfix/main.cf

# Test email
echo "Test message" | mail -s "Test" admin@dave.local
```

## Support

For issues with deployment scripts:

1. **Check Logs**: Review relevant log files
2. **Verify Permissions**: Ensure scripts are executable
3. **Test Manually**: Run individual commands
4. **Check Dependencies**: Verify required packages are installed
5. **Review Configuration**: Check configuration files

## Maintenance

### Regular Tasks
- **Daily**: Monitor system health
- **Weekly**: Review backup logs
- **Monthly**: Update system packages
- **Quarterly**: Review and update scripts

### Script Updates
- Scripts are version controlled
- Updates are applied via git pull
- Test scripts in development environment first
- Backup before applying updates

---

**Last Updated**: January 2024  
**Version**: 1.0.0  
**For Technical Support**: Contact your system administrator
