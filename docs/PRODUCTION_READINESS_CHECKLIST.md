# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# DAVE Production Readiness Checklist

## 🔴 Critical Pre-Deployment Items

### 1. Security Configuration

#### HTTPS/SSL Setup
- [ ] **Enable HTTPS enforcement in `.htaccess`** (currently commented out)
  ```apache
  # Uncomment these lines in .htaccess:
  RewriteCond %{HTTPS} off
  RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
  ```
- [ ] **Install SSL certificate** (Let's Encrypt or commercial)
  ```bash
  sudo certbot --apache -d yourdomain.com
  ```
- [ ] **Verify SSL renewal** is configured
  ```bash
  sudo certbot renew --dry-run
  ```
- [ ] **Add HSTS header** (already in Apache config, verify it's active)

#### Application Security
- [ ] **Disable debug mode** - Set `DAVE_DEBUG = false` in `config/config.php`
- [ ] **Disable error display** - Verify `display_errors = 0` in production
- [ ] **Verify all security headers** are active:
  - X-Content-Type-Options: nosniff ✅
  - X-Frame-Options: DENY ✅
  - X-XSS-Protection: 1; mode=block ✅
  - Strict-Transport-Security ✅
- [ ] **Review password policies** (min length, complexity)
- [ ] **Audit API rate limiting** settings
- [ ] **Verify session security** (secure cookies, HTTP-only)

#### Database Security
- [ ] **Change default database passwords** 
- [ ] **Create production database user** with minimal privileges
- [ ] **Enable PostgreSQL SSL connections** if database is remote
- [ ] **Review database backup security** (encryption, access control)

### 2. Environment Configuration

#### Configuration Files
- [ ] **Create `.env.example`** template for users (currently missing)
- [ ] **Set production `.env` file** with actual values:
  - Database credentials
  - API keys (OpenFDA, NVD, MaxMind)
  - SMTP configuration
  - Base URL (HTTPS)
- [ ] **Verify `.env` file permissions** are 600 (not readable by others)
  ```bash
  chmod 600 .env
  ```
- [ ] **Set `DAVE_DEBUG=false`** in environment
- [ ] **Verify `config/database.php`** has correct production settings

#### API Keys
- [ ] **Configure OpenFDA API key** (if using FDA recall sync)
- [ ] **Configure NVD API key** (for vulnerability data)
- [ ] **Configure MaxMind credentials** (for GeoIP, if using)
- [ ] **Store API keys securely** (environment variables, not in code)

### 3. Error Handling & Logging

#### Error Configuration
- [ ] **Verify error logging** is enabled in production
- [ ] **Disable error display** to users
- [ ] **Set appropriate log levels** (`DAVE_LOG_LEVEL=ERROR` or `WARNING` for production)
- [ ] **Configure log rotation** (already implemented, verify working)

#### Monitoring Setup
- [ ] **Set up log monitoring** (file monitoring, log aggregation)
- [ ] **Configure error alerts** (email notifications for critical errors)
- [ ] **Test error logging** by triggering a test error
- [ ] **Verify log file permissions** (not world-readable)

### 4. Database & Backups

#### Database Setup
- [ ] **Verify schema-production.sql** is up-to-date
- [ ] **Test fresh installation** using `schema-production.sql`
- [ ] **Verify all migrations** are tracked in `schema_migrations` table
- [ ] **Test migration application** on a fresh database

#### Backup Configuration
- [ ] **Test backup script** (`scripts/backup.sh`)
  ```bash
  sudo bash scripts/backup.sh
  ```
- [ ] **Test backup restoration** process
- [ ] **Configure automated backups** (cron job)
  ```bash
  # Add to crontab:
  0 2 * * * /var/www/html/scripts/backup.sh
  ```
- [ ] **Verify backup retention** (30 days default)
- [ ] **Test off-site backup** (if configured)

### 5. Performance Optimization

#### PHP Configuration
- [ ] **Enable OPcache** (already configured in install.sh, verify active)
- [ ] **Verify PHP memory limits** (256M default, adjust if needed)
- [ ] **Review execution time limits** (300s default)
- [ ] **Optimize upload limits** if handling large files

#### Database Optimization
- [ ] **Review database indexes** (ensure proper indexing on foreign keys)
- [ ] **Run `ANALYZE` on tables** for query optimization
  ```sql
  ANALYZE;
  ```
- [ ] **Review slow query logs** (if enabled)
- [ ] **Verify connection pooling** settings

#### Application Optimization
- [ ] **Enable caching** (`DAVE_CACHE_ENABLED=true`)
- [ ] **Verify asset compression** (Apache mod_deflate enabled)
- [ ] **Minify CSS/JS** if not already done
- [ ] **Review CDN setup** (if using external assets)

### 6. Testing & Verification

#### Pre-Deployment Testing
- [ ] **Run all tests** and verify they pass
- [ ] **Test user authentication** (login, logout, session expiry)
- [ ] **Test all critical workflows**:
  - Device management
  - Vulnerability scanning
  - Patch scheduling
  - Task consolidation
  - Risk assessment
- [ ] **Verify API endpoints** respond correctly
- [ ] **Test error scenarios** (invalid input, missing data)

#### Post-Deployment Verification
- [ ] **Verify application loads** correctly
- [ ] **Test HTTPS redirect** works
- [ ] **Verify all pages** are accessible (with proper authentication)
- [ ] **Test database connections** are working
- [ ] **Verify external API integrations** (FDA, NVD)
- [ ] **Check log files** for errors or warnings

### 7. Documentation & Support

#### Documentation
- [ ] **Review production deployment guide** (`docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md`)
- [ ] **Create troubleshooting guide** for common issues
- [ ] **Document backup/restore procedures**
- [ ] **Create runbook** for operations team

#### Support Setup
- [ ] **Configure email notifications** for critical errors
- [ ] **Set up monitoring alerts** (server health, disk space, etc.)
- [ ] **Document escalation procedures**
- [ ] **Create support contact information**

### 8. Server Configuration

#### System Requirements
- [ ] **Verify system meets requirements**:
  - Ubuntu 18.04+ or Debian 10+
  - Minimum 2GB RAM
  - Minimum 10GB disk space
- [ ] **Check disk space** and plan for growth
- [ ] **Verify firewall rules** (80, 443, 22 open)

#### Service Configuration
- [ ] **Verify Apache is running** and enabled on boot
- [ ] **Verify PostgreSQL is running** and enabled on boot
- [ ] **Configure service auto-restart** on failure
- [ ] **Verify file permissions** are correct (755 for directories, 644 for files)

### 9. User Management

#### Initial Setup
- [ ] **Change default admin password** (created by install.sh)
- [ ] **Create production user accounts**
- [ ] **Set up role-based access** as needed
- [ ] **Configure MFA** for admin accounts (if available)

### 10. Compliance & Legal

#### Data Protection
- [ ] **Review HIPAA compliance** requirements
- [ ] **Verify data encryption** (at rest and in transit)
- [ ] **Review data retention** policies
- [ ] **Document data handling procedures**

## ✅ Already Implemented

The following items are already in place:

- ✅ Database schema system (schema-production.sql)
- ✅ Installation scripts (install.sh, update.sh)
- ✅ Migration system (apply-migrations.sh with tracking)
- ✅ Backup scripts (scripts/backup.sh)
- ✅ Logging system with rotation
- ✅ Security headers configuration
- ✅ Environment configuration system
- ✅ CI/CD pipeline (GitHub Actions)
- ✅ Error handling infrastructure
- ✅ Session security
- ✅ Input validation
- ✅ SQL injection protection (parameterized queries)

## 📋 Quick Production Setup Commands

### Enable HTTPS (after SSL certificate installed)
```bash
# Edit .htaccess
sudo nano /var/www/html/.htaccess
# Uncomment HTTPS redirect lines (lines 14-15)
```

### Disable Debug Mode
```bash
# Edit config/config.php
sudo nano /var/www/html/config/config.php
# Change: define('DAVE_DEBUG', false);
```

### Set Production Log Level
```bash
# In .env or config/config.php
DAVE_LOG_LEVEL=ERROR
```

### Test Backup
```bash
sudo bash /var/www/html/scripts/backup.sh
```

### Enable Automated Backups
```bash
sudo crontab -e
# Add:
0 2 * * * /var/www/html/scripts/backup.sh >> /var/log/dave-backup.log 2>&1
```

## 🚨 Critical Security Checklist

Before going live, ensure:

1. ✅ HTTPS is enforced
2. ✅ Debug mode is OFF
3. ✅ Default passwords are changed
4. ✅ API keys are configured and secure
5. ✅ File permissions are correct (600 for .env, 755 for directories)
6. ✅ Error display is disabled
7. ✅ Logging is enabled
8. ✅ Backups are configured and tested
9. ✅ Security headers are active
10. ✅ Database user has minimal privileges

## 📞 Support

For issues during deployment:
1. Check installation logs
2. Review Apache error logs: `/var/log/apache2/dave_error.log`
3. Review application logs: `/var/www/html/logs/dave.log`
4. Check database connection: `psql -h localhost -U <database login> -d <database name>`
5. Verify services: `systemctl status apache2 postgresql`

---
**Last Updated:** 2025-01-31
**Version:** 1.0.0




