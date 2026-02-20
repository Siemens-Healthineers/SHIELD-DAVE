# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */
# Environment Configuration Guide

## Overview

The DAVE application now supports flexible environment configuration through environment variables. This allows you to easily configure the application for different environments (development, staging, production) without modifying code files.

## Environment Variables

### Core Application Settings

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DAVE_BASE_URL` | Main application URL | `http://localhost` | Yes |
| `DAVE_API_URL` | API endpoint URL | `{BASE_URL}/api` | No |
| `DAVE_ASSETS_URL` | Static assets URL | `{BASE_URL}/assets` | No |
| `DAVE_ENVIRONMENT` | Environment type | `development` | No |
| `DAVE_DEBUG` | Enable debug mode | `true` | No |

### Database Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DB_HOST` | Database host | `` | Yes |
| `DB_PORT` | Database port | `` | No |
| `DB_NAME` | Database name | `` | Yes |
| `DB_USER` | Database username | `` | Yes |
| `DB_PASSWORD` | Database password | `` | Yes |

### Email Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DAVE_SMTP_HOST` | SMTP server host | `localhost` | No |
| `DAVE_SMTP_PORT` | SMTP server port | `587` | No |
| `DAVE_SMTP_USERNAME` | SMTP username | `` | No |
| `DAVE_SMTP_PASSWORD` | SMTP password | `` | No |
| `DAVE_SMTP_ENCRYPTION` | Encryption type | `tls` | No |
| `DAVE_FROM_EMAIL` | From email address | `noreply@localhost` | No |
| `DAVE_FROM_NAME` | From name | `DAVE System` | No |

### Security Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DAVE_SESSION_DOMAIN` | Session cookie domain | Auto-detected | No |
| `DAVE_COOKIE_DOMAIN` | Application cookie domain | Auto-detected | No |
| `DAVE_SESSION_LIFETIME` | Session lifetime (seconds) | `3600` | No |
| `DAVE_MAX_LOGIN_ATTEMPTS` | Max login attempts | `5` | No |
| `DAVE_LOCKOUT_DURATION` | Lockout duration (seconds) | `900` | No |

### External API Keys

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `OPENFDA_API_KEY` | FDA API key | `` | No |
| `NVD_API_KEY` | NIST NVD API key | `` | No |
| `MAXMIND_API_KEY` | MaxMind GeoIP API key | `` | No |
| `MAXMIND_ACCOUNT_ID` | MaxMind Account ID | `` | No |

### File Upload Settings

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DAVE_MAX_UPLOAD_SIZE` | Max upload size (bytes) | `52428800` | No |
| `DAVE_UPLOAD_DIR` | Upload directory | `/var/www/html/uploads` | No |
| `DAVE_TEMP_DIR` | Temporary directory | `/var/www/html/temp` | No |

### Logging Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DAVE_LOG_LEVEL` | Log level | `INFO` | No |
| `DAVE_LOG_FILE` | Log file path | `/var/www/html/logs/dave.log` | No |
| `DAVE_LOG_MAX_SIZE` | Max log file size (bytes) | `10485760` | No |
| `DAVE_LOG_MAX_FILES` | Max number of log files | `5` | No |

### Cache Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DAVE_CACHE_ENABLED` | Enable caching | `true` | No |
| `DAVE_CACHE_DIR` | Cache directory | `/var/www/html/temp/cache` | No |
| `DAVE_CACHE_LIFETIME` | Cache lifetime (seconds) | `3600` | No |

## Quick Setup

### Web-Based Setup Wizard (Recommended)

The easiest way to configure DAVE is using the web-based setup wizard:

1. **Run Installation Script**
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

   ```bash
   cd /var/www/html
   sudo bash scripts/install.sh
   ```

2. **Access Setup Wizard**
   - Visit: `http://your-server-ip/setup.php`
   - Configure Base URL, database, and email settings
   - Complete setup automatically

3. **Access Application**
   - Login with default credentials: <admin user> / <admin password>
   - Change default password immediately

### Manual Configuration (Advanced)

If you prefer manual configuration or need to modify settings after setup:

## Configuration Methods

### 1. Environment File (.env)

Create a `.env` file in the application root directory:

```bash
# Core Application Settings
DAVE_BASE_URL=https://yourdomain.com
DAVE_ENVIRONMENT=production
DAVE_DEBUG=false

# Database Configuration
DB_HOST=your-db-host
DB_PORT=your-db-port_or_default_5432
DB_NAME=your-db-name
DB_USER=your-db-login
DB_PASSWORD=your-db-password

# Email Configuration
DAVE_SMTP_HOST=smtp.yourdomain.com
DAVE_SMTP_PORT=587
DAVE_SMTP_USERNAME=noreply@yourdomain.com
DAVE_SMTP_PASSWORD=your-smtp-password
DAVE_FROM_EMAIL=noreply@yourdomain.com
DAVE_FROM_NAME='Your Company Name'

# Security Configuration
DAVE_SESSION_DOMAIN=yourdomain.com
DAVE_COOKIE_DOMAIN=yourdomain.com

# External API Keys
OPENFDA_API_KEY=your-fda-api-key
NVD_API_KEY=your-nvd-api-key
MAXMIND_API_KEY=your-maxmind-api-key
MAXMIND_ACCOUNT_ID=your-maxmind-account-id
```

### 2. System Environment Variables

Set environment variables at the system level:

```bash
export DAVE_BASE_URL="https://yourdomain.com"
export DAVE_ENVIRONMENT="production"
export DAVE_DEBUG="false"
export DB_HOST="your-db-host"
export DB_PASSWORD="your-secure-password"
```

### 3. Web Server Configuration

#### Apache (.htaccess)
```apache
SetEnv DAVE_BASE_URL "https://yourdomain.com"
SetEnv DAVE_ENVIRONMENT "production"
SetEnv DAVE_DEBUG "false"
SetEnv DB_HOST "your-db-host"
SetEnv DB_PASSWORD "your-secure-password"
```

#### Nginx
```nginx
location / {
    fastcgi_param DAVE_BASE_URL "https://yourdomain.com";
    fastcgi_param DAVE_ENVIRONMENT "production";
    fastcgi_param DAVE_DEBUG "false";
    fastcgi_param DB_HOST "your-db-host";
    fastcgi_param DB_PASSWORD "your-secure-password";
}
```

## Configuration Management UI

### Web-Based Setup Wizard (Recommended)

The easiest way to configure DAVE is using the web-based setup wizard:

#### Access Setup Wizard
```
http://your-server-ip/setup.php
```

#### Features:
- **Beautiful UI**: Modern, responsive design with Siemens Healthineers branding
- **Real-time Validation**: Instant validation of Base URL and database connections
- **Auto-configuration**: Automatic API URL generation and environment setup
- **One-time Setup**: Prevents re-running after configuration is complete
- **Security**: Proper file permissions and secure configuration storage

#### Setup Wizard Configuration:
1. **Application Configuration**
   - Base URL (e.g., `https://dave.yourdomain.com`)
   - Debug mode settings
2. **Database Configuration**
   - Host, port, database name, username, password
   - Real-time connection testing
3. **Email Configuration** (Optional)
   - SMTP settings
   - From email and name
   - Encryption options

### Admin Configuration Interface

After initial setup, you can manage configuration through the admin interface:

```
https://yourdomain.com/pages/admin/system-config.php
```

#### Features:
- View current configuration
- Update environment variables
- Validate configuration
- Save to .env file
- Test database connections
- Auto-populate derived values

#### Access Requirements:
- Admin role required
- Authentication required

## API Configuration Management

The application provides REST API endpoints for configuration management:

### Get Configuration
```http
GET /api/v1/admin/environment-config.php
Authorization: Bearer {token}
```

### Update Configuration
```http
POST /api/v1/admin/environment-config.php
Content-Type: application/json
Authorization: Bearer {token}

{
    "base_url": "https://yourdomain.com",
    "environment": "production",
    "debug": false,
    "db_host": "your-db-host",
    "db_password": "your-secure-password"
}
```

### Validate Configuration
```http
PUT /api/v1/admin/environment-config.php
Content-Type: application/json
Authorization: Bearer {token}

{
    "db_host": "your-db-host",
    "db_name": "your-db-name",
    "db_user": "your-db-login",
    "db_password": "your-db-password"
}
```

## Environment-Specific Configurations

### Development Environment
```bash
DAVE_BASE_URL=http://localhost
DAVE_ENVIRONMENT=development
DAVE_DEBUG=true
DB_HOST=localhost
```

### Staging Environment
```bash
DAVE_BASE_URL=https://staging.yourdomain.com
DAVE_ENVIRONMENT=staging
DAVE_DEBUG=false
DB_HOST=staging-db-host
```

### Production Environment
```bash
DAVE_BASE_URL=https://yourdomain.com
DAVE_ENVIRONMENT=production
DAVE_DEBUG=false
DB_HOST=production-db-host
```

## Security Considerations

### 1. Environment File Security
- Ensure `.env` files are not accessible via web server
- Add `.env` to `.gitignore` to prevent committing sensitive data
- Use appropriate file permissions (600 or 640)

### 2. Database Credentials
- Use strong, unique passwords
- Consider using database connection pooling
- Regularly rotate credentials

### 3. API Keys
- Store API keys securely
- Use environment-specific keys when possible
- Monitor API key usage

### 4. Session Security
- Set appropriate session domains
- Use HTTPS in production
- Configure secure cookie settings

## Troubleshooting

### Common Issues

#### 1. Configuration Not Loading
- Check file permissions on `.env` file
- Verify environment variable syntax
- Ensure no spaces around `=` in `.env` file

#### 2. Database Connection Failed
- Verify database credentials
- Check network connectivity
- Ensure database server is running

#### 3. URL Issues
- Verify `DAVE_BASE_URL` format
- Check for trailing slashes
- Ensure HTTPS/HTTP consistency

#### 4. Email Not Working
- Verify SMTP credentials
- Check firewall settings
- Test SMTP connection

### Debug Mode

Enable debug mode to get detailed error information:

```bash
DAVE_DEBUG=true
DAVE_LOG_LEVEL=DEBUG
```

**Note:** Disable debug mode in production environments.

## Migration from Hardcoded Values

If you're upgrading from a version with hardcoded configuration:

1. **Backup current configuration**
2. **Create `.env` file** with current values
3. **Test configuration** using the management UI
4. **Update deployment scripts** to use environment variables
5. **Remove hardcoded values** from configuration files

## Best Practices

1. **Use environment-specific configurations**
2. **Never commit sensitive data** to version control
3. **Use strong, unique passwords**
4. **Regularly rotate credentials**
5. **Monitor configuration changes**
6. **Test configuration changes** in staging first
7. **Document environment-specific settings**
8. **Use configuration validation** before deployment

## Support

For additional support with environment configuration:

1. Check the application logs: `/var/www/html/logs/dave.log`
2. Use the configuration validation API
3. Review the troubleshooting section
4. Contact your system administrator

---

**Last Updated:** 2025-08-15  
**Version:** 1.0.0

