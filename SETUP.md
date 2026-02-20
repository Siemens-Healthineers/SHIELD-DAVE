
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# DAVE Setup Guide

## Fresh Installation Process

### 1. Run the Installation Script

   - Create the folder /var/www/html if it doesnt exist and copy the contents of c01-csms into the html folder. 
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

This will:
- Install all required packages (Apache, PostgreSQL, PHP, Python)
- Set up the database and create default admin user
- Configure file permissions
- Set up background services

### 2. Complete Initial Configuration

After the installation script completes, you'll see instructions to access the setup wizard:

```
Next Steps:
1. Access the setup wizard at: http://your-server-ip/setup.php
   or: http://localhost/setup.php

2. Configure your Base URL and other settings
3. Complete the setup process
4. Access your DAVE application
```

### 3. Setup Wizard Configuration

Visit `http://your-server-ip/setup.php` and configure:

#### Application Configuration
- **Base URL**: The main URL where DAVE will be accessible (e.g., `https://yourdomain.com`)
- **Debug Mode**: Enable for development, disable for production

#### Database Configuration
Copy docs/env.example to .env in the main folder and enter your credentials for admin user and database 
- **Host**: Database server (usually `localhost`)
- **Port**: Database port (usually `5432`)
- **Database Name**: `dave_db` (default)
- **Username**: (enter configured database user in .env)
- **Password**: (enter configured database password in .env)

#### Email Configuration (Optional)
- **SMTP Host**: Your email server
- **SMTP Port**: Usually `587` for TLS
- **SMTP Username**: Your email username
- **SMTP Password**: Your email password
- **SMTP Encryption**: TLS, SSL, or None
- **From Email**: Sender email address
- **From Name**: Sender display name

### 4. Access the Application

After completing the setup wizard, you can access DAVE at your configured Base URL.

**Default Admin Credentials:**
- Username: (enter configured admin user in .env)
- Password: (enter configured admin password in .env)

⚠️ **Important**: Change the default password immediately after first login!

## Manual Configuration (Alternative)

If you prefer to configure manually instead of using the setup wizard:

### 1. Create Configuration File

```bash
# Create settings.json
sudo nano /var/www/html/config/settings.json
```

```json
{
    "app": {
        "name": "Device Assessment and Vulnerability Exposure",
        "base_url": "https://yourdomain.com",
        "api_url": "https://yourdomain.com/api",
        "debug": false
    },
    "database": {
        "host": "<database host name/ IP>",
        "port": "<database port>",
        "name": "<database name>",
        "user": "<database login>",
        "password": "<database password>"
    },
    "security": {
        "session_lifetime": 3600,
        "max_login_attempts": 5,
        "lockout_duration": 900
    },
    "email": {
        "smtp_host": "localhost",
        "smtp_port": "587",
        "smtp_username": "",
        "smtp_password": "",
        "smtp_encryption": "tls",
        "from_email": "noreply@yourdomain.com",
        "from_name": "DAVE System"
    }
}
```

### 2. Create Environment File

```bash
# Create .env file
sudo nano /var/www/html/.env
```

```env
# DAVE Environment Configuration
DAVE_BASE_URL=https://yourdomain.com
DAVE_API_URL=https://yourdomain.com/api
DAVE_ADMIN_USER=<Enter admin user>
DAVE_ADMIN_DEFAULT_PASSWORD=<Enter default admin password>
DAVE_DEBUG=false

# Database Configuration
DB_HOST=<database hostname/IP>
DB_PORT=<database port>
DB_NAME=<database name>
DB_USER=<database login>
DB_PASSWORD=<database password>

# Email Configuration
DAVE_SMTP_HOST=localhost
DAVE_SMTP_PORT=587
DAVE_SMTP_USERNAME=
DAVE_SMTP_PASSWORD=
DAVE_SMTP_ENCRYPTION=tls
DAVE_FROM_EMAIL=noreply@yourdomain.com
DAVE_FROM_NAME='DAVE System'


# Cynerio API Credentials
CYNERIO_CLIENT_ID=<Cynerio client ID>
CYNERIO_CLIENT_SECRET=<Cynerio client secret>

# Cynerio API Endpoints
CYNERIO_ENDPOINT=<Cynerio endpoint>
CYNERIO_AUTH_ENDPOINT=<Cynerio Auth endpoint>
```

### 3. Set Proper Permissions

```bash
sudo chown www-data:www-data /var/www/html/config/settings.json
sudo chown www-data:www-data /var/www/html/.env
sudo chmod 600 /var/www/html/config/settings.json
sudo chmod 600 /var/www/html/.env
```

## Troubleshooting

### Setup Wizard Not Accessible

1. Check if Apache is running:
   ```bash
   sudo systemctl status apache2
   ```

2. Check if setup.php exists:
   ```bash
   ls -la /var/www/html/setup.php
   ```

3. Check Apache error logs:
   ```bash
   sudo tail -f /var/log/apache2/error.log
   ```

### Database Connection Issues

1. Check PostgreSQL status:
   ```bash
   sudo systemctl status postgresql
   ```

2. Test database connection:
   ```bash
   PGPASSWORD=<database password> psql -h <database host/IP> -U <database login> -d <database name> -c "SELECT 1;"
   ```

3. Check database credentials in configuration files

### Permission Issues

1. Fix file ownership:
   ```bash
   sudo chown -R www-data:www-data /var/www/html
   ```

2. Fix file permissions:
   ```bash
   sudo chmod -R 755 /var/www/html
   sudo chmod 600 /var/www/html/config/settings.json
   sudo chmod 600 /var/www/html/.env
   ```

## Security Considerations

1. **Change Default Passwords**: Update admin password and database credentials
2. **Use HTTPS**: Configure SSL certificate for production
3. **Firewall**: Restrict access to necessary ports only
4. **Regular Updates**: Keep system and application updated
5. **Backup**: Regular database and file backups

## Support

For additional help, check:
- Documentation: `/var/www/html/docs/`
- Logs: `/var/www/html/logs/`
- Configuration: `/var/www/html/config/`
