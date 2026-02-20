
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# DAVE Development Environment Setup

## File Permissions and User Groups

### Overview
The DAVE application runs under the `www-data` user (web server), but development work is typically done by a different user (e.g., `ubuntu`). To allow both users to read and write files, proper permissions and group membership must be configured.

### Quick Setup

Run the automated setup script:
```bash
sudo bash scripts/setup-permissions.sh
```

**Important:** After running this script, you must log out and log back in for group changes to take effect.

### Manual Setup

If you prefer to set up permissions manually:

#### 1. Add Your User to www-data Group
```bash
sudo usermod -a -G www-data $USER
```

#### 2. Set Proper Ownership
```bash
sudo chown -R www-data:www-data /var/www/html
```

#### 3. Set File Permissions
```bash
# Files: 664 (rw-rw-r--)
sudo find /var/www/html -type f -exec chmod 664 {} \;

# Directories: 775 (rwxrwxr-x)
sudo find /var/www/html -type d -exec chmod 775 {} \;
```

#### 4. Set Script Permissions
```bash
sudo chmod +x /var/www/html/scripts/*.sh
```

#### 5. Create Required Directories
```bash
# PHP sessions
sudo mkdir -p /tmp/php_sessions
sudo chmod 777 /tmp/php_sessions

# Application directories
sudo mkdir -p /var/www/html/{logs,uploads,temp,temp/cache}
sudo chmod 775 /var/www/html/{logs,uploads,temp,temp/cache}
sudo chown -R www-data:www-data /var/www/html/{logs,uploads,temp}
```

#### 6. Log Out and Log Back In
Group membership changes only take effect after logging out and back in:
```bash
# Check your groups (should include www-data after re-login)
groups
```

### Permission Explanation

#### Why These Permissions?

- **664 for files**: Owner and group can read/write, others can only read
- **775 for directories**: Owner and group can read/write/execute, others can read/execute
- **www-data:www-data ownership**: Web server needs to own files
- **www-data group membership**: Allows developers to edit files

#### File Permission Breakdown

```
-rw-rw-r-- (664)
│││ ││└ └─ Others: read
│││ └└───── Group (www-data): read, write
└└└─────── Owner (www-data): read, write
```

```
drwxrwxr-x (775)
│││ ││└ └─ Others: read, execute
│││ └└───── Group (www-data): read, write, execute
└└└─────── Owner (www-data): read, write, execute
```

### Common Issues

#### "Permission denied" when editing files
- **Cause**: User not in www-data group
- **Solution**: Run setup script and log out/in

#### "Permission denied" when web server writes files
- **Cause**: Files not owned by www-data or wrong permissions
- **Solution**: Run setup script to fix ownership

#### Changes not taking effect
- **Cause**: Group membership requires new login session
- **Solution**: Log out and log back in (not just open new terminal)

### Verifying Setup

Check that everything is configured correctly:

```bash
# 1. Check group membership (should include www-data)
groups

# 2. Check file ownership
ls -la /var/www/html/config/

# 3. Check file permissions
stat /var/www/html/config/database.php

# 4. Test file write access
touch /var/www/html/test-write.txt && rm /var/www/html/test-write.txt
```

### Git Configuration

Git may show file mode changes after permission updates. To avoid this:

```bash
# Tell git to ignore file mode changes
git config core.fileMode false
```

### CI/CD Considerations

In CI environments (GitHub Actions):
- Users typically have full permissions
- The setup script is not needed
- PHP sessions directory is created automatically

### Security Notes

- Never use `777` permissions except for specific cases (like `/tmp/php_sessions`)
- Keep `www-data` as the owner for security
- Group write permissions allow safe development without compromising security
- Production environments may have stricter permissions

### Troubleshooting

#### Problem: "Operation not permitted" errors
**Solution**: Run commands with `sudo`

#### Problem: Git showing permission changes
**Solution**: `git config core.fileMode false`

#### Problem: Web server can't write logs
**Solution**: Ensure logs directory is owned by www-data with 775 permissions

#### Problem: Sessions not working
**Solution**: Ensure `/tmp/php_sessions` exists with 777 permissions

---

For more information, see:
- [Installation Guide](INSTALLATION.md)
- [Deployment Guide](deployment-guide.md)
- [Security Best Practices](SECURITY.md)

