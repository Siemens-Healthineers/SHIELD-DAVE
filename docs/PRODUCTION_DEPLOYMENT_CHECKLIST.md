# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# DAVE Production Deployment Checklist

## Pre-Deployment Verification

### ✅ Database Setup
- [x] **Consolidated production schema** (`database/schema-production.sql`) - Single file with all changes ✅
- [x] Migration script (`scripts/apply-migrations.sh`) - For updates to existing installations ✅
- [x] Schema generator script (`scripts/generate-production-schema.sh`) - Regenerate consolidated schema ✅
- [x] Migration tracking table prevents duplicate applications
- [x] All views have proper GRANT permissions:
  - `scheduled_tasks_view` ✅
  - `downtime_calendar_view` ✅
  - `device_task_consolidation_view` ✅

**Fresh Install Strategy:**
- Uses `schema-production.sql` (single file, all migrations included) - **Fast & Simple** ✅

### ✅ Installation Script (`scripts/install.sh`)
- [x] Applies database schema first
- [x] Applies all migrations after schema
- [x] Installs Node.js and npm
- [x] Sets up Node.js dependencies
- [x] Sets up Python environment
- [x] Creates initial admin user
- [x] Sets proper file permissions

### ✅ Update Script (`scripts/update.sh`)
- [x] Uses migration script for ordered migrations
- [x] Has fallback to manual migration order
- [x] Handles migration failures gracefully

### ✅ CI/CD Pipeline (`.github/workflows/ci.yml`)
- [x] Creates test database
- [x] Applies schema
- [x] Uses migration script if available
- [x] Has fallback to manual migration order
- [x] Verifies database setup

## Database Schema System

### Two Approaches: Consolidated vs. Migrations

**For Fresh Production Installations (Recommended):**
- Use `database/schema-production.sql` - Single consolidated file with ALL database changes
- ✅ **Much faster** - One file vs. 52 migrations
- ✅ **Simpler** - No migration ordering issues
- ✅ **Production-ready** - Complete current database structure
- Generated from current database using: `scripts/generate-production-schema.sh`

**For Existing Installations (Updates):**
- Use `scripts/apply-migrations.sh` - Applies only new migrations
- ✅ Tracks which migrations are already applied
- ✅ Skips already-applied migrations
- ✅ Applies migrations in correct numerical order
- ✅ Ideal for incremental updates

### Schema Generation: `scripts/generate-production-schema.sh`
**Purpose:** Generate consolidated production schema from current database state

**Usage:**
```bash
bash scripts/generate-production-schema.sh [host] [user] [database] [password]
```

**When to regenerate:**
- After creating new migrations
- Before major release
- After significant schema changes

### Migration Script: `scripts/apply-migrations.sh`
**Features:**
- ✅ Applies migrations in correct numerical order
- ✅ Tracks applied migrations in `schema_migrations` table
- ✅ Skips already-applied migrations
- ✅ Provides detailed summary of applied/skipped/failed migrations
- ✅ Handles errors gracefully with detailed output

**Usage:**
```bash
bash scripts/apply-migrations.sh [host] [user] [database] [password]
```

**Default values:**
All default values need to be set by the user in the .env file before install

## Installation Process

### Fresh Installation
1. Run `scripts/install.sh` - This will:
   - Install all system dependencies (Apache, PostgreSQL, PHP 7.4, Python 3, Node.js, npm)
   - Set up database using **consolidated production schema** (if available)
   - OR use base schema + apply migrations (fallback)
   - Create initial admin user
   - Configure services and permissions

**Installation automatically chooses:**
1. **Preferred:** `schema-production.sql` (fast, single file, all changes included)
2. **Fallback:** `schema.sql` + apply migrations one by one

### Schema Files Explained

**`database/schema-production.sql`** (Recommended for fresh installs)
- Consolidated schema with ALL migrations applied
- Generated from current database state
- Single file, fast installation
- Includes migration tracking table with all migrations marked as applied

**`database/schema.sql`** (Base schema)
- Original base schema
- Used if production schema not available
- Requires applying 52+ migrations afterward

**`database/migrations/*.sql`** (Individual migrations)
- Historical record of database changes
- Used for incremental updates to existing installations
- Used when production schema is not available

### Migration Order (For Updates Only)
When using migrations (not production schema), they apply in numerical order:
1. `001_simplify_user_roles.sql`
2. `002_add_vulnerability_scans_table.sql`
3. ... (all migrations in order)
30. `030_exclude_completed_tasks_from_calendar.sql`

## Production Deployment Steps

### 1. System Requirements
- Ubuntu 18.04+ or Debian 10+
- Minimum 2GB RAM
- Minimum 10GB disk space
- Root or sudo access

### 2. Pre-Installation
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Clone repository
git clone https://github.com/socsoter/dave.git
cd dave
```

### 3. Installation
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
# Run installation script
sudo bash scripts/install.sh
```

### 4. Post-Installation Configuration
1. Access setup wizard: `http://your-server/setup.php`
2. Configure:
   - Base URL
   - Database credentials (if different from defaults)
   - Email settings
   - Other application settings

### 5. Verify Installation
```bash
# Check services
sudo systemctl status apache2
sudo systemctl status postgresql


# Check database
source .env
PGPASSWORD=$DB_PASSWORD psql -h localhost -U <database user> -d <database name> -c "SELECT COUNT(*) FROM schema_migrations;"

# Check migrations
PGPASSWORD=$DB_PASSWORD$ psql -h localhost -U <database user> -d <database name> -c "SELECT version FROM schema_migrations ORDER BY version;"
```

### 6. Update Existing Installation
```bash
# Run update script
sudo bash scripts/update.sh --db-only  # Database only
sudo bash scripts/update.sh --app-only # Application only
sudo bash scripts/update.sh --full     # Full update
```

## Known Issues and Solutions

### Issue: Migration Order Problems
**Solution:** Use `scripts/apply-migrations.sh` which ensures correct order

### Issue: Missing GRANT Permissions
**Solution:** Migrations 029 and 030 include proper GRANT statements

### Issue: Node.js Not Installed
**Solution:** Updated `install.sh` now includes Node.js and npm installation

## Verification Checklist

Before deploying to production, verify:

- [ ] All migrations are in `database/migrations/` directory
- [ ] Migration files are numbered sequentially
- [ ] `scripts/apply-migrations.sh` is executable
- [ ] `scripts/install.sh` includes migration application
- [ ] Node.js dependencies are installed
- [ ] All views have GRANT permissions
- [ ] CI/CD pipeline passes all tests
- [ ] Database schema is up-to-date
- [ ] Configuration files are properly secured (600 permissions)

## Support

For deployment issues, check:
1. Installation logs
2. Apache error logs: `/var/log/apache2/dave_error.log`
3. Database logs: PostgreSQL logs
4. Migration tracking: `SELECT * FROM schema_migrations;`

## Version History

- **2025-01-27**: Added migration script and updated install/update scripts
- **2025-01-27**: Added Node.js installation to install.sh
- **2025-01-27**: Added migration tracking system

