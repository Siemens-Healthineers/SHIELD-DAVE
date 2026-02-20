# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# Database Migrations Directory

## Current Status

**⚠️ IMPORTANT: This directory is NOT in GitHub**

**For this development instance:**
- ✅ Use `schema-production.sql` for fresh installs (recommended)
- ⚠️ Migrations in this directory are **local files only** (not in Git)
- 📝 Migrations are kept locally for:
  - Development reference on dev server
  - Understanding database evolution
  - Local historical record

## When You'll Need Migrations

**In the future, when you have:**
- Production systems running
- Need to update existing databases incrementally
- Multiple environments (dev, staging, production)

**Then you'll use:**
- `scripts/apply-migrations.sh` to apply only new migrations
- Migration tracking to avoid applying changes twice

## Current Workflow

**For fresh installs (your current case):**
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
bash scripts/install.sh
# Uses schema-production.sql automatically
```

**When you add new database changes:**
1. Create new migration file (e.g., `031_new_feature.sql`)
2. Apply it to your dev database
3. Regenerate production schema:
   ```bash
   bash scripts/generate-production-schema.sh
   ```
4. Commit both the migration AND the updated schema-production.sql

## Summary

- **Migrations are kept** for future use and historical reference
- **Current installs use** `schema-production.sql` (simpler, faster)
- **No action needed** - everything works as-is for your single dev instance

