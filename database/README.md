# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# DAVE Database Schema Files

## Overview

This directory contains the database schema files for the Device Assessment and Vulnerability Exposure (DAVE).

## Schema File

### `schema-production.sql`
- **Purpose:** Complete production-ready database schema
- **Contains:** All database structure, tables, indexes, functions, and constraints
- **Size:** ~200KB, ~4100+ lines
- **Usage:** Single file installation - fast and simple
- **Generation:** Auto-generated from current database using `scripts/generate-production-schema.sh`

**Benefits:**
- ✅ One comprehensive file for complete database setup
- ✅ Fast installation (seconds vs minutes)
- ✅ No ordering issues
- ✅ Represents complete current database state

## Installation

### Fresh Production Installation
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
# Install script automatically uses schema-production.sql
bash scripts/install.sh
```

The install script:
1. Uses `schema-production.sql` (required)
2. Creates all tables, indexes, functions, and constraints
3. Fast installation with consolidated schema

## Regenerating Production Schema

When you make database changes, regenerate the production schema:

```bash
# Generate from current database
bash scripts/generate-production-schema.sh [host] [user] [database] [password]

# Default values:
bash scripts/generate-production-schema.sh <database host/IP> <database login> <database name> <database password>
```

**Important:** 
- Regenerate after making any database changes
- Regenerate before major releases
- Review generated schema before committing

## Best Practices

1. **Fresh Install:** Always use `schema-production.sql` ✅
2. **Regenerate:** Run schema generator after any database changes ✅
3. **Version Control:** Commit updated schema-production.sql after changes ✅

## File Structure

```
database/
├── schema-production.sql    # Complete production database schema
└── README.md                # This file
```

## Questions?

**Q: How do I set up a fresh database?**
A: Run `bash scripts/install.sh` which uses `schema-production.sql`.

**Q: How do I update the schema file?**
A: After making database changes, run `scripts/generate-production-schema.sh` to regenerate the schema file.

