# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */
# DAVE (Device Assessment and Vulnerability Exposure) Dockerfile
# Based on Ubuntu 24.04 LTS
# This Dockerfile performs all installation steps directly without relying on install.sh

FROM ubuntu:24.04

# Validate .env file exists and required variables are set
# This must be done early in the build process
COPY .env /tmp/.env.check
RUN set -e && \
    echo "Validating .env file..." && \
    if [ ! -f /tmp/.env.check ]; then \
        echo "ERROR: .env file not found!" && \
        echo "Please copy docs/env.example to .env and configure the following required settings:" && \
        echo "  - DB_HOST (database host)" && \
        echo "  - DB_PORT (database port)" && \
        echo "  - DB_NAME (database name)" && \
        echo "  - DB_USER (database user)" && \
        echo "  - DB_PASSWORD (database password)" && \
        echo "  - DAVE_ADMIN_USER (admin username)" && \
        echo "  - DAVE_ADMIN_DEFAULT_PASSWORD (admin password)" && \
        exit 1; \
    fi && \
    echo "Converting line endings (CRLF to LF) if needed..." && \
    sed -i 's/\r$//' /tmp/.env.check && \
    echo "Contents of .env file:" && \
    cat /tmp/.env.check && \
    echo "" && \
    echo "Sourcing .env file..." && \
    set -a && \
    . /tmp/.env.check && \
    set +a && \
    echo "Checking required variables..." && \
    MISSING_VARS="" && \
    [ -z "$DB_HOST" ] && MISSING_VARS="$MISSING_VARS DB_HOST" && echo "DB_HOST is empty or not set" || echo "DB_HOST=$DB_HOST" && \
    [ -z "$DB_PORT" ] && MISSING_VARS="$MISSING_VARS DB_PORT" && echo "DB_PORT is empty or not set" || echo "DB_PORT=$DB_PORT" && \
    [ -z "$DB_NAME" ] && MISSING_VARS="$MISSING_VARS DB_NAME" && echo "DB_NAME is empty or not set" || echo "DB_NAME=$DB_NAME" && \
    [ -z "$DB_USER" ] && MISSING_VARS="$MISSING_VARS DB_USER" && echo "DB_USER is empty or not set" || echo "DB_USER=$DB_USER" && \
    [ -z "$DB_PASSWORD" ] && MISSING_VARS="$MISSING_VARS DB_PASSWORD" && echo "DB_PASSWORD is empty or not set" || echo "DB_PASSWORD is set" && \
    [ -z "$DAVE_ADMIN_USER" ] && MISSING_VARS="$MISSING_VARS DAVE_ADMIN_USER" && echo "DAVE_ADMIN_USER is empty or not set" || echo "DAVE_ADMIN_USER=$DAVE_ADMIN_USER" && \
    [ -z "$DAVE_ADMIN_DEFAULT_PASSWORD" ] && MISSING_VARS="$MISSING_VARS DAVE_ADMIN_DEFAULT_PASSWORD" && echo "DAVE_ADMIN_DEFAULT_PASSWORD is empty or not set" || echo "DAVE_ADMIN_DEFAULT_PASSWORD is set" && \
    if [ -n "$MISSING_VARS" ]; then \
        echo "" && \
        echo "ERROR: The following required environment variables are not set in .env:" && \
        for var in $MISSING_VARS; do \
            echo "  - $var"; \
        done && \
        echo "" && \
        echo "Please edit .env and set all required configuration values." && \
        exit 1; \
    fi && \
    echo "" && \
    echo "=== .env validation passed - all required variables are set ===" && \
    rm /tmp/.env.check

# Set environment variables to avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    APACHE_RUN_USER=www-data \
    APACHE_RUN_GROUP=www-data \
    APACHE_LOG_DIR=/var/log/apache2 \
    APACHE_RUN_DIR=/var/run/apache2 \
    APACHE_LOCK_DIR=/var/lock/apache2 \
    APACHE_PID_FILE=/var/run/apache2/apache2.pid \
    _ROOT=/var/www/html

# Labels
LABEL maintainer="Siemens Healthineers" \
      version="1.0.0" \
      description="Device Assessment and Vulnerability Exposure (DAVE) - Medical Device Cybersecurity Platform"

# Configure timezone non-interactively
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

# Update package lists and install all required packages
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends \
    apache2 \
    postgresql \
    postgresql-contrib \
    php8.3 \
    php8.3-pgsql \
    php8.3-curl \
    php8.3-mbstring \
    php8.3-xml \
    php8.3-zip \
    php8.3-gd \
    php8.3-cli \
    libapache2-mod-php8.3 \
    python3 \
    python3-full \
    python3-pip \
    python3-venv \
    curl \
    wget \
    git \
    unzip \
    cron \
    supervisor \
    ca-certificates \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python packages using pip (more reliable than apt for Python packages)
RUN pip3 install --break-system-packages \
    pandas \
    matplotlib \
    seaborn \
    psycopg2-binary \
    requests

# Set up application directory
WORKDIR /var/www/html

# Copy application files
COPY . /var/www/html/

# Copy .env file for runtime use
COPY .env /var/www/html/.env

# Enable Apache modules
RUN a2enmod rewrite && \
    a2enmod headers && \
    a2enmod ssl && \
    a2enmod deflate && \
    a2enmod expires

# Configure Apache
RUN echo '<VirtualHost *:80>\n\
    ServerName dave.local\n\
    DocumentRoot /var/www/html\n\
    \n\
    <Directory /var/www/html>\n\
        AllowOverride All\n\
        Require all granted\n\
    </Directory>\n\
    \n\
    # Security headers\n\
    Header always set X-Content-Type-Options nosniff\n\
    Header always set X-Frame-Options DENY\n\
    Header always set X-XSS-Protection "1; mode=block"\n\
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"\n\
    \n\
    # Logging\n\
    ErrorLog ${APACHE_LOG_DIR}/dave_error.log\n\
    CustomLog ${APACHE_LOG_DIR}/dave_access.log combined\n\
</VirtualHost>\n\
' > /etc/apache2/sites-available/dave.conf && \
    a2ensite dave.conf && \
    a2dissite 000-default.conf

# Configure PHP
RUN echo '\n\
;  PHP Configuration\n\
memory_limit = 256M\n\
max_execution_time = 300\n\
max_input_time = 300\n\
upload_max_filesize = 50M\n\
post_max_size = 50M\n\
max_file_uploads = 20\n\
date.timezone = UTC\n\
\n\
; OPcache settings\n\
opcache.enable=1\n\
opcache.memory_consumption=128\n\
opcache.interned_strings_buffer=8\n\
opcache.max_accelerated_files=4000\n\
opcache.revalidate_freq=2\n\
opcache.fast_shutdown=1\n\
' >> /etc/php/8.3/apache2/php.ini

# Set up application directories
RUN mkdir -p /var/www/html/{logs,uploads,temp,cache} && \
    mkdir -p /var/www/html/uploads/{sbom,reports,assets,nmap,nessus,csv} && \
    touch /var/www/html/uploads/.gitkeep && \
    touch /var/www/html/logs/.gitkeep && \
    touch /var/www/html/temp/.gitkeep

# Create config/database.php from template if it doesn't exist
RUN if [ ! -f /var/www/html/config/database.php ] && [ -f /var/www/html/config/database.php.template ]; then \
        cp /var/www/html/config/database.php.template /var/www/html/config/database.php; \
    fi

# Note: Python packages are already installed system-wide via apt (python3-pandas, etc.)
# No need for virtual environment in Docker container

# Prepare PostgreSQL directory (initialization will happen at runtime)
RUN mkdir -p /var/lib/postgresql/16/main && \
    chown -R postgres:postgres /var/lib/postgresql && \
    chmod 700 /var/lib/postgresql/16/main && \
    rm -rf /var/lib/postgresql/16/main/* && \
    su - postgres -c "/usr/lib/postgresql/16/bin/initdb -D /var/lib/postgresql/16/main"

# Configure PostgreSQL to listen on all addresses (port will be set from .env at runtime)
RUN echo "listen_addresses = '*'" >> /etc/postgresql/16/main/postgresql.conf && \
    echo "host all all 0.0.0.0/0 md5" >> /etc/postgresql/16/main/pg_hba.conf && \
    echo "host all all ::0/0 md5" >> /etc/postgresql/16/main/pg_hba.conf

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html && \
    chmod 600 /var/www/html/config/*.php 2>/dev/null || true && \
    chmod 600 /var/www/html/.env 2>/dev/null || true

# Create supervisor configuration to manage multiple services
RUN mkdir -p /var/log/supervisor && \
    echo '[supervisord]\n\
nodaemon=true\n\
logfile=/var/log/supervisor/supervisord.log\n\
pidfile=/var/run/supervisord.pid\n\
\n\
[program:postgresql]\n\
command=/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main -c config_file=/etc/postgresql/16/main/postgresql.conf\n\
user=postgres\n\
autostart=true\n\
autorestart=true\n\
stderr_logfile=/var/log/postgresql/postgresql.err.log\n\
stdout_logfile=/var/log/postgresql/postgresql.out.log\n\
priority=1\n\
\n\
[program:apache2]\n\
command=/usr/sbin/apache2ctl -D FOREGROUND\n\
autostart=true\n\
autorestart=true\n\
stderr_logfile=/var/log/apache2/error.log\n\
stdout_logfile=/var/log/apache2/access.log\n\
priority=2\n\
\n\
[program:cron]\n\
command=/usr/sbin/cron -f\n\
autostart=true\n\
autorestart=true\n\
stderr_logfile=/var/log/cron.err.log\n\
stdout_logfile=/var/log/cron.out.log\n\
priority=3\n\
' > /etc/supervisor/conf.d/dave.conf

# Create startup script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
echo "Starting DAVE (Device Assessment and Vulnerability Exposure)..."\n\
\n\
# Load environment variables from .env\n\
if [ -f /var/www/html/.env ]; then\n\
    echo "Loading configuration from .env..."\n\
    set -a\n\
    . /var/www/html/.env\n\
    set +a\n\
else\n\
    echo "ERROR: .env file not found at /var/www/html/.env"\n\
    exit 1\n\
fi\n\
\n\
# Validate required environment variables\n\
MISSING_VARS=""\n\
[ -z "$DB_HOST" ] && MISSING_VARS="$MISSING_VARS DB_HOST"\n\
[ -z "$DB_PORT" ] && MISSING_VARS="$MISSING_VARS DB_PORT"\n\
[ -z "$DB_NAME" ] && MISSING_VARS="$MISSING_VARS DB_NAME"\n\
[ -z "$DB_USER" ] && MISSING_VARS="$MISSING_VARS DB_USER"\n\
[ -z "$DB_PASSWORD" ] && MISSING_VARS="$MISSING_VARS DB_PASSWORD"\n\
[ -z "$DAVE_ADMIN_USER" ] && MISSING_VARS="$MISSING_VARS DAVE_ADMIN_USER"\n\
[ -z "$DAVE_ADMIN_DEFAULT_PASSWORD" ] && MISSING_VARS="$MISSING_VARS DAVE_ADMIN_DEFAULT_PASSWORD"\n\
\n\
if [ -n "$MISSING_VARS" ]; then\n\
    echo "ERROR: The following required environment variables are not set in .env:"\n\
    for var in $MISSING_VARS; do\n\
        echo "  - $var"\n\
    done\n\
    exit 1\n\
fi\n\
\n\
echo "Environment variables loaded successfully"\n\
echo "Database: $DB_NAME on $DB_HOST:$DB_PORT"\n\
echo "Admin user: $DAVE_ADMIN_USER"\n\
\n\
# Ensure PostgreSQL data directory exists and is properly initialized\n\
if [ ! -f /var/lib/postgresql/16/main/PG_VERSION ]; then\n\
    echo "PostgreSQL data directory not found - initializing..."\n\
    mkdir -p /var/lib/postgresql/16/main\n\
    chown -R postgres:postgres /var/lib/postgresql\n\
    chmod 700 /var/lib/postgresql/16/main\n\
    su - postgres -c "/usr/lib/postgresql/16/bin/initdb -D /var/lib/postgresql/16/main"\n\
    \n\
    # Configure PostgreSQL\n\
    echo "port = $DB_PORT" >> /etc/postgresql/16/main/postgresql.conf\n\
    echo "listen_addresses = '"'"'*'"'"'" >> /etc/postgresql/16/main/postgresql.conf\n\
    echo "host all all 0.0.0.0/0 md5" >> /etc/postgresql/16/main/pg_hba.conf\n\
    echo "host all all ::0/0 md5" >> /etc/postgresql/16/main/pg_hba.conf\n\
fi\n\
\n\
# Ensure proper ownership\n\
chown -R postgres:postgres /var/lib/postgresql\n\
chmod 700 /var/lib/postgresql/16/main\n\
\n\
# Start PostgreSQL temporarily to set up database\n\
echo "Starting PostgreSQL for initial setup..."\n\
su - postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D /var/lib/postgresql/16/main -o '"'"'-c config_file=/etc/postgresql/16/main/postgresql.conf'"'"' -l /var/log/postgresql/postgresql.log start"\n\
\n\
# Wait for PostgreSQL to be ready\n\
echo "Waiting for PostgreSQL to be ready..."\n\
for i in {1..30}; do\n\
    if su - postgres -c "psql -c '"'"'SELECT 1'"'"' >/dev/null 2>&1"; then\n\
        echo "PostgreSQL is ready"\n\
        break\n\
    fi\n\
    echo "Waiting for PostgreSQL... ($i/30)"\n\
    sleep 1\n\
done\n\
\n\
# Configure PostgreSQL database and user using .env values\n\
echo "Configuring PostgreSQL database with credentials from .env..."\n\
su - postgres -c "psql -c \\"CREATE USER $DB_USER WITH PASSWORD '"'"'$DB_PASSWORD'"'"';\\" " 2>/dev/null || true\n\
su - postgres -c "psql -c \\"ALTER USER $DB_USER CREATEDB;\\" " 2>/dev/null || true\n\
su - postgres -c "psql -c \\"CREATE DATABASE $DB_NAME OWNER $DB_USER;\\" " 2>/dev/null || true\n\
su - postgres -c "psql -c \\"GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;\\" " 2>/dev/null || true\n\
su - postgres -c "psql -d $DB_NAME -c \\"CREATE EXTENSION IF NOT EXISTS uuid-ossp;\\" " 2>/dev/null || true\n\
\n\
# Run database schema if it exists\n\
if [ -f /var/www/html/database/schema-production.sql ]; then\n\
    echo "Installing database schema..."\n\
    PGPASSWORD=$DB_PASSWORD psql -h localhost -U $DB_USER -d $DB_NAME -f /var/www/html/database/schema-production.sql 2>/dev/null || true\n\
    echo "Database schema installed"\n\
fi\n\
\n\
# Create initial admin user with credentials from .env\n\
echo "Creating initial admin user from .env configuration..."\n\
# Generate bcrypt hash for admin password using PHP\n\
ADMIN_PASSWORD_HASH=$(php -r "echo password_hash('"'"'$DAVE_ADMIN_DEFAULT_PASSWORD'"'"', PASSWORD_BCRYPT);")\n\
\n\
if [ -z "$ADMIN_PASSWORD_HASH" ]; then\n\
    echo "ERROR: Failed to generate password hash for admin user"\n\
    exit 1\n\
fi\n\
\n\
PGPASSWORD=$DB_PASSWORD psql -h localhost -U $DB_USER -d $DB_NAME -c "\n\
INSERT INTO users (username, email, password_hash, role, mfa_secret, is_active, created_at) \n\
VALUES ('"'"'$DAVE_ADMIN_USER'"'"', '"'"'$DAVE_ADMIN_USER@dave.local'"'"', '"'"'$ADMIN_PASSWORD_HASH'"'"', '"'"'Admin'"'"', '"'"''"'"', true, NOW())\n\
ON CONFLICT (username) DO NOTHING;\n\
" 2>/dev/null || true\n\
\n\
echo "Admin user '"'"'$DAVE_ADMIN_USER'"'"' created successfully"\n\
\n\
# Stop PostgreSQL (supervisor will manage it)\n\
echo "Stopping PostgreSQL temporary instance..."\n\
su - postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D /var/lib/postgresql/16/main stop" || true\n\
sleep 2\n\
\n\
# Ensure Apache run directories exist\n\
mkdir -p /var/run/apache2 /var/lock/apache2\n\
\n\
# Start all services via supervisor\n\
echo "Starting services via supervisor..."\n\
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf\n\
' > /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose ports (PostgreSQL port configured via DB_PORT in .env at runtime)
EXPOSE 80 443 5432

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command (supervisor will handle services)
CMD []
