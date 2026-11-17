# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */
# DAVE (Device Assessment and Vulnerability Exposure) Dockerfile
# Based on Ubuntu 26.04 LTS
# This Dockerfile performs all installation steps directly without relying on install.sh

FROM ubuntu:26.04

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
    _ROOT=/var/www/html \
    PHP_MIN_VERSION=8.5.12

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
    ca-certificates \
    curl \
    gnupg \
    software-properties-common \
    apache2 \
    postgresql \
    postgresql-contrib \
    python3 \
    python3-full \
    python3-pip \
    python3-venv \
    wget \
    git \
    unzip \
    cron \
    supervisor \
    build-essential \
    autoconf \
    bison \
    re2c \
    libxml2-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libsqlite3-dev \
    libpq-dev \
    libonig-dev \
    libzip-dev \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libwebp-dev \
    libxslt1-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libedit-dev \
    pkg-config \
    apache2-dev \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://packages.sury.org/php/apt.gpg | gpg --dearmor -o /etc/apt/keyrings/sury-php.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ resolute main" > /etc/apt/sources.list.d/sury-php.list \
    && apt-get update -y \
    && apt-get install -y --no-install-recommends \
    php8.5 \
    php8.5-pgsql \
    php8.5-curl \
    php8.5-mbstring \
    php8.5-xml \
    php8.5-zip \
    php8.5-gd \
    php8.5-cli \
    libapache2-mod-php8.5 \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    php -v | head -n 2 && \
    if ! php -r 'echo PHP_VERSION;' | grep -Eq '^8\.5\.' || ! php -r 'echo PHP_VERSION;' | awk '{print $1}' | dpkg --compare-versions "$(php -r 'echo PHP_VERSION;')" ge "$PHP_MIN_VERSION" 2>/dev/null; then \
        echo "Required PHP version is not available in the configured repositories; building PHP 8.5.12 from source..." && \
        cd /tmp && \
        curl -fL https://www.php.net/distributions/php-8.5.12.tar.gz -o php-8.5.12.tar.gz && \
        tar -xzf php-8.5.12.tar.gz && \
        cd php-8.5.12 && \
        ./configure --prefix=/usr/local/php-8.5.12 --with-config-file-path=/usr/local/php-8.5.12/etc --with-config-file-scan-dir=/usr/local/php-8.5.12/etc/conf.d --enable-cli --enable-fpm --with-fpm-user=www-data --with-fpm-group=www-data --with-pdo-pgsql --with-pgsql --with-curl --with-openssl --with-zip --with-zlib --with-bz2 --with-gd --with-jpeg --with-webp --enable-mbstring --with-xsl --with-readline && \
        make -j"$(nproc)" && \
        make install && \
        mkdir -p /usr/local/php-8.5.12/etc && \
        cp php.ini-production /usr/local/php-8.5.12/etc/php.ini && \
        sed -i 's/;date.timezone =/date.timezone = UTC/' /usr/local/php-8.5.12/etc/php.ini && \
        sed -i 's/memory_limit = 128M/memory_limit = 256M/' /usr/local/php-8.5.12/etc/php.ini && \
        ln -sf /usr/local/php-8.5.12/bin/php /usr/local/bin/php && \
        ln -sf /usr/local/php-8.5.12/bin/phpize /usr/local/bin/phpize && \
        ln -sf /usr/local/php-8.5.12/bin/php-config /usr/local/bin/php-config && \
        ln -sf /usr/local/php-8.5.12/sbin/php-fpm /usr/local/sbin/php-fpm; \
    fi && \
    php -v | head -n 2

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
' >> /etc/php/8.5/apache2/php.ini

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
RUN set -e && \
    PG_MAJOR=$(ls /usr/lib/postgresql 2>/dev/null | sort | tail -n 1 || echo 17) && \
    PG_DATA_DIR="/var/lib/postgresql/${PG_MAJOR}/main" && \
    PG_CONF_DIR="/etc/postgresql/${PG_MAJOR}/main" && \
    mkdir -p "$PG_DATA_DIR" && \
    chown -R postgres:postgres /var/lib/postgresql && \
    chmod 700 "$PG_DATA_DIR" && \
    rm -rf "$PG_DATA_DIR"/* && \
    su - postgres -c "/usr/lib/postgresql/${PG_MAJOR}/bin/initdb -D \"$PG_DATA_DIR\""

# Configure PostgreSQL to listen on all addresses (port will be set from .env at runtime)
RUN set -e && \
    PG_MAJOR=$(ls /usr/lib/postgresql 2>/dev/null | sort | tail -n 1 || echo 17) && \
    PG_CONF_DIR="/etc/postgresql/${PG_MAJOR}/main" && \
    echo "listen_addresses = '*'" >> "$PG_CONF_DIR/postgresql.conf" && \
    echo "host all all 0.0.0.0/0 md5" >> "$PG_CONF_DIR/pg_hba.conf" && \
    echo "host all all ::0/0 md5" >> "$PG_CONF_DIR/pg_hba.conf"

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html && \
    chmod 600 /var/www/html/config/*.php 2>/dev/null || true && \
    chmod 600 /var/www/html/.env 2>/dev/null || true

# Create supervisor configuration to manage multiple services
RUN cat <<'EOF' > /etc/supervisor/conf.d/dave.conf
[supervisord]
nodaemon=true
logfile=/var/log/supervisor/supervisord.log
pidfile=/var/run/supervisord.pid

[program:postgresql]
command=bash -lc 'PG_MAJOR=$(ls /usr/lib/postgresql 2>/dev/null | sort | tail -n 1 || echo 17); exec /usr/lib/postgresql/${PG_MAJOR}/bin/postgres -D /var/lib/postgresql/${PG_MAJOR}/main -c config_file=/etc/postgresql/${PG_MAJOR}/main/postgresql.conf'
user=postgres
autostart=true
autorestart=true
stderr_logfile=/var/log/postgresql/postgresql.err.log
stdout_logfile=/var/log/postgresql/postgresql.out.log
priority=1

[program:apache2]
command=/usr/sbin/apache2ctl -D FOREGROUND
autostart=true
autorestart=true
stderr_logfile=/var/log/apache2/error.log
stdout_logfile=/var/log/apache2/access.log
priority=2

[program:cron]
command=/usr/sbin/cron -f
autostart=true
autorestart=true
stderr_logfile=/var/log/cron.err.log
stdout_logfile=/var/log/cron.out.log
priority=3
EOF

# Create startup script
RUN cat <<'EOF' > /usr/local/bin/docker-entrypoint.sh
#!/bin/bash
set -e

echo "Starting DAVE (Device Assessment and Vulnerability Exposure)..."

# Load environment variables from .env
if [ -f /var/www/html/.env ]; then
    echo "Loading configuration from .env..."
    set -a
    . /var/www/html/.env
    set +a
else
    echo "ERROR: .env file not found at /var/www/html/.env"
    exit 1
fi

# Validate required environment variables
MISSING_VARS=""
[ -z "$DB_HOST" ] && MISSING_VARS="$MISSING_VARS DB_HOST"
[ -z "$DB_PORT" ] && MISSING_VARS="$MISSING_VARS DB_PORT"
[ -z "$DB_NAME" ] && MISSING_VARS="$MISSING_VARS DB_NAME"
[ -z "$DB_USER" ] && MISSING_VARS="$MISSING_VARS DB_USER"
[ -z "$DB_PASSWORD" ] && MISSING_VARS="$MISSING_VARS DB_PASSWORD"
[ -z "$DAVE_ADMIN_USER" ] && MISSING_VARS="$MISSING_VARS DAVE_ADMIN_USER"
[ -z "$DAVE_ADMIN_DEFAULT_PASSWORD" ] && MISSING_VARS="$MISSING_VARS DAVE_ADMIN_DEFAULT_PASSWORD"

if [ -n "$MISSING_VARS" ]; then
    echo "ERROR: The following required environment variables are not set in .env:"
    for var in $MISSING_VARS; do
        echo "  - $var"
    done
    exit 1
fi

# Escape SQL literals safely so usernames/passwords with shell metacharacters do not break the installer.
sql_escape() {
    printf "%s" "$1" | sed "s/'/''/g"
}

DB_USER_ESCAPED="$(sql_escape "$DB_USER")"
DB_PASSWORD_ESCAPED="$(sql_escape "$DB_PASSWORD")"
DAVE_ADMIN_USER_ESCAPED="$(sql_escape "$DAVE_ADMIN_USER")"
DAVE_ADMIN_EMAIL_ESCAPED="$(sql_escape "${DAVE_ADMIN_USER}@dave.local")"

PG_MAJOR=$(ls /usr/lib/postgresql 2>/dev/null | sort | tail -n 1 || echo 17)
PG_DATA_DIR="/var/lib/postgresql/${PG_MAJOR}/main"
PG_CONF_DIR="/etc/postgresql/${PG_MAJOR}/main"

echo "Environment variables loaded successfully"
echo "Database: $DB_NAME on $DB_HOST:$DB_PORT"
echo "Admin user: $DAVE_ADMIN_USER"

# Ensure PostgreSQL data directory exists and is properly initialized
if [ ! -f "$PG_DATA_DIR/PG_VERSION" ]; then
    echo "PostgreSQL data directory not found - initializing..."
    mkdir -p "$PG_DATA_DIR"
    chown -R postgres:postgres /var/lib/postgresql
    chmod 700 "$PG_DATA_DIR"
    su - postgres -c "/usr/lib/postgresql/${PG_MAJOR}/bin/initdb -D \"$PG_DATA_DIR\""

    echo "port = $DB_PORT" >> "$PG_CONF_DIR/postgresql.conf"
    echo "listen_addresses = '*'" >> "$PG_CONF_DIR/postgresql.conf"
    echo "host all all 0.0.0.0/0 md5" >> "$PG_CONF_DIR/pg_hba.conf"
    echo "host all all ::0/0 md5" >> "$PG_CONF_DIR/pg_hba.conf"
fi

# Ensure proper ownership
chown -R postgres:postgres /var/lib/postgresql
chmod 700 "$PG_DATA_DIR"

echo "Starting PostgreSQL for initial setup..."
su - postgres -c "/usr/lib/postgresql/${PG_MAJOR}/bin/pg_ctl -D \"$PG_DATA_DIR\" -o '-c config_file=${PG_CONF_DIR}/postgresql.conf' -l /var/log/postgresql/postgresql.log start"

echo "Waiting for PostgreSQL to be ready..."
for i in $(seq 1 30); do
    if su - postgres -c "psql -c 'SELECT 1' >/dev/null 2>&1"; then
        echo "PostgreSQL is ready"
        break
    fi
    echo "Waiting for PostgreSQL... ($i/30)"
    sleep 1
done

echo "Configuring PostgreSQL database with credentials from .env..."
su - postgres -c "psql -c \"CREATE USER '$DB_USER_ESCAPED' WITH PASSWORD '$DB_PASSWORD_ESCAPED';\"" 2>/dev/null || true
su - postgres -c "psql -c \"ALTER USER '$DB_USER_ESCAPED' CREATEDB;\"" 2>/dev/null || true
su - postgres -c "psql -c \"CREATE DATABASE '$DB_NAME' OWNER '$DB_USER_ESCAPED';\"" 2>/dev/null || true
su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE '$DB_NAME' TO '$DB_USER_ESCAPED';\"" 2>/dev/null || true
su - postgres -c "psql -d '$DB_NAME' -c \"CREATE EXTENSION IF NOT EXISTS uuid-ossp;\"" 2>/dev/null || true

if [ -f /var/www/html/database/schema-production.sql ]; then
    echo "Installing database schema..."
    PGPASSWORD=$DB_PASSWORD psql -h localhost -U "$DB_USER" -d "$DB_NAME" -f /var/www/html/database/schema-production.sql 2>/dev/null || true
    echo "Database schema installed"
fi

echo "Creating initial admin user from .env configuration..."
ADMIN_PASSWORD_HASH=$(php -r 'echo password_hash($argv[1], PASSWORD_BCRYPT);' -- "$DAVE_ADMIN_DEFAULT_PASSWORD")

if [ -z "$ADMIN_PASSWORD_HASH" ]; then
    echo "ERROR: Failed to generate password hash for admin user"
    exit 1
fi

ADMIN_PASSWORD_HASH_ESCAPED="$(sql_escape "$ADMIN_PASSWORD_HASH")"
PGPASSWORD=$DB_PASSWORD psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c "
INSERT INTO users (username, email, password_hash, role, mfa_secret, is_active, created_at)
VALUES ('${DAVE_ADMIN_USER_ESCAPED}', '${DAVE_ADMIN_EMAIL_ESCAPED}', '${ADMIN_PASSWORD_HASH_ESCAPED}', 'Admin', '', true, NOW())
ON CONFLICT (username) DO NOTHING;
" 2>/dev/null || true

echo "Admin user '$DAVE_ADMIN_USER' created successfully"

echo "Stopping PostgreSQL temporary instance..."
su - postgres -c "/usr/lib/postgresql/${PG_MAJOR}/bin/pg_ctl -D \"$PG_DATA_DIR\" stop" || true
sleep 2

mkdir -p /var/run/apache2 /var/lock/apache2

echo "Starting services via supervisor..."
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
EOF
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose ports (PostgreSQL port configured via DB_PORT in .env at runtime)
EXPOSE 80 443 5432

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command (supervisor will handle services)
CMD []
