#!/bin/bash
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */
#
#  Monitoring Script
# System health monitoring and alerting

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_ROOT="/var/www/html"
LOG_FILE="$APP_ROOT/logs/monitor.log"
ALERT_EMAIL="admin@dave.local"
ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEMORY=85
ALERT_THRESHOLD_DISK=90

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$LOG_FILE"
}

# Send alert email
send_alert() {
    local subject="$1"
    local message="$2"
    
    if command -v mail &> /dev/null; then
        echo "$message" | mail -s "$subject" "$ALERT_EMAIL"
        info "Alert sent: $subject"
    else
        warning "Mail command not available, alert not sent"
    fi
}

# Check service status
check_services() {
    log "Checking service status..."
    
    local services=("apache2" "postgresql" "dave-scheduler")
    local failed_services=()
    
    for service in "${services[@]}"; do
        if sudo systemctl is-active --quiet "$service"; then
            info "$service: ✅ Running"
        else
            error "$service: ❌ Not running"
            failed_services+=("$service")
        fi
    done
    
    if [ ${#failed_services[@]} -gt 0 ]; then
        local message="The following services are not running: ${failed_services[*]}"
        send_alert " Service Alert" "$message"
    fi
}

# Check database connectivity
check_database() {
    log "Checking database connectivity..."
    
    # Check if .env file exists
    if [ ! -f "$APP_ROOT/.env" ]; then
        error ".env file not found!"
        error "Please copy docs/env.example to .env and configure the following required settings:"
        error "  - DB_HOST (database host)"
        error "  - DB_PORT (database port)"
        error "  - DB_NAME (database name)"
        error "  - DB_USER (database user)"
        error "  - DB_PASSWORD (database password)"
        error ""
        error "Example: cp docs/env.example .env"
        exit 1
    fi

    # Source .env file
    log "Loading database configuration from .env..."
    source "$APP_ROOT/.env"

    # Validate required environment variables
    MISSING_VARS=()
    [ -z "$DB_HOST" ] && MISSING_VARS+=("DB_HOST")
    [ -z "$DB_PORT" ] && MISSING_VARS+=("DB_PORT")
    [ -z "$DB_NAME" ] && MISSING_VARS+=("DB_NAME")
    [ -z "$DB_USER" ] && MISSING_VARS+=("DB_USER")
    [ -z "$DB_PASSWORD" ] && MISSING_VARS+=("DB_PASSWORD")

    if [ ${#MISSING_VARS[@]} -gt 0 ]; then
        error "The following required environment variables are not set in .env:"
        for var in "${MISSING_VARS[@]}"; do
            error "  - $var"
        done
        error ""
        error "Please edit .env and set all required database configuration values."
        exit 1
    fi

    if PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1;" > /dev/null 2>&1; then
        info "Database: ✅ Connected"
    else
        error "Database: ❌ Connection failed"
        send_alert " Database Alert" "Database connection failed. Please check PostgreSQL service."
    fi
}

# Check web server
check_web_server() {
    log "Checking web server..."
    
    local response_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/test.php 2>/dev/null || echo "000")
    
    if [ "$response_code" = "200" ]; then
        info "Web Server: ✅ Responding (HTTP $response_code)"
    else
        error "Web Server: ❌ Not responding (HTTP $response_code)"
        send_alert " Web Server Alert" "Web server is not responding properly. HTTP code: $response_code"
    fi
}

# Check disk usage
check_disk_usage() {
    log "Checking disk usage..."
    
    local disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    local disk_available=$(df -h / | awk 'NR==2 {print $4}')
    
    if [ "$disk_usage" -lt "$ALERT_THRESHOLD_DISK" ]; then
        info "Disk Usage: ✅ OK ($disk_usage% used, $disk_available available)"
    else
        warning "Disk Usage: ⚠️ High usage ($disk_usage% used, $disk_available available)"
        send_alert " Disk Usage Alert" "Disk usage is at $disk_usage%. Available space: $disk_available"
    fi
}

# Check memory usage
check_memory_usage() {
    log "Checking memory usage..."
    
    local memory_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    local memory_available=$(free -h | awk 'NR==2{print $7}')
    
    if [ "$memory_usage" -lt "$ALERT_THRESHOLD_MEMORY" ]; then
        info "Memory Usage: ✅ OK ($memory_usage% used, $memory_available available)"
    else
        warning "Memory Usage: ⚠️ High usage ($memory_usage% used, $memory_available available)"
        send_alert " Memory Usage Alert" "Memory usage is at $memory_usage%. Available memory: $memory_available"
    fi
}

# Check CPU usage
check_cpu_usage() {
    log "Checking CPU usage..."
    
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    local cpu_usage_int=$(echo "$cpu_usage" | cut -d. -f1)
    
    if [ "$cpu_usage_int" -lt "$ALERT_THRESHOLD_CPU" ]; then
        info "CPU Usage: ✅ OK ($cpu_usage% used)"
    else
        warning "CPU Usage: ⚠️ High usage ($cpu_usage% used)"
        send_alert " CPU Usage Alert" "CPU usage is at $cpu_usage%"
    fi
}

# Check application logs
check_application_logs() {
    log "Checking application logs..."
    
    local log_files=("$APP_ROOT/logs/dave.log" "$APP_ROOT/logs/background_scheduler.log" "$APP_ROOT/logs/recall_monitor.log")
    
    for log_file in "${log_files[@]}"; do
        if [ -f "$log_file" ]; then
            local error_count=$(grep -c "ERROR\|FATAL" "$log_file" 2>/dev/null || echo "0")
            if [ "$error_count" -gt 0 ]; then
                warning "Log file $log_file has $error_count errors"
                send_alert " Application Log Alert" "Log file $log_file contains $error_count errors. Please check the logs."
            else
                info "Log file $log_file: ✅ No errors"
            fi
        fi
    done
}

# Check database performance
check_database_performance() {
    log "Checking database performance..."
    
    # Check if .env file exists
    if [ ! -f "$APP_ROOT/.env" ]; then
        error ".env file not found!"
        error "Please copy docs/env.example to .env and configure the following required settings:"
        error "  - DB_HOST (database host)"
        error "  - DB_PORT (database port)"
        error "  - DB_NAME (database name)"
        error "  - DB_USER (database user)"
        error "  - DB_PASSWORD (database password)"
        error ""
        error "Example: cp docs/env.example .env"
        exit 1
    fi

    # Source .env file
    log "Loading database configuration from .env..."
    source "$APP_ROOT/.env"

    # Validate required environment variables
    MISSING_VARS=()
    [ -z "$DB_HOST" ] && MISSING_VARS+=("DB_HOST")
    [ -z "$DB_PORT" ] && MISSING_VARS+=("DB_PORT")
    [ -z "$DB_NAME" ] && MISSING_VARS+=("DB_NAME")
    [ -z "$DB_USER" ] && MISSING_VARS+=("DB_USER")
    [ -z "$DB_PASSWORD" ] && MISSING_VARS+=("DB_PASSWORD")

    if [ ${#MISSING_VARS[@]} -gt 0 ]; then
        error "The following required environment variables are not set in .env:"
        for var in "${MISSING_VARS[@]}"; do
            error "  - $var"
        done
        error ""
        error "Please edit .env and set all required database configuration values."
        exit 1
    fi
    # Check active connections
    local active_connections=$(PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -t -c "SELECT COUNT(*) FROM pg_stat_activity;" 2>/dev/null || echo "0")

    if [ "$active_connections" -lt 50 ]; then
        info "Database Connections: ✅ OK ($active_connections active)"
    else
        warning "Database Connections: ⚠️ High ($active_connections active)"
        send_alert " Database Performance Alert" "High number of active database connections: $active_connections"
    fi
    
    # Check database size
    local db_size=$(PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -t -c "SELECT pg_size_pretty(pg_database_size('$DB_NAME'));" 2>/dev/null || echo "Unknown")
    info "Database Size: $db_size"
}

# Check file permissions
check_file_permissions() {
    log "Checking file permissions..."
    
    local critical_files=(
        "$APP_ROOT/config/config.php"
        "$APP_ROOT/config/database.php"
        "$APP_ROOT/includes/auth.php"
    )
    
    for file in "${critical_files[@]}"; do
        if [ -f "$file" ]; then
            local permissions=$(stat -c "%a" "$file")
            if [ "$permissions" = "600" ] || [ "$permissions" = "644" ]; then
                info "File $file: ✅ Permissions OK ($permissions)"
            else
                warning "File $file: ⚠️ Permissions may be too open ($permissions)"
            fi
        fi
    done
}

# Check SSL certificate (if configured)
check_ssl_certificate() {
    log "Checking SSL certificate..."
    
    if command -v openssl &> /dev/null; then
        local cert_file="/etc/letsencrypt/live/dave.local/cert.pem"
        if [ -f "$cert_file" ]; then
            local cert_expiry=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
            local cert_expiry_epoch=$(date -d "$cert_expiry" +%s)
            local current_epoch=$(date +%s)
            local days_until_expiry=$(( (cert_expiry_epoch - current_epoch) / 86400 ))
            
            if [ "$days_until_expiry" -gt 30 ]; then
                info "SSL Certificate: ✅ Valid ($days_until_expiry days until expiry)"
            elif [ "$days_until_expiry" -gt 0 ]; then
                warning "SSL Certificate: ⚠️ Expires in $days_until_expiry days"
                send_alert " SSL Certificate Alert" "SSL certificate expires in $days_until_expiry days. Please renew."
            else
                error "SSL Certificate: ❌ Expired"
                send_alert " SSL Certificate Alert" "SSL certificate has expired. Please renew immediately."
            fi
        else
            info "SSL Certificate: ℹ️ Not configured"
        fi
    else
        info "SSL Certificate: ℹ️ OpenSSL not available"
    fi
}

# Generate monitoring report
generate_report() {
    log "Generating monitoring report..."
    
    local report_file="/tmp/dave_monitor_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
 System Monitoring Report
============================
Date: $(date)
Hostname: $(hostname)
Uptime: $(uptime -p)

System Information:
- OS: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")
- Kernel: $(uname -r)
- Architecture: $(uname -m)

Service Status:
EOF
    
    # Add service status
    local services=("apache2" "postgresql" "dave-scheduler")
    for service in "${services[@]}"; do
        if sudo systemctl is-active --quiet "$service"; then
            echo "- $service: Running" >> "$report_file"
        else
            echo "- $service: Not running" >> "$report_file"
        fi
    done
    
    # Add system resources
    echo "" >> "$report_file"
    echo "System Resources:" >> "$report_file"
    echo "- CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')" >> "$report_file"
    echo "- Memory Usage: $(free | awk 'NR==2{printf "%.0f", $3*100/$2}')%" >> "$report_file"
    echo "- Disk Usage: $(df -h / | awk 'NR==2 {print $5}')" >> "$report_file"
    
    # Add database info
    echo "" >> "$report_file"
    echo "Database Information:" >> "$report_file"

    
    # Check if .env file exists
    if [ ! -f "$APP_ROOT/.env" ]; then
        error ".env file not found!"
        error "Please copy docs/env.example to .env and configure the following required settings:"
        error "  - DB_HOST (database host)"
        error "  - DB_PORT (database port)"
        error "  - DB_NAME (database name)"
        error "  - DB_USER (database user)"
        error "  - DB_PASSWORD (database password)"
        error ""
        error "Example: cp docs/env.example .env"
        exit 1
    fi

    # Source .env file
    log "Loading database configuration from .env..."
    source "$APP_ROOT/.env"

    # Validate required environment variables
    MISSING_VARS=()
    [ -z "$DB_HOST" ] && MISSING_VARS+=("DB_HOST")
    [ -z "$DB_PORT" ] && MISSING_VARS+=("DB_PORT")
    [ -z "$DB_NAME" ] && MISSING_VARS+=("DB_NAME")
    [ -z "$DB_USER" ] && MISSING_VARS+=("DB_USER")
    [ -z "$DB_PASSWORD" ] && MISSING_VARS+=("DB_PASSWORD")

    if [ ${#MISSING_VARS[@]} -gt 0 ]; then
        error "The following required environment variables are not set in .env:"
        for var in "${MISSING_VARS[@]}"; do
            error "  - $var"
        done
        error ""
        error "Please edit .env and set all required database configuration values."
        exit 1
    fi


    if PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1;" > /dev/null 2>&1; then
        echo "- Status: Connected" >> "$report_file"
        echo "- Size: $(PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -t -c "SELECT pg_size_pretty(pg_database_size('$DB_NAME'));" 2>/dev/null || echo "Unknown")" >> "$report_file"
    else
        echo "- Status: Not connected" >> "$report_file"
    fi
    
    info "Monitoring report generated: $report_file"
}

# Main monitoring function
main() {
    log "Starting  monitoring..."
    
    # Parse command line arguments
    MONITOR_TYPE="full"
    GENERATE_REPORT=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)
                MONITOR_TYPE="$2"
                shift 2
                ;;
            --services-only)
                MONITOR_TYPE="services"
                shift
                ;;
            --resources-only)
                MONITOR_TYPE="resources"
                shift
                ;;
            --database-only)
                MONITOR_TYPE="database"
                shift
                ;;
            --logs-only)
                MONITOR_TYPE="logs"
                shift
                ;;
            --report)
                GENERATE_REPORT=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --type TYPE          Monitor type (full, services, resources, database, logs)"
                echo "  --services-only      Check services only"
                echo "  --resources-only     Check system resources only"
                echo "  --database-only      Check database only"
                echo "  --logs-only          Check logs only"
                echo "  --report             Generate monitoring report"
                echo "  --help               Show this help message"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
    
    # Perform monitoring based on type
    case $MONITOR_TYPE in
        "services")
            check_services
            check_database
            check_web_server
            ;;
        "resources")
            check_disk_usage
            check_memory_usage
            check_cpu_usage
            ;;
        "database")
            check_database
            check_database_performance
            ;;
        "logs")
            check_application_logs
            ;;
        "full")
            check_services
            check_database
            check_web_server
            check_disk_usage
            check_memory_usage
            check_cpu_usage
            check_application_logs
            check_database_performance
            check_file_permissions
            check_ssl_certificate
            ;;
        *)
            error "Invalid monitor type: $MONITOR_TYPE"
            ;;
    esac
    
    # Generate report if requested
    if [ "$GENERATE_REPORT" = true ]; then
        generate_report
    fi
    
    log "🎉 Monitoring completed successfully!"
    info "Monitor type: $MONITOR_TYPE"
    info "Log file: $LOG_FILE"
}

# Run main function
main "$@"
