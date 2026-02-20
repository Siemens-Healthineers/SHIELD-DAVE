
# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# Device Assessment and Vulnerability Exposure (DAVE)

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/your-org/dave)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/PHP-8.0+-green.svg)](https://php.net)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-13+-blue.svg)](https://postgresql.org)

## 🏥 Overview

The **Device Assessment and Vulnerability Exposure (DAVE)** is a comprehensive platform designed to manage medical device cybersecurity, FDA compliance, and vulnerability tracking for healthcare organizations. DAVE provides asset monitoring, and risk assessment capabilities.

## Key Features

- **Medical Device Security Management** - Comprehensive asset tracking and vulnerability management
- **FDA Compliance Monitoring** - Automated recall monitoring and device mapping
- **Vulnerability Assessment** - SBOM processing and CVE tracking
- **Risk Prioritization** - Risk scoring and remediation planning
- **Compliance Reporting** - Automated compliance reports and dashboards
- **Enterprise Security** - Role-based access control and audit logging
- **Web-Based Setup** - Easy installation with guided setup wizard

## Quick Start

### Fresh Installation

1. **Run the Installation Script**
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
   bash scripts/install.sh
   ```

2. **Complete Setup Wizard**
   - Visit `http://your-server-ip/setup.php`
   - Configure your Base URL and database settings
   - Set up email configuration (optional)
   - Complete the setup process

3. **Access Your Application**
   - Login with default credentials: <admin user> / <admin password>
   - Change the default password immediately
   - Start managing your medical devices

### Credentials

**Important**: Create .env with your credentials before install!

## Documentation

### Installation & Setup
- **[Setup Guide](SETUP.md)** - Complete installation and configuration guide
- **[Deployment Guide](docs/deployment-guide.md)** - Production deployment instructions
- **[Environment Configuration](docs/ENVIRONMENT_CONFIGURATION.md)** - Configuration management

### User Guides
- **[Quick Start Guide](docs/quick-start.md)** - Get started with DAVE
- **[User Guide](docs/user-guide.md)** - Complete user documentation
- **[Administrator Guide](docs/administrator-guide.md)** - System administration

### Technical Documentation
- **[API Documentation](docs/api-fields-reference.md)** - REST API reference
- **[Development Setup](docs/DEVELOPMENT-SETUP.md)** - Development environment setup
- **[Security Guide](docs/admin-security-guide.md)** - Security best practices

## System Architecture

### Technology Stack
- **Frontend**: PHP 7.4+ (8.0+ recommended), HTML5, CSS3, JavaScript (ES6+)
- **Backend**: Python 3.8+ (3.9+ recommended), PHP 7.4+ (8.0+ recommended)
- **Database**: PostgreSQL 13+ (14+ recommended)
- **Web Server**: Apache 2.4+ or Nginx 1.18+
- **OS**: Linux (Ubuntu 22.04 LTS or later recommended)

### Core Components
- **Web Interface** - PHP-based user interface with Siemens Healthineers branding
- **API Layer** - RESTful APIs for data access and integration
- **Background Services** - Python services for automation and monitoring
- **Database Layer** - PostgreSQL for data persistence and analytics
- **File Storage** - Local file system for uploads and reports

## System Requirements

### Production Requirements
- **CPU**: 2 cores, 2.0 GHz (4 cores, 3.0 GHz recommended)
- **RAM**: 4 GB (8 GB recommended)
- **Storage**: 50 GB SSD (100 GB SSD recommended)
- **Network**: 100 Mbps (1 Gbps recommended)
- **OS**: Ubuntu 22.04 LTS or later (recommended)
- **Web Server**: Apache 2.4+ or Nginx 1.18+
- **PHP**: 7.4+ (8.0+ recommended) with required extensions
- **PostgreSQL**: 13+ (14+ recommended)
- **Python**: 3.8+ (3.9+ recommended) for background services

### Development/Testing Requirements (Optional)
- Additional development tools (Composer, PHPUnit, etc.)

## Installation Methods

### 1. Automated Installation (Recommended)
```bash
# Clone or extract application files
cd /var/www/html

# Run installation script
sudo bash scripts/install.sh

# Complete setup wizard
# Visit: http://your-server-ip/setup.php
```

### 2. Manual Installation
See [Deployment Guide](docs/deployment-guide.md) for detailed manual installation steps.


## Web-Based Setup Wizard

The DAVE setup wizard provides an intuitive, web-based configuration interface:

### Features
- **Beautiful UI** - Modern, responsive design with Siemens Healthineers branding
- **Real-time Validation** - Instant validation of Base URL and database connections
- **Auto-configuration** - Automatic API URL generation and environment setup
- **Email Setup** - Optional SMTP configuration for notifications
- **Security** - One-time setup with proper file permissions

### Access Setup Wizard
After running the installation script, access the setup wizard at:
- `http://your-server-ip/setup.php`
- `http://localhost/setup.php`

## Security Features

- **Role-Based Access Control** - Granular permissions and user roles
- **Multi-Factor Authentication** - TOTP support for enhanced security
- **Audit Logging** - Comprehensive activity tracking and compliance
- **Data Encryption** - Encryption at rest and in transit
- **Session Management** - Secure session handling and timeout
- **Password Policies** - Enforced password complexity and rotation

## Key Capabilities

### Asset Management
- Medical device inventory tracking
- Network device discovery
- Asset lifecycle management
- Compliance status monitoring

### Vulnerability Management
- SBOM processing and analysis
- CVE tracking and scoring
- Risk assessment and prioritization
- Remediation planning and tracking

### FDA Compliance
- Device mapping to FDA records
- Recall monitoring and alerts
- Compliance reporting
- Regulatory requirement tracking

### Reporting & Analytics
- Executive dashboards
- Compliance reports
- Risk assessments
- Trend analysis

## Development

### Prerequisites

#### Production Installation
- PHP 7.4+ with required extensions (8.0+ recommended)
- PostgreSQL 13+ (14+ recommended)
- Python 3.8+ with pip (3.9+ recommended)
- Apache 2.4+ or Nginx 1.18+

#### Development/Testing (Optional)
- Composer (for PHP dependencies)

### Development Setup
```bash
# Clone repository
git clone https://github.com/your-org/dave.git
cd dave

# Set up development environment
sudo bash scripts/setup-permissions.sh

# Install dependencies
composer install
pip install -r requirements.txt
```

See [Development Setup Guide](docs/DEVELOPMENT-SETUP.md) for detailed instructions.

## Monitoring & Maintenance

### Application Health Monitoring
- System resource monitoring
- Database performance tracking
- Application log analysis
- Service status monitoring

### Application Backup & Recovery
- Automated database backups
- Configuration backups
- File system backups
- Disaster recovery procedures

### Application Updates & Maintenance
- System package updates
- Application updates
- Database maintenance
- Security patches

## Support

### Documentation
- [Complete Documentation](docs/)
- [API Reference](docs/api-fields-reference.md)
- [Troubleshooting Guide](docs/administrator-guide.md#troubleshooting)

### Getting Help
- **Setup Issues**: Check [Setup Guide](SETUP.md)
- **Configuration**: See [Environment Configuration](docs/ENVIRONMENT_CONFIGURATION.md)
- **User Questions**: Review [User Guide](docs/user-guide.md)
- **Admin Tasks**: Consult [Administrator Guide](docs/administrator-guide.md)

### Contact
- **Technical Support**: Contact your system administrator
- **Documentation Issues**: Create an issue in the repository
- **Feature Requests**: Submit via the issue tracker

## License

This software is proprietary and confidential. All rights reserved.

**Copyright (c) 2026 Siemens Healthineers - All rights reserved**

## Version History

- **v1.0.0** - Initial release with web-based setup wizard
- **v0.9.0** - Beta release with core functionality
- **v0.8.0** - Alpha release with basic features

## Acknowledgments

- Designed for healthcare cybersecurity requirements
- Developed for FDA compliance monitoring
- Optimized for medical device management

---

**Ready to get started?** Run the installation script and visit the setup wizard to configure your DAVE installation!

```bash
sudo bash scripts/install.sh
# Then visit: http://your-server-ip/setup.php
```