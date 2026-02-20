# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */

# DAVE Quick Start Guide

## Welcome to DAVE

The Device Assessment and Vulnerability Exposure (DAVE) is a comprehensive platform for managing medical device cybersecurity, FDA compliance, and vulnerability tracking. This quick start guide will help you get up and running quickly.

## Table of Contents

- [First Login](#first-login)
- [Initial Setup](#initial-setup)
- [Adding Your First Asset](#adding-your-first-asset)
- [Device Mapping](#device-mapping)
- [Vulnerability Management](#vulnerability-management)
- [Recall Monitoring](#recall-monitoring)
- [Generating Reports](#generating-reports)
- [Next Steps](#next-steps)

## Fresh Installation

If you're setting up DAVE for the first time:

### 1. Run Installation Script
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

### 2. Complete Setup Wizard
- Visit: `http://your-server-ip/setup.php`
- Configure your Base URL and database settings
- Set up email configuration (optional)
- Complete the setup process

### 3. Access Application
- Login with default credentials: <admin user> / <admin password>
- Change the default password immediately

## First Login

### Accessing the System

1. **Open your web browser** and navigate to your DAVE URL
2. **Enter your credentials**:
   - Username: Your email address
   - Password: Your temporary password
3. **Complete MFA setup** if required
4. **Change your password** when prompted

### Dashboard Overview

After logging in, you'll see the main dashboard with:
- **Key Metrics**: Total assets, vulnerabilities, recalls, compliance rate
- **Recent Activity**: Latest system activities
- **Quick Actions**: Common tasks and shortcuts
- **Navigation Menu**: Access to all system features

## Initial Setup

### User Profile

1. **Click your username** in the top-right corner
2. **Complete your profile**:
   - First Name
   - Last Name
   - Department
   - Phone Number
3. **Set notification preferences**
4. **Save changes**

### System Configuration

#### Departments and Locations
1. **Navigate to Admin → System Configuration**
2. **Add Departments**:
   - ICU
   - Emergency
   - Surgery
   - Laboratory
   - IT
3. **Add Locations**:
   - Building A
   - Building B
   - Remote Sites

#### User Roles
- **Administrator**: Full system access, user management, and configuration
- **User**: Asset management, vulnerability monitoring, and reporting

## Adding Your First Asset

### Manual Asset Entry

1. **Navigate to Assets → Add Asset**
2. **Fill in basic information**:
   - Hostname: `patient-monitor-01`
   - IP Address: `192.168.1.100`
   - Manufacturer: `MedTech Corp`
   - Model Number: `PM-2000`
   - Serial Number: `SN123456`
3. **Set organizational data**:
   - Department: `ICU`
   - Location: `Room 101`
   - Asset Owner: `Dr. Smith`
4. **Configure criticality**:
   - Criticality Level: `High`
   - Compliance Status: `Compliant`
5. **Click Save Asset**

### Bulk Asset Import

1. **Navigate to Assets → Upload Assets**
2. **Download the CSV template**
3. **Fill in your asset data**:
   ```csv
   hostname,ip_address,manufacturer,model_number,serial_number,department,location,status,criticality_level
   patient-monitor-01,192.168.1.100,MedTech Corp,PM-2000,SN123456,ICU,Room 101,Active,High
   patient-monitor-02,192.168.1.101,MedTech Corp,PM-2000,SN123457,ICU,Room 102,Active,High
   ```
4. **Upload the CSV file**
5. **Review the preview**
6. **Click Import Assets**

## Device Mapping

### Automatic Mapping

The system automatically maps your assets to FDA device records:

1. **Navigate to Device Mapping**
2. **Review automatic matches**:
   - Green: High confidence matches
   - Yellow: Medium confidence matches
   - Red: Low confidence matches
3. **Confirm high-confidence matches**
4. **Review medium-confidence matches**

### Manual Mapping

1. **Navigate to Device Mapping → Unmapped Assets**
2. **Select an unmapped asset**
3. **Search FDA database** using device information
4. **Review potential matches**
5. **Select the correct FDA device**
6. **Click Confirm Mapping**

### Mapping Benefits

- **FDA Compliance**: Track FDA device registrations
- **Recall Monitoring**: Automatic recall notifications
- **Vulnerability Tracking**: Device-specific vulnerability monitoring
- **Compliance Reporting**: Generate compliance reports

## Vulnerability Management

### Uploading SBOM Files

1. **Navigate to Vulnerabilities → Upload SBOM**
2. **Select target device**
3. **Choose SBOM file** (CycloneDX, SPDX, JSON, XML)
4. **Click Upload and Process**

### Vulnerability Scanning

1. **Navigate to Vulnerabilities → Scan Devices**
2. **Select devices to scan**
3. **Choose scan parameters**
4. **Click Start Scan**

### Vulnerability Information

- **CVE ID**: Common Vulnerabilities and Exposures identifier
- **Description**: Detailed vulnerability description
- **Severity**: Critical, High, Medium, Low, Info
- **CVSS Score**: Numerical risk score (0.0-10.0)
- **Affected Components**: Software components affected
- **Remediation**: Suggested fixes and patches

### Risk Assessment

- **Critical**: Immediate attention required
- **High**: Priority remediation needed
- **Medium**: Address within reasonable timeframe
- **Low**: Monitor and address when possible

## Recall Monitoring

### Automatic Recall Monitoring

The system automatically monitors FDA recalls:

1. **Navigate to Recalls Dashboard**
2. **View active recalls** affecting your devices
3. **Review recall details**:
   - FDA Recall Number
   - Recall Date
   - Product Description
   - Reason for Recall
   - Classification (Class I, II, III)

### Recall Workflow

1. **Detection**: System identifies new recall
2. **Matching**: Matches recall to your devices
3. **Notification**: Alerts relevant users
4. **Assessment**: Review impact and required actions
5. **Remediation**: Implement corrective actions
6. **Tracking**: Monitor remediation progress
7. **Closure**: Document resolution

### Remediation Management

- **Open**: Recall requires action
- **In Progress**: Remediation actions underway
- **Resolved**: Recall has been addressed
- **Closed**: No further action required

## Generating Reports

### Quick Reports

1. **Navigate to Reports → Generate Report**
2. **Select report type**:
   - Asset Summary
   - Vulnerability Report
   - Recall Report
   - Compliance Report
3. **Choose export format** (PDF, Excel, CSV)
4. **Set date range**
5. **Click Generate Report**

### Report Types

#### Asset Summary Report
- Total assets and status breakdown
- Assets by department and location
- Recent asset additions
- Compliance status overview

#### Vulnerability Report
- Vulnerability statistics by severity
- Top vulnerabilities by CVSS score
- Affected devices and components
- Remediation recommendations

#### Recall Report
- Active recalls affecting your devices
- Recall classification breakdown
- Remediation status and progress
- Compliance impact analysis

#### Compliance Report
- Overall compliance rate
- Department compliance breakdown
- Non-compliant assets and issues
- Compliance improvement recommendations

### Scheduled Reports

1. **Navigate to Reports → Scheduled Reports**
2. **Click Create Schedule**
3. **Configure report parameters**
4. **Set delivery schedule**:
   - Daily
   - Weekly
   - Monthly
   - Custom
5. **Add email recipients**
6. **Click Save Schedule**

## Next Steps

### Advanced Features

#### User Management
- Create additional users
- Assign roles and permissions
- Configure notification preferences
- Set up user groups

#### System Configuration
- Configure email settings
- Set up API integrations
- Configure background services
- Set up monitoring and alerts

#### Advanced Reporting
- Create custom reports
- Set up automated reporting
- Configure data exports
- Set up analytics dashboards

### Best Practices

#### Asset Management
- **Regular Updates**: Keep asset information current
- **Accurate Data**: Ensure data accuracy and completeness
- **Proper Categorization**: Use consistent categorization
- **Regular Audits**: Conduct regular asset audits

#### Security Management
- **Regular Scanning**: Schedule regular vulnerability scans
- **SBOM Updates**: Keep SBOM files current
- **Risk Assessment**: Regular risk assessments
- **Incident Response**: Develop incident response procedures

#### Compliance Management
- **Regular Monitoring**: Monitor compliance status regularly
- **Documentation**: Maintain proper documentation
- **Training**: Provide user training and education
- **Continuous Improvement**: Continuously improve processes

### Training and Support

#### User Training
- **Online Tutorials**: Step-by-step video guides
- **Documentation**: Comprehensive user documentation
- **Best Practices**: Recommended procedures and workflows
- **FAQ**: Frequently asked questions

#### Technical Support
- **Email Support**: support@yourorganization.com
- **Phone Support**: (555) 123-4567
- **Ticket System**: Submit support tickets
- **Live Chat**: Real-time support during business hours

#### Resources
- **User Guide**: Comprehensive user documentation
- **API Documentation**: Programmatic access documentation
- **Video Tutorials**: Step-by-step video guides
- **Knowledge Base**: Searchable help articles

### Getting Help

#### Self-Service Resources
- **User Guide**: This comprehensive guide
- **FAQ**: Frequently asked questions
- **Video Tutorials**: Step-by-step video guides
- **Knowledge Base**: Searchable help articles

#### Contact Support
- **Email Support**: support@yourorganization.com
- **Phone Support**: (555) 123-4567
- **Ticket System**: Submit support tickets
- **Live Chat**: Real-time support during business hours

#### Training and Resources
- **User Training**: Scheduled training sessions
- **Documentation**: Comprehensive documentation
- **Best Practices**: Recommended procedures
- **Updates**: System update notifications

---

**Welcome to DAVE!** You're now ready to start managing your medical device cybersecurity. For additional help, refer to the full user guide or contact support.

**Last Updated**: January 2024  
**Version**: 1.0.0  
**For Technical Support**: Contact your system administrator
