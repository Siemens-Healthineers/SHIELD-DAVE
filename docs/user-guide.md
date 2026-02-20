# /*
# * SPDX-License-Identifier: AGPL-3.0-or-later
# * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
# */
# DAVE User Guide

## Table of Contents

- [Getting Started](#getting-started)
- [Dashboard Overview](#dashboard-overview)
- [Asset Management](#asset-management)
- [Device Mapping](#device-mapping)
- [Vulnerability Management](#vulnerability-management)
- [Recall Management](#recall-management)
- [Reporting](#reporting)
- [User Management](#user-management)
- [Troubleshooting](#troubleshooting)

## Getting Started

### First Login

1. **Access the System**
   - Open your web browser
   - Navigate to your DAVE URL (e.g., `https://dave.yourorganization.com`)
   - You'll see the login page

2. **Login Process**
   - Enter your username (usually your email address)
   - Enter your password
   - If MFA is enabled, enter the 6-digit code from your authenticator app
   - Click "Login"

3. **Initial Setup**
   - Complete your profile information
   - Set up notification preferences
   - Review and accept the terms of service

### Dashboard Overview

The main dashboard provides a comprehensive overview of your organization's cybersecurity posture:

#### Key Metrics
- **Total Assets**: Number of managed devices
- **Active Vulnerabilities**: Current security issues
- **Open Recalls**: FDA recalls affecting your devices
- **Compliance Rate**: Overall compliance percentage

#### Navigation Menu
- **Dashboard**: Main overview page
- **Assets**: Device and asset management
- **Device Mapping**: FDA device mapping
- **Recalls**: FDA recall monitoring
- **Vulnerabilities**: Security vulnerability management
- **Reports**: Report generation and analytics

## Asset Management

### Adding Assets

#### Manual Entry
1. Navigate to **Assets** → **Add Asset**
2. Fill in the required information:
   - **Basic Information**
     - Hostname/IP Address
     - Asset Type
     - Manufacturer
     - Model Number
     - Serial Number
   - **Network Information**
     - IP Address
     - MAC Address
     - Network Segment
   - **Organizational Data**
     - Department
     - Location
     - Business Unit
     - Asset Owner
   - **Criticality & Compliance**
     - Criticality Level
     - Compliance Status
     - Security Classification
3. Click **Save Asset**

#### Bulk Import
1. Navigate to **Assets** → **Upload Assets**
2. Prepare your CSV file with the following columns:
   - `hostname`, `ip_address`, `manufacturer`, `model_number`, `serial_number`
   - `department`, `location`, `status`, `criticality_level`
3. Click **Choose File** and select your CSV
4. Review the preview and click **Import Assets**

### Managing Assets

#### Viewing Assets
- **List View**: Tabular format with sorting and filtering
- **Grid View**: Card-based layout for visual browsing
- **Search**: Use the search bar to find specific assets
- **Filters**: Filter by department, status, criticality, etc.

#### Editing Assets
1. Click on an asset from the list
2. Click **Edit** button
3. Modify the required fields
4. Click **Save Changes**

#### Asset Status Management
- **Active**: Device is operational
- **Inactive**: Device is offline or decommissioned
- **Maintenance**: Device is under maintenance
- **Retired**: Device has been decommissioned

### Asset Categories

#### Medical Devices
- Patient monitoring equipment
- Diagnostic devices
- Therapeutic devices
- Laboratory equipment

#### IT Infrastructure
- Servers and workstations
- Network equipment
- Storage systems
- Security appliances

## Device Mapping

### FDA Device Mapping

The system automatically maps your assets to FDA device records for enhanced compliance monitoring.

#### Automatic Mapping
1. **MAC Address Lookup**: System identifies manufacturer from MAC address
2. **FDA Database Query**: Searches openFDA database for matching devices
3. **Confidence Scoring**: Ranks potential matches by confidence level
4. **Manual Review**: Review and confirm automatic matches

#### Manual Mapping
1. Navigate to **Device Mapping** → **Unmapped Assets**
2. Select an unmapped asset
3. Search FDA database using device information
4. Review potential matches
5. Select the correct FDA device record
6. Click **Confirm Mapping**

#### Mapping Status
- **Mapped**: Asset successfully linked to FDA record
- **Unmapped**: No FDA record found or mapping pending
- **Pending Review**: Automatic mapping requires manual confirmation
- **Mapping Failed**: Unable to find suitable FDA match

### Device Information

#### FDA Device Data
- **Device Name**: Official FDA device name
- **Manufacturer**: Device manufacturer
- **Product Code**: FDA product classification code
- **Device Class**: FDA device class (I, II, or III)
- **Regulation Number**: FDA regulation reference

#### Compliance Tracking
- **FDA Registration**: Device registration status
- **Recall History**: Past FDA recalls affecting this device
- **Vulnerability Status**: Known security vulnerabilities
- **Compliance Score**: Overall compliance rating

## Vulnerability Management

### SBOM Processing

Software Bill of Materials (SBOM) files provide detailed information about software components in your devices.

#### Uploading SBOM Files
1. Navigate to **Vulnerabilities** → **Upload SBOM**
2. Select the target device
3. Choose your SBOM file (supports CycloneDX, SPDX, JSON, XML)
4. Click **Upload and Process**

#### Supported SBOM Formats
- **CycloneDX**: Industry-standard format
- **SPDX**: Software Package Data Exchange format
- **JSON**: Generic JSON format
- **XML**: XML-based format

#### SBOM Processing
- **Component Extraction**: Identifies all software components
- **Vulnerability Matching**: Matches components to known vulnerabilities
- **Risk Assessment**: Calculates risk scores for each component
- **Remediation Planning**: Suggests remediation actions

### Vulnerability Scanning

#### Automated Scanning
- **Scheduled Scans**: Weekly vulnerability scans
- **Real-time Monitoring**: Continuous vulnerability monitoring
- **NVD Integration**: National Vulnerability Database integration
- **CVSS Scoring**: Common Vulnerability Scoring System

#### Manual Scanning
1. Navigate to **Vulnerabilities** → **Scan Devices**
2. Select devices to scan
3. Choose scan parameters
4. Click **Start Scan**

#### Vulnerability Information
- **CVE ID**: Common Vulnerabilities and Exposures identifier
- **Description**: Detailed vulnerability description
- **Severity**: Critical, High, Medium, Low, Info
- **CVSS Score**: Numerical risk score (0.0-10.0)
- **Affected Components**: Software components affected
- **Remediation**: Suggested fixes and patches

### Risk Assessment

#### Vulnerability Prioritization
- **Critical**: Immediate attention required
- **High**: Priority remediation needed
- **Medium**: Address within reasonable timeframe
- **Low**: Monitor and address when possible
- **Info**: Informational only

#### Risk Factors
- **CVSS Score**: Vulnerability severity
- **Exploitability**: Ease of exploitation
- **Impact**: Potential damage
- **Asset Criticality**: Importance of affected device
- **Network Exposure**: Network accessibility

## Recall Management

### FDA Recall Monitoring

The system automatically monitors FDA recalls and matches them to your devices.

#### Automatic Monitoring
- **Daily Checks**: Automated daily recall monitoring
- **Real-time Alerts**: Immediate notifications for new recalls
- **Device Matching**: Automatic matching to affected devices
- **User Notifications**: Email alerts to relevant users

#### Recall Information
- **FDA Recall Number**: Official FDA recall identifier
- **Recall Date**: Date recall was issued
- **Product Description**: Detailed product information
- **Reason for Recall**: Why the recall was issued
- **Manufacturer**: Device manufacturer
- **Classification**: Class I, II, or III recall
- **Affected Devices**: Your devices affected by the recall

#### Recall Workflow
1. **Detection**: System identifies new recall
2. **Matching**: Matches recall to your devices
3. **Notification**: Alerts relevant users
4. **Assessment**: Review impact and required actions
5. **Remediation**: Implement corrective actions
6. **Tracking**: Monitor remediation progress
7. **Closure**: Document resolution

### Remediation Management

#### Remediation Status
- **Open**: Recall requires action
- **In Progress**: Remediation actions underway
- **Resolved**: Recall has been addressed
- **Closed**: No further action required

#### Remediation Actions
- **Device Replacement**: Replace affected devices
- **Firmware Update**: Update device firmware
- **Configuration Change**: Modify device settings
- **Isolation**: Remove device from network
- **Monitoring**: Enhanced monitoring of affected devices

#### Documentation
- **Remediation Plan**: Detailed action plan
- **Progress Updates**: Regular status updates
- **Evidence Collection**: Documentation of actions taken
- **Verification**: Confirmation of successful remediation

## Reporting

### Report Generation

#### Available Reports
- **Asset Summary**: Comprehensive asset overview
- **Vulnerability Report**: Security vulnerability analysis
- **Recall Report**: FDA recall status and impact
- **Compliance Report**: Compliance status and issues
- **Device Mapping**: Mapping status and gaps
- **Security Dashboard**: Overall security posture

#### Generating Reports
1. Navigate to **Reports** → **Generate Report**
2. Select report type
3. Choose export format (PDF, Excel, CSV)
4. Set date range and filters
5. Click **Generate Report**

#### Report Formats
- **PDF**: Professional formatted reports
- **Excel**: Spreadsheet format for analysis
- **CSV**: Comma-separated values for data import
- **JSON**: Machine-readable format

### Analytics Dashboard

#### Key Metrics
- **Asset Statistics**: Total, active, and new assets
- **Vulnerability Trends**: Security issue trends over time
- **Recall Impact**: Devices affected by recalls
- **Compliance Rates**: Department compliance percentages

#### Department Analysis
- **Asset Distribution**: Assets by department
- **Risk Assessment**: Department risk levels
- **Compliance Status**: Department compliance rates
- **Vulnerability Summary**: Security issues by department

#### Trend Analysis
- **Historical Data**: Trends over time
- **Seasonal Patterns**: Recurring patterns
- **Risk Indicators**: Early warning signs
- **Performance Metrics**: System performance indicators

### Scheduled Reports

#### Setting Up Scheduled Reports
1. Navigate to **Reports** → **Scheduled Reports**
2. Click **Create Schedule**
3. Configure report parameters
4. Set delivery schedule
5. Add email recipients
6. Click **Save Schedule**

#### Schedule Options
- **Daily**: Daily report delivery
- **Weekly**: Weekly summary reports
- **Monthly**: Monthly comprehensive reports
- **Custom**: Custom schedule configuration

## User Management

### User Roles

#### Administrator
- Full system access
- User management
- System configuration
- Background service management
- Security management
- API key management
- Risk matrix configuration

#### User
- Asset management
- Device mapping
- Vulnerability monitoring
- Report generation
- Dashboard access
- Read-only system access

### User Profile

#### Profile Information
- **Personal Details**: Name, email, phone
- **Department**: Organizational department
- **Role**: User role and permissions
- **Preferences**: Notification and display preferences

#### Notification Settings
- **Email Notifications**: Email alert preferences
- **Dashboard Alerts**: Dashboard notification settings
- **Report Delivery**: Scheduled report preferences
- **Security Alerts**: Security notification settings

### Password Management

#### Password Requirements
- Minimum 8 characters
- Must contain uppercase and lowercase letters
- Must contain numbers
- Must contain special characters
- Cannot reuse last 5 passwords

#### Password Reset
1. Click **Forgot Password** on login page
2. Enter your email address
3. Check email for reset link
4. Click reset link and enter new password
5. Login with new password

## Troubleshooting

### Common Issues

#### Login Problems
- **Forgot Password**: Use password reset function
- **Account Locked**: Contact administrator
- **MFA Issues**: Check authenticator app time sync
- **Browser Issues**: Clear browser cache and cookies

#### Asset Management Issues
- **Upload Failures**: Check file format and size
- **Missing Data**: Verify required fields are filled
- **Permission Errors**: Contact administrator for access
- **Search Issues**: Try different search terms

#### Vulnerability Scanning Issues
- **Scan Failures**: Check device connectivity
- **Missing Vulnerabilities**: Verify SBOM upload
- **False Positives**: Review vulnerability details
- **Update Issues**: Check for system updates

#### Report Generation Issues
- **Report Failures**: Check date ranges and filters
- **Missing Data**: Verify data availability
- **Format Issues**: Try different export formats
- **Download Problems**: Check browser settings

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

**Last Updated**: January 2024  
**Version**: 1.0.0  
**For Technical Support**: Contact your system administrator
