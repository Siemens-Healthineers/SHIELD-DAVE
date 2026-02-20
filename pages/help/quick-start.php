<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
/**
 * Quick Start Guide for Device Assessment and Vulnerability Exposure ()
 * Step-by-step guide to get users up and running quickly
 */

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/auth.php';

// Require authentication
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quick Start Guide - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/help.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

    <main class="main-content">
        <div class="help-content-container">
            <div class="help-page-header">
                <div class="container">
                    <h1><i class="fas fa-rocket"></i> Quick Start Guide</h1>
                    <p>Get up and running with  quickly and efficiently</p>
                </div>
            </div>

            <div class="help-content">
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i>
                    <strong>Welcome to !</strong> This guide will help you get started with the Device Assessment and Vulnerability Exposure in just a few steps.
                </div>

                <h2 id="welcome">Welcome to </h2>
                <p>The Device Assessment and Vulnerability Exposure () is a comprehensive platform for managing medical device cybersecurity, FDA compliance, and vulnerability tracking. This quick start guide will help you get up and running quickly.</p>

                <h2 id="table-of-contents">Table of Contents</h2>
                <ul>
                    <li><a href="#fresh-installation">Fresh Installation</a></li>
                    <li><a href="#first-login">First Login</a></li>
                    <li><a href="#initial-setup">Initial Setup</a></li>
                    <li><a href="#adding-first-asset">Adding Your First Asset</a></li>
                    <li><a href="#device-mapping">Device Mapping</a></li>
                    <li><a href="#vulnerability-management">Vulnerability Management</a></li>
                    <li><a href="#recall-monitoring">Recall Monitoring</a></li>
                    <li><a href="#generating-reports">Generating Reports</a></li>
                    <li><a href="#api-integration">API Integration</a></li>
                    <li><a href="#next-steps">Next Steps</a></li>
                </ul>

                <h2 id="fresh-installation">Fresh Installation</h2>
                
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Important:</strong> If you're setting up  for the first time, follow these installation steps before proceeding with the quick start guide.
                </div>

                <h3>1. Run Installation Script</h3>
                <p>Execute the automated installation script to set up all required components:
                    Create the folder /var/www/html if it doesnt exist and copy the contents of c01-csms into the html folder. 
                    Copy docs/env.example to .env and update the following fields with your own defaults
                    The values you specify here will be used by the installation scripts to create the specific accounts/databases 

                       - DAVE_ADMIN_USER=<your admin user name>
                       - DAVE_ADMIN_DEFAULT_PASSWORD=<your admin default password>

                       - DB_HOST=localhost
                       - DB_PORT=5432
                       - DB_NAME=<your database name. Eg., dave_db>
                       - DB_USER=<your database login. Eg., dave_user>
                       - DB_PASSWORD=<your database password. Eg., dave_password>

                </p>
                <pre><code>cd /var/www/html
sudo bash scripts/install.sh</code></pre>
                
                <p>The installation script will:</p>
                <ul>
                    <li>Install Apache, PostgreSQL, PHP 7.4, and Python 3</li>
                    <li>Configure the web server and database</li>
                    <li>Set up proper file permissions</li>
                    <li>Create the database schema</li>
                    <li>Install required Python packages</li>
                    <li>Configure SSL certificates (if available)</li>
                </ul>

                <h3>2. Complete Setup Wizard</h3>
                <p>After the installation script completes:</p>
                <ol>
                    <li><strong>Visit the setup wizard</strong>: Navigate to <code>http://your-server-ip/setup.php</code></li>
                    <li><strong>Configure your settings</strong>:
                        <ul>
                            <li>Base URL (e.g., <code>https://dave.yourorganization.com</code>)</li>
                            <li>Database connection details</li>
                            <li>Email configuration (optional)</li>
                            <li>Security settings</li>
                        </ul>
                    </li>
                    <li><strong>Complete the setup process</strong> and save your configuration</li>
                </ol>

                <h3>3. Access Application</h3>
                <p>Once setup is complete, you can access the application:</p>
                <ul>
                    <li><strong>URL</strong>: Your configured base URL</li>
                    <li><strong>Default Username</strong>: <code>admin</code></li>
                    <li><strong>Default Password</strong>: <code>XXXXX</code></li>
                </ul>
                
                <div class="alert alert-danger">
                    <i class="fas fa-shield-alt"></i>
                    <strong>Security Warning:</strong> Change the default password immediately after first login!
                </div>

                <h2 id="first-login">First Login</h2>
                
                <h3>Accessing the System</h3>
                <ol>
                    <li><strong>Open your web browser</strong> and navigate to your  URL</li>
                    <li><strong>Enter your credentials</strong>:
                        <ul>
                            <li>Username: <code>admin</code></li>
                            <li>Password: <code>admin123</code></li>
                        </ul>
                    </li>
                    <li><strong>Click "Login"</strong> to access the system</li>
                    <li><strong>Change your password immediately</strong> for security</li>
                </ol>
                
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i>
                    <strong>Note:</strong> MFA (Multi-Factor Authentication) is not enabled by default but can be configured later in your user profile settings.
                </div>

                <h3>Dashboard Overview</h3>
                <p>After logging in, you'll see the main dashboard with:</p>
                <ul>
                    <li><strong>Key Metrics</strong>: Total assets, vulnerabilities, recalls, compliance rate</li>
                    <li><strong>Recent Activity</strong>: Latest system activities</li>
                    <li><strong>Quick Actions</strong>: Common tasks and shortcuts</li>
                    <li><strong>Navigation Menu</strong>: Access to all system features</li>
                </ul>

                <h2 id="initial-setup">Initial Setup</h2>
                
                <h3>Change Default Password</h3>
                <div class="alert alert-danger">
                    <i class="fas fa-shield-alt"></i>
                    <strong>Critical First Step:</strong> Change the default password immediately for security!
                </div>
                <ol>
                    <li><strong>Click your username</strong> in the top-right corner</li>
                    <li><strong>Select "Profile"</strong> from the dropdown menu</li>
                    <li><strong>Click "Change Password"</strong></li>
                    <li><strong>Enter a strong password</strong> (minimum 8 characters, mixed case, numbers, symbols)</li>
                    <li><strong>Confirm the new password</strong></li>
                    <li><strong>Save changes</strong></li>
                </ol>

                <h3>User Profile Setup</h3>
                <ol>
                    <li><strong>Complete your profile information</strong>:
                        <ul>
                            <li>Username (already set as 'admin')</li>
                            <li>Email Address (update if needed)</li>
                        </ul>
                    </li>
                    <li><strong>Configure MFA (optional but recommended)</strong></li>
                    <li><strong>Set notification preferences</strong></li>
                    <li><strong>Save changes</strong></li>
                </ol>
                
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i>
                    <strong>Note:</strong> The user profile only requires username and email. Additional personal information like first name, last name, phone number, and department are not stored in the user profile.
                </div>

                <h3>System Configuration</h3>
                <p>As an administrator, configure your organization's settings:</p>
                <ol>
                    <li><strong>Navigate to Admin → System Configuration</strong></li>
                    <li><strong>Add Departments</strong>:
                        <ul>
                            <li>ICU</li>
                            <li>Emergency</li>
                            <li>Surgery</li>
                            <li>Laboratory</li>
                            <li>IT</li>
                        </ul>
                    </li>
                    <li><strong>Add Locations</strong>:
                        <ul>
                            <li>Building A</li>
                            <li>Building B</li>
                            <li>Remote Sites</li>
                        </ul>
                    </li>
                    <li><strong>Configure Email Settings</strong> (if not done during setup)</li>
                    <li><strong>Set up additional users</strong> with appropriate roles</li>
                </ol>

                <h2 id="adding-first-asset">Adding Your First Asset</h2>
                
                <h3>Manual Asset Entry</h3>
                <ol>
                    <li><strong>Navigate to Assets</strong> from the main menu</li>
                    <li><strong>Click "Add New Asset"</strong></li>
                    <li><strong>Fill in the required information</strong>:
                        <ul>
                            <li>Asset Name</li>
                            <li>Asset Type</li>
                            <li>IP Address</li>
                            <li>MAC Address</li>
                            <li>Location</li>
                            <li>Department</li>
                        </ul>
                    </li>
                    <li><strong>Set criticality level</strong></li>
                    <li><strong>Save the asset</strong></li>
                </ol>

                <h3>Bulk Asset Import</h3>
                <p>For importing multiple assets at once, you have several options:</p>
                
                <h4>Option 1: CSV Upload</h4>
                <ol>
                    <li><strong>Prepare your data</strong> in CSV format</li>
                    <li><strong>Navigate to Assets → Upload</strong></li>
                    <li><strong>Select your CSV file</strong></li>
                    <li><strong>Map columns</strong> to asset fields</li>
                    <li><strong>Review and import</strong></li>
                </ol>
                
                <h4>Option 2: Nmap Scan Import</h4>
                <ol>
                    <li><strong>Run an Nmap scan</strong> on your network</li>
                    <li><strong>Save results as XML</strong></li>
                    <li><strong>Use the API endpoint</strong> <code>POST /api/v1/assets/import</code></li>
                    <li><strong>Upload the XML file</strong> for automatic processing</li>
                </ol>
                
                <h4>Option 3: Nessus Scan Import</h4>
                <ol>
                    <li><strong>Export Nessus scan results</strong> as XML</li>
                    <li><strong>Use the API endpoint</strong> <code>POST /api/v1/assets/import</code></li>
                    <li><strong>Upload the XML file</strong> for processing</li>
                </ol>

                <h2 id="device-mapping">Device Mapping</h2>
                
                <h3>Automatic Mapping</h3>
                <p> automatically attempts to map assets to FDA device records:</p>
                <ol>
                    <li><strong>Navigate to Device Mapping</strong></li>
                    <li><strong>Review automatic matches</strong></li>
                    <li><strong>Accept or reject matches</strong> based on confidence scores</li>
                    <li><strong>Manually map unmatched assets</strong></li>
                </ol>

                <h3>Manual Mapping</h3>
                <p>For assets that couldn't be automatically mapped:</p>
                <ol>
                    <li><strong>Search the FDA database</strong> using device information</li>
                    <li><strong>Select the appropriate device</strong></li>
                    <li><strong>Confirm the mapping</strong></li>
                </ol>

                <h2 id="vulnerability-management">Vulnerability Management</h2>
                
                <h3>SBOM Upload for Medical Devices</h3>
                <p>Upload Software Bill of Materials (SBOM) for your medical devices to enable vulnerability scanning:</p>
                <ol>
                    <li><strong>Navigate to Devices</strong> and select a medical device</li>
                    <li><strong>Click "Upload SBOM"</strong> or use the API endpoint</li>
                    <li><strong>Select your SBOM file</strong> (CycloneDX, SPDX, spdx-tag-value, JSON, XML)</li>
                    <li><strong>Upload and process</strong> the SBOM</li>
                </ol>
                
                <h4>API Method</h4>
                <p>Use the API for automated SBOM uploads:</p>
                <pre><code>POST /api/v1/devices/sbom
Content-Type: multipart/form-data

{
  "device_id": "device-uuid-here",
  "sbom_file": "sbom-file.xml"
}</code></pre>

                <h3>Vulnerability Scanning Process</h3>
                <p>Once SBOMs are uploaded, the system automatically:</p>
                <ul>
                    <li><strong>Parses SBOM components</strong> and extracts software packages</li>
                    <li><strong>Queues for evaluation</strong> in the background processing system</li>
                    <li><strong>Scans for vulnerabilities</strong> using the NVD database</li>
                    <li><strong>Assesses risk levels</strong> based on CVSS scores and EPSS data</li>
                    <li><strong>Generates alerts</strong> for high-risk vulnerabilities</li>
                    <li><strong>Provides remediation guidance</strong> and tracking</li>
                </ul>
                
                <h3>Manual Vulnerability Entry</h3>
                <p>You can also manually add vulnerabilities using the API:</p>
                <pre><code>POST /api/v1/vulnerabilities
Content-Type: application/json

{
  "cve_id": "CVE-2024-1234",
  "description": "Vulnerability description",
  "severity": "High",
  "cvss_v3_score": 7.5,
  "published_date": "2024-01-15"
}</code></pre>

                <h2 id="recall-monitoring">Recall Monitoring</h2>
                
                <h3>Automatic Monitoring</h3>
                <p> automatically monitors FDA recalls:</p>
                <ul>
                    <li><strong>Daily checks</strong> for new recalls</li>
                    <li><strong>Device matching</strong> against your assets</li>
                    <li><strong>Alert generation</strong> for affected devices</li>
                    <li><strong>Email notifications</strong> to subscribed users</li>
                </ul>

                <h3>Recall Management</h3>
                <ol>
                    <li><strong>Navigate to Recalls</strong></li>
                    <li><strong>Review active recalls</strong></li>
                    <li><strong>Assess impact</strong> on your organization</li>
                    <li><strong>Track remediation progress</strong></li>
                </ol>

                <h2 id="generating-reports">Generating Reports</h2>
                
                <h3>Quick Reports</h3>
                <ol>
                    <li><strong>Navigate to Reports</strong></li>
                    <li><strong>Select report type</strong>:
                        <ul>
                            <li>Asset Summary</li>
                            <li>Vulnerability Report</li>
                            <li>Recall Status</li>
                            <li>Compliance Report</li>
                        </ul>
                    </li>
                    <li><strong>Set date range</strong></li>
                    <li><strong>Choose export format</strong> (PDF, Excel, CSV, JSON)</li>
                    <li><strong>Generate report</strong></li>
                </ol>

                <h3>Scheduled Reports</h3>
                <p>Set up automated report generation:</p>
                <ol>
                    <li><strong>Configure report schedule</strong></li>
                    <li><strong>Set recipients</strong></li>
                    <li><strong>Choose delivery method</strong></li>
                    <li><strong>Activate scheduling</strong></li>
                </ol>

                <h2 id="api-integration">API Integration</h2>
                
                <h3>API Key Management</h3>
                <p>Generate API keys for external system integration:</p>
                <ol>
                    <li><strong>Navigate to your profile</strong> and click "My API Keys"</li>
                    <li><strong>Click "Create New API Key"</strong></li>
                    <li><strong>Configure permissions</strong> based on your needs:
                        <ul>
                            <li>Assets: Read/Write access to asset data</li>
                            <li>Vulnerabilities: Read/Write access to vulnerability data</li>
                            <li>Recalls: Read access to recall information</li>
                            <li>Reports: Generate and export reports</li>
                        </ul>
                    </li>
                    <li><strong>Set rate limits</strong> and IP whitelist (optional)</li>
                    <li><strong>Save and copy your API key</strong> (store securely!)</li>
                </ol>
                
                <h3>API Usage Examples</h3>
                <p>Use your API key for automated operations:</p>
                <pre><code># List all assets
curl -H "Authorization: Bearer YOUR_API_KEY" \
     https://your-dave.com/api/v1/assets

# Upload Nmap scan results
curl -X POST \
     -H "Authorization: Bearer YOUR_API_KEY" \
     -F "file=@nmap_scan.xml" \
     -F "import_options={\"auto_categorize\":true}" \
     https://your-dave.com/api/v1/assets/import</code></pre>

                <h2 id="next-steps">Next Steps</h2>
                
                <h3>Explore Advanced Features</h3>
                <ul>
                    <li><strong>User Management</strong>: Add team members and assign roles</li>
                    <li><strong>API Integration</strong>: Connect with existing systems using API keys</li>
                    <li><strong>Custom Dashboards</strong>: Create personalized views</li>
                    <li><strong>Advanced Analytics</strong>: Deep dive into your data</li>
                    <li><strong>Automated Scanning</strong>: Set up scheduled vulnerability scans</li>
                    <li><strong>Compliance Reporting</strong>: Generate regulatory compliance reports</li>
                </ul>

                <h3>Training and Support</h3>
                <ul>
                    <li><strong>User Guide</strong>: Comprehensive documentation</li>
                    <li><strong>Video Tutorials</strong>: Step-by-step video guides</li>
                    <li><strong>Support Portal</strong>: Get help when you need it</li>
                    <li><strong>Community Forum</strong>: Connect with other users</li>
                </ul>

                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <strong>Congratulations!</strong> You've completed the quick start guide. You're now ready to use  effectively for your medical device cybersecurity needs.
                </div>

                <div class="help-navigation">
                    <a href="/pages/help/user-guide.php" class="btn btn-primary">
                        <i class="fas fa-book"></i>
                        Read User Guide
                    </a>
                    <a href="/pages/help/administrator-guide.php" class="btn btn-secondary">
                        <i class="fas fa-cog"></i>
                        Administrator Guide
                    </a>
                </div>
            </div>
                </div>
        </div>
    </main>

    <script>
        // Quick Start Guide JavaScript
        document.addEventListener('DOMContentLoaded', function() {
            // Smooth scrolling for anchor links
            document.querySelectorAll('a[href^="#"]').forEach(function(link) {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {
                        target.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                });
            });

            // Add loading states to buttons
            document.querySelectorAll('.btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    this.classList.add('loading');
                });
            });
        });
    </script>
</body>
</html>
