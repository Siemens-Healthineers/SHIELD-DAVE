<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
/**
 * User Guide for Device Assessment and Vulnerability Exposure ()
 * Comprehensive user documentation covering all features and functionality
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
    <title>User Guide - <?php echo _NAME; ?></title>
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
                    <h1><i class="fas fa-user"></i> User Guide</h1>
                    <p>Comprehensive user documentation covering all features and functionality</p>
                </div>
            </div>

            <div class="help-content">
                <div class="page-actions" style="margin-bottom: 2rem;">
                    <a href="/docs/index.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Back to Help
                    </a>
                </div>
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i>
                    <strong>Welcome to the  User Guide!</strong> This comprehensive guide covers all features and functionality of the Device Assessment and Vulnerability Exposure.
                </div>

                <h2 id="table-of-contents">Table of Contents</h2>
                <ul>
                    <li><a href="#getting-started">Getting Started</a></li>
                    <li><a href="#dashboard-overview">Dashboard Overview</a></li>
                    <li><a href="#asset-management">Asset Management</a></li>
                    <li><a href="#device-mapping">Device Mapping</a></li>
                    <li><a href="#vulnerability-management">Vulnerability Management</a></li>
                    <li><a href="#recall-management">Recall Management</a></li>
                    <li><a href="#reporting">Reporting</a></li>
                    <li><a href="#user-management">User Management</a></li>
                    <li><a href="#troubleshooting">Troubleshooting</a></li>
                </ul>

                <h2 id="getting-started">Getting Started</h2>
                
                <h3>First Login</h3>
                <ol>
                    <li><strong>Access the System</strong>
                        <ul>
                            <li>Open your web browser</li>
                            <li>Navigate to your  URL (e.g., <code>https://dave.yourorganization.com</code>)</li>
                            <li>You'll see the login page</li>
                        </ul>
                    </li>
                    <li><strong>Login Process</strong>
                        <ul>
                            <li>Enter your username (usually your email address)</li>
                            <li>Enter your password</li>
                            <li>If MFA is enabled, enter the 6-digit code from your authenticator app</li>
                            <li>Click "Login"</li>
                        </ul>
                    </li>
                    <li><strong>Initial Setup</strong>
                        <ul>
                            <li>Complete your profile information</li>
                            <li>Set up notification preferences</li>
                            <li>Review and accept the terms of service</li>
                        </ul>
                    </li>
                </ol>

                <h3>Dashboard Overview</h3>
                <p>The main dashboard provides a comprehensive overview of your organization's cybersecurity posture:</p>
                
                <h4>Key Metrics</h4>
                <ul>
                    <li><strong>Total Assets</strong>: Number of managed devices</li>
                    <li><strong>Active Vulnerabilities</strong>: Current security issues</li>
                    <li><strong>Open Recalls</strong>: FDA recalls affecting your devices</li>
                    <li><strong>Compliance Rate</strong>: Overall compliance percentage</li>
                </ul>

                <h4>Navigation Menu</h4>
                <ul>
                    <li><strong>Dashboard</strong>: Main overview page</li>
                    <li><strong>Assets</strong>: Device and asset management</li>
                    <li><strong>Device Mapping</strong>: FDA device mapping</li>
                    <li><strong>Recalls</strong>: FDA recall monitoring</li>
                    <li><strong>Vulnerabilities</strong>: Security vulnerability management</li>
                    <li><strong>Reports</strong>: Report generation and analytics</li>
                </ul>

                <h2 id="asset-management">Asset Management</h2>
                
                <h3>Adding Assets</h3>
                
                <h4>Manual Entry</h4>
                <ol>
                    <li>Navigate to <strong>Assets</strong> → <strong>Add Asset</strong></li>
                    <li>Fill in the required information:
                        <ul>
                            <li><strong>Basic Information</strong>
                                <ul>
                                    <li>Hostname/IP Address</li>
                                    <li>Asset Type</li>
                                    <li>Manufacturer</li>
                                    <li>Model Number</li>
                                    <li>Serial Number</li>
                                </ul>
                            </li>
                            <li><strong>Network Information</strong>
                                <ul>
                                    <li>IP Address</li>
                                    <li>MAC Address</li>
                                    <li>Network Segment</li>
                                </ul>
                            </li>
                            <li><strong>Organizational Data</strong>
                                <ul>
                                    <li>Department</li>
                                    <li>Location</li>
                                    <li>Business Unit</li>
                                    <li>Asset Owner</li>
                                </ul>
                            </li>
                            <li><strong>Criticality & Compliance</strong>
                                <ul>
                                    <li>Criticality Level</li>
                                    <li>Compliance Status</li>
                                    <li>Security Classification</li>
                                </ul>
                            </li>
                        </ul>
                    </li>
                    <li>Click <strong>Save Asset</strong></li>
                </ol>

                <h4>Bulk Import</h4>
                <ol>
                    <li>Navigate to <strong>Assets</strong> → <strong>Upload Assets</strong></li>
                    <li>Prepare your CSV file with the following columns:
                        <ul>
                            <li><code>hostname</code>, <code>ip_address</code>, <code>manufacturer</code>, <code>model_number</code>, <code>serial_number</code></li>
                            <li><code>department</code>, <code>location</code>, <code>status</code>, <code>criticality_level</code></li>
                        </ul>
                    </li>
                    <li>Click <strong>Choose File</strong> and select your CSV</li>
                    <li>Review the preview and click <strong>Import Assets</strong></li>
                </ol>

                <h3>Managing Assets</h3>
                
                <h4>Viewing Assets</h4>
                <ul>
                    <li><strong>List View</strong>: Tabular format with sorting and filtering</li>
                    <li><strong>Grid View</strong>: Card-based layout for visual browsing</li>
                    <li><strong>Search</strong>: Use the search bar to find specific assets</li>
                    <li><strong>Filters</strong>: Filter by department, status, criticality, etc.</li>
                </ul>

                <h4>Editing Assets</h4>
                <ol>
                    <li>Click on an asset from the list</li>
                    <li>Click <strong>Edit</strong> button</li>
                    <li>Modify the required fields</li>
                    <li>Click <strong>Save Changes</strong></li>
                </ol>

                <h2 id="device-mapping">Device Mapping</h2>
                
                <h3>Automatic Mapping</h3>
                <p> automatically attempts to map assets to FDA device records using:</p>
                <ul>
                    <li><strong>MAC Address Lookup</strong>: OUI database for manufacturer identification</li>
                    <li><strong>FDA Database Search</strong>: openFDA API integration</li>
                    <li><strong>Confidence Scoring</strong>: Algorithm-based matching</li>
                </ul>

                <h3>Manual Mapping</h3>
                <ol>
                    <li>Navigate to <strong>Device Mapping</strong></li>
                    <li>Review unmapped assets</li>
                    <li>Search the FDA database for potential matches</li>
                    <li>Select the appropriate device</li>
                    <li>Confirm the mapping</li>
                </ol>

                <h2 id="vulnerability-management">Vulnerability Management</h2>
                
                <h3>SBOM Upload</h3>
                <ol>
                    <li>Navigate to <strong>Vulnerabilities</strong> → <strong>Upload SBOM</strong></li>
                    <li>Select your SBOM file (CycloneDX, SPDX, JSON, XML)</li>
                    <li>Choose the target device</li>
                    <li>Upload and process</li>
                </ol>

                <h3>Vulnerability Scanning</h3>
                <p>Once SBOMs are uploaded, the system automatically:</p>
                <ul>
                    <li><strong>Scans for vulnerabilities</strong> using the NVD database</li>
                    <li><strong>Assesses risk levels</strong> based on CVSS scores</li>
                    <li><strong>Generates alerts</strong> for high-risk vulnerabilities</li>
                    <li><strong>Provides remediation guidance</strong></li>
                </ul>

                <h2 id="recall-management">Recall Management</h2>
                
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
                    <li>Navigate to <strong>Recalls</strong></li>
                    <li>Review active recalls</li>
                    <li>Assess impact on your organization</li>
                    <li>Track remediation progress</li>
                </ol>

                <h2 id="reporting">Reporting</h2>
                
                <h3>Report Generation</h3>
                <ol>
                    <li>Navigate to <strong>Reports</strong> → <strong>Generate Report</strong></li>
                    <li>Select report type:
                        <ul>
                            <li>Asset Summary</li>
                            <li>Vulnerability Report</li>
                            <li>Recall Status</li>
                            <li>Compliance Report</li>
                            <li>Device Mapping Report</li>
                            <li>Security Dashboard</li>
                        </ul>
                    </li>
                    <li>Set date range and filters</li>
                    <li>Choose export format (PDF, Excel, CSV, JSON)</li>
                    <li>Generate report</li>
                </ol>

                <h3>Scheduled Reports</h3>
                <p>Set up automated report generation:</p>
                <ol>
                    <li>Configure report schedule</li>
                    <li>Set recipients</li>
                    <li>Choose delivery method</li>
                    <li>Activate scheduling</li>
                </ol>

                <h2 id="user-management">User Management</h2>
                
                <h3>User Roles</h3>
                <ul>
                    <li><strong>Admin</strong>: Full system access and configuration</li>
                    <li><strong>User</strong>: Standard user access to features</li>
                </ul>

                <h3>User Administration</h3>
                <ol>
                    <li>Navigate to <strong>Admin</strong> → <strong>Users</strong></li>
                    <li>Add new users</li>
                    <li>Assign roles and permissions</li>
                    <li>Manage user access</li>
                </ol>

                <h2 id="troubleshooting">Troubleshooting</h2>
                
                <h3>Common Issues</h3>
                
                <h4>Login Problems</h4>
                <ul>
                    <li>Check your username and password</li>
                    <li>Verify MFA code is correct</li>
                    <li>Contact administrator if account is locked</li>
                </ul>

                <h4>Asset Import Issues</h4>
                <ul>
                    <li>Verify CSV format and column headers</li>
                    <li>Check for required fields</li>
                    <li>Review error messages in import log</li>
                </ul>

                <h4>Mapping Problems</h4>
                <ul>
                    <li>Verify device information is complete</li>
                    <li>Check manufacturer name spelling</li>
                    <li>Try manual mapping if automatic fails</li>
                </ul>

                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <strong>Need More Help?</strong> Contact your system administrator or refer to the Administrator Guide for advanced configuration options.
                </div>

                <div class="help-navigation">
                    <a href="/pages/help/quick-start.php" class="btn btn-secondary">
                        <i class="fas fa-rocket"></i>
                        Quick Start Guide
                    </a>
                    <a href="/pages/help/administrator-guide.php" class="btn btn-primary">
                        <i class="fas fa-cog"></i>
                        Administrator Guide
                    </a>
                </div>
            </div>
        </div>
    </main>

    <script>
        // User Guide JavaScript
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
