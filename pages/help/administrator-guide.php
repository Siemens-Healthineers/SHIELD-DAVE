<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
/**
 * Administrator Guide for Device Assessment and Vulnerability Exposure ()
 * Complete administrator documentation for system management and maintenance
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
    <title>Administrator Guide - <?php echo _NAME; ?></title>
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
                    <h1><i class="fas fa-cog"></i> Administrator Guide</h1>
                    <p>Complete administrator documentation for system management and maintenance</p>
                </div>
            </div>

            <div class="help-content">

            <div class="help-content">
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Administrator Access Required!</strong> This guide contains advanced system administration procedures. Ensure you have proper permissions before making changes.
                </div>

                <h2 id="table-of-contents">Table of Contents</h2>
                <ul>
                    <li><a href="#system-administration">System Administration</a></li>
                    <li><a href="#user-management">User Management</a></li>
                    <li><a href="#security-configuration">Security Configuration</a></li>
                    <li><a href="#database-management">Database Management</a></li>
                    <li><a href="#background-services">Background Services</a></li>
                    <li><a href="#monitoring-and-logging">Monitoring and Logging</a></li>
                    <li><a href="#backup-and-recovery">Backup and Recovery</a></li>
                    <li><a href="#performance-tuning">Performance Tuning</a></li>
                    <li><a href="#troubleshooting">Troubleshooting</a></li>
                    <li><a href="#maintenance-procedures">Maintenance Procedures</a></li>
                </ul>

                <h2 id="system-administration">System Administration</h2>
                
                <h3>System Overview</h3>
                <p>The  platform consists of several key components:</p>
                <ul>
                    <li><strong>Web Interface</strong>: PHP-based user interface</li>
                    <li><strong>API Layer</strong>: RESTful APIs for data access</li>
                    <li><strong>Background Services</strong>: Python services for automation</li>
                    <li><strong>Database</strong>: PostgreSQL for data persistence</li>
                    <li><strong>File Storage</strong>: Local file system for uploads and reports</li>
                </ul>

                <h3>System Requirements</h3>
                
                <h4>Minimum Requirements</h4>
                <ul>
                    <li><strong>CPU</strong>: 2 cores, 2.0 GHz</li>
                    <li><strong>RAM</strong>: 4 GB</li>
                    <li><strong>Storage</strong>: 50 GB SSD</li>
                    <li><strong>Network</strong>: 100 Mbps</li>
                </ul>

                <h4>Recommended Requirements</h4>
                <ul>
                    <li><strong>CPU</strong>: 4 cores, 3.0 GHz</li>
                    <li><strong>RAM</strong>: 8 GB</li>
                    <li><strong>Storage</strong>: 100 GB SSD</li>
                    <li><strong>Network</strong>: 1 Gbps</li>
                </ul>

                <h3>Installation and Setup</h3>
                
                <h4>Initial Installation</h4>
                <ol>
                    <li><strong>System Preparation</strong>
                        <pre><code># Update system packages
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y apache2 postgresql php php-pgsql python3 python3-pip</code></pre>
                    </li>
                    <li><strong>Database Setup</strong>
                        <pre><code># Create database and user
sudo -u postgres psql
CREATE DATABASE <database name>;
CREATE USER <database login> WITH PASSWORD <database password>;
GRANT ALL PRIVILEGES ON DATABASE dave TO <database login>;
\q</code></pre>
                    </li>
                    <li><strong>Application Deployment</strong>
                        <pre><code># Clone application
git clone https://github.com/yourorg/dave.git /var/www/html
cd /var/www/html

# Set permissions
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html</code></pre>
                    </li>
                </ol>

                <h2 id="user-management">User Management</h2>
                
                <h3>User Roles and Permissions</h3>
                <ul>
                    <li><strong>Admin</strong>: Full system access and configuration</li>
                    <li><strong>User</strong>: Standard user access to features</li>
                </ul>

                <h3>User Administration</h3>
                <ol>
                    <li>Navigate to <strong>Admin</strong> → <strong>Users</strong></li>
                    <li>Add new users with appropriate roles</li>
                    <li>Manage user permissions and access</li>
                    <li>Monitor user activity and sessions</li>
                </ol>

                <h2 id="security-configuration">Security Configuration</h2>
                
                <h3>Authentication Settings</h3>
                <ul>
                    <li><strong>Password Policy</strong>: Configure minimum requirements</li>
                    <li><strong>MFA Settings</strong>: Enable/disable multi-factor authentication</li>
                    <li><strong>Session Management</strong>: Configure session timeouts</li>
                    <li><strong>Account Lockout</strong>: Set lockout policies</li>
                </ul>

                <h3>Network Security</h3>
                <ul>
                    <li><strong>Firewall Configuration</strong>: Restrict access to necessary ports</li>
                    <li><strong>SSL/TLS</strong>: Configure HTTPS encryption</li>
                    <li><strong>IP Whitelisting</strong>: Restrict access by IP address</li>
                    <li><strong>VPN Integration</strong>: Secure remote access</li>
                </ul>

                <h2 id="database-management">Database Management</h2>
                
                <h3>Database Maintenance</h3>
                <ol>
                    <li><strong>Regular Backups</strong>
                        <pre><code># Create backup
pg_dump -h localhost -U <database login> <database name>  > backup_$(date +%Y%m%d).sql

# Restore backup
psql -h localhost -U <database login> dave < backup_20241201.sql</code></pre>
                    </li>
                    <li><strong>Performance Optimization</strong>
                        <ul>
                            <li>Monitor query performance</li>
                            <li>Optimize database indexes</li>
                            <li>Clean up old data</li>
                        </ul>
                    </li>
                </ol>

                <h3>Database Monitoring</h3>
                <ul>
                    <li><strong>Connection Monitoring</strong>: Track active connections</li>
                    <li><strong>Query Performance</strong>: Monitor slow queries</li>
                    <li><strong>Storage Usage</strong>: Monitor disk space</li>
                    <li><strong>Backup Status</strong>: Verify backup completion</li>
                </ul>

                <h2 id="background-services">Background Services</h2>
                
                <h3>Service Management</h3>
                <ul>
                    <li><strong>Recall Monitoring</strong>: Daily FDA recall checks</li>
                    <li><strong>Vulnerability Scanning</strong>: Weekly vulnerability assessments</li>
                    <li><strong>Health Checks</strong>: Hourly system health monitoring</li>
                    <li><strong>Data Cleanup</strong>: Automated data maintenance</li>
                </ul>

                <h3>Manual Task Management</h3>
                <ol>
                    <li>Navigate to <strong>Admin</strong> → <strong>Manual Tasks</strong></li>
                    <li>Run system health checks</li>
                    <li>Execute data consistency validation</li>
                    <li>Recalculate remediation actions and risk scores</li>
                    <li>Process SBOM queue for failed uploads</li>
                </ol>

                <h2 id="monitoring-and-logging">Monitoring and Logging</h2>
                
                <h3>System Monitoring</h3>
                <ul>
                    <li><strong>Performance Metrics</strong>: CPU, memory, disk usage</li>
                    <li><strong>Application Health</strong>: Service status and availability</li>
                    <li><strong>Database Performance</strong>: Query times and connections</li>
                    <li><strong>Network Monitoring</strong>: Bandwidth and connectivity</li>
                </ul>

                <h3>Log Management</h3>
                <ul>
                    <li><strong>Application Logs</strong>: User actions and system events</li>
                    <li><strong>Error Logs</strong>: System errors and exceptions</li>
                    <li><strong>Security Logs</strong>: Authentication and access attempts</li>
                    <li><strong>Audit Logs</strong>: Compliance and regulatory tracking</li>
                </ul>

                <h2 id="backup-and-recovery">Backup and Recovery</h2>
                
                <h3>Backup Strategy</h3>
                <ul>
                    <li><strong>Database Backups</strong>: Daily automated backups</li>
                    <li><strong>File Backups</strong>: Application files and uploads</li>
                    <li><strong>Configuration Backups</strong>: System settings and configurations</li>
                    <li><strong>Offsite Storage</strong>: Secure remote backup storage</li>
                </ul>

                <h3>Recovery Procedures</h3>
                <ol>
                    <li><strong>Database Recovery</strong>
                        <pre><code># Stop services
sudo systemctl stop apache2
sudo systemctl stop postgresql

# Restore database
sudo -u postgres psql -c "DROP DATABASE <database name>;"
sudo -u postgres psql -c "CREATE DATABASE <database name>;"
psql -h localhost -U <database login> <database name> < backup_file.sql

# Restart services
sudo systemctl start postgresql
sudo systemctl start apache2</code></pre>
                    </li>
                    <li><strong>File Recovery</strong>
                        <ul>
                            <li>Restore application files from backup</li>
                            <li>Restore uploaded files and reports</li>
                            <li>Verify file permissions</li>
                        </ul>
                    </li>
                </ol>

                <h2 id="performance-tuning">Performance Tuning</h2>
                
                <h3>Database Optimization</h3>
                <ul>
                    <li><strong>Index Optimization</strong>: Create and maintain proper indexes</li>
                    <li><strong>Query Optimization</strong>: Optimize slow queries</li>
                    <li><strong>Connection Pooling</strong>: Manage database connections</li>
                    <li><strong>Memory Configuration</strong>: Optimize PostgreSQL settings</li>
                </ul>

                <h3>Application Optimization</h3>
                <ul>
                    <li><strong>PHP Configuration</strong>: Optimize PHP settings</li>
                    <li><strong>Apache Configuration</strong>: Tune web server settings</li>
                    <li><strong>Caching</strong>: Implement application caching</li>
                    <li><strong>CDN Integration</strong>: Use content delivery networks</li>
                </ul>

                <h2 id="troubleshooting">Troubleshooting</h2>
                
                <h3>Common Issues</h3>
                
                <h4>Database Connection Issues</h4>
                <ul>
                    <li>Check PostgreSQL service status</li>
                    <li>Verify database credentials</li>
                    <li>Check network connectivity</li>
                    <li>Review database logs</li>
                </ul>

                <h4>Application Errors</h4>
                <ul>
                    <li>Check PHP error logs</li>
                    <li>Verify file permissions</li>
                    <li>Check Apache error logs</li>
                    <li>Review application logs</li>
                </ul>

                <h4>Performance Issues</h4>
                <ul>
                    <li>Monitor system resources</li>
                    <li>Check database performance</li>
                    <li>Review application logs</li>
                    <li>Optimize configurations</li>
                </ul>

                <h2 id="maintenance-procedures">Maintenance Procedures</h2>
                
                <h3>Regular Maintenance</h3>
                <ul>
                    <li><strong>Daily</strong>: Check system health and backups</li>
                    <li><strong>Weekly</strong>: Review logs and performance</li>
                    <li><strong>Monthly</strong>: Update system packages</li>
                    <li><strong>Quarterly</strong>: Security audits and reviews</li>
                </ul>

                <h3>Update Procedures</h3>
                <ol>
                    <li><strong>Backup System</strong>: Create full system backup</li>
                    <li><strong>Test Environment</strong>: Test updates in staging</li>
                    <li><strong>Apply Updates</strong>: Deploy updates to production</li>
                    <li><strong>Verify Functionality</strong>: Test all system functions</li>
                    <li><strong>Monitor Performance</strong>: Watch for issues</li>
                </ol>

                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <strong>Administrator Guide Complete!</strong> This guide covers all essential administrator procedures. For additional support, refer to the deployment guide or contact technical support.
                </div>

                <div class="help-navigation">
                    <a href="/pages/help/user-guide.php" class="btn btn-secondary">
                        <i class="fas fa-user"></i>
                        User Guide
                    </a>
                </div>
            </div>
                </div>
        </div>
    </main>

    <script>
        // Administrator Guide JavaScript
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
