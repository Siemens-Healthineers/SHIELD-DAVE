<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
/**
 * SBOM Evaluation Service Guide for Device Assessment and Vulnerability Exposure ()
 * Comprehensive guide for the Software Bill of Materials (SBOM) evaluation background service
 */

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/auth.php';

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
    <title>SBOM Evaluation Service Guide - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/help.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <?php include __DIR__ . '/../assets/templates/dashboard-header.php'; ?>

    <main class="main-content">
        <div class="help-content-container">
            <div class="help-page-header">
                <div class="container">
                    <h1><i class="fas fa-cogs"></i> SBOM Evaluation Service Guide</h1>
                    <p>Comprehensive guide for the Software Bill of Materials (SBOM) evaluation background service</p>
                </div>
            </div>

            <div class="help-content">
                <div class="page-actions" style="margin-bottom: 2rem;">
                    <a href="/docs/index.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Back to Documentation
                    </a>
                </div>
    <style>
        .help-content-container {
            max-width: 1440px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .help-page-header {
            background: linear-gradient(135deg, var(--siemens-petrol) 0%, var(--siemens-petrol-dark) 100%);
            color: white;
            padding: 40px 0;
            margin-bottom: 30px;
            border-radius: 10px;
        }
        
        .help-page-header .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }
        
        .help-page-header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        .help-page-header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        .help-content {
            max-width: 1200px;
            margin: 0 auto;
            line-height: 1.7;
        }
        
        .help-content h1 {
            color: var(--siemens-petrol);
            border-bottom: 3px solid var(--siemens-petrol);
            padding-bottom: 10px;
            margin-bottom: 30px;
        }
        
        .help-content h2 {
            color: var(--siemens-petrol);
            margin-top: 40px;
            margin-bottom: 20px;
            font-size: 1.8rem;
        }
        
        .help-content h3 {
            color: var(--text-primary);
            margin-top: 30px;
            margin-bottom: 15px;
            font-size: 1.4rem;
        }
        
        .help-content h4 {
            color: var(--text-primary);
            margin-top: 25px;
            margin-bottom: 10px;
            font-size: 1.2rem;
        }
        
        .help-content p {
            margin-bottom: 15px;
            color: var(--text-secondary);
        }
        
        .help-content ul, .help-content ol {
            margin-bottom: 20px;
            padding-left: 30px;
        }
        
        .help-content li {
            margin-bottom: 8px;
            color: var(--text-secondary);
        }
        
        .help-content code {
            background: var(--bg-tertiary);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: var(--siemens-orange);
        }
        
        .help-content pre {
            background: var(--bg-tertiary);
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            margin: 20px 0;
            border-left: 4px solid var(--siemens-petrol);
        }
        
        .help-content pre code {
            background: none;
            padding: 0;
            color: var(--text-primary);
        }
        
        .help-content table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .help-content th, .help-content td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-primary);
        }
        
        .help-content th {
            background: var(--siemens-petrol);
            color: white;
            font-weight: 600;
        }
        
        .help-content tr:hover {
            background: var(--bg-hover);
        }
        
        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid;
        }
        
        .alert-info {
            background: rgba(0, 153, 153, 0.1);
            border-color: var(--siemens-petrol);
            color: var(--text-primary);
        }
        
        .alert-warning {
            background: rgba(255, 107, 53, 0.1);
            border-color: var(--siemens-orange);
            color: var(--text-primary);
        }
        
        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            border-color: #10b981;
            color: var(--text-primary);
        }
        
        .alert-danger {
            background: rgba(239, 68, 68, 0.1);
            border-color: #ef4444;
            color: var(--text-primary);
        }
        
        .back-link {
            display: inline-flex;
            align-items: center;
            color: var(--siemens-petrol);
            text-decoration: none;
            margin-bottom: 20px;
            font-weight: 500;
        }
        
        .back-link:hover {
            color: var(--siemens-petrol-dark);
            text-decoration: underline;
        }
        
        .back-link i {
            margin-right: 8px;
        }
        
        .architecture-diagram {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border: 1px solid var(--border-primary);
            font-family: 'Courier New', monospace;
            white-space: pre;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="help-content-container">
        <div class="help-page-header">
            <div class="container">
                <h1>SBOM Evaluation Background Service</h1>
                <p>Comprehensive guide for the SBOM evaluation background service and vulnerability detection</p>
            </div>
        </div>
        
        <div class="help-content">
            <a href="/docs/index.php" class="back-link">
                <i class="fas fa-arrow-left"></i>
                Back to Documentation
            </a>
            
            <h1>SBOM Evaluation Background Service</h1>

            <h2>Overview</h2>

            <p>The SBOM Evaluation Service is a background process that automatically evaluates Software Bill of Materials (SBOMs) against the National Vulnerability Database (NVD) to identify security vulnerabilities in medical devices.</p>

            <h2>Features</h2>

            <ul>
                <li><strong>Automatic Queue Processing</strong>: Monitors the evaluation queue and processes SBOMs automatically</li>
                <li><strong>NVD API Rate Limiting</strong>: Respects NVD API rate limits (50 requests/30s without key, 100 with key)</li>
                <li><strong>Comprehensive Logging</strong>: Detailed logs of all evaluation attempts and results</li>
                <li><strong>Error Handling & Retries</strong>: Automatic retry mechanism for failed evaluations</li>
                <li><strong>Graceful Shutdown</strong>: Handles system signals for safe shutdown</li>
                <li><strong>Database Integration</strong>: Stores all results in PostgreSQL database</li>
            </ul>

            <h2>Architecture</h2>

            <div class="architecture-diagram">┌─────────────────┐
│  SBOM Upload    │
│   (Web UI)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Evaluation      │
│   Queue         │
│ (PostgreSQL)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────┐
│  Background     │────►│  NVD API    │
│   Service       │     │ (Rate       │
│  (Python)       │     │  Limited)   │
└────────┬────────┘     └─────────────┘
         │
         ▼
┌─────────────────┐
│ Vulnerabilities │
│   Database      │
└─────────────────┘</div>

            <h2>Installation</h2>

            <h3>Prerequisites</h3>

            <ul>
                <li>Python 3.x</li>
                <li>PostgreSQL database</li>
                <li>Required Python packages:
                    <ul>
                        <li><code>psycopg2-binary</code></li>
                        <li><code>requests</code></li>
                    </ul>
                </li>
            </ul>

            <h3>Automated Installation</h3>

            <p>Run the installation script as root:</p>

            <pre><code>sudo bash /var/www/html/services/install_service.sh</code></pre>

            <p>This script will:</p>
            <ol>
                <li>Install Python dependencies</li>
                <li>Create necessary directories</li>
                <li>Apply database migrations</li>
                <li>Install and start the systemd service</li>
            </ol>

            <h3>Manual Installation</h3>

            <p>If you prefer manual installation:</p>

            <pre><code># Install Python dependencies
pip3 install psycopg2-binary requests

# Create logs directory
sudo mkdir -p /var/www/html/logs
sudo chown www-data:www-data /var/www/html/logs

# Apply database migrations
sudo -u postgres psql -d <database name> -f /var/www/html/database/migrations/008_create_sbom_evaluation_queue.sql

# Copy and enable systemd service
sudo cp /var/www/html/services/dave-sbom-evaluation.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable dave-sbom-evaluation
sudo systemctl start dave-sbom-evaluation</code></pre>

            <h2>Configuration</h2>

            <h3>NVD API Key (Optional but Recommended)</h3>

            <p>To increase the API rate limit from 50 to 100 requests per 30 seconds:</p>

            <ol>
                <li>Obtain an API key from <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank">NVD</a></li>
                <li>Save it in the system configuration page or directly to <code>/var/www/html/config/nvd_api_key.txt</code></li>
            </ol>

            <p>The service will automatically detect and use the API key.</p>

            <h3>Database Configuration</h3>

            <p>The service reads database configuration from <code>/var/www/html/config/database.php</code>.</p>

            <p>Default configuration:</p>
            <pre><code>'host' => '<Database host>',
'database' => '<Database name>',
'username' => '<Database user>',
'password' => '<Database password>'</code></pre>

            <h2>Usage</h2>

            <h3>Automatic Queueing</h3>

            <p>When an SBOM is uploaded through the web interface, it is automatically queued for evaluation. No manual action is required.</p>

            <h3>Manual Queue Management</h3>

            <p>To manually queue an SBOM for evaluation:</p>

            <pre><code>INSERT INTO sbom_evaluation_queue (sbom_id, device_id, priority, status, queued_by)
VALUES ('your-sbom-id', 'your-device-id', 5, 'Queued', 'your-user-id');</code></pre>

            <p>Priority ranges from 1 (highest) to 10 (lowest).</p>

            <h3>Monitoring</h3>

            <h4>Web Dashboard</h4>

            <p>Access the monitoring dashboard at:</p>
            <pre><code>https://your-server/pages/vulnerabilities/evaluation-queue.php</code></pre>

            <p>The dashboard shows:</p>
            <ul>
                <li>Queue statistics (queued, processing, completed, failed)</li>
                <li>Current queue items</li>
                <li>Recent evaluation logs</li>
                <li>Average evaluation duration</li>
                <li>API usage statistics</li>
            </ul>

            <h4>Command Line</h4>

            <p>View service status:</p>
            <pre><code>sudo systemctl status dave-sbom-evaluation</code></pre>

            <p>View live logs:</p>
            <pre><code>sudo journalctl -u dave-sbom-evaluation -f</code></pre>

            <p>View log file:</p>
            <pre><code>tail -f /var/www/html/logs/sbom_evaluation.log</code></pre>

            <h2>Service Management</h2>

            <h3>Start Service</h3>
            <pre><code>sudo systemctl start dave-sbom-evaluation</code></pre>

            <h3>Stop Service</h3>
            <pre><code>sudo systemctl stop dave-sbom-evaluation</code></pre>

            <h3>Restart Service</h3>
            <pre><code>sudo systemctl restart dave-sbom-evaluation</code></pre>

            <h3>Enable Auto-start</h3>
            <pre><code>sudo systemctl enable dave-sbom-evaluation</code></pre>

            <h3>Disable Auto-start</h3>
            <pre><code>sudo systemctl disable dave-sbom-evaluation</code></pre>

            <h3>Check Service Status</h3>
            <pre><code>sudo systemctl status dave-sbom-evaluation</code></pre>

            <h2>Database Schema</h2>

            <h3>sbom_evaluation_queue</h3>

            <p>Tracks the evaluation queue:</p>

            <table>
                <thead>
                    <tr>
                        <th>Column</th>
                        <th>Type</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>queue_id</td>
                        <td>UUID</td>
                        <td>Primary key</td>
                    </tr>
                    <tr>
                        <td>sbom_id</td>
                        <td>UUID</td>
                        <td>SBOM to evaluate</td>
                    </tr>
                    <tr>
                        <td>device_id</td>
                        <td>UUID</td>
                        <td>Device associated with SBOM</td>
                    </tr>
                    <tr>
                        <td>priority</td>
                        <td>INTEGER</td>
                        <td>Priority (1-10, lower is higher priority)</td>
                    </tr>
                    <tr>
                        <td>status</td>
                        <td>VARCHAR</td>
                        <td>Queued, Processing, Completed, Failed</td>
                    </tr>
                    <tr>
                        <td>queued_at</td>
                        <td>TIMESTAMP</td>
                        <td>When queued</td>
                    </tr>
                    <tr>
                        <td>started_at</td>
                        <td>TIMESTAMP</td>
                        <td>When processing started</td>
                    </tr>
                    <tr>
                        <td>completed_at</td>
                        <td>TIMESTAMP</td>
                        <td>When completed</td>
                    </tr>
                    <tr>
                        <td>vulnerabilities_found</td>
                        <td>INTEGER</td>
                        <td>Number of vulnerabilities found</td>
                    </tr>
                    <tr>
                        <td>components_evaluated</td>
                        <td>INTEGER</td>
                        <td>Number of components evaluated</td>
                    </tr>
                    <tr>
                        <td>error_message</td>
                        <td>TEXT</td>
                        <td>Error message if failed</td>
                    </tr>
                    <tr>
                        <td>retry_count</td>
                        <td>INTEGER</td>
                        <td>Number of retry attempts</td>
                    </tr>
                </tbody>
            </table>

            <h3>sbom_evaluation_logs</h3>

            <p>Detailed logs of all evaluations:</p>

            <table>
                <thead>
                    <tr>
                        <th>Column</th>
                        <th>Type</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>log_id</td>
                        <td>UUID</td>
                        <td>Primary key</td>
                    </tr>
                    <tr>
                        <td>queue_id</td>
                        <td>UUID</td>
                        <td>Reference to queue item</td>
                    </tr>
                    <tr>
                        <td>sbom_id</td>
                        <td>UUID</td>
                        <td>SBOM evaluated</td>
                    </tr>
                    <tr>
                        <td>device_id</td>
                        <td>UUID</td>
                        <td>Device evaluated</td>
                    </tr>
                    <tr>
                        <td>evaluation_started_at</td>
                        <td>TIMESTAMP</td>
                        <td>Start time</td>
                    </tr>
                    <tr>
                        <td>evaluation_completed_at</td>
                        <td>TIMESTAMP</td>
                        <td>End time</td>
                    </tr>
                    <tr>
                        <td>evaluation_duration_seconds</td>
                        <td>INTEGER</td>
                        <td>Duration in seconds</td>
                    </tr>
                    <tr>
                        <td>components_evaluated</td>
                        <td>INTEGER</td>
                        <td>Components processed</td>
                    </tr>
                    <tr>
                        <td>vulnerabilities_found</td>
                        <td>INTEGER</td>
                        <td>Vulnerabilities discovered</td>
                    </tr>
                    <tr>
                        <td>vulnerabilities_stored</td>
                        <td>INTEGER</td>
                        <td>Vulnerabilities stored</td>
                    </tr>
                    <tr>
                        <td>nvd_api_calls_made</td>
                        <td>INTEGER</td>
                        <td>API calls made</td>
                    </tr>
                    <tr>
                        <td>nvd_api_failures</td>
                        <td>INTEGER</td>
                        <td>API failures</td>
                    </tr>
                    <tr>
                        <td>status</td>
                        <td>VARCHAR</td>
                        <td>Success, Failed, Partial</td>
                    </tr>
                    <tr>
                        <td>error_message</td>
                        <td>TEXT</td>
                        <td>Error details if failed</td>
                    </tr>
                </tbody>
            </table>

            <h2>Rate Limiting</h2>

            <p>The service implements automatic rate limiting to comply with NVD API requirements:</p>

            <ul>
                <li><strong>Without API Key</strong>: 50 requests per 30 seconds</li>
                <li><strong>With API Key</strong>: 100 requests per 30 seconds</li>
            </ul>

            <p>The rate limiter:</p>
            <ul>
                <li>Tracks request times in a sliding window</li>
                <li>Automatically waits if rate limit is reached</li>
                <li>Logs wait times for monitoring</li>
            </ul>

            <h2>Error Handling</h2>

            <p>The service includes comprehensive error handling:</p>

            <ol>
                <li><strong>Automatic Retries</strong>: Failed evaluations are retried up to 3 times</li>
                <li><strong>Error Logging</strong>: All errors are logged with full context</li>
                <li><strong>Graceful Degradation</strong>: Individual component failures don't stop the entire evaluation</li>
                <li><strong>Status Tracking</strong>: Failed items are marked in the queue for investigation</li>
            </ol>

            <h2>Performance</h2>

            <p>Typical performance metrics:</p>

            <ul>
                <li><strong>Small SBOM</strong> (10-50 components): 30-60 seconds</li>
                <li><strong>Medium SBOM</strong> (50-200 components): 1-5 minutes</li>
                <li><strong>Large SBOM</strong> (200+ components): 5-20 minutes</li>
            </ul>

            <p>Actual time depends on:</p>
            <ul>
                <li>Number of components</li>
                <li>Components with CPE identifiers</li>
                <li>NVD API response time</li>
                <li>Rate limiting delays</li>
            </ul>

            <h2>Troubleshooting</h2>

            <h3>Service Won't Start</h3>

            <p>Check logs:</p>
            <pre><code>sudo journalctl -u dave-sbom-evaluation -n 50</code></pre>

            <p>Common issues:</p>
            <ul>
                <li>Python dependencies not installed</li>
                <li>Database connection failed</li>
                <li>Permissions on log directory</li>
            </ul>

            <h3>No Items Processing</h3>

            <p>Check if service is running:</p>
            <pre><code>sudo systemctl status dave-sbom-evaluation</code></pre>

            <p>Check if items are in queue:</p>
            <pre><code>SELECT * FROM sbom_evaluation_queue WHERE status = 'Queued';</code></pre>

            <h3>Slow Processing</h3>

            <ul>
                <li>Check if NVD API key is configured</li>
                <li>Monitor API response times in logs</li>
                <li>Check network connectivity</li>
                <li>Review rate limiting delays in logs</li>
            </ul>

            <h3>Database Errors</h3>

            <p>Check PostgreSQL logs:</p>
            <pre><code>sudo tail -f /var/log/postgresql/postgresql-*.log</code></pre>

            <p>Verify database schema is up to date:</p>
            <pre><code>sudo -u postgres psql -d <database name> -c "\d sbom_evaluation_queue"</code></pre>

            <h2>Security Considerations</h2>

            <ol>
                <li><strong>API Key Storage</strong>: Store NVD API key securely in <code>/var/www/html/config/nvd_api_key.txt</code> with restricted permissions</li>
                <li><strong>Database Credentials</strong>: Use strong passwords for database access</li>
                <li><strong>Service User</strong>: Service runs as <code>www-data</code> user with minimal privileges</li>
                <li><strong>Network Access</strong>: Ensure outbound HTTPS access to nvd.nist.gov</li>
                <li><strong>Log Rotation</strong>: Configure log rotation to prevent disk space issues</li>
            </ol>

            <h2>Maintenance</h2>

            <h3>Log Rotation</h3>

            <p>Configure logrotate for service logs:</p>

            <pre><code>sudo cat > /etc/logrotate.d/dave-sbom-evaluation << EOF
/var/www/html/logs/sbom_evaluation.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 www-data www-data
    postrotate
        systemctl reload dave-sbom-evaluation > /dev/null 2>&1 || true
    endscript
}
EOF</code></pre>

            <h3>Database Cleanup</h3>

            <p>Periodically clean old completed evaluations:</p>

            <pre><code>DELETE FROM sbom_evaluation_queue 
WHERE status = 'Completed' 
  AND completed_at < NOW() - INTERVAL '90 days';

DELETE FROM sbom_evaluation_logs 
WHERE evaluation_completed_at < NOW() - INTERVAL '90 days';</code></pre>

            <h3>Monitoring</h3>

            <p>Set up monitoring alerts for:</p>
            <ul>
                <li>Service down/stopped</li>
                <li>High failure rate</li>
                <li>Queue backup (too many queued items)</li>
                <li>Evaluation duration exceeds threshold</li>
                <li>API errors</li>
            </ul>

            <h2>Best Practices</h2>

            <ol>
                <li><strong>Configure NVD API Key</strong>: Increases rate limit and improves performance</li>
                <li><strong>Monitor Queue Regularly</strong>: Check the web dashboard daily</li>
                <li><strong>Review Failed Evaluations</strong>: Investigate and fix failures promptly</li>
                <li><strong>Prioritize Critical Devices</strong>: Use lower priority numbers for critical devices</li>
                <li><strong>Clean Old Data</strong>: Regularly purge old evaluation logs</li>
                <li><strong>Update Service</strong>: Keep Python packages and service code updated</li>
                <li><strong>Test After Updates</strong>: Verify service functionality after any updates</li>
            </ol>

            <h2>Support</h2>

            <p>For issues or questions:</p>
            <ol>
                <li>Check the logs first</li>
                <li>Review this documentation</li>
                <li>Check GitHub issues</li>
                <li>Contact system administrator</li>
            </ol>

            <h2>License</h2>

            <p>Copyright (c) 2026 Siemens Healthineers - All rights reserved</p>
            </div>
        </div>
    </main>

    <?php include __DIR__ . '/../assets/templates/dashboard-footer.php'; ?>
    <script src="/assets/js/jquery-3.6.0.min.js"></script>
    <script src="/assets/js/main.js"></script>
</body>
</html>
