<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
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
    <title>EPSS Integration Guide - <?php echo _NAME; ?></title>
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
                    <h1><i class="fas fa-chart-line"></i> EPSS Integration Guide</h1>
                    <p>Comprehensive guide for integrating with Exploit Prediction Scoring System (EPSS)</p>
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
    </style>
</head>
<body>
    <div class="help-content-container">
        <div class="help-page-header">
            <div class="container">
                <h1>EPSS Integration Guide</h1>
                <p>Comprehensive guide for EPSS (Exploit Prediction Scoring System) integration in vulnerability management</p>
            </div>
        </div>
        
        <div class="help-content">
            <a href="/docs/index.php" class="back-link">
                <i class="fas fa-arrow-left"></i>
                Back to Documentation
            </a>
            
            <h1>EPSS Integration Guide</h1>

            <p><strong>Device Assessment and Vulnerability Exposure ()</strong><br>
            <strong>EPSS (Exploit Prediction Scoring System) Integration Documentation</strong></p>

            <hr>

            <p><strong>SPDX-License-Identifier: AGPL-3.0-or-later</strong></p>
            <p><strong>SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers</strong></p>

            <hr>

            <h2>Table of Contents</h2>

            <ol>
                <li><a href="#what-is-epss">What is EPSS?</a></li>
                <li><a href="#epss-integration-overview">EPSS Integration Overview</a></li>
                <li><a href="#epss-scores-in-risk-calculations">EPSS Scores in Risk Calculations</a></li>
                <li><a href="#using-epss-in-the-ui">Using EPSS in the UI</a></li>
                <li><a href="#understanding-epss-trends">Understanding EPSS Trends</a></li>
                <li><a href="#admin-configuration">Admin Configuration</a></li>
                <li><a href="#troubleshooting">Troubleshooting</a></li>
                <li><a href="#api-reference">API Reference</a></li>
            </ol>

            <hr>

            <h2 id="what-is-epss">What is EPSS?</h2>

            <p>The <strong>Exploit Prediction Scoring System (EPSS)</strong> is a data-driven effort for estimating the likelihood (probability) that a software vulnerability will be exploited in the wild. EPSS is developed by the <a href="https://www.first.org/epss/" target="_blank">Forum of Incident Response and Security Teams (FIRST)</a>.</p>

            <h3>Key Concepts</h3>

            <ul>
                <li><strong>EPSS Score</strong>: A probability score between 0.0 and 1.0 indicating the likelihood of exploitation</li>
                <li><strong>EPSS Percentile</strong>: A ranking from 0.0 to 1.0 showing how a CVE compares to all other CVEs</li>
                <li><strong>Daily Updates</strong>: EPSS scores are updated daily based on new threat intelligence</li>
                <li><strong>Historical Tracking</strong>: The system tracks EPSS score changes over time for trend analysis</li>
            </ul>

            <h3>EPSS Risk Levels</h3>

            <table>
                <thead>
                    <tr>
                        <th>Risk Level</th>
                        <th>Score Range</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>High</strong></td>
                        <td>≥ 70%</td>
                        <td>High exploitation probability - immediate attention recommended</td>
                    </tr>
                    <tr>
                        <td><strong>Medium</strong></td>
                        <td>30% - 69%</td>
                        <td>Medium exploitation probability - monitor closely</td>
                    </tr>
                    <tr>
                        <td><strong>Low</strong></td>
                        <td>&lt; 30%</td>
                        <td>Low exploitation probability - standard priority</td>
                    </tr>
                </tbody>
            </table>

            <hr>

            <h2 id="epss-integration-overview">EPSS Integration Overview</h2>

            <p>The  system integrates EPSS data to enhance vulnerability prioritization by combining:</p>

            <ol>
                <li><strong>CVSS Scores</strong> - Technical severity</li>
                <li><strong>KEV Status</strong> - Known exploitation</li>
                <li><strong>EPSS Scores</strong> - Exploitation likelihood prediction</li>
                <li><strong>Asset Criticality</strong> - Business impact</li>
                <li><strong>Location Criticality</strong> - Environmental factors</li>
            </ol>

            <h3>Data Flow</h3>

            <pre><code>FIRST.org EPSS API → EPSS Sync Service → Database → Risk Calculations → UI Display</code></pre>

            <h3>Daily Sync Process</h3>

            <ul>
                <li><strong>Schedule</strong>: Daily at 2:00 AM (offset from KEV sync at 1:00 AM)</li>
                <li><strong>Source</strong>: <a href="https://www.first.org/epss/api" target="_blank">FIRST.org EPSS API</a></li>
                <li><strong>Coverage</strong>: All CVEs with EPSS scores (~200,000+ vulnerabilities)</li>
                <li><strong>Historical</strong>: Daily snapshots stored for trend analysis</li>
            </ul>

            <hr>

            <h2 id="epss-scores-in-risk-calculations">EPSS Scores in Risk Calculations</h2>

            <h3>Risk Score Formula</h3>

            <p>The risk score calculation now includes an EPSS component:</p>

            <pre><code>Risk Score = KEV Weight + Asset Criticality + Location Criticality + CVSS Severity + EPSS Component</code></pre>

            <h3>EPSS Component</h3>

            <pre><code>EPSS Component = CASE 
    WHEN epss_weight_enabled = TRUE AND epss_score >= epss_high_threshold 
    THEN epss_weight_score 
    ELSE 0 
END</code></pre>

            <h3>Default Configuration</h3>

            <ul>
                <li><strong>EPSS Weight Enabled</strong>: <code>true</code></li>
                <li><strong>High EPSS Threshold</strong>: <code>0.7</code> (70%)</li>
                <li><strong>EPSS Weight Score</strong>: <code>20</code> points</li>
            </ul>

            <h3>Example Calculation</h3>

            <p>For a vulnerability with:</p>
            <ul>
                <li><strong>KEV</strong>: No (0 points)</li>
                <li><strong>Asset Criticality</strong>: Clinical-High (100 points)</li>
                <li><strong>Location Criticality</strong>: 8/10 (40 points)</li>
                <li><strong>CVSS Severity</strong>: Critical (40 points)</li>
                <li><strong>EPSS Score</strong>: 0.85 (85% - above 70% threshold)</li>
            </ul>

            <p><strong>Total Risk Score</strong>: 0 + 100 + 40 + 40 + 20 = <strong>200 points</strong></p>

            <hr>

            <h2 id="using-epss-in-the-ui">Using EPSS in the UI</h2>

            <h3>Vulnerability List Page</h3>

            <p>The vulnerability list now includes an <strong>EPSS</strong> column showing:</p>

            <ul>
                <li><strong>EPSS Badge</strong>: Color-coded badge with score percentage</li>
                <li><strong>Tooltip</strong>: Hover to see percentile ranking</li>
                <li><strong>Sortable</strong>: Click column header to sort by EPSS score</li>
                <li><strong>Filterable</strong>: Use EPSS filter dropdown</li>
            </ul>

            <h4>EPSS Filter Options</h4>

            <ul>
                <li><strong>All</strong>: Show all vulnerabilities</li>
                <li><strong>High Risk (≥70%)</strong>: Show only high EPSS vulnerabilities</li>
                <li><strong>Medium Risk (30-69%)</strong>: Show medium EPSS vulnerabilities</li>
                <li><strong>Low Risk (&lt;30%)</strong>: Show low EPSS vulnerabilities</li>
            </ul>

            <h3>Risk Priorities Dashboard</h3>

            <p>The risk priorities dashboard includes:</p>

            <ul>
                <li><strong>EPSS Column</strong>: Shows EPSS score for each priority</li>
                <li><strong>EPSS Summary Card</strong>: Displays high-risk EPSS count and averages</li>
                <li><strong>EPSS Filtering</strong>: Filter priorities by EPSS risk level</li>
            </ul>

            <h3>Vulnerability Details</h3>

            <p>When viewing vulnerability details, you'll see:</p>

            <ul>
                <li><strong>Current EPSS Score</strong>: Large display with progress bar</li>
                <li><strong>EPSS Percentile</strong>: Relative ranking among all CVEs</li>
                <li><strong>Last Updated</strong>: Timestamp of last EPSS data</li>
                <li><strong>Trend Chart</strong>: 30-day EPSS score history</li>
                <li><strong>Status Indicator</strong>: Shows if data is recent or stale</li>
            </ul>

            <hr>

            <h2 id="understanding-epss-trends">Understanding EPSS Trends</h2>

            <h3>Trend Analysis</h3>

            <p>EPSS scores change over time as new threat intelligence becomes available. The system tracks these changes to identify:</p>

            <ul>
                <li><strong>Rising Threats</strong>: Vulnerabilities with increasing EPSS scores</li>
                <li><strong>Stabilizing Threats</strong>: Vulnerabilities with consistent scores</li>
                <li><strong>Declining Threats</strong>: Vulnerabilities with decreasing scores</li>
            </ul>

            <h3>Trend Chart Features</h3>

            <ul>
                <li><strong>30-Day History</strong>: Default view shows last 30 days</li>
                <li><strong>Interactive Tooltips</strong>: Hover for exact values</li>
                <li><strong>Color Coding</strong>: Chart color matches risk level</li>
                <li><strong>Responsive Design</strong>: Works on all screen sizes</li>
            </ul>

            <h3>Trending Vulnerabilities</h3>

            <p>The system identifies vulnerabilities with the largest EPSS score increases, helping prioritize:</p>

            <ul>
                <li><strong>Newly Exploited</strong>: CVEs with recent exploitation activity</li>
                <li><strong>Emerging Threats</strong>: CVEs gaining attention from threat actors</li>
                <li><strong>Escalating Risk</strong>: CVEs requiring immediate attention</li>
            </ul>

            <hr>

            <h2 id="admin-configuration">Admin Configuration</h2>

            <h3>Risk Matrix Configuration</h3>

            <p>Administrators can configure EPSS integration through the Risk Matrix settings:</p>

            <h4>EPSS Settings</h4>

            <ol>
                <li><strong>Include EPSS in Risk Scoring</strong>
                    <ul>
                        <li>Toggle to enable/disable EPSS in risk calculations</li>
                        <li>Default: <code>Enabled</code></li>
                    </ul>
                </li>
                <li><strong>High EPSS Threshold</strong>
                    <ul>
                        <li>Score threshold for high-risk classification</li>
                        <li>Range: 0.0 - 1.0</li>
                        <li>Default: <code>0.7</code> (70%)</li>
                    </ul>
                </li>
                <li><strong>EPSS Weight Score</strong>
                    <ul>
                        <li>Points added to risk score for high EPSS vulnerabilities</li>
                        <li>Range: 0 - 100</li>
                        <li>Default: <code>20</code> points</li>
                    </ul>
                </li>
            </ol>

            <h4>Configuration Impact</h4>

            <p>When EPSS settings are changed:</p>

            <ol>
                <li><strong>Immediate Effect</strong>: New risk calculations use updated settings</li>
                <li><strong>Recalculation</strong>: All existing vulnerabilities are recalculated</li>
                <li><strong>Materialized View Refresh</strong>: Risk priority view is updated</li>
                <li><strong>Audit Log</strong>: Changes are logged for compliance</li>
            </ol>

            <h3>Sync Status Monitoring</h3>

            <p>Administrators can monitor EPSS sync status:</p>

            <ul>
                <li><strong>Last Sync Time</strong>: When data was last updated</li>
                <li><strong>Sync Success/Failure</strong>: Status of last sync operation</li>
                <li><strong>Coverage Statistics</strong>: How many vulnerabilities have EPSS data</li>
                <li><strong>Error Messages</strong>: Details of any sync failures</li>
            </ul>

            <hr>

            <h2 id="troubleshooting">Troubleshooting</h2>

            <h3>Common Issues</h3>

            <h4>EPSS Data Not Updating</h4>

            <p><strong>Symptoms</strong>: EPSS scores showing as "N/A" or old timestamps</p>

            <p><strong>Solutions</strong>:</p>
            <ol>
                <li>Check sync service logs: <code>/var/www/html/logs/epss_sync.log</code></li>
                <li>Verify cron job is running: <code>crontab -l -u www-data</code></li>
                <li>Test manual sync: <code>/var/www/html/services/test_epss_sync.sh</code></li>
                <li>Check database connectivity and permissions</li>
            </ol>

            <h4>High EPSS Threshold Not Working</h4>

            <p><strong>Symptoms</strong>: Vulnerabilities with high EPSS scores not getting additional risk points</p>

            <p><strong>Solutions</strong>:</p>
            <ol>
                <li>Verify EPSS weight is enabled in Risk Matrix configuration</li>
                <li>Check threshold value (should be 0.0 - 1.0)</li>
                <li>Ensure EPSS weight score is greater than 0</li>
                <li>Refresh risk priorities after configuration changes</li>
            </ol>

            <h4>Trend Charts Not Displaying</h4>

            <p><strong>Symptoms</strong>: EPSS trend charts showing as blank or error</p>

            <p><strong>Solutions</strong>:</p>
            <ol>
                <li>Check browser console for JavaScript errors</li>
                <li>Verify Chart.js library is loaded</li>
                <li>Ensure API endpoint is accessible: <code>/api/v1/epss/trends/{cve_id}</code></li>
                <li>Check network connectivity and CORS settings</li>
            </ol>

            <h4>Sync Service Failures</h4>

            <p><strong>Symptoms</strong>: Daily sync failing with errors</p>

            <p><strong>Solutions</strong>:</p>
            <ol>
                <li>Check Python dependencies: <code>pip3 list | grep -E "(requests|psycopg2)"</code></li>
                <li>Verify database credentials in environment variables</li>
                <li>Check network connectivity to FIRST.org API</li>
                <li>Review sync service logs for specific error messages</li>
            </ol>

            <h3>Log Files</h3>

            <ul>
                <li><strong>EPSS Sync Log</strong>: <code>/var/www/html/logs/epss_sync.log</code></li>
                <li><strong>Database Sync Log</strong>: <code>epss_sync_log</code> table</li>
                <li><strong>System Logs</strong>: <code>system_logs</code> table for EPSS operations</li>
            </ul>

            <h3>Manual Operations</h3>

            <h4>Force EPSS Sync</h4>

            <pre><code># Run EPSS sync manually
/usr/bin/python3 /var/www/html/services/epss_sync_service.py

# Check sync status
/var/www/html/services/check_epss_status.sh</code></pre>

            <h4>Refresh Risk Priorities</h4>

            <pre><code>-- Refresh materialized view
SELECT refresh_risk_priorities();

-- Archive historical EPSS scores
SELECT archive_epss_historical_scores();</code></pre>

            <hr>

            <h2 id="api-reference">API Reference</h2>

            <h3>EPSS Analytics API</h3>

            <h4>Get EPSS Statistics</h4>
            <pre><code>GET /api/v1/epss/</code></pre>

            <p><strong>Response</strong>:</p>
            <pre><code>{
  "success": true,
  "data": {
    "overall": {
      "total_vulnerabilities": 1500,
      "vulnerabilities_with_epss": 1200,
      "high_epss_count": 45,
      "avg_epss_score": 0.1234,
      "last_epss_update": "2025-01-10T02:30:00Z"
    },
    "by_severity": [...],
    "recent_trends": [...]
  }
}</code></pre>

            <h4>Get EPSS Trends for CVE</h4>
            <pre><code>GET /api/v1/epss/trends/{cve_id}?days=30</code></pre>

            <p><strong>Response</strong>:</p>
            <pre><code>{
  "success": true,
  "data": {
    "cve_id": "CVE-2024-1234",
    "current": {
      "epss_score": 0.8542,
      "epss_percentile": 0.9876,
      "epss_date": "2025-01-10",
      "epss_last_updated": "2025-01-10T02:30:00Z"
    },
    "trend": [
      {
        "recorded_date": "2025-01-09",
        "epss_score": 0.8234,
        "epss_percentile": 0.9856
      }
    ]
  }
}</code></pre>

            <h4>Get High-Risk Vulnerabilities</h4>
            <pre><code>GET /api/v1/epss/high-risk?threshold=0.7&limit=20</code></pre>

            <h4>Get Trending Vulnerabilities</h4>
            <pre><code>GET /api/v1/epss/trending?days=7&limit=10</code></pre>

            <h4>Get Sync Status</h4>
            <pre><code>GET /api/v1/epss/sync-status</code></pre>

            <h3>Vulnerabilities API (Updated)</h3>

            <h4>List Vulnerabilities with EPSS</h4>
            <pre><code>GET /api/v1/vulnerabilities?epss-gt=0.7&sort=epss&sort_dir=desc</code></pre>

            <p><strong>New Query Parameters</strong>:</p>
            <ul>
                <li><code>epss-gt</code>: Filter by EPSS score greater than value</li>
                <li><code>epss-percentile-gt</code>: Filter by EPSS percentile greater than value</li>
                <li><code>sort=epss</code>: Sort by EPSS score</li>
                <li><code>sort=epss_percentile</code>: Sort by EPSS percentile</li>
            </ul>

            <p><strong>Response includes</strong>:</p>
            <pre><code>{
  "epss_score": 0.8542,
  "epss_percentile": 0.9876,
  "epss_date": "2025-01-10",
  "epss_last_updated": "2025-01-10T02:30:00Z"
}</code></pre>

            <h3>Risk Matrix API (Updated)</h3>

            <h4>Update Risk Matrix with EPSS</h4>
            <pre><code>PUT /api/v1/admin/risk-matrix</code></pre>

            <p><strong>Request Body</strong>:</p>
            <pre><code>{
  "config_name": "Updated Risk Matrix with EPSS",
  "epss_weight_enabled": true,
  "epss_high_threshold": 0.7,
  "epss_weight_score": 20,
  "kev_weight": 1000,
  "clinical_high_score": 100,
  "business_medium_score": 50,
  "non_essential_score": 10,
  "location_weight_multiplier": 5,
  "critical_severity_score": 40,
  "high_severity_score": 28,
  "medium_severity_score": 16,
  "low_severity_score": 4
}</code></pre>

            <hr>

            <h2>Best Practices</h2>

            <h3>For Security Teams</h3>

            <ol>
                <li><strong>Daily Review</strong>: Check high EPSS vulnerabilities daily</li>
                <li><strong>Trend Monitoring</strong>: Watch for vulnerabilities with rising EPSS scores</li>
                <li><strong>Risk Prioritization</strong>: Use EPSS to supplement CVSS and KEV data</li>
                <li><strong>Historical Analysis</strong>: Review EPSS trends to understand threat evolution</li>
            </ol>

            <h3>For Administrators</h3>

            <ol>
                <li><strong>Regular Monitoring</strong>: Check sync status and coverage statistics</li>
                <li><strong>Threshold Tuning</strong>: Adjust EPSS thresholds based on organizational risk tolerance</li>
                <li><strong>Performance Monitoring</strong>: Monitor API response times and database performance</li>
                <li><strong>Backup Strategy</strong>: Ensure EPSS historical data is included in backups</li>
            </ol>

            <h3>For Developers</h3>

            <ol>
                <li><strong>API Usage</strong>: Use EPSS APIs for custom integrations</li>
                <li><strong>Error Handling</strong>: Implement proper error handling for EPSS data</li>
                <li><strong>Caching</strong>: Consider caching EPSS statistics for dashboard performance</li>
                <li><strong>Testing</strong>: Test EPSS features with various score ranges and edge cases</li>
            </ol>

            <hr>

            <h2>Support and Resources</h2>

            <h3>Documentation</h3>

            <ul>
                <li><a href="https://www.first.org/epss/" target="_blank">FIRST.org EPSS Documentation</a></li>
                <li><a href="https://www.first.org/epss/api" target="_blank">EPSS API Documentation</a></li>
                <li><a href="docs/api-fields-reference.md"> API Documentation</a></li>
            </ul>

            <h3>Contact</h3>

            <p>For technical support or questions about EPSS integration:</p>

            <ul>
                <li><strong>System Administrator</strong>: Check system logs and sync status</li>
                <li><strong>Database Administrator</strong>: Review EPSS sync logs and database performance</li>
                <li><strong>Security Team</strong>: Verify EPSS data accuracy and risk calculations</li>
            </ul>

            <hr>

            <p><strong>Last Updated</strong>: 2025-01-10<br>
            <strong>Version</strong>: 1.0.0</p>
            </div>
        </div>
    </main>

    <?php include __DIR__ . '/../assets/templates/dashboard-footer.php'; ?>
    <script src="/assets/js/jquery-3.6.0.min.js"></script>
    <script src="/assets/js/main.js"></script>
</body>
</html>
