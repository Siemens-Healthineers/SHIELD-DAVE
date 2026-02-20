<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

/**
 * CISA KEV Integration Guide for Device Assessment and Vulnerability Exposure ()
 * Comprehensive guide for integrating with CISA's Known Exploited Vulnerabilities (KEV) catalog
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
    <title>CISA KEV Integration Guide - <?php echo _NAME; ?></title>
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
                    <h1><i class="fas fa-shield-virus"></i> CISA KEV Integration Guide</h1>
                    <p>Comprehensive guide for integrating with CISA's Known Exploited Vulnerabilities (KEV) catalog</p>
                </div>
            </div>

            <div class="help-content">
                <div class="page-actions" style="margin-bottom: 2rem;">
                    <a href="/docs/index.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Back to Documentation
                    </a>
                </div>
            
            <h1>CISA KEV Integration Documentation</h1>

            <h2>Overview</h2>

            <p>The CISA Known Exploited Vulnerabilities (KEV) Catalog integration automatically identifies vulnerabilities in your medical devices that are actively being exploited in the wild. This provides critical security intelligence for prioritizing remediation efforts.</p>

            <h2>What is CISA KEV?</h2>

            <p>The CISA KEV Catalog is a curated list of vulnerabilities that have been actively exploited by threat actors. CISA requires Federal Civilian Executive Branch (FCEB) agencies to remediate these vulnerabilities within specified timeframes, making them critical priorities for all organizations.</p>

            <p><strong>Key Characteristics:</strong></p>
            <ul>
                <li>✅ <strong>Actively Exploited</strong>: All KEV entries are confirmed to be exploited in real-world attacks</li>
                <li>⚠️ <strong>Time-Sensitive</strong>: Each KEV has a mandated remediation due date</li>
                <li>🎯 <strong>High Priority</strong>: KEV vulnerabilities should be remediated before other vulnerabilities</li>
                <li>🔥 <strong>Ransomware Tracking</strong>: Many KEVs are used in ransomware campaigns</li>
            </ul>

            <h2>Features</h2>

            <h3>Automatic KEV Detection</h3>

            <p>When the SBOM evaluation service discovers a vulnerability, it automatically:</p>
            <ol>
                <li>Checks if the CVE is in the CISA KEV catalog</li>
                <li>Marks the vulnerability as <code>is_kev = TRUE</code></li>
                <li>Sets priority to <code>Critical-KEV</code></li>
                <li>Logs a warning alert: <code>🚨 KEV ALERT</code></li>
                <li>Stores KEV-specific data (due date, required action)</li>
            </ol>

            <h3>KEV Dashboard</h3>

            <p>Access at: <code>/pages/vulnerabilities/kev-dashboard.php</code></p>

            <p><strong>Features:</strong></p>
            <ul>
                <li>Real-time KEV statistics</li>
                <li>Overdue KEV remediation tracking</li>
                <li>Recently added KEV vulnerabilities</li>
                <li>Affected device listing</li>
                <li>Ransomware campaign identification</li>
                <li>One-click manual sync</li>
            </ul>

            <h3>Automated Synchronization</h3>

            <ul>
                <li><strong>Daily Sync</strong>: Automatically syncs CISA KEV catalog daily at 2 AM</li>
                <li><strong>Manual Sync</strong>: Trigger sync from dashboard or API</li>
                <li><strong>Sync Logging</strong>: All sync operations are logged with statistics</li>
            </ul>

            <h2>Installation</h2>

            <h3>Step 1: Apply Database Migration</h3>

            <pre><code>cd /var/www/html
sudo -u postgres psql -d <database name> -f database/migrations/009_create_cisa_kev_catalog.sql</code></pre>

            <h3>Step 2: Setup Cron Job for Automatic Sync</h3>

            <pre><code>cd /var/www/html
sudo bash services/setup_kev_cron.sh</code></pre>

            <p>This will:</p>
            <ul>
                <li>Create a cron job for daily KEV sync at 2 AM</li>
                <li>Make the sync service executable</li>
                <li>Run an initial sync to populate data</li>
            </ul>

            <h3>Step 3: Verify Installation</h3>

            <p>Check that the cron job is installed:</p>
            <pre><code>crontab -u www-data -l</code></pre>

            <p>Check the initial sync log:</p>
            <pre><code>tail -f /var/www/html/logs/kev_sync.log</code></pre>

            <h2>Usage</h2>

            <h3>Accessing KEV Dashboard</h3>

            <p>Navigate to: <strong>Vulnerabilities → KEV Dashboard</strong></p>

            <p>The dashboard shows:</p>
            <ul>
                <li>Total KEV vulnerabilities in catalog</li>
                <li>Affected devices in your environment</li>
                <li>Overdue remediation items</li>
                <li>Recently added KEV entries</li>
                <li>Devices most affected by KEVs</li>
            </ul>

            <h3>Manual Sync</h3>

            <p>From the KEV dashboard, click <strong>"Sync Now"</strong> to manually trigger synchronization.</p>

            <p>Or from command line:</p>
            <pre><code>sudo -u www-data python3 /var/www/html/services/kev_sync_service.py</code></pre>

            <h3>API Sync</h3>

            <p>Trigger sync via API:</p>
            <pre><code>curl -X POST https://your-server/api/v1/kev/sync \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json"</code></pre>

            <h3>Viewing KEV Vulnerabilities</h3>

            <p>KEV vulnerabilities are marked with:</p>
            <ul>
                <li><strong>Priority</strong>: <code>Critical-KEV</code></li>
                <li><strong>Badge</strong>: Red "KEV" badge in vulnerability lists</li>
                <li><strong>Alert</strong>: 🚨 icon indicating active exploitation</li>
            </ul>

            <p>Filter vulnerabilities by KEV status:</p>
            <pre><code>/pages/vulnerabilities/list.php?kev=true</code></pre>

            <h2>Database Schema</h2>

            <h3>cisa_kev_catalog</h3>

            <p>Stores CISA KEV catalog entries:</p>

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
                        <td>kev_id</td>
                        <td>UUID</td>
                        <td>Primary key</td>
                    </tr>
                    <tr>
                        <td>cve_id</td>
                        <td>VARCHAR(20)</td>
                        <td>CVE identifier (unique)</td>
                    </tr>
                    <tr>
                        <td>vendor_project</td>
                        <td>VARCHAR(255)</td>
                        <td>Vendor/project name</td>
                    </tr>
                    <tr>
                        <td>product</td>
                        <td>VARCHAR(255)</td>
                        <td>Product name</td>
                    </tr>
                    <tr>
                        <td>vulnerability_name</td>
                        <td>TEXT</td>
                        <td>Descriptive name</td>
                    </tr>
                    <tr>
                        <td>date_added</td>
                        <td>DATE</td>
                        <td>Date added to KEV catalog</td>
                    </tr>
                    <tr>
                        <td>short_description</td>
                        <td>TEXT</td>
                        <td>Brief description</td>
                    </tr>
                    <tr>
                        <td>required_action</td>
                        <td>TEXT</td>
                        <td>CISA-mandated remediation action</td>
                    </tr>
                    <tr>
                        <td>due_date</td>
                        <td>DATE</td>
                        <td>Remediation due date</td>
                    </tr>
                    <tr>
                        <td>known_ransomware_campaign_use</td>
                        <td>BOOLEAN</td>
                        <td>Used in ransomware?</td>
                    </tr>
                    <tr>
                        <td>notes</td>
                        <td>TEXT</td>
                        <td>Additional notes</td>
                    </tr>
                    <tr>
                        <td>cwes</td>
                        <td>TEXT[]</td>
                        <td>Array of CWE IDs</td>
                    </tr>
                </tbody>
            </table>

            <h3>vulnerabilities (KEV fields)</h3>

            <p>Enhanced with KEV tracking:</p>

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
                        <td>is_kev</td>
                        <td>BOOLEAN</td>
                        <td>TRUE if in KEV catalog</td>
                    </tr>
                    <tr>
                        <td>kev_id</td>
                        <td>UUID</td>
                        <td>Reference to KEV entry</td>
                    </tr>
                    <tr>
                        <td>kev_date_added</td>
                        <td>DATE</td>
                        <td>Date added to KEV</td>
                    </tr>
                    <tr>
                        <td>kev_due_date</td>
                        <td>DATE</td>
                        <td>Remediation due date</td>
                    </tr>
                    <tr>
                        <td>kev_required_action</td>
                        <td>TEXT</td>
                        <td>Required action</td>
                    </tr>
                    <tr>
                        <td>priority</td>
                        <td>VARCHAR(20)</td>
                        <td>Critical-KEV for KEVs</td>
                    </tr>
                </tbody>
            </table>

            <h3>Database Views</h3>

            <h4>kev_vulnerability_summary</h4>

            <p>Summary of KEV catalog with affected device counts:</p>

            <pre><code>SELECT * FROM kev_vulnerability_summary;</code></pre>

            <h4>overdue_kev_vulnerabilities</h4>

            <p>KEV vulnerabilities past their due date:</p>

            <pre><code>SELECT * FROM overdue_kev_vulnerabilities;</code></pre>

            <h2>Prioritization Logic</h2>

            <h3>Vulnerability Priority Levels</h3>

            <ol>
                <li><strong>Critical-KEV</strong>: Actively exploited (CISA KEV catalog)</li>
                <li><strong>High</strong>: CVSS 9.0-10.0</li>
                <li><strong>Medium</strong>: CVSS 7.0-8.9</li>
                <li><strong>Low</strong>: CVSS 4.0-6.9</li>
                <li><strong>Normal</strong>: CVSS 0.0-3.9</li>
            </ol>

            <h3>KEV Priority Rules</h3>

            <p>All KEV vulnerabilities are automatically assigned <code>Critical-KEV</code> priority, regardless of CVSS score, because:</p>
            <ul>
                <li>Active exploitation is confirmed</li>
                <li>Real-world attacks are occurring</li>
                <li>Time-sensitive remediation required</li>
                <li>CISA mandates action</li>
            </ul>

            <h3>Remediation Order</h3>

            <p>Recommended remediation order:</p>

            <ol>
                <li><strong>Overdue KEVs with Ransomware flag</strong> (highest priority)</li>
                <li><strong>Overdue KEVs</strong> (past due date)</li>
                <li><strong>KEVs approaching due date</strong> (within 30 days)</li>
                <li><strong>All other KEVs</strong></li>
                <li><strong>High CVSS vulnerabilities</strong> (non-KEV)</li>
                <li><strong>Medium CVSS vulnerabilities</strong></li>
                <li><strong>Low CVSS vulnerabilities</strong></li>
            </ol>

            <h2>Alerts and Notifications</h2>

            <h3>SBOM Evaluation Alerts</h3>

            <p>When a KEV is discovered during SBOM evaluation:</p>
            <pre><code>🚨 KEV ALERT: CVE-2023-12345 is in CISA KEV catalog - actively exploited!</code></pre>

            <h3>Dashboard Alerts</h3>

            <p>Red alert banner when overdue KEVs exist:</p>
            <pre><code>URGENT: Overdue KEV Remediation
You have X overdue CISA KEV vulnerabilities past their remediation due date.</code></pre>

            <h3>Email Notifications (Future Enhancement)</h3>

            <p>Configure email alerts for:</p>
            <ul>
                <li>New KEV entries affecting your devices</li>
                <li>Approaching due dates</li>
                <li>Overdue remediations</li>
            </ul>

            <h2>KEV Sync Process</h2>

            <h3>Sync Workflow</h3>

            <ol>
                <li><strong>Download</strong>: Fetch KEV catalog from CISA (JSON format)</li>
                <li><strong>Parse</strong>: Extract vulnerability entries</li>
                <li><strong>Compare</strong>: Check for new and updated entries</li>
                <li><strong>Update</strong>: Insert/update KEV catalog entries</li>
                <li><strong>Match</strong>: Find matching vulnerabilities in database</li>
                <li><strong>Flag</strong>: Mark matched vulnerabilities as KEV</li>
                <li><strong>Prioritize</strong>: Set priority to Critical-KEV</li>
                <li><strong>Log</strong>: Record sync statistics</li>
            </ol>

            <h3>Sync Statistics</h3>

            <p>Each sync logs:</p>
            <ul>
                <li>Total KEV entries in catalog</li>
                <li>New entries added</li>
                <li>Existing entries updated</li>
                <li>Vulnerabilities matched</li>
                <li>Catalog version</li>
                <li>Sync duration</li>
            </ul>

            <h3>Error Handling</h3>

            <ul>
                <li><strong>Network Failure</strong>: Logs error, retries on next schedule</li>
                <li><strong>Parse Failure</strong>: Logs malformed entries, continues with valid ones</li>
                <li><strong>Database Error</strong>: Rolls back transaction, logs error</li>
                <li><strong>Partial Success</strong>: Marks sync as "Partial" with details</li>
            </ul>

            <h2>CISA KEV Catalog Details</h2>

            <h3>Source</h3>

            <p>CISA KEV Catalog URL:</p>
            <pre><code>https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json</code></pre>

            <h3>Update Frequency</h3>

            <ul>
                <li><strong>CISA Updates</strong>: Multiple times per week</li>
                <li><strong>Our Sync</strong>: Daily at 2 AM (configurable)</li>
                <li><strong>Manual Sync</strong>: Available on-demand</li>
            </ul>

            <h3>Catalog Format</h3>

            <p>JSON structure:</p>
            <pre><code>{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2024.XX.XX",
  "dateReleased": "2024-XX-XX",
  "count": XXXX,
  "vulnerabilities": [
    {
      "cveID": "CVE-YYYY-XXXXX",
      "vendorProject": "Vendor Name",
      "product": "Product Name",
      "vulnerabilityName": "Descriptive Name",
      "dateAdded": "YYYY-MM-DD",
      "shortDescription": "Description",
      "requiredAction": "Action Required",
      "dueDate": "YYYY-MM-DD",
      "knownRansomwareCampaignUse": "Known/Unknown",
      "notes": "Additional notes"
    }
  ]
}</code></pre>

            <h2>Monitoring</h2>

            <h3>View Sync Logs</h3>

            <pre><code>tail -f /var/www/html/logs/kev_sync.log</code></pre>

            <h3>Check Sync Status</h3>

            <pre><code>SELECT * FROM cisa_kev_sync_log 
ORDER BY sync_started_at DESC 
LIMIT 10;</code></pre>

            <h3>View KEV Statistics</h3>

            <pre><code>SELECT 
    COUNT(*) as total_kevs,
    COUNT(*) FILTER (WHERE known_ransomware_campaign_use = TRUE) as ransomware_kevs,
    COUNT(*) FILTER (WHERE due_date < CURRENT_DATE) as overdue_kevs,
    MAX(last_synced_at) as last_sync
FROM cisa_kev_catalog;</code></pre>

            <h3>Monitor Affected Devices</h3>

            <pre><code>SELECT 
    COUNT(DISTINCT device_id) as affected_devices,
    COUNT(DISTINCT vulnerability_id) as kev_vulnerabilities
FROM vulnerabilities
WHERE is_kev = TRUE
  AND status != 'Resolved';</code></pre>

            <h2>Troubleshooting</h2>

            <h3>Sync Not Running</h3>

            <p>Check cron job:</p>
            <pre><code>crontab -u www-data -l | grep kev_sync</code></pre>

            <p>Check cron logs:</p>
            <pre><code>grep CRON /var/log/syslog | grep kev_sync</code></pre>

            <h3>No KEV Data</h3>

            <p>Run manual sync:</p>
            <pre><code>sudo -u www-data python3 /var/www/html/services/kev_sync_service.py</code></pre>

            <p>Check logs:</p>
            <pre><code>tail -100 /var/www/html/logs/kev_sync.log</code></pre>

            <h3>Network Issues</h3>

            <p>Test CISA KEV URL:</p>
            <pre><code>curl -I https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json</code></pre>

            <p>Check firewall:</p>
            <pre><code>sudo ufw status</code></pre>

            <h3>Database Issues</h3>

            <p>Check if tables exist:</p>
            <pre><code>sudo -u postgres psql -d <database name> -c "\d cisa_kev_catalog"</code></pre>

            <p>Check KEV count:</p>
            <pre><code>sudo -u postgres psql -d <database name> -c "SELECT COUNT(*) FROM cisa_kev_catalog;"</code></pre>

            <h2>Best Practices</h2>

            <h3>Remediation Workflow</h3>

            <ol>
                <li><strong>Daily Review</strong>: Check KEV dashboard daily</li>
                <li><strong>Prioritize Overdue</strong>: Address overdue KEVs immediately</li>
                <li><strong>Track Progress</strong>: Update vulnerability status as remediated</li>
                <li><strong>Document Actions</strong>: Record remediation actions taken</li>
                <li><strong>Verify Fixes</strong>: Confirm vulnerabilities resolved</li>
            </ol>

            <h3>Compliance</h3>

            <p>For Federal agencies:</p>
            <ul>
                <li><strong>Mandate</strong>: BOD 22-01 requires KEV remediation</li>
                <li><strong>Deadlines</strong>: Due dates are firm requirements</li>
                <li><strong>Reporting</strong>: Track compliance status</li>
                <li><strong>Documentation</strong>: Maintain remediation records</li>
            </ul>

            <p>For other organizations:</p>
            <ul>
                <li><strong>Best Practice</strong>: Treat KEV deadlines as guidance</li>
                <li><strong>Risk Priority</strong>: KEVs represent highest risk</li>
                <li><strong>Industry Standards</strong>: Many regulations reference KEV</li>
            </ul>

            <h3>Integration with Incident Response</h3>

            <ul>
                <li><strong>Alert Correlation</strong>: Cross-reference KEVs with security alerts</li>
                <li><strong>Threat Intelligence</strong>: KEVs indicate active threat actor TTPs</li>
                <li><strong>Vulnerability Assessment</strong>: Include KEV status in assessments</li>
                <li><strong>Patch Management</strong>: Prioritize KEV patches</li>
            </ul>

            <h2>Reporting</h2>

            <h3>KEV Summary Report</h3>

            <pre><code>SELECT 
    'Total KEV Entries' as metric,
    COUNT(*) as value
FROM cisa_kev_catalog
UNION ALL
SELECT 
    'Affected Devices',
    COUNT(DISTINCT device_id)
FROM vulnerabilities
WHERE is_kev = TRUE
UNION ALL
SELECT 
    'Overdue KEVs',
    COUNT(*)
FROM overdue_kev_vulnerabilities;</code></pre>

            <h3>Device KEV Report</h3>

            <pre><code>SELECT 
    a.hostname,
    md.brand_name,
    COUNT(v.vulnerability_id) as kev_count,
    STRING_AGG(v.cve_id, ', ') as cve_ids
FROM vulnerabilities v
JOIN medical_devices md ON v.device_id = md.device_id
JOIN assets a ON md.asset_id = a.asset_id
WHERE v.is_kev = TRUE
  AND v.status != 'Resolved'
GROUP BY a.hostname, md.brand_name
ORDER BY kev_count DESC;</code></pre>

            <h2>Security Considerations</h2>

            <ol>
                <li><strong>Data Source</strong>: Official CISA KEV catalog only</li>
                <li><strong>Integrity</strong>: Verify catalog signature (future enhancement)</li>
                <li><strong>Privacy</strong>: KEV catalog is public information</li>
                <li><strong>Access Control</strong>: Restrict KEV management to authorized users</li>
                <li><strong>Audit Logging</strong>: All sync operations are logged</li>
            </ol>

            <h2>Future Enhancements</h2>

            <ul>
                <li>Email notifications for new KEV matches</li>
                <li>Slack/Teams integration for KEV alerts</li>
                <li>Automatic ticket creation for overdue KEVs</li>
                <li>KEV remediation workflow automation</li>
                <li>Historical KEV trend analysis</li>
                <li>Integration with CISA ADP for Federal agencies</li>
                <li>KEV catalog signature verification</li>
                <li>Custom due date extensions with justification</li>
            </ul>

            <h2>References</h2>

            <ul>
                <li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank">CISA KEV Catalog</a></li>
                <li><a href="https://www.cisa.gov/binding-operational-directive-22-01" target="_blank">BOD 22-01</a></li>
                <li><a href="https://www.cisa.gov/known-exploited-vulnerabilities" target="_blank">KEV FAQ</a></li>
                <li><a href="https://www.cisa.gov/cybersecurity-advisories" target="_blank">CISA Cybersecurity Advisories</a></li>
            </ul>

            <h2>Support</h2>

            <p>For issues or questions:</p>
            <ol>
                <li>Check sync logs: <code>/var/www/html/logs/kev_sync.log</code></li>
                <li>Review database sync log: <code>cisa_kev_sync_log</code> table</li>
                <li>Verify cron job: <code>crontab -u www-data -l</code></li>
                <li>Test manual sync</li>
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
