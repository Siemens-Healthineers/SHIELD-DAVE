<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../services/shell_command_utilities.php';

// Require authentication
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['ajax']) {
        case 'get_vulnerability_stats':
            // Get vulnerability counts - only CVEs linked to existing devices
            $vulnSql = "SELECT 
                COUNT(DISTINCT v.cve_id) as unique_cves,
                COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN v.cve_id END) as critical_count,
                COUNT(DISTINCT CASE WHEN v.severity = 'High' THEN v.cve_id END) as high_count,
                COUNT(DISTINCT CASE WHEN v.severity = 'Medium' THEN v.cve_id END) as medium_count,
                COUNT(DISTINCT CASE WHEN v.severity = 'Low' THEN v.cve_id END) as low_count
                FROM vulnerabilities v
                INNER JOIN device_vulnerabilities_link dvl ON v.vulnerability_id = dvl.vulnerability_id
                LEFT JOIN medical_devices md ON dvl.device_id = md.device_id
                LEFT JOIN assets a ON COALESCE(md.asset_id, dvl.asset_id) = a.asset_id
                WHERE a.asset_id IS NOT NULL AND a.status = 'Active'";
            
            $vulnStmt = $db->query($vulnSql);
            $vulnStats = $vulnStmt->fetch();
            
            // Get device and instance counts (exclude patched devices, only existing devices)
            $deviceSql = "SELECT 
                COUNT(*) as total_instances,
                COUNT(DISTINCT dvl.device_id) as affected_devices,
                COUNT(CASE WHEN dvl.remediation_status = 'Open' THEN 1 END) as open_vulnerabilities
                FROM device_vulnerabilities_link dvl
                INNER JOIN vulnerabilities v ON dvl.vulnerability_id = v.vulnerability_id
                LEFT JOIN medical_devices md ON dvl.device_id = md.device_id
                LEFT JOIN assets a ON COALESCE(md.asset_id, dvl.asset_id) = a.asset_id
                WHERE a.asset_id IS NOT NULL AND a.status = 'Active'
                  AND NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))";
            
            $deviceStmt = $db->query($deviceSql);
            $deviceStats = $deviceStmt->fetch();
            
            // Combine the results
            $stats = array_merge($vulnStats, $deviceStats);
            
            // Set total_vulnerabilities to instances for consistency
            $stats['total_vulnerabilities'] = $stats['total_instances'];
            
            echo json_encode($stats);
            exit;
            
        case 'get_vulnerability_list':
            $page = intval($_GET['page'] ?? 1);
            $limit = intval($_GET['limit'] ?? 25);
            $offset = ($page - 1) * $limit;
            $severity = $_GET['severity'] ?? '';
            $status = $_GET['status'] ?? '';
            
            // Build filters
            $filters = [];
            $params = [];
            
            if (!empty($severity)) {
                $filters[] = "v.severity = ?";
                $params[] = $severity;
            }
            
            if (!empty($status)) {
                if ($status === 'open') {
                    $filters[] = "dvl.remediation_status = 'Open'";
                } elseif ($status === 'resolved') {
                    $filters[] = "dvl.remediation_status = 'Resolved'";
                }
            }
            
            $whereClause = !empty($filters) ? 'WHERE ' . implode(' AND ', $filters) : '';
            
            // Get vulnerabilities - only CVEs linked to existing devices
            $sql = "SELECT 
                v.cve_id,
                v.description,
                v.severity,
                v.cvss_v4_score,
                v.cvss_v3_score,
                v.cvss_v2_score,
                v.published_date,
                COUNT(DISTINCT dvl.device_id) as affected_devices,
                COUNT(DISTINCT sc.name) as affected_components,
                MAX(dvl.discovered_at) as last_discovered
                FROM vulnerabilities v
                INNER JOIN device_vulnerabilities_link dvl ON v.vulnerability_id = dvl.vulnerability_id
                LEFT JOIN medical_devices md ON dvl.device_id = md.device_id
                LEFT JOIN assets a ON COALESCE(md.asset_id, dvl.asset_id) = a.asset_id
                LEFT JOIN software_components sc ON dvl.component_id = sc.component_id
                WHERE a.asset_id IS NOT NULL AND a.status = 'Active'
                $whereClause
                GROUP BY v.cve_id, v.description, v.severity, v.cvss_v4_score, v.cvss_v3_score, v.cvss_v2_score, v.published_date
                ORDER BY COALESCE(v.cvss_v4_score, v.cvss_v3_score, v.cvss_v2_score) DESC, v.published_date DESC
                LIMIT ? OFFSET ?";
            
            $params[] = $limit;
            $params[] = $offset;
            $stmt = $db->query($sql, $params);
            $vulnerabilities = $stmt->fetchAll();
            
            // Get total count - only CVEs linked to existing devices
            $countSql = "SELECT COUNT(DISTINCT v.cve_id) 
                        FROM vulnerabilities v
                        INNER JOIN device_vulnerabilities_link dvl ON v.vulnerability_id = dvl.vulnerability_id
                        LEFT JOIN medical_devices md ON dvl.device_id = md.device_id
                        LEFT JOIN assets a ON COALESCE(md.asset_id, dvl.asset_id) = a.asset_id
                        WHERE a.asset_id IS NOT NULL AND a.status = 'Active'
                        $whereClause";
            $countStmt = $db->query($countSql, array_slice($params, 0, -2));
            $total = $countStmt->fetch()['count'];
            
            echo json_encode([
                'vulnerabilities' => $vulnerabilities,
                'total' => $total,
                'page' => $page,
                'limit' => $limit,
                'pages' => ceil($total / $limit)
            ]);
            exit;
            
        case 'get_device_vulnerabilities':
            $deviceId = $_GET['device_id'] ?? '';
            
            if (empty($deviceId)) {
                echo json_encode(['error' => 'Device ID required']);
                exit;
            }
            
            $sql = "SELECT 
                v.cve_id,
                v.description,
                v.severity,
                v.cvss_v3_score,
                sc.name as component_name,
                sc.version as component_version,
                dvl.remediation_status,
                dvl.discovered_at
                FROM device_vulnerabilities_link dvl
                JOIN vulnerabilities v ON dvl.vulnerability_id = v.vulnerability_id
                JOIN software_components sc ON dvl.component_id = sc.component_id
                WHERE dvl.device_id = ?
                ORDER BY v.cvss_v3_score DESC";
            
            $stmt = $db->query($sql, [$deviceId]);
            $vulnerabilities = $stmt->fetchAll();
            
            echo json_encode(['vulnerabilities' => $vulnerabilities]);
            exit;
            
        case 'evaluate_sboms':
            if (!$auth->hasPermission('vulnerabilities.manage')) {
                echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                exit;
            }
            
            // Get all assets with SBOMs and evaluate them against NVD
            // Support both device_id and asset_id in sboms table
            $assetSql = "SELECT DISTINCT 
                         COALESCE(s.asset_id, md.asset_id) as asset_id,
                         s.device_id,
                         a.hostname,
                         s.sbom_id,
                         s.parsing_status,
                         s.file_name
                         FROM sboms s
                         LEFT JOIN medical_devices md ON s.device_id = md.device_id
                         LEFT JOIN assets a ON COALESCE(s.asset_id, md.asset_id) = a.asset_id";
            $assetStmt = $db->query($assetSql);
            $assets = $assetStmt->fetchAll();
            
            error_log("Found " . count($assets) . " SBOMs to evaluate");
            
            if (count($assets) === 0) {
                echo json_encode([
                    'success' => false, 
                    'message' => 'No SBOMs found in database',
                    'jobs' => []
                ]);
                exit;
            }
            
            // Start all scans non-blocking and return job info
            $jobs = [];
            
            foreach ($assets as $asset) {
                // Skip if parsing failed
                if ($asset['parsing_status'] !== 'Success') {
                    $jobs[] = [
                        'sbom_id' => $asset['sbom_id'],
                        'asset_id' => $asset['asset_id'],
                        'hostname' => $asset['hostname'],
                        'status' => 'skipped',
                        'error' => 'SBOM parsing status is ' . $asset['parsing_status']
                    ];
                    continue;
                }
                
                // Skip if no asset found
                if (empty($asset['asset_id'])) {
                    $jobs[] = [
                        'sbom_id' => $asset['sbom_id'],
                        'status' => 'skipped',
                        'error' => 'No asset associated with this SBOM'
                    ];
                    continue;
                }
                
                // Use asset-id if available, otherwise fall back to device-id
                if (!empty($asset['asset_id'])) {
                    $command = "cd " . _ROOT . " && python3 python/services/vulnerability_scanner.py --asset-id " . escapeshellarg($asset['asset_id']) . " --scan-type sbom";
                } else if (!empty($asset['device_id'])) {
                    $command = "cd " . _ROOT . " && python3 python/services/vulnerability_scanner.py --device-id " . escapeshellarg($asset['device_id']) . " --scan-type sbom";
                } else {
                    $jobs[] = [
                        'sbom_id' => $asset['sbom_id'],
                        'hostname' => $asset['hostname'],
                        'status' => 'skipped',
                        'error' => 'No asset_id or device_id available'
                    ];
                    continue;
                }
                
                // Execute non-blocking
                $cmdResult = ShellCommandUtilities::executeShellCommand($command, ['blocking' => false]);
                
                if ($cmdResult['success']) {
                    $jobs[] = [
                        'sbom_id' => $asset['sbom_id'],
                        'asset_id' => $asset['asset_id'],
                        'device_id' => $asset['device_id'],
                        'hostname' => $asset['hostname'],
                        'pid' => $cmdResult['pid'],
                        'log_file' => $cmdResult['log_file'],
                        'status' => 'running'
                    ];
                    error_log("Started scan for asset {$asset['asset_id']}, PID: {$cmdResult['pid']}");
                } else {
                    $jobs[] = [
                        'sbom_id' => $asset['sbom_id'],
                        'asset_id' => $asset['asset_id'],
                        'hostname' => $asset['hostname'],
                        'status' => 'failed',
                        'error' => $cmdResult['error'] ?? 'Failed to start scan'
                    ];
                }
            }
            
            echo json_encode([
                'success' => true, 
                'jobs' => $jobs,
                'total_jobs' => count($jobs)
            ]);
            exit;
            
        case 'check_scan_jobs':
            // Check status of running scan jobs
            $jobs = json_decode(file_get_contents('php://input'), true);
            
            if (!$jobs || !isset($jobs['jobs'])) {
                echo json_encode(['success' => false, 'error' => 'No jobs provided']);
                exit;
            }
            
            $results = [];
            
            foreach ($jobs['jobs'] as $job) {
                if (!isset($job['pid']) || !isset($job['log_file'])) {
                    $results[] = [
                        'sbom_id' => $job['sbom_id'] ?? null,
                        'status' => $job['status'] ?? 'unknown',
                        'error' => $job['error'] ?? 'Invalid job data'
                    ];
                    continue;
                }
                
                // Check if process is still running
                $isRunning = ShellCommandUtilities::isProcessRunning($job['pid']);
                
                if ($isRunning) {
                    $results[] = [
                        'sbom_id' => $job['sbom_id'],
                        'asset_id' => $job['asset_id'],
                        'hostname' => $job['hostname'],
                        'pid' => $job['pid'],
                        'status' => 'running'
                    ];
                } else {
                    // Process completed, get results from log file
                    $output = ShellCommandUtilities::getCommandOutput($job['log_file']);
                    
                    if ($output) {
                        try {
                            $result = json_decode($output, true);
                            if (json_last_error() === JSON_ERROR_NONE && isset($result['success']) && $result['success']) {
                                $results[] = [
                                    'sbom_id' => $job['sbom_id'],
                                    'asset_id' => $job['asset_id'],
                                    'device_id' => $job['device_id'] ?? null,
                                    'hostname' => $job['hostname'],
                                    'vulnerabilities_found' => $result['vulnerabilities_found'],
                                    'status' => 'completed'
                                ];
                            } else {
                                $results[] = [
                                    'sbom_id' => $job['sbom_id'],
                                    'asset_id' => $job['asset_id'],
                                    'hostname' => $job['hostname'],
                                    'status' => 'failed',
                                    'error' => $result['reason'] ?? ($output ?: 'Unknown error')
                                ];
                            }
                        } catch (Exception $e) {
                            $results[] = [
                                'sbom_id' => $job['sbom_id'],
                                'asset_id' => $job['asset_id'],
                                'hostname' => $job['hostname'],
                                'status' => 'failed',
                                'error' => 'JSON decode error: ' . $e->getMessage()
                            ];
                        }
                    } else {
                        $results[] = [
                            'sbom_id' => $job['sbom_id'],
                            'asset_id' => $job['asset_id'],
                            'hostname' => $job['hostname'],
                            'status' => 'failed',
                            'error' => 'No output from scan process'
                        ];
                    }
                }
            }
            
            echo json_encode([
                'success' => true,
                'results' => $results
            ]);
            exit;
            
        case 'get_scan_status':
            // Get recent and active scans
            $recent_sql = "SELECT scan_id, asset_id, scan_type, status, 
                          requested_at, started_at, completed_at, 
                          vulnerabilities_found, error_message
                          FROM vulnerability_scans 
                          WHERE status IN ('Completed', 'Failed')
                          ORDER BY completed_at DESC 
                          LIMIT 10";
            $recent_stmt = $db->query($recent_sql);
            $recent_scans = $recent_stmt->fetchAll();
            
            $active_sql = "SELECT scan_id, asset_id, scan_type, status, 
                          requested_at, started_at, 
                          vulnerabilities_found, error_message
                          FROM vulnerability_scans 
                          WHERE status IN ('Pending', 'Running')
                          ORDER BY requested_at DESC";
            $active_stmt = $db->query($active_sql);
            $active_scans = $active_stmt->fetchAll();
            
            echo json_encode([
                'success' => true,
                'scans' => [
                    'recent' => $recent_scans,
                    'active' => $active_scans
                ]
            ]);
            exit;
            
        case 'get_vulnerability_trends':
            $days = intval($_GET['days'] ?? 30);
            
            // Get vulnerability trends data for the specified number of days
            $sql = "WITH date_series AS (
                SELECT generate_series(
                    CURRENT_DATE - INTERVAL '$days days',
                    CURRENT_DATE,
                    INTERVAL '1 day'
                )::date as date
            ),
            daily_vulns AS (
                SELECT 
                    DATE(dvl.discovered_at) as discovery_date,
                    COUNT(DISTINCT v.cve_id) as new_vulnerabilities,
                    COUNT(CASE WHEN v.severity = 'Critical' THEN 1 END) as critical_count,
                    COUNT(CASE WHEN v.severity = 'High' THEN 1 END) as high_count,
                    COUNT(CASE WHEN v.severity = 'Medium' THEN 1 END) as medium_count,
                    COUNT(CASE WHEN v.severity = 'Low' THEN 1 END) as low_count
                FROM device_vulnerabilities_link dvl
                JOIN vulnerabilities v ON dvl.vulnerability_id = v.vulnerability_id
                WHERE dvl.discovered_at >= CURRENT_DATE - INTERVAL '$days days'
                GROUP BY DATE(dvl.discovered_at)
            )
            SELECT 
                ds.date,
                COALESCE(dv.new_vulnerabilities, 0) as new_vulnerabilities,
                COALESCE(dv.critical_count, 0) as critical_count,
                COALESCE(dv.high_count, 0) as high_count,
                COALESCE(dv.medium_count, 0) as medium_count,
                COALESCE(dv.low_count, 0) as low_count
            FROM date_series ds
            LEFT JOIN daily_vulns dv ON ds.date = dv.discovery_date
            ORDER BY ds.date";
            
            $stmt = $db->query($sql);
            $trends = $stmt->fetchAll();
            
            // Calculate cumulative totals
            $cumulative = 0;
            foreach ($trends as &$trend) {
                $cumulative += $trend['new_vulnerabilities'];
                $trend['cumulative_vulnerabilities'] = $cumulative;
            }
            
            echo json_encode([
                'success' => true,
                'data' => $trends,
                'period' => $days . ' days'
            ]);
            exit;
    }
}

// Get vulnerability statistics
$stats = [
    'total_vulnerabilities' => 0,
    'unique_cves' => 0,
    'total_instances' => 0,
    'critical_count' => 0,
    'high_count' => 0,
    'medium_count' => 0,
    'low_count' => 0,
    'affected_devices' => 0,
    'open_vulnerabilities' => 0
];

// Get vulnerability counts - only CVEs linked to existing devices
$vulnSql = "SELECT 
    COUNT(DISTINCT v.cve_id) as unique_cves,
    COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN v.cve_id END) as critical_count,
    COUNT(DISTINCT CASE WHEN v.severity = 'High' THEN v.cve_id END) as high_count,
    COUNT(DISTINCT CASE WHEN v.severity = 'Medium' THEN v.cve_id END) as medium_count,
    COUNT(DISTINCT CASE WHEN v.severity = 'Low' THEN v.cve_id END) as low_count
    FROM vulnerabilities v
    INNER JOIN device_vulnerabilities_link dvl ON v.vulnerability_id = dvl.vulnerability_id
    LEFT JOIN medical_devices md ON dvl.device_id = md.device_id
    LEFT JOIN assets a ON COALESCE(md.asset_id, dvl.asset_id) = a.asset_id
    WHERE a.asset_id IS NOT NULL AND a.status = 'Active'";
$vulnStmt = $db->query($vulnSql);
$vulnResult = $vulnStmt->fetch();

// Get device and instance counts (exclude patched devices, only existing devices)
$deviceSql = "SELECT 
    COUNT(*) as total_instances,
    COUNT(DISTINCT dvl.device_id) as affected_devices,
    COUNT(CASE WHEN dvl.remediation_status = 'Open' THEN 1 END) as open_vulnerabilities
    FROM device_vulnerabilities_link dvl
    INNER JOIN vulnerabilities v ON dvl.vulnerability_id = v.vulnerability_id
    LEFT JOIN medical_devices md ON dvl.device_id = md.device_id
    LEFT JOIN assets a ON COALESCE(md.asset_id, dvl.asset_id) = a.asset_id
    WHERE a.asset_id IS NOT NULL AND a.status = 'Active'
      AND NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))";
$deviceStmt = $db->query($deviceSql);
$deviceResult = $deviceStmt->fetch();

// Combine the results
$stats = array_merge($stats, $vulnResult, $deviceResult);

// Set total_vulnerabilities to instances (the remediation workload)
$stats['total_vulnerabilities'] = $stats['total_instances'];

// Get recent vulnerabilities (exclude patched devices)
$sql = "SELECT 
    v.cve_id,
    v.description,
    v.severity,
    v.cvss_v3_score,
    v.cvss_v4_score,
    v.cvss_v2_score,
    v.published_date,
    v.last_modified_date,
    COUNT(DISTINCT COALESCE(dvl.asset_id, md.asset_id)) as affected_devices
    FROM vulnerabilities v
    LEFT JOIN device_vulnerabilities_link dvl ON v.vulnerability_id = dvl.vulnerability_id
        AND NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))
    LEFT JOIN medical_devices md ON dvl.device_id = md.device_id
    GROUP BY v.cve_id, v.description, v.severity, v.cvss_v3_score, v.cvss_v4_score, v.cvss_v2_score, v.published_date, v.last_modified_date
    HAVING COUNT(DISTINCT COALESCE(dvl.asset_id, md.asset_id)) > 0
    ORDER BY COALESCE(v.published_date, v.last_modified_date, CURRENT_TIMESTAMP) DESC
    LIMIT 10";
$stmt = $db->query($sql);
$recentVulnerabilities = $stmt->fetchAll();

// Get devices with most vulnerabilities (exclude patched)
$sql = "SELECT 
    md.device_id,
    a.hostname,
    a.asset_tag,
    a.ip_address,
    md.device_name,
    md.brand_name,
    md.model_number,
    COUNT(dvl.cve_id) as vulnerability_count,
    COUNT(CASE WHEN v.severity = 'Critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN v.severity = 'High' THEN 1 END) as high_count
    FROM medical_devices md
    JOIN assets a ON md.asset_id = a.asset_id
    LEFT JOIN device_vulnerabilities_link dvl ON md.device_id = dvl.device_id
    LEFT JOIN vulnerabilities v ON dvl.vulnerability_id = v.vulnerability_id
        AND NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))
    GROUP BY md.device_id, a.hostname, a.asset_tag, a.ip_address, md.device_name, md.brand_name, md.model_number
    HAVING COUNT(dvl.cve_id) > 0
    ORDER BY vulnerability_count DESC
    LIMIT 10";
$stmt = $db->query($sql);
$devicesWithVulns = $stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Dashboard - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 16px 24px;
            border-radius: 8px;
            color: #fff;
            font-size: 14px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            z-index: 10000;
            animation: slideIn 0.3s ease-out;
        }
        .notification i {
            font-size: 20px;
        }
        .notification-success {
            background-color: #10b981;
        }
        .notification-error {
            background-color: #dc2626;
        }
        .notification-warning {
            background-color: #f59e0b;
        }
        .notification-info {
            background-color: #3b82f6;
        }
        @keyframes slideIn {
            from {
                transform: translateX(400px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-bug"></i> Vulnerability Dashboard</h1>
                    <p>Monitor and manage cybersecurity vulnerabilities through SBOM evaluation</p>
                </div>
                <div class="page-actions">
                    <?php if ($auth->hasPermission('vulnerabilities.manage')): ?>
                    <button type="button" id="evaluateSboms" class="btn btn-primary">
                        <i class="fas fa-search"></i>
                        Evaluate SBOMs Against NVD
                    </button>
                    <?php endif; ?>
                    <a href="/pages/vulnerabilities/upload-sbom.php" class="btn btn-secondary">
                        <i class="fas fa-upload"></i>
                        Upload SBOM
                    </a>
                </div>
            </div>

            <!-- Vulnerability Statistics -->
            <section class="metrics-section">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-bug"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Vulnerability Instances</h3>
                            <div class="metric-value"><?php echo number_format($stats['total_vulnerabilities']); ?></div>
                            <div class="metric-detail">
                                <span class="affected"><?php echo number_format($stats['unique_cves']); ?> unique CVEs</span>
                                <span style="margin-left: 0.5rem; color: var(--text-muted);">•</span>
                                <span style="margin-left: 0.5rem;"><?php echo number_format($stats['affected_devices']); ?> devices</span>
                            </div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon critical">
                            <i class="fas fa-exclamation-circle"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Critical</h3>
                            <div class="metric-value"><?php echo number_format($stats['critical_count']); ?></div>
                            <div class="metric-detail">Immediate attention required</div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon warning">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <div class="metric-content">
                            <h3>High Severity</h3>
                            <div class="metric-value"><?php echo number_format($stats['high_count']); ?></div>
                            <div class="metric-detail">Priority remediation</div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon info">
                            <i class="fas fa-clock"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Open Issues</h3>
                            <div class="metric-value"><?php echo number_format($stats['open_vulnerabilities']); ?></div>
                            <div class="metric-detail">Require remediation</div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Vulnerability Trends -->
            <section class="dashboard-grid">
                <div class="dashboard-widget trends-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-chart-line"></i> Vulnerability Trends</h3>
                        <div class="trends-controls">
                            <select id="trendsPeriod" class="trends-period-select">
                                <option value="7">Last 7 days</option>
                                <option value="30" selected>Last 30 days</option>
                                <option value="90">Last 90 days</option>
                            </select>
                        </div>
                    </div>
                    <div class="widget-content">
                        <div class="trends-layout">
                            <div class="trends-chart-section">
                                <div class="trends-chart-container">
                                    <canvas id="vulnerabilityTrendsChart" width="400" height="200"></canvas>
                                </div>
                            </div>
                            <div class="trends-summary-section">
                                <div class="trends-summary" id="trendsSummary">
                                    <!-- Summary will be populated by JavaScript -->
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Evaluation Status Section -->
            <section class="evaluation-status-section">
                <div class="section-header">
                    <h2><i class="fas fa-search"></i> SBOM Evaluation Status</h2>
                    <div class="evaluation-controls">
                        <button type="button" id="refreshEvaluationStatus" class="btn btn-secondary btn-sm">
                            <i class="fas fa-sync-alt"></i> Refresh
                        </button>
                    </div>
                </div>
                
                <div class="evaluation-status-grid">
                    <div class="evaluation-status-card">
                        <div class="evaluation-status-header">
                            <h3>Recent Evaluations</h3>
                            <span class="evaluation-count" id="recentEvaluationsCount">0</span>
                        </div>
                        <div class="evaluation-list" id="recentEvaluationsList">
                            <div class="no-evaluations">No recent evaluations</div>
                        </div>
                    </div>
                    
                    <div class="evaluation-status-card">
                        <div class="evaluation-status-header">
                            <h3>Active Evaluations</h3>
                            <span class="evaluation-count" id="activeEvaluationsCount">0</span>
                        </div>
                        <div class="evaluation-list" id="activeEvaluationsList">
                            <div class="no-evaluations">No active evaluations</div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Dashboard Grid -->
            <section class="dashboard-grid">
                <!-- Recent Vulnerabilities -->
                <div class="dashboard-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-bug"></i> Recent Vulnerabilities</h3>
                        <a href="/pages/vulnerabilities/list.php" class="widget-action">View All</a>
                    </div>
                    <div class="widget-content">
                        <?php if (empty($recentVulnerabilities)): ?>
                            <div class="empty-state">
                                <i class="fas fa-shield-alt"></i>
                                <p>No vulnerabilities found</p>
                            </div>
                        <?php else: ?>
                            <div class="vulnerability-list">
                                <?php foreach ($recentVulnerabilities as $vuln): ?>
                                    <div class="vulnerability-item">
                                        <div class="vuln-info">
                                            <div class="vuln-cve"><?php echo dave_htmlspecialchars($vuln['cve_id'] ?: 'N/A'); ?></div>
                                            <div class="vuln-description"><?php echo dave_htmlspecialchars(substr($vuln['description'] ?: 'No description', 0, 100)); ?><?php echo strlen($vuln['description'] ?: '') > 100 ? '...' : ''; ?></div>
                                            <div class="vuln-meta">
                                                <?php if (!empty($vuln['published_date'])): ?>
                                                    Published: <?php echo date('M j, Y', strtotime($vuln['published_date'])); ?>
                                                <?php elseif (!empty($vuln['last_modified_date'])): ?>
                                                    Modified: <?php echo date('M j, Y', strtotime($vuln['last_modified_date'])); ?>
                                                <?php else: ?>
                                                    No date
                                                <?php endif; ?>
                                                 • <?php echo $vuln['affected_devices']; ?> assets
                                            </div>
                                        </div>
                                        <div class="vuln-severity">
                                            <span class="severity-badge <?php echo strtolower($vuln['severity'] ?: 'unknown'); ?>">
                                                <?php echo $vuln['severity'] ?: 'Unknown'; ?>
                                            </span>
                                            <div class="cvss-score">
                                                <?php
                                                // Determine which CVSS score to display (v4 > v3 > v2)
                                                if (!empty($vuln['cvss_v4_score']) && floatval($vuln['cvss_v4_score']) > 0) {
                                                    echo $vuln['cvss_v4_score'] . ' <span style="font-size: 0.75rem; color: var(--text-muted);">(v4.0)</span>';
                                                } elseif (!empty($vuln['cvss_v3_score']) && floatval($vuln['cvss_v3_score']) > 0) {
                                                    echo $vuln['cvss_v3_score'] . ' <span style="font-size: 0.75rem; color: var(--text-muted);">(v3.x)</span>';
                                                } elseif (!empty($vuln['cvss_v2_score']) && floatval($vuln['cvss_v2_score']) > 0) {
                                                    echo $vuln['cvss_v2_score'] . ' <span style="font-size: 0.75rem; color: var(--text-muted);">(v2.0)</span>';
                                                } else {
                                                    echo 'N/A';
                                                }
                                                ?>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Devices with Most Vulnerabilities -->
                <div class="dashboard-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-server"></i> Most Vulnerable Devices</h3>
                        <a href="/pages/assets/manage.php" class="widget-action">View Assets</a>
                    </div>
                    <div class="widget-content">
                        <?php if (empty($devicesWithVulns)): ?>
                            <div class="empty-state">
                                <i class="fas fa-check-circle"></i>
                                <p>No vulnerable devices found</p>
                            </div>
                        <?php else: ?>
                            <div class="device-list">
                                <?php foreach ($devicesWithVulns as $index => $device): ?>
                                    <?php
                                    // Build device name with fallbacks (prioritize device_name from medical_devices table)
                                    $deviceName = $device['hostname'] 
                                        ?: $device['device_name'] 
                                        ?: $device['asset_tag'] 
                                        ?: $device['brand_name'] 
                                        ?: $device['ip_address']
                                        ?: 'Unknown Device';
                                    
                                    // Build device details
                                    $details = [];
                                    if (!empty($device['brand_name'])) {
                                        $details[] = $device['brand_name'];
                                    }
                                    if (!empty($device['model_number'])) {
                                        $details[] = $device['model_number'];
                                    }
                                    if (!empty($device['ip_address']) && $deviceName !== $device['ip_address']) {
                                        $details[] = $device['ip_address'];
                                    }
                                    $deviceDetails = !empty($details) ? implode(' • ', $details) : 'Device ID: ' . substr($device['device_id'], 0, 8) . '...';
                                    ?>
                                    <div class="device-item" data-device-index="<?php echo $index + 1; ?>">
                                        <div class="device-info">
                                            <div class="device-name">
                                                <i class="fas fa-server"></i>
                                                <?php echo dave_htmlspecialchars($deviceName); ?>
                                            </div>
                                            <div class="device-details">
                                                <?php echo dave_htmlspecialchars($deviceDetails); ?>
                                            </div>
                                        </div>
                                        <div class="device-vulns">
                                            <div class="vuln-count">
                                                <span class="vuln-number"><?php echo number_format($device['vulnerability_count']); ?></span>
                                                <span class="vuln-label">vulnerabilities</span>
                                            </div>
                                            <div class="vuln-breakdown">
                                                <?php if ($device['critical_count'] > 0): ?>
                                                    <span class="severity-badge critical">
                                                        <i class="fas fa-exclamation-circle"></i>
                                                        <?php echo $device['critical_count']; ?> Critical
                                                    </span>
                                                <?php endif; ?>
                                                <?php if ($device['high_count'] > 0): ?>
                                                    <span class="severity-badge high">
                                                        <i class="fas fa-exclamation-triangle"></i>
                                                        <?php echo $device['high_count']; ?> High
                                                    </span>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Vulnerability Severity Chart -->
                <div class="dashboard-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-chart-pie"></i> Vulnerability Severity</h3>
                    </div>
                    <div class="widget-content">
                        <div class="severity-chart">
                            <div class="severity-item">
                                <div class="severity-label">Critical</div>
                                <div class="severity-bar">
                                    <div class="severity-fill critical" style="width: <?php echo ($stats['critical_count'] / max($stats['total_vulnerabilities'], 1)) * 100; ?>%"></div>
                                </div>
                                <div class="severity-value"><?php echo $stats['critical_count']; ?></div>
                            </div>
                            <div class="severity-item">
                                <div class="severity-label">High</div>
                                <div class="severity-bar">
                                    <div class="severity-fill high" style="width: <?php echo ($stats['high_count'] / max($stats['total_vulnerabilities'], 1)) * 100; ?>%"></div>
                                </div>
                                <div class="severity-value"><?php echo $stats['high_count']; ?></div>
                            </div>
                            <div class="severity-item">
                                <div class="severity-label">Medium</div>
                                <div class="severity-bar">
                                    <div class="severity-fill medium" style="width: <?php echo ($stats['medium_count'] / max($stats['total_vulnerabilities'], 1)) * 100; ?>%"></div>
                                </div>
                                <div class="severity-value"><?php echo $stats['medium_count']; ?></div>
                            </div>
                            <div class="severity-item">
                                <div class="severity-label">Low</div>
                                <div class="severity-bar">
                                    <div class="severity-fill low" style="width: <?php echo ($stats['low_count'] / max($stats['total_vulnerabilities'], 1)) * 100; ?>%"></div>
                                </div>
                                <div class="severity-value"><?php echo $stats['low_count']; ?></div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
        </main>
    </div>

    <script>
        // Vulnerability Dashboard JavaScript
        document.addEventListener('DOMContentLoaded', function() {
            setupEventListeners();
        });

        function setupEventListeners() {
            // Evaluate SBOMs button
            const evaluateBtn = document.getElementById('evaluateSboms');
            if (evaluateBtn) {
                evaluateBtn.addEventListener('click', evaluateSboms);
            }
            
            // Refresh evaluation status button
            const refreshBtn = document.getElementById('refreshEvaluationStatus');
            if (refreshBtn) {
                refreshBtn.addEventListener('click', loadEvaluationStatus);
            }
        }

        function evaluateSboms() {
            const btn = document.getElementById('evaluateSboms');
            const originalText = btn.innerHTML;
            
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting Evaluation...';
            btn.disabled = true;
            
            // Start all scans non-blocking
            fetch('?ajax=evaluate_sboms', {
                method: 'GET'
            })
            .then(response => response.json())
            .then(data => {
                console.log('Started evaluation jobs:', data);
                if (data.success && data.jobs && data.jobs.length > 0) {
                    const runningJobs = data.jobs.filter(j => j.status === 'running');
                    const skippedJobs = data.jobs.filter(j => j.status === 'skipped');
                    const failedJobs = data.jobs.filter(j => j.status === 'failed');
                    
                    if (runningJobs.length > 0) {
                        showNotification(`Started ${runningJobs.length} scan(s). Polling for results...`, 'info');
                        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
                        
                        // Start polling for results
                        pollScanJobs(data.jobs, btn, originalText);
                    } else if (failedJobs.length > 0) {
                        showNotification(`${failedJobs.length} scan(s) failed to start. ${skippedJobs.length} skipped.`, 'error');
                        btn.innerHTML = originalText;
                        btn.disabled = false;
                    } else {
                        showNotification(`All ${skippedJobs.length} item(s) were skipped.`, 'warning');
                        btn.innerHTML = originalText;
                        btn.disabled = false;
                    }
                } else {
                    showNotification(data.message || 'No scans to evaluate', 'warning');
                    btn.innerHTML = originalText;
                    btn.disabled = false;
                }
            })
            .catch(error => {
                console.error('Error starting evaluation:', error);
                showNotification('Error starting SBOM evaluation', 'error');
                btn.innerHTML = originalText;
                btn.disabled = false;
            });
        }
        
        function pollScanJobs(jobs, btn, originalText) {
            let completedCount = 0;
            let failedCount = 0;
            let totalVulnerabilities = 0;
            const totalJobs = jobs.filter(j => j.status === 'running').length;
            
            const pollInterval = setInterval(() => {
                // Send jobs to check endpoint
                fetch('?ajax=check_scan_jobs', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ jobs: jobs })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success && data.results) {
                        // Update jobs array with current status
                        data.results.forEach(result => {
                            const jobIndex = jobs.findIndex(j => j.sbom_id === result.sbom_id);
                            if (jobIndex !== -1) {
                                jobs[jobIndex] = result;
                            }
                        });
                        
                        // Count completed and failed jobs
                        completedCount = jobs.filter(j => j.status === 'completed').length;
                        failedCount = jobs.filter(j => j.status === 'failed').length;
                        const runningCount = jobs.filter(j => j.status === 'running').length;
                        
                        // Calculate total vulnerabilities from completed jobs
                        totalVulnerabilities = jobs
                            .filter(j => j.status === 'completed')
                            .reduce((sum, j) => sum + (j.vulnerabilities_found || 0), 0);
                        
                        // Update button text with progress
                        if (runningCount > 0) {
                            btn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Scanning... (${completedCount + failedCount}/${totalJobs})`;
                        }
                        
                        // Check if all jobs are done
                        if (runningCount === 0) {
                            clearInterval(pollInterval);
                            
                            btn.innerHTML = originalText;
                            btn.disabled = false;
                            
                            if (completedCount > 0) {
                                showNotification(
                                    `Evaluation completed! ${completedCount} scan(s) successful, ` +
                                    `${failedCount} failed. Found ${totalVulnerabilities} vulnerabilities.`,
                                    'success'
                                );
                                // Refresh the page to show updated data
                                setTimeout(() => location.reload(), 2000);
                            } else {
                                showNotification(
                                    `All scans failed or were skipped.`,
                                    'error'
                                );
                            }
                        }
                    }
                })
                .catch(error => {
                    console.error('Error polling scan jobs:', error);
                    clearInterval(pollInterval);
                    btn.innerHTML = originalText;
                    btn.disabled = false;
                    showNotification('Error checking scan status', 'error');
                });
            }, 2000); // Poll every 2 seconds
        }

        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                ${message}
            `;
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, type === 'success' ? 3000 : 5000);
        }

        // Evaluation Status Management
        let evaluationStatusInterval = null;
        let evaluationErrorCount = 0;
        const MAX_EVALUATION_ERRORS = 3;
        
        function loadEvaluationStatus() {
            fetch('?ajax=get_scan_status')
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        evaluationErrorCount = 0; // Reset error count on success
                        updateEvaluationStatusDisplay(data.scans);
                    }
                })
                .catch(error => {
                    evaluationErrorCount++;
                    console.error('Error loading evaluation status:', error);
                    
                    // Stop polling after too many errors
                    if (evaluationErrorCount >= MAX_EVALUATION_ERRORS) {
                        console.warn('Too many evaluation status errors. Stopping automatic polling.');
                        if (evaluationStatusInterval) {
                            clearInterval(evaluationStatusInterval);
                            evaluationStatusInterval = null;
                        }
                    }
                });
        }

        function updateEvaluationStatusDisplay(scans) {
            const recentEvaluations = scans.recent || [];
            const activeEvaluations = scans.active || [];
            
            // Update counts
            document.getElementById('recentEvaluationsCount').textContent = recentEvaluations.length;
            document.getElementById('activeEvaluationsCount').textContent = activeEvaluations.length;
            
            // Update recent evaluations list
            const recentList = document.getElementById('recentEvaluationsList');
            if (recentEvaluations.length === 0) {
                recentList.innerHTML = '<div class="no-evaluations">No recent evaluations</div>';
            } else {
                recentList.innerHTML = recentEvaluations.map(evaluation => `
                    <div class="evaluation-item">
                        <div class="evaluation-info">
                            <div class="evaluation-type">${evaluation.scan_type === 'sbom' ? 'SBOM Evaluation' : evaluation.scan_type}</div>
                            <div class="evaluation-time">${new Date(evaluation.completed_at).toLocaleString()}</div>
                            <div class="evaluation-results">${evaluation.vulnerabilities_found || 0} vulnerabilities found</div>
                        </div>
                        <div class="evaluation-status ${evaluation.status.toLowerCase()}">
                            <i class="fas fa-${getStatusIcon(evaluation.status)}"></i>
                            ${evaluation.status}
                        </div>
                    </div>
                `).join('');
            }
            
            // Update active evaluations list
            const activeList = document.getElementById('activeEvaluationsList');
            if (activeEvaluations.length === 0) {
                activeList.innerHTML = '<div class="no-evaluations">No active evaluations</div>';
            } else {
                activeList.innerHTML = activeEvaluations.map(evaluation => `
                    <div class="evaluation-item">
                        <div class="evaluation-info">
                            <div class="evaluation-type">${evaluation.scan_type === 'sbom' ? 'SBOM Evaluation' : evaluation.scan_type}</div>
                            <div class="evaluation-progress">
                                <div class="progress-bar">
                                    <div class="progress-fill" style="width: ${evaluation.progress || 0}%"></div>
                                </div>
                                <span class="progress-text">${evaluation.progress || 0}%</span>
                            </div>
                        </div>
                        <div class="evaluation-status ${evaluation.status.toLowerCase()}">
                            <i class="fas fa-${getStatusIcon(evaluation.status)}"></i>
                            ${evaluation.status}
                        </div>
                    </div>
                `).join('');
            }
        }

        function getStatusIcon(status) {
            switch (status.toLowerCase()) {
                case 'completed': return 'check-circle';
                case 'running': return 'spinner fa-spin';
                case 'failed': return 'times-circle';
                case 'pending': return 'clock';
                default: return 'question-circle';
            }
        }

        // Auto-refresh evaluation status every 30 seconds (stops after errors)
        evaluationStatusInterval = setInterval(loadEvaluationStatus, 30000);
        
        // Load initial evaluation status
        loadEvaluationStatus();
        
        // Stop polling when page is hidden or user navigates away
        document.addEventListener('visibilitychange', function() {
            if (document.hidden && evaluationStatusInterval) {
                clearInterval(evaluationStatusInterval);
                evaluationStatusInterval = null;
            } else if (!document.hidden && !evaluationStatusInterval && evaluationErrorCount < MAX_EVALUATION_ERRORS) {
                evaluationStatusInterval = setInterval(loadEvaluationStatus, 30000);
                loadEvaluationStatus();
            }
        });
        
        // Stop polling before page unload
        window.addEventListener('beforeunload', function() {
            if (evaluationStatusInterval) {
                clearInterval(evaluationStatusInterval);
                evaluationStatusInterval = null;
            }
        });
        
        // Vulnerability Trends Chart
        let trendsChart = null;
        
        function initTrendsChart() {
            const ctx = document.getElementById('vulnerabilityTrendsChart');
            if (!ctx) return;
            
            // Set up period selector
            const periodSelect = document.getElementById('trendsPeriod');
            if (periodSelect) {
                periodSelect.addEventListener('change', function() {
                    loadTrendsData(this.value);
                });
            }
            
            // Load initial data
            loadTrendsData(30);
        }
        
        function loadTrendsData(days) {
            const chartContainer = document.querySelector('.trends-chart-container');
            const summaryContainer = document.getElementById('trendsSummary');
            
            // Show loading state
            chartContainer.innerHTML = '<div class="trends-chart-loading"><i class="fas fa-spinner fa-spin"></i>Loading trends data...</div>';
            summaryContainer.innerHTML = '';
            
            fetch(`?ajax=get_vulnerability_trends&days=${days}`)
                .then(response => {
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        renderTrendsChart(data.data);
                        updateTrendsSummary(data.data);
                    } else {
                        console.error('Trends data error:', data);
                        showTrendsError('Failed to load trends data');
                    }
                })
                .catch(error => {
                    console.error('Error loading trends:', error);
                    showTrendsError('Error loading trends data');
                });
        }
        
        function renderTrendsChart(data) {
            const chartContainer = document.querySelector('.trends-chart-container');
            const ctx = document.getElementById('vulnerabilityTrendsChart');
            
            // Clear loading message and restore canvas
            chartContainer.innerHTML = '<canvas id="vulnerabilityTrendsChart" width="400" height="200"></canvas>';
            
            const newCtx = document.getElementById('vulnerabilityTrendsChart');
            if (!newCtx) {
                console.error('Could not find canvas element');
                return;
            }
            
            // Destroy existing chart
            if (trendsChart) {
                trendsChart.destroy();
            }
            
            // Prepare data
            const labels = data.map(item => {
                const date = new Date(item.date);
                return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            });
            
            const newVulns = data.map(item => item.new_vulnerabilities);
            const criticalVulns = data.map(item => item.critical_count);
            const highVulns = data.map(item => item.high_count);
            const mediumVulns = data.map(item => item.medium_count);
            const lowVulns = data.map(item => item.low_count);
            
            // Create chart
            trendsChart = new Chart(newCtx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Total New',
                            data: newVulns,
                            borderColor: '#6b7280',
                            backgroundColor: 'rgba(107, 114, 128, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4
                        },
                        {
                            label: 'Critical',
                            data: criticalVulns,
                            borderColor: '#dc2626',
                            backgroundColor: 'rgba(220, 38, 38, 0.1)',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.4
                        },
                        {
                            label: 'High',
                            data: highVulns,
                            borderColor: '#ea580c',
                            backgroundColor: 'rgba(234, 88, 12, 0.1)',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.4
                        },
                        {
                            label: 'Medium',
                            data: mediumVulns,
                            borderColor: '#009999',
                            backgroundColor: 'rgba(0, 153, 153, 0.1)',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.4
                        },
                        {
                            label: 'Low',
                            data: lowVulns,
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: {
                                color: '#f8fafc',
                                usePointStyle: true,
                                padding: 20
                            }
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false,
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            titleColor: '#f8fafc',
                            bodyColor: '#f8fafc',
                            borderColor: '#374151',
                            borderWidth: 1
                        }
                    },
                    scales: {
                        x: {
                            display: true,
                            title: {
                                display: true,
                                text: 'Date',
                                color: '#cbd5e1'
                            },
                            ticks: {
                                color: '#cbd5e1'
                            },
                            grid: {
                                color: 'rgba(203, 213, 225, 0.1)'
                            }
                        },
                        y: {
                            display: true,
                            title: {
                                display: true,
                                text: 'Vulnerabilities',
                                color: '#cbd5e1'
                            },
                            ticks: {
                                color: '#cbd5e1',
                                beginAtZero: true
                            },
                            grid: {
                                color: 'rgba(203, 213, 225, 0.1)'
                            }
                        }
                    },
                    interaction: {
                        mode: 'nearest',
                        axis: 'x',
                        intersect: false
                    }
                }
            });
        }
        
        function updateTrendsSummary(data) {
            const summaryContainer = document.getElementById('trendsSummary');
            if (!summaryContainer) return;
            
            // Calculate summary statistics
            const totalNew = data.reduce((sum, item) => sum + item.new_vulnerabilities, 0);
            const totalCritical = data.reduce((sum, item) => sum + item.critical_count, 0);
            const totalHigh = data.reduce((sum, item) => sum + item.high_count, 0);
            const totalMedium = data.reduce((sum, item) => sum + item.medium_count, 0);
            const totalLow = data.reduce((sum, item) => sum + item.low_count, 0);
            
            // Calculate trend (comparing first half vs second half)
            const midPoint = Math.floor(data.length / 2);
            const firstHalf = data.slice(0, midPoint).reduce((sum, item) => sum + item.new_vulnerabilities, 0);
            const secondHalf = data.slice(midPoint).reduce((sum, item) => sum + item.new_vulnerabilities, 0);
            
            let trend = 'neutral';
            let trendText = 'No change';
            if (secondHalf > firstHalf) {
                trend = 'positive';
                trendText = `+${((secondHalf - firstHalf) / Math.max(firstHalf, 1) * 100).toFixed(0)}%`;
            } else if (secondHalf < firstHalf) {
                trend = 'negative';
                trendText = `-${((firstHalf - secondHalf) / Math.max(firstHalf, 1) * 100).toFixed(0)}%`;
            }
            
            summaryContainer.innerHTML = `
                <div class="trends-summary-item">
                    <div class="trends-summary-label">Total New</div>
                    <div class="trends-summary-value">${totalNew}</div>
                </div>
                <div class="trends-summary-item">
                    <div class="trends-summary-label">Critical</div>
                    <div class="trends-summary-value">${totalCritical}</div>
                </div>
                <div class="trends-summary-item">
                    <div class="trends-summary-label">High</div>
                    <div class="trends-summary-value">${totalHigh}</div>
                </div>
                <div class="trends-summary-item">
                    <div class="trends-summary-label">Medium</div>
                    <div class="trends-summary-value">${totalMedium}</div>
                </div>
                <div class="trends-summary-item">
                    <div class="trends-summary-label">Low</div>
                    <div class="trends-summary-value">${totalLow}</div>
                </div>
                <div class="trends-summary-item">
                    <div class="trends-summary-label">Trend</div>
                    <div class="trends-summary-change ${trend}">${trendText}</div>
                </div>
            `;
        }
        
        function showTrendsError(message) {
            const chartContainer = document.querySelector('.trends-chart-container');
            chartContainer.innerHTML = `
                <div class="trends-chart-error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>${message}</p>
                </div>
            `;
        }
        
        // Initialize trends chart when page loads
        document.addEventListener('DOMContentLoaded', function() {
            initTrendsChart();
        });
    </script>
    <!-- Common Dashboard JavaScript -->
    <script src="/assets/js/dashboard-common.js"></script>
</body>
</html>
