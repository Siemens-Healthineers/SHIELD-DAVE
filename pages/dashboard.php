<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/session-middleware.php';
require_once __DIR__ . '/../includes/cache.php';
require_once __DIR__ . '/../includes/lockdown-enforcement.php';

// Enforce system lockdown
enforceSystemLockdown(__FILE__);

// Session middleware is auto-initialized

// Get current user from session middleware
$user = $_SESSION['user'] ?? [
    'username' => $_SESSION['username'] ?? 'Unknown',
    'role' => $_SESSION['role'] ?? 'User',
    'email' => $_SESSION['email'] ?? 'Not provided'
];

// Get dashboard metrics with caching
$db = DatabaseConfig::getInstance();

// Create cache key for dashboard metrics (5-minute cache)
$cache_key = 'dashboard_metrics_' . date('Y-m-d-H-i', floor(time() / 300) * 300);
$metrics = Cache::get($cache_key);

if (!$metrics) {
    // Combined dashboard metrics query for better performance
    $sql = "WITH asset_metrics AS (
        SELECT 
            COUNT(*) as total_assets,
            COUNT(CASE WHEN md.device_id IS NOT NULL THEN 1 END) as mapped_assets,
            COUNT(CASE WHEN md.device_id IS NULL THEN 1 END) as unmapped_assets,
            COUNT(CASE WHEN a.criticality = 'Clinical-High' THEN 1 END) as critical_assets
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        WHERE a.status = 'Active'
    ),
    vuln_metrics AS (
        SELECT 
            COUNT(*) as total_vulns,
            COUNT(CASE WHEN v.severity = 'Critical' THEN 1 END) as critical_vulns,
            COUNT(CASE WHEN v.severity = 'High' THEN 1 END) as high_vulns,
            COUNT(CASE WHEN dvl.remediation_status = 'Open' THEN 1 END) as open_vulns,
            COUNT(CASE WHEN v.is_kev = true THEN 1 END) as kev_vulns,
            COUNT(CASE WHEN v.is_kev = true AND v.kev_due_date < CURRENT_DATE THEN 1 END) as overdue_kevs
        FROM device_vulnerabilities_link dvl
        JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
        WHERE NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))
    ),
    recall_metrics AS (
        SELECT 
            COUNT(DISTINCT r.recall_id) FILTER (WHERE drl.device_id IS NOT NULL) as active_recalls,
            COUNT(DISTINCT drl.device_id) as affected_devices,
            COUNT(DISTINCT r.recall_id) FILTER (WHERE drl.device_id IS NOT NULL AND r.recall_date > CURRENT_DATE - INTERVAL '30 days') as recent_recalls
        FROM recalls r
        LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
            AND (drl.remediation_status IS NULL OR drl.remediation_status <> 'Resolved')
        WHERE r.recall_status = 'Active'
    ),
    action_metrics AS (
        SELECT 
            COUNT(*) as total_actions,
            COUNT(CASE WHEN ra.status = 'Pending' THEN 1 END) as pending_actions,
            COUNT(CASE WHEN ra.status = 'In Progress' THEN 1 END) as in_progress_actions,
            COUNT(CASE WHEN ra.status = 'Completed' THEN 1 END) as completed_actions,
            COUNT(CASE WHEN ra.due_date < CURRENT_DATE AND ra.status != 'Completed' THEN 1 END) as overdue_actions,
            COUNT(CASE WHEN ars.urgency_score >= 1000 THEN 1 END) as tier1_actions,
            COUNT(CASE WHEN ars.urgency_score >= 180 AND ars.urgency_score < 1000 THEN 1 END) as tier2_actions,
            COUNT(CASE WHEN ars.kev_count > 0 THEN 1 END) as kev_actions,
            COUNT(CASE WHEN ars.kev_count > 0 AND ra.due_date < CURRENT_DATE AND ra.status != 'Completed' THEN 1 END) as overdue_kev_actions
        FROM remediation_actions ra
        LEFT JOIN action_risk_scores ars ON ra.action_id = ars.action_id
        WHERE ra.status != 'Cancelled' 
          AND ra.status != 'Completed'
          AND EXISTS (SELECT 1 FROM action_device_links adl WHERE adl.action_id = ra.action_id)
    )
    SELECT 
        am.*,
        vm.*,
        rm.*,
        act.*
    FROM asset_metrics am, vuln_metrics vm, recall_metrics rm, action_metrics act";

    $stmt = $db->query($sql);
    $metrics = $stmt->fetch();
    
    // Cache the results for 5 minutes
    Cache::set($cache_key, $metrics, 300);
}

// Parse combined results
$assetStats = [
    'total' => $metrics['total_assets'],
    'mapped' => $metrics['mapped_assets'],
    'unmapped' => $metrics['unmapped_assets'],
    'critical' => $metrics['critical_assets'],
    'by_type' => []
];

$vulnStats = [
    'total' => $metrics['total_vulns'],
    'critical' => $metrics['critical_vulns'],
    'high' => $metrics['high_vulns'],
    'open' => $metrics['open_vulns'],
    'kev' => $metrics['kev_vulns'] ?? 0,
    'overdue_kev' => $metrics['overdue_kevs'] ?? 0
];

$recallStats = [
    'active' => $metrics['active_recalls'],
    'affected_devices' => $metrics['affected_devices'],
    'recent' => $metrics['recent_recalls']
];

$actionStats = [
    'total' => $metrics['total_actions'],
    'pending' => $metrics['pending_actions'],
    'in_progress' => $metrics['in_progress_actions'],
    'completed' => $metrics['completed_actions'],
    'overdue' => $metrics['overdue_actions'],
    'tier1' => $metrics['tier1_actions'],
    'tier2' => $metrics['tier2_actions'],
    'kev' => $metrics['kev_actions'],
    'overdue_kev' => $metrics['overdue_kev_actions']
];


// Location metrics (separate query for location data) with caching
$location_metrics_cache_key = 'location_metrics_' . date('Y-m-d-H-i', floor(time() / 300) * 300);
$locationMetrics = Cache::get($location_metrics_cache_key);

if (!$locationMetrics) {
    $sql = "SELECT 
                COUNT(DISTINCT l.location_id) as total_locations,
                COUNT(DISTINCT CASE WHEN l.is_active = true THEN l.location_id END) as active_locations,
                COUNT(DISTINCT CASE WHEN a.location_id IS NOT NULL THEN a.location_id END) as locations_with_assets,
                COUNT(CASE WHEN a.location_id IS NOT NULL THEN 1 END) as assets_with_locations
            FROM locations l
            LEFT JOIN assets a ON l.location_id = a.location_id";
    $stmt = $db->query($sql);
    $locationMetrics = $stmt->fetch();
    
    // Cache the results for 5 minutes
    Cache::set($location_metrics_cache_key, $locationMetrics, 300);
}

// Get top locations by assets assigned
$top_locations_cache_key = 'top_locations_' . date('Y-m-d-H-i', floor(time() / 300) * 300);
$topLocations = Cache::get($top_locations_cache_key);

if (!$topLocations) {
    $sql = "SELECT 
                l.location_name,
                l.location_code,
                COUNT(a.asset_id) as assets_count
            FROM locations l
            LEFT JOIN assets a ON l.location_id = a.location_id
            WHERE l.is_active = true
            GROUP BY l.location_id, l.location_name, l.location_code
            HAVING COUNT(a.asset_id) > 0
            ORDER BY assets_count DESC
            LIMIT 5";
    $stmt = $db->query($sql);
    $topLocations = $stmt->fetchAll();
    
    // Cache the results for 5 minutes
    Cache::set($top_locations_cache_key, $topLocations, 300);
}

$locationStats = [
    'total' => $locationMetrics['total_locations'],
    'active' => $locationMetrics['active_locations'],
    'with_assets' => $locationMetrics['locations_with_assets'],
    'assets_assigned' => $locationMetrics['assets_with_locations']
];

// Recent activities
$sql = "SELECT 
    a.hostname,
    a.ip_address,
    a.asset_type,
    a.department,
    a.last_seen,
    md.brand_name,
    md.device_name,
    CASE WHEN md.device_id IS NOT NULL THEN 'Mapped' ELSE 'Unmapped' END as status
    FROM assets a
    LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
    WHERE a.status = 'Active'
    ORDER BY a.last_seen DESC
    LIMIT 10";
$stmt = $db->query($sql);
$recentAssets = $stmt->fetchAll();

// Recent vulnerabilities
$sql = "SELECT 
    v.cve_id,
    v.severity,
    v.cvss_v3_score,
    sc.name as component_name,
    a.hostname,
    a.department,
    dvl.remediation_status
    FROM device_vulnerabilities_link dvl
    JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
    JOIN software_components sc ON dvl.component_id = sc.component_id
    JOIN medical_devices md ON dvl.device_id = md.device_id
    JOIN assets a ON md.asset_id = a.asset_id
    WHERE NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))
    ORDER BY v.cvss_v3_score DESC, dvl.discovered_at DESC
    LIMIT 10";
$stmt = $db->query($sql);
$recentVulnerabilities = $stmt->fetchAll();

// Recent recalls (exclude resolved)
$sql = "SELECT 
    r.fda_recall_number,
    r.recall_date,
    r.reason_for_recall,
    r.manufacturer_name,
    COUNT(drl.device_id) as affected_count
    FROM recalls r
    LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
        AND (drl.remediation_status IS NULL OR drl.remediation_status <> 'Resolved')
    WHERE r.recall_status = 'Active'
    GROUP BY r.recall_id, r.fda_recall_number, r.recall_date, r.reason_for_recall, r.manufacturer_name
    ORDER BY r.recall_date DESC
    LIMIT 5";
$stmt = $db->query($sql);
$recentRecalls = $stmt->fetchAll();

// Get action-based risk priority statistics
// Cache key uses current minute to ensure updates are reflected immediately when tasks are completed
$risk_priority_cache_key = 'action_priority_stats_' . date('Y-m-d-H-i');
$riskPriorityStats = Cache::get($risk_priority_cache_key);

if (!$riskPriorityStats) {
    // Get action-based tier statistics (exclude completed and actions with no devices)
    $sql = "SELECT 
        CASE 
            WHEN ars.urgency_score >= 1000 THEN 1
            WHEN ars.urgency_score >= 180 THEN 2
            WHEN ars.urgency_score >= 160 THEN 3
            ELSE 4
        END as priority_tier,
        COUNT(*) as total_count,
        COUNT(CASE WHEN ra.status = 'In Progress' THEN 1 END) as in_progress_count,
        COUNT(CASE WHEN ra.status = 'Pending' THEN 1 END) as pending_count,
        COUNT(CASE WHEN ra.assigned_to IS NOT NULL THEN 1 END) as assigned_count,
        COUNT(CASE WHEN ra.due_date < CURRENT_DATE AND ra.status != 'Completed' THEN 1 END) as overdue_count
    FROM remediation_actions ra
    LEFT JOIN action_risk_scores ars ON ra.action_id = ars.action_id
    WHERE ra.status != 'Cancelled' 
      AND ra.status != 'Completed'
      AND EXISTS (SELECT 1 FROM action_device_links adl WHERE adl.action_id = ra.action_id)
    GROUP BY 
        CASE 
            WHEN ars.urgency_score >= 1000 THEN 1
            WHEN ars.urgency_score >= 180 THEN 2
            WHEN ars.urgency_score >= 160 THEN 3
            ELSE 4
        END
    ORDER BY priority_tier";
    
    $stmt = $db->query($sql);
    $tierData = [];
    while ($row = $stmt->fetch()) {
        $tierData[$row['priority_tier']] = $row;
    }
    
    // Get KEV action stats (exclude completed and actions with no devices)
    $sql = "SELECT 
        COUNT(*) as total_kevs,
        COUNT(CASE WHEN ra.due_date < CURRENT_DATE AND ra.status != 'Completed' THEN 1 END) as overdue_kevs
    FROM remediation_actions ra
    LEFT JOIN action_risk_scores ars ON ra.action_id = ars.action_id
    WHERE ra.status != 'Cancelled' 
      AND ra.status != 'Completed' 
      AND ars.kev_count > 0
      AND EXISTS (SELECT 1 FROM action_device_links adl WHERE adl.action_id = ra.action_id)";
    
    $stmt = $db->query($sql);
    $kevData = $stmt->fetch();
    
    $riskPriorityStats = [
        'tiers' => $tierData,
        'kevs' => $kevData
    ];
    
    Cache::set($risk_priority_cache_key, $riskPriorityStats, 300);
}

$tierStats = $riskPriorityStats['tiers'] ?? [];
$kevStats = $riskPriorityStats['kevs'] ?? ['total_kevs' => 0, 'overdue_kevs' => 0];

// Get EPSS data for dashboard
$epss_cache_key = 'epss_dashboard_data_' . date('Y-m-d-H-i', floor(time() / 300) * 300);
$epssData = Cache::get($epss_cache_key);

if (!$epssData) {
    try {
        // Use standardized vulnerability statistics service
        require_once __DIR__ . '/../includes/vulnerability-stats.php';
        $vulnStatsService = new VulnerabilityStats();
        
        // Get comprehensive vulnerability statistics
        $comprehensiveStats = $vulnStatsService->getComprehensiveStats();
        
        if ($comprehensiveStats['success']) {
            $stats = $comprehensiveStats['data'];
            
            // Get EPSS statistics with standardized approach
            $sql = "SELECT 
                COUNT(*) as total_vulnerabilities,
                COUNT(CASE WHEN epss_score IS NOT NULL THEN 1 END) as vulnerabilities_with_epss,
                COUNT(CASE WHEN epss_score >= 0.7 THEN 1 END) as high_epss_count,
                COUNT(CASE WHEN epss_score >= 0.3 AND epss_score < 0.7 THEN 1 END) as medium_epss_count,
                COUNT(CASE WHEN epss_score < 0.3 THEN 1 END) as low_epss_count,
                ROUND(AVG(epss_score), 4) as avg_epss_score,
                ROUND(AVG(epss_percentile), 4) as avg_epss_percentile,
                MAX(epss_last_updated) as last_epss_update
            FROM vulnerabilities 
            WHERE epss_score IS NOT NULL";
            
            $stmt = $db->query($sql);
            $overall_stats = $stmt->fetch();
            
            // Override with standardized counts
            $overall_stats['total_vulnerabilities'] = $stats['unique_vulnerabilities']['count'];
            $overall_stats['vulnerabilities_with_epss'] = $stats['vulnerabilities_with_epss']['count'];
        } else {
            // Fallback to original query if service fails
            $sql = "SELECT 
                COUNT(*) as total_vulnerabilities,
                COUNT(CASE WHEN epss_score IS NOT NULL THEN 1 END) as vulnerabilities_with_epss,
                COUNT(CASE WHEN epss_score >= 0.7 THEN 1 END) as high_epss_count,
                COUNT(CASE WHEN epss_score >= 0.3 AND epss_score < 0.7 THEN 1 END) as medium_epss_count,
                COUNT(CASE WHEN epss_score < 0.3 THEN 1 END) as low_epss_count,
                ROUND(AVG(epss_score), 4) as avg_epss_score,
                ROUND(AVG(epss_percentile), 4) as avg_epss_percentile,
                MAX(epss_last_updated) as last_epss_update
            FROM vulnerabilities 
            WHERE epss_score IS NOT NULL";
            
            $stmt = $db->query($sql);
            $overall_stats = $stmt->fetch();
        }
        
        // Get recent EPSS trends (last 7 days)
        $sql = "SELECT 
            recorded_date,
            COUNT(*) as vulnerabilities_count,
            ROUND(AVG(epss_score), 4) as avg_epss_score,
            COUNT(CASE WHEN epss_score >= 0.7 THEN 1 END) as high_epss_count
        FROM epss_score_history 
        WHERE recorded_date >= CURRENT_DATE - INTERVAL '7 days'
        GROUP BY recorded_date
        ORDER BY recorded_date ASC";
        
        $stmt = $db->query($sql);
        $recent_trends = $stmt->fetchAll();
        
        // Get trending vulnerabilities (simplified version)
        $sql = "SELECT 
            v.cve_id,
            v.description,
            v.severity,
            v.epss_score,
            v.epss_percentile,
            v.is_kev,
            COUNT(dvl.device_id) as affected_assets
        FROM vulnerabilities v
        LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
        WHERE v.epss_score >= 0.5
        GROUP BY v.cve_id, v.description, v.severity, v.epss_score, v.epss_percentile, v.is_kev
        ORDER BY v.epss_score DESC
        LIMIT 5";
        
        $stmt = $db->query($sql);
        $trending_vulns = $stmt->fetchAll();
        
        $epssData = [
            'success' => true,
            'data' => [
                'overall' => $overall_stats,
                'recent_trends' => $recent_trends,
                'trending' => [
                    'vulnerabilities' => $trending_vulns,
                    'count' => count($trending_vulns)
                ]
            ],
            'timestamp' => date('c')
        ];
        
        Cache::set($epss_cache_key, $epssData, 300);
    } catch (Exception $e) {
        $epssData = [
            'success' => false,
            'error' => 'Failed to load EPSS data: ' . $e->getMessage()
        ];
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>Dashboard - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css?v=<?php echo time() . rand(1000, 9999); ?>">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/admin.css?v=<?php echo time(); ?>">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css?v=<?php echo time(); ?>">
    <link rel="stylesheet" href="/assets/css/priority-badges.css?v=<?php echo time(); ?>">
    <link rel="stylesheet" href="/assets/css/epss-badges.css?v=<?php echo time(); ?>">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <!-- Metrics Cards -->
            <section class="metrics-section" style="margin-bottom: 0.5rem !important;">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-server"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Total Assets</h3>
                            <div class="metric-value"><?php echo number_format($assetStats['total']); ?></div>
                            <div class="metric-detail">
                                <span class="mapped"><?php echo number_format($assetStats['mapped']); ?> Mapped</span>
                                <span class="unmapped"><?php echo number_format($assetStats['unmapped']); ?> Unmapped</span>
                            </div>
                            <div class="metric-chart">
                                <div class="mini-chart">
                                    <div class="chart-bar">
                                        <div class="chart-fill mapped" style="width: <?php echo $assetStats['total'] > 0 ? ($assetStats['mapped'] / $assetStats['total']) * 100 : 0; ?>%"></div>
                                        <div class="chart-fill unmapped" style="width: <?php echo $assetStats['total'] > 0 ? ($assetStats['unmapped'] / $assetStats['total']) * 100 : 0; ?>%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon critical">
                            <i class="fas fa-exclamation-circle"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Critical Assets</h3>
                            <div class="metric-value"><?php echo number_format($assetStats['critical']); ?></div>
                            <div class="metric-detail">High clinical impact devices</div>
                            <div class="metric-chart">
                                <div class="mini-chart">
                                    <div class="chart-bar">
                                        <div class="chart-fill critical" style="width: <?php echo $assetStats['total'] > 0 ? ($assetStats['critical'] / $assetStats['total']) * 100 : 0; ?>%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon warning">
                            <i class="fas fa-bug"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Vulnerabilities</h3>
                            <div class="metric-value"><?php echo number_format($vulnStats['total']); ?></div>
                            <div class="metric-detail">
                                <span class="critical"><?php echo number_format($vulnStats['critical']); ?> Critical</span>
                                <span class="high"><?php echo number_format($vulnStats['high']); ?> High</span>
                            </div>
                            <div class="metric-chart">
                                <div class="mini-chart">
                                    <div class="chart-bar">
                                        <div class="chart-fill critical" style="width: <?php echo $vulnStats['total'] > 0 ? ($vulnStats['critical'] / $vulnStats['total']) * 100 : 0; ?>%"></div>
                                        <div class="chart-fill high" style="width: <?php echo $vulnStats['total'] > 0 ? ($vulnStats['high'] / $vulnStats['total']) * 100 : 0; ?>%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <a href="/pages/vulnerabilities/kev-dashboard.php" class="metric-card kev-card" style="text-decoration: none; color: inherit;">
                        <div class="metric-icon kev">
                            <i class="fas fa-fire"></i>
                        </div>
                        <div class="metric-content">
                            <h3>CISA KEV</h3>
                            <div class="metric-value"><?php echo number_format($vulnStats['kev']); ?></div>
                            <div class="metric-detail">
                                <span class="kev-overdue"><?php echo number_format($vulnStats['overdue_kev']); ?> Overdue Remediation</span>
                            </div>
                            <div class="metric-chart">
                                <div class="mini-chart">
                                    <div class="chart-bar">
                                        <div class="chart-fill kev-overdue" style="width: <?php echo $vulnStats['kev'] > 0 ? ($vulnStats['overdue_kev'] / $vulnStats['kev']) * 100 : 0; ?>%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </a>

                </div>
            </section>

            <!-- Risk Priority Management Section -->
            <section class="priority-section" style="margin: 2rem 0 !important;">
                <!-- Compact Priority Metrics -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                    <!-- Tier 1 Metric -->
                    <a href="/pages/risk-priorities/dashboard.php?tier=1" style="text-decoration: none;">
                        <div style="background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%); border: 2px solid #dc2626; border-radius: 0.75rem; padding: 1.25rem; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s;" 
                             onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 8px 16px rgba(220, 38, 38, 0.3)';"
                             onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 12px rgba(220, 38, 38, 0.2)';">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                                <span style="font-size: 0.75rem; font-weight: 600; color: #fca5a5; text-transform: uppercase; letter-spacing: 0.05em;">Tier 1 - Critical Actions</span>
                                <svg style="width: 1.25rem; height: 1.25rem; color: #dc2626;" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                                </svg>
                            </div>
                            <div style="font-size: 2.5rem; font-weight: 700; color: #ffffff; line-height: 1;"><?php echo $tierStats[1]['total_count'] ?? 0; ?></div>
                            <div style="font-size: 0.75rem; color: #fca5a5; margin-top: 0.5rem;">
                                <?php echo $tierStats[1]['overdue_count'] ?? 0; ?> overdue
                            </div>
                        </div>
                    </a>
                    
                    <!-- Tier 2 Metric -->
                    <a href="/pages/risk-priorities/dashboard.php?tier=2" style="text-decoration: none;">
                        <div style="background: linear-gradient(135deg, #7c2d12 0%, #9a3412 100%); border: 2px solid #f97316; border-radius: 0.75rem; padding: 1.25rem; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s;"
                             onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 8px 16px rgba(249, 115, 22, 0.3)';"
                             onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 12px rgba(249, 115, 22, 0.2)';">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                                <span style="font-size: 0.75rem; font-weight: 600; color: #fdba74; text-transform: uppercase; letter-spacing: 0.05em;">Tier 2 - High Priority</span>
                                <svg style="width: 1.25rem; height: 1.25rem; color: #f97316;" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                </svg>
                            </div>
                            <div style="font-size: 2.5rem; font-weight: 700; color: #ffffff; line-height: 1;"><?php echo $tierStats[2]['total_count'] ?? 0; ?></div>
                            <div style="font-size: 0.75rem; color: #fdba74; margin-top: 0.5rem;">
                                <?php echo $tierStats[2]['overdue_count'] ?? 0; ?> overdue
                            </div>
                        </div>
                    </a>
                    
                    <!-- Tier 3 Metric -->
                    <a href="/pages/risk-priorities/dashboard.php?tier=3" style="text-decoration: none;">
                        <div style="background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%); border: 2px solid #3b82f6; border-radius: 0.75rem; padding: 1.25rem; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s;"
                             onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 8px 16px rgba(59, 130, 246, 0.3)';"
                             onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 12px rgba(59, 130, 246, 0.2)';">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                                <span style="font-size: 0.75rem; font-weight: 600; color: #93c5fd; text-transform: uppercase; letter-spacing: 0.05em;">Tier 3 - Medium Priority</span>
                                <svg style="width: 1.25rem; height: 1.25rem; color: #3b82f6;" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clip-rule="evenodd" />
                                </svg>
                            </div>
                            <div style="font-size: 2.5rem; font-weight: 700; color: #ffffff; line-height: 1;"><?php echo $tierStats[3]['total_count'] ?? 0; ?></div>
                            <div style="font-size: 0.75rem; color: #93c5fd; margin-top: 0.5rem;">
                                <?php echo $tierStats[3]['overdue_count'] ?? 0; ?> overdue
                            </div>
                        </div>
                    </a>
                    
                    <!-- Device Recall Metric -->
                    <a href="/pages/recalls/dashboard.php" style="text-decoration: none;">
                        <div style="background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%); border: 2px solid #dc2626; border-radius: 0.75rem; padding: 1.25rem; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s;" 
                             onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 8px 16px rgba(220, 38, 38, 0.3)';"
                             onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 12px rgba(220, 38, 38, 0.2)';">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                                <span style="font-size: 0.75rem; font-weight: 600; color: #fca5a5; text-transform: uppercase; letter-spacing: 0.05em;">Device Recall</span>
                                <svg style="width: 1.25rem; height: 1.25rem; color: #dc2626;" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                                </svg>
                            </div>
                            <div style="font-size: 2.5rem; font-weight: 700; color: #ffffff; line-height: 1;"><?php echo number_format($recallStats['affected_devices']); ?></div>
                            <div style="font-size: 0.75rem; color: #fca5a5; margin-top: 0.5rem;">
                                <?php echo number_format($recallStats['active']); ?> active recalls
                            </div>
                        </div>
                    </a>
                </div>
            </section>

            <!-- Combined Metrics Section -->
            <section class="combined-metrics-section" style="margin: 2rem 0;">
                <!-- Asset & Recall Metrics Grid -->
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; align-items: start;">
                    <!-- Asset Locations Chart -->
                    <div class="dashboard-widget locations-chart" style="grid-column: span 1; background: linear-gradient(135deg, var(--bg-card, #111111) 0%, var(--bg-tertiary, #1a1a1a) 100%); border: 1px solid var(--border-card, #1f2937); border-radius: var(--radius-lg, 0.75rem); box-shadow: var(--shadow-lg, 0 10px 15px rgba(0, 0, 0, 0.5));">
                        <div class="widget-header" style="padding: var(--spacing-md, 1rem) var(--spacing-lg, 1.5rem); border-bottom: 1px solid var(--border-card, #1f2937); background: linear-gradient(135deg, var(--bg-tertiary, #1a1a1a) 0%, var(--bg-card, #111111) 100%);">
                            <h3 style="font-size: var(--font-size-h3, 1.5rem); margin: 0; font-weight: var(--font-weight-semibold, 600); color: var(--text-primary, #ffffff); display: flex; align-items: center; font-family: var(--font-family, 'Siemens Sans', sans-serif);">
                                <i class="fas fa-map-marker-alt" style="color: var(--siemens-petrol-light, #00bbbb); margin-right: var(--spacing-sm, 0.5rem); font-size: 1.1rem;"></i>
                                Asset Locations
                            </h3>
                            <a href="/pages/admin/locations.php" class="widget-action" style="font-size: var(--font-size-small, 0.875rem); color: var(--siemens-petrol-light, #00bbbb); text-decoration: none; font-weight: var(--font-weight-medium, 500); transition: color var(--transition-duration, 0.2s);">View Details</a>
                        </div>
                        <div class="widget-content" style="padding: var(--spacing-lg, 1.5rem); display: flex; flex-direction: column; gap: var(--spacing-md, 1rem);">
                            <div class="chart-container" style="height: 120px; background: var(--bg-secondary, #0a0a0a); border-radius: var(--radius-md, 0.5rem); padding: var(--spacing-sm, 0.5rem) var(--spacing-md, 1rem); border: 1px solid var(--border-secondary, #374151);">
                                <canvas id="locationsChart" width="600" height="100"></canvas>
                            </div>
                            <div class="stats-grid" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: var(--spacing-md, 1rem);">
                                <div class="stat-card" style="background: rgba(0, 153, 153, 0.1); border: 1px solid var(--siemens-petrol, #009999); border-radius: var(--radius-md, 0.5rem); padding: var(--spacing-md, 1rem); text-align: center;">
                                    <div class="stat-value" style="font-size: 1.25rem; font-weight: var(--font-weight-bold, 700); color: var(--siemens-petrol-light, #00bbbb); margin-bottom: var(--spacing-xs, 0.25rem);"><?php echo count($topLocations); ?></div>
                                    <div class="stat-label" style="font-size: var(--font-size-small, 0.875rem); color: var(--text-muted, #9ca3af); font-weight: var(--font-weight-medium, 500); text-transform: uppercase; letter-spacing: 0.5px;">Top Locations</div>
                                </div>
                                <div class="stat-card" style="background: rgba(16, 185, 129, 0.1); border: 1px solid var(--success-green, #10b981); border-radius: var(--radius-md, 0.5rem); padding: var(--spacing-md, 1rem); text-align: center;">
                                    <div class="stat-value" style="font-size: 1.25rem; font-weight: var(--font-weight-bold, 700); color: var(--success-green, #10b981); margin-bottom: var(--spacing-xs, 0.25rem);"><?php echo !empty($topLocations) ? number_format($topLocations[0]['assets_count']) : '0'; ?></div>
                                    <div class="stat-label" style="font-size: var(--font-size-small, 0.875rem); color: var(--text-muted, #9ca3af); font-weight: var(--font-weight-medium, 500); text-transform: uppercase; letter-spacing: 0.5px;">Highest Count</div>
                                </div>
                                <div class="stat-card" style="background: rgba(255, 107, 53, 0.1); border: 1px solid var(--siemens-orange, #ff6b35); border-radius: var(--radius-md, 0.5rem); padding: var(--spacing-md, 1rem); text-align: center;">
                                    <div class="stat-value" style="font-size: 1.25rem; font-weight: var(--font-weight-bold, 700); color: var(--siemens-orange, #ff6b35); margin-bottom: var(--spacing-xs, 0.25rem);"><?php echo number_format($locationStats['assets_assigned']); ?></div>
                                    <div class="stat-label" style="font-size: var(--font-size-small, 0.875rem); color: var(--text-muted, #9ca3af); font-weight: var(--font-weight-medium, 500); text-transform: uppercase; letter-spacing: 0.5px;">Total Assigned</div>
                                </div>
                            </div>
                        </div>
                    </div>


                    <!-- EPSS Risk Trends Chart -->
                    <div class="dashboard-widget epss-chart" style="grid-column: span 1; background: linear-gradient(135deg, var(--bg-card, #111111) 0%, var(--bg-tertiary, #1a1a1a) 100%); border: 1px solid var(--border-card, #1f2937); border-radius: var(--radius-lg, 0.75rem); box-shadow: var(--shadow-lg, 0 10px 15px rgba(0, 0, 0, 0.5));">
                        <div class="widget-header" style="padding: var(--spacing-md, 1rem) var(--spacing-lg, 1.5rem); border-bottom: 1px solid var(--border-card, #1f2937); background: linear-gradient(135deg, var(--bg-tertiary, #1a1a1a) 0%, var(--bg-card, #111111) 100%);">
                            <h3 style="font-size: var(--font-size-h3, 1.5rem); margin: 0; font-weight: var(--font-weight-semibold, 600); color: var(--text-primary, #ffffff); display: flex; align-items: center; font-family: var(--font-family, 'Siemens Sans', sans-serif);">
                                <i class="fas fa-chart-line" style="color: var(--siemens-petrol-light, #00bbbb); margin-right: var(--spacing-sm, 0.5rem); font-size: 1.1rem;"></i>
                                EPSS Risk Trends
                            </h3>
                            <a href="/pages/vulnerabilities/list.php" class="widget-action" style="font-size: var(--font-size-small, 0.875rem); color: var(--siemens-petrol-light, #00bbbb); text-decoration: none; font-weight: var(--font-weight-medium, 500); transition: color var(--transition-duration, 0.2s);">View Details</a>
                        </div>
                        <div class="widget-content" style="padding: var(--spacing-lg, 1.5rem); display: flex; flex-direction: column; gap: var(--spacing-md, 1rem);">
                            <div class="chart-container" style="height: 120px; background: var(--bg-secondary, #0a0a0a); border-radius: var(--radius-md, 0.5rem); padding: var(--spacing-sm, 0.5rem) var(--spacing-md, 1rem); border: 1px solid var(--border-secondary, #374151);">
                                <canvas id="epssTrendChart" width="600" height="100"></canvas>
                            </div>
                            <div class="stats-grid" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: var(--spacing-md, 1rem);">
                                <div class="stat-card" style="background: rgba(0, 153, 153, 0.1); border: 1px solid var(--siemens-petrol, #009999); border-radius: var(--radius-md, 0.5rem); padding: var(--spacing-md, 1rem); text-align: center;">
                                    <div class="stat-value" id="epss-avg-score" style="font-size: 1.25rem; font-weight: var(--font-weight-bold, 700); color: var(--siemens-petrol-light, #00bbbb); margin-bottom: var(--spacing-xs, 0.25rem);">-</div>
                                    <div class="stat-label" style="font-size: var(--font-size-small, 0.875rem); color: var(--text-muted, #9ca3af); font-weight: var(--font-weight-medium, 500); text-transform: uppercase; letter-spacing: 0.5px;">Avg EPSS Score</div>
                                </div>
                                <div class="stat-card" style="background: rgba(239, 68, 68, 0.1); border: 1px solid var(--error-red, #ef4444); border-radius: var(--radius-md, 0.5rem); padding: var(--spacing-md, 1rem); text-align: center;">
                                    <div class="stat-value" id="epss-high-risk" style="font-size: 1.25rem; font-weight: var(--font-weight-bold, 700); color: var(--error-red, #ef4444); margin-bottom: var(--spacing-xs, 0.25rem);">-</div>
                                    <div class="stat-label" style="font-size: var(--font-size-small, 0.875rem); color: var(--text-muted, #9ca3af); font-weight: var(--font-weight-medium, 500); text-transform: uppercase; letter-spacing: 0.5px;">High Risk (≥70%)</div>
                                </div>
                                <div class="stat-card" style="background: rgba(255, 107, 53, 0.1); border: 1px solid var(--siemens-orange, #ff6b35); border-radius: var(--radius-md, 0.5rem); padding: var(--spacing-md, 1rem); text-align: center;">
                                    <div class="stat-value" id="epss-trending" style="font-size: 1.25rem; font-weight: var(--font-weight-bold, 700); color: var(--siemens-orange, #ff6b35); margin-bottom: var(--spacing-xs, 0.25rem);">-</div>
                                    <div class="stat-label" style="font-size: var(--font-size-small, 0.875rem); color: var(--text-muted, #9ca3af); font-weight: var(--font-weight-medium, 500); text-transform: uppercase; letter-spacing: 0.5px;">Trending Up</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Dashboard Grid -->
            <section class="dashboard-grid">
                <!-- Recent Assets -->
                <div class="dashboard-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-server"></i> Recent Assets</h3>
                        <a href="/pages/assets/manage.php" class="widget-action">View All</a>
                    </div>
                    <div class="widget-content">
                        <?php if (empty($recentAssets)): ?>
                            <div class="empty-state">
                                <i class="fas fa-inbox"></i>
                                <p>No assets found</p>
                            </div>
                        <?php else: ?>
                            <div class="asset-list">
                                <?php foreach ($recentAssets as $asset): ?>
                                    <div class="asset-item">
                                        <div class="asset-info">
                                            <div class="asset-name"><?php echo dave_htmlspecialchars($asset['hostname'] ?: $asset['brand_name'] ?: $asset['device_name'] ?: 'Unknown'); ?></div>
                                            <div class="asset-details">
                                                <?php echo dave_htmlspecialchars($asset['ip_address']); ?> • 
                                                <?php echo dave_htmlspecialchars($asset['status'] === 'Mapped' ? 'Medical Device' : $asset['asset_type']); ?> • 
                                                <?php echo dave_htmlspecialchars($asset['department']); ?>
                                            </div>
                                        </div>
                                        <div class="asset-status">
                                            <span class="status-badge <?php echo strtolower($asset['status']); ?>">
                                                <?php echo $asset['status']; ?>
                                            </span>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Recent Vulnerabilities -->
                <div class="dashboard-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-bug"></i> Recent Vulnerabilities</h3>
                        <a href="/pages/vulnerabilities/dashboard.php" class="widget-action">View All</a>
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
                                            <div class="vuln-cve"><?php echo dave_htmlspecialchars($vuln['cve_id']); ?></div>
                                            <div class="vuln-details">
                                                <?php echo dave_htmlspecialchars($vuln['component_name']); ?> • 
                                                <?php echo dave_htmlspecialchars($vuln['hostname']); ?>
                                            </div>
                                        </div>
                                        <div class="vuln-severity">
                                            <span class="severity-badge <?php echo strtolower($vuln['severity']); ?>">
                                                <?php echo $vuln['severity']; ?>
                                            </span>
                                            <div class="cvss-score"><?php echo $vuln['cvss_v3_score']; ?></div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Recent Recalls -->
                <div class="dashboard-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-exclamation-triangle"></i> Recent Recalls</h3>
                        <a href="/pages/recalls/dashboard.php" class="widget-action">View All</a>
                    </div>
                    <div class="widget-content">
                        <?php if (empty($recentRecalls)): ?>
                            <div class="empty-state">
                                <i class="fas fa-check-circle"></i>
                                <p>No active recalls</p>
                            </div>
                        <?php else: ?>
                            <div class="recall-list">
                                <?php foreach ($recentRecalls as $recall): ?>
                                    <div class="recall-item">
                                        <div class="recall-info">
                                            <div class="recall-number"><?php echo dave_htmlspecialchars($recall['fda_recall_number']); ?></div>
                                            <div class="recall-details">
                                                <?php echo dave_htmlspecialchars($recall['manufacturer_name']); ?> • 
                                                <?php echo date('M j, Y', strtotime($recall['recall_date'])); ?>
                                            </div>
                                            <div class="recall-reason"><?php echo dave_htmlspecialchars(substr($recall['reason_for_recall'], 0, 100)); ?>...</div>
                                        </div>
                                        <div class="recall-impact">
                                            <span class="impact-count"><?php echo $recall['affected_count']; ?> devices</span>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

            </section>


        </main>
    </div>

    <script>
        // Auto-refresh dashboard - disabled by default to prevent browser lockup
        // Uncomment and adjust interval if needed:
        // setInterval(function() {
        //     location.reload();
        // }, 30000);

        // Add loading states to navigation links
        document.querySelectorAll('.nav-item').forEach(function(item) {
            item.addEventListener('click', function() {
                this.classList.add('loading');
            });
        });

        // Load EPSS trend chart and locations chart
        document.addEventListener('DOMContentLoaded', function() {
            loadEPSSDashboardChart();
            loadLocationsChart();
        });

        async function loadEPSSDashboardChart() {
            try {
                
                // Use embedded EPSS data from PHP
                const epssData = <?php echo json_encode($epssData); ?>;

                if (epssData.success) {
                    const stats = epssData.data.overall;
                    const trends = epssData.data.recent_trends;
                    const trending = epssData.data.trending;
                    
                    // Update stat displays
                    document.getElementById('epss-avg-score').textContent = 
                        stats.avg_epss_score ? (stats.avg_epss_score * 100).toFixed(1) + '%' : 'N/A';
                    document.getElementById('epss-high-risk').textContent = stats.high_epss_count || 0;
                    document.getElementById('epss-trending').textContent = trending.count || 0;
                    
                    
                    // Create chart with trend data
                    if (trends && trends.length > 0) {
                        createEPSSDashboardChart(trends);
                    } else {
                    }
                } else {
                    console.error('EPSS data returned error:', epssData.error);
                }
            } catch (error) {
                console.error('Error loading EPSS dashboard data:', error);
            }
        }

        function createEPSSDashboardChart(trendData) {
            
            const ctx = document.getElementById('epssTrendChart');
            if (!ctx) {
                console.error('Canvas element not found: epssTrendChart');
                return;
            }
            
            if (!trendData || trendData.length === 0) {
                console.error('No trend data provided');
                return;
            }

            // Prepare chart data
            const labels = trendData.map(item => {
                const date = new Date(item.recorded_date);
                return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            });
            
            const epssScores = trendData.map(item => (item.avg_epss_score * 100).toFixed(1));
            const highRiskCounts = trendData.map(item => item.high_epss_count);


            try {
                const chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Avg EPSS Score (%)',
                            data: epssScores,
                            borderColor: '#009999', // Siemens Petrol
                            backgroundColor: 'rgba(0, 153, 153, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4,
                            yAxisID: 'y'
                        },
                        {
                            label: 'High Risk Count',
                            data: highRiskCounts,
                            borderColor: '#ff6b35', // Siemens Orange
                            backgroundColor: 'rgba(255, 107, 53, 0.1)',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.4,
                            yAxisID: 'y1'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#cbd5e1',
                                font: {
                                    size: 12
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: '#94a3b8',
                                font: {
                                    size: 11
                                }
                            },
                            grid: {
                                color: '#374151'
                            }
                        },
                        y: {
                            type: 'linear',
                            display: true,
                            position: 'left',
                            title: {
                                display: true,
                                text: 'EPSS Score (%)',
                                color: '#cbd5e1',
                                font: {
                                    size: 12
                                }
                            },
                            ticks: {
                                color: '#94a3b8',
                                font: {
                                    size: 11
                                }
                            },
                            grid: {
                                color: '#374151'
                            }
                        },
                        y1: {
                            type: 'linear',
                            display: true,
                            position: 'right',
                            title: {
                                display: true,
                                text: 'High Risk Count',
                                color: '#cbd5e1',
                                font: {
                                    size: 12
                                }
                            },
                            ticks: {
                                color: '#94a3b8',
                                font: {
                                    size: 11
                                }
                            },
                            grid: {
                                drawOnChartArea: false,
                            }
                        }
                    }
                }
            });
            
            } catch (error) {
                console.error('Error creating EPSS chart:', error);
            }
        }

        // Load Locations Chart
        function loadLocationsChart() {
            try {
                
                // Get top locations data from PHP
                const topLocations = <?php echo json_encode($topLocations); ?>;
                
                createLocationsChart(topLocations);
            } catch (error) {
                console.error('Error loading locations chart:', error);
            }
        }

        function createLocationsChart(topLocations) {
            
            const ctx = document.getElementById('locationsChart');
            if (!ctx) {
                console.error('Canvas element not found: locationsChart');
                return;
            }
            
            if (!topLocations || topLocations.length === 0) {
                return;
            }
            
            // Prepare chart data
            const labels = topLocations.map(location => {
                // Truncate long location names
                const name = location.location_name;
                return name.length > 12 ? name.substring(0, 12) + '...' : name;
            });
            const data = topLocations.map(location => parseInt(location.assets_count));
            
            // Generate colors for each bar
            const colors = [
                'rgba(59, 130, 246, 0.8)',   // Blue
                'rgba(34, 197, 94, 0.8)',   // Green
                'rgba(249, 115, 22, 0.8)',   // Orange
                'rgba(168, 85, 247, 0.8)',   // Purple
                'rgba(236, 72, 153, 0.8)'    // Pink
            ];
            
            const borderColors = [
                'rgba(59, 130, 246, 1)',
                'rgba(34, 197, 94, 1)',
                'rgba(249, 115, 22, 1)',
                'rgba(168, 85, 247, 1)',
                'rgba(236, 72, 153, 1)'
            ];
            
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Assets Assigned',
                        data: data,
                        backgroundColor: colors.slice(0, data.length),
                        borderColor: borderColors.slice(0, data.length),
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: '#94a3b8',
                                font: {
                                    size: 9
                                },
                                maxRotation: 45
                            },
                            grid: {
                                color: '#374151'
                            }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: {
                                color: '#94a3b8',
                                font: {
                                    size: 10
                                }
                            },
                            grid: {
                                color: '#374151'
                            }
                        }
                    }
                }
            });
            
        }
    </script>
    
    <!--  Configuration -->
    <script>
        <?php include __DIR__ . '/../assets/js/config.js'; ?>
    </script>
    
    <!-- Common Dashboard JavaScript -->
    <script src="/assets/js/dashboard-common.js"></script>
    
    <style>
        /* Consistent Spacing Override for All Dashboard Sections */
        .metrics-section {
            margin-bottom: 0.5rem !important;
        }
        
        .priority-section {
            margin: 2rem 0 !important;
        }
        
        .combined-metrics-section {
            margin: 2rem 0 !important;
        }
        
        .dashboard-grid {
            margin-bottom: 0.5rem !important;
        }
        
        /* Siemens Healthineers Brand-Compliant Card Styling */
        .dashboard-widget.locations-chart,
        .dashboard-widget.epss-chart {
            transition: all var(--transition-duration, 0.2s) var(--transition-easing, ease);
            cursor: pointer;
        }
        
        .dashboard-widget.locations-chart:hover,
        .dashboard-widget.epss-chart:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-xl, 0 20px 25px rgba(0, 0, 0, 0.6));
            border-color: var(--siemens-petrol-light, #00bbbb);
        }
        
        .stat-card {
            transition: all var(--transition-duration, 0.2s) var(--transition-easing, ease);
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md, 0 4px 6px rgba(0, 0, 0, 0.4));
        }
        
        .widget-action:hover {
            color: var(--text-primary, #ffffff) !important;
        }
        
        .chart-container {
            transition: all var(--transition-duration, 0.2s) var(--transition-easing, ease);
        }
        
        .dashboard-widget:hover .chart-container {
            border-color: var(--siemens-petrol-light, #00bbbb);
            background: rgba(0, 187, 187, 0.05);
        }
        
        /* Siemens Healthineers Brand Focus States */
        .dashboard-widget:focus-within {
            outline: 2px solid var(--siemens-petrol, #009999);
            outline-offset: 2px;
        }
        
        .stat-card:focus-within {
            outline: 1px solid var(--siemens-petrol, #009999);
            outline-offset: 1px;
        }
    </style>
</body>
</html>
