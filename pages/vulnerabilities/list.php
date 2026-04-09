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

// Initialize authentication
$auth = new Auth();
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

// Check permissions
if (!$auth->hasPermission('vulnerabilities.view')) {
    header('Location: /pages/dashboard.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['ajax']) {
        case 'risk_accept_vulnerability':
            try {
                $input = json_decode(file_get_contents('php://input'), true);
                $cveId = $input['cve_id'] ?? '';
                $note = trim($input['note'] ?? '');
                if (!$cveId || $note === '') { throw new Exception('CVE ID and note are required'); }
                // Upsert override
                $pdo = DatabaseConfig::getInstance()->getConnection();
                $sql = "INSERT INTO vulnerability_overrides (cve_id, override_status, note, accepted_by)
                        VALUES (?, 'Risk Accepted', ?, ?)
                        ON CONFLICT (cve_id) DO UPDATE SET override_status = EXCLUDED.override_status, note = EXCLUDED.note, accepted_by = EXCLUDED.accepted_by, created_at = CURRENT_TIMESTAMP";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$cveId, $note, $user['user_id'] ?? null]);
                echo json_encode(['success' => true]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            exit;

        case 'delete_vulnerability':
            try {
                $input = json_decode(file_get_contents('php://input'), true);
                $cveId = $input['cve_id'] ?? '';
                if (!$cveId) { throw new Exception('CVE ID is required'); }
                // Delete dependent data first (safe even if empty)
                $pdo = DatabaseConfig::getInstance()->getConnection();
                $pdo->beginTransaction();
                $pdo->prepare("DELETE FROM device_vulnerabilities_link WHERE cve_id = ?")->execute([$cveId]);
                $pdo->prepare("DELETE FROM action_device_links USING remediation_actions ra WHERE action_device_links.action_id = ra.action_id AND ra.cve_id = ?")->execute([$cveId]);
                $pdo->prepare("DELETE FROM remediation_actions WHERE cve_id = ?")->execute([$cveId]);
                $pdo->prepare("DELETE FROM software_package_vulnerabilities WHERE cve_id = ?")->execute([$cveId]);
                $pdo->prepare("DELETE FROM epss_score_history WHERE cve_id = ?")->execute([$cveId]);
                $pdo->prepare("DELETE FROM vulnerability_overrides WHERE cve_id = ?")->execute([$cveId]);
                $pdo->prepare("DELETE FROM vulnerabilities WHERE cve_id = ?")->execute([$cveId]);
                $pdo->commit();
                echo json_encode(['success' => true]);
            } catch (Exception $e) {
                try { if (isset($pdo) && $pdo->inTransaction()) { $pdo->rollBack(); } } catch (Exception $ie) {}
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            exit;
        case 'get_vulnerabilities':
            try {
                $page = (int)($_GET['page'] ?? 1);
                $limit = (int)($_GET['limit'] ?? 25);
                $offset = ($page - 1) * $limit;
                
                $search = $_GET['search'] ?? '';
                $severity = $_GET['severity'] ?? '';
                $status = $_GET['status'] ?? '';
                $epss_gt = $_GET['epss_gt'] ?? '';
                $epss_percentile_gt = $_GET['epss_percentile_gt'] ?? '';
                
                // Build query
                $whereConditions = [];
                $params = [];
                
                if (!empty($search)) {
                    $whereConditions[] = "(v.cve_id ILIKE ? OR v.description ILIKE ?)";
                    $params[] = "%$search%";
                    $params[] = "%$search%";
                }
                
                if (!empty($severity)) {
                    $whereConditions[] = "v.severity = ?";
                    $params[] = $severity;
                }
                
                if (!empty($status)) {
                    if ($status === 'Risk Accepted (any)') {
                        $whereConditions[] = "EXISTS (SELECT 1 FROM vulnerability_overrides_device vod_any WHERE vod_any.cve_id = v.cve_id)";
                    } else if ($status === 'Risk Accepted') {
                        // Fully accepted = every linked device has a per-device override
                        $whereConditions[] = "NOT EXISTS (SELECT 1 FROM device_vulnerabilities_link d1 WHERE d1.cve_id = v.cve_id AND NOT EXISTS (SELECT 1 FROM vulnerability_overrides_device vod2 WHERE vod2.cve_id = v.cve_id AND vod2.device_id = d1.device_id))";
                    } else {
                        $whereConditions[] = "dvl.remediation_status = ?";
                        $params[] = $status;
                    }
                }
                
                if (!empty($epss_gt) && is_numeric($epss_gt)) {
                    $whereConditions[] = "v.epss_score >= ?";
                    $params[] = floatval($epss_gt);
                }
                
                if (!empty($epss_percentile_gt) && is_numeric($epss_percentile_gt)) {
                    $whereConditions[] = "v.epss_percentile >= ?";
                    $params[] = floatval($epss_percentile_gt);
                }
                
                $whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';
                
                // Get total count
                $countSql = "SELECT COUNT(DISTINCT v.cve_id) as total
                            FROM vulnerabilities v
                            LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
                            LEFT JOIN vulnerability_overrides vo ON vo.cve_id = v.cve_id
                            LEFT JOIN vulnerability_overrides_device vod ON vod.cve_id = v.cve_id AND vod.device_id = dvl.device_id
                            $whereClause";
                
                $countStmt = $db->prepare($countSql);
                $countStmt->execute($params);
                $total = $countStmt->fetch()['total'];
                
                // Get vulnerabilities
                $sql = "SELECT 
                            v.vulnerability_id,
                            v.cve_id,
                            v.description,
                            v.cvss_v4_score,
                            v.cvss_v4_vector,
                            v.cvss_v3_score,
                            v.cvss_v3_vector,
                            v.cvss_v2_score,
                            v.cvss_v2_vector,
                            v.severity,
                            v.published_date,
                            v.last_modified_date,
                            v.epss_score,
                            v.epss_percentile,
                            v.epss_date,
                            v.epss_last_updated,
                            vo.override_status,
                            COUNT(DISTINCT dvl.device_id) as affected_devices,
                            COUNT(DISTINCT CASE WHEN dvl.remediation_status = 'Open' AND vod.device_id IS NULL THEN dvl.device_id END) as open_count,
                            COUNT(DISTINCT CASE WHEN dvl.remediation_status = 'Resolved' THEN dvl.device_id END) as resolved_count,
                            COALESCE(v.cvss_v4_score, v.cvss_v3_score, v.cvss_v2_score) as best_cvss_score
                        FROM vulnerabilities v
                        LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
                        LEFT JOIN vulnerability_overrides vo ON vo.cve_id = v.cve_id
                        LEFT JOIN vulnerability_overrides_device vod ON vod.cve_id = v.cve_id AND vod.device_id = dvl.device_id
                        $whereClause
                        GROUP BY v.vulnerability_id, v.cve_id, v.description, v.cvss_v4_score, v.cvss_v4_vector,
                                 v.cvss_v3_score, v.cvss_v3_vector, v.cvss_v2_score, v.cvss_v2_vector,
                                 v.severity, v.published_date, v.last_modified_date,
                                 v.epss_score, v.epss_percentile, v.epss_date, v.epss_last_updated,
                                 vo.override_status
                        ORDER BY best_cvss_score DESC NULLS LAST, v.published_date DESC
                        LIMIT ? OFFSET ?";
                
                $params[] = $limit;
                $params[] = $offset;
                
                $stmt = $db->prepare($sql);
                $stmt->execute($params);
                $vulnerabilities = $stmt->fetchAll();
                
                echo json_encode([
                    'success' => true,
                    'data' => $vulnerabilities,
                    'pagination' => [
                        'page' => $page,
                        'limit' => $limit,
                        'total' => $total,
                        'pages' => ceil($total / $limit)
                    ]
                ]);
                
            } catch (Exception $e) {
                echo json_encode([
                    'success' => false,
                    'error' => $e->getMessage()
                ]);
            }
            exit;
            
        case 'get_vulnerability_details':
            try {
                $vulnerabilityId = $_GET['vulnerability_id'] ?? '';
                
                if (empty($vulnerabilityId)) {
                    throw new Exception('Vulnerability ID required');
                }
                
                // Get vulnerability basic details first
                $sql = "SELECT v.*
                        FROM vulnerabilities v
                        WHERE v.vulnerability_id = ?";
                
                $stmt = $db->prepare($sql);
                $stmt->execute([$vulnerabilityId]);
                $vulnerability = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$vulnerability) {
                    throw new Exception('Vulnerability not found');
                }
                
                // Get aggregated counts separately
                $countSql = "SELECT 
                               COUNT(DISTINCT dvl.device_id) as total_affected,
                               COUNT(DISTINCT CASE WHEN dvl.remediation_status = 'Open' AND vod.device_id IS NULL THEN dvl.device_id END) as open_count,
                               COUNT(DISTINCT CASE WHEN dvl.remediation_status = 'In Progress' THEN dvl.device_id END) as in_progress_count,
                               COUNT(DISTINCT CASE WHEN dvl.remediation_status = 'Resolved' THEN dvl.device_id END) as resolved_count,
                               COUNT(DISTINCT CASE WHEN dvl.remediation_status = 'Mitigated' THEN dvl.device_id END) as mitigated_count,
                               COUNT(DISTINCT CASE WHEN dvl.remediation_status = 'False Positive' THEN dvl.device_id END) as false_positive_count,
                               COUNT(DISTINCT vod.device_id) as risk_accepted_devices
                        FROM vulnerabilities v
                        LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
                        LEFT JOIN vulnerability_overrides_device vod ON vod.cve_id = v.cve_id AND vod.device_id = dvl.device_id
                        WHERE v.vulnerability_id = ?";
                
                $countStmt = $db->prepare($countSql);
                $countStmt->execute([$vulnerabilityId]);
                $counts = $countStmt->fetch(PDO::FETCH_ASSOC);
                
                // Merge counts into vulnerability array
                $vulnerability = array_merge($vulnerability, $counts);
                
                // Get affected devices
                $deviceSql = "SELECT DISTINCT ON (dvl.device_id) dvl.*, 
                                     CASE 
                                         WHEN a.hostname IS NOT NULL AND a.hostname != '' THEN a.hostname
                                         WHEN md.device_name IS NOT NULL AND md.device_name != '' THEN md.device_name
                                         WHEN md.brand_name IS NOT NULL AND md.model_number IS NOT NULL THEN CONCAT(md.brand_name, ' ', md.model_number)
                                         WHEN md.brand_name IS NOT NULL THEN md.brand_name
                                         WHEN a.asset_tag IS NOT NULL AND a.asset_tag != '' THEN a.asset_tag
                                         WHEN a.ip_address IS NOT NULL THEN a.ip_address::text
                                         ELSE 'Unknown Device'
                                     END as device_name,
                                     a.hostname, 
                                     a.ip_address,
                                     a.asset_tag,
                                     a.asset_type,
                                     md.device_name as fda_device_name,
                                     md.brand_name,
                                     md.model_number,
                                     md.manufacturer_name,
                                     sc.name as component_name,
                                     sc.version as component_version,
                                     sc.vendor as component_vendor,
                                     (vod.device_id IS NOT NULL) as risk_accepted,
                                     vod.note as risk_accept_note
                              FROM device_vulnerabilities_link dvl
                              JOIN medical_devices md ON dvl.device_id = md.device_id
                              JOIN assets a ON md.asset_id = a.asset_id
                              JOIN software_components sc ON dvl.component_id = sc.component_id
                              LEFT JOIN vulnerability_overrides_device vod ON vod.cve_id = dvl.cve_id AND vod.device_id = dvl.device_id
                              WHERE dvl.cve_id = ? AND dvl.device_id IS NOT NULL
                              ORDER BY dvl.device_id, device_name, sc.name";
                
                $deviceStmt = $db->prepare($deviceSql);
                $deviceStmt->execute([$vulnerability['cve_id']]);
                $affectedDevices = $deviceStmt->fetchAll();
                
                echo json_encode([
                    'success' => true,
                    'vulnerability' => $vulnerability,
                    'affected_devices' => $affectedDevices
                ]);
                
            } catch (Exception $e) {
                echo json_encode([
                    'success' => false,
                    'error' => $e->getMessage()
                ]);
            }
            exit;
            
        case 'get_epss_trends':
            try {
                $cveId = $_GET['cve_id'] ?? '';
                $days = (int)($_GET['days'] ?? 30);
                
                if (empty($cveId)) {
                    throw new Exception('CVE ID required');
                }
                
                // Get EPSS trend data
                $sql = "SELECT 
                            recorded_date,
                            epss_score,
                            epss_percentile
                        FROM epss_score_history 
                        WHERE cve_id = ? 
                        AND recorded_date >= CURRENT_DATE - ? * INTERVAL '1 day'
                        ORDER BY recorded_date ASC";
                
                $stmt = $db->prepare($sql);
                $stmt->execute([$cveId, $days]);
                $trends = $stmt->fetchAll();
                
                echo json_encode([
                    'success' => true,
                    'data' => $trends
                ]);
                
            } catch (Exception $e) {
                echo json_encode([
                    'success' => false,
                    'error' => $e->getMessage()
                ]);
            }
            exit;
        case 'risk_accept_vulnerability_devices':
            try {
                $input = json_decode(file_get_contents('php://input'), true);
                $cveId = $input['cve_id'] ?? '';
                $deviceIds = $input['device_ids'] ?? [];
                $note = trim($input['note'] ?? '');
                if (!$cveId || empty($deviceIds) || $note === '') { throw new Exception('CVE ID, devices, and note are required'); }
                $pdo = DatabaseConfig::getInstance()->getConnection();
                $pdo->beginTransaction();
                $stmt = $pdo->prepare("INSERT INTO vulnerability_overrides_device (cve_id, device_id, override_status, note, accepted_by) VALUES (?, ?, 'Risk Accepted', ?, ?)\n                                        ON CONFLICT (cve_id, device_id) DO UPDATE SET override_status = EXCLUDED.override_status, note = EXCLUDED.note, accepted_by = EXCLUDED.accepted_by, created_at = CURRENT_TIMESTAMP");
                foreach ($deviceIds as $did) {
                    $stmt->execute([$cveId, $did, $note, $user['user_id'] ?? null]);
                }
                $pdo->commit();
                echo json_encode(['success' => true]);
            } catch (Exception $e) {
                try { if (isset($pdo) && $pdo->inTransaction()) { $pdo->rollBack(); } } catch (Exception $ie) {}
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            exit;
    }
}

// Get vulnerability statistics
try {
    // Get vulnerability counts (no join needed)
    $vulnStatsSql = "SELECT 
                        COUNT(*) as total_vulnerabilities,
                        COUNT(CASE WHEN severity = 'Critical' THEN 1 END) as critical_count,
                        COUNT(CASE WHEN severity = 'High' THEN 1 END) as high_count,
                        COUNT(CASE WHEN severity = 'Medium' THEN 1 END) as medium_count,
                        COUNT(CASE WHEN severity = 'Low' THEN 1 END) as low_count
                     FROM vulnerabilities";
    
    $vulnStatsStmt = $db->query($vulnStatsSql);
    $vulnStats = $vulnStatsStmt->fetch();
    
    // Get device and remediation counts (exclude patched devices)
    $deviceStatsSql = "SELECT 
                        COUNT(DISTINCT dvl.device_id) as affected_devices,
                        COUNT(CASE WHEN dvl.remediation_status = 'Open' THEN 1 END) as open_count,
                        COUNT(CASE WHEN dvl.remediation_status = 'Resolved' THEN 1 END) as resolved_count
                       FROM device_vulnerabilities_link dvl
                       JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
                       WHERE NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))";
    
    $deviceStatsStmt = $db->query($deviceStatsSql);
    $deviceStats = $deviceStatsStmt->fetch();
    
    // Combine the results
    $stats = array_merge($vulnStats, $deviceStats);
    
} catch (Exception $e) {
    $stats = [
        'total_vulnerabilities' => 0,
        'affected_devices' => 0,
        'critical_count' => 0,
        'high_count' => 0,
        'medium_count' => 0,
        'low_count' => 0,
        'open_count' => 0,
        'resolved_count' => 0
    ];
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
    <title>Vulnerability Management - </title>
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/vulnerabilities.css">
    <link rel="stylesheet" href="/assets/css/epss-badges.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-bug"></i> Vulnerability Management</h1>
                    <p>Monitor and manage cybersecurity vulnerabilities discovered through SBOM evaluation</p>
                </div>
                <div class="page-actions">
                    <a href="/pages/vulnerabilities/dashboard.php" class="btn btn-secondary">
                        <i class="fas fa-chart-line"></i> Dashboard
                    </a>
                    <?php if ($auth->hasPermission('vulnerabilities.manage')): ?>
                    <a href="/pages/vulnerabilities/upload-sbom.php" class="btn btn-primary">
                        <i class="fas fa-upload"></i> Upload SBOM
                    </a>
                    <?php endif; ?>
                </div>
            </div>

        <!-- Vulnerability Metrics -->
        <div class="metrics-section">
            <div class="metrics-header">
                <h2><i class="fas fa-chart-bar"></i> Vulnerability Metrics</h2>
                <div class="metrics-summary">
                    <span class="summary-item">
                        <strong><?php echo number_format($stats['total_vulnerabilities']); ?></strong> Total Vulnerabilities
                    </span>
                    <span class="summary-item">
                        <strong><?php echo number_format($stats['affected_devices']); ?></strong> Affected Devices
                    </span>
                    <span class="summary-item">
                        <strong><?php echo number_format($stats['open_count']); ?></strong> Open Issues
                    </span>
                </div>
            </div>
            
            <div class="metrics-grid">
                <div class="metric-card critical">
                    <div class="metric-icon">
                        <i class="fas fa-fire"></i>
                    </div>
                    <div class="metric-content">
                        <div class="metric-value"><?php echo number_format($stats['critical_count']); ?></div>
                        <div class="metric-label">Critical</div>
                        <div class="metric-description">Immediate attention required</div>
                    </div>
                </div>
                
                <div class="metric-card high">
                    <div class="metric-icon">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="metric-content">
                        <div class="metric-value"><?php echo number_format($stats['high_count']); ?></div>
                        <div class="metric-label">High</div>
                        <div class="metric-description">Priority remediation</div>
                    </div>
                </div>
                
                <div class="metric-card medium">
                    <div class="metric-icon">
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                    <div class="metric-content">
                        <div class="metric-value"><?php echo number_format($stats['medium_count']); ?></div>
                        <div class="metric-label">Medium</div>
                        <div class="metric-description">Schedule remediation</div>
                    </div>
                </div>
                
                <div class="metric-card low">
                    <div class="metric-icon">
                        <i class="fas fa-info-circle"></i>
                    </div>
                    <div class="metric-content">
                        <div class="metric-value"><?php echo number_format($stats['low_count']); ?></div>
                        <div class="metric-label">Low</div>
                        <div class="metric-description">Monitor and assess</div>
                    </div>
                </div>
                
                <div class="metric-card resolved">
                    <div class="metric-icon">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div class="metric-content">
                        <div class="metric-value"><?php echo number_format($stats['resolved_count']); ?></div>
                        <div class="metric-label">Resolved</div>
                        <div class="metric-description">Successfully remediated</div>
                    </div>
                </div>
                
                <div class="metric-card total">
                    <div class="metric-icon">
                        <i class="fas fa-bug"></i>
                    </div>
                    <div class="metric-content">
                        <div class="metric-value"><?php echo number_format($stats['total_vulnerabilities']); ?></div>
                        <div class="metric-label">Total</div>
                        <div class="metric-description">All vulnerabilities</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Filters and Search -->
        <div class="filters-section">
            <!-- Search Bar -->
            <div class="search-bar-container">
                <div class="search-input-wrapper">
                    <i class="fas fa-search search-icon"></i>
                    <input 
                        type="text" 
                        id="searchInput" 
                        class="search-input" 
                        placeholder="Search vulnerabilities by CVE ID or description..."
                        autocomplete="off"
                    >
                    <button type="button" id="clearSearch" class="clear-search-btn" style="display: none;">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>
            
            <!-- Filters Grid -->
            <div class="filters-grid">
                <div class="filter-group">
                    <label for="severityFilter">
                        <i class="fas fa-exclamation-triangle"></i> Severity
                    </label>
                    <select id="severityFilter" class="filter-select">
                        <option value="">All Severities</option>
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                    </select>
                </div>
                
                <div class="filter-group">
                    <label for="statusFilter">
                        <i class="fas fa-signal"></i> Status
                    </label>
                    <select id="statusFilter" class="filter-select">
                        <option value="">All Statuses</option>
                        <option value="Open">Open</option>
                        <option value="In Progress">In Progress</option>
                        <option value="Resolved">Resolved</option>
                        <option value="Mitigated">Mitigated</option>
                        <option value="False Positive">False Positive</option>
                        <option value="Risk Accepted">Risk Accepted</option>
                        <option value="Risk Accepted (any)">Risk Accepted (any device)</option>
                    </select>
                </div>
                
                <div class="filter-group">
                    <label for="epssFilter">
                        <i class="fas fa-chart-line"></i> EPSS Risk
                    </label>
                    <select id="epssFilter" class="filter-select">
                        <option value="">All EPSS Scores</option>
                        <option value="0.7">High Risk (≥70%)</option>
                        <option value="0.3">Medium Risk (≥30%)</option>
                        <option value="0.1">Low Risk (≥10%)</option>
                    </select>
                </div>
                
                <div class="filter-group">
                    <label>&nbsp;</label>
                    <button type="button" id="clearFilters" class="btn btn-secondary">
                        <i class="fas fa-times"></i> Clear All
                    </button>
                </div>
            </div>
        </div>

        <!-- Vulnerabilities DataTable -->
        <div class="datatable-container">
            <div class="datatable-header">
                <div class="datatable-title">
                    <h3><i class="fas fa-table"></i> Vulnerabilities Database</h3>
                    <p>Complete list of discovered vulnerabilities with search and filtering capabilities</p>
                </div>
                <div class="datatable-actions">
                    <div class="table-controls">
                        <label for="pageSize">Show:</label>
                        <select id="pageSize" class="page-size-select">
                            <option value="25">25</option>
                            <option value="50">50</option>
                            <option value="100">100</option>
                        </select>
                        <span class="results-info">
                            <span id="resultsCount">Loading...</span>
                        </span>
                    </div>
                </div>
            </div>
            
            <div class="datatable-wrapper">
                <table class="data-table" id="vulnerabilitiesTable">
                    <thead>
                        <tr>
                            <th class="sortable" data-sort="vulnerability_id">
                                ID <i class="fas fa-sort"></i>
                            </th>
                            <th class="sortable" data-sort="cve_id">
                                CVE ID <i class="fas fa-sort"></i>
                            </th>
                            <th class="sortable" data-sort="description">
                                Description <i class="fas fa-sort"></i>
                            </th>
                            <th class="sortable" data-sort="severity">
                                Severity <i class="fas fa-sort"></i>
                            </th>
                            <th class="sortable" data-sort="cvss_v3_score">
                                CVSS Score <i class="fas fa-sort"></i>
                            </th>
                            <th class="sortable" data-sort="epss_score">
                                EPSS Score <i class="fas fa-sort"></i>
                            </th>
                            <th class="sortable" data-sort="published_date">
                                Published <i class="fas fa-sort"></i>
                            </th>
                            <th class="sortable" data-sort="affected_devices">
                                Affected Devices <i class="fas fa-sort"></i>
                            </th>
                            <th class="sortable" data-sort="open_count">
                                Status <i class="fas fa-sort"></i>
                            </th>
                            
                        </tr>
                    </thead>
                    <tbody id="vulnerabilitiesTableBody">
                        <tr>
                            <td colspan="9" class="loading-cell">
                                <div class="loading-content">
                                    <i class="fas fa-spinner fa-spin"></i>
                                    <span>Loading vulnerabilities...</span>
                                </div>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <!-- Pagination and Table Info -->
            <div class="datatable-footer">
                <div class="table-info">
                    <span id="tableInfo">Loading...</span>
                </div>
                <div class="pagination-container" id="paginationContainer">
                    <!-- Pagination will be populated by JavaScript -->
                </div>
            </div>
        </div>
    </div>

    <!-- Vulnerability Details Modal -->
    <div id="vulnerabilityModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">Vulnerability Details</h2>
                <button type="button" class="modal-close" onclick="closeVulnerabilityModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body" id="modalBody">
                <!-- Content will be populated by JavaScript -->
            </div>
        </div>
        </main>
    </div>

    <script src="/assets/js/dashboard-common.js?v=<?php echo time(); ?>"></script>
    <script src="/assets/js/epss-utils.js?v=<?php echo time(); ?>"></script>
    <script>
        // Utility Functions
        function debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }

        function showNotification(message, type = 'info') {
            // Create notification element
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <div class="notification-content">
                    <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                    <span>${message}</span>
                </div>
                <button class="notification-close" onclick="this.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            `;
            
            // Add to page
            document.body.appendChild(notification);
            
            // Auto remove after 5 seconds
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.remove();
                }
            }, 5000);
        }

        let currentPage = 1;
        let currentPageSize = 25;
        let currentSort = 'cvss_v3_score';
        let currentSortDir = 'desc';
        let currentFilters = {
            search: '',
            severity: '',
            status: '',
            epss_gt: ''
        };

        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {
            loadVulnerabilities();
            setupEventListeners();
        });

        function setupEventListeners() {
            // Search input
            document.getElementById('searchInput').addEventListener('input', debounce(function() {
                currentFilters.search = this.value;
                currentPage = 1;
                loadVulnerabilities();
            }, 500));

            // Filter selects
            document.getElementById('severityFilter').addEventListener('change', function() {
                currentFilters.severity = this.value;
                currentPage = 1;
                loadVulnerabilities();
            });

            document.getElementById('statusFilter').addEventListener('change', function() {
                currentFilters.status = this.value;
                currentPage = 1;
                loadVulnerabilities();
            });

            document.getElementById('epssFilter').addEventListener('change', function() {
                currentFilters.epss_gt = this.value;
                currentPage = 1;
                loadVulnerabilities();
            });

            // Page size selector
            document.getElementById('pageSize').addEventListener('change', function() {
                currentPageSize = parseInt(this.value);
                currentPage = 1;
                loadVulnerabilities();
            });

            // Clear filters
            document.getElementById('clearFilters').addEventListener('click', function() {
                document.getElementById('searchInput').value = '';
                document.getElementById('severityFilter').value = '';
                document.getElementById('statusFilter').value = '';
                document.getElementById('epssFilter').value = '';
                currentFilters = { search: '', severity: '', status: '', epss_gt: '' };
                currentPage = 1;
                loadVulnerabilities();
            });

            // Sortable headers
            document.querySelectorAll('.sortable').forEach(header => {
                header.addEventListener('click', function() {
                    const sortField = this.dataset.sort;
                    if (currentSort === sortField) {
                        currentSortDir = currentSortDir === 'asc' ? 'desc' : 'asc';
                    } else {
                        currentSort = sortField;
                        currentSortDir = 'desc';
                    }
                    currentPage = 1;
                    updateSortIndicators();
                    loadVulnerabilities();
                });
            });
        }

        function loadVulnerabilities() {
            const params = new URLSearchParams({
                ajax: 'get_vulnerabilities',
                page: currentPage,
                limit: currentPageSize,
                sort: currentSort,
                sort_dir: currentSortDir,
                ...currentFilters,
                _t: Date.now() // Cache busting
            });

            fetch(`?${params}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        displayVulnerabilities(data.data);
                        updatePagination(data.pagination);
                        updateResultsCount(data.pagination.total);
                        updateTableInfo(data.pagination);
                    } else {
                        showNotification('Error loading vulnerabilities: ' + data.error, 'error');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showNotification('Error loading vulnerabilities', 'error');
                });
        }

        function displayVulnerabilities(vulnerabilities) {
            const tbody = document.getElementById('vulnerabilitiesTableBody');
            
            if (vulnerabilities.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="9" class="empty-cell">
                            <i class="fas fa-search"></i>
                            <p>No vulnerabilities found</p>
                            <small>Try adjusting your search criteria</small>
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = vulnerabilities.map(vuln => `
                <tr ${vuln.is_kev ? 'class="kev-row"' : ''}>
                    <td>
                        <a href="#" onclick="showVulnerabilityDetails('${vuln.vulnerability_id}'); return false;" class="cve-link">
                            ${vuln.vulnerability_id}
                        </a>
                    </td>
                    <td>
                        ${vuln.cve_id}
                        ${vuln.is_kev ? '<span class="kev-badge" title="CISA Known Exploited Vulnerability">🔥 KEV</span>' : ''}
                    </td>
                    <td class="description-cell">
                        <div class="description-text" title="${escapeHtml(vuln.description)}">
                            ${truncateText(vuln.description, 100)}
                        </div>
                    </td>
                    <td>
                        <span class="severity-badge ${vuln.severity.toLowerCase()}">
                            ${vuln.severity || 'Unknown'}
                        </span>
                        ${vuln.is_kev && vuln.kev_due_date ? `<div class="kev-due-date ${isOverdue(vuln.kev_due_date) ? 'overdue' : ''}">Due: ${formatDate(vuln.kev_due_date)}</div>` : ''}
                    </td>
                    <td>
                        ${(() => {
                            // Determine which CVSS score to display (v4 > v3 > v2)
                            let cvssDisplay = 'N/A';
                            let cvssVersion = '';
                            
                            if (vuln.cvss_v4_score && parseFloat(vuln.cvss_v4_score) > 0) {
                                cvssDisplay = vuln.cvss_v4_score;
                                cvssVersion = '(v4.0)';
                            } else if (vuln.cvss_v3_score && parseFloat(vuln.cvss_v3_score) > 0) {
                                cvssDisplay = vuln.cvss_v3_score;
                                cvssVersion = '(v3.x)';
                            } else if (vuln.cvss_v2_score && parseFloat(vuln.cvss_v2_score) > 0) {
                                cvssDisplay = vuln.cvss_v2_score;
                                cvssVersion = '(v2.0)';
                            }
                            
                            if (cvssDisplay !== 'N/A') {
                                return `<span class="cvss-score ${getCvssClass(cvssDisplay)}">${cvssDisplay}</span> <span style="font-size: 0.75rem; color: var(--text-muted);">${cvssVersion}</span>`;
                            } else {
                                return '<span class="text-muted">N/A</span>';
                            }
                        })()}
                    </td>
                    <td>
                        ${vuln.epss_score !== null && vuln.epss_score !== undefined ? 
                            generateEPSSBadge(vuln.epss_score, vuln.epss_percentile) : 
                            '<span class="text-muted">N/A</span>'
                        }
                    </td>
                    <td>
                        ${vuln.published_date ? 
                            new Date(vuln.published_date).toLocaleDateString() : 
                            '<span class="text-muted">N/A</span>'
                        }
                    </td>
                    <td>
                        <span class="device-count">${vuln.affected_devices}</span>
                        ${vuln.open_count > 0 ? `<span class="open-count">${vuln.open_count} open</span>` : ''}
                    </td>
                    <td>
                        <span class="status-badge ${getStatusClass(vuln.open_count, vuln.resolved_count, vuln.override_status)}">
                            ${getStatusText(vuln.open_count, vuln.resolved_count, vuln.override_status)}
                        </span>
                    </td>
                    
                </tr>
            `).join('');
        }

        function showVulnerabilityDetails(vulnerabilityId) {
            fetch(`?ajax=get_vulnerability_details&vulnerability_id=${encodeURIComponent(vulnerabilityId)}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        displayVulnerabilityModal(data.vulnerability, data.affected_devices);
                    } else {
                        showNotification('Error loading vulnerability details: ' + data.error, 'error');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showNotification('Error loading vulnerability details', 'error');
                });
        }

        function displayVulnerabilityModal(vulnerability, affectedDevices) {
            document.getElementById('modalTitle').textContent = `Vulnerability #${vulnerability.vulnerability_id} - ${vulnerability.cve_id}`;
            
            const modalBody = document.getElementById('modalBody');
            modalBody.innerHTML = `
                <div class="vulnerability-details">
                    <!-- Compact Overview Section -->
                    <div class="vulnerability-overview">
                        <div class="overview-header">
                            <div class="severity-section">
                                <span class="severity-badge ${vulnerability.severity?.toLowerCase() || 'unknown'}">
                                    ${vulnerability.severity || 'Unknown'}
                                </span>
                            </div>
                            <div class="dates-section">
                                <div class="date-item">
                                    <span class="date-label">Published:</span>
                                    <span class="date-value">${vulnerability.published_date ? new Date(vulnerability.published_date).toLocaleDateString() : 'N/A'}</span>
                                </div>
                                <div class="date-item">
                                    <span class="date-label">Modified:</span>
                                    <span class="date-value">${vulnerability.last_modified_date ? new Date(vulnerability.last_modified_date).toLocaleDateString() : 'N/A'}</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="overview-content">
                            <div class="description-section">
                                <h3>Description</h3>
                                <p>${escapeHtml(vulnerability.description || 'No description available')}</p>
                            </div>
                            
                            <div class="metrics-section">
                                <div class="cvss-scores">
                                    <h4>CVSS Scores</h4>
                                    <div class="scores-container">
                                        ${vulnerability.cvss_v4_score ? 
                                            `<div class="score-item">
                                                <span class="score-value ${getCvssClass(vulnerability.cvss_v4_score)}">${vulnerability.cvss_v4_score}</span>
                                                <span class="score-version">v4.0</span>
                                            </div>` : ''
                                        }
                                        ${vulnerability.cvss_v3_score ? 
                                            `<div class="score-item">
                                                <span class="score-value ${getCvssClass(vulnerability.cvss_v3_score)}">${vulnerability.cvss_v3_score}</span>
                                                <span class="score-version">v3.x</span>
                                            </div>` : ''
                                        }
                                        ${vulnerability.cvss_v2_score ? 
                                            `<div class="score-item">
                                                <span class="score-value ${getCvssClass(vulnerability.cvss_v2_score)}">${vulnerability.cvss_v2_score}</span>
                                                <span class="score-version">v2.0</span>
                                            </div>` : ''
                                        }
                                        ${!vulnerability.cvss_v4_score && !vulnerability.cvss_v3_score && !vulnerability.cvss_v2_score ? 
                                            '<div class="no-data">No CVSS scores available</div>' : ''
                                        }
                                    </div>
                                </div>
                                
                                <div class="impact-summary">
                                    <h4>Impact Summary</h4>
                                <div class="impact-stats">
                                        <div class="impact-stat">
                                            <span class="stat-number">${vulnerability.total_affected}</span>
                                            <span class="stat-label">Total Affected</span>
                                        </div>
                                    <div class="impact-stat">
                                        <span class="stat-number">${vulnerability.risk_accepted_devices}/${vulnerability.total_affected}</span>
                                        <span class="stat-label">Risk Accepted</span>
                                    </div>
                                        <div class="impact-stat">
                                            <span class="stat-number">${vulnerability.open_count}</span>
                                            <span class="stat-label">Open</span>
                                        </div>
                                        <div class="impact-stat">
                                            <span class="stat-number">${vulnerability.in_progress_count}</span>
                                            <span class="stat-label">In Progress</span>
                                        </div>
                                        <div class="impact-stat">
                                            <span class="stat-number">${vulnerability.resolved_count}</span>
                                            <span class="stat-label">Resolved</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    ${affectedDevices.length > 0 ? `
                    <div class="detail-section">
                        <h3>Affected Applications</h3>
                        <div class="affected-applications">
                            ${affectedDevices.map(device => `
                                <div class="application-item">
                                    <div class="application-info">
                                        <span class="component-name">${device.component_name}</span>
                                        <span class="component-version">v${device.component_version}</span>
                                        ${device.component_vendor ? `<span class="component-vendor">${device.component_vendor}</span>` : ''}
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    ` : ''}
                    
                    ${vulnerability.epss_score !== null && vulnerability.epss_score !== undefined ? `
                    <div class="detail-section">
                        <h3>EPSS Trend Analysis</h3>
                        <div class="epss-trend-container">
                            <div class="epss-trend-chart" style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 1rem;">
                                <div id="epssChartLoading" style="display: none; text-align: center; padding: 2rem; color: var(--text-muted);">
                                    <i class="fas fa-spinner fa-spin"></i> Loading EPSS trend data...
                                </div>
                                <canvas id="epssTrendChart" width="400" height="200" style="width: 100%; height: 250px; display: block;"></canvas>
                            </div>
                            <div class="epss-trend-info">
                                <p><strong>Current EPSS Score:</strong> ${formatEPSSScore(vulnerability.epss_score)}</p>
                                <p><strong>Percentile:</strong> ${formatEPSSScore(vulnerability.epss_percentile)}</p>
                                <p><strong>Last Updated:</strong> ${vulnerability.epss_date ? new Date(vulnerability.epss_date).toLocaleDateString() : 'N/A'}</p>
                            </div>
                        </div>
                    </div>
                    ` : ''}
                    
                    <div class="detail-section">
                        <h3>Affected Devices</h3>
                        ${affectedDevices.length > 0 ? `
                            <div class="affected-devices">
                                <label style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.5rem;"><input type="checkbox" id="selectAllDevices" onchange="toggleAllDevices(this)"> Select All</label>
                                ${affectedDevices.map(device => `
                                    <div class="device-item" style="display:flex; align-items:center; gap:0.75rem;">
                                        <input type="checkbox" class="device-select" value="${device.device_id}">
                                        <div class="device-info">
                                            <strong>${device.device_name || 'Unknown Device'}</strong>
                                            <div class="device-details">
                                                ${device.hostname ? `<span class="device-hostname">Hostname: ${device.hostname}</span>` : ''}
                                                ${device.fda_device_name ? `<span class="device-fda-name">FDA Name: ${device.fda_device_name}</span>` : ''}
                                                ${device.brand_name ? `<span class="device-brand">Brand: ${device.brand_name}</span>` : ''}
                                                ${device.model_number ? `<span class="device-model">Model: ${device.model_number}</span>` : ''}
                                            </div>
                                        </div>
                                        <div class="device-status" style="display:flex; gap:.5rem; align-items:center;">
                                            <span class="status-badge ${device.remediation_status?.toLowerCase().replace(' ', '-') || 'open'}">
                                                ${device.remediation_status || 'Open'}
                                            </span>
                                            ${device.risk_accepted ? `<div><span class="status-badge resolved" title="Risk Accepted">Risk Accepted</span></div>` : ''}
                                            ${device.risk_accepted && device.risk_accept_note ? `<div style="max-width:520px; color: var(--text-secondary,#cbd5e1); font-size:.85rem; background: var(--bg-tertiary,#333333); border:1px solid var(--border-primary,#333333); border-radius:.375rem; padding:.5rem .75rem;"><strong style="color: var(--text-primary,#f8fafc);">Note:</strong> ${escapeHtml(device.risk_accept_note)}</div>` : ''}
                                         </div>\n                                    </div>\n                                `).join('')}
                            </div>
                        ` : '<p class="text-muted">No affected devices found</p>'}
                    </div>
                </div>
            `;
            
            document.getElementById('vulnerabilityModal').style.display = 'block';
            // Add actions (Delete / Risk Accept) with proper modal note
            const actions = document.createElement('div');
            actions.style.cssText = 'margin-top: 1rem; display:flex; gap:0.5rem; justify-content:flex-end;';
            actions.innerHTML = `
                <button class="btn btn-accent" onclick="openRiskAcceptModal('${vulnerability.cve_id}')">Risk Accept Selected</button>
                <button class="btn btn-primary" onclick="confirmDeleteVulnerability('${vulnerability.cve_id}')">Delete</button>
            `;
            modalBody.appendChild(actions);
            
            // Load EPSS trend chart if EPSS data is available
            if (vulnerability.epss_score !== null && vulnerability.epss_score !== undefined) {
                // Add a delay to ensure the modal is fully rendered
                setTimeout(() => {
                    loadEPSSTrendChart(vulnerability.cve_id);
                }, 500);
            }
        }

        function closeVulnerabilityModal() {
            document.getElementById('vulnerabilityModal').style.display = 'none';
        }

        function promptRiskAccept(cveId) {
            const note = prompt('Enter a required note for Risk Acceptance:');
            if (!note || !note.trim()) {
                showNotification('Risk Acceptance note is required', 'error');
                return;
            }
            fetch(`?ajax=risk_accept_vulnerability`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cve_id: cveId, note })
            }).then(r=>r.json()).then(result => {
                if (result.success) {
                    showNotification('Vulnerability marked as Risk Accepted', 'success');
                    closeVulnerabilityModal();
                    loadVulnerabilities();
                } else {
                    showNotification('Error: ' + (result.error || 'Failed'), 'error');
                }
            }).catch(() => showNotification('Error performing risk acceptance', 'error'));
        }

        function confirmDeleteVulnerability(cveId) {
            if (!confirm(`Delete ${cveId}? This will remove it and re-syncs may re-add it.`)) return;
            fetch(`?ajax=delete_vulnerability`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cve_id: cveId })
            }).then(r=>r.json()).then(result => {
                if (result.success) {
                    showNotification('Vulnerability deleted', 'success');
                    closeVulnerabilityModal();
                    loadVulnerabilities();
                } else {
                    showNotification('Error: ' + (result.error || 'Failed'), 'error');
                }
            }).catch(() => showNotification('Error deleting vulnerability', 'error'));
        }

        function loadEPSSTrendChart(cveId) {
            
            // Show loading indicator
            const loadingDiv = document.getElementById('epssChartLoading');
            if (loadingDiv) {
                loadingDiv.style.display = 'block';
            }
            
            fetch(`?ajax=get_epss_trends&cve_id=${encodeURIComponent(cveId)}&days=30`)
                .then(response => {
                    return response.json();
                })
                .then(data => {
                    
                    // Hide loading indicator
                    if (loadingDiv) {
                        loadingDiv.style.display = 'none';
                    }
                    
                    if (data.success && data.data.length > 0) {
                        createEPSSTrendChart(data.data);
                    } else {
                        // Show message if no trend data available
                        const chartContainer = document.querySelector('.epss-trend-chart');
                        if (chartContainer) {
                            chartContainer.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-muted);"><i class="fas fa-chart-line"></i><br>No trend data available for this vulnerability</div>';
                        }
                    }
                })
                .catch(error => {
                    console.error('Error loading EPSS trends:', error);
                    
                    // Hide loading indicator
                    if (loadingDiv) {
                        loadingDiv.style.display = 'none';
                    }
                    
                    const chartContainer = document.querySelector('.epss-trend-chart');
                    if (chartContainer) {
                        chartContainer.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-muted);"><i class="fas fa-exclamation-triangle"></i><br>Error loading trend data</div>';
                    }
                });
        }

        function createEPSSTrendChart(trendData) {
            const ctx = document.getElementById('epssTrendChart');
            if (!ctx) {
                console.error('Canvas element epssTrendChart not found');
                return;
            }

            
            // Check if Chart.js is loaded
            if (typeof Chart === 'undefined') {
                console.error('Chart.js is not loaded');
                const chartContainer = document.querySelector('.epss-trend-chart');
                if (chartContainer) {
                    chartContainer.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-muted);"><i class="fas fa-exclamation-triangle"></i><br>Chart.js library not loaded</div>';
                }
                return;
            }

            // Destroy existing chart if it exists
            if (window.epssTrendChart && typeof window.epssTrendChart.destroy === 'function') {
                window.epssTrendChart.destroy();
            } else if (window.epssTrendChart) {
                window.epssTrendChart = null;
            }

            const labels = trendData.map(item => new Date(item.recorded_date).toLocaleDateString());
            const scores = trendData.map(item => item.epss_score * 100); // Convert to percentage
            const percentiles = trendData.map(item => item.epss_percentile * 100); // Convert to percentage
            

            try {
                window.epssTrendChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'EPSS Score (%)',
                        data: scores,
                        borderColor: '#009999', // Siemens Petrol
                        backgroundColor: 'rgba(0, 153, 153, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }, {
                        label: 'EPSS Percentile (%)',
                        data: percentiles,
                        borderColor: '#ff6b35', // Siemens Orange
                        backgroundColor: 'rgba(255, 107, 53, 0.1)',
                        borderWidth: 2,
                        fill: false,
                        tension: 0.4,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    aspectRatio: 2,
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: {
                                color: '#f8fafc' // Light text for dark theme
                            }
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false,
                            callbacks: {
                                label: function(context) {
                                    return context.dataset.label + ': ' + context.parsed.y.toFixed(2) + '%';
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            display: true,
                            title: {
                                display: true,
                                text: 'Date',
                                color: '#f8fafc'
                            },
                            ticks: {
                                color: '#cbd5e1'
                            },
                            grid: {
                                color: '#333333'
                            }
                        },
                        y: {
                            display: true,
                            title: {
                                display: true,
                                text: 'Score (%)',
                                color: '#f8fafc'
                            },
                            ticks: {
                                color: '#cbd5e1',
                                callback: function(value) {
                                    return value.toFixed(1) + '%';
                                }
                            },
                            grid: {
                                color: '#333333'
                            },
                            min: 0,
                            max: 100
                        }
                    },
                    interaction: {
                        mode: 'nearest',
                        axis: 'x',
                        intersect: false
                    }
                }
            });
            
                
                // Force a resize to ensure the chart is properly displayed
                setTimeout(() => {
                    if (window.epssTrendChart && typeof window.epssTrendChart.resize === 'function') {
                        window.epssTrendChart.resize();
                    }
                }, 100);
                
            } catch (error) {
                console.error('Error creating EPSS trend chart:', error);
                const chartContainer = document.querySelector('.epss-trend-chart');
                if (chartContainer) {
                    chartContainer.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-muted);"><i class="fas fa-exclamation-triangle"></i><br>Error creating chart: ' + error.message + '</div>';
                }
            }
        }

        // Utility functions
        function getCvssClass(score) {
            if (score >= 9.0) return 'critical';
            if (score >= 7.0) return 'high';
            if (score >= 4.0) return 'medium';
            return 'low';
        }

function getStatusClass(openCount, resolvedCount, overrideStatus) {
    if (overrideStatus === 'Risk Accepted') return 'resolved';
    if (resolvedCount > 0 && openCount === 0) return 'resolved';
    if (openCount > 0) return 'open';
    return 'unknown';
}

function getStatusText(openCount, resolvedCount, overrideStatus) {
    if (overrideStatus === 'Risk Accepted') return 'Resolved (Risk Accepted)';
    if (resolvedCount > 0 && openCount === 0) return 'Resolved';
    if (openCount > 0) return 'Open';
    return 'Unknown';
}

        function truncateText(text, maxLength) {
            if (!text) return '';
            return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function updatePagination(pagination) {
            const container = document.getElementById('paginationContainer');
            
            if (pagination.pages <= 1) {
                container.innerHTML = '';
                return;
            }
            
            let html = '<div class="pagination">';
            
            // Previous button
            if (pagination.page > 1) {
                html += `<button type="button" class="page-btn" onclick="changePage(${pagination.page - 1})">
                    <i class="fas fa-chevron-left"></i> Previous
                </button>`;
            }
            
            // Page numbers
            const startPage = Math.max(1, pagination.page - 2);
            const endPage = Math.min(pagination.pages, pagination.page + 2);
            
            for (let i = startPage; i <= endPage; i++) {
                html += `<button type="button" class="page-btn ${i === pagination.page ? 'active' : ''}" 
                         onclick="changePage(${i})">${i}</button>`;
            }
            
            // Next button
            if (pagination.page < pagination.pages) {
                html += `<button type="button" class="page-btn" onclick="changePage(${pagination.page + 1})">
                    Next <i class="fas fa-chevron-right"></i>
                </button>`;
            }
            
            html += '</div>';
            container.innerHTML = html;
        }

        function changePage(page) {
            currentPage = page;
            loadVulnerabilities();
        }

        function updateResultsCount(total) {
            document.getElementById('resultsCount').textContent = `${total} vulnerabilities found`;
        }

        function updateSortIndicators() {
            document.querySelectorAll('.sortable i').forEach(icon => {
                icon.className = 'fas fa-sort';
            });
            
            const currentHeader = document.querySelector(`[data-sort="${currentSort}"] i`);
            if (currentHeader) {
                currentHeader.className = currentSortDir === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down';
            }
        }

        function updateTableInfo(pagination) {
            const start = (pagination.page - 1) * pagination.limit + 1;
            const end = Math.min(pagination.page * pagination.limit, pagination.total);
            const info = `Showing ${start} to ${end} of ${pagination.total} entries`;
            document.getElementById('tableInfo').textContent = info;
        }

        function toggleAllDevices(cb) {
            document.querySelectorAll('.device-select').forEach(el => el.checked = cb.checked);
        }

        function openRiskAcceptModal(cveId) {
            const selected = Array.from(document.querySelectorAll('.device-select:checked')).map(el => el.value);
            if (selected.length === 0) { showNotification('Select at least one device', 'error'); return; }
            const modal = document.createElement('div');
            modal.className = 'modal';
            modal.id = 'risk-accept-modal';
            modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:10002;';
            modal.innerHTML = `
                <div style="background: var(--bg-card, #1a1a1a); border:1px solid var(--border-primary, #333333); border-radius:0.75rem; padding:1.5rem; width: min(600px, 90vw);">
                    <h3 style="margin-top:0;color:var(--text-primary,#f8fafc);">Risk Accept (${selected.length} devices)</h3>
                    <label style="display:block;color:var(--text-secondary,#cbd5e1);margin:.5rem 0">Required Note</label>
                    <textarea id="riskAcceptNote" rows="4" style="width:100%;padding:.75rem;border:1px solid var(--border-primary,#333333);border-radius:.5rem;background:var(--bg-tertiary,#333333);color:var(--text-primary,#fff);">${selected.length === 1 ? 'Document rationale, compensating controls, approval, etc.' : ''}</textarea>
                    <div style="display:flex;gap:.5rem;justify-content:flex-end;margin-top:1rem;">
                        <button class="btn" onclick="this.closest('.modal').remove()" style="background:var(--bg-tertiary,#333333);color:var(--text-primary,#fff);border:1px solid var(--border-secondary,#555);">Cancel</button>
                        <button class="btn btn-accent" onclick="submitRiskAccept('${cveId}', ${JSON.stringify(selected).replace(/"/g,'&quot;')})">Confirm</button>
                    </div>
                </div>`;
            document.body.appendChild(modal);
        }

        function submitRiskAccept(cveId, deviceIds) {
            const note = document.getElementById('riskAcceptNote').value.trim();
            if (!note) { showNotification('Note is required', 'error'); return; }
            fetch(`?ajax=risk_accept_vulnerability_devices`, {
                method: 'POST', headers: {'Content-Type':'application/json'},
                body: JSON.stringify({ cve_id: cveId, device_ids: deviceIds, note })
            }).then(r=>r.json()).then(result => {
                if (result.success) {
                    showNotification('Risk acceptance recorded', 'success');
                    const ra = document.getElementById('risk-accept-modal');
                    if (ra) ra.remove();
                    closeVulnerabilityModal();
                    loadVulnerabilities();
                } else {
                    showNotification('Error: ' + (result.error || 'Failed'), 'error');
                }
            }).catch(()=>showNotification('Error performing risk acceptance','error'));
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('vulnerabilityModal');
            if (event.target === modal) {
                closeVulnerabilityModal();
            }
        }
    </script>
    
    <style>
        /* Compact Vulnerability Overview */
        .vulnerability-overview {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .overview-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-primary, #333333);
        }
        
        .severity-section {
            display: flex;
            align-items: center;
        }
        
        .dates-section {
            display: flex;
            gap: 2rem;
        }
        
        .date-item {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        .date-label {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .date-value {
            font-size: 0.875rem;
            color: var(--text-secondary, #cbd5e1);
            font-weight: 500;
        }
        
        .overview-content {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
        }
        
        .description-section h3 {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--text-primary, #f8fafc);
            margin-bottom: 0.75rem;
        }
        
        .description-section p {
            line-height: 1.6;
            color: var(--text-secondary, #cbd5e1);
            margin: 0;
        }
        
        .metrics-section {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }
        
        .cvss-scores h4,
        .impact-summary h4 {
            font-size: 1rem;
            font-weight: 600;
            color: var(--text-primary, #f8fafc);
            margin: 0 0 0.75rem 0;
        }
        
        .scores-container {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        
        .score-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .score-value {
            font-size: 1.25rem;
            font-weight: 700;
            padding: 0.375rem 0.75rem;
            border-radius: 0.375rem;
        }
        
        .score-version {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
            background: var(--bg-secondary, #2a2a2a);
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
        }
        
        .impact-stats {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.75rem;
        }
        
        .impact-stat {
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 0.75rem;
            background: var(--bg-secondary, #2a2a2a);
            border-radius: 0.5rem;
            border: 1px solid var(--border-primary, #333333);
        }
        
        .stat-number {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text-primary, #f8fafc);
        }
        
        .stat-label {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
            text-align: center;
            margin-top: 0.25rem;
        }
        
        .no-data {
            color: var(--text-muted, #94a3b8);
            font-style: italic;
            text-align: center;
            padding: 0.75rem;
            font-size: 0.875rem;
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .overview-header {
                flex-direction: column;
                gap: 1rem;
                align-items: flex-start;
            }
            
            .dates-section {
                flex-direction: column;
                gap: 0.75rem;
            }
            
            .overview-content {
                grid-template-columns: 1fr;
                gap: 1.5rem;
            }
            
            .impact-stats {
                grid-template-columns: 1fr 1fr;
            }
        }
    </style>
</body>
</html>

