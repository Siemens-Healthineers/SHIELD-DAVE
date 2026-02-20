<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
/**
 * Reports Dashboard for Device Assessment and Vulnerability Exposure ()
 * Comprehensive reporting dashboard with analytics and insights
 */

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/auth.php';

// Initialize authentication
$auth = new Auth();

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
        case 'get_analytics_data':
            $dateFrom = $_GET['date_from'] ?? date('Y-m-01'); // First day of current month
            $dateTo = $_GET['date_to'] ?? date('Y-m-d'); // Today
            
            $analytics = [
                'assets' => getAssetAnalytics($dateFrom, $dateTo),
                'vulnerabilities' => getVulnerabilityAnalytics($dateFrom, $dateTo),
                'recalls' => getRecallAnalytics($dateFrom, $dateTo),
                'compliance' => getComplianceAnalytics($dateFrom, $dateTo),
                'trends' => getTrendAnalytics($dateFrom, $dateTo)
            ];
            
            echo json_encode(['success' => true, 'data' => $analytics]);
            exit;
            
        case 'get_department_breakdown':
            $dateFrom = $_GET['date_from'] ?? date('Y-m-01');
            $dateTo = $_GET['date_to'] ?? date('Y-m-d');
            
            $breakdown = getDepartmentBreakdown($dateFrom, $dateTo);
            echo json_encode(['success' => true, 'data' => $breakdown]);
            exit;
            
        case 'get_risk_assessment':
            $riskData = getRiskAssessment();
            echo json_encode(['success' => true, 'data' => $riskData]);
            exit;
    }
}

/**
 * Get asset analytics
 */
function getAssetAnalytics($dateFrom, $dateTo) {
    global $db;
    
    $sql = "SELECT 
        COUNT(*) as total_assets,
        COUNT(CASE WHEN status = 'Active' THEN 1 END) as active_assets,
        COUNT(CASE WHEN status = 'Inactive' THEN 1 END) as inactive_assets,
        COUNT(CASE WHEN status = 'Maintenance' THEN 1 END) as maintenance_assets,
        COUNT(DISTINCT department) as departments,
        COUNT(DISTINCT location) as locations,
        COUNT(CASE WHEN created_at >= ? THEN 1 END) as new_assets
        FROM assets
        WHERE created_at <= ?";
    
    $stmt = $db->query($sql, [$dateFrom, $dateTo]);
    return $stmt->fetch();
}

/**
 * Get vulnerability analytics
 */
function getVulnerabilityAnalytics($dateFrom, $dateTo) {
    global $db;
    
    $sql = "SELECT 
        COUNT(DISTINCT v.cve_id) as total_vulnerabilities,
        COUNT(CASE WHEN v.severity = 'Critical' THEN 1 END) as critical_count,
        COUNT(CASE WHEN v.severity = 'High' THEN 1 END) as high_count,
        COUNT(CASE WHEN v.severity = 'Medium' THEN 1 END) as medium_count,
        COUNT(CASE WHEN v.severity = 'Low' THEN 1 END) as low_count,
        COUNT(DISTINCT dvl.device_id) as affected_devices,
        COUNT(DISTINCT CASE WHEN dvl.remediation_status = 'Open' THEN dvl.device_id END) as open_remediations,
        AVG(v.cvss_v3_score) as avg_cvss_score
        FROM vulnerabilities v
        LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
        WHERE v.published_date >= ? AND v.published_date <= ?";
    
    $stmt = $db->query($sql, [$dateFrom, $dateTo]);
    return $stmt->fetch();
}

/**
 * Get recall analytics
 */
function getRecallAnalytics($dateFrom, $dateTo) {
    global $db;
    
    $sql = "SELECT 
        COUNT(DISTINCT r.recall_id) as total_recalls,
        COUNT(DISTINCT CASE WHEN r.recall_status = 'Active' THEN r.recall_id END) as active_recalls,
        COUNT(DISTINCT drl.device_id) as affected_devices,
        COUNT(DISTINCT CASE WHEN drl.remediation_status = 'Open' THEN drl.device_id END) as open_remediations,
        COUNT(DISTINCT CASE WHEN r.recall_classification = 'Class I' THEN r.recall_id END) as class_i_recalls,
        COUNT(DISTINCT CASE WHEN r.recall_classification = 'Class II' THEN r.recall_id END) as class_ii_recalls,
        COUNT(DISTINCT CASE WHEN r.recall_classification = 'Class III' THEN r.recall_id END) as class_iii_recalls
        FROM recalls r
        LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
        WHERE r.recall_date >= ? AND r.recall_date <= ?";
    
    $stmt = $db->query($sql, [$dateFrom, $dateTo]);
    return $stmt->fetch();
}

/**
 * Get compliance analytics
 */
function getComplianceAnalytics($dateFrom, $dateTo) {
    global $db;
    
    $sql = "SELECT 
        COUNT(*) as total_assets,
        COUNT(CASE WHEN compliance_status = 'Compliant' THEN 1 END) as compliant_assets,
        COUNT(CASE WHEN compliance_status = 'Non-Compliant' THEN 1 END) as non_compliant_assets,
        COUNT(CASE WHEN compliance_status = 'Under Review' THEN 1 END) as under_review_assets,
        ROUND(
            (COUNT(CASE WHEN compliance_status = 'Compliant' THEN 1 END) * 100.0 / COUNT(*)), 2
        ) as compliance_rate
        FROM assets
        WHERE created_at >= ? AND created_at <= ?";
    
    $stmt = $db->query($sql, [$dateFrom, $dateTo]);
    return $stmt->fetch();
}

/**
 * Get trend analytics
 */
function getTrendAnalytics($dateFrom, $dateTo) {
    global $db;
    
    // Asset trends by month
    $sql = "SELECT 
        DATE_TRUNC('month', created_at) as month,
        COUNT(*) as asset_count
        FROM assets
        WHERE created_at >= ? AND created_at <= ?
        GROUP BY DATE_TRUNC('month', created_at)
        ORDER BY month";
    
    $stmt = $db->query($sql, [$dateFrom, $dateTo]);
    $assetTrends = $stmt->fetchAll();
    
    // Vulnerability trends by month
    $sql = "SELECT 
        DATE_TRUNC('month', published_date) as month,
        COUNT(*) as vulnerability_count
        FROM vulnerabilities
        WHERE published_date >= ? AND published_date <= ?
        GROUP BY DATE_TRUNC('month', published_date)
        ORDER BY month";
    
    $stmt = $db->query($sql, [$dateFrom, $dateTo]);
    $vulnerabilityTrends = $stmt->fetchAll();
    
    // Recall trends by month
    $sql = "SELECT 
        DATE_TRUNC('month', recall_date) as month,
        COUNT(*) as recall_count
        FROM recalls
        WHERE recall_date >= ? AND recall_date <= ?
        GROUP BY DATE_TRUNC('month', recall_date)
        ORDER BY month";
    
    $stmt = $db->query($sql, [$dateFrom, $dateTo]);
    $recallTrends = $stmt->fetchAll();
    
    return [
        'assets' => $assetTrends,
        'vulnerabilities' => $vulnerabilityTrends,
        'recalls' => $recallTrends
    ];
}

/**
 * Get department breakdown
 */
function getDepartmentBreakdown($dateFrom, $dateTo) {
    global $db;
    
    $sql = "SELECT 
        a.department,
        COUNT(*) as total_assets,
        COUNT(CASE WHEN a.status = 'Active' THEN 1 END) as active_assets,
        COUNT(DISTINCT md.device_id) as mapped_devices,
        COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN a.asset_id END) as critical_assets,
        COUNT(DISTINCT CASE WHEN r.recall_status = 'Active' THEN a.asset_id END) as recalled_assets,
        ROUND(
            (COUNT(CASE WHEN a.compliance_status = 'Compliant' THEN 1 END) * 100.0 / COUNT(*)), 2
        ) as compliance_rate
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        LEFT JOIN device_vulnerabilities_link dvl ON md.device_id = dvl.device_id
        LEFT JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
        LEFT JOIN device_recalls_link drl ON md.device_id = drl.device_id
        LEFT JOIN recalls r ON drl.recall_id = r.recall_id
        WHERE a.created_at >= ? AND a.created_at <= ?
        GROUP BY a.department
        ORDER BY total_assets DESC";
    
    $stmt = $db->query($sql, [$dateFrom, $dateTo]);
    return $stmt->fetchAll();
}

/**
 * Get risk assessment
 */
function getRiskAssessment() {
    global $db;
    
    $sql = "SELECT 
        a.department,
        COUNT(*) as total_assets,
        COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN a.asset_id END) as critical_vulnerabilities,
        COUNT(DISTINCT CASE WHEN r.recall_status = 'Active' THEN a.asset_id END) as active_recalls,
        COUNT(CASE WHEN a.compliance_status = 'Non-Compliant' THEN 1 END) as non_compliant_assets,
        ROUND(
            (COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN a.asset_id END) * 100.0 / COUNT(*)), 2
        ) as critical_vulnerability_rate,
        ROUND(
            (COUNT(DISTINCT CASE WHEN r.recall_status = 'Active' THEN a.asset_id END) * 100.0 / COUNT(*)), 2
        ) as recall_rate
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        LEFT JOIN device_vulnerabilities_link dvl ON md.device_id = dvl.device_id
        LEFT JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
        LEFT JOIN device_recalls_link drl ON md.device_id = drl.device_id
        LEFT JOIN recalls r ON drl.recall_id = r.recall_id
        GROUP BY a.department
        ORDER BY critical_vulnerability_rate DESC, recall_rate DESC";
    
    $stmt = $db->query($sql);
    return $stmt->fetchAll();
}

// Get initial analytics data with error handling
try {
    $analytics = [
        'assets' => getAssetAnalytics(date('Y-m-01'), date('Y-m-d')),
        'vulnerabilities' => getVulnerabilityAnalytics(date('Y-m-01'), date('Y-m-d')),
        'recalls' => getRecallAnalytics(date('Y-m-01'), date('Y-m-d')),
        'compliance' => getComplianceAnalytics(date('Y-m-01'), date('Y-m-d'))
    ];

    $departmentBreakdown = getDepartmentBreakdown(date('Y-m-01'), date('Y-m-d'));
    $riskAssessment = getRiskAssessment();
} catch (Exception $e) {
    // If database queries fail, use empty data
    $analytics = [
        'assets' => [],
        'vulnerabilities' => [],
        'recalls' => [],
        'compliance' => []
    ];
    $departmentBreakdown = [];
    $riskAssessment = [];
    error_log("Reports Dashboard database error: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reports Dashboard - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="/assets/css/reports.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-chart-bar"></i> Reports Dashboard</h1>
                    <p>Comprehensive analytics and reporting insights</p>
                </div>
                <div class="page-actions">
                    <a href="/pages/reports/generate.php" class="btn btn-primary">
                        <i class="fas fa-file-alt"></i>
                        Generate Report
                    </a>
                    <button type="button" id="refreshAnalytics" class="btn btn-secondary">
                        <i class="fas fa-sync"></i>
                        Refresh
                    </button>
                </div>
            </div>

            <!-- Date Range Filter -->
            <div class="date-filter">
                <div class="filter-group">
                    <label for="dateFrom">From</label>
                    <input type="date" id="dateFrom" value="<?php echo date('Y-m-01'); ?>">
                </div>
                <div class="filter-group">
                    <label for="dateTo">To</label>
                    <input type="date" id="dateTo" value="<?php echo date('Y-m-d'); ?>">
                </div>
                <button type="button" id="applyDateFilter" class="btn btn-primary">
                    <i class="fas fa-filter"></i>
                    Apply Filter
                </button>
            </div>

            <!-- Analytics Overview -->
            <section class="analytics-section">
                <div class="section-header">
                    <h3><i class="fas fa-chart-pie"></i> Analytics Overview</h3>
                </div>
                
                <div class="analytics-grid">
                    <!-- Assets Analytics -->
                    <div class="analytics-card">
                        <div class="card-header">
                            <h4><i class="fas fa-server"></i> Assets</h4>
                        </div>
                        <div class="card-content">
                            <div class="metric-row">
                                <span class="metric-label">Total Assets</span>
                                <span class="metric-value"><?php echo number_format($analytics['assets']['total_assets']); ?></span>
                            </div>
                            <div class="metric-row">
                                <span class="metric-label">Active</span>
                                <span class="metric-value success"><?php echo number_format($analytics['assets']['active_assets']); ?></span>
                            </div>
                            <div class="metric-row">
                                <span class="metric-label">New This Period</span>
                                <span class="metric-value info"><?php echo number_format($analytics['assets']['new_assets']); ?></span>
                            </div>
                            <div class="metric-row">
                                <span class="metric-label">Departments</span>
                                <span class="metric-value"><?php echo number_format($analytics['assets']['departments']); ?></span>
                            </div>
                        </div>
                    </div>

                    <!-- Vulnerabilities Analytics -->
                    <div class="analytics-card">
                        <div class="card-header">
                            <h4><i class="fas fa-bug"></i> Vulnerabilities</h4>
                        </div>
                        <div class="card-content">
                            <div class="metric-row">
                                <span class="metric-label">Total Vulnerabilities</span>
                                <span class="metric-value"><?php echo number_format($analytics['vulnerabilities']['total_vulnerabilities']); ?></span>
                            </div>
                            <div class="metric-row">
                                <span class="metric-label">Critical</span>
                                <span class="metric-value critical"><?php echo number_format($analytics['vulnerabilities']['critical_count']); ?></span>
                            </div>
                            <div class="metric-row">
                                <span class="metric-label">High</span>
                                <span class="metric-value warning"><?php echo number_format($analytics['vulnerabilities']['high_count']); ?></span>
                            </div>
                            <div class="metric-row">
                                <span class="metric-label">Affected Devices</span>
                                <span class="metric-value"><?php echo number_format($analytics['vulnerabilities']['affected_devices']); ?></span>
                            </div>
                        </div>
                    </div>

                    <!-- Recalls Analytics -->
                    <div class="analytics-card">
                        <div class="card-header">
                            <h4><i class="fas fa-exclamation-triangle"></i> Recalls</h4>
                        </div>
                        <div class="card-content">
                            <div class="metric-row">
                                <span class="metric-label">Total Recalls</span>
                                <span class="metric-value"><?php echo number_format($analytics['recalls']['total_recalls']); ?></span>
                            </div>
                            <div class="metric-row">
                                <span class="metric-label">Active</span>
                                <span class="metric-value warning"><?php echo number_format($analytics['recalls']['active_recalls']); ?></span>
                            </div>
                            <div class="metric-row">
                                <span class="metric-label">Affected Devices</span>
                                <span class="metric-value"><?php echo number_format($analytics['recalls']['affected_devices']); ?></span>
                            </div>
                            <div class="metric-row">
                                <span class="metric-label">Class I</span>
                                <span class="metric-value critical"><?php echo number_format($analytics['recalls']['class_i_recalls']); ?></span>
                            </div>
                        </div>
                    </div>

                    <!-- Compliance Analytics -->
                    <div class="analytics-card">
                        <div class="card-header">
                            <h4><i class="fas fa-shield-alt"></i> Compliance</h4>
                        </div>
                        <div class="card-content">
                            <div class="metric-row">
                                <span class="metric-label">Compliance Rate</span>
                                <span class="metric-value success"><?php echo $analytics['compliance']['compliance_rate']; ?>%</span>
                            </div>
                            <div class="metric-row">
                                <span class="metric-label">Compliant</span>
                                <span class="metric-value success"><?php echo number_format($analytics['compliance']['compliant_assets']); ?></span>
                            </div>
                            <div class="metric-row">
                                <span class="metric-label">Non-Compliant</span>
                                <span class="metric-value error"><?php echo number_format($analytics['compliance']['non_compliant_assets']); ?></span>
                            </div>
                            <div class="metric-row">
                                <span class="metric-label">Under Review</span>
                                <span class="metric-value info"><?php echo number_format($analytics['compliance']['under_review_assets']); ?></span>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Department Breakdown -->
            <section class="department-section">
                <div class="section-header">
                    <h3><i class="fas fa-building"></i> Department Breakdown</h3>
                </div>
                
                <div class="department-grid">
                    <?php foreach ($departmentBreakdown as $dept): ?>
                        <div class="department-card">
                            <div class="dept-header">
                                <h4><?php echo dave_htmlspecialchars($dept['department']); ?></h4>
                            </div>
                            <div class="dept-metrics">
                                <div class="dept-metric">
                                    <span class="metric-label">Total Assets</span>
                                    <span class="metric-value"><?php echo number_format($dept['total_assets']); ?></span>
                                </div>
                                <div class="dept-metric">
                                    <span class="metric-label">Active</span>
                                    <span class="metric-value success"><?php echo number_format($dept['active_assets']); ?></span>
                                </div>
                                <div class="dept-metric">
                                    <span class="metric-label">Mapped</span>
                                    <span class="metric-value info"><?php echo number_format($dept['mapped_devices']); ?></span>
                                </div>
                                <div class="dept-metric">
                                    <span class="metric-label">Critical</span>
                                    <span class="metric-value critical"><?php echo number_format($dept['critical_assets']); ?></span>
                                </div>
                                <div class="dept-metric">
                                    <span class="metric-label">Recalled</span>
                                    <span class="metric-value warning"><?php echo number_format($dept['recalled_assets']); ?></span>
                                </div>
                                <div class="dept-metric">
                                    <span class="metric-label">Compliance</span>
                                    <span class="metric-value <?php echo $dept['compliance_rate'] >= 80 ? 'success' : ($dept['compliance_rate'] >= 60 ? 'warning' : 'error'); ?>">
                                        <?php echo $dept['compliance_rate']; ?>%
                                    </span>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </section>

            <!-- Risk Assessment -->
            <section class="risk-section">
                <div class="section-header">
                    <h3><i class="fas fa-exclamation-circle"></i> Risk Assessment</h3>
                </div>
                
                <div class="risk-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Department</th>
                                <th>Total Assets</th>
                                <th>Critical Vulnerabilities</th>
                                <th>Active Recalls</th>
                                <th>Non-Compliant</th>
                                <th>Risk Score</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($riskAssessment as $risk): ?>
                                <?php
                                $riskScore = $risk['critical_vulnerability_rate'] + $risk['recall_rate'] + 
                                           ($risk['non_compliant_assets'] / max($risk['total_assets'], 1)) * 100;
                                $riskLevel = $riskScore >= 50 ? 'high' : ($riskScore >= 25 ? 'medium' : 'low');
                                ?>
                                <tr>
                                    <td><?php echo dave_htmlspecialchars($risk['department']); ?></td>
                                    <td><?php echo number_format($risk['total_assets']); ?></td>
                                    <td>
                                        <span class="risk-value critical"><?php echo number_format($risk['critical_vulnerabilities']); ?></span>
                                        <small>(<?php echo $risk['critical_vulnerability_rate']; ?>%)</small>
                                    </td>
                                    <td>
                                        <span class="risk-value warning"><?php echo number_format($risk['active_recalls']); ?></span>
                                        <small>(<?php echo $risk['recall_rate']; ?>%)</small>
                                    </td>
                                    <td>
                                        <span class="risk-value error"><?php echo number_format($risk['non_compliant_assets']); ?></span>
                                    </td>
                                    <td>
                                        <span class="risk-score <?php echo $riskLevel; ?>">
                                            <?php echo round($riskScore, 1); ?>
                                        </span>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </section>

            <!-- Quick Actions -->
            <section class="actions-section">
                <div class="section-header">
                    <h3><i class="fas fa-bolt"></i> Quick Actions</h3>
                </div>
                
                <div class="actions-grid">
                    <a href="/pages/reports/generate.php?type=asset_summary" class="action-card">
                        <div class="action-icon">
                            <i class="fas fa-server"></i>
                        </div>
                        <div class="action-content">
                            <h4>Asset Summary</h4>
                            <p>Generate comprehensive asset report</p>
                        </div>
                    </a>
                    
                    <a href="/pages/reports/generate.php?type=vulnerability_report" class="action-card">
                        <div class="action-icon">
                            <i class="fas fa-bug"></i>
                        </div>
                        <div class="action-content">
                            <h4>Vulnerability Report</h4>
                            <p>Detailed vulnerability analysis</p>
                        </div>
                    </a>
                    
                    <a href="/pages/reports/generate.php?type=recall_report" class="action-card">
                        <div class="action-icon">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <div class="action-content">
                            <h4>Recall Report</h4>
                            <p>FDA recall status and impact</p>
                        </div>
                    </a>
                    
                    <a href="/pages/reports/generate.php?type=compliance_report" class="action-card">
                        <div class="action-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div class="action-content">
                            <h4>Compliance Report</h4>
                            <p>Compliance status and issues</p>
                        </div>
                    </a>
                    
                    <a href="/pages/reports/generate.php?type=security_dashboard" class="action-card">
                        <div class="action-icon">
                            <i class="fas fa-chart-line"></i>
                        </div>
                        <div class="action-content">
                            <h4>Security Dashboard</h4>
                            <p>Comprehensive security overview</p>
                        </div>
                    </a>
                    
                    <a href="/pages/reports/generate.php?type=device_mapping" class="action-card">
                        <div class="action-icon">
                            <i class="fas fa-map"></i>
                        </div>
                        <div class="action-content">
                            <h4>Device Mapping</h4>
                            <p>Device mapping status and gaps</p>
                        </div>
                    </a>
                </div>
            </section>
        </main>
    </div>

    <script>
        // Reports Dashboard JavaScript
        document.addEventListener('DOMContentLoaded', function() {
            setupEventListeners();
        });
        
        function setupEventListeners() {
            // Apply date filter
            document.getElementById('applyDateFilter').addEventListener('click', applyDateFilter);
            
            // Refresh analytics
            document.getElementById('refreshAnalytics').addEventListener('click', refreshAnalytics);
        }
        
        function applyDateFilter() {
            const dateFrom = document.getElementById('dateFrom').value;
            const dateTo = document.getElementById('dateTo').value;
            
            if (!dateFrom || !dateTo) {
                showNotification('Please select both date range values', 'error');
                return;
            }
            
            if (dateFrom > dateTo) {
                showNotification('Start date cannot be after end date', 'error');
                return;
            }
            
            loadAnalytics(dateFrom, dateTo);
        }
        
        function loadAnalytics(dateFrom, dateTo) {
            fetch(`?ajax=get_analytics_data&date_from=${dateFrom}&date_to=${dateTo}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateAnalyticsDisplay(data.data);
                } else {
                    showNotification('Error loading analytics data', 'error');
                }
            })
            .catch(error => {
                console.error('Error loading analytics:', error);
                showNotification('Error loading analytics data', 'error');
            });
        }
        
        function updateAnalyticsDisplay(analytics) {
            // Update analytics cards with new data
            // This would typically update the displayed values
        }
        
        function refreshAnalytics() {
            const dateFrom = document.getElementById('dateFrom').value;
            const dateTo = document.getElementById('dateTo').value;
            
            loadAnalytics(dateFrom, dateTo);
            showNotification('Analytics refreshed', 'success');
        }
        
        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
                ${message}
            `;
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 3000);
        }
    </script>
    <!-- Common Dashboard JavaScript -->
    <script src="/assets/js/dashboard-common.js"></script>
</body>
</html>
