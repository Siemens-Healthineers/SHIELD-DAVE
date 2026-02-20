<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
/**
 * Report Generation for Device Assessment and Vulnerability Exposure ()
 * Comprehensive reporting interface with multiple report types and export options
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

$db = DatabaseConfig::getInstance();
$error = '';
$success = '';

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['ajax']) {
        case 'generate_report':
            $reportType = $_POST['report_type'] ?? '';
            $format = $_POST['format'] ?? 'pdf';
            $dateFrom = $_POST['date_from'] ?? '';
            $dateTo = $_POST['date_to'] ?? '';
            $filters = $_POST['filters'] ?? [];
            
            if (empty($reportType)) {
                echo json_encode(['success' => false, 'message' => 'Report type required']);
                exit;
            }
            
            try {
                $reportData = generateReport($reportType, $dateFrom, $dateTo, $filters);
                
                if ($format === 'pdf') {
                    $filePath = generatePDFReport($reportData, $reportType);
                } elseif ($format === 'excel') {
                    $filePath = generateExcelReport($reportData, $reportType);
                } elseif ($format === 'csv') {
                    $filePath = generateCSVReport($reportData, $reportType);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Unsupported format']);
                    exit;
                }
                
                echo json_encode([
                    'success' => true,
                    'file_path' => $filePath,
                    'download_url' => '/downloads/' . basename($filePath)
                ]);
                
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'message' => $e->getMessage()]);
            }
            exit;
            
        case 'get_report_preview':
            $reportType = $_GET['report_type'] ?? '';
            $dateFrom = $_GET['date_from'] ?? '';
            $dateTo = $_GET['date_to'] ?? '';
            $filters = $_GET['filters'] ?? [];
            
            try {
                $reportData = generateReport($reportType, $dateFrom, $dateTo, $filters);
                echo json_encode(['success' => true, 'data' => $reportData]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'message' => $e->getMessage()]);
            }
            exit;
    }
}

/**
 * Generate report data based on type and filters
 */
function generateReport($reportType, $dateFrom, $dateTo, $filters) {
    global $db;
    
    $reportData = [
        'type' => $reportType,
        'generated_at' => date('Y-m-d H:i:s'),
        'date_range' => ['from' => $dateFrom, 'to' => $dateTo],
        'filters' => $filters,
        'data' => []
    ];
    
    switch ($reportType) {
        case 'asset_summary':
            $reportData['data'] = generateAssetSummaryReport($dateFrom, $dateTo, $filters);
            break;
            
        case 'vulnerability_report':
            $reportData['data'] = generateVulnerabilityReport($dateFrom, $dateTo, $filters);
            break;
            
        case 'recall_report':
            $reportData['data'] = generateRecallReport($dateFrom, $dateTo, $filters);
            break;
            
        case 'compliance_report':
            $reportData['data'] = generateComplianceReport($dateFrom, $dateTo, $filters);
            break;
            
        case 'device_mapping':
            $reportData['data'] = generateDeviceMappingReport($dateFrom, $dateTo, $filters);
            break;
            
        case 'security_dashboard':
            $reportData['data'] = generateSecurityDashboardReport($dateFrom, $dateTo, $filters);
            break;
            
        default:
            throw new Exception('Unknown report type');
    }
    
    return $reportData;
}

/**
 * Generate asset summary report
 */
function generateAssetSummaryReport($dateFrom, $dateTo, $filters) {
    global $db;
    
    $whereClause = "WHERE 1=1";
    $params = [];
    
    if (!empty($dateFrom)) {
        $whereClause .= " AND a.created_at >= ?";
        $params[] = $dateFrom;
    }
    
    if (!empty($dateTo)) {
        $whereClause .= " AND a.created_at <= ?";
        $params[] = $dateTo;
    }
    
    if (!empty($filters['department'])) {
        $whereClause .= " AND a.department = ?";
        $params[] = $filters['department'];
    }
    
    if (!empty($filters['status'])) {
        $whereClause .= " AND a.status = ?";
        $params[] = $filters['status'];
    }
    
    // Asset statistics
    $sql = "SELECT 
        COUNT(*) as total_assets,
        COUNT(CASE WHEN a.status = 'Active' THEN 1 END) as active_assets,
        COUNT(CASE WHEN a.status = 'Inactive' THEN 1 END) as inactive_assets,
        COUNT(CASE WHEN a.status = 'Maintenance' THEN 1 END) as maintenance_assets,
        COUNT(DISTINCT a.department) as departments,
        COUNT(DISTINCT a.location) as locations
        FROM assets a $whereClause";
    
    $stmt = $db->query($sql, $params);
    $stats = $stmt->fetch();
    
    // Assets by department
    $sql = "SELECT 
        a.department,
        COUNT(*) as asset_count,
        COUNT(CASE WHEN a.status = 'Active' THEN 1 END) as active_count
        FROM assets a $whereClause
        GROUP BY a.department
        ORDER BY asset_count DESC";
    
    $stmt = $db->query($sql, $params);
    $byDepartment = $stmt->fetchAll();
    
    // Assets by location
    $sql = "SELECT 
        a.location,
        COUNT(*) as asset_count,
        COUNT(CASE WHEN a.status = 'Active' THEN 1 END) as active_count
        FROM assets a $whereClause
        GROUP BY a.location
        ORDER BY asset_count DESC";
    
    $stmt = $db->query($sql, $params);
    $byLocation = $stmt->fetchAll();
    
    // Recent assets
    $sql = "SELECT 
        a.asset_id,
        a.hostname,
        a.ip_address,
        a.department,
        a.location,
        a.status,
        a.created_at
        FROM assets a $whereClause
        ORDER BY a.created_at DESC
        LIMIT 20";
    
    $stmt = $db->query($sql, $params);
    $recentAssets = $stmt->fetchAll();
    
    return [
        'statistics' => $stats,
        'by_department' => $byDepartment,
        'by_location' => $byLocation,
        'recent_assets' => $recentAssets
    ];
}

/**
 * Generate vulnerability report
 */
function generateVulnerabilityReport($dateFrom, $dateTo, $filters) {
    global $db;
    
    $whereClause = "WHERE 1=1";
    $params = [];
    
    if (!empty($dateFrom)) {
        $whereClause .= " AND v.published_date >= ?";
        $params[] = $dateFrom;
    }
    
    if (!empty($dateTo)) {
        $whereClause .= " AND v.published_date <= ?";
        $params[] = $dateTo;
    }
    
    if (!empty($filters['severity'])) {
        $whereClause .= " AND v.severity = ?";
        $params[] = $filters['severity'];
    }
    
    // Vulnerability statistics
    $sql = "SELECT 
        COUNT(DISTINCT v.cve_id) as total_vulnerabilities,
        COUNT(CASE WHEN v.severity = 'Critical' THEN 1 END) as critical_count,
        COUNT(CASE WHEN v.severity = 'High' THEN 1 END) as high_count,
        COUNT(CASE WHEN v.severity = 'Medium' THEN 1 END) as medium_count,
        COUNT(CASE WHEN v.severity = 'Low' THEN 1 END) as low_count,
        COUNT(DISTINCT dvl.device_id) as affected_devices,
        COUNT(DISTINCT CASE WHEN dvl.remediation_status = 'Open' THEN dvl.device_id END) as open_remediations
        FROM vulnerabilities v
        LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
        $whereClause";
    
    $stmt = $db->query($sql, $params);
    $stats = $stmt->fetch();
    
    // Vulnerabilities by severity
    $sql = "SELECT 
        v.severity,
        COUNT(*) as count,
        AVG(v.cvss_v3_score) as avg_score
        FROM vulnerabilities v $whereClause
        GROUP BY v.severity
        ORDER BY 
            CASE v.severity 
                WHEN 'Critical' THEN 1 
                WHEN 'High' THEN 2 
                WHEN 'Medium' THEN 3 
                WHEN 'Low' THEN 4 
                ELSE 5 
            END";
    
    $stmt = $db->query($sql, $params);
    $bySeverity = $stmt->fetchAll();
    
    // Top vulnerabilities
    $sql = "SELECT 
        v.cve_id,
        v.description,
        v.severity,
        v.cvss_v3_score,
        v.published_date,
        COUNT(DISTINCT dvl.device_id) as affected_devices
        FROM vulnerabilities v
        LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
        $whereClause
        GROUP BY v.cve_id, v.description, v.severity, v.cvss_v3_score, v.published_date
        ORDER BY v.cvss_v3_score DESC
        LIMIT 20";
    
    $stmt = $db->query($sql, $params);
    $topVulnerabilities = $stmt->fetchAll();
    
    return [
        'statistics' => $stats,
        'by_severity' => $bySeverity,
        'top_vulnerabilities' => $topVulnerabilities
    ];
}

/**
 * Generate recall report
 */
function generateRecallReport($dateFrom, $dateTo, $filters) {
    global $db;
    
    $whereClause = "WHERE 1=1";
    $params = [];
    
    if (!empty($dateFrom)) {
        $whereClause .= " AND r.recall_date >= ?";
        $params[] = $dateFrom;
    }
    
    if (!empty($dateTo)) {
        $whereClause .= " AND r.recall_date <= ?";
        $params[] = $dateTo;
    }
    
    if (!empty($filters['classification'])) {
        $whereClause .= " AND r.recall_classification = ?";
        $params[] = $filters['classification'];
    }
    
    // Recall statistics
    $sql = "SELECT 
        COUNT(DISTINCT r.recall_id) as total_recalls,
        COUNT(DISTINCT CASE WHEN r.recall_status = 'Active' THEN r.recall_id END) as active_recalls,
        COUNT(DISTINCT drl.device_id) as affected_devices,
        COUNT(DISTINCT CASE WHEN drl.remediation_status = 'Open' THEN drl.device_id END) as open_remediations
        FROM recalls r
        LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
        $whereClause";
    
    $stmt = $db->query($sql, $params);
    $stats = $stmt->fetch();
    
    // Recalls by classification
    $sql = "SELECT 
        r.recall_classification,
        COUNT(*) as count
        FROM recalls r $whereClause
        GROUP BY r.recall_classification
        ORDER BY count DESC";
    
    $stmt = $db->query($sql, $params);
    $byClassification = $stmt->fetchAll();
    
    // Recent recalls
    $sql = "SELECT 
        r.recall_id,
        r.fda_recall_number,
        r.recall_date,
        r.product_description,
        r.manufacturer_name,
        r.recall_classification,
        COUNT(DISTINCT drl.device_id) as affected_devices
        FROM recalls r
        LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
        $whereClause
        GROUP BY r.recall_id, r.fda_recall_number, r.recall_date, r.product_description, 
                 r.manufacturer_name, r.recall_classification
        ORDER BY r.recall_date DESC
        LIMIT 20";
    
    $stmt = $db->query($sql, $params);
    $recentRecalls = $stmt->fetchAll();
    
    return [
        'statistics' => $stats,
        'by_classification' => $byClassification,
        'recent_recalls' => $recentRecalls
    ];
}

/**
 * Generate compliance report
 */
function generateComplianceReport($dateFrom, $dateTo, $filters) {
    global $db;
    
    // Compliance statistics
    $sql = "SELECT 
        COUNT(DISTINCT a.asset_id) as total_assets,
        COUNT(DISTINCT CASE WHEN a.compliance_status = 'Compliant' THEN a.asset_id END) as compliant_assets,
        COUNT(DISTINCT CASE WHEN a.compliance_status = 'Non-Compliant' THEN a.asset_id END) as non_compliant_assets,
        COUNT(DISTINCT CASE WHEN a.compliance_status = 'Under Review' THEN a.asset_id END) as under_review_assets,
        COUNT(DISTINCT a.department) as departments
        FROM assets a";
    
    $stmt = $db->query($sql);
    $stats = $stmt->fetch();
    
    // Compliance by department
    $sql = "SELECT 
        a.department,
        COUNT(*) as total_assets,
        COUNT(CASE WHEN a.compliance_status = 'Compliant' THEN 1 END) as compliant_count,
        COUNT(CASE WHEN a.compliance_status = 'Non-Compliant' THEN 1 END) as non_compliant_count,
        ROUND(
            (COUNT(CASE WHEN a.compliance_status = 'Compliant' THEN 1 END) * 100.0 / COUNT(*)), 2
        ) as compliance_rate
        FROM assets a
        GROUP BY a.department
        ORDER BY compliance_rate DESC";
    
    $stmt = $db->query($sql);
    $byDepartment = $stmt->fetchAll();
    
    // Compliance issues
    $sql = "SELECT 
        a.asset_id,
        a.hostname,
        a.department,
        a.compliance_status,
        a.compliance_notes,
        a.last_compliance_check
        FROM assets a
        WHERE a.compliance_status != 'Compliant'
        ORDER BY a.last_compliance_check DESC";
    
    $stmt = $db->query($sql);
    $complianceIssues = $stmt->fetchAll();
    
    return [
        'statistics' => $stats,
        'by_department' => $byDepartment,
        'compliance_issues' => $complianceIssues
    ];
}

/**
 * Generate device mapping report
 */
function generateDeviceMappingReport($dateFrom, $dateTo, $filters) {
    global $db;
    
    // Mapping statistics
    $sql = "SELECT 
        COUNT(DISTINCT a.asset_id) as total_assets,
        COUNT(DISTINCT md.device_id) as mapped_devices,
        COUNT(DISTINCT CASE WHEN md.device_id IS NULL THEN a.asset_id END) as unmapped_assets,
        ROUND(
            (COUNT(DISTINCT md.device_id) * 100.0 / COUNT(DISTINCT a.asset_id)), 2
        ) as mapping_rate
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id";
    
    $stmt = $db->query($sql);
    $stats = $stmt->fetch();
    
    // Mapping by department
    $sql = "SELECT 
        a.department,
        COUNT(DISTINCT a.asset_id) as total_assets,
        COUNT(DISTINCT md.device_id) as mapped_devices,
        ROUND(
            (COUNT(DISTINCT md.device_id) * 100.0 / COUNT(DISTINCT a.asset_id)), 2
        ) as mapping_rate
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        GROUP BY a.department
        ORDER BY mapping_rate DESC";
    
    $stmt = $db->query($sql);
    $byDepartment = $stmt->fetchAll();
    
    // Unmapped assets
    $sql = "SELECT 
        a.asset_id,
        a.hostname,
        a.ip_address,
        a.department,
        a.location,
        a.created_at
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        WHERE md.device_id IS NULL
        ORDER BY a.created_at DESC";
    
    $stmt = $db->query($sql);
    $unmappedAssets = $stmt->fetchAll();
    
    return [
        'statistics' => $stats,
        'by_department' => $byDepartment,
        'unmapped_assets' => $unmappedAssets
    ];
}

/**
 * Generate security dashboard report
 */
function generateSecurityDashboardReport($dateFrom, $dateTo, $filters) {
    global $db;
    
    // Security overview
    $sql = "SELECT 
        COUNT(DISTINCT a.asset_id) as total_assets,
        COUNT(DISTINCT v.cve_id) as total_vulnerabilities,
        COUNT(DISTINCT r.recall_id) as total_recalls,
        COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN v.cve_id END) as critical_vulnerabilities,
        COUNT(DISTINCT CASE WHEN r.recall_status = 'Active' THEN r.recall_id END) as active_recalls
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        LEFT JOIN device_vulnerabilities_link dvl ON md.device_id = dvl.device_id
        LEFT JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
        LEFT JOIN device_recalls_link drl ON md.device_id = drl.device_id
        LEFT JOIN recalls r ON drl.recall_id = r.recall_id";
    
    $stmt = $db->query($sql);
    $overview = $stmt->fetch();
    
    // Risk assessment
    $sql = "SELECT 
        a.department,
        COUNT(DISTINCT a.asset_id) as total_assets,
        COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN a.asset_id END) as critical_assets,
        COUNT(DISTINCT CASE WHEN r.recall_status = 'Active' THEN a.asset_id END) as recalled_assets
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        LEFT JOIN device_vulnerabilities_link dvl ON md.device_id = dvl.device_id
        LEFT JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
        LEFT JOIN device_recalls_link drl ON md.device_id = drl.device_id
        LEFT JOIN recalls r ON drl.recall_id = r.recall_id
        GROUP BY a.department
        ORDER BY critical_assets DESC, recalled_assets DESC";
    
    $stmt = $db->query($sql);
    $riskAssessment = $stmt->fetchAll();
    
    return [
        'overview' => $overview,
        'risk_assessment' => $riskAssessment
    ];
}

/**
 * Generate PDF report
 */
function generatePDFReport($reportData, $reportType) {
    // Create downloads directory if it doesn't exist
    $downloadsDir = _UPLOADS . '/reports';
    if (!is_dir($downloadsDir)) {
        mkdir($downloadsDir, 0755, true);
    }
    
    $filename = $reportType . '_' . date('Y-m-d_H-i-s') . '.pdf';
    $filepath = $downloadsDir . '/' . $filename;
    
    // For now, create a simple text file as PDF generation would require additional libraries
    $content = "Report: " . ucfirst(str_replace('_', ' ', $reportType)) . "\n";
    $content .= "Generated: " . $reportData['generated_at'] . "\n";
    $content .= "Date Range: " . $reportData['date_range']['from'] . " to " . $reportData['date_range']['to'] . "\n\n";
    
    $content .= json_encode($reportData['data'], JSON_PRETTY_PRINT);
    
    file_put_contents($filepath, $content);
    
    return $filepath;
}

/**
 * Generate Excel report
 */
function generateExcelReport($reportData, $reportType) {
    $downloadsDir = _UPLOADS . '/reports';
    if (!is_dir($downloadsDir)) {
        mkdir($downloadsDir, 0755, true);
    }
    
    $filename = $reportType . '_' . date('Y-m-d_H-i-s') . '.xlsx';
    $filepath = $downloadsDir . '/' . $filename;
    
    // Create CSV for now (Excel generation would require additional libraries)
    $csvFilename = str_replace('.xlsx', '.csv', $filename);
    $csvFilepath = $downloadsDir . '/' . $csvFilename;
    
    $content = "Report: " . ucfirst(str_replace('_', ' ', $reportType)) . "\n";
    $content .= "Generated: " . $reportData['generated_at'] . "\n";
    $content .= "Date Range: " . $reportData['date_range']['from'] . " to " . $reportData['date_range']['to'] . "\n\n";
    
    $content .= json_encode($reportData['data'], JSON_PRETTY_PRINT);
    
    file_put_contents($csvFilepath, $content);
    
    return $csvFilepath;
}

/**
 * Generate CSV report
 */
function generateCSVReport($reportData, $reportType) {
    $downloadsDir = _UPLOADS . '/reports';
    if (!is_dir($downloadsDir)) {
        mkdir($downloadsDir, 0755, true);
    }
    
    $filename = $reportType . '_' . date('Y-m-d_H-i-s') . '.csv';
    $filepath = $downloadsDir . '/' . $filename;
    
    $content = "Report: " . ucfirst(str_replace('_', ' ', $reportType)) . "\n";
    $content .= "Generated: " . $reportData['generated_at'] . "\n";
    $content .= "Date Range: " . $reportData['date_range']['from'] . " to " . $reportData['date_range']['to'] . "\n\n";
    
    $content .= json_encode($reportData['data'], JSON_PRETTY_PRINT);
    
    file_put_contents($filepath, $content);
    
    return $filepath;
}

// Get filter options
$sql = "SELECT DISTINCT department FROM assets WHERE department IS NOT NULL ORDER BY department";
$stmt = $db->query($sql);
$departments = $stmt->fetchAll();

$sql = "SELECT DISTINCT status FROM assets ORDER BY status";
$stmt = $db->query($sql);
$statuses = $stmt->fetchAll();

$sql = "SELECT DISTINCT recall_classification FROM recalls ORDER BY recall_classification";
$stmt = $db->query($sql);
$classifications = $stmt->fetchAll();

$sql = "SELECT DISTINCT severity FROM vulnerabilities ORDER BY severity";
$stmt = $db->query($sql);
$severities = $stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report Generation - <?php echo _NAME; ?></title>
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
                    <h1><i class="fas fa-chart-bar"></i> Report Generation</h1>
                    <p>Generate comprehensive reports and exports</p>
                </div>
            </div>

            <?php if ($error): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i>
                    <?php echo dave_htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <?php echo dave_htmlspecialchars($success); ?>
                </div>
            <?php endif; ?>

            <!-- Report Generation Form -->
            <section class="report-section">
                <div class="section-header">
                    <h3><i class="fas fa-file-alt"></i> Generate Report</h3>
                </div>
                
                <form id="reportForm" class="report-form">
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="reportType">Report Type *</label>
                            <select id="reportType" name="report_type" required>
                                <option value="">Select Report Type</option>
                                <option value="asset_summary">Asset Summary Report</option>
                                <option value="vulnerability_report">Vulnerability Report</option>
                                <option value="recall_report">Recall Report</option>
                                <option value="compliance_report">Compliance Report</option>
                                <option value="device_mapping">Device Mapping Report</option>
                                <option value="security_dashboard">Security Dashboard Report</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="format">Export Format *</label>
                            <select id="format" name="format" required>
                                <option value="pdf">PDF</option>
                                <option value="excel">Excel</option>
                                <option value="csv">CSV</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="dateFrom">Date From</label>
                            <input type="date" id="dateFrom" name="date_from">
                        </div>
                        
                        <div class="form-group">
                            <label for="dateTo">Date To</label>
                            <input type="date" id="dateTo" name="date_to">
                        </div>
                    </div>
                    
                    <!-- Dynamic Filters -->
                    <div id="filtersSection" class="filters-section" style="display: none;">
                        <h4>Filters</h4>
                        <div id="filtersContent" class="filters-content">
                            <!-- Filters will be populated based on report type -->
                        </div>
                    </div>
                    
                    <div class="form-actions">
                        <button type="button" id="previewReport" class="btn btn-outline">
                            <i class="fas fa-eye"></i>
                            Preview
                        </button>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-download"></i>
                            Generate Report
                        </button>
                    </div>
                </form>
            </section>

            <!-- Report Preview -->
            <section id="previewSection" class="preview-section" style="display: none;">
                <div class="section-header">
                    <h3><i class="fas fa-eye"></i> Report Preview</h3>
                </div>
                <div id="previewContent" class="preview-content">
                    <!-- Preview content will be loaded here -->
                </div>
            </section>

            <!-- Report Templates -->
            <section class="templates-section">
                <div class="section-header">
                    <h3><i class="fas fa-template"></i> Report Templates</h3>
                </div>
                
                <div class="templates-grid">
                    <div class="template-item">
                        <div class="template-icon">
                            <i class="fas fa-server"></i>
                        </div>
                        <div class="template-content">
                            <h4>Asset Summary</h4>
                            <p>Comprehensive overview of all assets including statistics, department breakdown, and recent additions.</p>
                            <button type="button" class="btn btn-outline" onclick="selectTemplate('asset_summary')">
                                Use Template
                            </button>
                        </div>
                    </div>
                    
                    <div class="template-item">
                        <div class="template-icon">
                            <i class="fas fa-bug"></i>
                        </div>
                        <div class="template-content">
                            <h4>Vulnerability Report</h4>
                            <p>Detailed vulnerability analysis including severity breakdown, affected devices, and remediation status.</p>
                            <button type="button" class="btn btn-outline" onclick="selectTemplate('vulnerability_report')">
                                Use Template
                            </button>
                        </div>
                    </div>
                    
                    <div class="template-item">
                        <div class="template-icon">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <div class="template-content">
                            <h4>Recall Report</h4>
                            <p>FDA recall information including affected devices, classification breakdown, and remediation progress.</p>
                            <button type="button" class="btn btn-outline" onclick="selectTemplate('recall_report')">
                                Use Template
                            </button>
                        </div>
                    </div>
                    
                    <div class="template-item">
                        <div class="template-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div class="template-content">
                            <h4>Compliance Report</h4>
                            <p>Compliance status overview including department compliance rates and outstanding issues.</p>
                            <button type="button" class="btn btn-outline" onclick="selectTemplate('compliance_report')">
                                Use Template
                            </button>
                        </div>
                    </div>
                    
                    <div class="template-item">
                        <div class="template-icon">
                            <i class="fas fa-map"></i>
                        </div>
                        <div class="template-content">
                            <h4>Device Mapping</h4>
                            <p>Device mapping status including mapped vs unmapped assets and department breakdown.</p>
                            <button type="button" class="btn btn-outline" onclick="selectTemplate('device_mapping')">
                                Use Template
                            </button>
                        </div>
                    </div>
                    
                    <div class="template-item">
                        <div class="template-icon">
                            <i class="fas fa-chart-line"></i>
                        </div>
                        <div class="template-content">
                            <h4>Security Dashboard</h4>
                            <p>Comprehensive security overview including risk assessment and department analysis.</p>
                            <button type="button" class="btn btn-outline" onclick="selectTemplate('security_dashboard')">
                                Use Template
                            </button>
                        </div>
                    </div>
                </div>
            </section>
        </main>
    </div>

    <script>
        // Report Generation JavaScript
        document.addEventListener('DOMContentLoaded', function() {
            setupEventListeners();
        });
        
        function setupEventListeners() {
            // Report type change
            document.getElementById('reportType').addEventListener('change', updateFilters);
            
            // Preview button
            document.getElementById('previewReport').addEventListener('click', previewReport);
            
            // Form submission
            document.getElementById('reportForm').addEventListener('submit', generateReport);
        }
        
        function updateFilters() {
            const reportType = document.getElementById('reportType').value;
            const filtersSection = document.getElementById('filtersSection');
            const filtersContent = document.getElementById('filtersContent');
            
            if (!reportType) {
                filtersSection.style.display = 'none';
                return;
            }
            
            let filtersHtml = '';
            
            switch (reportType) {
                case 'asset_summary':
                case 'compliance_report':
                case 'device_mapping':
                    filtersHtml = `
                        <div class="filter-group">
                            <label for="department">Department</label>
                            <select id="department" name="filters[department]">
                                <option value="">All Departments</option>
                                <?php foreach ($departments as $dept): ?>
                                <option value="<?php echo dave_htmlspecialchars($dept['department']); ?>">
                                    <?php echo dave_htmlspecialchars($dept['department']); ?>
                                </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label for="status">Status</label>
                            <select id="status" name="filters[status]">
                                <option value="">All Statuses</option>
                                <?php foreach ($statuses as $status): ?>
                                <option value="<?php echo dave_htmlspecialchars($status['status']); ?>">
                                    <?php echo dave_htmlspecialchars($status['status']); ?>
                                </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    `;
                    break;
                    
                case 'vulnerability_report':
                    filtersHtml = `
                        <div class="filter-group">
                            <label for="severity">Severity</label>
                            <select id="severity" name="filters[severity]">
                                <option value="">All Severities</option>
                                <?php foreach ($severities as $severity): ?>
                                <option value="<?php echo dave_htmlspecialchars($severity['severity']); ?>">
                                    <?php echo dave_htmlspecialchars($severity['severity']); ?>
                                </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    `;
                    break;
                    
                case 'recall_report':
                    filtersHtml = `
                        <div class="filter-group">
                            <label for="classification">Classification</label>
                            <select id="classification" name="filters[classification]">
                                <option value="">All Classifications</option>
                                <?php foreach ($classifications as $classification): ?>
                                <option value="<?php echo dave_htmlspecialchars($classification['recall_classification']); ?>">
                                    <?php echo dave_htmlspecialchars($classification['recall_classification']); ?>
                                </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    `;
                    break;
            }
            
            filtersContent.innerHTML = filtersHtml;
            filtersSection.style.display = filtersHtml ? 'block' : 'none';
        }
        
        function selectTemplate(templateType) {
            document.getElementById('reportType').value = templateType;
            updateFilters();
        }
        
        function previewReport() {
            const formData = new FormData(document.getElementById('reportForm'));
            const params = new URLSearchParams();
            
            for (let [key, value] of formData.entries()) {
                if (value) {
                    params.append(key, value);
                }
            }
            
            fetch('?ajax=get_report_preview&' + params.toString())
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayPreview(data.data);
                } else {
                    showNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error previewing report:', error);
                showNotification('Error previewing report', 'error');
            });
        }
        
        function displayPreview(reportData) {
            const previewSection = document.getElementById('previewSection');
            const previewContent = document.getElementById('previewContent');
            
            let html = `
                <div class="report-preview">
                    <div class="report-header">
                        <h4>${reportData.type.replace('_', ' ').toUpperCase()}</h4>
                        <p>Generated: ${reportData.generated_at}</p>
                        <p>Date Range: ${reportData.date_range.from} to ${reportData.date_range.to}</p>
                    </div>
                    <div class="report-data">
                        <pre>${JSON.stringify(reportData.data, null, 2)}</pre>
                    </div>
                </div>
            `;
            
            previewContent.innerHTML = html;
            previewSection.style.display = 'block';
        }
        
        function generateReport(e) {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            
            fetch('?ajax=generate_report', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Report generated successfully', 'success');
                    // Create download link
                    const downloadLink = document.createElement('a');
                    downloadLink.href = data.download_url;
                    downloadLink.download = '';
                    downloadLink.click();
                } else {
                    showNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error generating report:', error);
                showNotification('Error generating report', 'error');
            });
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
