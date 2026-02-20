<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Initialize unified authentication
$unifiedAuth = new UnifiedAuth();

// Authenticate user (supports both session and API key)
if (!$unifiedAuth->authenticate()) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'UNAUTHORIZED',
            'message' => 'Authentication required'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

// Get authenticated user
$user = $unifiedAuth->getCurrentUser();
// Check if user has permission to access this resource
$unifiedAuth->requirePermission('reports', 'read');

$db = DatabaseConfig::getInstance();

// Get request method and path
$method = $_SERVER['REQUEST_METHOD'];
$path = $_GET['path'] ?? '';

try {
    switch ($method) {
        case 'GET':
            handleGetRequest($path);
            break;
        case 'POST':
            handlePostRequest($path);
            break;
        default:
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            break;
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}

/**
 * Handle GET requests
 */
function handleGetRequest($path) {
    global $db, $user;
    
    switch ($path) {
        case 'formats':
            getSupportedFormats();
            break;
        case 'templates':
            getReportTemplates();
            break;
        case 'status':
            getExportStatus();
            break;
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

/**
 * Handle POST requests
 */
function handlePostRequest($path) {
    global $db, $user;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    switch ($path) {
        case 'export':
            exportReport($input);
            break;
        case 'schedule':
            scheduleReport($input);
            break;
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

/**
 * Get supported export formats
 */
function getSupportedFormats() {
    $formats = [
        'pdf' => [
            'name' => 'PDF',
            'description' => 'Portable Document Format',
            'mime_type' => 'application/pdf',
            'extension' => 'pdf'
        ],
        'excel' => [
            'name' => 'Excel',
            'description' => 'Microsoft Excel Spreadsheet',
            'mime_type' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'extension' => 'xlsx'
        ],
        'csv' => [
            'name' => 'CSV',
            'description' => 'Comma-Separated Values',
            'mime_type' => 'text/csv',
            'extension' => 'csv'
        ],
        'json' => [
            'name' => 'JSON',
            'description' => 'JavaScript Object Notation',
            'mime_type' => 'application/json',
            'extension' => 'json'
        ]
    ];
    
    echo json_encode(['success' => true, 'formats' => $formats]);
}

/**
 * Get report templates
 */
function getReportTemplates() {
    $templates = [
        'asset_summary' => [
            'name' => 'Asset Summary Report',
            'description' => 'Comprehensive overview of all assets including statistics, department breakdown, and recent additions.',
            'category' => 'Assets',
            'icon' => 'fas fa-server'
        ],
        'vulnerability_report' => [
            'name' => 'Vulnerability Report',
            'description' => 'Detailed vulnerability analysis including severity breakdown, affected devices, and remediation status.',
            'category' => 'Security',
            'icon' => 'fas fa-bug'
        ],
        'recall_report' => [
            'name' => 'Recall Report',
            'description' => 'FDA recall information including affected devices, classification breakdown, and remediation progress.',
            'category' => 'Compliance',
            'icon' => 'fas fa-exclamation-triangle'
        ],
        'compliance_report' => [
            'name' => 'Compliance Report',
            'description' => 'Compliance status overview including department compliance rates and outstanding issues.',
            'category' => 'Compliance',
            'icon' => 'fas fa-shield-alt'
        ],
        'device_mapping' => [
            'name' => 'Device Mapping Report',
            'description' => 'Device mapping status including mapped vs unmapped assets and department breakdown.',
            'category' => 'Devices',
            'icon' => 'fas fa-map'
        ],
        'security_dashboard' => [
            'name' => 'Security Dashboard Report',
            'description' => 'Comprehensive security overview including risk assessment and department analysis.',
            'category' => 'Security',
            'icon' => 'fas fa-chart-line'
        ]
    ];
    
    echo json_encode(['success' => true, 'templates' => $templates]);
}

/**
 * Get export status
 */
function getExportStatus() {
    global $user;
    
    // Get user's recent exports
    $exports = getUserRecentExports($user['user_id']);
    
    echo json_encode(['success' => true, 'exports' => $exports]);
}

/**
 * Export report
 */
function exportReport($input) {
    global $user;
    
    $reportType = $input['report_type'] ?? '';
    $format = $input['format'] ?? 'pdf';
    $dateFrom = $input['date_from'] ?? '';
    $dateTo = $input['date_to'] ?? '';
    $filters = $input['filters'] ?? [];
    
    if (empty($reportType)) {
        http_response_code(400);
        echo json_encode(['error' => 'Report type is required']);
        return;
    }
    
    try {
        // Generate report data
        $reportData = generateReportData($reportType, $dateFrom, $dateTo, $filters);
        
        // Create export file
        $exportFile = createExportFile($reportData, $reportType, $format);
        
        // Log export activity
        logExportActivity($user['user_id'], $reportType, $format, $exportFile);
        
        echo json_encode([
            'success' => true,
            'export_id' => $exportFile['id'],
            'download_url' => $exportFile['download_url'],
            'expires_at' => $exportFile['expires_at']
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

/**
 * Schedule report
 */
function scheduleReport($input) {
    global $user;
    
    $reportType = $input['report_type'] ?? '';
    $format = $input['format'] ?? 'pdf';
    $schedule = $input['schedule'] ?? '';
    $email = $input['email'] ?? '';
    $filters = $input['filters'] ?? [];
    
    if (empty($reportType) || empty($schedule)) {
        http_response_code(400);
        echo json_encode(['error' => 'Report type and schedule are required']);
        return;
    }
    
    try {
        // Validate schedule format
        if (!validateSchedule($schedule)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid schedule format']);
            return;
        }
        
        // Create scheduled report
        $scheduleId = createScheduledReport($user['user_id'], $reportType, $format, $schedule, $email, $filters);
        
        echo json_encode([
            'success' => true,
            'schedule_id' => $scheduleId,
            'next_run' => calculateNextRun($schedule)
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

/**
 * Generate report data
 */
function generateReportData($reportType, $dateFrom, $dateTo, $filters) {
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
            $reportData['data'] = generateAssetSummaryData($dateFrom, $dateTo, $filters);
            break;
            
        case 'vulnerability_report':
            $reportData['data'] = generateVulnerabilityData($dateFrom, $dateTo, $filters);
            break;
            
        case 'recall_report':
            $reportData['data'] = generateRecallData($dateFrom, $dateTo, $filters);
            break;
            
        case 'compliance_report':
            $reportData['data'] = generateComplianceData($dateFrom, $dateTo, $filters);
            break;
            
        case 'device_mapping':
            $reportData['data'] = generateDeviceMappingData($dateFrom, $dateTo, $filters);
            break;
            
        case 'security_dashboard':
            $reportData['data'] = generateSecurityDashboardData($dateFrom, $dateTo, $filters);
            break;
            
        default:
            throw new Exception('Unknown report type');
    }
    
    return $reportData;
}

/**
 * Generate asset summary data
 */
function generateAssetSummaryData($dateFrom, $dateTo, $filters) {
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
    
    return [
        'statistics' => $stats,
        'by_department' => $byDepartment
    ];
}

/**
 * Generate vulnerability data
 */
function generateVulnerabilityData($dateFrom, $dateTo, $filters) {
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
        AVG(v.cvss_v3_score) as avg_cvss_score
        FROM vulnerabilities v
        LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
        $whereClause";
    
    $stmt = $db->query($sql, $params);
    $stats = $stmt->fetch();
    
    return [
        'statistics' => $stats
    ];
}

/**
 * Generate recall data
 */
function generateRecallData($dateFrom, $dateTo, $filters) {
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
    
    return [
        'statistics' => $stats
    ];
}

/**
 * Generate compliance data
 */
function generateComplianceData($dateFrom, $dateTo, $filters) {
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
    
    return [
        'statistics' => $stats
    ];
}

/**
 * Generate device mapping data
 */
function generateDeviceMappingData($dateFrom, $dateTo, $filters) {
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
    
    return [
        'statistics' => $stats
    ];
}

/**
 * Generate security dashboard data
 */
function generateSecurityDashboardData($dateFrom, $dateTo, $filters) {
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
    
    return [
        'overview' => $overview
    ];
}

/**
 * Create export file
 */
function createExportFile($reportData, $reportType, $format) {
    $downloadsDir = _UPLOADS . '/reports';
    if (!is_dir($downloadsDir)) {
        mkdir($downloadsDir, 0755, true);
    }
    
    $filename = $reportType . '_' . date('Y-m-d_H-i-s') . '.' . $format;
    $filepath = $downloadsDir . '/' . $filename;
    
    // Create file based on format
    switch ($format) {
        case 'json':
            $content = json_encode($reportData, JSON_PRETTY_PRINT);
            break;
        case 'csv':
            $content = convertToCSV($reportData);
            break;
        default:
            $content = json_encode($reportData, JSON_PRETTY_PRINT);
    }
    
    file_put_contents($filepath, $content);
    
    return [
        'id' => uniqid(),
        'filename' => $filename,
        'filepath' => $filepath,
        'download_url' => '/downloads/' . $filename,
        'expires_at' => date('Y-m-d H:i:s', strtotime('+7 days'))
    ];
}

/**
 * Convert data to CSV format
 */
function convertToCSV($data) {
    $csv = '';
    
    if (isset($data['data']['statistics'])) {
        $csv .= "Metric,Value\n";
        foreach ($data['data']['statistics'] as $key => $value) {
            $csv .= $key . ',' . $value . "\n";
        }
    }
    
    return $csv;
}

/**
 * Validate schedule format
 */
function validateSchedule($schedule) {
    // Basic validation for cron-like format
    $parts = explode(' ', $schedule);
    return count($parts) >= 5;
}

/**
 * Calculate next run time
 */
function calculateNextRun($schedule) {
    // Simplified calculation - in real implementation, use a cron parser
    return date('Y-m-d H:i:s', strtotime('+1 day'));
}

/**
 * Create scheduled report
 */
function createScheduledReport($userId, $reportType, $format, $schedule, $email, $filters) {
    global $db;
    
    $sql = "INSERT INTO scheduled_reports (user_id, report_type, format, schedule, email, filters, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) RETURNING report_id";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([$userId, $reportType, $format, $schedule, $email, json_encode($filters)]);
    
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    return $result['report_id'];
}

/**
 * Get user's recent exports
 */
function getUserRecentExports($userId) {
    global $db;
    
    $sql = "SELECT export_id, report_type, format, created_at, download_url 
            FROM report_exports 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 10";
    
    $stmt = $db->query($sql, [$userId]);
    return $stmt->fetchAll();
}

/**
 * Log export activity
 */
function logExportActivity($userId, $reportType, $format, $exportFile) {
    global $db;
    
    $sql = "INSERT INTO report_exports (user_id, report_type, format, filename, download_url, created_at) 
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([
        $userId, 
        $reportType, 
        $format, 
        $exportFile['filename'], 
        $exportFile['download_url']
    ]);
}
