<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../config/database.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
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
$unifiedAuth->requirePermission('analytics', 'read');

$method = $_SERVER['REQUEST_METHOD'];
$path = $_GET['path'] ?? '';

// Route requests
switch ($method) {
    case 'GET':
        handleGetRequest($path);
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleGetRequest($path) {
    global $user;
    
    try {
        if (empty($path)) {
            // Get dashboard analytics
            getDashboardAnalytics();
        } elseif ($path === 'assets') {
            // Get asset analytics
            getAssetAnalytics();
        } elseif ($path === 'vulnerabilities') {
            // Get vulnerability analytics
            getVulnerabilityAnalytics();
        } elseif ($path === 'recalls') {
            // Get recall analytics
            getRecallAnalytics();
        } elseif ($path === 'compliance') {
            // Get compliance analytics
            getComplianceAnalytics();
        } else {
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'ENDPOINT_NOT_FOUND',
                    'message' => 'Endpoint not found'
                ],
                'timestamp' => date('c')
            ]);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function getDashboardAnalytics() {
    global $user;
    
    try {
        $db = DatabaseConfig::getInstance();
        
        // Get query parameters
        $date_from = $_GET['date_from'] ?? date('Y-m-01'); // First day of current month
        $date_to = $_GET['date_to'] ?? date('Y-m-d');
        $department = $_GET['department'] ?? '';
        
        // Build date filter
        $date_filter = "AND a.created_at >= :date_from AND a.created_at <= :date_to";
        $params = [
            ':date_from' => $date_from,
            ':date_to' => $date_to . ' 23:59:59'
        ];
        
        if (!empty($department)) {
            $date_filter .= " AND a.department = :department";
            $params[':department'] = $department;
        }
        
        // Get asset metrics
        $asset_sql = "SELECT 
            COUNT(*) as total_assets,
            COUNT(CASE WHEN md.device_id IS NOT NULL THEN 1 END) as mapped_assets,
            COUNT(CASE WHEN a.criticality = 'Clinical-High' THEN 1 END) as critical_assets,
            COUNT(CASE WHEN a.status = 'Active' THEN 1 END) as active_assets
            FROM assets a
            LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
            WHERE 1=1 $date_filter";
        
        $asset_stmt = $db->prepare($asset_sql);
        $asset_stmt->execute($params);
        $asset_metrics = $asset_stmt->fetch();
        
        // Get vulnerability metrics
        // Get vulnerability counts (no join needed)
        $vuln_sql = "SELECT 
            COUNT(*) as total_vulnerabilities,
            COUNT(CASE WHEN severity = 'Critical' THEN 1 END) as critical_vulns,
            COUNT(CASE WHEN severity = 'High' THEN 1 END) as high_vulns
            FROM vulnerabilities
            WHERE 1=1 $date_filter";
        
        $vuln_stmt = $db->prepare($vuln_sql);
        $vuln_stmt->execute($params);
        $vuln_metrics = $vuln_stmt->fetch();
        
        // Get open vulnerabilities count (exclude patched devices)
        $open_sql = "SELECT 
            COUNT(CASE WHEN dvl.remediation_status = 'Open' THEN 1 END) as open_vulns
            FROM device_vulnerabilities_link dvl
            LEFT JOIN medical_devices md ON dvl.device_id = md.device_id
            LEFT JOIN assets a ON md.asset_id = a.asset_id
            JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
            WHERE 1=1 $date_filter
            AND NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))";
        
        $open_stmt = $db->prepare($open_sql);
        $open_stmt->execute($params);
        $open_metrics = $open_stmt->fetch();
        
        // Combine the results
        $vuln_metrics = array_merge($vuln_metrics, $open_metrics);
        
        // Get recall metrics (exclude resolved)
        $recall_sql = "SELECT 
            COUNT(*) as total_recalls,
            COUNT(CASE WHEN r.recall_status = 'Active' THEN 1 END) as active_recalls,
            COUNT(DISTINCT drl.device_id) as affected_devices
            FROM recalls r
            LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
                AND (drl.remediation_status IS NULL OR drl.remediation_status <> 'Resolved')
            WHERE r.recall_date >= :date_from AND r.recall_date <= :date_to";
        
        $recall_stmt = $db->prepare($recall_sql);
        $recall_stmt->execute([
            ':date_from' => $date_from,
            ':date_to' => $date_to
        ]);
        $recall_metrics = $recall_stmt->fetch();
        
        // Get trend data (last 30 days)
        $trend_sql = "SELECT 
            DATE(a.created_at) as date,
            COUNT(*) as assets_added
            FROM assets a
            WHERE a.created_at >= :trend_from
            GROUP BY DATE(a.created_at)
            ORDER BY date";
        
        $trend_stmt = $db->prepare($trend_sql);
        $trend_stmt->execute([
            ':trend_from' => date('Y-m-d', strtotime('-30 days'))
        ]);
        $trend_data = $trend_stmt->fetchAll();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'summary' => [
                    'assets' => $asset_metrics,
                    'vulnerabilities' => $vuln_metrics,
                    'recalls' => $recall_metrics
                ],
                'trends' => [
                    'assets_added' => $trend_data
                ],
                'date_range' => [
                    'from' => $date_from,
                    'to' => $date_to
                ],
                'department' => $department
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'ANALYTICS_ERROR',
                'message' => 'Failed to get dashboard analytics'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function getAssetAnalytics() {
    global $user;
    
    try {
        $db = DatabaseConfig::getInstance();
        
        // Get asset type distribution
        $type_sql = "SELECT 
            asset_type,
            COUNT(*) as count,
            COUNT(CASE WHEN md.device_id IS NOT NULL THEN 1 END) as mapped_count
            FROM assets a
            LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
            WHERE a.status = 'Active'
            GROUP BY asset_type
            ORDER BY count DESC";
        
        $type_stmt = $db->query($type_sql);
        $type_distribution = $type_stmt->fetchAll();
        
        // Get department distribution
        $dept_sql = "SELECT 
            department,
            COUNT(*) as count
            FROM assets a
            WHERE a.status = 'Active' AND a.department IS NOT NULL
            GROUP BY department
            ORDER BY count DESC";
        
        $dept_stmt = $db->query($dept_sql);
        $dept_distribution = $dept_stmt->fetchAll();
        
        // Get criticality distribution
        $crit_sql = "SELECT 
            criticality,
            COUNT(*) as count
            FROM assets a
            WHERE a.status = 'Active'
            GROUP BY criticality
            ORDER BY count DESC";
        
        $crit_stmt = $db->query($crit_sql);
        $crit_distribution = $crit_stmt->fetchAll();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'type_distribution' => $type_distribution,
                'department_distribution' => $dept_distribution,
                'criticality_distribution' => $crit_distribution
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'ANALYTICS_ERROR',
                'message' => 'Failed to get asset analytics'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function getVulnerabilityAnalytics() {
    global $user;
    
    try {
        $db = DatabaseConfig::getInstance();
        
        // Get severity distribution (exclude patched devices)
        $severity_sql = "SELECT 
            v.severity,
            COUNT(DISTINCT v.cve_id) as count,
            COUNT(dvl.asset_id) as affected_assets
            FROM vulnerabilities v
            LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
                AND NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))
            GROUP BY v.severity
            ORDER BY 
                CASE v.severity 
                    WHEN 'Critical' THEN 1 
                    WHEN 'High' THEN 2 
                    WHEN 'Medium' THEN 3 
                    WHEN 'Low' THEN 4 
                END";
        
        $severity_stmt = $db->query($severity_sql);
        $severity_distribution = $severity_stmt->fetchAll();
        
        // Get remediation status (exclude patched devices)
        $status_sql = "SELECT 
            dvl.remediation_status,
            COUNT(*) as count
            FROM device_vulnerabilities_link dvl
            JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
            WHERE NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))
            GROUP BY dvl.remediation_status
            ORDER BY count DESC";
        
        $status_stmt = $db->query($status_sql);
        $status_distribution = $status_stmt->fetchAll();
        
        // Get top affected assets (exclude patched)
        $assets_sql = "SELECT 
            a.asset_id,
            a.hostname,
            a.asset_type,
            a.department,
            COUNT(dvl.cve_id) as vulnerability_count,
            COUNT(CASE WHEN v.severity = 'Critical' THEN 1 END) as critical_count
            FROM assets a
            JOIN device_vulnerabilities_link dvl ON a.asset_id = dvl.asset_id
            JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
            WHERE NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))
            GROUP BY a.asset_id, a.hostname, a.asset_type, a.department
            ORDER BY vulnerability_count DESC
            LIMIT 10";
        
        $assets_stmt = $db->query($assets_sql);
        $top_affected_assets = $assets_stmt->fetchAll();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'severity_distribution' => $severity_distribution,
                'status_distribution' => $status_distribution,
                'top_affected_assets' => $top_affected_assets
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'ANALYTICS_ERROR',
                'message' => 'Failed to get vulnerability analytics'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function getRecallAnalytics() {
    global $user;
    
    try {
        $db = DatabaseConfig::getInstance();
        
        // Get recall status distribution
        $status_sql = "SELECT 
            recall_status,
            COUNT(*) as count
            FROM recalls r
            GROUP BY recall_status
            ORDER BY count DESC";
        
        $status_stmt = $db->query($status_sql);
        $status_distribution = $status_stmt->fetchAll();
        
        // Get manufacturer distribution
        $manufacturer_sql = "SELECT 
            manufacturer,
            COUNT(*) as count
            FROM recalls r
            GROUP BY manufacturer
            ORDER BY count DESC
            LIMIT 10";
        
        $manufacturer_stmt = $db->query($manufacturer_sql);
        $manufacturer_distribution = $manufacturer_stmt->fetchAll();
        
        // Get recent recalls (exclude resolved)
        $recent_sql = "SELECT 
            r.recall_id,
            r.recall_number,
            r.product_name,
            r.manufacturer,
            r.recall_date,
            r.recall_status,
            COUNT(drl.device_id) as affected_devices
            FROM recalls r
            LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
                AND (drl.remediation_status IS NULL OR drl.remediation_status <> 'Resolved')
            WHERE r.recall_date >= :recent_date
            GROUP BY r.recall_id, r.recall_number, r.product_name, r.manufacturer, r.recall_date, r.recall_status
            ORDER BY r.recall_date DESC
            LIMIT 10";
        
        $recent_stmt = $db->prepare($recent_sql);
        $recent_stmt->execute([
            ':recent_date' => date('Y-m-d', strtotime('-90 days'))
        ]);
        $recent_recalls = $recent_stmt->fetchAll();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'status_distribution' => $status_distribution,
                'manufacturer_distribution' => $manufacturer_distribution,
                'recent_recalls' => $recent_recalls
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'ANALYTICS_ERROR',
                'message' => 'Failed to get recall analytics'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function getComplianceAnalytics() {
    global $user;
    
    try {
        $db = DatabaseConfig::getInstance();
        
        // Get compliance metrics (exclude patched/resolved)
        $compliance_sql = "SELECT 
            COUNT(DISTINCT a.asset_id) as total_assets,
            COUNT(DISTINCT CASE WHEN md.device_id IS NOT NULL THEN a.asset_id END) as mapped_assets,
            COUNT(DISTINCT CASE WHEN dvl.cve_id IS NOT NULL AND NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text)) THEN a.asset_id END) as assets_with_vulns,
            COUNT(DISTINCT CASE WHEN drl.recall_id IS NOT NULL AND (drl.remediation_status IS NULL OR drl.remediation_status <> 'Resolved') THEN a.asset_id END) as assets_with_recalls
            FROM assets a
            LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
            LEFT JOIN device_vulnerabilities_link dvl ON a.asset_id = dvl.asset_id
            LEFT JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
            LEFT JOIN device_recalls_link drl ON a.asset_id = drl.asset_id
            WHERE a.status = 'Active'";
        
        $compliance_stmt = $db->query($compliance_sql);
        $compliance_metrics = $compliance_stmt->fetch();
        
        // Calculate compliance percentages
        $total_assets = $compliance_metrics['total_assets'];
        $mapped_percentage = $total_assets > 0 ? round(($compliance_metrics['mapped_assets'] / $total_assets) * 100, 2) : 0;
        $vuln_percentage = $total_assets > 0 ? round(($compliance_metrics['assets_with_vulns'] / $total_assets) * 100, 2) : 0;
        $recall_percentage = $total_assets > 0 ? round(($compliance_metrics['assets_with_recalls'] / $total_assets) * 100, 2) : 0;
        
        echo json_encode([
            'success' => true,
            'data' => [
                'compliance_metrics' => [
                    'total_assets' => $total_assets,
                    'mapped_assets' => $compliance_metrics['mapped_assets'],
                    'assets_with_vulnerabilities' => $compliance_metrics['assets_with_vulns'],
                    'assets_with_recalls' => $compliance_metrics['assets_with_recalls'],
                    'mapping_compliance' => $mapped_percentage,
                    'vulnerability_coverage' => $vuln_percentage,
                    'recall_coverage' => $recall_percentage
                ]
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'ANALYTICS_ERROR',
                'message' => 'Failed to get compliance analytics'
            ],
            'timestamp' => date('c')
        ]);
    }
}
?>
