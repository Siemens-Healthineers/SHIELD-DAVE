<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}

// Start output buffering to prevent PHP warnings/notices from corrupting JSON
ob_start();

require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../config/database.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
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
    ob_clean();
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

// Check if user has permission to read software packages
$unifiedAuth->requirePermission('vulnerabilities', 'read');

// Get database connection
$db = DatabaseConfig::getInstance();

// Handle different operations
$method = $_SERVER['REQUEST_METHOD'];

// When included by the router, we don't use PATH_INFO
// The router already parsed the request and this file is directly included
// So we just handle the base endpoint (list packages)

try {
    switch ($method) {
        case 'GET':
            // Always handle list packages when this file is accessed
            handleListPackages($db, $user);
            break;
            
        default:
            ob_clean();
            http_response_code(405);
            echo json_encode([
                'success' => false,
                'error' => 'Method not allowed',
                'timestamp' => date('c')
            ]);
            exit;
    }
} catch (Exception $e) {
    error_log("Software Packages API Error: " . $e->getMessage());
    ob_clean();
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'INTERNAL_ERROR',
            'message' => 'Internal server error'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * List software packages with risk priorities
 */
function handleListPackages($db, $user) {
    // Get filter parameters
    $page = isset($_GET['page']) ? intval($_GET['page']) : 1;
    $limit = isset($_GET['limit']) ? intval($_GET['limit']) : 25;
    $offset = ($page - 1) * $limit;
    
    $filters = [];
    $params = [];
    
    // Filter by tier
    if (isset($_GET['tier']) && $_GET['tier'] !== '') {
        if ($_GET['tier'] === '1') {
            $filters[] = "tier1_assets_count > 0";
        } elseif ($_GET['tier'] === '2') {
            $filters[] = "tier2_assets_count > 0";
        } elseif ($_GET['tier'] === '3') {
            $filters[] = "tier3_assets_count > 0";
        }
    }
    
    // Filter by KEV
    if (isset($_GET['kev_only']) && $_GET['kev_only'] === 'true') {
        $filters[] = "kev_count > 0";
    }
    
    // Filter by severity
    if (isset($_GET['severity']) && $_GET['severity'] !== '') {
        $severity = $_GET['severity'];
        if ($severity === 'Critical') {
            $filters[] = "critical_severity_count > 0";
        } elseif ($severity === 'High') {
            $filters[] = "high_severity_count > 0";
        }
    }
    
    // Search by package name
    if (isset($_GET['search']) && $_GET['search'] !== '') {
        $filters[] = "LOWER(package_name) LIKE LOWER(?)";
        $params[] = '%' . $_GET['search'] . '%';
    }
    
    $whereClause = !empty($filters) ? 'WHERE ' . implode(' AND ', $filters) : '';
    
    // Get total count
    $sql = "SELECT COUNT(*) as total FROM software_package_risk_priority_view $whereClause";
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $total = $stmt->fetch()['total'];
    
    // Get paginated results
    $sql = "SELECT * FROM software_package_risk_priority_view 
            $whereClause
            ORDER BY kev_count DESC, tier1_assets_count DESC, aggregate_risk_score DESC
            LIMIT ? OFFSET ?";
    $params[] = $limit;
    $params[] = $offset;
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $packages = $stmt->fetchAll();
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => $packages,
        'pagination' => [
            'page' => $page,
            'limit' => $limit,
            'total' => $total,
            'pages' => ceil($total / $limit)
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * Get detailed package information
 */
function handleGetPackageDetails($db, $packageId) {
    $sql = "SELECT * FROM software_package_risk_priority_view WHERE package_id = ?";
    $stmt = $db->prepare($sql);
    $stmt->execute([$packageId]);
    $package = $stmt->fetch();
    
    if (!$package) {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'Package not found']);
        return;
    }
    
    // Get available patches
    $sql = "SELECT * FROM patches WHERE target_package_id = ? AND is_active = TRUE ORDER BY release_date DESC";
    $stmt = $db->prepare($sql);
    $stmt->execute([$packageId]);
    $patches = $stmt->fetchAll();
    
    $package['available_patches'] = $patches;
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => $package,
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * Get affected assets for a package
 */
function handleGetAffectedAssets($db, $packageId) {
    $tier = isset($_GET['tier']) ? $_GET['tier'] : null;
    
    // Modified query to show all assets that have this package installed
    // This matches how affected_assets_count is calculated - all assets with the package, regardless of vulnerability status
    // We still prefer to show open vulnerabilities if they exist
    $sql = "SELECT DISTINCT
                a.asset_id,
                a.hostname,
                a.ip_address,
                a.asset_type as device_type,
                a.criticality,
                a.department,
                a.status as is_active,
                l.location_name as location,
                l.criticality as location_criticality,
                md.device_id,
                md.device_name,
                md.brand_name,
                sc.version,
                COALESCE(COUNT(DISTINCT CASE WHEN dvl.remediation_status = 'Open' THEN dvl.cve_id END), 0) as vulnerability_count,
                MAX(CASE WHEN v.is_kev = true AND dvl.remediation_status = 'Open' THEN 1 ELSE 0 END)::int as has_kev,
                MAX(CASE WHEN dvl.remediation_status = 'Open' THEN dvl.risk_score END) as max_risk_score,
                CASE 
                    WHEN MAX(CASE WHEN v.is_kev = true AND dvl.remediation_status = 'Open' THEN 1 ELSE 0 END) = 1 THEN 1
                    WHEN a.criticality = 'Clinical-High' AND COALESCE(l.criticality, 0) >= 8 THEN 2
                    ELSE 3
                END as tier
            FROM software_packages sp
            -- Match components by package name (since package_id may not be set on components)
            JOIN software_components sc ON sc.name = sp.name
            JOIN sboms s ON sc.sbom_id = s.sbom_id
            JOIN medical_devices md ON s.device_id = md.device_id
            JOIN assets a ON md.asset_id = a.asset_id
            LEFT JOIN locations l ON a.location_id = l.location_id
            LEFT JOIN device_vulnerabilities_link dvl ON md.device_id = dvl.device_id 
                AND (sc.component_id = dvl.component_id
                     OR EXISTS (
                         SELECT 1 FROM software_package_vulnerabilities spvuln
                         WHERE (spvuln.version_id = sc.version_id OR spvuln.package_id = sp.package_id)
                         AND spvuln.cve_id = dvl.cve_id
                     ))
            LEFT JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
            WHERE sp.package_id = ?";
    
    $params = [$packageId];
    
    $sql .= " GROUP BY a.asset_id, a.hostname, a.ip_address, a.asset_type, a.criticality, a.department, a.status,
                       l.location_name, l.criticality, md.device_id, md.device_name, md.brand_name, sc.version";
    
    if ($tier) {
        $sql .= " HAVING CASE 
                    WHEN MAX(CASE WHEN v.is_kev = true AND dvl.remediation_status = 'Open' THEN 1 ELSE 0 END) = 1 THEN 1
                    WHEN a.criticality = 'Clinical-High' AND COALESCE(l.criticality, 0) >= 8 THEN 2
                    ELSE 3
                END = ?";
        $params[] = $tier;
    }
    
    $sql .= " ORDER BY tier ASC, max_risk_score DESC NULLS LAST";
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $assets = $stmt->fetchAll();
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => $assets,
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * Get vulnerabilities for a package
 */
function handleGetPackageVulnerabilities($db, $packageId) {
    $sql = "SELECT 
                v.cve_id,
                v.description,
                v.severity,
                v.cvss_v4_score,
                v.cvss_v4_vector,
                v.cvss_v3_score,
                v.cvss_v3_vector,
                v.cvss_v2_score,
                v.cvss_v2_vector,
                v.is_kev as kev,
                v.published_date,
                v.last_modified_date,
                v.kev_due_date,
                spv.affects_version_range,
                COUNT(DISTINCT dvl.link_id) as affected_device_count,
                -- Determine best CVSS score for sorting (v4 > v3 > v2)
                COALESCE(v.cvss_v4_score, v.cvss_v3_score, v.cvss_v2_score) as cvss_score
            FROM software_package_vulnerabilities spv
            JOIN vulnerabilities v ON spv.cve_id = v.cve_id
            LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id 
                AND dvl.remediation_status = 'Open'
            WHERE spv.package_id = ?
            GROUP BY v.cve_id, v.description, v.severity, 
                     v.cvss_v4_score, v.cvss_v4_vector,
                     v.cvss_v3_score, v.cvss_v3_vector, 
                     v.cvss_v2_score, v.cvss_v2_vector,
                     v.is_kev, v.published_date, v.last_modified_date, v.kev_due_date, spv.affects_version_range
            ORDER BY v.is_kev DESC, 
                     COALESCE(v.cvss_v4_score, v.cvss_v3_score, v.cvss_v2_score) DESC NULLS LAST";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([$packageId]);
    $vulnerabilities = $stmt->fetchAll();
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => $vulnerabilities,
        'total' => count($vulnerabilities),
        'timestamp' => date('c')
    ]);
    exit;
}

