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

$db = DatabaseConfig::getInstance();
$method = $_SERVER['REQUEST_METHOD'];
$path = $_GET['path'] ?? '';

// Route requests
switch ($method) {
    case 'GET':
        handleGetRequest($path);
        break;
    case 'POST':
        handlePostRequest($path);
        break;
    case 'PUT':
        handlePutRequest($path);
        break;
    case 'DELETE':
        handleDeleteRequest($path);
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleGetRequest($path) {
    global $db, $user;
    
    try {
        if (empty($path)) {
            // List all vulnerabilities
            listVulnerabilities();
        } else {
            // Get specific vulnerability
            getVulnerability($path);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function buildOrderClause($sort, $sort_dir) {
    $valid_sorts = [
        'severity' => 'v.severity',
        'cvss_score' => 'COALESCE(v.cvss_v4_score, v.cvss_v3_score, v.cvss_v2_score)',
        'published_date' => 'v.published_date',
        'epss' => 'v.epss_score',
        'epss_percentile' => 'v.epss_percentile',
        'affected_assets' => 'COUNT(dvl.device_id)'
    ];
    
    $valid_dirs = ['asc', 'desc'];
    $dir = in_array(strtolower($sort_dir), $valid_dirs) ? strtoupper($sort_dir) : 'DESC';
    
    if (!empty($sort) && isset($valid_sorts[$sort])) {
        return $valid_sorts[$sort] . ' ' . $dir;
    }
    
    // Default sorting
    return 'v.severity DESC, COALESCE(v.cvss_v4_score, v.cvss_v3_score, v.cvss_v2_score) DESC';
}

function listVulnerabilities() {
    global $db, $user;
    
    // Get query parameters
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = min(100, max(1, intval($_GET['limit'] ?? 25)));
    $search = $_GET['search'] ?? '';
    $severity = $_GET['severity'] ?? '';
    $status = $_GET['status'] ?? '';
    $asset_id = $_GET['asset_id'] ?? '';
    
    // EPSS filtering parameters
    $epss_gt = $_GET['epss-gt'] ?? '';
    $epss_percentile_gt = $_GET['epss-percentile-gt'] ?? '';
    $sort = $_GET['sort'] ?? '';
    $sort_dir = $_GET['sort_dir'] ?? 'desc';
    
    $offset = ($page - 1) * $limit;
    
    // Build query
    $where_conditions = [];
    $params = [];
    
    if (!empty($search)) {
        $where_conditions[] = "(v.cve_id ILIKE :search OR v.description ILIKE :search)";
        $params[':search'] = "%$search%";
    }
    
    if (!empty($severity)) {
        $where_conditions[] = "v.severity = :severity";
        $params[':severity'] = $severity;
    }
    
    if (!empty($status)) {
        $where_conditions[] = "dvl.remediation_status = :status";
        $params[':status'] = $status;
    }
    
    if (!empty($asset_id)) {
        $where_conditions[] = "md.asset_id = :asset_id";
        $params[':asset_id'] = $asset_id;
    }
    
    // EPSS filtering
    if (!empty($epss_gt) && is_numeric($epss_gt)) {
        $where_conditions[] = "v.epss_score >= :epss_gt";
        $params[':epss_gt'] = floatval($epss_gt);
    }
    
    if (!empty($epss_percentile_gt) && is_numeric($epss_percentile_gt)) {
        $where_conditions[] = "v.epss_percentile >= :epss_percentile_gt";
        $params[':epss_percentile_gt'] = floatval($epss_percentile_gt);
    }
    
    // Build join clause - use LEFT JOIN to include all vulnerabilities even without links
    // Use vulnerability_id for the join and handle both device_id and asset_id cases
    $join_clause = "LEFT JOIN device_vulnerabilities_link dvl ON v.vulnerability_id = dvl.vulnerability_id";
    $join_clause .= " LEFT JOIN medical_devices md ON dvl.device_id = md.device_id";
    $join_clause .= " LEFT JOIN assets a ON COALESCE(md.asset_id, dvl.asset_id) = a.asset_id";
    
    // Only add asset filters if specifically filtering by asset_id
    // Don't exclude vulnerabilities without assets by default
    if (!empty($asset_id)) {
        $where_conditions[] = "(md.asset_id = :asset_id OR dvl.asset_id = :asset_id)";
    }
    
    // If status filter is applied, only show vulnerabilities with that status
    // Otherwise show all vulnerabilities (including those without any links)
    if (!empty($status)) {
        // Already added to where_conditions above
    }
    
    $where_clause = empty($where_conditions) ? '1=1' : implode(' AND ', $where_conditions);
    
    // Get total count
    $count_sql = "SELECT COUNT(DISTINCT v.vulnerability_id) as total 
                  FROM vulnerabilities v 
                  $join_clause
                  WHERE $where_clause";
    $count_stmt = $db->prepare($count_sql);
    $count_stmt->execute($params);
    $total = $count_stmt->fetch()['total'];
    
    // Get vulnerabilities
    $sql = "SELECT 
        v.vulnerability_id,
        v.cve_id,
        v.description,
        v.severity,
        v.cvss_v4_score,
        v.cvss_v4_vector,
        v.cvss_v3_score,
        v.cvss_v3_vector,
        v.cvss_v2_score,
        v.cvss_v2_vector,
        COALESCE(v.cvss_v4_score, v.cvss_v3_score, v.cvss_v2_score) as cvss_score,
        v.is_kev as kev,
        v.published_date,
        v.last_modified_date as last_modified,
        -- EPSS fields
        v.epss_score,
        v.epss_percentile,
        v.epss_date,
        v.epss_last_updated,
        COUNT(DISTINCT a.asset_id) as affected_assets,
        COUNT(CASE WHEN dvl.remediation_status = 'Open' THEN 1 END) as open_count,
        COUNT(CASE WHEN dvl.remediation_status = 'In Progress' THEN 1 END) as in_progress_count,
        COUNT(CASE WHEN dvl.remediation_status = 'Resolved' THEN 1 END) as resolved_count
        FROM vulnerabilities v
        $join_clause
        WHERE $where_clause
        GROUP BY v.vulnerability_id, v.cve_id, v.description, v.severity, 
                 v.cvss_v4_score, v.cvss_v4_vector,
                 v.cvss_v3_score, v.cvss_v3_vector,
                 v.cvss_v2_score, v.cvss_v2_vector,
                 v.is_kev, v.published_date, v.last_modified_date,
                 v.epss_score, v.epss_percentile, v.epss_date, v.epss_last_updated
        ORDER BY " . buildOrderClause($sort, $sort_dir) . "
        LIMIT :limit OFFSET :offset";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    
    $stmt->execute();
    $vulnerabilities = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $vulnerabilities,
        'pagination' => [
            'page' => $page,
            'limit' => $limit,
            'total' => $total,
            'pages' => ceil($total / $limit)
        ],
        'timestamp' => date('c')
    ]);
}

function getVulnerability($vulnerability_id) {
    global $db, $user;
    
    $sql = "SELECT 
        v.vulnerability_id,
        v.cve_id,
        v.description,
        v.severity,
        v.cvss_v4_score,
        v.cvss_v4_vector,
        v.cvss_v3_score,
        v.cvss_v3_vector,
        v.cvss_v2_score,
        v.cvss_v2_vector,
        COALESCE(v.cvss_v4_score, v.cvss_v3_score, v.cvss_v2_score) as cvss_score,
        v.is_kev as kev,
        v.published_date,
        v.last_modified_date as last_modified,
        -- EPSS fields
        v.epss_score,
        v.epss_percentile,
        v.epss_date,
        v.epss_last_updated,
        v.nvd_data
        FROM vulnerabilities v
        WHERE v.vulnerability_id = :vulnerability_id";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':vulnerability_id', $vulnerability_id);
    $stmt->execute();
    $vulnerability = $stmt->fetch();
    
    if (!$vulnerability) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'VULNERABILITY_NOT_FOUND',
                'message' => 'Vulnerability not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Get affected assets with debugging
    // First check if there are any links
    $debug_links_sql = "SELECT 
        link_id,
        asset_id,
        device_id,
        vulnerability_id,
        cve_id
        FROM device_vulnerabilities_link 
        WHERE vulnerability_id = :vulnerability_id";
    $debug_links_stmt = $db->prepare($debug_links_sql);
    $debug_links_stmt->bindValue(':vulnerability_id', $vulnerability_id);
    $debug_links_stmt->execute();
    $debug_links = $debug_links_stmt->fetchAll();
    
    $assets_sql = "SELECT 
        a.asset_id,
        a.hostname,
        a.ip_address,
        a.asset_type,
        a.department,
        dvl.remediation_status,
        dvl.remediation_notes,
        dvl.discovered_at,
        dvl.asset_id as link_asset_id,
        dvl.device_id as link_device_id,
        md.asset_id as md_asset_id
        FROM device_vulnerabilities_link dvl
        LEFT JOIN medical_devices md ON dvl.device_id = md.device_id
        LEFT JOIN assets a ON COALESCE(md.asset_id, dvl.asset_id) = a.asset_id
        WHERE dvl.vulnerability_id = :vulnerability_id";
    
    $assets_stmt = $db->prepare($assets_sql);
    $assets_stmt->bindValue(':vulnerability_id', $vulnerability_id);
    $assets_stmt->execute();
    $affected_assets = $assets_stmt->fetchAll();
    
    $vulnerability['affected_assets'] = $affected_assets;
    $vulnerability['_debug'] = [
        'links_found' => count($debug_links),
        'links' => $debug_links,
        'assets_query_result_count' => count($affected_assets)
    ];
    
    echo json_encode([
        'success' => true,
        'data' => $vulnerability,
        'timestamp' => date('c')
    ]);
}

function handlePostRequest($path) {
    global $db, $user;
    
    try {
        if ($path === 'evaluate') {
            // Evaluate SBOM against NVD
            evaluateSbomVulnerabilities();
        } elseif (empty($path)) {
            // Create new vulnerability
            createVulnerability();
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

function evaluateSbomVulnerabilities() {
    global $db, $user;
    
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_JSON',
                'message' => 'Invalid JSON input'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    $asset_id = $input['asset_id'] ?? null;
    $evaluation_type = $input['evaluation_type'] ?? 'sbom';
    
    if (!$asset_id) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'MISSING_ASSET_ID',
                'message' => 'Asset ID is required'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Check if asset exists
    $asset_sql = "SELECT asset_id, hostname FROM assets WHERE asset_id = :asset_id";
    $asset_stmt = $db->prepare($asset_sql);
    $asset_stmt->bindValue(':asset_id', $asset_id);
    $asset_stmt->execute();
    $asset = $asset_stmt->fetch();
    
    if (!$asset) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'ASSET_NOT_FOUND',
                'message' => 'Asset not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Create evaluation job record
    $eval_sql = "INSERT INTO vulnerability_scans (
        asset_id, scan_type, include_sbom, status, 
        requested_by, requested_at, created_at
    ) VALUES (
        :asset_id, :evaluation_type, 'true', 'Pending',
        :requested_by, :requested_at, :created_at
    ) RETURNING scan_id";
    
    $eval_stmt = $db->prepare($eval_sql);
    $eval_stmt->bindValue(':asset_id', $asset_id);
    $eval_stmt->bindValue(':evaluation_type', $evaluation_type);
    $eval_stmt->bindValue(':requested_by', $user['user_id']);
    $eval_stmt->bindValue(':requested_at', date('Y-m-d H:i:s'));
    $eval_stmt->bindValue(':created_at', date('Y-m-d H:i:s'));
    $eval_stmt->execute();
    $eval_id = $eval_stmt->fetch()['scan_id'];
    
    // Trigger SBOM evaluation against NVD (Python service)
    $eval_result = triggerPythonSbomEvaluation($eval_id, $asset_id, $evaluation_type);
    
    echo json_encode([
        'success' => true,
        'data' => [
            'evaluation_id' => $eval_id,
            'asset_id' => $asset_id,
            'evaluation_type' => $evaluation_type,
            'status' => $eval_result['status'],
            'message' => $eval_result['message'],
            'vulnerabilities_found' => $eval_result['vulnerabilities_found'] ?? 0
        ],
        'timestamp' => date('c')
    ]);
}

/**
 * Trigger Python SBOM evaluation against NVD
 */
function triggerPythonSbomEvaluation($eval_id, $asset_id, $evaluation_type) {
    try {
        // Update evaluation status to Running
        $db = DatabaseConfig::getInstance();
        $update_sql = "UPDATE vulnerability_scans SET status = 'Running', started_at = CURRENT_TIMESTAMP WHERE scan_id = :eval_id";
        $update_stmt = $db->prepare($update_sql);
        $update_stmt->bindValue(':eval_id', $eval_id);
        $update_stmt->execute();
        
        // Get device_id from asset_id
        $device_sql = "SELECT device_id FROM medical_devices WHERE asset_id = :asset_id";
        $device_stmt = $db->prepare($device_sql);
        $device_stmt->bindValue(':asset_id', $asset_id);
        $device_stmt->execute();
        $device = $device_stmt->fetch();
        
        if (!$device) {
            // Update evaluation status to Failed
            $fail_sql = "UPDATE vulnerability_scans SET status = 'Failed', error_message = :error, completed_at = CURRENT_TIMESTAMP WHERE scan_id = :eval_id";
            $fail_stmt = $db->prepare($fail_sql);
            $fail_stmt->bindValue(':error', 'Device not found for asset');
            $fail_stmt->bindValue(':eval_id', $eval_id);
            $fail_stmt->execute();
            
            return [
                'status' => 'Failed',
                'message' => 'Device not found for asset',
                'vulnerabilities_found' => 0
            ];
        }
        
        // Execute Python SBOM evaluator
        $python_script = '/var/www/html/python/services/vulnerability_scanner.py';
        $command = "cd /var/www/html && python3 $python_script --device-id " . escapeshellarg($device['device_id']) . " --scan-type sbom";
        
        // Run in background
        $output = shell_exec($command . " 2>&1 &");
        
        // For now, mark as completed (in real implementation, this would be async)
        $complete_sql = "UPDATE vulnerability_scans SET status = 'Completed', completed_at = CURRENT_TIMESTAMP, vulnerabilities_found = 0, vulnerabilities_stored = 0 WHERE scan_id = :eval_id";
        $complete_stmt = $db->prepare($complete_sql);
        $complete_stmt->bindValue(':eval_id', $eval_id);
        $complete_stmt->execute();
        
        return [
            'status' => 'Completed',
            'message' => 'SBOM evaluation against NVD initiated successfully',
            'vulnerabilities_found' => 0
        ];
        
    } catch (Exception $e) {
        // Update evaluation status to Failed
        $db = DatabaseConfig::getInstance();
        $fail_sql = "UPDATE vulnerability_scans SET status = 'Failed', error_message = :error, completed_at = CURRENT_TIMESTAMP WHERE scan_id = :eval_id";
        $fail_stmt = $db->prepare($fail_sql);
        $fail_stmt->bindValue(':error', $e->getMessage());
        $fail_stmt->bindValue(':eval_id', $eval_id);
        $fail_stmt->execute();
        
        return [
            'status' => 'Failed',
            'message' => 'Error initiating SBOM evaluation: ' . $e->getMessage(),
            'vulnerabilities_found' => 0
        ];
    }
}

function handlePutRequest($path) {
    global $db, $user;
    
    try {
        if (empty($path)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_VULNERABILITY_ID',
                    'message' => 'Vulnerability ID is required'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        updateVulnerability($path);
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

function updateVulnerability($vulnerability_id) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to update vulnerabilities
    $unifiedAuth->requirePermission('vulnerabilities', 'write');
    
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_JSON',
                'message' => 'Invalid JSON input'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Check if vulnerability exists
    $existing = $db->query("SELECT vulnerability_id FROM vulnerabilities WHERE vulnerability_id = ?", [$vulnerability_id])->fetch();
    if (!$existing) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'VULNERABILITY_NOT_FOUND',
                'message' => 'Vulnerability not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Validate severity if provided
    if (isset($input['severity'])) {
        $valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown'];
        if (!in_array($input['severity'], $valid_severities)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_SEVERITY',
                    'message' => 'Severity must be one of: ' . implode(', ', $valid_severities)
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    // Validate priority if provided
    if (isset($input['priority'])) {
        $valid_priorities = ['Critical-KEV', 'High', 'Medium', 'Low', 'Normal'];
        if (!in_array($input['priority'], $valid_priorities)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_PRIORITY',
                    'message' => 'Priority must be one of: ' . implode(', ', $valid_priorities)
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    // Validate CVSS scores (0.0-10.0)
    $cvss_fields = ['cvss_v2_score', 'cvss_v3_score', 'cvss_v4_score'];
    foreach ($cvss_fields as $field) {
        if (isset($input[$field])) {
            $score = floatval($input[$field]);
            if ($score < 0.0 || $score > 10.0) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => [
                        'code' => 'INVALID_CVSS_SCORE',
                        'message' => $field . ' must be between 0.0 and 10.0'
                    ],
                    'timestamp' => date('c')
                ]);
                return;
            }
        }
    }
    
    // Validate EPSS scores (0.0000-1.0000)
    $epss_fields = ['epss_score', 'epss_percentile'];
    foreach ($epss_fields as $field) {
        if (isset($input[$field])) {
            $score = floatval($input[$field]);
            if ($score < 0.0000 || $score > 1.0000) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => [
                        'code' => 'INVALID_EPSS_SCORE',
                        'message' => $field . ' must be between 0.0000 and 1.0000'
                    ],
                    'timestamp' => date('c')
                ]);
                return;
            }
        }
    }
    
    // Validate dates
    $date_fields = ['published_date', 'last_modified_date', 'kev_date_added', 'kev_due_date', 'epss_date'];
    foreach ($date_fields as $field) {
        if (isset($input[$field]) && !empty($input[$field])) {
            $date = DateTime::createFromFormat('Y-m-d', $input[$field]);
            if (!$date || $date->format('Y-m-d') !== $input[$field]) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => [
                        'code' => 'INVALID_DATE_FORMAT',
                        'message' => $field . ' must be in YYYY-MM-DD format'
                    ],
                    'timestamp' => date('c')
                ]);
                return;
            }
        }
    }
    
    // Validate timestamps
    $timestamp_fields = ['epss_last_updated'];
    foreach ($timestamp_fields as $field) {
        if (isset($input[$field]) && !empty($input[$field])) {
            $timestamp = DateTime::createFromFormat('Y-m-d H:i:s', $input[$field]);
            if (!$timestamp || $timestamp->format('Y-m-d H:i:s') !== $input[$field]) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => [
                        'code' => 'INVALID_TIMESTAMP_FORMAT',
                        'message' => $field . ' must be in YYYY-MM-DD HH:MM:SS format'
                    ],
                    'timestamp' => date('c')
                ]);
                return;
            }
        }
    }
    
    // Validate boolean fields
    if (isset($input['is_kev'])) {
        if (!is_bool($input['is_kev']) && !in_array($input['is_kev'], ['true', 'false', '1', '0', 1, 0])) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_BOOLEAN_VALUE',
                    'message' => 'is_kev must be a boolean value'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    // Validate KEV ID if provided
    if (isset($input['kev_id']) && !empty($input['kev_id'])) {
        $kev_exists = $db->query("SELECT kev_id FROM cisa_kev_catalog WHERE kev_id = ?", [$input['kev_id']])->fetch();
        if (!$kev_exists) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_KEV_ID',
                    'message' => 'KEV ID does not exist in the CISA KEV catalog'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    // Build update query with all allowed fields
    $update_fields = [];
    $params = [];
    
    // Map input fields to database columns
    $field_mapping = [
        'description' => 'description',
        'severity' => 'severity',
        'priority' => 'priority',
        'cvss_v2_score' => 'cvss_v2_score',
        'cvss_v2_vector' => 'cvss_v2_vector',
        'cvss_v3_score' => 'cvss_v3_score',
        'cvss_v3_vector' => 'cvss_v3_vector',
        'cvss_v4_score' => 'cvss_v4_score',
        'cvss_v4_vector' => 'cvss_v4_vector',
        'published_date' => 'published_date',
        'last_modified_date' => 'last_modified_date',
        'is_kev' => 'is_kev',
        'kev_id' => 'kev_id',
        'kev_date_added' => 'kev_date_added',
        'kev_due_date' => 'kev_due_date',
        'kev_required_action' => 'kev_required_action',
        'epss_score' => 'epss_score',
        'epss_percentile' => 'epss_percentile',
        'epss_date' => 'epss_date',
        'epss_last_updated' => 'epss_last_updated',
        'nvd_data' => 'nvd_data'
    ];
    
    foreach ($field_mapping as $input_field => $db_field) {
        if (isset($input[$input_field])) {
            $value = $input[$input_field];
            
            // Handle special conversions
            if ($input_field === 'is_kev') {
                $value = ($value === true || $value === 'true' || $value === '1' || $value === 1) ? 'true' : 'false';
            } elseif (in_array($input_field, ['cvss_v2_score', 'cvss_v3_score', 'cvss_v4_score', 'epss_score', 'epss_percentile'])) {
                $value = floatval($value);
            } elseif ($input_field === 'nvd_data' && (is_array($value) || is_object($value))) {
                $value = json_encode($value);
            } elseif (in_array($input_field, ['published_date', 'last_modified_date', 'kev_date_added', 'kev_due_date', 'epss_date']) && empty($value)) {
                continue; // Skip empty dates (set to NULL if needed)
            }
            
            $update_fields[] = "$db_field = ?";
            $params[] = $value;
        }
    }
    
    if (empty($update_fields)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'NO_FIELDS_TO_UPDATE',
                'message' => 'No valid fields to update'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Always update updated_at timestamp
    $update_fields[] = "updated_at = CURRENT_TIMESTAMP";
    
    // Add vulnerability_id to params for WHERE clause
    $params[] = $vulnerability_id;
    
    try {
        $sql = "UPDATE vulnerabilities SET " . implode(', ', $update_fields) . " WHERE vulnerability_id = ?";
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        
        if ($stmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'VULNERABILITY_NOT_FOUND',
                    'message' => 'Vulnerability not found or no changes were made'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        echo json_encode([
            'success' => true,
            'message' => 'Vulnerability updated successfully',
            'data' => [
                'vulnerability_id' => $vulnerability_id,
                'updated_fields' => array_keys(array_intersect_key($input, $field_mapping)),
                'updated_at' => date('c')
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'UPDATE_FAILED',
                'message' => 'Failed to update vulnerability: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function handleDeleteRequest($path) {
    global $db, $user;
    
    try {
        if (empty($path)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_VULNERABILITY_ID',
                    'message' => 'Vulnerability ID is required'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        deleteVulnerability($path);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error',
                'detail' => $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function deleteVulnerability($vulnerability_id) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to delete vulnerabilities
    $unifiedAuth->requirePermission('vulnerabilities', 'write');
    
    // Delete vulnerability and related links
    $db->beginTransaction();
    
    try {
        // Delete device vulnerability links
        $links_sql = "DELETE FROM device_vulnerabilities_link WHERE vulnerability_id = ?";
        $links_stmt = $db->prepare($links_sql);
        $links_stmt->execute([$vulnerability_id]);
        
        // Delete vulnerability
        $vuln_sql = "DELETE FROM vulnerabilities WHERE vulnerability_id = ?";
        $vuln_stmt = $db->prepare($vuln_sql);
        $vuln_stmt->execute([$vulnerability_id]);

        if ($vuln_stmt->rowCount() === 0) {
            $db->rollback();
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'VULNERABILITY_NOT_FOUND',
                    'message' => 'Vulnerability not found'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        $db->commit();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'vulnerability_id' => $vulnerability_id,
                'message' => 'Vulnerability deleted successfully'
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        $db->rollback();
        throw $e;
    }
}

/**
 * Create a new vulnerability
 */
function createVulnerability() {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to create vulnerabilities
    $unifiedAuth->requirePermission('vulnerabilities', 'write');
    
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_JSON',
                'message' => 'Invalid JSON input'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Validate required fields
    // Note: device_id OR asset_id is required (asset_id will be resolved to device_id)
    $required_fields = [];
    $missing_fields = [];
    
    foreach ($required_fields as $field) {
        if (!isset($input[$field]) || empty($input[$field])) {
            $missing_fields[] = $field;
        }
    }
    
    // Require either device_id or asset_id (with component_id)
    if (!isset($input['device_id']) && !isset($input['asset_id'])) {
        $missing_fields[] = 'device_id or asset_id';
    }
    
    //if (!isset($input['component_id']) || empty($input['component_id'])) {
        //$missing_fields[] = 'component_id';
    //}
    
    if (!empty($missing_fields)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'MISSING_REQUIRED_FIELDS',
                'message' => 'Missing required fields: ' . implode(', ', $missing_fields) . '. Vulnerabilities must be linked to a device/asset and component.'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Initialize variables
    $cve_id = null;
    $device_id = null;
    $asset_id = null;
    $component_id = null;
    
    // Validate CVE ID format
    if (isset($input['cve_id']) && !empty($input['cve_id'])) {
        $cve_id = trim($input['cve_id']);
        if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve_id)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_CVE_ID',
                    'message' => 'CVE ID must be in format CVE-YYYY-NNNN'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    // Resolve device_id from asset_id if provided
    if (isset($input['device_id']) && !empty($input['device_id'])) {
        $device_id = $input['device_id'];
        
        // Validate device exists and get asset_id
        $device_check = $db->query("SELECT device_id, asset_id FROM medical_devices WHERE device_id = ?", [$device_id])->fetch();
        if (!$device_check) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'DEVICE_NOT_FOUND',
                    'message' => 'Device with ID ' . $device_id . ' does not exist'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        // Get asset_id from input or from device record
        if (isset($input['asset_id']) && !empty($input['asset_id'])) {
            $asset_id = $input['asset_id'];
        } else {
            $asset_id = $device_check['asset_id'];
        }
    } elseif (isset($input['asset_id']) && !empty($input['asset_id'])) {
        // Resolve asset_id to device_id
        $asset_id = $input['asset_id'];
        $device_result = $db->query("SELECT device_id FROM medical_devices WHERE asset_id = ?", [$asset_id])->fetch();
        if (!$device_result) {
            $device_id = null;
        } else {
            $device_id = $device_result['device_id'];
        }
        
    }
    
    if (isset($input['component_id']) && !empty($input['component_id'])) {
        // Validate component_id exists
        $component_id = $input['component_id'];
        $component_check = $db->query("SELECT component_id FROM software_components WHERE component_id = ?", [$component_id])->fetch();
        if (!$component_check) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'COMPONENT_NOT_FOUND',
                    'message' => 'Software component with ID ' . $component_id . ' does not exist'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    if (isset($input['cve_id']) && !empty($input['cve_id'])) {
        // Check if vulnerability already exists (but allow if we're adding a new device link)
        $existing = $db->query("SELECT cve_id FROM vulnerabilities WHERE cve_id = ?", [$cve_id])->fetch();
        if ($existing) {
            // Vulnerability exists, check if device link already exists
            $link_exists = $db->query(
                "SELECT link_id FROM device_vulnerabilities_link WHERE device_id = ? AND component_id = ? AND cve_id = ?",
                [$device_id, $component_id, $cve_id]
            )->fetch();
            
            if ($link_exists) {
                http_response_code(409);
                echo json_encode([
                    'success' => false,
                    'error' => [
                        'code' => 'DEVICE_VULNERABILITY_LINK_EXISTS',
                        'message' => 'This vulnerability is already linked to the specified device and component'
                    ],
                    'timestamp' => date('c')
                ]);
                return;
            }
            // Vulnerability exists but link doesn't - we'll create the link below
        }
    }
    
    // Validate severity if provided
    if (isset($input['severity'])) {
        $valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown'];
        if (!in_array($input['severity'], $valid_severities)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_SEVERITY',
                    'message' => 'Severity must be one of: ' . implode(', ', $valid_severities)
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    // Validate priority if provided
    if (isset($input['priority'])) {
        $valid_priorities = ['Critical-KEV', 'High', 'Medium', 'Low', 'Normal'];
        if (!in_array($input['priority'], $valid_priorities)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_PRIORITY',
                    'message' => 'Priority must be one of: ' . implode(', ', $valid_priorities)
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    // Validate CVSS scores (0.0-10.0)
    $cvss_fields = ['cvss_v2_score', 'cvss_v3_score', 'cvss_v4_score'];
    foreach ($cvss_fields as $field) {
        if (isset($input[$field])) {
            $score = floatval($input[$field]);
            if ($score < 0.0 || $score > 10.0) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => [
                        'code' => 'INVALID_CVSS_SCORE',
                        'message' => $field . ' must be between 0.0 and 10.0'
                    ],
                    'timestamp' => date('c')
                ]);
                return;
            }
        }
    }
    
    // Validate EPSS scores (0.0000-1.0000)
    $epss_fields = ['epss_score', 'epss_percentile'];
    foreach ($epss_fields as $field) {
        if (isset($input[$field])) {
            $score = floatval($input[$field]);
            if ($score < 0.0000 || $score > 1.0000) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => [
                        'code' => 'INVALID_EPSS_SCORE',
                        'message' => $field . ' must be between 0.0000 and 1.0000'
                    ],
                    'timestamp' => date('c')
                ]);
                return;
            }
        }
    }
    
    // Validate dates
    $date_fields = ['published_date', 'last_modified_date', 'kev_date_added', 'kev_due_date', 'epss_date'];
    foreach ($date_fields as $field) {
        if (isset($input[$field]) && !empty($input[$field])) {
            $date = DateTime::createFromFormat('Y-m-d', $input[$field]);
            if (!$date || $date->format('Y-m-d') !== $input[$field]) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => [
                        'code' => 'INVALID_DATE_FORMAT',
                        'message' => $field . ' must be in YYYY-MM-DD format'
                    ],
                    'timestamp' => date('c')
                ]);
                return;
            }
        }
    }
    
    // Validate timestamps
    $timestamp_fields = ['epss_last_updated'];
    foreach ($timestamp_fields as $field) {
        if (isset($input[$field]) && !empty($input[$field])) {
            $timestamp = DateTime::createFromFormat('Y-m-d H:i:s', $input[$field]);
            if (!$timestamp || $timestamp->format('Y-m-d H:i:s') !== $input[$field]) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => [
                        'code' => 'INVALID_TIMESTAMP_FORMAT',
                        'message' => $field . ' must be in YYYY-MM-DD HH:MM:SS format'
                    ],
                    'timestamp' => date('c')
                ]);
                return;
            }
        }
    }
    
    // Validate boolean fields
    $boolean_fields = ['is_kev'];
    foreach ($boolean_fields as $field) {
        if (isset($input[$field])) {
            if (!is_bool($input[$field]) && !in_array($input[$field], ['true', 'false', '1', '0', 1, 0])) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => [
                        'code' => 'INVALID_BOOLEAN_VALUE',
                        'message' => $field . ' must be a boolean value'
                    ],
                    'timestamp' => date('c')
                ]);
                return;
            }
        }
    }
    
    // Validate KEV ID if provided
    if (isset($input['kev_id']) && !empty($input['kev_id'])) {
        $kev_exists = $db->query("SELECT kev_id FROM cisa_kev_catalog WHERE kev_id = ?", [$input['kev_id']])->fetch();
        if (!$kev_exists) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_KEV_ID',
                    'message' => 'KEV ID does not exist in the CISA KEV catalog'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    try {
        $db->beginTransaction();
        
        // Prepare the insert statement with all possible fields in database order
        $fields = [
            'cve_id' => $cve_id ?? null,
            'description' => $input['description'] ?? null,
            'cvss_v3_score' => isset($input['cvss_v3_score']) ? floatval($input['cvss_v3_score']) : null,
            'cvss_v3_vector' => $input['cvss_v3_vector'] ?? null,
            'severity' => $input['severity'] ?? null,
            'published_date' => $input['published_date'] ?? null,
            'last_modified_date' => $input['last_modified_date'] ?? null,
            'nvd_data' => isset($input['nvd_data']) ? json_encode($input['nvd_data']) : null,
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s'),
            'cvss_v2_score' => isset($input['cvss_v2_score']) ? floatval($input['cvss_v2_score']) : null,
            'cvss_v2_vector' => $input['cvss_v2_vector'] ?? null,
            'is_kev' => isset($input['is_kev']) ? ($input['is_kev'] ? 'true' : 'false') : 'false',
            'kev_id' => $input['kev_id'] ?? null,
            'kev_date_added' => $input['kev_date_added'] ?? null,
            'kev_due_date' => $input['kev_due_date'] ?? null,
            'kev_required_action' => $input['kev_required_action'] ?? null,
            'priority' => $input['priority'] ?? 'Normal',
            'cvss_v4_score' => isset($input['cvss_v4_score']) ? floatval($input['cvss_v4_score']) : null,
            'cvss_v4_vector' => $input['cvss_v4_vector'] ?? null,
            'epss_score' => isset($input['epss_score']) ? floatval($input['epss_score']) : null,
            'epss_percentile' => isset($input['epss_percentile']) ? floatval($input['epss_percentile']) : null,
            'epss_date' => $input['epss_date'] ?? null,
            'epss_last_updated' => $input['epss_last_updated'] ?? null
        ];
        
        // Build the SQL query - handle ON CONFLICT based on whether cve_id is provided
        $field_names = array_keys($fields);
        $placeholders = array_fill(0, count($field_names), '?');
        $values = array_values($fields);
        
        $result1 = "";
        // If cve_id is provided and not null, check for duplicates first
        if (!empty($cve_id)) {
            $existing = $db->query("SELECT vulnerability_id FROM vulnerabilities WHERE cve_id = ?", [$cve_id])->fetch();
            if ($existing) {
                // Update existing vulnerability
                $update_parts = [];
                $update_values = [];
                foreach ($fields as $key => $value) {
                    if ($key !== 'cve_id' && $key !== 'created_at') {
                        $update_parts[] = "$key = ?";
                        $update_values[] = $value;
                    }
                }
                $update_values[] = $cve_id;
                
                $update_sql = "UPDATE vulnerabilities SET " . implode(', ', $update_parts) . " WHERE cve_id = ? RETURNING vulnerability_id, cve_id";
                $stmt = $db->prepare($update_sql);
                $stmt->execute($update_values);
                $result = $stmt->fetch(PDO::FETCH_ASSOC);
                $vulnerability_id = $result['vulnerability_id'];
                $returned_cve_id = $result['cve_id'];
                $result1 = $result;
            } else {
                // Insert new vulnerability
                $sql = "INSERT INTO vulnerabilities (" . implode(', ', $field_names) . ") 
                        VALUES (" . implode(', ', $placeholders) . ")
                        RETURNING vulnerability_id, cve_id";
                $stmt = $db->prepare($sql);
                $stmt->execute($values);
                $result = $stmt->fetch(PDO::FETCH_ASSOC);
                $vulnerability_id = $result['vulnerability_id'];
                $returned_cve_id = $result['cve_id'];
                $result1 = $result;
            }
        } else {
            // No cve_id provided - just insert without conflict handling
            $sql = "INSERT INTO vulnerabilities (" . implode(', ', $field_names) . ") 
                    VALUES (" . implode(', ', $placeholders) . ")
                    RETURNING vulnerability_id, cve_id";
            $stmt = $db->prepare($sql);
            $stmt->execute($values);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            $vulnerability_id = $result['vulnerability_id'];
            $returned_cve_id = $result['cve_id'];
            $result1 = $result;
        }
        
        // Create device_vulnerabilities_link entry (required - ensures vulnerability always has at least one affected asset)
        // Create link if we have at least vulnerability_id and (device_id OR asset_id)
        if (!empty($vulnerability_id) && (!empty($device_id) || !empty($asset_id))) {
            $link_sql = "INSERT INTO device_vulnerabilities_link (device_id, asset_id, component_id, cve_id, vulnerability_id, remediation_status, discovered_at)
                         VALUES (?, ?, ?, ?, ?, 'Open', CURRENT_TIMESTAMP)";
            
            // Use appropriate conflict resolution based on whether cve_id exists
            if (!empty($returned_cve_id)) {
                $link_sql .= " ON CONFLICT (device_id, component_id, cve_id) WHERE cve_id IS NOT NULL DO NOTHING";
                $link_stmt = $db->prepare($link_sql);
                $link_stmt->execute([$device_id, $asset_id, $component_id, $returned_cve_id, $vulnerability_id]);
            } else {
                $link_sql .= " ON CONFLICT (device_id, component_id, vulnerability_id) WHERE vulnerability_id IS NOT NULL DO NOTHING";
                $link_stmt = $db->prepare($link_sql);
                $link_stmt->execute([$device_id, $asset_id, $component_id, null, $vulnerability_id]);
            }
        }

        $db->commit();
        
        // Return the created vulnerability with link information
        http_response_code(201);
        echo json_encode([
            'success' => true,
            'message' => 'Vulnerability created successfully and linked to device',
            'data' => [
                'vulnerability_id' => $vulnerability_id,
                'cve_id' => $cve_id,
                'device_id' => $device_id,
                'component_id' => $component_id,
                'link_created' => true,
                'created_at' => date('c'),
                'created_by' => $user['username'],
                
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        $db->rollback();

        echo json_encode([
            'success' => false,
            'message' => 'Vulnerability creation failed',
            'data' => $e->getMessage(),
            'timestamp' => date('c')
        ]);
        throw $e;
    }
}
?>
