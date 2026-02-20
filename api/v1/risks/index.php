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
            // List all risks
            listRisks();
        } else {
            // Get specific risk
            getRisk($path);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function listRisks() {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to read risks
    $unifiedAuth->requirePermission('risks', 'read');
    
    // Get query parameters
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = min(100, max(1, intval($_GET['limit'] ?? 25)));
    $search = $_GET['search'] ?? '';
    $asset_id = $_GET['asset_id'] ?? '';
    $site = $_GET['site'] ?? '';
    $risk_score_level = $_GET['risk_score_level'] ?? '';
    $device_class = $_GET['device_class'] ?? '';
    $status = $_GET['status'] ?? '';
    $exploited = $_GET['exploited'] ?? '';
    $sort = $_GET['sort'] ?? 'risk_score';
    $sort_dir = $_GET['sort_dir'] ?? 'desc';
    
    $offset = ($page - 1) * $limit;
    
    // Build query
    $where_conditions = [];
    $params = [];
    
    if (!empty($search)) {
        $where_conditions[] = "(r.name ILIKE :search OR r.risk_id ILIKE :search OR r.description ILIKE :search OR r.display_name ILIKE :search)";
        $params[':search'] = "%$search%";
    }
    
    if (!empty($asset_id)) {
        $where_conditions[] = "r.asset_id = :asset_id";
        $params[':asset_id'] = $asset_id;
    }
    
    if (!empty($site)) {
        $where_conditions[] = "r.site = :site";
        $params[':site'] = $site;
    }
    
    if (!empty($risk_score_level)) {
        $where_conditions[] = "r.risk_score_level = :risk_score_level";
        $params[':risk_score_level'] = $risk_score_level;
    }
    
    if (!empty($device_class)) {
        $where_conditions[] = "r.device_class = :device_class";
        $params[':device_class'] = $device_class;
    }
    
    if (!empty($status)) {
        $where_conditions[] = "r.status_display_name = :status";
        $params[':status'] = $status;
    }
    
    if (!empty($exploited) && in_array(strtolower($exploited), ['true', 'false', '1', '0'])) {
        $exploited_bool = in_array(strtolower($exploited), ['true', '1']) ? 'true' : 'false';
        $where_conditions[] = "r.tags_exploited_in_the_wild = :exploited";
        $params[':exploited'] = $exploited_bool;
    }
    
    $where_clause = empty($where_conditions) ? '1=1' : implode(' AND ', $where_conditions);
    
    // Build order clause
    $valid_sorts = [
        'risk_score' => 'r.risk_score',
        'cvss' => 'r.cvss',
        'epss' => 'r.epss',
        'created_at' => 'r.created_at',
        'nhs_published_date' => 'r.nhs_published_date',
        'name' => 'r.name'
    ];
    
    $valid_dirs = ['asc', 'desc'];
    $dir = in_array(strtolower($sort_dir), $valid_dirs) ? strtoupper($sort_dir) : 'DESC';
    $order_clause = isset($valid_sorts[$sort]) ? $valid_sorts[$sort] . ' ' . $dir : 'r.risk_score DESC';
    
    // Get total count
    $count_sql = "SELECT COUNT(*) as total FROM risks r WHERE $where_clause";
    $count_stmt = $db->prepare($count_sql);
    $count_stmt->execute($params);
    $total = $count_stmt->fetch()['total'];
    
    // Get risks
    $sql = "SELECT 
        r.id,
        r.asset_id,
        r.device_class,
        r.type,
        r.type_display_name,
        r.display_name,
        r.risk_id,
        r.risk_type_display_name,
        r.risk_group,
        r.name,
        r.risk_score,
        r.risk_score_level,
        r.cvss,
        r.epss,
        r.availability_score,
        r.confidentiality_score,
        r.integrity_score,
        r.impact_confidentiality,
        r.impact_patient_safety,
        r.impact_service_disruption,
        r.nhs_published_date,
        r.nhs_severity,
        r.nhs_threat_id,
        r.description,
        r.status_display_name,
        r.category,
        r.has_malware,
        r.tags_easy_to_weaponize,
        r.tags_exploit_code_maturity,
        r.tags_exploited_in_the_wild,
        r.tags_lateral_movement,
        r.tags_malware,
        r.site,
        r.link,
        r.external_id,
        r.created_at,
        r.updated_at
        FROM risks r
        WHERE $where_clause
        ORDER BY $order_clause
        LIMIT :limit OFFSET :offset";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    
    $stmt->execute();
    $risks = $stmt->fetchAll();
    
    // Parse JSON fields
    foreach ($risks as &$risk) {
        if (!empty($risk['tags_malware'])) {
            $risk['tags_malware'] = json_decode($risk['tags_malware'], true);
        }
        if (!empty($risk['link'])) {
            $risk['link'] = json_decode($risk['link'], true);
        }
    }
    
    echo json_encode([
        'success' => true,
        'data' => $risks,
        'pagination' => [
            'page' => $page,
            'limit' => $limit,
            'total' => $total,
            'pages' => ceil($total / $limit)
        ],
        'timestamp' => date('c')
    ]);
}

function getRisk($id) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to read risks
    $unifiedAuth->requirePermission('risks', 'read');
    
    $sql = "SELECT 
        r.id,
        r.asset_id,
        r.device_class,
        r.type,
        r.type_display_name,
        r.display_name,
        r.risk_id,
        r.risk_type_display_name,
        r.risk_group,
        r.name,
        r.risk_score,
        r.risk_score_level,
        r.cvss,
        r.epss,
        r.availability_score,
        r.confidentiality_score,
        r.integrity_score,
        r.impact_confidentiality,
        r.impact_patient_safety,
        r.impact_service_disruption,
        r.nhs_published_date,
        r.nhs_severity,
        r.nhs_threat_id,
        r.description,
        r.status_display_name,
        r.category,
        r.has_malware,
        r.tags_easy_to_weaponize,
        r.tags_exploit_code_maturity,
        r.tags_exploited_in_the_wild,
        r.tags_lateral_movement,
        r.tags_malware,
        r.site,
        r.link,
        r.external_id,
        r.created_at,
        r.updated_at
        FROM risks r
        WHERE r.id = :id";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':id', $id);
    $stmt->execute();
    $risk = $stmt->fetch();
    
    if (!$risk) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'RISK_NOT_FOUND',
                'message' => 'Risk not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Parse JSON fields
    if (!empty($risk['tags_malware'])) {
        $risk['tags_malware'] = json_decode($risk['tags_malware'], true);
    }
    if (!empty($risk['link'])) {
        $risk['link'] = json_decode($risk['link'], true);
    }
    
    echo json_encode([
        'success' => true,
        'data' => $risk,
        'timestamp' => date('c')
    ]);
}

function handlePostRequest($path) {
    global $db, $user;
    
    try {
        // Create new risk
        createRisk();
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function createRisk() {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to write risks
    $unifiedAuth->requirePermission('risks', 'write');
    
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
    $required_fields = ['asset_id', 'risk_id', 'name'];
    foreach ($required_fields as $field) {
        if (empty($input[$field])) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_FIELD',
                    'message' => "Field '$field' is required"
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    // Validate asset_id exists
    $asset_check = $db->prepare("SELECT asset_id FROM assets WHERE asset_id = :asset_id");
    $asset_check->bindValue(':asset_id', $input['asset_id']);
    $asset_check->execute();
    if (!$asset_check->fetch()) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_ASSET_ID',
                'message' => 'Asset ID does not exist'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Check if external_id already exists (if provided)
    if (!empty($input['external_id'])) {
        $check_sql = "SELECT id, risk_id FROM risks WHERE external_id = :external_id";
        $check_stmt = $db->prepare($check_sql);
        $check_stmt->bindValue(':external_id', $input['external_id']);
        $check_stmt->execute();
        
        if ($existing = $check_stmt->fetch()) {
            http_response_code(409);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'RISK_EXISTS',
                    'message' => 'Risk with this external_id already exists',
                    'existing_risk_id' => $existing['risk_id'],
                    'existing_uuid' => $existing['id']
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    // Check if risk_id already exists (for non-external risks)
    $check_sql = "SELECT id FROM risks WHERE risk_id = :risk_id";
    $check_stmt = $db->prepare($check_sql);
    $check_stmt->bindValue(':risk_id', $input['risk_id']);
    $check_stmt->execute();
    
    if ($existing = $check_stmt->fetch()) {
        http_response_code(409);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'RISK_ID_EXISTS',
                'message' => 'Risk with this risk_id already exists',
                'existing_uuid' => $existing['id']
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Prepare fields for insertion
    $fields = [
        'asset_id', 'device_class', 'type', 'type_display_name', 'display_name',
        'risk_id', 'risk_type_display_name', 'risk_group', 'name',
        'risk_score', 'risk_score_level', 'cvss', 'epss',
        'availability_score', 'confidentiality_score', 'integrity_score',
        'impact_confidentiality', 'impact_patient_safety', 'impact_service_disruption',
        'nhs_published_date', 'nhs_severity', 'nhs_threat_id',
        'description', 'status_display_name', 'category',
        'has_malware', 'tags_easy_to_weaponize', 'tags_exploit_code_maturity',
        'tags_exploited_in_the_wild', 'tags_lateral_movement', 'tags_malware',
        'site', 'link', 'external_id'
    ];
    
    $insert_fields = [];
    $insert_values = [];
    $params = [];
    
    foreach ($fields as $field) {
        if (isset($input[$field])) {
            $insert_fields[] = $field;
            $insert_values[] = ":$field";
            
            // Handle JSON fields
            if (in_array($field, ['tags_malware', 'link'])) {
                $params[":$field"] = is_array($input[$field]) || is_object($input[$field]) 
                    ? json_encode($input[$field]) 
                    : $input[$field];
            }
            // Handle boolean fields
            elseif (in_array($field, ['has_malware', 'tags_easy_to_weaponize', 'tags_exploited_in_the_wild', 'tags_lateral_movement'])) {
                $params[":$field"] = filter_var($input[$field], FILTER_VALIDATE_BOOLEAN) ? 'true' : 'false';
            }
            // Handle numeric fields
            elseif (in_array($field, ['risk_score', 'cvss', 'epss'])) {
                $params[":$field"] = !empty($input[$field]) ? floatval($input[$field]) : null;
            }
            else {
                $params[":$field"] = $input[$field];
            }
        }
    }
    
    $sql = "INSERT INTO risks (" . implode(', ', $insert_fields) . ") 
            VALUES (" . implode(', ', $insert_values) . ")";
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    
    echo json_encode([
        'success' => true,
        'data' => [
            'risk_id' => $input['risk_id'],
            'message' => 'Risk created successfully'
        ],
        'timestamp' => date('c')
    ]);
}

function handlePutRequest($path) {
    global $db, $user;
    
    try {
        if (empty($path)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_RISK_ID',
                    'message' => 'Risk ID is required'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        updateRisk($path);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function updateRisk($id) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to update risks
    $unifiedAuth->requirePermission('risks', 'write');
    
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
    
    // Check if risk exists
    $check_sql = "SELECT id FROM risks WHERE id = :id";
    $check_stmt = $db->prepare($check_sql);
    $check_stmt->bindValue(':id', $id);
    $check_stmt->execute();
    
    if (!$check_stmt->fetch()) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'RISK_NOT_FOUND',
                'message' => 'Risk not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Build update query
    $update_fields = [];
    $params = [':id' => $id];
    
    $allowed_fields = [
        'device_class', 'type', 'type_display_name', 'display_name',
        'risk_type_display_name', 'risk_group', 'name',
        'risk_score', 'risk_score_level', 'cvss', 'epss',
        'availability_score', 'confidentiality_score', 'integrity_score',
        'impact_confidentiality', 'impact_patient_safety', 'impact_service_disruption',
        'nhs_published_date', 'nhs_severity', 'nhs_threat_id',
        'description', 'status_display_name', 'category',
        'has_malware', 'tags_easy_to_weaponize', 'tags_exploit_code_maturity',
        'tags_exploited_in_the_wild', 'tags_lateral_movement', 'tags_malware',
        'site', 'link', 'external_id'
    ];
    
    foreach ($allowed_fields as $field) {
        if (array_key_exists($field, $input)) {
            $update_fields[] = "$field = :$field";
            
            // Handle JSON fields
            if (in_array($field, ['tags_malware', 'link'])) {
                $params[":$field"] = is_array($input[$field]) || is_object($input[$field]) 
                    ? json_encode($input[$field]) 
                    : $input[$field];
            }
            // Handle boolean fields
            elseif (in_array($field, ['has_malware', 'tags_easy_to_weaponize', 'tags_exploited_in_the_wild', 'tags_lateral_movement'])) {
                $params[":$field"] = filter_var($input[$field], FILTER_VALIDATE_BOOLEAN) ? 'true' : 'false';
            }
            // Handle numeric fields
            elseif (in_array($field, ['risk_score', 'cvss', 'epss'])) {
                $params[":$field"] = !empty($input[$field]) ? floatval($input[$field]) : null;
            }
            else {
                $params[":$field"] = $input[$field];
            }
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
    
    $sql = "UPDATE risks SET " . implode(', ', $update_fields) . " WHERE id = :id";
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    
    echo json_encode([
        'success' => true,
        'data' => [
            'id' => $id,
            'message' => 'Risk updated successfully'
        ],
        'timestamp' => date('c')
    ]);
}

function handleDeleteRequest($path) {
    global $db, $user;
    
    try {
        if (empty($path)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_RISK_ID',
                    'message' => 'Risk ID is required'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        deleteRisk($path);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function deleteRisk($id) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to delete risks
    $unifiedAuth->requirePermission('risks', 'delete');
    
    // Hard delete - remove from database
    $sql = "DELETE FROM risks WHERE id = :id";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':id', $id);
    $stmt->execute();
    
    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'RISK_NOT_FOUND',
                'message' => 'Risk not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'data' => [
            'id' => $id,
            'message' => 'Risk deleted successfully'
        ],
        'timestamp' => date('c')
    ]);
}
?>
