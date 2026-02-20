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

// Check if user has permission to read recalls
$unifiedAuth->requirePermission('recalls', 'read');

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
            // List all recalls
            listRecalls();
        } else {
            // Get specific recall
            getRecall($path);
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

function listRecalls() {
    global $db, $user;
    
    // Get query parameters
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = min(100, max(1, intval($_GET['limit'] ?? 25)));
    $search = $_GET['search'] ?? '';
    $status = $_GET['status'] ?? '';
    $date_from = $_GET['date_from'] ?? '';
    $date_to = $_GET['date_to'] ?? '';
    $manufacturer = $_GET['manufacturer'] ?? '';
    
    $offset = ($page - 1) * $limit;
    
    // Build query
    $where_conditions = [];
    $params = [];
    
    if (!empty($search)) {
        $where_conditions[] = "(r.recall_number ILIKE :search OR r.product_name ILIKE :search OR r.manufacturer ILIKE :search)";
        $params[':search'] = "%$search%";
    }
    
    if (!empty($status)) {
        $where_conditions[] = "r.recall_status = :status";
        $params[':status'] = $status;
    }
    
    if (!empty($date_from)) {
        $where_conditions[] = "r.recall_date >= :date_from";
        $params[':date_from'] = $date_from;
    }
    
    if (!empty($date_to)) {
        $where_conditions[] = "r.recall_date <= :date_to";
        $params[':date_to'] = $date_to;
    }
    
    if (!empty($manufacturer)) {
        $where_conditions[] = "r.manufacturer ILIKE :manufacturer";
        $params[':manufacturer'] = "%$manufacturer%";
    }
    
    $where_clause = empty($where_conditions) ? '1=1' : implode(' AND ', $where_conditions);
    
    // Get total count
    $count_sql = "SELECT COUNT(*) as total FROM recalls r WHERE $where_clause";
    $count_stmt = $db->prepare($count_sql);
    $count_stmt->execute($params);
    $total = $count_stmt->fetch()['total'];
    
    // Get recalls
    $sql = "SELECT 
        r.recall_id,
        r.recall_number,
        r.product_name,
        r.manufacturer,
        r.recall_date,
        r.recall_status,
        r.reason_for_recall,
        r.recall_classification,
        r.affected_products,
        r.contact_information,
        r.created_at,
        r.updated_at,
        COUNT(drl.device_id) as affected_devices
        FROM recalls r
        LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
        WHERE $where_clause
        GROUP BY r.recall_id, r.recall_number, r.product_name, r.manufacturer, 
                 r.recall_date, r.recall_status, r.reason_for_recall, 
                 r.recall_classification, r.affected_products, r.contact_information,
                 r.created_at, r.updated_at
        ORDER BY r.recall_date DESC
        LIMIT :limit OFFSET :offset";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    
    $stmt->execute();
    $recalls = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $recalls,
        'pagination' => [
            'page' => $page,
            'limit' => $limit,
            'total' => $total,
            'pages' => ceil($total / $limit)
        ],
        'timestamp' => date('c')
    ]);
}

function getRecall($recall_id) {
    global $db, $user;
    
    $sql = "SELECT 
        r.recall_id,
        r.recall_number,
        r.product_name,
        r.manufacturer,
        r.recall_date,
        r.recall_status,
        r.reason_for_recall,
        r.recall_classification,
        r.affected_products,
        r.contact_information,
        r.created_at,
        r.updated_at
        FROM recalls r
        WHERE r.recall_id = :recall_id";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':recall_id', $recall_id);
    $stmt->execute();
    $recall = $stmt->fetch();
    
    if (!$recall) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'RECALL_NOT_FOUND',
                'message' => 'Recall not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Get affected devices
    $devices_sql = "SELECT 
        a.asset_id,
        a.hostname,
        a.ip_address,
        a.asset_type,
        a.department,
        a.location,
        drl.alert_sent,
        drl.remediation_status,
        drl.remediation_notes,
        drl.alert_date
        FROM device_recalls_link drl
        JOIN assets a ON drl.asset_id = a.asset_id
        WHERE drl.recall_id = :recall_id";
    
    $devices_stmt = $db->prepare($devices_sql);
    $devices_stmt->bindValue(':recall_id', $recall_id);
    $devices_stmt->execute();
    $affected_devices = $devices_stmt->fetchAll();
    
    $recall['affected_devices'] = $affected_devices;
    
    echo json_encode([
        'success' => true,
        'data' => $recall,
        'timestamp' => date('c')
    ]);
}

function handlePostRequest($path) {
    global $db, $user;
    
    try {
        if ($path === 'check') {
            // Check for new recalls
            checkRecalls();
        } else {
            // Create new recall
            createRecall();
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

function checkRecalls() {
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
    
    $device_ids = $input['device_ids'] ?? [];
    $date_range = $input['date_range'] ?? [];
    
    if (empty($device_ids)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'MISSING_DEVICE_IDS',
                'message' => 'Device IDs are required'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Check for actual recalls in the database
    try {
        $sql = "SELECT 
                    COUNT(*) as total_devices,
                    COUNT(CASE WHEN r.recall_id IS NOT NULL THEN 1 END) as devices_with_recalls,
                    COUNT(CASE WHEN r.status = 'Active' THEN 1 END) as active_recalls
                FROM medical_devices md
                LEFT JOIN device_recalls dr ON md.device_id = dr.device_id
                LEFT JOIN recalls r ON dr.recall_id = r.recall_id
                WHERE md.device_id = ANY(?)";
        
        $stmt = $db->getConnection()->prepare($sql);
        $stmt->execute([$device_ids]);
        $result = $stmt->fetch();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'checked_devices' => $result['total_devices'],
                'devices_with_recalls' => $result['devices_with_recalls'],
                'active_recalls' => $result['active_recalls'],
                'message' => 'Recall check completed using real data'
            ],
            'timestamp' => date('c')
        ]);
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'RECALL_CHECK_ERROR',
                'message' => 'Failed to check recalls: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function createRecall() {
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
    
    // Validate required fields
    $required_fields = ['recall_number', 'product_name', 'manufacturer', 'recall_date'];
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
    
    // Insert recall
    $sql = "INSERT INTO recalls (
        recall_number, product_name, manufacturer, recall_date, 
        recall_status, reason_for_recall, recall_classification, 
        affected_products, contact_information, created_at, updated_at
    ) VALUES (
        :recall_number, :product_name, :manufacturer, :recall_date,
        :recall_status, :reason_for_recall, :recall_classification,
        :affected_products, :contact_information, :created_at, :updated_at
    ) RETURNING recall_id";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':recall_number', $input['recall_number']);
    $stmt->bindValue(':product_name', $input['product_name']);
    $stmt->bindValue(':manufacturer', $input['manufacturer']);
    $stmt->bindValue(':recall_date', $input['recall_date']);
    $stmt->bindValue(':recall_status', $input['recall_status'] ?? 'Active');
    $stmt->bindValue(':reason_for_recall', $input['reason_for_recall'] ?? '');
    $stmt->bindValue(':recall_classification', $input['recall_classification'] ?? 'Class II');
    $stmt->bindValue(':affected_products', $input['affected_products'] ?? '');
    $stmt->bindValue(':contact_information', $input['contact_information'] ?? '');
    $stmt->bindValue(':created_at', date('Y-m-d H:i:s'));
    $stmt->bindValue(':updated_at', date('Y-m-d H:i:s'));
    
    $stmt->execute();
    $recall_id = $stmt->fetch()['recall_id'];
    
    echo json_encode([
        'success' => true,
        'data' => [
            'recall_id' => $recall_id,
            'message' => 'Recall created successfully'
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
                    'code' => 'MISSING_RECALL_ID',
                    'message' => 'Recall ID is required'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        updateRecall($path);
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

function updateRecall($recall_id) {
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
    
    // Build update query
    $update_fields = [];
    $params = [':recall_id' => $recall_id];
    
    $allowed_fields = [
        'recall_number', 'product_name', 'manufacturer', 'recall_date',
        'recall_status', 'reason_for_recall', 'recall_classification',
        'affected_products', 'contact_information'
    ];
    
    foreach ($allowed_fields as $field) {
        if (isset($input[$field])) {
            $update_fields[] = "$field = :$field";
            $params[":$field"] = $input[$field];
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
    
    $update_fields[] = "updated_at = :updated_at";
    $params[':updated_at'] = date('Y-m-d H:i:s');
    
    $sql = "UPDATE recalls SET " . implode(', ', $update_fields) . " WHERE recall_id = :recall_id";
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    
    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'RECALL_NOT_FOUND',
                'message' => 'Recall not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'data' => [
            'recall_id' => $recall_id,
            'message' => 'Recall updated successfully'
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
                    'code' => 'MISSING_RECALL_ID',
                    'message' => 'Recall ID is required'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        deleteRecall($path);
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

function deleteRecall($recall_id) {
    global $db, $user;
    
    // Delete recall and related links
    $db->beginTransaction();
    
    try {
        // Delete device recall links
        $links_sql = "DELETE FROM device_recalls_link WHERE recall_id = :recall_id";
        $links_stmt = $db->prepare($links_sql);
        $links_stmt->bindValue(':recall_id', $recall_id);
        $links_stmt->execute();
        
        // Delete recall
        $recall_sql = "DELETE FROM recalls WHERE recall_id = :recall_id";
        $recall_stmt = $db->prepare($recall_sql);
        $recall_stmt->bindValue(':recall_id', $recall_id);
        $recall_stmt->execute();
        
        if ($recall_stmt->rowCount() === 0) {
            $db->rollback();
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'RECALL_NOT_FOUND',
                    'message' => 'Recall not found'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        $db->commit();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'recall_id' => $recall_id,
                'message' => 'Recall deleted successfully'
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        $db->rollback();
        throw $e;
    }
}
?>
