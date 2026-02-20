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

require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../includes/unified-auth.php';

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

// Check if user has permission to read threats (read-only operations)
// Write operations will check permissions individually

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

try {
    switch ($action) {
        case 'list':
            handleListThreats();
            break;
        case 'create':
            handleCreateThreat();
            break;
        case 'update':
            handleUpdateThreat();
            break;
        case 'delete':
            handleDeleteThreat();
            break;
        case 'get':
            handleGetThreat();
            break;
        case 'cwe_list':
            handleCWEList();
            break;
        default:
            ob_clean();
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_ACTION',
                    'message' => 'Invalid action'
                ],
                'timestamp' => date('c')
            ]);
            exit;
    }
} catch (Exception $e) {
    error_log("Threat API Error: " . $e->getMessage());
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

function handleListThreats() {
    global $db, $unifiedAuth;
    
    // Check read permission
    $unifiedAuth->requirePermission('vulnerabilities', 'read');
    
    $page = intval($_GET['page'] ?? 1);
    $limit = intval($_GET['limit'] ?? 25);
    $offset = ($page - 1) * $limit;
    $search = $_GET['search'] ?? '';
    $threat_type = $_GET['threat_type'] ?? '';
    $cwe_id = $_GET['cwe_id'] ?? '';
    
    $whereConditions = [];
    $params = [];
    
    if (!empty($search)) {
        $whereConditions[] = "(t.threat_name ILIKE ? OR t.description ILIKE ?)";
        $params[] = "%$search%";
        $params[] = "%$search%";
    }
    
    if (!empty($threat_type)) {
        $whereConditions[] = "t.threat_type = ?";
        $params[] = $threat_type;
    }
    
    if (!empty($cwe_id)) {
        $whereConditions[] = "t.cwe_id = ?";
        $params[] = $cwe_id;
    }
    
    $whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';
    
    // Get total count
    $countSql = "SELECT COUNT(*) as total FROM threats t $whereClause";
    $countStmt = $db->prepare($countSql);
    $countStmt->execute($params);
    $total = $countStmt->fetch()['total'];
    
    // Get threats with CWE and CVE info
    $sql = "SELECT t.*, 
                   c.cwe_name, c.cwe_description, c.category as cwe_category,
                   v.cve_id, v.description as cve_description, v.severity as cve_severity
            FROM threats t
            LEFT JOIN cwe_reference c ON t.cwe_id = c.cwe_id
            LEFT JOIN vulnerabilities v ON t.cve_id = v.cve_id
            $whereClause
            ORDER BY t.created_at DESC
            LIMIT ? OFFSET ?";
    
    $params[] = $limit;
    $params[] = $offset;
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $threats = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => $threats,
        'total' => $total,
        'page' => $page,
        'limit' => $limit,
        'pages' => ceil($total / $limit),
        'timestamp' => date('c')
    ]);
    exit;
}

function handleCreateThreat() {
    global $db, $unifiedAuth, $user;
    
    // Check write permission
    $unifiedAuth->requirePermission('vulnerabilities', 'write');
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        ob_clean();
        http_response_code(405);
        echo json_encode(['success' => false, 'error' => 'Method not allowed']);
        exit;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    $threat_name = $input['threat_name'] ?? '';
    $threat_type = $input['threat_type'] ?? 'Custom';
    $description = $input['description'] ?? '';
    $severity = $input['severity'] ?? 'Medium';
    $cwe_id = $input['cwe_id'] ?? null;
    $cve_id = $input['cve_id'] ?? null;
    $created_by = $user['user_id'];
    
    // Validate required fields
    if (empty($threat_name)) {
        ob_clean();
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Threat name is required']);
        exit;
    }
    
    // Validate threat type
    $validTypes = ['CVE', 'Zero-Day', 'Novel', 'Configuration', 'CWE', 'Custom'];
    if (!in_array($threat_type, $validTypes)) {
        ob_clean();
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Invalid threat type']);
        exit;
    }
    
    // Validate CWE exists if provided
    if ($cwe_id) {
        $cweStmt = $db->prepare("SELECT cwe_id FROM cwe_reference WHERE cwe_id = ?");
        $cweStmt->execute([$cwe_id]);
        if (!$cweStmt->fetch()) {
            ob_clean();
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid CWE ID']);
            exit;
        }
    }
    
    // Validate CVE exists if provided
    if ($cve_id) {
        $cveStmt = $db->prepare("SELECT cve_id FROM vulnerabilities WHERE cve_id = ?");
        $cveStmt->execute([$cve_id]);
        if (!$cveStmt->fetch()) {
            ob_clean();
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid CVE ID']);
            exit;
        }
    }
    
    $sql = "INSERT INTO threats (threat_name, threat_type, description, severity, cwe_id, cve_id, created_by) 
            VALUES (?, ?, ?, ?, ?, ?, ?)";
    
    $stmt = $db->prepare($sql);
    $result = $stmt->execute([$threat_name, $threat_type, $description, $severity, $cwe_id, $cve_id, $created_by]);
    
    if ($result) {
        $threat_id = $db->lastInsertId();
        ob_clean();
        echo json_encode([
            'success' => true,
            'data' => [
                'threat_id' => $threat_id,
                'message' => 'Threat created successfully'
            ],
            'timestamp' => date('c')
        ]);
        exit;
    } else {
        ob_clean();
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'Failed to create threat']);
        exit;
    }
}

function handleUpdateThreat() {
    global $db, $unifiedAuth;
    
    // Check write permission
    $unifiedAuth->requirePermission('vulnerabilities', 'write');
    
    if ($_SERVER['REQUEST_METHOD'] !== 'PUT') {
        ob_clean();
        http_response_code(405);
        echo json_encode(['success' => false, 'error' => 'Method not allowed']);
        exit;
    }
    
    $threat_id = $_GET['id'] ?? '';
    if (empty($threat_id)) {
        echo json_encode(['success' => false, 'error' => 'Threat ID is required']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    $threat_name = $input['threat_name'] ?? '';
    $threat_type = $input['threat_type'] ?? '';
    $description = $input['description'] ?? '';
    $severity = $input['severity'] ?? '';
    $cwe_id = $input['cwe_id'] ?? null;
    $cve_id = $input['cve_id'] ?? null;
    
    // Build update query dynamically
    $updateFields = [];
    $params = [];
    
    if (!empty($threat_name)) {
        $updateFields[] = "threat_name = ?";
        $params[] = $threat_name;
    }
    
    if (!empty($threat_type)) {
        $validTypes = ['CVE', 'Zero-Day', 'Novel', 'Configuration', 'CWE', 'Custom'];
        if (in_array($threat_type, $validTypes)) {
            $updateFields[] = "threat_type = ?";
            $params[] = $threat_type;
        }
    }
    
    if (!empty($description)) {
        $updateFields[] = "description = ?";
        $params[] = $description;
    }
    
    if (!empty($severity)) {
        $updateFields[] = "severity = ?";
        $params[] = $severity;
    }
    
    if ($cwe_id !== null) {
        $updateFields[] = "cwe_id = ?";
        $params[] = $cwe_id;
    }
    
    if ($cve_id !== null) {
        $updateFields[] = "cve_id = ?";
        $params[] = $cve_id;
    }
    
    if (empty($updateFields)) {
        ob_clean();
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'No fields to update']);
        exit;
    }
    
    $updateFields[] = "updated_at = CURRENT_TIMESTAMP";
    $params[] = $threat_id;
    
    $sql = "UPDATE threats SET " . implode(', ', $updateFields) . " WHERE threat_id = ?";
    
    $stmt = $db->prepare($sql);
    $result = $stmt->execute($params);
    
    if ($result) {
        ob_clean();
        echo json_encode([
            'success' => true,
            'message' => 'Threat updated successfully',
            'timestamp' => date('c')
        ]);
        exit;
    } else {
        ob_clean();
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'Failed to update threat']);
        exit;
    }
}

function handleDeleteThreat() {
    global $db, $unifiedAuth;
    
    // Check write permission
    $unifiedAuth->requirePermission('vulnerabilities', 'write');
    
    if ($_SERVER['REQUEST_METHOD'] !== 'DELETE') {
        ob_clean();
        http_response_code(405);
        echo json_encode(['success' => false, 'error' => 'Method not allowed']);
        exit;
    }
    
    $threat_id = $_GET['id'] ?? '';
    if (empty($threat_id)) {
        ob_clean();
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Threat ID is required']);
        exit;
    }
    
    $sql = "DELETE FROM threats WHERE threat_id = ?";
    $stmt = $db->prepare($sql);
    $result = $stmt->execute([$threat_id]);
    
    if ($result) {
        ob_clean();
        echo json_encode([
            'success' => true,
            'message' => 'Threat deleted successfully',
            'timestamp' => date('c')
        ]);
        exit;
    } else {
        ob_clean();
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'Failed to delete threat']);
        exit;
    }
}

function handleGetThreat() {
    global $db, $unifiedAuth;
    
    // Check read permission
    $unifiedAuth->requirePermission('vulnerabilities', 'read');
    
    $threat_id = $_GET['id'] ?? '';
    if (empty($threat_id)) {
        ob_clean();
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Threat ID is required']);
        exit;
    }
    
    $sql = "SELECT t.*, 
                   c.cwe_name, c.cwe_description, c.category as cwe_category,
                   v.cve_id, v.description as cve_description, v.severity as cve_severity
            FROM threats t
            LEFT JOIN cwe_reference c ON t.cwe_id = c.cwe_id
            LEFT JOIN vulnerabilities v ON t.cve_id = v.cve_id
            WHERE t.threat_id = ?";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([$threat_id]);
    $threat = $stmt->fetch(PDO::FETCH_ASSOC);
    
    ob_clean();
    if ($threat) {
        echo json_encode([
            'success' => true,
            'data' => $threat,
            'timestamp' => date('c')
        ]);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'Threat not found']);
    }
    exit;
}

function handleCWEList() {
    global $db, $unifiedAuth;
    
    // Check read permission
    $unifiedAuth->requirePermission('vulnerabilities', 'read');
    
    $search = $_GET['search'] ?? '';
    $category = $_GET['category'] ?? '';
    $limit = intval($_GET['limit'] ?? 100);
    
    $whereConditions = [];
    $params = [];
    
    if (!empty($search)) {
        $whereConditions[] = "(cwe_id ILIKE ? OR cwe_name ILIKE ? OR cwe_description ILIKE ?)";
        $params[] = "%$search%";
        $params[] = "%$search%";
        $params[] = "%$search%";
    }
    
    if (!empty($category)) {
        $whereConditions[] = "category = ?";
        $params[] = $category;
    }
    
    $whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';
    
    $sql = "SELECT cwe_id, cwe_name, cwe_description, category 
            FROM cwe_reference 
            $whereClause
            ORDER BY cwe_id
            LIMIT ?";
    
    $params[] = $limit;
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $cwe_list = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => $cwe_list,
        'timestamp' => date('c')
    ]);
    exit;
}
?>
