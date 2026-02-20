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

// Check if user has permission to read risk priorities
$unifiedAuth->requirePermission('vulnerabilities', 'read');

$method = $_SERVER['REQUEST_METHOD'];
$path = $_SERVER['PATH_INFO'] ?? '/';

try {
    $db = DatabaseConfig::getInstance()->getConnection();
    
    // Route requests
    if ($method === 'GET' && $path === '/') {
        handleGetPriorities($db, $user);
    } elseif ($method === 'GET' && $path === '/stats') {
        handleGetStats($db, $user);
    } elseif ($method === 'GET' && preg_match('/^\/([a-f0-9-]+)$/', $path, $matches)) {
        handleGetPriority($db, $matches[1], $user);
    } elseif ($method === 'PUT' && preg_match('/^\/([a-f0-9-]+)$/', $path, $matches)) {
        handleUpdatePriority($db, $matches[1], $user);
    } elseif ($method === 'POST' && preg_match('/^\/([a-f0-9-]+)\/vendor$/', $path, $matches)) {
        handleUpdateVendor($db, $matches[1], $user);
    } elseif ($method === 'POST' && preg_match('/^\/([a-f0-9-]+)\/controls$/', $path, $matches)) {
        handleAddControl($db, $matches[1], $user);
    } elseif ($method === 'GET' && preg_match('/^\/([a-f0-9-]+)\/controls$/', $path, $matches)) {
        handleGetControls($db, $matches[1], $user);
    } elseif ($method === 'DELETE' && preg_match('/^\/controls\/([a-f0-9-]+)$/', $path, $matches)) {
        handleDeleteControl($db, $matches[1], $user);
    } elseif ($method === 'POST' && $path === '/refresh') {
        handleRefresh($db, $user);
    } else {
        ob_clean();
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => 'Endpoint not found',
            'timestamp' => date('c')
        ]);
        exit;
    }
    
} catch (Exception $e) {
    error_log("Risk Priorities API Error: " . $e->getMessage());
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
 * Handle GET /api/v1/risk-priorities - List prioritized vulnerabilities
 */
function handleGetPriorities($db, $user) {
    $filters = [
        'tier' => $_GET['tier'] ?? null,
        'assigned_to' => $_GET['assigned_to'] ?? null,
        'overdue_only' => $_GET['overdue_only'] ?? 'false',
        'location_id' => $_GET['location_id'] ?? null,
        'department' => $_GET['department'] ?? null,
        'vendor_status' => $_GET['vendor_status'] ?? null,
        'my_assignments' => $_GET['my_assignments'] ?? 'false',
        'limit' => min((int)($_GET['limit'] ?? 100), 1000),
        'offset' => max((int)($_GET['offset'] ?? 0), 0)
    ];
    
    $conditions = [];
    $params = [];
    
    if ($filters['tier']) {
        $conditions[] = "priority_tier = ?";
        $params[] = $filters['tier'];
    }
    
    if ($filters['assigned_to']) {
        $conditions[] = "assigned_to = ?";
        $params[] = $filters['assigned_to'];
    }
    
    if ($filters['my_assignments'] === 'true') {
        $conditions[] = "assigned_to = ?";
        $params[] = $user['user_id'];
    }
    
    if ($filters['overdue_only'] === 'true') {
        $conditions[] = "days_overdue > 0";
    }
    
    if ($filters['location_id']) {
        $conditions[] = "location_id = ?";
        $params[] = $filters['location_id'];
    }
    
    if ($filters['department']) {
        $conditions[] = "department = ?";
        $params[] = $filters['department'];
    }
    
    if ($filters['vendor_status']) {
        $conditions[] = "vendor_status = ?";
        $params[] = $filters['vendor_status'];
    }
    
    $where = !empty($conditions) ? 'WHERE ' . implode(' AND ', $conditions) : '';
    
    // Get total count
    $sql = "SELECT COUNT(*) as total FROM risk_priority_view $where";
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $total = $stmt->fetch()['total'];
    
    // Get paginated results
    $sql = "SELECT * FROM risk_priority_view 
            $where
            ORDER BY priority_tier ASC, calculated_risk_score DESC, days_overdue DESC NULLS LAST
            LIMIT ? OFFSET ?";
    $params[] = $filters['limit'];
    $params[] = $filters['offset'];
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $priorities = $stmt->fetchAll();
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => $priorities,
        'total' => $total,
        'limit' => $filters['limit'],
        'offset' => $filters['offset'],
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * Handle GET /api/v1/risk-priorities/stats - Dashboard statistics
 */
function handleGetStats($db, $user) {
    // Tier statistics
    $sql = "SELECT 
        priority_tier,
        COUNT(*) as total_count,
        COUNT(CASE WHEN days_overdue > 0 THEN 1 END) as overdue_count,
        COUNT(CASE WHEN assigned_to IS NOT NULL THEN 1 END) as assigned_count,
        COUNT(CASE WHEN assigned_to IS NULL THEN 1 END) as unassigned_count,
        AVG(calculated_risk_score) as avg_risk_score
    FROM risk_priority_view
    GROUP BY priority_tier
    ORDER BY priority_tier";
    
    $stmt = $db->query($sql);
    $tiers = $stmt->fetchAll();
    
    // Vendor status statistics
    $sql = "SELECT 
        vendor_status,
        COUNT(*) as count
    FROM risk_priority_view
    WHERE vendor_status IS NOT NULL
    GROUP BY vendor_status";
    
    $stmt = $db->query($sql);
    $vendorStats = $stmt->fetchAll();
    
    // Department statistics
    $sql = "SELECT 
        department,
        priority_tier,
        COUNT(*) as count
    FROM risk_priority_view
    WHERE department IS NOT NULL
    GROUP BY department, priority_tier
    ORDER BY priority_tier, count DESC";
    
    $stmt = $db->query($sql);
    $departmentStats = $stmt->fetchAll();
    
    // KEV statistics
    $sql = "SELECT 
        COUNT(*) as total_kevs,
        COUNT(CASE WHEN remediation_status = 'Open' THEN 1 END) as open_kevs,
        COUNT(CASE WHEN kev_due_date < CURRENT_DATE THEN 1 END) as overdue_kevs
    FROM risk_priority_view
    WHERE is_kev = TRUE";
    
    $stmt = $db->query($sql);
    $kevStats = $stmt->fetch();
    
    // Top 10 highest risk items
    $sql = "SELECT 
        link_id,
        cve_id,
        hostname,
        device_name,
        severity,
        is_kev,
        calculated_risk_score,
        priority_tier,
        days_overdue
    FROM risk_priority_view
    ORDER BY calculated_risk_score DESC, days_overdue DESC NULLS LAST
    LIMIT 10";
    
    $stmt = $db->query($sql);
    $topRisks = $stmt->fetchAll();
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => [
            'tiers' => $tiers,
            'vendor_stats' => $vendorStats,
            'department_stats' => $departmentStats,
            'kev_stats' => $kevStats,
            'top_risks' => $topRisks
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * Handle GET /api/v1/risk-priorities/{link_id} - Get specific priority
 */
function handleGetPriority($db, $linkId, $user) {
    $sql = "SELECT * FROM risk_priority_view WHERE link_id = ?";
    $stmt = $db->prepare($sql);
    $stmt->execute([$linkId]);
    $priority = $stmt->fetch();
    
    if (!$priority) {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'Priority not found']);
        return;
    }
    
    // Get additional details from device_vulnerabilities_link
    $sql = "SELECT 
        remediation_notes,
        compensating_controls,
        vendor_name,
        vendor_contact,
        vendor_ticket_id,
        patch_applied_date
    FROM device_vulnerabilities_link
    WHERE link_id = ?";
    $stmt = $db->prepare($sql);
    $stmt->execute([$linkId]);
    $details = $stmt->fetch();
    
    $priority = array_merge($priority, $details);
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => $priority,
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * Handle PUT /api/v1/risk-priorities/{link_id} - Update remediation details
 */
function handleUpdatePriority($db, $linkId, $user) {
    global $unifiedAuth;
    
    // Check write permission
    $unifiedAuth->requirePermission('vulnerabilities', 'write');
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    $fields = [];
    $params = [];
    
    if (isset($input['remediation_status'])) {
        $fields[] = "remediation_status = ?";
        $params[] = $input['remediation_status'];
    }
    
    if (isset($input['remediation_notes'])) {
        $fields[] = "remediation_notes = ?";
        $params[] = $input['remediation_notes'];
    }
    
    if (isset($input['assigned_to'])) {
        $fields[] = "assigned_to = ?";
        $params[] = $input['assigned_to'];
    }
    
    if (isset($input['due_date'])) {
        $fields[] = "due_date = ?";
        $params[] = $input['due_date'] ?: null;
    }
    
    if (isset($input['compensating_controls'])) {
        $fields[] = "compensating_controls = ?";
        $params[] = $input['compensating_controls'];
    }
    
    if (empty($fields)) {
        ob_clean();
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'No fields to update',
            'timestamp' => date('c')
        ]);
        exit;
    }
    
    $fields[] = "updated_at = CURRENT_TIMESTAMP";
    $params[] = $linkId;
    
    $sql = "UPDATE device_vulnerabilities_link 
            SET " . implode(', ', $fields) . "
            WHERE link_id = ?";
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    
    // Log the action
    logAudit($db, $user['user_id'], 'UPDATE', 'device_vulnerabilities_link', $linkId, 
             'Updated risk priority: ' . json_encode($input));
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'message' => 'Priority updated successfully',
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * Handle POST /api/v1/risk-priorities/{link_id}/vendor - Update vendor tracking
 */
function handleUpdateVendor($db, $linkId, $user) {
    global $unifiedAuth;
    
    // Check write permission
    $unifiedAuth->requirePermission('vulnerabilities', 'write');
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    $fields = [];
    $params = [];
    
    if (isset($input['vendor_name'])) {
        $fields[] = "vendor_name = ?";
        $params[] = $input['vendor_name'];
    }
    
    if (isset($input['vendor_contact'])) {
        $fields[] = "vendor_contact = ?";
        $params[] = $input['vendor_contact'];
    }
    
    if (isset($input['vendor_ticket_id'])) {
        $fields[] = "vendor_ticket_id = ?";
        $params[] = $input['vendor_ticket_id'];
    }
    
    if (isset($input['vendor_status'])) {
        $fields[] = "vendor_status = ?";
        $params[] = $input['vendor_status'];
    }
    
    if (isset($input['patch_expected_date'])) {
        $fields[] = "patch_expected_date = ?";
        $params[] = $input['patch_expected_date'] ?: null;
    }
    
    if (isset($input['patch_applied_date'])) {
        $fields[] = "patch_applied_date = ?";
        $params[] = $input['patch_applied_date'] ?: null;
    }
    
    if (empty($fields)) {
        ob_clean();
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'No fields to update',
            'timestamp' => date('c')
        ]);
        exit;
    }
    
    $fields[] = "updated_at = CURRENT_TIMESTAMP";
    $params[] = $linkId;
    
    $sql = "UPDATE device_vulnerabilities_link 
            SET " . implode(', ', $fields) . "
            WHERE link_id = ?";
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    
    // Log the action
    logAudit($db, $user['user_id'], 'UPDATE_VENDOR', 'device_vulnerabilities_link', $linkId,
             'Updated vendor tracking: ' . json_encode($input));
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'message' => 'Vendor tracking updated successfully',
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * Handle POST /api/v1/risk-priorities/{link_id}/controls - Add compensating control
 */
function handleAddControl($db, $linkId, $user) {
    global $unifiedAuth;
    
    // Check write permission
    $unifiedAuth->requirePermission('vulnerabilities', 'write');
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($input['control_type']) || !isset($input['control_description'])) {
        ob_clean();
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Missing required fields',
            'timestamp' => date('c')
        ]);
        exit;
    }
    
    $sql = "INSERT INTO compensating_controls_checklist 
            (link_id, control_type, control_description, is_implemented, implemented_date, verified_by, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([
        $linkId,
        $input['control_type'],
        $input['control_description'],
        $input['is_implemented'] ?? false,
        $input['implemented_date'] ?? null,
        $input['verified_by'] ?? null,
        $input['notes'] ?? null
    ]);
    
    $controlId = $db->lastInsertId();
    
    // Log the action
    logAudit($db, $user['user_id'], 'ADD_CONTROL', 'compensating_controls_checklist', $controlId,
             'Added compensating control for link ' . $linkId);
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'message' => 'Compensating control added successfully',
        'data' => ['control_id' => $controlId],
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * Handle GET /api/v1/risk-priorities/{link_id}/controls - Get compensating controls
 */
function handleGetControls($db, $linkId, $user) {
    $sql = "SELECT 
        c.*,
        u.username as verified_by_name
    FROM compensating_controls_checklist c
    LEFT JOIN users u ON c.verified_by = u.user_id
    WHERE c.link_id = ?
    ORDER BY c.created_at DESC";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([$linkId]);
    $controls = $stmt->fetchAll();
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => $controls,
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * Handle DELETE /api/v1/risk-priorities/controls/{control_id} - Delete control
 */
function handleDeleteControl($db, $controlId, $user) {
    global $unifiedAuth;
    
    // Check write permission
    $unifiedAuth->requirePermission('vulnerabilities', 'write');
    
    $sql = "DELETE FROM compensating_controls_checklist WHERE control_id = ?";
    $stmt = $db->prepare($sql);
    $stmt->execute([$controlId]);
    
    // Log the action
    logAudit($db, $user['user_id'], 'DELETE_CONTROL', 'compensating_controls_checklist', $controlId,
             'Deleted compensating control');
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'message' => 'Compensating control deleted successfully',
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * Handle POST /api/v1/risk-priorities/refresh - Refresh materialized view
 */
function handleRefresh($db, $user) {
    global $unifiedAuth;
    
    // Check write permission (admin-level operation)
    $unifiedAuth->requirePermission('system', 'write');
    
    $sql = "SELECT refresh_risk_priorities()";
    $stmt = $db->query($sql);
    
    // Log the action
    logAudit($db, $user['user_id'], 'REFRESH', 'risk_priority_view', null,
             'Manually refreshed risk priority view');
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'message' => 'Risk priority view refreshed successfully',
        'timestamp' => date('c')
    ]);
    exit;
}

/**
 * Log audit trail
 */
if (!function_exists('logAudit')) {
function logAudit($db, $userId, $action, $table, $recordId, $details) {
    $sql = "INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values, timestamp)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)";
    $stmt = $db->prepare($sql);
    $detailsJson = is_array($details) ? json_encode($details) : $details;
    $stmt->execute([$userId, $action, $table, $recordId, $detailsJson]);
}
}

