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

// Set JSON response headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
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
    exit();
}

// Get authenticated user
$user = $unifiedAuth->getCurrentUser();

try {
    $db = DatabaseConfig::getInstance();
    
    // Get the request method and path
    $method = $_SERVER['REQUEST_METHOD'];
    $path = $_GET['path'] ?? '';
    
    // Parse the path to get action and parameters
    $pathParts = explode('/', trim($path, '/'));
    $action = $pathParts[0] ?? '';
    $actionId = $pathParts[1] ?? null;
    $subAction = $pathParts[2] ?? null;
    
    // Route the request
    switch ($method) {
        case 'GET':
            switch ($action) {
                case '':
                case 'list':
                    // Check read permission
                    $unifiedAuth->requirePermission('remediation_actions', 'read');
                    handleGetActions($db, $unifiedAuth);
                    break;
                case 'statistics':
                    // Check read permission
                    $unifiedAuth->requirePermission('remediation_actions', 'read');
                    handleGetStatistics($db, $unifiedAuth);
                    break;
                case 'tier':
                    // Check read permission
                    $unifiedAuth->requirePermission('remediation_actions', 'read');
                    handleGetTierActions($db, $unifiedAuth, $actionId);
                    break;
                default:
                    if ($actionId) {
                        // Check read permission
                        $unifiedAuth->requirePermission('remediation_actions', 'read');
                        if ($subAction === 'devices') {
                            handleGetActionDevices($db, $unifiedAuth, $actionId);
                        } else {
                            handleGetActionDetails($db, $unifiedAuth, $actionId);
                        }
                    } else {
                        ob_clean();
                        http_response_code(404);
                        echo json_encode([
                            'success' => false,
                            'error' => 'Action not found',
                            'timestamp' => date('c')
                        ]);
                        exit();
                    }
                    break;
            }
            break;
            
        case 'POST':
            // Check write permission for all POST operations
            $unifiedAuth->requirePermission('remediation_actions', 'write');
            switch ($action) {
                case 'assign':
                    handleAssignAction($db, $unifiedAuth, $actionId);
                    break;
                case 'complete':
                    handleCompleteAction($db, $unifiedAuth, $actionId);
                    break;
                default:
                    ob_clean();
                    http_response_code(404);
                    echo json_encode([
                        'success' => false,
                        'error' => 'Action not found',
                        'timestamp' => date('c')
                    ]);
                    exit();
            }
            break;
            
        case 'PATCH':
            // Check write permission for PATCH operations
            $unifiedAuth->requirePermission('remediation_actions', 'write');
            if ($actionId && $subAction === 'devices' && isset($pathParts[3])) {
                handleUpdateDeviceStatus($db, $unifiedAuth, $actionId, $pathParts[3]);
            } else {
                ob_clean();
                http_response_code(404);
                echo json_encode([
                    'success' => false,
                    'error' => 'Action not found',
                    'timestamp' => date('c')
                ]);
                exit();
            }
            break;
            
        default:
            ob_clean();
            http_response_code(405);
            echo json_encode([
                'success' => false,
                'error' => 'Method not allowed',
                'timestamp' => date('c')
            ]);
            exit();
    }
    
} catch (Exception $e) {
    error_log("Remediation Actions API Error: " . $e->getMessage());
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
    exit();
}

/**
 * Get list of remediation actions with filters
 */
function handleGetActions($db, $unifiedAuth) {
    $filters = [
        'tier' => $_GET['tier'] ?? '',
        'status' => $_GET['status'] ?? '',
        'assigned_to' => $_GET['assigned_to'] ?? '',
        'action_type' => $_GET['action_type'] ?? '',
        'kev_only' => $_GET['kev_only'] ?? '',
        'urgency_min' => $_GET['urgency_min'] ?? '',
        'urgency_max' => $_GET['urgency_max'] ?? '',
        'efficiency_min' => $_GET['efficiency_min'] ?? '',
        'efficiency_max' => $_GET['efficiency_max'] ?? '',
        'limit' => (int)($_GET['limit'] ?? 25),
        'offset' => (int)($_GET['offset'] ?? 0)
    ];
    
    // Build WHERE clause
    $whereConditions = [];
    $params = [];
    
    if (!empty($filters['tier'])) {
        $whereConditions[] = "priority_tier = ?";
        $params[] = $filters['tier'];
    }
    
    if (!empty($filters['status'])) {
        $whereConditions[] = "status = ?";
        $params[] = $filters['status'];
    }
    
    if (!empty($filters['assigned_to'])) {
        if ($filters['assigned_to'] === 'unassigned') {
            $whereConditions[] = "assigned_to IS NULL";
        } else {
            $whereConditions[] = "assigned_to = ?";
            $params[] = $filters['assigned_to'];
        }
    }
    
    if (!empty($filters['action_type'])) {
        $whereConditions[] = "action_type = ?";
        $params[] = $filters['action_type'];
    }
    
    if (!empty($filters['kev_only']) && $filters['kev_only'] === 'true') {
        $whereConditions[] = "is_kev = TRUE";
    }
    
    if (!empty($filters['urgency_min'])) {
        $whereConditions[] = "urgency_score >= ?";
        $params[] = $filters['urgency_min'];
    }
    
    if (!empty($filters['urgency_max'])) {
        $whereConditions[] = "urgency_score <= ?";
        $params[] = $filters['urgency_max'];
    }
    
    if (!empty($filters['efficiency_min'])) {
        $whereConditions[] = "efficiency_score >= ?";
        $params[] = $filters['efficiency_min'];
    }
    
    if (!empty($filters['efficiency_max'])) {
        $whereConditions[] = "efficiency_score <= ?";
        $params[] = $filters['efficiency_max'];
    }
    
    $whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';
    
    // Get total count
    $countSql = "SELECT COUNT(*) as total FROM action_priority_view $whereClause";
    $countStmt = $db->getConnection()->prepare($countSql);
    $countStmt->execute($params);
    $totalCount = $countStmt->fetch()['total'];
    
    // Get actions
    $sql = "SELECT * FROM action_priority_view 
            $whereClause 
            ORDER BY priority_tier ASC, urgency_score DESC, efficiency_score DESC
            LIMIT ? OFFSET ?";
    
    $params[] = $filters['limit'];
    $params[] = $filters['offset'];
    
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute($params);
    $actions = $stmt->fetchAll();
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => $actions,
        'pagination' => [
            'total' => $totalCount,
            'limit' => $filters['limit'],
            'offset' => $filters['offset'],
            'pages' => ceil($totalCount / $filters['limit'])
        ],
        'timestamp' => date('c')
    ]);
    exit();
}

/**
 * Get action statistics
 */
function handleGetStatistics($db, $unifiedAuth) {
    $sql = "SELECT 
                priority_tier,
                COUNT(*) as count,
                ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM action_priority_view), 1) as percentage,
                MIN(urgency_score) as min_urgency,
                MAX(urgency_score) as max_urgency,
                ROUND(AVG(urgency_score), 1) as avg_urgency,
                MIN(efficiency_score) as min_efficiency,
                MAX(efficiency_score) as max_efficiency,
                ROUND(AVG(efficiency_score), 1) as avg_efficiency,
                COUNT(*) FILTER (WHERE is_kev = TRUE) as kev_count,
                COUNT(*) FILTER (WHERE is_kev = FALSE) as non_kev_count,
                SUM(affected_device_count) as total_devices,
                COUNT(*) FILTER (WHERE status = 'Completed') as completed_actions,
                COUNT(*) FILTER (WHERE status IN ('Pending', 'In Progress')) as pending_actions
            FROM action_priority_view
            GROUP BY priority_tier
            ORDER BY priority_tier";
    
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute();
    $statistics = $stmt->fetchAll();
    
    // Get overall statistics
    $overallSql = "SELECT 
                    COUNT(*) as total_actions,
                    SUM(affected_device_count) as total_devices,
                    COUNT(*) FILTER (WHERE status = 'Completed') as completed_actions,
                    COUNT(*) FILTER (WHERE status = 'Pending') as pending_actions,
                    COUNT(*) FILTER (WHERE status = 'In Progress') as in_progress_actions,
                    COUNT(*) FILTER (WHERE is_kev = TRUE) as kev_actions
                  FROM action_priority_view";
    
    $overallStmt = $db->getConnection()->prepare($overallSql);
    $overallStmt->execute();
    $overall = $overallStmt->fetch();
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => [
            'tiers' => $statistics,
            'overall' => $overall
        ],
        'timestamp' => date('c')
    ]);
    exit();
}

/**
 * Get actions for specific tier
 */
function handleGetTierActions($db, $unifiedAuth, $tier) {
    if (!in_array($tier, ['1', '2', '3', '4'])) {
        ob_clean();
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Invalid tier',
            'timestamp' => date('c')
        ]);
        exit();
    }
    
    $sql = "SELECT * FROM action_priority_view 
            WHERE priority_tier = ? 
            ORDER BY urgency_score DESC, efficiency_score DESC
            LIMIT 50";
    
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute([$tier]);
    $actions = $stmt->fetchAll();
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => $actions,
        'timestamp' => date('c')
    ]);
    exit();
}

/**
 * Get single action details
 */
function handleGetActionDetails($db, $unifiedAuth, $actionId) {
    $sql = "SELECT * FROM action_priority_view WHERE action_id = ?";
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute([$actionId]);
    $action = $stmt->fetch();
    
    ob_clean();
    if (!$action) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => 'Action not found',
            'timestamp' => date('c')
        ]);
        exit();
    }
    
    echo json_encode([
        'success' => true,
        'data' => $action,
        'timestamp' => date('c')
    ]);
    exit();
}

/**
 * Get devices affected by an action
 */
function handleGetActionDevices($db, $unifiedAuth, $actionId) {
    $sql = "SELECT 
                adl.*,
                rpv.asset_name,
                rpv.location_name,
                rpv.asset_criticality,
                rpv.location_criticality,
                rpv.severity,
                rpv.is_kev
            FROM action_device_links adl
            LEFT JOIN risk_priority_view rpv ON adl.device_id = rpv.link_id
            WHERE adl.action_id = ?
            ORDER BY adl.device_risk_score DESC";
    
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute([$actionId]);
    $devices = $stmt->fetchAll();
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'data' => $devices,
        'timestamp' => date('c')
    ]);
    exit();
}

/**
 * Assign action to user
 */
function handleAssignAction($db, $unifiedAuth, $actionId) {
    global $user;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($input['assigned_to']) || !isset($input['due_date'])) {
        ob_clean();
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Missing required fields',
            'timestamp' => date('c')
        ]);
        exit();
    }
    
    $sql = "UPDATE remediation_actions 
            SET assigned_to = ?, due_date = ?, updated_at = CURRENT_TIMESTAMP
            WHERE action_id = ?";
    
    $stmt = $db->getConnection()->prepare($sql);
    $result = $stmt->execute([$input['assigned_to'], $input['due_date'], $actionId]);
    
    ob_clean();
    if ($result) {
        echo json_encode([
            'success' => true,
            'message' => 'Action assigned successfully',
            'timestamp' => date('c')
        ]);
    } else {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Failed to assign action',
            'timestamp' => date('c')
        ]);
    }
    exit();
}

/**
 * Mark action as complete
 */
function handleCompleteAction($db, $unifiedAuth, $actionId) {
    global $user;
    
    $sql = "UPDATE remediation_actions 
            SET status = 'Completed', completed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE action_id = ?";
    
    $stmt = $db->getConnection()->prepare($sql);
    $result = $stmt->execute([$actionId]);
    
    ob_clean();
    if ($result) {
        echo json_encode([
            'success' => true,
            'message' => 'Action completed successfully',
            'timestamp' => date('c')
        ]);
    } else {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Failed to complete action',
            'timestamp' => date('c')
        ]);
    }
    exit();
}

/**
 * Update device patch status
 */
function handleUpdateDeviceStatus($db, $unifiedAuth, $actionId, $deviceId) {
    global $user;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($input['patch_status'])) {
        ob_clean();
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Missing patch_status',
            'timestamp' => date('c')
        ]);
        exit();
    }
    
    $sql = "UPDATE action_device_links 
            SET patch_status = ?, patched_at = ?, patched_by = ?, updated_at = CURRENT_TIMESTAMP
            WHERE action_id = ? AND device_id = ?";
    
    $patchedAt = $input['patch_status'] === 'Completed' ? date('Y-m-d H:i:s') : null;
    $patchedBy = $input['patch_status'] === 'Completed' ? $user['user_id'] : null;
    
    $stmt = $db->getConnection()->prepare($sql);
    $result = $stmt->execute([$input['patch_status'], $patchedAt, $patchedBy, $actionId, $deviceId]);
    
    ob_clean();
    if ($result) {
        echo json_encode([
            'success' => true,
            'message' => 'Device status updated successfully',
            'timestamp' => date('c')
        ]);
    } else {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Failed to update device status',
            'timestamp' => date('c')
        ]);
    }
    exit();
}
?>
