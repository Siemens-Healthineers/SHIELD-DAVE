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
require_once __DIR__ . '/../../../includes/auth.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Set content type
header('Content-Type: application/json');

// Get request method
$method = $_SERVER['REQUEST_METHOD'];
$path = $_GET['path'] ?? '';

try {
    $db = DatabaseConfig::getInstance();
    $auth = new UnifiedAuth();
    
    // Authenticate user (supports both session and API key)
    if (!$auth->authenticate()) {
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
    $user = $auth->getCurrentUser();
    
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
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'METHOD_NOT_ALLOWED',
                    'message' => 'Method not allowed'
                ],
                'timestamp' => date('c')
            ]);
    }
    
} catch (Exception $e) {
    error_log("Recall scheduling API error: " . $e->getMessage());
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

function handleGetRequest($path) {
    global $db, $user, $auth;
    
    // Check permission
    $auth->requirePermission('recalls', 'read');
    
    switch ($path) {
        case 'affected-devices':
            getAffectedDevices();
            break;
        case 'maintenance-tasks':
            getMaintenanceTasks();
            break;
        case 'statistics':
            getMaintenanceStatistics();
            break;
        default:
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'NOT_FOUND',
                    'message' => 'Endpoint not found'
                ],
                'timestamp' => date('c')
            ]);
    }
}

function handlePostRequest($path) {
    global $db, $user, $auth;
    
    // Check permission
    $auth->requirePermission('recalls', 'write');
    
    switch ($path) {
        case 'create-task':
            createMaintenanceTask();
            break;
        case 'bulk-schedule':
            bulkScheduleMaintenance();
            break;
        default:
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'NOT_FOUND',
                    'message' => 'Endpoint not found'
                ],
                'timestamp' => date('c')
            ]);
    }
}

function handlePutRequest($path) {
    global $db, $user, $auth;
    
    // Check permission
    $auth->requirePermission('recalls', 'write');
    
    switch ($path) {
        case 'update-task':
            updateMaintenanceTask();
            break;
        case 'update-status':
            updateTaskStatus();
            break;
        default:
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'NOT_FOUND',
                    'message' => 'Endpoint not found'
                ],
                'timestamp' => date('c')
            ]);
    }
}

function handleDeleteRequest($path) {
    global $db, $user, $auth;
    
    // Check permission
    $auth->requirePermission('recalls', 'write');
    
    switch ($path) {
        case 'cancel-task':
            cancelMaintenanceTask();
            break;
        default:
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'NOT_FOUND',
                    'message' => 'Endpoint not found'
                ],
                'timestamp' => date('c')
            ]);
    }
}

function getAffectedDevices() {
    global $db;
    
    $recallId = $_GET['recall_id'] ?? null;
    
    if (!$recallId) {
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
    
    $sql = "SELECT 
        drl.device_id,
        md.device_name,
        md.brand_name,
        md.model_number,
        md.k_number,
        a.hostname,
        a.asset_tag,
        a.location,
        a.department,
        l.location_name,
        a.criticality,
        drl.remediation_status,
        drl.due_date,
        -- Check if already scheduled
        CASE WHEN st.task_id IS NOT NULL THEN true ELSE false END as is_scheduled,
        st.task_id,
        st.status as task_status,
        st.scheduled_date
        FROM device_recalls_link drl
        JOIN medical_devices md ON drl.device_id = md.device_id
        JOIN assets a ON md.asset_id = a.asset_id
        LEFT JOIN locations l ON a.location_id = l.location_id
        LEFT JOIN scheduled_tasks st ON drl.device_id = st.device_id 
            AND st.recall_id = drl.recall_id 
            AND st.task_type = 'recall_maintenance'
        WHERE drl.recall_id = :recall_id
        ORDER BY a.criticality DESC, md.device_name";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':recall_id', $recallId);
    $stmt->execute();
    $devices = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $devices,
        'timestamp' => date('c')
    ]);
}

function getMaintenanceTasks() {
    global $db;
    
    $filters = [
        'status' => $_GET['status'] ?? null,
        'priority' => $_GET['priority'] ?? null,
        'assigned_to' => $_GET['assigned_to'] ?? null,
        'recall_id' => $_GET['recall_id'] ?? null,
        'limit' => intval($_GET['limit'] ?? 50),
        'offset' => intval($_GET['offset'] ?? 0)
    ];
    
    $whereConditions = ["st.task_type = 'recall_maintenance'"];
    $params = [];
    
    if ($filters['status']) {
        $whereConditions[] = "st.status = :status";
        $params['status'] = $filters['status'];
    }
    
    if ($filters['priority']) {
        $whereConditions[] = "st.recall_priority = :priority";
        $params['priority'] = $filters['priority'];
    }
    
    if ($filters['assigned_to']) {
        $whereConditions[] = "st.assigned_to = :assigned_to";
        $params['assigned_to'] = $filters['assigned_to'];
    }
    
    if ($filters['recall_id']) {
        $whereConditions[] = "st.recall_id = :recall_id";
        $params['recall_id'] = $filters['recall_id'];
    }
    
    $whereClause = implode(' AND ', $whereConditions);
    
    $sql = "SELECT * FROM scheduled_recall_tasks_view 
            WHERE $whereClause
            ORDER BY urgency_score DESC, st.scheduled_date ASC
            LIMIT :limit OFFSET :offset";
    
    $stmt = $db->prepare($sql);
    foreach ($params as $key => $value) {
        $stmt->bindValue(":$key", $value);
    }
    $stmt->bindValue(':limit', $filters['limit'], PDO::PARAM_INT);
    $stmt->bindValue(':offset', $filters['offset'], PDO::PARAM_INT);
    $stmt->execute();
    $tasks = $stmt->fetchAll();
    
    // Get total count
    $countSql = "SELECT COUNT(*) FROM scheduled_recall_tasks_view WHERE $whereClause";
    $countStmt = $db->prepare($countSql);
    foreach ($params as $key => $value) {
        $countStmt->bindValue(":$key", $value);
    }
    $countStmt->execute();
    $totalCount = $countStmt->fetchColumn();
    
    echo json_encode([
        'success' => true,
        'data' => $tasks,
        'pagination' => [
            'total' => $totalCount,
            'limit' => $filters['limit'],
            'offset' => $filters['offset'],
            'has_more' => ($filters['offset'] + $filters['limit']) < $totalCount
        ],
        'timestamp' => date('c')
    ]);
}

function getMaintenanceStatistics() {
    global $db;
    
    $sql = "SELECT * FROM get_recall_maintenance_stats()";
    $stmt = $db->query($sql);
    $stats = $stmt->fetch();
    
    echo json_encode([
        'success' => true,
        'data' => $stats,
        'timestamp' => date('c')
    ]);
}

function createMaintenanceTask() {
    global $db, $user;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_INPUT',
                'message' => 'Invalid JSON input'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Validate required fields
    $required_fields = ['recall_id', 'device_id', 'assigned_to', 'scheduled_date', 'estimated_downtime'];
    foreach ($required_fields as $field) {
        if (empty($input[$field])) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_FIELD',
                    'message' => "Required field '$field' is missing"
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    try {
        // Use the database function to create the task
        $sql = "SELECT assign_recall_maintenance_task(
            :recall_id,
            :device_id,
            :assigned_to,
            :assigned_by,
            :scheduled_date,
            :estimated_downtime,
            :recall_priority,
            :remediation_type,
            :task_description,
            :notes,
            :affected_serial_numbers,
            :vendor_contact_required,
            :fda_notification_required,
            :patient_safety_impact
        ) as task_id";
        
        $stmt = $db->prepare($sql);
        $stmt->bindValue(':recall_id', $input['recall_id']);
        $stmt->bindValue(':device_id', $input['device_id']);
        $stmt->bindValue(':assigned_to', $input['assigned_to']);
        $stmt->bindValue(':assigned_by', $user['user_id']);
        $stmt->bindValue(':scheduled_date', $input['scheduled_date']);
        $stmt->bindValue(':estimated_downtime', intval($input['estimated_downtime']));
        $stmt->bindValue(':recall_priority', $input['recall_priority'] ?? 'Medium');
        $stmt->bindValue(':remediation_type', $input['remediation_type'] ?? 'Inspection');
        $stmt->bindValue(':task_description', $input['task_description'] ?? null);
        $stmt->bindValue(':notes', $input['notes'] ?? null);
        $stmt->bindValue(':affected_serial_numbers', $input['affected_serial_numbers'] ?? null);
        $stmt->bindValue(':vendor_contact_required', filter_var($input['vendor_contact_required'] ?? false, FILTER_VALIDATE_BOOLEAN), PDO::PARAM_BOOL);
        $stmt->bindValue(':fda_notification_required', filter_var($input['fda_notification_required'] ?? false, FILTER_VALIDATE_BOOLEAN), PDO::PARAM_BOOL);
        $stmt->bindValue(':patient_safety_impact', filter_var($input['patient_safety_impact'] ?? false, FILTER_VALIDATE_BOOLEAN), PDO::PARAM_BOOL);
        
        $stmt->execute();
        $taskId = $stmt->fetch()['task_id'];
        
        // Get the created task details
        $taskSql = "SELECT * FROM scheduled_recall_tasks_view WHERE task_id = :task_id";
        $taskStmt = $db->prepare($taskSql);
        $taskStmt->bindValue(':task_id', $taskId);
        $taskStmt->execute();
        $task = $taskStmt->fetch();
        
        echo json_encode([
            'success' => true,
            'data' => $task,
            'message' => 'Recall maintenance task created successfully',
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        error_log("Error creating recall maintenance task: " . $e->getMessage());
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'CREATION_FAILED',
                'message' => 'Failed to create maintenance task: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function bulkScheduleMaintenance() {
    global $db, $user;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input || !isset($input['tasks']) || !is_array($input['tasks'])) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_INPUT',
                'message' => 'Invalid input: tasks array is required'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    $createdTasks = [];
    $errors = [];
    
    foreach ($input['tasks'] as $index => $taskData) {
        try {
            // Validate required fields for each task
            $required_fields = ['recall_id', 'device_id', 'assigned_to', 'scheduled_date', 'estimated_downtime'];
            $missing_fields = [];
            foreach ($required_fields as $field) {
                if (empty($taskData[$field])) {
                    $missing_fields[] = $field;
                }
            }
            
            if (!empty($missing_fields)) {
                $errors[] = "Task $index: Missing required fields: " . implode(', ', $missing_fields);
                continue;
            }
            
            // Create the task
            $sql = "SELECT assign_recall_maintenance_task(
                :recall_id,
                :device_id,
                :assigned_to,
                :assigned_by,
                :scheduled_date,
                :estimated_downtime,
                :recall_priority,
                :remediation_type,
                :task_description,
                :notes,
                :affected_serial_numbers,
                :vendor_contact_required,
                :fda_notification_required,
                :patient_safety_impact
            ) as task_id";
            
            $stmt = $db->prepare($sql);
            $stmt->bindValue(':recall_id', $taskData['recall_id']);
            $stmt->bindValue(':device_id', $taskData['device_id']);
            $stmt->bindValue(':assigned_to', $taskData['assigned_to']);
            $stmt->bindValue(':assigned_by', $user['user_id']);
            $stmt->bindValue(':scheduled_date', $taskData['scheduled_date']);
            $stmt->bindValue(':estimated_downtime', intval($taskData['estimated_downtime']));
            $stmt->bindValue(':recall_priority', $taskData['recall_priority'] ?? 'Medium');
            $stmt->bindValue(':remediation_type', $taskData['remediation_type'] ?? 'Inspection');
            $stmt->bindValue(':task_description', $taskData['task_description'] ?? null);
            $stmt->bindValue(':notes', $taskData['notes'] ?? null);
            $stmt->bindValue(':affected_serial_numbers', $taskData['affected_serial_numbers'] ?? null);
            $stmt->bindValue(':vendor_contact_required', filter_var($taskData['vendor_contact_required'] ?? false, FILTER_VALIDATE_BOOLEAN), PDO::PARAM_BOOL);
            $stmt->bindValue(':fda_notification_required', filter_var($taskData['fda_notification_required'] ?? false, FILTER_VALIDATE_BOOLEAN), PDO::PARAM_BOOL);
            $stmt->bindValue(':patient_safety_impact', filter_var($taskData['patient_safety_impact'] ?? false, FILTER_VALIDATE_BOOLEAN), PDO::PARAM_BOOL);
            
            $stmt->execute();
            $taskId = $stmt->fetch()['task_id'];
            
            $createdTasks[] = $taskId;
            
        } catch (Exception $e) {
            $errors[] = "Task $index: " . $e->getMessage();
        }
    }
    
    echo json_encode([
        'success' => count($errors) === 0,
        'data' => [
            'created_tasks' => $createdTasks,
            'total_created' => count($createdTasks),
            'total_requested' => count($input['tasks']),
            'errors' => $errors
        ],
        'message' => count($createdTasks) . ' tasks created successfully',
        'timestamp' => date('c')
    ]);
}

function updateMaintenanceTask() {
    global $db, $user;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input || empty($input['task_id'])) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'MISSING_TASK_ID',
                'message' => 'Task ID is required'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    $taskId = $input['task_id'];
    unset($input['task_id']);
    
    // Build update query
    $updateFields = [];
    $params = ['task_id' => $taskId];
    
    $allowedFields = [
        'assigned_to', 'scheduled_date', 'implementation_date', 'estimated_downtime',
        'actual_downtime', 'status', 'task_description', 'notes', 'completion_notes',
        'recall_priority', 'remediation_type', 'affected_serial_numbers',
        'vendor_contact_required', 'fda_notification_required', 'patient_safety_impact'
    ];
    
    foreach ($allowedFields as $field) {
        if (isset($input[$field])) {
            $updateFields[] = "$field = :$field";
            $params[$field] = $input[$field];
        }
    }
    
    if (empty($updateFields)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'NO_UPDATES',
                'message' => 'No valid fields to update'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    $updateFields[] = "updated_at = CURRENT_TIMESTAMP";
    
    $sql = "UPDATE scheduled_tasks SET " . implode(', ', $updateFields) . " 
            WHERE task_id = :task_id AND task_type = 'recall_maintenance'";
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    
    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'TASK_NOT_FOUND',
                'message' => 'Task not found or not a recall maintenance task'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Get updated task
    $taskSql = "SELECT * FROM scheduled_recall_tasks_view WHERE task_id = :task_id";
    $taskStmt = $db->prepare($taskSql);
    $taskStmt->bindValue(':task_id', $taskId);
    $taskStmt->execute();
    $task = $taskStmt->fetch();
    
    echo json_encode([
        'success' => true,
        'data' => $task,
        'message' => 'Task updated successfully',
        'timestamp' => date('c')
    ]);
}

function updateTaskStatus() {
    global $db, $user;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input || empty($input['task_id']) || empty($input['status'])) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'MISSING_FIELDS',
                'message' => 'Task ID and status are required'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    $validStatuses = ['Scheduled', 'In Progress', 'Completed', 'Cancelled', 'Failed'];
    if (!in_array($input['status'], $validStatuses)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_STATUS',
                'message' => 'Invalid status. Must be one of: ' . implode(', ', $validStatuses)
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    $sql = "UPDATE scheduled_tasks SET 
            status = :status,
            updated_at = CURRENT_TIMESTAMP,
            completed_at = CASE WHEN :status = 'Completed' THEN CURRENT_TIMESTAMP ELSE completed_at END,
            completed_by = CASE WHEN :status = 'Completed' THEN :completed_by ELSE completed_by END
            WHERE task_id = :task_id AND task_type = 'recall_maintenance'";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':status', $input['status']);
    $stmt->bindValue(':task_id', $input['task_id']);
    if ($input['status'] === 'Completed') {
        $stmt->bindValue(':completed_by', $user['user_id']);
    }
    $stmt->execute();
    
    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'TASK_NOT_FOUND',
                'message' => 'Task not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Task status updated successfully',
        'timestamp' => date('c')
    ]);
}

function cancelMaintenanceTask() {
    global $db;
    
    $taskId = $_GET['task_id'] ?? null;
    
    if (!$taskId) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'MISSING_TASK_ID',
                'message' => 'Task ID is required'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    $sql = "UPDATE scheduled_tasks SET 
            status = 'Cancelled',
            updated_at = CURRENT_TIMESTAMP
            WHERE task_id = :task_id AND task_type = 'recall_maintenance'";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':task_id', $taskId);
    $stmt->execute();
    
    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'TASK_NOT_FOUND',
                'message' => 'Task not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Task cancelled successfully',
        'timestamp' => date('c')
    ]);
}
?>
