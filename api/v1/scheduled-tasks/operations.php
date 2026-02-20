<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, PUT, DELETE');
header('Access-Control-Allow-Headers: Content-Type');

require_once __DIR__ . '/../../../config/database.php';

// Basic validation - allow requests from the same domain
if (!isset($_SERVER['HTTP_REFERER']) || strpos($_SERVER['HTTP_REFERER'], $_SERVER['HTTP_HOST']) === false) {
    http_response_code(403);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'FORBIDDEN',
            'message' => 'Request must come from the same domain'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

try {
    $db = DatabaseConfig::getInstance();
    $method = $_SERVER['REQUEST_METHOD'];
    $task_id = $_GET['task_id'] ?? null;
    
    if (!$task_id) {
        throw new Exception('Task ID is required');
    }
    
    // Validate UUID format
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $task_id)) {
        throw new Exception('Invalid task ID format');
    }
    
    switch ($method) {
        case 'GET':
            // Get task details - query with manual join for completed_by since view may not have it
            $sql = "SELECT st.*,
                    u_assigned.username AS assigned_to_username,
                    u_assigned.email AS assigned_to_email,
                    u_creator.username AS assigned_by_username,
                    u_creator.email AS assigned_by_email,
                    u_approver.username AS approval_by_username,
                    u_approver.email AS approval_by_email,
                    u_completed.username AS completed_by_username,
                    u_completed.email AS completed_by_email
                FROM scheduled_tasks st
                LEFT JOIN users u_assigned ON st.assigned_to = u_assigned.user_id
                LEFT JOIN users u_creator ON st.assigned_by = u_creator.user_id
                LEFT JOIN users u_approver ON st.department_approval_by = u_approver.user_id
                LEFT JOIN users u_completed ON st.completed_by = u_completed.user_id
                WHERE st.task_id = ?";
            $stmt = $db->getConnection()->prepare($sql);
            $stmt->execute([$task_id]);
            $task = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$task) {
                // Fallback to view if direct query fails
                $sql = "SELECT * FROM scheduled_tasks_view WHERE task_id = ?";
                $stmt = $db->getConnection()->prepare($sql);
                $stmt->execute([$task_id]);
                $task = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$task) {
                    throw new Exception('Task not found');
                }
            }
            
            echo json_encode([
                'success' => true,
                'data' => $task
            ]);
            break;
            
        case 'PUT':
            // Update task
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (!$input) {
                throw new Exception('Invalid JSON input');
            }
            
            $update_fields = [];
            $params = [];
            
            if (isset($input['status'])) {
                $update_fields[] = "status = ?";
                $params[] = $input['status'];
            }
            
            if (isset($input['scheduled_date'])) {
                $update_fields[] = "scheduled_date = ?";
                $params[] = $input['scheduled_date'];
            }
            
            if (isset($input['implementation_date'])) {
                $update_fields[] = "implementation_date = ?";
                $params[] = $input['implementation_date'];
            }
            
            if (isset($input['estimated_downtime'])) {
                $update_fields[] = "estimated_downtime = ?";
                $params[] = (int)$input['estimated_downtime'];
            }
            
            if (isset($input['notes'])) {
                $update_fields[] = "notes = ?";
                $params[] = $input['notes'];
            }
            
            if (isset($input['task_description'])) {
                $update_fields[] = "task_description = ?";
                $params[] = $input['task_description'];
            }
            
            if (isset($input['completion_notes'])) {
                $update_fields[] = "completion_notes = ?";
                $params[] = $input['completion_notes'];
            }
            
            if (isset($input['department_approval_status'])) {
                $update_fields[] = "department_approval_status = ?";
                $params[] = $input['department_approval_status'];
            }
            
            if (isset($input['department_approval_contact'])) {
                $update_fields[] = "department_approval_contact = ?";
                $params[] = $input['department_approval_contact'];
            }
            
            if (isset($input['department_approval_notes'])) {
                $update_fields[] = "department_approval_notes = ?";
                $params[] = $input['department_approval_notes'];
            }
            
            if (isset($input['department_approval_date'])) {
                $update_fields[] = "department_approval_date = ?";
                $params[] = $input['department_approval_date'];
            }
            
            if (isset($input['department_notified'])) {
                $update_fields[] = "department_notified = ?";
                $params[] = $input['department_notified'] ? 1 : 0;
            }
            
            if (empty($update_fields)) {
                throw new Exception('No fields to update');
            }
            
            $update_fields[] = "updated_at = CURRENT_TIMESTAMP";
            $params[] = $task_id;
            
            $sql = "UPDATE scheduled_tasks SET " . implode(', ', $update_fields) . " WHERE task_id = ?";
            $stmt = $db->getConnection()->prepare($sql);
            $stmt->execute($params);
            
            echo json_encode([
                'success' => true,
                'message' => 'Task updated successfully'
            ]);
            break;
            
        case 'DELETE':
            // Delete task
            $sql = "DELETE FROM scheduled_tasks WHERE task_id = ?";
            $stmt = $db->getConnection()->prepare($sql);
            $stmt->execute([$task_id]);
            
            if ($stmt->rowCount() === 0) {
                throw new Exception('Task not found');
            }
            
            echo json_encode([
                'success' => true,
                'message' => 'Task deleted successfully'
            ]);
            break;
            
        default:
            throw new Exception('Method not allowed');
    }
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'TASK_OPERATION_FAILED',
            'message' => $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
}
?>



