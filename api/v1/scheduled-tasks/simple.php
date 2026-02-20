<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

require_once __DIR__ . '/../../../config/database.php';

// Basic validation - allow requests from the same domain
// This is a simplified endpoint for modal task creation
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
    $input = json_decode(file_get_contents('php://input'), true);
    
    // Debug logging
    error_log("Simple API received data: " . json_encode($input));
    
    if (!$input) {
        throw new Exception('Invalid JSON input');
    }
    
    // Validate required fields
    $required_fields = ['task_type', 'device_id', 'assigned_to', 'scheduled_date', 'estimated_downtime'];
    foreach ($required_fields as $field) {
        if (!isset($input[$field]) || empty($input[$field])) {
            throw new Exception("Missing required field: $field");
        }
    }
    
    // Prepare task data
    $task_type = $input['task_type'];
    $device_id = $input['device_id'];
    $assigned_to = $input['assigned_to'];
    $scheduled_date = $input['scheduled_date'];
    $implementation_date = $input['implementation_date'] ?? null;
    $estimated_downtime = (int)$input['estimated_downtime'];
    $task_description = $input['task_description'] ?? null;
    $notes = $input['notes'] ?? null;
    
    // Get specific IDs based on task_type
    $package_id = ($task_type === 'package_remediation' && isset($input['package_id'])) ? $input['package_id'] : null;
    $cve_id = ($task_type === 'cve_remediation' && isset($input['cve_id'])) ? $input['cve_id'] : null;
    $action_id = isset($input['action_id']) ? $input['action_id'] : null;
    $patch_id = ($task_type === 'patch_application' && isset($input['patch_id'])) ? $input['patch_id'] : null;
    
    // Create task using appropriate function based on task type
    $task_id = null;
    
    if ($task_type === 'cve_remediation' && $cve_id) {
        // Use CVE remediation function
        $sql = "SELECT assign_cve_remediation_task(?, ?, ?, ?, ?, ?, ?, ?, ?) as task_id";
        $stmt = $db->getConnection()->prepare($sql);
        $stmt->execute([
            $cve_id,
            $device_id,
            $assigned_to,
            $assigned_to, // Using assigned_to as assigned_by for now
            $scheduled_date,
            $estimated_downtime,
            $task_description,
            $notes,
            $action_id  // Pass action_id to link task to remediation action
        ]);
        $result = $stmt->fetch();
        $task_id = $result['task_id'];
    } elseif ($task_type === 'patch_application' && $patch_id) {
        // Use patch application function
        $sql = "SELECT assign_patch_application_task(?, ?, ?, ?, ?, ?, ?, ?) as task_id";
        $stmt = $db->getConnection()->prepare($sql);
        $stmt->execute([
            $patch_id,
            $device_id,
            $assigned_to,
            $assigned_to, // Using assigned_to as assigned_by for now
            $scheduled_date,
            $estimated_downtime,
            $task_description,
            $notes
        ]);
        $result = $stmt->fetch();
        $task_id = $result['task_id'];
    } else {
        // Fallback to direct insert for package_remediation or other types
        $sql = "INSERT INTO scheduled_tasks (
            task_type, 
            package_id,
            cve_id,
            action_id,
            patch_id,
            device_id, 
            assigned_to, 
            scheduled_date, 
            implementation_date, 
            estimated_downtime, 
            task_description,
            notes, 
            created_at, 
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING task_id";
        
        $stmt = $db->getConnection()->prepare($sql);
        $stmt->execute([
            $task_type,
            $package_id,
            $cve_id,
            $action_id,
            $patch_id,
            $device_id,
            $assigned_to,
            $scheduled_date,
            $implementation_date,
            $estimated_downtime,
            $task_description,
            $notes
        ]);
        
        $result = $stmt->fetch();
        $task_id = $result['task_id'];
    }
    
    $result = ['task_id' => $task_id];
    
    // Note: scheduled_tasks_view is a regular view, not a materialized view
    // No refresh needed for regular views as they are computed on-the-fly
    
    echo json_encode([
        'success' => true,
        'data' => $result,
        'message' => 'Task created successfully'
    ]);
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'TASK_CREATION_FAILED',
            'message' => $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
}
?>
