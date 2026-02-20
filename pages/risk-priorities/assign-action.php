<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/database.php';

// Set JSON response headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

try {
    $db = DatabaseConfig::getInstance();
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    $actionId = $input['action_id'] ?? null;
    $assignedTo = $input['assigned_to'] ?? null;
    $dueDate = $input['due_date'] ?? null;
    
    if (!$actionId) {
        echo json_encode(['success' => false, 'error' => 'Action ID required']);
        exit;
    }
    
    // Update action assignment
    $sql = "UPDATE remediation_actions 
            SET assigned_to = ?, 
                due_date = ?, 
                updated_at = CURRENT_TIMESTAMP
            WHERE action_id = ?";
    
    $stmt = $db->getConnection()->prepare($sql);
    $result = $stmt->execute([$assignedTo, $dueDate, $actionId]);
    
    if ($result) {
        echo json_encode([
            'success' => true, 
            'message' => 'Action assigned successfully'
        ]);
    } else {
        echo json_encode([
            'success' => false, 
            'error' => 'Failed to assign action'
        ]);
    }
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'error' => 'Database error: ' . $e->getMessage()
    ]);
}
?>
