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
    
    $actionId = $_POST['action_id'] ?? null;
    $deviceId = $_POST['device_id'] ?? null;
    
    if (!$actionId || !$deviceId) {
        echo json_encode(['success' => false, 'error' => 'Action ID and Device ID required']);
        exit;
    }
    
    // Update device patch status
    $sql = "UPDATE action_device_links 
            SET patch_status = 'Completed', 
                patched_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE action_id = ? AND device_id = ?";
    
    $stmt = $db->getConnection()->prepare($sql);
    $result = $stmt->execute([$actionId, $deviceId]);
    
    if ($result) {
        echo json_encode(['success' => true, 'message' => 'Device marked as patched successfully']);
    } else {
        echo json_encode(['success' => false, 'error' => 'Failed to update device status']);
    }
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'error' => 'Database error: ' . $e->getMessage()
    ]);
}
?>
