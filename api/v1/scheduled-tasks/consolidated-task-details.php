<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
ob_start();

require_once __DIR__ . '/../../../config/database.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

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
    
    if (!isset($_GET['task_id'])) {
        throw new Exception('Task ID is required');
    }
    
    $task_id = $_GET['task_id'];
    
    // Validate task ID format
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $task_id)) {
        throw new Exception('Invalid task ID format');
    }
    
    // Get the consolidated task
    $sql = "SELECT task_id, task_type, task_description, notes, scheduled_date, estimated_downtime, 
                   status, created_at, updated_at
            FROM scheduled_tasks 
            WHERE task_id = ? AND task_type = 'package_remediation'";
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute([$task_id]);
    $task = $stmt->fetch();
    
    if (!$task) {
        throw new Exception('Consolidated task not found');
    }
    
    // Parse the detailed information from notes
    $detailed_info = null;
    if ($task['notes'] && strpos($task['notes'], 'DETAILED TASK INFORMATION:') !== false) {
        $json_start = strpos($task['notes'], 'DETAILED TASK INFORMATION:') + strlen('DETAILED TASK INFORMATION:');
        $json_part = trim(substr($task['notes'], $json_start));
        $detailed_info = json_decode($json_part, true);
    }
    
    echo json_encode([
        'success' => true,
        'data' => [
            'task' => $task,
            'detailed_information' => $detailed_info
        ]
    ]);
    
} catch (Exception $e) {
    error_log("Consolidated Task Details API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'DETAILS_FETCH_FAILED',
            'message' => $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
}

ob_end_flush();
?>

