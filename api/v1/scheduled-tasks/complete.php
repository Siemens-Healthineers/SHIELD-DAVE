<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Start output buffering to prevent any output before JSON
ob_start();

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    ob_clean();
    http_response_code(204);
    ob_end_flush();
    exit;
}

// Define DAVE_ACCESS to allow inclusion of unified-auth.php
if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}

require_once __DIR__ . '/../../../config/database.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';

// Basic validation - allow requests from the same domain (same as operations.php)
if (!isset($_SERVER['HTTP_REFERER']) || strpos($_SERVER['HTTP_REFERER'], $_SERVER['HTTP_HOST']) === false) {
    ob_clean();
    http_response_code(403);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'FORBIDDEN',
            'message' => 'Request must come from the same domain'
        ],
        'timestamp' => date('c')
    ]);
    ob_end_flush();
    exit;
}

try {
    // Auth (session or API key) - just authenticate, no specific permission check (same as operations.php)
    $auth = new UnifiedAuth();
    $auth->authenticate();
    $user = $auth->getCurrentUser();
    if (!$user) {
        throw new Exception('Authentication required');
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Method not allowed');
    }

    $task_id = $_GET['task_id'] ?? null;
    if (!$task_id) {
        throw new Exception('Task ID is required');
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $completion_notes = $input['completion_notes'] ?? null;
    $actual_downtime = isset($input['actual_downtime']) && $input['actual_downtime'] !== ''
        ? (int)$input['actual_downtime']
        : null;

    if (!$completion_notes) {
        throw new Exception('Completion notes are required');
    }

    $db = DatabaseConfig::getInstance();
    $pdo = $db->getConnection();
    
    // Validate task_id format (UUID)
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $task_id)) {
        throw new Exception('Invalid task ID format');
    }

    $stmt = $pdo->prepare("SELECT complete_scheduled_task(?, ?, ?, ?) AS result");
    
    if (!$stmt->execute([$task_id, $completion_notes, $actual_downtime, $user['user_id']])) {
        $error = $stmt->errorInfo();
        throw new Exception('Database error: ' . ($error[2] ?? 'Unknown error'));
    }
    
    $row = $stmt->fetch();
    
    if (!$row || !isset($row['result'])) {
        throw new Exception('Task completion function did not return a result');
    }
    
    $result = json_decode($row['result'], true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Invalid JSON response from completion function: ' . json_last_error_msg());
    }

    // Clean any output that may have been generated
    ob_clean();
    
    echo json_encode([
        'success' => true,
        'data' => $result,
        'message' => 'Task completed successfully'
    ]);
    
    ob_end_flush();
    exit;

} catch (Exception $e) {
    // Clean any output that may have been generated
    ob_clean();
    
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'TASK_COMPLETE_FAILED',
            'message' => $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
    
    ob_end_flush();
    exit;
}
?>


