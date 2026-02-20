<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';

// Set JSON response header
header('Content-Type: application/json');

// Require authentication
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Authentication required']);
    exit;
}

// Check if user has admin role
if ($user['role'] !== 'Admin') {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Admin access required']);
    exit;
}

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

try {
    // Get request data
    $input = json_decode(file_get_contents('php://input'), true);
    $filename = $input['file'] ?? '';
    
    if (empty($filename)) {
        throw new Exception('File parameter required');
    }
    
    // Validate filename (security check)
    if (!preg_match('/^[a-zA-Z0-9_.-]+\.log$/', $filename)) {
        throw new Exception('Invalid filename');
    }
    
    $log_path = _LOGS . '/' . $filename;
    
    if (!file_exists($log_path)) {
        throw new Exception('Log file not found');
    }
    
    // Clear the log file
    if (file_put_contents($log_path, '') === false) {
        throw new Exception('Failed to clear log file');
    }
    
    // Log the clear action
    $db = DatabaseConfig::getInstance();
    $stmt = $db->prepare("
        INSERT INTO audit_logs (user_id, action, new_values, ip_address, user_agent, timestamp) 
        VALUES (?, 'log_clear', ?, ?, ?, CURRENT_TIMESTAMP)
    ");
    $stmt->execute([
        $user['user_id'],
        json_encode(['filename' => $filename]),
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ]);
    
    // Return success response
    echo json_encode([
        'success' => true,
        'message' => "Log file '{$filename}' cleared successfully"
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error clearing log: ' . $e->getMessage()
    ]);
}
?>
