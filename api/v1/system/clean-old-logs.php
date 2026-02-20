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
require_once __DIR__ . '/../../../includes/functions.php';

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
    // Clean old logs (older than 30 days)
    $cleaned = cleanOldLogs(30);
    
    // Log the clean action
    $db = DatabaseConfig::getInstance();
    $stmt = $db->prepare("
        INSERT INTO audit_logs (user_id, action, new_values, ip_address, user_agent, timestamp) 
        VALUES (?, 'log_clean_old', ?, ?, ?, CURRENT_TIMESTAMP)
    ");
    $stmt->execute([
        $user['user_id'],
        json_encode(['files_cleaned' => $cleaned, 'days_old' => 30]),
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ]);
    
    // Return success response
    echo json_encode([
        'success' => true,
        'message' => "Cleaned {$cleaned} old log files (older than 30 days)"
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error cleaning old logs: ' . $e->getMessage()
    ]);
}
?>
