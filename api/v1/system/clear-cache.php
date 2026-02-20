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
require_once __DIR__ . '/../../../includes/cache.php';

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
    // Get cache statistics before clearing
    $stats_before = Cache::getStats();
    
    // Clear all cache
    $cleared_files = Cache::clear();
    
    // Get cache statistics after clearing
    $stats_after = Cache::getStats();
    
    // Log the cache clear action
    $db = DatabaseConfig::getInstance();
    $stmt = $db->prepare("
        INSERT INTO audit_logs (user_id, action, new_values, ip_address, user_agent, timestamp) 
        VALUES (?, 'cache_clear', ?, ?, ?, CURRENT_TIMESTAMP)
    ");
    $stmt->execute([
        $user['user_id'],
        json_encode([
            'files_cleared' => $cleared_files,
            'cache_enabled' => $stats_before['enabled'],
            'total_files_before' => $stats_before['total_files'],
            'total_size_before' => $stats_before['total_size']
        ]),
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ]);
    
    // Return success response
    echo json_encode([
        'success' => true,
        'message' => "Cache cleared successfully. Removed {$cleared_files} cache files.",
        'data' => [
            'files_cleared' => $cleared_files,
            'cache_stats_before' => $stats_before,
            'cache_stats_after' => $stats_after
        ]
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error clearing cache: ' . $e->getMessage()
    ]);
}
?>
