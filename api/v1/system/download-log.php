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

// Require authentication
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    http_response_code(401);
    echo 'Authentication required';
    exit;
}

// Check if user has admin role
if ($user['role'] !== 'Admin') {
    http_response_code(403);
    echo 'Admin access required';
    exit;
}

// Get requested file
$filename = $_GET['file'] ?? '';
if (empty($filename)) {
    http_response_code(400);
    echo 'File parameter required';
    exit;
}

// Validate filename (security check)
if (!preg_match('/^[a-zA-Z0-9_.-]+\.log$/', $filename)) {
    http_response_code(400);
    echo 'Invalid filename';
    exit;
}

$log_path = _LOGS . '/' . $filename;

if (!file_exists($log_path)) {
    http_response_code(404);
    echo 'Log file not found';
    exit;
}

// Set headers for file download
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Content-Length: ' . filesize($log_path));

// Log the download action
$db = DatabaseConfig::getInstance();
$stmt = $db->prepare("
    INSERT INTO audit_logs (user_id, action, new_values, ip_address, user_agent, timestamp) 
    VALUES (?, 'log_download', ?, ?, ?, CURRENT_TIMESTAMP)
");
$stmt->execute([
    $user['user_id'],
    json_encode(['filename' => $filename]),
    $_SERVER['REMOTE_ADDR'] ?? 'unknown',
    $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
]);

// Output file content
readfile($log_path);
?>
