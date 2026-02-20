<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/


if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../../config/config.php';
require_once __DIR__ . '/../../../../includes/auth.php';
require_once __DIR__ . '/../../../../includes/security-settings.php';
require_once __DIR__ . '/../../../../includes/security-monitor.php';
require_once __DIR__ . '/../../../../includes/security-audit.php';

// Set content type to JSON
header('Content-Type: application/json');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Initialize authentication
$auth = new Auth();
$auth->requireAuth();

// Check if user has admin privileges
$user = $_SESSION['user'] ?? [];
if (!isset($user['role']) || strtolower($user['role']) !== 'admin') {
    http_response_code(403);
    echo json_encode(['error' => 'Admin access required']);
    exit();
}

// Initialize services
$securityMonitor = new SecurityMonitor();
$securityAudit = new SecurityAudit();

try {
    // Get security metrics
    $metrics = $securityMonitor->getSecurityMetrics();
    
    echo json_encode([
        'success' => true,
        'metrics' => $metrics
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
?>

