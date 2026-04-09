<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}

// Start output buffering to prevent PHP warnings/notices from corrupting JSON
ob_start();

require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';
require_once __DIR__ . '/../../../services/shell_command_utilities.php';

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Initialize unified authentication
$unifiedAuth = new UnifiedAuth();

// Authenticate user (supports both session and API key)
if (!$unifiedAuth->authenticate()) {
    ob_clean();
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'UNAUTHORIZED',
            'message' => 'Authentication required'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

// Get authenticated user
$user = $unifiedAuth->getCurrentUser();

// Check if user has permission to manage vulnerabilities
$unifiedAuth->requirePermission('vulnerabilities', 'write');

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

try {
    // Trigger KEV sync in background
    $command = 'cd ' . _ROOT . ' && python3 services/kev_sync_service.py';
    $result = ShellCommandUtilities::executeShellCommand($command, ['blocking' => false]);
    
    // Log the action (if logging is available through UnifiedAuth or direct DB access)
    // Note: UnifiedAuth doesn't have logUserAction, but we can log through audit if needed
    
    ob_clean();
    
    if ($result['success']) {
        echo json_encode([
            'success' => true,
            'message' => 'KEV sync started in background. Check sync log for progress.',
            'pid' => $result['pid'] ?? null,
            'timestamp' => date('c')
        ]);
    } else {
        echo json_encode([
            'success' => false,
            'error' => 'Failed to start KEV sync: ' . ($result['error'] ?? 'Unknown error'),
            'timestamp' => date('c')
        ]);
    }
    exit;
    
} catch (Exception $e) {
    ob_clean();
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'SYNC_ERROR',
            'message' => 'Failed to trigger KEV sync: ' . $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

