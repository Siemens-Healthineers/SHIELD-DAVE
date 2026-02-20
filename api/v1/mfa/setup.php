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
require_once __DIR__ . '/../../../includes/mfa-service.php';
require_once __DIR__ . '/../../../includes/api-lockdown-middleware.php';

// Enforce API lockdown
enforceApiLockdown('/api/v1/mfa/setup', $_SERVER['REQUEST_METHOD']);

// Set JSON response headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Start output buffering
ob_start();

// Initialize authentication
$auth = new Auth();
$auth->requireAuth();

// Get current user
$user = $_SESSION['user'] ?? [
    'user_id' => $_SESSION['user_id'] ?? null,
    'username' => $_SESSION['username'] ?? 'Unknown',
    'role' => $_SESSION['role'] ?? 'User',
    'email' => $_SESSION['email'] ?? 'Not provided'
];

if (!isset($user['user_id']) || empty($user['user_id'])) {
    http_response_code(401);
    ob_clean();
    echo json_encode(['error' => 'User not authenticated']);
    exit();
}

// Initialize MFA service
$mfaService = new MFAService();

// Get request method and action
$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

// Include handler functions
require_once __DIR__ . '/mfa-handlers.php';

try {
    switch ($method) {
        case 'GET':
            handleGetRequest($mfaService, $user, $action);
            break;
        case 'POST':
            handlePostRequest($mfaService, $user, $action);
            break;
        case 'PUT':
            handlePutRequest($mfaService, $user, $action);
            break;
        case 'DELETE':
            handleDeleteRequest($mfaService, $user, $action);
            break;
        default:
            http_response_code(405);
            ob_clean();
            echo json_encode(['error' => 'Method not allowed']);
            break;
    }
} catch (Exception $e) {
    error_log("MFA Setup API Error: " . $e->getMessage());
    http_response_code(500);
    ob_clean();
    echo json_encode(['error' => 'Internal server error: ' . $e->getMessage()]);
}

?>
