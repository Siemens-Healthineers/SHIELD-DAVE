<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../includes/auth.php';

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

$method = $_SERVER['REQUEST_METHOD'];

// Route requests
switch ($method) {
    case 'POST':
        handleLogout();
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleLogout() {
    global $auth;
    
    try {
        // Check if user is logged in
        if (!$auth->isLoggedIn()) {
            http_response_code(401);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'NOT_AUTHENTICATED',
                    'message' => 'User not authenticated'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        // Perform logout
        $auth->logoutUser();
        
        echo json_encode([
            'success' => true,
            'message' => 'Logout successful',
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error'
            ],
            'timestamp' => date('c')
        ]);
    }
}
?>
