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
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];

// Route requests
switch ($method) {
    case 'GET':
        handleGetCurrentUser();
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleGetCurrentUser() {
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
        
        // Get current user
        $user = $auth->getCurrentUser();
        
        if (!$user) {
            http_response_code(401);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'USER_NOT_FOUND',
                    'message' => 'User not found'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        echo json_encode([
            'success' => true,
            'data' => [
                'user_id' => $user['user_id'],
                'username' => $user['username'],
                'email' => $user['email'],
                'role' => $user['role'],
                'permissions' => getUserPermissions($user['role']),
                'last_login' => $user['last_login'],
                'is_active' => $user['is_active']
            ],
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

function getUserPermissions($role) {
    $permissions = [
        'Admin' => [
            'assets.read', 'assets.write', 'assets.delete', 'assets.create',
            'devices.read', 'devices.write', 'devices.delete',
            'vulnerabilities.read', 'vulnerabilities.write', 'vulnerabilities.delete',
            'recalls.read', 'recalls.write', 'recalls.delete',
            'reports.read', 'reports.write', 'reports.delete',
            'users.read', 'users.write', 'users.delete',
            'system.read', 'system.write'
        ],
        'User' => [
            'assets.read', 'assets.write', 'assets.create',
            'devices.read', 'devices.write',
            'vulnerabilities.read',
            'recalls.read',
            'reports.read', 'reports.write'
        ]
    ];
    
    return $permissions[$role] ?? [];
}
?>
