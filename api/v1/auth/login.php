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
        handleLogin();
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleLogin() {
    global $auth;
    
    try {
        // Get JSON input
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_JSON',
                    'message' => 'Invalid JSON input'
                ]
            ]);
            return;
        }
        
        // Validate required fields
        $username = $input['username'] ?? '';
        $password = $input['password'] ?? '';
        $mfa_code = $input['mfa_code'] ?? '';
        
        if (empty($username) || empty($password)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_FIELDS',
                    'message' => 'Username and password are required'
                ]
            ]);
            return;
        }
        
        // Attempt login
        $result = $auth->loginUser($username, $password, $mfa_code);
        
        if ($result['success']) {
            // Get user details
            $user = $auth->getCurrentUser();
            
            echo json_encode([
                'success' => true,
                'data' => [
                    'user_id' => $user['user_id'],
                    'username' => $user['username'],
                    'role' => $user['role'],
                    'permissions' => getUserPermissions($user['role']),
                    'session_id' => session_id()
                ],
                'message' => 'Login successful',
                'timestamp' => date('c')
            ]);
        } else {
            http_response_code(401);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'LOGIN_FAILED',
                    'message' => $result['message']
                ],
                'timestamp' => date('c')
            ]);
        }
        
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
            'assets.read', 'assets.write', 'assets.delete',
            'devices.read', 'devices.write', 'devices.delete',
            'vulnerabilities.read', 'vulnerabilities.write', 'vulnerabilities.delete',
            'recalls.read', 'recalls.write', 'recalls.delete',
            'reports.read', 'reports.write', 'reports.delete',
            'users.read', 'users.write', 'users.delete',
            'system.read', 'system.write'
        ],
        'User' => [
            'assets.read', 'assets.write',
            'devices.read', 'devices.write',
            'vulnerabilities.read',
            'recalls.read',
            'reports.read', 'reports.write'
        ]
    ];
    
    return $permissions[$role] ?? [];
}
?>
