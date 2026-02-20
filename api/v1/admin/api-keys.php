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
require_once __DIR__ . '/../../../includes/api-key-manager.php';

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Initialize unified authentication
$unifiedAuth = new UnifiedAuth();

// Authenticate user (supports both session and API key)
if (!$unifiedAuth->authenticate()) {
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
// Check if user has permission to access this resource
$unifiedAuth->requirePermission('system', 'read');

// Check if user has admin permissions
if ($user['role'] !== 'Admin') {
    http_response_code(403);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'INSUFFICIENT_PERMISSIONS',
            'message' => 'Admin access required'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

$apiKeyManager = new ApiKeyManager();
$method = $_SERVER['REQUEST_METHOD'];
$path = $_GET['path'] ?? '';

// Route requests
switch ($method) {
    case 'GET':
        handleGetRequest($path);
        break;
    case 'POST':
        handlePostRequest($path);
        break;
    case 'PUT':
        handlePutRequest($path);
        break;
    case 'DELETE':
        handleDeleteRequest($path);
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleGetRequest($path) {
    global $apiKeyManager, $user;
    
    switch ($path) {
        case 'list':
            $includeInactive = $_GET['include_inactive'] ?? false;
            $keys = $apiKeyManager->listApiKeys($user['user_id'], $includeInactive);
            
            echo json_encode([
                'success' => true,
                'data' => $keys,
                'timestamp' => date('c')
            ]);
            break;
            
        case 'usage':
            $keyId = $_GET['key_id'] ?? '';
            $days = (int)($_GET['days'] ?? 30);
            
            if (empty($keyId)) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => 'Key ID required'
                ]);
                return;
            }
            
            $stats = $apiKeyManager->getUsageStats($keyId, $days);
            
            echo json_encode([
                'success' => true,
                'data' => $stats,
                'timestamp' => date('c')
            ]);
            break;
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

function handlePostRequest($path) {
    global $apiKeyManager, $user;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Invalid JSON input'
        ]);
        return;
    }
    
    switch ($path) {
        case 'create':
            $input['created_by'] = $user['user_id'];
            $result = $apiKeyManager->createApiKey($input);
            
            if ($result['success']) {
                echo json_encode([
                    'success' => true,
                    'data' => $result,
                    'timestamp' => date('c')
                ]);
            } else {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => $result['error'],
                    'timestamp' => date('c')
                ]);
            }
            break;
            
        case 'regenerate':
            $keyId = $input['key_id'] ?? '';
            
            if (empty($keyId)) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => 'Key ID required'
                ]);
                return;
            }
            
            $result = $apiKeyManager->regenerateApiKey($keyId);
            
            if ($result['success']) {
                echo json_encode([
                    'success' => true,
                    'data' => $result,
                    'timestamp' => date('c')
                ]);
            } else {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => $result['error'],
                    'timestamp' => date('c')
                ]);
            }
            break;
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

function handlePutRequest($path) {
    global $apiKeyManager;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Invalid JSON input'
        ]);
        return;
    }
    
    $keyId = $input['key_id'] ?? '';
    
    if (empty($keyId)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Key ID required'
        ]);
        return;
    }
    
    // Remove key_id from update data
    unset($input['key_id']);
    
    $result = $apiKeyManager->updateApiKey($keyId, $input);
    
    if ($result['success']) {
        echo json_encode([
            'success' => true,
            'data' => $result,
            'timestamp' => date('c')
        ]);
    } else {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => $result['error'],
            'timestamp' => date('c')
        ]);
    }
}

function handleDeleteRequest($path) {
    global $apiKeyManager;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Invalid JSON input'
        ]);
        return;
    }
    
    $keyId = $input['key_id'] ?? '';
    
    if (empty($keyId)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Key ID required'
        ]);
        return;
    }
    
    $result = $apiKeyManager->deleteApiKey($keyId);
    
    if ($result['success']) {
        echo json_encode([
            'success' => true,
            'data' => $result,
            'timestamp' => date('c')
        ]);
    } else {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => $result['error'],
            'timestamp' => date('c')
        ]);
    }
}
