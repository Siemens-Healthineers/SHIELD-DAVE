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
require_once __DIR__ . '/../../../includes/api-key-auth.php';

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

// Initialize API key authentication
$apiKeyAuth = new ApiKeyAuth();

// Authenticate using API key
if (!$apiKeyAuth->authenticate('assets:read')) {
    // Authentication failed, response already sent
    exit;
}

// Get authenticated user
$apiUser = $apiKeyAuth->getCurrentApiUser();

$method = $_SERVER['REQUEST_METHOD'];
$startTime = microtime(true);

// Route requests
switch ($method) {
    case 'GET':
        handleGetRequest();
        break;
    case 'POST':
        handlePostRequest();
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleGetRequest() {
    global $apiKeyAuth, $apiUser;
    
    try {
        // Example: Get assets data
        $db = DatabaseConfig::getInstance();
        
        // Check if user has permission to read assets
        if (!$apiKeyAuth->hasScope('assets:read')) {
            http_response_code(403);
            echo json_encode([
                'success' => false,
                'error' => 'Insufficient permissions for assets:read'
            ]);
            return;
        }
        
        // Get query parameters
        $limit = min((int)($_GET['limit'] ?? 10), 100); // Max 100 records
        $offset = (int)($_GET['offset'] ?? 0);
        $search = $_GET['search'] ?? '';
        
        // Build query
        $sql = "SELECT asset_id, hostname, ip_address, asset_type, status, created_at 
                FROM assets 
                WHERE 1=1";
        $params = [];
        
        if (!empty($search)) {
            $sql .= " AND (hostname ILIKE ? OR ip_address::text ILIKE ?)";
            $searchTerm = "%{$search}%";
            $params[] = $searchTerm;
            $params[] = $searchTerm;
        }
        
        $sql .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
        $params[] = $limit;
        $params[] = $offset;
        
        $stmt = $db->query($sql, $params);
        $assets = $stmt->fetchAll();
        
        // Get total count
        $countSql = "SELECT COUNT(*) as total FROM assets";
        if (!empty($search)) {
            $countSql .= " WHERE (hostname ILIKE ? OR ip_address::text ILIKE ?)";
        }
        $countStmt = $db->query($countSql, $params);
        $total = $countStmt->fetch()['total'];
        
        echo json_encode([
            'success' => true,
            'data' => [
                'assets' => $assets,
                'pagination' => [
                    'total' => (int)$total,
                    'limit' => $limit,
                    'offset' => $offset,
                    'has_more' => ($offset + $limit) < $total
                ]
            ],
            'meta' => [
                'authenticated_user' => $apiUser['username'],
                'user_role' => $apiUser['role'],
                'scopes' => $apiUser['scopes']
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Internal server error',
            'timestamp' => date('c')
        ]);
    }
}

function handlePostRequest() {
    global $apiKeyAuth, $apiUser;
    
    try {
        // Check if user has permission to write assets
        if (!$apiKeyAuth->hasScope('assets:write')) {
            http_response_code(403);
            echo json_encode([
                'success' => false,
                'error' => 'Insufficient permissions for assets:write'
            ]);
            return;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => 'Invalid JSON input'
            ]);
            return;
        }
        
        // Validate required fields
        $requiredFields = ['hostname', 'ip_address', 'asset_type'];
        foreach ($requiredFields as $field) {
            if (empty($input[$field])) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => "Missing required field: {$field}"
                ]);
                return;
            }
        }
        
        // Insert new asset
        $db = DatabaseConfig::getInstance();
        $sql = "INSERT INTO assets (hostname, ip_address, asset_type, source, created_at) 
                VALUES (?, ?, ?, 'api', CURRENT_TIMESTAMP) 
                RETURNING asset_id";
        
        $stmt = $db->query($sql, [
            $input['hostname'],
            $input['ip_address'],
            $input['asset_type']
        ]);
        
        $result = $stmt->fetch();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'asset_id' => $result['asset_id'],
                'message' => 'Asset created successfully'
            ],
            'meta' => [
                'authenticated_user' => $apiUser['username'],
                'user_role' => $apiUser['role']
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Internal server error',
            'timestamp' => date('c')
        ]);
    }
}

// Log API usage
$endTime = microtime(true);
$responseTime = round(($endTime - $startTime) * 1000); // Convert to milliseconds
$responseCode = http_response_code();

$apiKeyAuth->logUsage(
    '/api/v1/assets/api-example',
    $_SERVER['REQUEST_METHOD'],
    $responseCode,
    $responseTime,
    strlen(file_get_contents('php://input')), // Request size
    ob_get_length() // Response size
);
