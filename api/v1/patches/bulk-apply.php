<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../config/database.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';
require_once __DIR__ . '/../../../includes/patch-processor.php';

header('Content-Type: application/json');

// Initialize authentication
$auth = new Auth();
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Authentication required']);
    exit;
}

// Only handle POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

// Get database connection
$db = DatabaseConfig::getInstance();

try {
    $input = json_decode(file_get_contents('php://input'), true);
    
    // Validate input
    if (empty($input['patch_id'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Patch ID is required']);
        exit;
    }
    
    if (empty($input['asset_ids']) || !is_array($input['asset_ids'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Asset IDs array is required']);
        exit;
    }
    
    // Apply patch to all assets
    $result = applyPatch(
        $input['patch_id'],
        $input['asset_ids'],
        $user['user_id'],
        $input['verification_status'] ?? 'Pending',
        $input['verification_method'] ?? 'Manual',
        $input['notes'] ?? ''
    );
    
    if ($result['success']) {
        // Log bulk application
        $sql = "INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values, ip_address, user_agent, timestamp)
                VALUES (?, 'BULK_PATCH_APPLY', 'patches', ?, ?, ?, ?, CURRENT_TIMESTAMP)";
        
        $stmt = $db->prepare($sql);
        $stmt->execute([
            $user['user_id'],
            $input['patch_id'],
            json_encode([
                'asset_count' => count($input['asset_ids']),
                'applications_created' => $result['applications_created'],
                'vulnerabilities_closed' => $result['vulnerabilities_closed']
            ]),
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ]);
    }
    
    echo json_encode($result);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}

