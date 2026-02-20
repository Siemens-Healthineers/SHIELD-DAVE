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
// Temporarily disabled for testing - remove in production
// $auth = new Auth();
// $auth->requireAuth();

// Get current user
// $user = $auth->getCurrentUser();
// if (!$user) {
//     http_response_code(401);
//     echo json_encode(['success' => false, 'error' => 'Authentication required']);
//     exit;
// }

// Get database connection
$db = DatabaseConfig::getInstance();

// Handle different operations
$method = $_SERVER['REQUEST_METHOD'];

//$pathInfo = $_SERVER['PATH_INFO'] ?? '';

$pathInfo = $_GET['path'] ?? '';

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

try {
    switch ($method) {
        case 'GET':
            if (empty($pathInfo) || $pathInfo === '/') {
                handleListPatches($db);
            } else {
                $parts = explode('/', trim($pathInfo, '/'));
                $patchId = $parts[0];
                
                if (count($parts) === 1) {
                    handleGetPatch($db, $patchId);
                } elseif ($parts[1] === 'applications') {
                    handleGetPatchApplications($db, $patchId);
                } else {
                    http_response_code(404);
                    echo json_encode(['success' => false, 'error' => 'Endpoint not found']);
                }
            }
            break;
            
        case 'POST':
            if (empty($pathInfo) || $pathInfo === '/') {
                handleCreatePatch($db, $user);
            } else {
                $parts = explode('/', trim($pathInfo, '/'));
                $patchId = $parts[0];
                
                if (count($parts) === 2 && $parts[1] === 'apply') {
                    handleApplyPatch($db, $patchId, $user);
                } else {
                    http_response_code(404);
                    echo json_encode(['success' => false, 'error' => 'Endpoint not found']);
                }
            }
            break;
            
        case 'PUT':
            if (!empty($pathInfo)) {
                $patchId = trim($pathInfo, '/');
                handleUpdatePatch($db, $patchId, $user);
            } else {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Patch ID required']);
            }
            break;
            
        case 'DELETE':
            if (!empty($pathInfo)) {
                $patchId = trim($pathInfo, '/');
                handleDeletePatch($db, $patchId, $user);
            } else {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Patch ID required']);
            }
            break;
            
        default:
            http_response_code(405);
            echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}

/**
 * Convert time string to minutes (integer)
 * Accepts formats like: "2 hours", "30 minutes", "1.5 hours", "90"
 */
function convertToMinutes($timeInput) {
    if ($timeInput === null || $timeInput === '') {
        return null;
    }
    
    // If already a number, assume it's minutes
    if (is_numeric($timeInput)) {
        return (int)$timeInput;
    }
    
    // Parse string formats
    $timeInput = strtolower(trim($timeInput));
    
    // Match patterns like "2 hours", "30 minutes", "1.5 hours"
    if (preg_match('/^(\d+\.?\d*)\s*(hour|hours|hr|hrs|h)$/i', $timeInput, $matches)) {
        return (int)round(floatval($matches[1]) * 60);
    }
    
    if (preg_match('/^(\d+\.?\d*)\s*(minute|minutes|min|mins|m)$/i', $timeInput, $matches)) {
        return (int)round(floatval($matches[1]));
    }
    
    // If no pattern matched, try to parse as integer
    return is_numeric($timeInput) ? (int)$timeInput : null;
}

/**
 * List all patches
 */
function handleListPatches($db) {
    $activeOnly = isset($_GET['active_only']) && $_GET['active_only'] === 'true';
    $deviceType = isset($_GET['device_type']) ? $_GET['device_type'] : null;
    
    $filters = [];
    $params = [];
    
    if ($activeOnly) {
        $filters[] = "is_active = TRUE";
    }
    
    if ($deviceType) {
        $filters[] = "(target_device_type = ? OR target_device_type IS NULL)";
        $params[] = $deviceType;
    }
    
    $whereClause = !empty($filters) ? 'WHERE ' . implode(' AND ', $filters) : '';
    
    $sql = "SELECT 
                p.*,
                sp.name as package_name,
                sp.vendor as package_vendor,
                u.username as created_by_name,
                (SELECT COUNT(*) FROM patch_applications WHERE patch_id = p.patch_id) as application_count,
                CASE 
                    WHEN p.cve_list IS NULL THEN 0
                    ELSE jsonb_array_length(p.cve_list)
                END as cve_count
            FROM patches p
            LEFT JOIN software_packages sp ON p.target_package_id = sp.package_id
            LEFT JOIN users u ON p.created_by = u.user_id
            $whereClause
            ORDER BY p.created_at DESC";
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $patches = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $patches
    ]);
}

/**
 * Get single patch details
 */
function handleGetPatch($db, $patchId) {
    $sql = "SELECT 
                p.*,
                sp.name as package_name,
                sp.vendor as package_vendor,
                u.username as created_by_name
            FROM patches p
            LEFT JOIN software_packages sp ON p.target_package_id = sp.package_id
            LEFT JOIN users u ON p.created_by = u.user_id
            WHERE p.patch_id = ?";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([$patchId]);
    $patch = $stmt->fetch();
    
    if (!$patch) {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'Patch not found']);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'data' => $patch
    ]);
}

/**
 * Create new patch
 */
function handleCreatePatch($db, $user) {
    $input = json_decode(file_get_contents('php://input'), true);
    
    // Validate required fields
    if (empty($input['patch_name'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Patch name is required']);
        return;
    }
    
    // Validate patch_type
    $validPatchTypes = ['Software Update', 'Firmware', 'Configuration', 'Security Patch', 'Hotfix'];
    $patchType = $input['patch_type'] ?? 'Software Update';
    
    if (!in_array($patchType, $validPatchTypes)) {
        http_response_code(400);
        echo json_encode([
            'success' => false, 
            'error' => 'Invalid patch_type. Allowed values: ' . implode(', ', $validPatchTypes),
            'provided_value' => $patchType
        ]);
        return;
    }
    
    $sql = "INSERT INTO patches (
                patch_name, patch_type, target_device_type, target_package_id,
                target_version, cve_list, description, release_date,
                vendor, kb_article, download_url, install_instructions,
                prerequisites, estimated_install_time, requires_reboot, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING patch_id";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([
        $input['patch_name'],
        $patchType,
        $input['target_device_type'] ?? null,
        $input['target_package_id'] ?? null,
        $input['target_version'] ?? null,
        json_encode($input['cve_list'] ?? []),
        $input['description'] ?? null,
        $input['release_date'] ?? null,
        $input['vendor'] ?? null,
        $input['kb_article'] ?? null,
        $input['download_url'] ?? null,
        $input['install_instructions'] ?? null,
        $input['prerequisites'] ?? null,
        convertToMinutes($input['estimated_install_time'] ?? null),
        isset($input['requires_reboot']) ? ($input['requires_reboot'] ? 'true' : 'false') : 'false',
        $user['user_id']
    ]);
    
    $result = $stmt->fetch();
    $patchId = $result['patch_id'];
    
    // Log the action
    logPatchAudit($db, $user['user_id'], 'CREATE_PATCH', 'patches', $patchId, [
        'patch_name' => $input['patch_name']
    ]);
    
    echo json_encode([
        'success' => true,
        'message' => 'Patch created successfully',
        'patch_id' => $patchId
    ]);
}

/**
 * Update existing patch
 */
function handleUpdatePatch($db, $patchId, $user) {
    // Check if user has admin permission
    if ($user['role'] !== 'Admin') {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Admin access required']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    // Validate patch_type if provided
    if (isset($input['patch_type'])) {
        $validPatchTypes = ['Software Update', 'Firmware', 'Configuration', 'Security Patch', 'Hotfix'];
        
        if (!in_array($input['patch_type'], $validPatchTypes)) {
            http_response_code(400);
            echo json_encode([
                'success' => false, 
                'error' => 'Invalid patch_type. Allowed values: ' . implode(', ', $validPatchTypes),
                'provided_value' => $input['patch_type']
            ]);
            return;
        }
    }
    
    $sql = "UPDATE patches SET
                patch_name = COALESCE(?, patch_name),
                patch_type = COALESCE(?, patch_type),
                target_device_type = COALESCE(?, target_device_type),
                target_package_id = COALESCE(?, target_package_id),
                target_version = COALESCE(?, target_version),
                cve_list = COALESCE(?, cve_list),
                description = COALESCE(?, description),
                release_date = COALESCE(?, release_date),
                vendor = COALESCE(?, vendor),
                kb_article = COALESCE(?, kb_article),
                download_url = COALESCE(?, download_url),
                install_instructions = COALESCE(?, install_instructions),
                prerequisites = COALESCE(?, prerequisites),
                estimated_install_time = COALESCE(?, estimated_install_time),
                requires_reboot = COALESCE(?, requires_reboot),
                is_active = COALESCE(?, is_active),
                updated_at = CURRENT_TIMESTAMP
            WHERE patch_id = ?";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([
        $input['patch_name'] ?? null,
        $input['patch_type'] ?? null,
        $input['target_device_type'] ?? null,
        $input['target_package_id'] ?? null,
        $input['target_version'] ?? null,
        isset($input['cve_list']) ? json_encode($input['cve_list']) : null,
        $input['description'] ?? null,
        $input['release_date'] ?? null,
        $input['vendor'] ?? null,
        $input['kb_article'] ?? null,
        $input['download_url'] ?? null,
        $input['install_instructions'] ?? null,
        $input['prerequisites'] ?? null,
        isset($input['estimated_install_time']) ? convertToMinutes($input['estimated_install_time']) : null,
        isset($input['requires_reboot']) ? ($input['requires_reboot'] ? 'true' : 'false') : null,
        $input['is_active'] ?? null,
        $patchId
    ]);
    
    // Log the action
    logPatchAudit($db, $user['user_id'], 'UPDATE_PATCH', 'patches', $patchId, $input);
    
    echo json_encode([
        'success' => true,
        'message' => 'Patch updated successfully'
    ]);
}

/**
 * Delete (deactivate) patch
 */
function handleDeletePatch($db, $patchId, $user) {
    // Check if user has admin permission
    if ($user['role'] !== 'Admin') {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Admin access required']);
        return;
    }
    
    $sql = "UPDATE patches SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE patch_id = ?";
    $stmt = $db->prepare($sql);
    $stmt->execute([$patchId]);
    
    // Log the action
    logPatchAudit($db, $user['user_id'], 'DELETE_PATCH', 'patches', $patchId, []);
    
    echo json_encode([
        'success' => true,
        'message' => 'Patch deactivated successfully'
    ]);
}

/**
 * Apply patch to asset(s)
 */
function handleApplyPatch($db, $patchId, $user) {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (empty($input['asset_ids']) || !is_array($input['asset_ids'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Asset IDs array required']);
        return;
    }
    
    $result = applyPatch(
        $patchId,
        $input['asset_ids'],
        $user['user_id'],
        $input['verification_status'] ?? 'Pending',
        $input['verification_method'] ?? 'Manual',
        $input['notes'] ?? ''
    );
    
    echo json_encode($result);
}

/**
 * Get patch application history
 */
function handleGetPatchApplications($db, $patchId) {
    $sql = "SELECT 
                pa.*,
                a.hostname,
                a.ip_address,
                md.brand_name as device_name,
                u1.username as applied_by_name,
                u2.username as verified_by_name
            FROM patch_applications pa
            JOIN assets a ON pa.asset_id = a.asset_id
            LEFT JOIN medical_devices md ON pa.device_id = md.device_id
            LEFT JOIN users u1 ON pa.applied_by = u1.user_id
            LEFT JOIN users u2 ON pa.verified_by = u2.user_id
            WHERE pa.patch_id = ?
            ORDER BY pa.applied_at DESC";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([$patchId]);
    $applications = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $applications
    ]);
}

/**
 * Helper function to log patch-related audit trail
 */
function logPatchAudit($db, $userId, $action, $entityType, $entityId, $details) {
    $sql = "INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values, ip_address, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([
        $userId,
        $action,
        $entityType,
        $entityId,
        json_encode($details),
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ]);
}

