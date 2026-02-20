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

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
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

$db = DatabaseConfig::getInstance();
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
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'METHOD_NOT_ALLOWED',
                'message' => 'Method not allowed'
            ],
            'timestamp' => date('c')
        ]);
        break;
}

function handleGetRequest($path) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to read components
    $unifiedAuth->requirePermission('components', 'read');
    
    try {
        if (empty($path)) {
            // List all components
            listComponents();
        } else {
            // Get specific component
            getComponent($path);
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

function handlePostRequest($path) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to create components
    $unifiedAuth->requirePermission('components', 'write');
    
    try {
        if (empty($path)) {
            // Create new component
            createComponent();
        } else {
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'NOT_FOUND',
                    'message' => 'Endpoint not found'
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

function handlePutRequest($path) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to update components
    $unifiedAuth->requirePermission('components', 'write');
    
    try {
        if (!empty($path)) {
            // Update existing component
            updateComponent($path);
        } else {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'BAD_REQUEST',
                    'message' => 'Component ID required'
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

function handleDeleteRequest($path) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to delete components
    $unifiedAuth->requirePermission('components', 'delete');
    
    try {
        if (!empty($path)) {
            // Delete component
            deleteComponent($path);
        } else {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'BAD_REQUEST',
                    'message' => 'Component ID required'
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

/**
 * List all software components
 */
function listComponents() {
    global $db;
    
    $limit = isset($_GET['limit']) ? min((int)$_GET['limit'], 1000) : 100;
    $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;
    $search = $_GET['search'] ?? '';
    
    $sql = "SELECT 
                component_id,
                sbom_id,
                name,
                version,
                vendor,
                license,
                purl,
                cpe,
                created_at,
                package_id,
                version_id
            FROM software_components
            WHERE 1=1";
    
    $params = [];
    
    if (!empty($search)) {
        $sql .= " AND (name ILIKE ? OR vendor ILIKE ? OR version ILIKE ?)";
        $searchTerm = "%{$search}%";
        $params = [$searchTerm, $searchTerm, $searchTerm];
    }
    
    // Optionally filter by sbom_id (NULL for independent components)
    if (isset($_GET['independent_only']) && $_GET['independent_only'] === 'true') {
        $sql .= " AND sbom_id IS NULL";
    }
    
    $sql .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
    $params[] = $limit;
    $params[] = $offset;
    
    $stmt = $db->query($sql, $params);
    $components = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get total count
    $countSql = "SELECT COUNT(*) FROM software_components WHERE 1=1";
    if (!empty($search)) {
        $countSql .= " AND (name ILIKE ? OR vendor ILIKE ? OR version ILIKE ?)";
    }
    if (isset($_GET['independent_only']) && $_GET['independent_only'] === 'true') {
        $countSql .= " AND sbom_id IS NULL";
    }
    
    $countParams = !empty($search) ? ["%{$search}%", "%{$search}%", "%{$search}%"] : [];
    $countStmt = $db->query($countSql, $countParams);
    $total = $countStmt->fetchColumn();
    
    echo json_encode([
        'success' => true,
        'data' => $components,
        'pagination' => [
            'total' => (int)$total,
            'limit' => $limit,
            'offset' => $offset,
            'has_more' => ($offset + $limit) < $total
        ],
        'timestamp' => date('c')
    ]);
}

/**
 * Get a specific software component
 */
function getComponent($componentId) {
    global $db;
    
    $stmt = $db->query(
        "SELECT 
            component_id,
            sbom_id,
            name,
            version,
            vendor,
            license,
            purl,
            cpe,
            created_at,
            package_id,
            version_id
        FROM software_components
        WHERE component_id = ?",
        [$componentId]
    );
    
    $component = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$component) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'COMPONENT_NOT_FOUND',
                'message' => 'Software component not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'data' => $component,
        'timestamp' => date('c')
    ]);
}

/**
 * Create a new software component
 */
function createComponent() {
    global $db;
    
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_JSON',
                'message' => 'Invalid JSON input'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Validate required fields
    if (empty($input['name'])) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'MISSING_REQUIRED_FIELD',
                'message' => 'Field "name" is required'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    try {
        // Generate component ID
        $componentId = $db->query("SELECT uuid_generate_v4()")->fetchColumn();
        
        // Insert component (sbom_id is NULL for independent components)
        $sql = "INSERT INTO software_components (
            component_id,
            sbom_id,
            name,
            version,
            vendor,
            license,
            purl,
            cpe,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        RETURNING component_id";
        
        $params = [
            $componentId,
            null, // sbom_id is NULL for independent components
            trim($input['name']),
            !empty($input['version']) ? trim($input['version']) : null,
            !empty($input['vendor']) ? trim($input['vendor']) : null,
            !empty($input['license']) ? trim($input['license']) : null,
            !empty($input['purl']) ? trim($input['purl']) : null,
            !empty($input['cpe']) ? trim($input['cpe']) : null
        ];
        
        $stmt = $db->query($sql, $params);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Get the created component
        $stmt = $db->query(
            "SELECT 
                component_id,
                sbom_id,
                name,
                version,
                vendor,
                license,
                purl,
                cpe,
                created_at,
                package_id,
                version_id
            FROM software_components
            WHERE component_id = ?",
            [$result['component_id']]
        );
        
        $component = $stmt->fetch(PDO::FETCH_ASSOC);
        
        http_response_code(201);
        echo json_encode([
            'success' => true,
            'message' => 'Software component created successfully',
            'data' => $component,
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'CREATION_FAILED',
                'message' => 'Failed to create software component: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

/**
 * Update an existing software component
 */
function updateComponent($componentId) {
    global $db;
    
    // Check if component exists
    $checkStmt = $db->query(
        "SELECT component_id FROM software_components WHERE component_id = ?",
        [$componentId]
    );
    
    if (!$checkStmt->fetch()) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'COMPONENT_NOT_FOUND',
                'message' => 'Software component not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_JSON',
                'message' => 'Invalid JSON input'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    try {
        // Build update query dynamically based on provided fields
        $updateFields = [];
        $params = [];
        
        $allowedFields = ['name', 'version', 'vendor', 'license', 'purl', 'cpe'];
        
        foreach ($allowedFields as $field) {
            if (isset($input[$field])) {
                $updateFields[] = "{$field} = ?";
                $params[] = !empty($input[$field]) ? trim($input[$field]) : null;
            }
        }
        
        if (empty($updateFields)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'NO_FIELDS_TO_UPDATE',
                    'message' => 'No valid fields provided for update'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        $params[] = $componentId;
        
        $sql = "UPDATE software_components 
                SET " . implode(', ', $updateFields) . "
                WHERE component_id = ?
                RETURNING component_id";
        
        $stmt = $db->query($sql, $params);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Get the updated component
        $stmt = $db->query(
            "SELECT 
                component_id,
                sbom_id,
                name,
                version,
                vendor,
                license,
                purl,
                cpe,
                created_at,
                package_id,
                version_id
            FROM software_components
            WHERE component_id = ?",
            [$componentId]
        );
        
        $component = $stmt->fetch(PDO::FETCH_ASSOC);
        
        echo json_encode([
            'success' => true,
            'message' => 'Software component updated successfully',
            'data' => $component,
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'UPDATE_FAILED',
                'message' => 'Failed to update software component: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

/**
 * Delete a software component
 */
function deleteComponent($componentId) {
    global $db;
    
    // Check if component exists
    $checkStmt = $db->query(
        "SELECT component_id FROM software_components WHERE component_id = ?",
        [$componentId]
    );
    
    if (!$checkStmt->fetch()) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'COMPONENT_NOT_FOUND',
                'message' => 'Software component not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Check if component is linked to vulnerabilities
    $linkCheck = $db->query(
        "SELECT COUNT(*) FROM device_vulnerabilities_link WHERE component_id = ?",
        [$componentId]
    );
    
    $linkCount = $linkCheck->fetchColumn();
    
    if ($linkCount > 0) {
        http_response_code(409);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'COMPONENT_IN_USE',
                'message' => 'Cannot delete component: it is linked to ' . $linkCount . ' vulnerability(ies)'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    try {
        $db->query(
            "DELETE FROM software_components WHERE component_id = ?",
            [$componentId]
        );
        
        echo json_encode([
            'success' => true,
            'message' => 'Software component deleted successfully',
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'DELETION_FAILED',
                'message' => 'Failed to delete software component: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

