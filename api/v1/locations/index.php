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
require_once __DIR__ . '/../../../includes/auth.php';

// Set JSON response headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight OPTIONS request
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Initialize authentication
$auth = new Auth();
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

// Check if user has admin privileges for write operations
$isAdmin = $user['role'] === 'Admin';

try {
    $db = DatabaseConfig::getInstance();
    $pdo = $db->getConnection();
    
    $method = $_SERVER['REQUEST_METHOD'];
    $path = $_SERVER['PATH_INFO'] ?? '';
    
    switch ($method) {
        case 'GET':
            // Check if requesting specific location via query parameter or path
            $locationId = $_GET['id'] ?? null;
            if (empty($path) || $path === '/') {
                if ($locationId) {
                    // GET /api/v1/locations?id=... - Get specific location
                    handleGetLocation($pdo, $locationId, $user);
                } else {
                    // GET /api/v1/locations - List all locations
                    handleGetLocations($pdo, $user);
                }
            } else {
                // GET /api/v1/locations/{id} - Get specific location
                $locationId = trim($path, '/');
                handleGetLocation($pdo, $locationId, $user);
            }
            break;
            
        case 'POST':
            if (!$isAdmin) {
                http_response_code(403);
                echo json_encode(['error' => 'Admin privileges required']);
                exit;
            }
            // POST /api/v1/locations - Create new location
            handleCreateLocation($pdo, $user);
            break;
            
        case 'PUT':
            if (!$isAdmin) {
                http_response_code(403);
                echo json_encode(['error' => 'Admin privileges required']);
                exit;
            }
            // PUT /api/v1/locations/{id} - Update location
            $locationId = trim($path, '/');
            handleUpdateLocation($pdo, $locationId, $user);
            break;
            
        case 'DELETE':
            if (!$isAdmin) {
                http_response_code(403);
                echo json_encode(['error' => 'Admin privileges required']);
                exit;
            }
            // DELETE /api/v1/locations/{id} - Delete location
            $locationId = trim($path, '/');
            handleDeleteLocation($pdo, $locationId, $user);
            break;
            
        default:
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            break;
    }
    
} catch (Exception $e) {
    error_log("Location API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error']);
}

/**
 * Handle GET /api/v1/locations - List all locations with optional filters
 */
function handleGetLocations($pdo, $user) {
    $filters = [
        'type' => $_GET['type'] ?? null,
        'parent_id' => $_GET['parent_id'] ?? null,
        'criticality_min' => $_GET['criticality_min'] ?? null,
        'criticality_max' => $_GET['criticality_max'] ?? null,
        'active_only' => $_GET['active_only'] ?? 'true',
        'include_hierarchy' => $_GET['include_hierarchy'] ?? 'true'
    ];
    
    $sql = "SELECT 
                l.location_id,
                l.parent_location_id,
                l.location_name,
                l.location_type,
                l.location_code,
                l.description,
                l.criticality,
                l.is_active,
                l.created_at,
                l.updated_at,
                u.username as created_by_username,
                parent.location_name as parent_location_name,
                parent.location_code as parent_location_code,
                (SELECT COUNT(*) FROM locations child WHERE child.parent_location_id = l.location_id) as child_count,
                (SELECT COUNT(*) FROM assets a WHERE a.location_id = l.location_id) as asset_count
            FROM locations l
            LEFT JOIN users u ON l.created_by = u.user_id
            LEFT JOIN locations parent ON l.parent_location_id = parent.location_id";
    
    $conditions = [];
    $params = [];
    
    if ($filters['type']) {
        $conditions[] = "l.location_type = ?";
        $params[] = $filters['type'];
    }
    
    if ($filters['parent_id']) {
        if ($filters['parent_id'] === 'null') {
            $conditions[] = "l.parent_location_id IS NULL";
        } else {
            $conditions[] = "l.parent_location_id = ?";
            $params[] = $filters['parent_id'];
        }
    }
    
    if ($filters['criticality_min']) {
        $conditions[] = "l.criticality >= ?";
        $params[] = $filters['criticality_min'];
    }
    
    if ($filters['criticality_max']) {
        $conditions[] = "l.criticality <= ?";
        $params[] = $filters['criticality_max'];
    }
    
    if ($filters['active_only'] === 'true') {
        $conditions[] = "l.is_active = TRUE";
    }
    
    if (!empty($conditions)) {
        $sql .= " WHERE " . implode(" AND ", $conditions);
    }
    
    $sql .= " ORDER BY l.location_type, l.location_name";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $locations = $stmt->fetchAll();
    
    // Get IP ranges for each location
    foreach ($locations as &$location) {
        $location['ip_ranges'] = getLocationIpRanges($pdo, $location['location_id']);
    }
    
    // Build hierarchy if requested
    if ($filters['include_hierarchy'] === 'true') {
        $locations = buildLocationHierarchy($locations);
    }
    
    echo json_encode([
        'success' => true,
        'data' => $locations,
        'count' => count($locations)
    ]);
}

/**
 * Handle GET /api/v1/locations/{id} - Get specific location with hierarchy
 */
function handleGetLocation($pdo, $locationId, $user) {
    if (!isValidUuid($locationId)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid location ID']);
        return;
    }
    
    $sql = "SELECT 
                l.location_id,
                l.parent_location_id,
                l.location_name,
                l.location_type,
                l.location_code,
                l.description,
                l.criticality,
                l.is_active,
                l.created_at,
                l.updated_at,
                u.username as created_by_username,
                parent.location_name as parent_location_name,
                parent.location_code as parent_location_code
            FROM locations l
            LEFT JOIN users u ON l.created_by = u.user_id
            LEFT JOIN locations parent ON l.parent_location_id = parent.location_id
            WHERE l.location_id = ?";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$locationId]);
    $location = $stmt->fetch();
    
    if (!$location) {
        http_response_code(404);
        echo json_encode(['error' => 'Location not found']);
        return;
    }
    
    // Get IP ranges
    $location['ip_ranges'] = getLocationIpRanges($pdo, $locationId);
    
    // Get hierarchy path
    $location['hierarchy_path'] = getLocationHierarchyPath($pdo, $locationId);
    
    // Get child locations
    $location['children'] = getChildLocations($pdo, $locationId);
    
    // Get assigned assets
    $location['assets'] = getLocationAssets($pdo, $locationId);
    
    echo json_encode([
        'success' => true,
        'data' => $location
    ]);
}

/**
 * Handle POST /api/v1/locations - Create new location
 */
function handleCreateLocation($pdo, $user) {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON input']);
        return;
    }
    
    // Validate required fields
    $required = ['location_name', 'location_type', 'criticality'];
    foreach ($required as $field) {
        if (!isset($input[$field]) || empty($input[$field])) {
            http_response_code(400);
            echo json_encode(['error' => "Missing required field: $field"]);
            return;
        }
    }
    
    // Validate criticality
    if (!is_numeric($input['criticality']) || $input['criticality'] < 1 || $input['criticality'] > 10) {
        http_response_code(400);
        echo json_encode(['error' => 'Criticality must be between 1 and 10']);
        return;
    }
    
    // Validate location type
    $validTypes = ['Building', 'Floor', 'Department', 'Ward', 'Lab', 'Room', 'Other'];
    if (!in_array($input['location_type'], $validTypes)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid location type']);
        return;
    }
    
    // Validate parent location if provided
    if (!empty($input['parent_location_id'])) {
        if (!isValidUuid($input['parent_location_id'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid parent location ID']);
            return;
        }
        
        $stmt = $pdo->prepare("SELECT location_id FROM locations WHERE location_id = ? AND is_active = TRUE");
        $stmt->execute([$input['parent_location_id']]);
        if (!$stmt->fetch()) {
            http_response_code(400);
            echo json_encode(['error' => 'Parent location not found']);
            return;
        }
    }
    
    // Generate location code if not provided
    if (empty($input['location_code'])) {
        $input['location_code'] = generateLocationCode($pdo, $input['location_name'], $input['parent_location_id'] ?? null);
    } else {
        // Check if location code already exists
        $stmt = $pdo->prepare("SELECT location_id FROM locations WHERE location_code = ?");
        $stmt->execute([$input['location_code']]);
        if ($stmt->fetch()) {
            http_response_code(400);
            echo json_encode(['error' => 'Location code already exists']);
            return;
        }
    }
    
    try {
        $pdo->beginTransaction();
        
        // Insert location
        $sql = "INSERT INTO locations (
                    parent_location_id, location_name, location_type, location_code,
                    description, criticality, is_active, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING location_id";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            $input['parent_location_id'] ?? null,
            $input['location_name'],
            $input['location_type'],
            $input['location_code'],
            $input['description'] ?? null,
            $input['criticality'],
            $input['is_active'] ?? true,
            $user['user_id']
        ]);
        
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        $locationId = $result['location_id'];
        
        // Add IP ranges if provided
        if (!empty($input['ip_ranges'])) {
            addLocationIpRanges($pdo, $locationId, $input['ip_ranges']);
        }
        
        $pdo->commit();
        
        // Return created location
        handleGetLocation($pdo, $locationId, $user);
        
    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Error creating location: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Failed to create location']);
    }
}

/**
 * Handle PUT /api/v1/locations/{id} - Update location
 */
function handleUpdateLocation($pdo, $locationId, $user) {
    if (!isValidUuid($locationId)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid location ID']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON input']);
        return;
    }
    
    // Check if location exists
    $stmt = $pdo->prepare("SELECT location_id FROM locations WHERE location_id = ?");
    $stmt->execute([$locationId]);
    if (!$stmt->fetch()) {
        http_response_code(404);
        echo json_encode(['error' => 'Location not found']);
        return;
    }
    
    // Validate criticality if provided
    if (isset($input['criticality'])) {
        if (!is_numeric($input['criticality']) || $input['criticality'] < 1 || $input['criticality'] > 10) {
            http_response_code(400);
            echo json_encode(['error' => 'Criticality must be between 1 and 10']);
            return;
        }
    }
    
    // Validate location type if provided
    if (isset($input['location_type'])) {
        $validTypes = ['Building', 'Floor', 'Department', 'Ward', 'Lab', 'Room', 'Other'];
        if (!in_array($input['location_type'], $validTypes)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid location type']);
            return;
        }
    }
    
    // Validate parent location if provided
    if (isset($input['parent_location_id'])) {
        if ($input['parent_location_id'] !== null) {
            if (!isValidUuid($input['parent_location_id'])) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid parent location ID']);
                return;
            }
            
            // Prevent setting parent to self or descendant
            if ($input['parent_location_id'] === $locationId) {
                http_response_code(400);
                echo json_encode(['error' => 'Location cannot be its own parent']);
                return;
            }
            
            if (isDescendantLocation($pdo, $locationId, $input['parent_location_id'])) {
                http_response_code(400);
                echo json_encode(['error' => 'Location cannot be parent of its descendant']);
                return;
            }
            
            $stmt = $pdo->prepare("SELECT location_id FROM locations WHERE location_id = ? AND is_active = TRUE");
            $stmt->execute([$input['parent_location_id']]);
            if (!$stmt->fetch()) {
                http_response_code(400);
                echo json_encode(['error' => 'Parent location not found']);
                return;
            }
        }
    }
    
    try {
        $pdo->beginTransaction();
        
        // Build update query
        $updateFields = [];
        $params = [];
        
        $allowedFields = ['parent_location_id', 'location_name', 'location_type', 'location_code', 
                         'description', 'criticality', 'is_active'];
        
        foreach ($allowedFields as $field) {
            if (isset($input[$field])) {
                $updateFields[] = "$field = ?";
                $params[] = $input[$field];
            }
        }
        
        if (empty($updateFields)) {
            http_response_code(400);
            echo json_encode(['error' => 'No valid fields to update']);
            return;
        }
        
        $params[] = $locationId;
        
        $sql = "UPDATE locations SET " . implode(', ', $updateFields) . " WHERE location_id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        
        // Update IP ranges if provided
        if (isset($input['ip_ranges'])) {
            // Delete existing ranges
            $stmt = $pdo->prepare("DELETE FROM location_ip_ranges WHERE location_id = ?");
            $stmt->execute([$locationId]);
            
            // Add new ranges
            if (!empty($input['ip_ranges'])) {
                addLocationIpRanges($pdo, $locationId, $input['ip_ranges']);
            }
        }
        
        $pdo->commit();
        
        // Return updated location
        handleGetLocation($pdo, $locationId, $user);
        
    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Error updating location: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Failed to update location']);
    }
}

/**
 * Handle DELETE /api/v1/locations/{id} - Delete location
 */
function handleDeleteLocation($pdo, $locationId, $user) {
    if (!isValidUuid($locationId)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid location ID']);
        return;
    }
    
    // Check if location exists
    $stmt = $pdo->prepare("SELECT location_id FROM locations WHERE location_id = ?");
    $stmt->execute([$locationId]);
    if (!$stmt->fetch()) {
        http_response_code(404);
        echo json_encode(['error' => 'Location not found']);
        return;
    }
    
    // Check for child locations
    $stmt = $pdo->prepare("SELECT COUNT(*) as child_count FROM locations WHERE parent_location_id = ?");
    $stmt->execute([$locationId]);
    $result = $stmt->fetch();
    
    if ($result['child_count'] > 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Cannot delete location with child locations']);
        return;
    }
    
    // Check for assigned assets
    $stmt = $pdo->prepare("SELECT COUNT(*) as asset_count FROM assets WHERE location_id = ?");
    $stmt->execute([$locationId]);
    $result = $stmt->fetch();
    
    if ($result['asset_count'] > 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Cannot delete location with assigned assets']);
        return;
    }
    
    try {
        $pdo->beginTransaction();
        
        // Delete IP ranges first
        $stmt = $pdo->prepare("DELETE FROM location_ip_ranges WHERE location_id = ?");
        $stmt->execute([$locationId]);
        
        // Delete location
        $stmt = $pdo->prepare("DELETE FROM locations WHERE location_id = ?");
        $stmt->execute([$locationId]);
        
        $pdo->commit();
        
        echo json_encode([
            'success' => true,
            'message' => 'Location deleted successfully'
        ]);
        
    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Error deleting location: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Failed to delete location']);
    }
}

// Helper functions

function getLocationIpRanges($pdo, $locationId) {
    $sql = "SELECT range_id, range_format, cidr_notation, start_ip, end_ip, description 
            FROM location_ip_ranges 
            WHERE location_id = ? 
            ORDER BY range_format, cidr_notation, start_ip";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$locationId]);
    return $stmt->fetchAll();
}

function buildLocationHierarchy($locations) {
    $hierarchy = [];
    $locationMap = [];
    
    // Create a map of locations by ID
    foreach ($locations as $location) {
        $locationMap[$location['location_id']] = $location;
        $locationMap[$location['location_id']]['children'] = [];
    }
    
    // Build hierarchy
    foreach ($locations as $location) {
        if ($location['parent_location_id']) {
            if (isset($locationMap[$location['parent_location_id']])) {
                $locationMap[$location['parent_location_id']]['children'][] = &$locationMap[$location['location_id']];
            }
        } else {
            $hierarchy[] = &$locationMap[$location['location_id']];
        }
    }
    
    return $hierarchy;
}

function getLocationHierarchyPath($pdo, $locationId) {
    $sql = "SELECT hierarchy_path FROM location_hierarchy WHERE location_id = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$locationId]);
    $result = $stmt->fetch();
    return $result ? $result['hierarchy_path'] : null;
}

function getChildLocations($pdo, $locationId) {
    $sql = "SELECT location_id, location_name, location_type, location_code, criticality, is_active
            FROM locations 
            WHERE parent_location_id = ? AND is_active = TRUE
            ORDER BY location_type, location_name";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$locationId]);
    return $stmt->fetchAll();
}

function getLocationAssets($pdo, $locationId) {
    $sql = "SELECT asset_id, hostname, ip_address, asset_type, criticality, status
            FROM assets 
            WHERE location_id = ?
            ORDER BY hostname";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$locationId]);
    return $stmt->fetchAll();
}

function generateLocationCode($pdo, $locationName, $parentId = null) {
    // Generate a simple code from location name
    $code = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $locationName));
    $code = substr($code, 0, 10);
    
    // Add parent prefix if exists
    if ($parentId) {
        $stmt = $pdo->prepare("SELECT location_code FROM locations WHERE location_id = ?");
        $stmt->execute([$parentId]);
        $parent = $stmt->fetch();
        if ($parent) {
            $code = $parent['location_code'] . '-' . $code;
        }
    }
    
    // Ensure uniqueness
    $originalCode = $code;
    $counter = 1;
    
    while (true) {
        $stmt = $pdo->prepare("SELECT location_id FROM locations WHERE location_code = ?");
        $stmt->execute([$code]);
        if (!$stmt->fetch()) {
            break;
        }
        $code = $originalCode . $counter;
        $counter++;
    }
    
    return $code;
}

function addLocationIpRanges($pdo, $locationId, $ipRanges) {
    foreach ($ipRanges as $range) {
        if (empty($range['range_format'])) {
            continue;
        }
        
        $sql = "INSERT INTO location_ip_ranges (location_id, range_format, cidr_notation, start_ip, end_ip, description)
                VALUES (?, ?, ?, ?, ?, ?)";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            $locationId,
            $range['range_format'],
            $range['range_format'] === 'CIDR' ? $range['cidr_notation'] : null,
            $range['range_format'] === 'StartEnd' ? $range['start_ip'] : null,
            $range['range_format'] === 'StartEnd' ? $range['end_ip'] : null,
            $range['description'] ?? null
        ]);
    }
}

function isDescendantLocation($pdo, $locationId, $potentialParentId) {
    $sql = "WITH RECURSIVE location_tree AS (
                SELECT location_id, parent_location_id
                FROM locations
                WHERE location_id = ?
                UNION ALL
                SELECT l.location_id, l.parent_location_id
                FROM locations l
                JOIN location_tree lt ON l.parent_location_id = lt.location_id
            )
            SELECT COUNT(*) as count FROM location_tree WHERE location_id = ?";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$potentialParentId, $locationId]);
    $result = $stmt->fetch();
    
    return $result['count'] > 0;
}

function isValidUuid($uuid) {
    return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uuid);
}
