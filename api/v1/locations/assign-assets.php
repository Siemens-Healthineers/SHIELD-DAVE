<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Suppress PHP notices and warnings for clean JSON output
error_reporting(E_ERROR | E_PARSE);

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../config/database.php';

// Set JSON response headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight OPTIONS request
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Authentication required
require_once __DIR__ . '/../../../includes/unified-auth.php';

$unifiedAuth = new UnifiedAuth();
if (!$unifiedAuth->authenticate()) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$user = $unifiedAuth->getCurrentUser();

try {
    $db = DatabaseConfig::getInstance();
    $pdo = $db->getConnection();
    
    $method = $_SERVER['REQUEST_METHOD'];
    $path = $_SERVER['PATH_INFO'] ?? '';
    
    switch ($method) {
        case 'POST':
            if (empty($path) || $path === '/') {
                // POST /api/v1/locations/assign-assets - Run auto-assignment for all assets
                handleAutoAssignAllAssets($pdo);
            } else {
                // POST /api/v1/locations/assign-assets/{location_id} - Assign assets for specific location
                $locationId = trim($path, '/');
                handleAutoAssignLocationAssets($pdo, $locationId);
            }
            break;
            
        case 'GET':
            if (preg_match('/^\/check-ip\/(.+)$/', $path, $matches)) {
                // GET /api/v1/locations/assign-assets/check-ip/{ip} - Check which location an IP belongs to
                $ipAddress = $matches[1];
                handleCheckIpLocation($pdo, $ipAddress);
            } else {
                http_response_code(404);
                echo json_encode(['error' => 'Endpoint not found']);
            }
            break;
            
        default:
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            break;
    }
    
} catch (Exception $e) {
    error_log("Location Assignment API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error']);
}

/**
 * Handle POST /api/v1/locations/assign-assets - Run auto-assignment for all assets
 */
function handleAutoAssignAllAssets($pdo) {
    $input = json_decode(file_get_contents('php://input'), true);
    
    $options = [
        'force_reassign' => $input['force_reassign'] ?? false,
        'dry_run' => $input['dry_run'] ?? false,
        'location_id' => $input['location_id'] ?? null
    ];
    
    try {
        $pdo->beginTransaction();
        
        $results = autoAssignAssetLocations($pdo, $options);
        
        if (!$options['dry_run']) {
            $pdo->commit();
        } else {
            $pdo->rollBack();
        }
        
        echo json_encode([
            'success' => true,
            'dry_run' => $options['dry_run'],
            'results' => $results
        ]);
        
    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Error in auto-assignment: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Auto-assignment failed']);
    }
}

/**
 * Handle POST /api/v1/locations/assign-assets/{location_id} - Assign assets for specific location
 */
function handleAutoAssignLocationAssets($pdo, $locationId) {
    if (!isValidUuid($locationId)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid location ID']);
        return;
    }
    
    // Check if location exists
    $stmt = $pdo->prepare("SELECT location_id, location_name FROM locations WHERE location_id = ? AND is_active = TRUE");
    $stmt->execute([$locationId]);
    $location = $stmt->fetch();
    
    if (!$location) {
        http_response_code(404);
        echo json_encode(['error' => 'Location not found']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    $options = [
        'force_reassign' => $input['force_reassign'] ?? false,
        'dry_run' => $input['dry_run'] ?? false,
        'location_id' => $locationId
    ];
    
    try {
        $pdo->beginTransaction();
        
        $results = autoAssignAssetLocations($pdo, $options);
        
        if (!$options['dry_run']) {
            $pdo->commit();
        } else {
            $pdo->rollBack();
        }
        
        echo json_encode([
            'success' => true,
            'location' => $location,
            'dry_run' => $options['dry_run'],
            'results' => $results
        ]);
        
    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Error in location-specific auto-assignment: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Auto-assignment failed']);
    }
}

/**
 * Handle GET /api/v1/locations/assign-assets/check-ip/{ip} - Check which location an IP belongs to
 */
function handleCheckIpLocation($pdo, $ipAddress) {
    // Validate IP address
    if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid IP address']);
        return;
    }
    
    try {
        $locations = findLocationByIp($pdo, $ipAddress);
        
        echo json_encode([
            'success' => true,
            'ip_address' => $ipAddress,
            'locations' => $locations
        ]);
        
    } catch (Exception $e) {
        error_log("Error checking IP location: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Failed to check IP location']);
    }
}

/**
 * Auto-assign asset locations based on IP addresses
 */
function autoAssignAssetLocations($pdo, $options) {
    $results = [
        'processed' => 0,
        'assigned' => 0,
        'updated' => 0,
        'skipped' => 0,
        'errors' => 0,
        'assignments' => [],
        'errors_list' => []
    ];
    
    // Build query to get assets that need location assignment
    $sql = "SELECT asset_id, hostname, ip_address, location_id, location_assignment_method
            FROM assets 
            WHERE ip_address IS NOT NULL";
    
    $params = [];
    
    if (!$options['force_reassign']) {
        $sql .= " AND (location_id IS NULL OR location_assignment_method != 'Manual')";
    }
    
    if ($options['location_id']) {
        $sql .= " AND location_id = ?";
        $params[] = $options['location_id'];
    }
    
    $sql .= " ORDER BY asset_id";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $assets = $stmt->fetchAll();
    
    foreach ($assets as $asset) {
        $results['processed']++;
        
        try {
            // Find matching locations for this IP
            $locations = findLocationByIp($pdo, $asset['ip_address']);
            
            if (empty($locations)) {
                $results['skipped']++;
                continue;
            }
            
            // Select the most specific location (first in the ordered result)
            $selectedLocation = $locations[0];
            
            // Check if assignment would change
            $wouldChange = ($asset['location_id'] !== $selectedLocation['location_id']);
            
            if (!$wouldChange && !$options['force_reassign']) {
                $results['skipped']++;
                continue;
            }
            
            if (!$options['dry_run']) {
                // Update asset location
                $updateSql = "UPDATE assets 
                             SET location_id = ?, 
                                 location_assignment_method = 'Auto-IP',
                                 location_assigned_at = CURRENT_TIMESTAMP
                             WHERE asset_id = ?";
                
                $updateStmt = $pdo->prepare($updateSql);
                $updateStmt->execute([$selectedLocation['location_id'], $asset['asset_id']]);
                
                // Log the assignment
                logLocationAssignment($pdo, $asset['asset_id'], $selectedLocation['location_id'], 'Auto-IP');
            }
            
            $assignment = [
                'asset_id' => $asset['asset_id'],
                'hostname' => $asset['hostname'],
                'ip_address' => $asset['ip_address'],
                'old_location_id' => $asset['location_id'],
                'new_location_id' => $selectedLocation['location_id'],
                'new_location_name' => $selectedLocation['location_name'],
                'new_location_code' => $selectedLocation['location_code'],
                'hierarchy_path' => $selectedLocation['hierarchy_path'],
                'criticality' => $selectedLocation['criticality'],
                'range_format' => $selectedLocation['range_format'],
                'changed' => $wouldChange
            ];
            
            $results['assignments'][] = $assignment;
            
            if ($asset['location_id'] === null) {
                // Asset has no current location - this is a new assignment
                $results['assigned']++;
            } else {
                // Asset has a current location - this is an update
                $results['updated']++;
            }
            
        } catch (Exception $e) {
            $results['errors']++;
            $results['errors_list'][] = [
                'asset_id' => $asset['asset_id'],
                'hostname' => $asset['hostname'],
                'ip_address' => $asset['ip_address'],
                'error' => $e->getMessage()
            ];
            error_log("Error assigning location for asset {$asset['asset_id']}: " . $e->getMessage());
        }
    }
    
    return $results;
}

/**
 * Find locations that match a given IP address
 */
function findLocationByIp($pdo, $ipAddress) {
    $sql = "SELECT 
                l.location_id,
                l.location_name,
                l.location_code,
                lh.hierarchy_path,
                l.criticality,
                lir.range_id,
                lir.range_format,
                lir.cidr_notation,
                lir.start_ip,
                lir.end_ip
            FROM locations l
            JOIN location_hierarchy lh ON l.location_id = lh.location_id
            JOIN location_ip_ranges lir ON l.location_id = lir.location_id
            WHERE l.is_active = TRUE
            AND (
                (lir.range_format = 'CIDR' AND ? << lir.cidr_notation) OR
                (lir.range_format = 'StartEnd' AND ? >= lir.start_ip AND ? <= lir.end_ip)
            )
            ORDER BY 
                -- Prefer most specific CIDR (smallest network)
                CASE WHEN lir.range_format = 'CIDR' THEN masklen(lir.cidr_notation) ELSE 0 END DESC,
                -- Then by criticality (highest first)
                l.criticality DESC";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$ipAddress, $ipAddress, $ipAddress]);
    return $stmt->fetchAll();
}

/**
 * Log location assignment for audit trail
 */
function logLocationAssignment($pdo, $assetId, $locationId, $method) {
    // Create audit log entry
    $sql = "INSERT INTO audit_logs (action, table_name, record_id, old_values, new_values, user_id, ip_address, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([
        'UPDATE',
        'assets',
        $assetId,
        json_encode(['location_id' => null]),
        json_encode(['location_id' => $locationId, 'location_assignment_method' => $method]),
        $_SESSION['user_id'] ?? null,
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ]);
}

/**
 * Validate UUID format
 */
function isValidUuid($uuid) {
    return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uuid);
}
