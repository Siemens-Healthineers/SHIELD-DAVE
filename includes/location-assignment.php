<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

/**
 * Auto-assign asset location based on IP address
 * 
 * @param PDO $pdo Database connection
 * @param string $assetId Asset ID
 * @param string $ipAddress IP address to match
 * @param bool $forceReassign Force reassignment even if manually assigned
 * @return array Assignment result
 */
function autoAssignAssetLocation($pdo, $assetId, $ipAddress, $forceReassign = false) {
    $result = [
        'success' => false,
        'location_id' => null,
        'location_name' => null,
        'hierarchy_path' => null,
        'criticality' => null,
        'method' => null,
        'error' => null
    ];
    
    try {
        // Check if asset exists and get current assignment
        $stmt = $pdo->prepare("SELECT location_id, location_assignment_method FROM assets WHERE asset_id = ?");
        $stmt->execute([$assetId]);
        $asset = $stmt->fetch();
        
        if (!$asset) {
            $result['error'] = 'Asset not found';
            return $result;
        }
        
        // Skip if manually assigned and not forcing reassignment
        if (!$forceReassign && $asset['location_assignment_method'] === 'Manual') {
            $result['error'] = 'Asset is manually assigned, use force_reassign to override';
            return $result;
        }
        
        // Find matching locations
        $locations = findLocationByIp($pdo, $ipAddress);
        
        if (empty($locations)) {
            $result['error'] = 'No matching location found for IP address';
            return $result;
        }
        
        // Select the most specific location (first in ordered result)
        $selectedLocation = $locations[0];
        
        // Update asset location
        $updateSql = "UPDATE assets 
                     SET location_id = ?, 
                         location_assignment_method = 'Auto-IP',
                         location_assigned_at = CURRENT_TIMESTAMP
                     WHERE asset_id = ?";
        
        $updateStmt = $pdo->prepare($updateSql);
        $updateStmt->execute([$selectedLocation['location_id'], $assetId]);
        
        // Log the assignment
        logLocationAssignment($pdo, $assetId, $selectedLocation['location_id'], 'Auto-IP');
        
        $result['success'] = true;
        $result['location_id'] = $selectedLocation['location_id'];
        $result['location_name'] = $selectedLocation['location_name'];
        $result['hierarchy_path'] = $selectedLocation['hierarchy_path'];
        $result['criticality'] = $selectedLocation['criticality'];
        $result['method'] = 'Auto-IP';
        
        return $result;
        
    } catch (Exception $e) {
        $result['error'] = $e->getMessage();
        error_log("Error in autoAssignAssetLocation: " . $e->getMessage());
        return $result;
    }
}

/**
 * Find locations that match a given IP address
 * 
 * @param PDO $pdo Database connection
 * @param string $ipAddress IP address to match
 * @return array Array of matching locations ordered by specificity
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
 * Check for IP range overlaps between locations
 * 
 * @param PDO $pdo Database connection
 * @param string $locationId Location ID to check (exclude from results)
 * @param string $cidrNotation CIDR notation to check
 * @param string $startIp Start IP for range check
 * @param string $endIp End IP for range check
 * @return array Array of overlapping locations
 */
function checkIpRangeOverlap($pdo, $locationId, $cidrNotation = null, $startIp = null, $endIp = null) {
    $sql = "SELECT * FROM check_ip_range_overlap(?, ?, ?, ?)";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$locationId, $cidrNotation, $startIp, $endIp]);
    return $stmt->fetchAll();
}

/**
 * Get location hierarchy path
 * 
 * @param PDO $pdo Database connection
 * @param string $locationId Location ID
 * @return string|null Hierarchy path
 */
function getLocationHierarchyPath($pdo, $locationId) {
    $sql = "SELECT hierarchy_path FROM location_hierarchy WHERE location_id = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$locationId]);
    $result = $stmt->fetch();
    return $result ? $result['hierarchy_path'] : null;
}

/**
 * Get all child locations recursively
 * 
 * @param PDO $pdo Database connection
 * @param string $locationId Parent location ID
 * @return array Array of child locations
 */
function getChildLocations($pdo, $locationId) {
    $sql = "WITH RECURSIVE location_tree AS (
                SELECT location_id, parent_location_id, location_name, location_type, 
                       location_code, criticality, is_active, 0 as level
                FROM locations
                WHERE parent_location_id = ?
                UNION ALL
                SELECT l.location_id, l.parent_location_id, l.location_name, l.location_type,
                       l.location_code, l.criticality, l.is_active, lt.level + 1
                FROM locations l
                JOIN location_tree lt ON l.parent_location_id = lt.location_id
            )
            SELECT * FROM location_tree ORDER BY level, location_type, location_name";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$locationId]);
    return $stmt->fetchAll();
}

/**
 * Get assets assigned to a location
 * 
 * @param PDO $pdo Database connection
 * @param string $locationId Location ID
 * @return array Array of assigned assets
 */
function getLocationAssets($pdo, $locationId) {
    $sql = "SELECT asset_id, hostname, ip_address, asset_type, criticality, status,
                   location_assignment_method, location_assigned_at
            FROM assets 
            WHERE location_id = ?
            ORDER BY hostname";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$locationId]);
    return $stmt->fetchAll();
}

/**
 * Log location assignment for audit trail
 * 
 * @param PDO $pdo Database connection
 * @param string $assetId Asset ID
 * @param string $locationId Location ID
 * @param string $method Assignment method
 */
function logLocationAssignment($pdo, $assetId, $locationId, $method) {
    try {
        // Check if audit_logs table exists
        $stmt = $pdo->query("SELECT to_regclass('audit_logs')");
        $tableExists = $stmt->fetchColumn();
        
        if ($tableExists) {
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
    } catch (Exception $e) {
        // Log error but don't fail the assignment
        error_log("Error logging location assignment: " . $e->getMessage());
    }
}

/**
 * Validate IP address format
 * 
 * @param string $ip IP address to validate
 * @return bool True if valid
 */
function isValidIpAddress($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

/**
 * Validate CIDR notation
 * 
 * @param string $cidr CIDR notation to validate
 * @return bool True if valid
 */
function isValidCidrNotation($cidr) {
    if (!preg_match('/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/', $cidr)) {
        return false;
    }
    
    list($ip, $prefix) = explode('/', $cidr);
    
    if (!isValidIpAddress($ip)) {
        return false;
    }
    
    $prefix = (int)$prefix;
    return $prefix >= 0 && $prefix <= 32;
}

/**
 * Validate IP range (start and end IPs)
 * 
 * @param string $startIp Start IP address
 * @param string $endIp End IP address
 * @return bool True if valid
 */
function isValidIpRange($startIp, $endIp) {
    if (!isValidIpAddress($startIp) || !isValidIpAddress($endIp)) {
        return false;
    }
    
    return ip2long($startIp) <= ip2long($endIp);
}

/**
 * Get location statistics
 * 
 * @param PDO $pdo Database connection
 * @return array Location statistics
 */
function getLocationStatistics($pdo) {
    $stats = [];
    
    // Total locations
    $stmt = $pdo->query("SELECT COUNT(*) as total FROM locations WHERE is_active = TRUE");
    $stats['total_locations'] = $stmt->fetchColumn();
    
    // Locations by type
    $stmt = $pdo->query("SELECT location_type, COUNT(*) as count 
                        FROM locations 
                        WHERE is_active = TRUE 
                        GROUP BY location_type 
                        ORDER BY count DESC");
    $stats['by_type'] = $stmt->fetchAll();
    
    // Locations by criticality
    $stmt = $pdo->query("SELECT criticality, COUNT(*) as count 
                        FROM locations 
                        WHERE is_active = TRUE 
                        GROUP BY criticality 
                        ORDER BY criticality DESC");
    $stats['by_criticality'] = $stmt->fetchAll();
    
    // Assets with/without locations
    $stmt = $pdo->query("SELECT 
                            COUNT(*) as total_assets,
                            COUNT(location_id) as assets_with_location,
                            COUNT(*) - COUNT(location_id) as assets_without_location
                        FROM assets");
    $locationStats = $stmt->fetch();
    $stats['asset_assignment'] = $locationStats;
    
    // Assignment methods
    $stmt = $pdo->query("SELECT location_assignment_method, COUNT(*) as count 
                        FROM assets 
                        WHERE location_id IS NOT NULL 
                        GROUP BY location_assignment_method");
    $stats['assignment_methods'] = $stmt->fetchAll();
    
    return $stats;
}

/**
 * Bulk assign locations to assets
 * 
 * @param PDO $pdo Database connection
 * @param array $assignments Array of asset_id => location_id assignments
 * @param string $method Assignment method
 * @return array Results
 */
function bulkAssignAssetLocations($pdo, $assignments, $method = 'Manual') {
    $results = [
        'processed' => 0,
        'success' => 0,
        'errors' => 0,
        'error_details' => []
    ];
    
    try {
        $pdo->beginTransaction();
        
        foreach ($assignments as $assetId => $locationId) {
            $results['processed']++;
            
            try {
                // Validate asset exists
                $stmt = $pdo->prepare("SELECT asset_id FROM assets WHERE asset_id = ?");
                $stmt->execute([$assetId]);
                if (!$stmt->fetch()) {
                    throw new Exception("Asset not found");
                }
                
                // Validate location exists (if provided)
                if ($locationId) {
                    $stmt = $pdo->prepare("SELECT location_id FROM locations WHERE location_id = ? AND is_active = TRUE");
                    $stmt->execute([$locationId]);
                    if (!$stmt->fetch()) {
                        throw new Exception("Location not found");
                    }
                }
                
                // Update asset
                $updateSql = "UPDATE assets 
                             SET location_id = ?, 
                                 location_assignment_method = ?,
                                 location_assigned_at = CURRENT_TIMESTAMP
                             WHERE asset_id = ?";
                
                $updateStmt = $pdo->prepare($updateSql);
                $updateStmt->execute([$locationId, $method, $assetId]);
                
                // Log assignment
                if ($locationId) {
                    logLocationAssignment($pdo, $assetId, $locationId, $method);
                }
                
                $results['success']++;
                
            } catch (Exception $e) {
                $results['errors']++;
                $results['error_details'][] = [
                    'asset_id' => $assetId,
                    'location_id' => $locationId,
                    'error' => $e->getMessage()
                ];
            }
        }
        
        $pdo->commit();
        
    } catch (Exception $e) {
        $pdo->rollBack();
        throw $e;
    }
    
    return $results;
}
