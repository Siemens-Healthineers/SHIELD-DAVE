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
$unifiedAuth->requirePermission('assets', 'read');

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
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleGetRequest($path) {
    global $db, $auth, $user;
    
    switch ($path) {
        case 'unmapped':
            getUnmappedAssets();
            break;
        case 'mapped':
            getMappedAssets();
            break;
        case 'search':
            searchFDADevices();
            break;
        case 'suggestions':
            getManufacturerSuggestions();
            break;
        case 'stats':
            getMappingStats();
            break;
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

function handlePostRequest($path) {
    global $db, $auth, $user;
    
    switch ($path) {
        case 'map':
            mapDevice();
            break;
        case 'auto-map':
            autoMapDevices();
            break;
        case 'bulk-map':
            bulkMapDevices();
            break;
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

function handlePutRequest($path) {
    global $db, $auth, $user;
    
    switch ($path) {
        case 'update':
            updateDeviceMapping();
            break;
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

function handleDeleteRequest($path) {
    global $db, $auth, $user;
    
    switch ($path) {
        case 'unmap':
            unmapDevice();
            break;
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

function getUnmappedAssets() {
    global $db;
    
    $page = intval($_GET['page'] ?? 1);
    $limit = intval($_GET['limit'] ?? 25);
    $offset = ($page - 1) * $limit;
    $search = trim($_GET['search'] ?? '');
    
    // Build query
    $whereClause = "WHERE md.device_id IS NULL AND a.status = 'Active'";
    $params = [];
    
    if (!empty($search)) {
        $whereClause .= " AND (a.hostname ILIKE ? OR a.manufacturer ILIKE ? OR a.model ILIKE ?)";
        $searchTerm = '%' . $search . '%';
        $params = array_merge($params, [$searchTerm, $searchTerm, $searchTerm]);
    }
    
    $sql = "SELECT 
        a.asset_id,
        a.hostname,
        a.ip_address,
        a.mac_address,
        a.manufacturer,
        a.model,
        a.asset_type,
        a.department,
        a.criticality,
        a.last_seen
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        $whereClause
        ORDER BY a.last_seen DESC
        LIMIT ? OFFSET ?";
    
    $params[] = $limit;
    $params[] = $offset;
    
    $stmt = $db->query($sql, $params);
    $assets = $stmt->fetchAll();
    
    // Get total count
    $countSql = "SELECT COUNT(*) as total 
                FROM assets a
                LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
                $whereClause";
    $countStmt = $db->query($countSql, array_slice($params, 0, -2));
    $total = $countStmt->fetch()['total'];
    
    echo json_encode([
        'assets' => $assets,
        'total' => $total,
        'page' => $page,
        'limit' => $limit,
        'pages' => ceil($total / $limit)
    ]);
}

function getMappedAssets() {
    global $db;
    
    $page = intval($_GET['page'] ?? 1);
    $limit = intval($_GET['limit'] ?? 25);
    $offset = ($page - 1) * $limit;
    $search = trim($_GET['search'] ?? '');
    
    // Build query
    $whereClause = "WHERE md.device_id IS NOT NULL AND a.status = 'Active'";
    $params = [];
    
    if (!empty($search)) {
        $whereClause .= " AND (a.hostname ILIKE ? OR md.brand_name ILIKE ? OR md.model_number ILIKE ?)";
        $searchTerm = '%' . $search . '%';
        $params = array_merge($params, [$searchTerm, $searchTerm, $searchTerm]);
    }
    
    $sql = "SELECT 
        a.asset_id,
        a.hostname,
        a.ip_address,
        a.manufacturer,
        a.model,
        a.asset_type,
        a.department,
        a.criticality,
        md.device_id,
        md.brand_name,
        md.model_number,
        md.manufacturer_name,
        md.device_description,
        md.mapping_confidence,
        md.mapped_at
        FROM assets a
        JOIN medical_devices md ON a.asset_id = md.asset_id
        $whereClause
        ORDER BY md.mapped_at DESC
        LIMIT ? OFFSET ?";
    
    $params[] = $limit;
    $params[] = $offset;
    
    $stmt = $db->query($sql, $params);
    $assets = $stmt->fetchAll();
    
    // Get total count
    $countSql = "SELECT COUNT(*) as total 
                FROM assets a
                JOIN medical_devices md ON a.asset_id = md.asset_id
                $whereClause";
    $countStmt = $db->query($countSql, array_slice($params, 0, -2));
    $total = $countStmt->fetch()['total'];
    
    echo json_encode([
        'assets' => $assets,
        'total' => $total,
        'page' => $page,
        'limit' => $limit,
        'pages' => ceil($total / $limit)
    ]);
}

function searchFDADevices() {
    $manufacturer = trim($_GET['manufacturer'] ?? '');
    $model = trim($_GET['model'] ?? '');
    $limit = intval($_GET['limit'] ?? 100); // Default to 100, allow up to 1000
    
    if (empty($manufacturer)) {
        http_response_code(400);
        echo json_encode(['error' => 'Manufacturer is required']);
        return;
    }
    
    // Cap the limit to prevent excessive API calls
    $limit = min($limit, 1000);
    
    try {
        // Call Python FDA service with limit parameter
        $command = "cd /var/www/html && python3 python/services/fda_integration.py search_devices '$manufacturer' '$model' $limit";
        $output = shell_exec($command . ' 2>&1');
        
        $devices = json_decode($output, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            echo json_encode(['success' => true, 'devices' => $devices, 'count' => count($devices)]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Failed to parse FDA response']);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => 'FDA search failed: ' . $e->getMessage()]);
    }
}

function getManufacturerSuggestions() {
    $partial = trim($_GET['partial'] ?? '');
    
    if (strlen($partial) < 2) {
        echo json_encode(['suggestions' => []]);
        return;
    }
    
    try {
        // Call Python FDA service for suggestions
        $command = "cd /var/www/html && python3 python/services/fda_integration.py get_suggestions '$partial'";
        $output = shell_exec($command . ' 2>&1');
        
        $suggestions = json_decode($output, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            echo json_encode(['suggestions' => $suggestions]);
        } else {
            echo json_encode(['suggestions' => []]);
        }
    } catch (Exception $e) {
        echo json_encode(['suggestions' => []]);
    }
}

function getMappingStats() {
    global $db;
    
    $sql = "SELECT 
        COUNT(*) as total_assets,
        COUNT(md.device_id) as mapped_assets,
        AVG(md.mapping_confidence) as avg_confidence
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        WHERE a.status = 'Active'";
    
    $stmt = $db->query($sql);
    $stats = $stmt->fetch();
    
    $stats['unmapped_assets'] = $stats['total_assets'] - $stats['mapped_assets'];
    $stats['mapping_percentage'] = $stats['total_assets'] > 0 ? 
        round(($stats['mapped_assets'] / $stats['total_assets']) * 100, 1) : 0;
    
    echo json_encode($stats);
}

function mapDevice() {
    global $db, $auth, $user;
    
    if (!$auth->hasPermission('devices.map')) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient permissions']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    $assetId = $input['asset_id'] ?? '';
    $deviceData = $input['device_data'] ?? '';
    
    if (empty($assetId) || empty($deviceData)) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required data']);
        return;
    }
    
    try {
        $db->beginTransaction();
        
        $deviceInfo = json_decode($deviceData, true);
        if (!$deviceInfo) {
            throw new Exception('Invalid device data');
        }
        
        // Check if asset is already mapped
        $checkSql = "SELECT device_id FROM medical_devices WHERE asset_id = ?";
        $checkStmt = $db->query($checkSql, [$assetId]);
        if ($checkStmt->fetch()) {
            throw new Exception('Asset is already mapped');
        }
        
        // Extract 510k information from premarket submissions
        $kNumber = '';
        $k510kData = null;
        
        if (isset($deviceInfo['premarket_submissions']) && is_array($deviceInfo['premarket_submissions'])) {
            // Get the first K number from premarket submissions
            foreach ($deviceInfo['premarket_submissions'] as $submission) {
                if (isset($submission['submission_number']) && strpos($submission['submission_number'], 'K') === 0) {
                    $kNumber = $submission['submission_number'];
                    break;
                }
            }
        }
        
        // If we have a K number, fetch the full 510k details
        if ($kNumber) {
            try {
                $command = "cd /var/www/html && python3 python/services/fda_integration.py search_510k '$kNumber'";
                $output = shell_exec($command . ' 2>&1');
                $k510kResults = json_decode($output, true);
                
                if ($k510kResults && is_array($k510kResults) && count($k510kResults) > 0) {
                    $k510kData = $k510kResults[0]; // Get the first result
                }
            } catch (Exception $e) {
                // Continue without 510k details if fetch fails
                error_log("Failed to fetch 510k details for $kNumber: " . $e->getMessage());
            }
        }
        
        // Insert medical device record with 510k information
        $sql = "INSERT INTO medical_devices (
            asset_id, device_identifier, brand_name, model_number, 
            manufacturer_name, device_description, gmdn_term, 
            is_implantable, fda_class, udi, mapping_confidence, mapping_method, 
            mapped_by, mapped_at, k_number, decision_code, decision_date, 
            decision_description, clearance_type, date_received, statement_or_summary,
            applicant, contact, address_1, address_2, city, state, zip_code,
            postal_code, country_code, advisory_committee, advisory_committee_description,
            review_advisory_committee, expedited_review_flag, third_party_flag,
            device_class, medical_specialty_description, registration_numbers,
            fei_numbers, device_name, product_code, regulation_number, raw_510k_data
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual', ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        $stmt = $db->prepare($sql);
        $stmt->execute([
            $assetId,
            $deviceInfo['device_identifier'] ?? '',
            $deviceInfo['brand_name'] ?? '',
            $deviceInfo['model_number'] ?? '',
            $deviceInfo['manufacturer_name'] ?? '',
            $deviceInfo['device_description'] ?? '',
            $deviceInfo['gmdn_term'] ?? '',
            $deviceInfo['is_implantable'] ?? false,
            $deviceInfo['fda_class'] ?? '',
            $deviceInfo['udi'] ?? '',
            $deviceInfo['confidence_score'] ?? 0.0,
            $user['user_id'],
            $kNumber,
            // 510k specific fields
            $k510kData['decision_code'] ?? '',
            $k510kData['decision_date'] ?? null,
            $k510kData['decision_description'] ?? '',
            $k510kData['clearance_type'] ?? '',
            $k510kData['date_received'] ?? null,
            $k510kData['statement_or_summary'] ?? '',
            $k510kData['applicant'] ?? '',
            $k510kData['contact'] ?? '',
            $k510kData['address_1'] ?? '',
            $k510kData['address_2'] ?? '',
            $k510kData['city'] ?? '',
            $k510kData['state'] ?? '',
            $k510kData['zip_code'] ?? '',
            $k510kData['postal_code'] ?? '',
            $k510kData['country_code'] ?? '',
            $k510kData['advisory_committee'] ?? '',
            $k510kData['advisory_committee_description'] ?? '',
            $k510kData['review_advisory_committee'] ?? '',
            $k510kData['expedited_review_flag'] ?? '',
            $k510kData['third_party_flag'] ?? '',
            $k510kData['device_class'] ?? '',
            $k510kData['medical_specialty_description'] ?? '',
            $k510kData['registration_numbers'] ?? '',
            $k510kData['fei_numbers'] ?? '',
            $k510kData['device_name'] ?? '',
            $k510kData['product_code'] ?? '',
            $k510kData['regulation_number'] ?? '',
            $k510kData ? json_encode($k510kData) : null
        ]);
        
        $db->commit();
        
        // Log action
        $auth->logUserAction($user['user_id'], 'MAP_DEVICE', 'medical_devices', $assetId);
        
        echo json_encode(['success' => true, 'message' => 'Device mapped successfully']);
        
    } catch (Exception $e) {
        $db->rollback();
        http_response_code(500);
        echo json_encode(['error' => 'Failed to map device: ' . $e->getMessage()]);
    }
}

function autoMapDevices() {
    global $db, $auth, $user;
    
    if (!$auth->hasPermission('devices.map')) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient permissions']);
        return;
    }
    
    try {
        // Get unmapped assets with manufacturer information
        $sql = "SELECT asset_id, manufacturer, model, mac_address 
                FROM assets 
                WHERE asset_id NOT IN (SELECT asset_id FROM medical_devices) 
                AND status = 'Active' 
                AND manufacturer IS NOT NULL 
                AND manufacturer != ''";
        
        $stmt = $db->query($sql);
        $assets = $stmt->fetchAll();
        
        $mapped = 0;
        $errors = [];
        
        foreach ($assets as $asset) {
            try {
                // Search FDA database with higher limit for better matching
                $command = "cd /var/www/html && python3 python/services/fda_integration.py search_devices '{$asset['manufacturer']}' '{$asset['model']}' 50";
                $output = shell_exec($command . ' 2>&1');
                
                $devices = json_decode($output, true);
                if ($devices && count($devices) > 0) {
                    // Use the device with highest confidence
                    $bestDevice = $devices[0];
                    foreach ($devices as $device) {
                        if ($device['confidence_score'] > $bestDevice['confidence_score']) {
                            $bestDevice = $device;
                        }
                    }
                    
                    // Only auto-map if confidence is high enough
                    if ($bestDevice['confidence_score'] >= 0.7) {
                        // Extract 510k information from premarket submissions
                        $kNumber = '';
                        $k510kData = null;
                        
                        if (isset($bestDevice['premarket_submissions']) && is_array($bestDevice['premarket_submissions'])) {
                            // Get the first K number from premarket submissions
                            foreach ($bestDevice['premarket_submissions'] as $submission) {
                                if (isset($submission['submission_number']) && strpos($submission['submission_number'], 'K') === 0) {
                                    $kNumber = $submission['submission_number'];
                                    break;
                                }
                            }
                        }
                        
                        // If we have a K number, fetch the full 510k details
                        if ($kNumber) {
                            try {
                                $command = "cd /var/www/html && python3 python/services/fda_integration.py search_510k '$kNumber'";
                                $output = shell_exec($command . ' 2>&1');
                                $k510kResults = json_decode($output, true);
                                
                                if ($k510kResults && is_array($k510kResults) && count($k510kResults) > 0) {
                                    $k510kData = $k510kResults[0]; // Get the first result
                                }
                            } catch (Exception $e) {
                                // Continue without 510k details if fetch fails
                                error_log("Failed to fetch 510k details for $kNumber: " . $e->getMessage());
                            }
                        }
                        
                        $insertSql = "INSERT INTO medical_devices (
                            asset_id, device_identifier, brand_name, model_number, 
                            manufacturer_name, device_description, gmdn_term, 
                            is_implantable, fda_class, udi, mapping_confidence, mapping_method, 
                            mapped_by, mapped_at, k_number, decision_code, decision_date, 
                            decision_description, clearance_type, date_received, statement_or_summary,
                            applicant, contact, address_1, address_2, city, state, zip_code,
                            postal_code, country_code, advisory_committee, advisory_committee_description,
                            review_advisory_committee, expedited_review_flag, third_party_flag,
                            device_class, medical_specialty_description, registration_numbers,
                            fei_numbers, device_name, product_code, regulation_number, raw_510k_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'automatic', ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                        
                        $insertStmt = $db->prepare($insertSql);
                        $insertStmt->execute([
                            $asset['asset_id'],
                            $bestDevice['device_identifier'] ?? '',
                            $bestDevice['brand_name'] ?? '',
                            $bestDevice['model_number'] ?? '',
                            $bestDevice['manufacturer_name'] ?? '',
                            $bestDevice['device_description'] ?? '',
                            $bestDevice['gmdn_term'] ?? '',
                            $bestDevice['is_implantable'] ?? false,
                            $bestDevice['fda_class'] ?? '',
                            $bestDevice['udi'] ?? '',
                            $bestDevice['confidence_score'] ?? 0.0,
                            $user['user_id'],
                            $kNumber,
                            // 510k specific fields
                            $k510kData['decision_code'] ?? '',
                            $k510kData['decision_date'] ?? null,
                            $k510kData['decision_description'] ?? '',
                            $k510kData['clearance_type'] ?? '',
                            $k510kData['date_received'] ?? null,
                            $k510kData['statement_or_summary'] ?? '',
                            $k510kData['applicant'] ?? '',
                            $k510kData['contact'] ?? '',
                            $k510kData['address_1'] ?? '',
                            $k510kData['address_2'] ?? '',
                            $k510kData['city'] ?? '',
                            $k510kData['state'] ?? '',
                            $k510kData['zip_code'] ?? '',
                            $k510kData['postal_code'] ?? '',
                            $k510kData['country_code'] ?? '',
                            $k510kData['advisory_committee'] ?? '',
                            $k510kData['advisory_committee_description'] ?? '',
                            $k510kData['review_advisory_committee'] ?? '',
                            $k510kData['expedited_review_flag'] ?? '',
                            $k510kData['third_party_flag'] ?? '',
                            $k510kData['device_class'] ?? '',
                            $k510kData['medical_specialty_description'] ?? '',
                            $k510kData['registration_numbers'] ?? '',
                            $k510kData['fei_numbers'] ?? '',
                            $k510kData['device_name'] ?? '',
                            $k510kData['product_code'] ?? '',
                            $k510kData['regulation_number'] ?? '',
                            $k510kData ? json_encode($k510kData) : null
                        ]);
                        
                        $mapped++;
                    }
                }
            } catch (Exception $e) {
                $errors[] = "Error mapping asset {$asset['asset_id']}: " . $e->getMessage();
            }
        }
        
        // Log action
        $auth->logUserAction($user['user_id'], 'AUTO_MAP_DEVICES', 'medical_devices', null, [
            'mapped_count' => $mapped,
            'errors' => $errors
        ]);
        
        echo json_encode([
            'success' => true,
            'mapped' => $mapped,
            'errors' => $errors
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Auto-mapping failed: ' . $e->getMessage()]);
    }
}

function updateDeviceMapping() {
    global $db, $auth, $user;
    
    if (!$auth->hasPermission('devices.map')) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient permissions']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    $deviceId = $input['device_id'] ?? '';
    $deviceData = $input['device_data'] ?? '';
    
    if (empty($deviceId) || empty($deviceData)) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required data']);
        return;
    }
    
    try {
        $db->beginTransaction();
        
        $deviceInfo = json_decode($deviceData, true);
        if (!$deviceInfo) {
            throw new Exception('Invalid device data');
        }
        
        // Update medical device record
        $sql = "UPDATE medical_devices SET
            device_identifier = ?,
            brand_name = ?,
            model_number = ?,
            manufacturer_name = ?,
            device_description = ?,
            gmdn_term = ?,
            is_implantable = ?,
            fda_class = ?,
            udi = ?,
            mapping_confidence = ?,
            mapping_method = 'manual',
            mapped_by = ?,
            mapped_at = CURRENT_TIMESTAMP
            WHERE device_id = ?";
        
        $stmt = $db->prepare($sql);
        $stmt->execute([
            $deviceInfo['device_identifier'] ?? '',
            $deviceInfo['brand_name'] ?? '',
            $deviceInfo['model_number'] ?? '',
            $deviceInfo['manufacturer_name'] ?? '',
            $deviceInfo['device_description'] ?? '',
            $deviceInfo['gmdn_term'] ?? '',
            $deviceInfo['is_implantable'] ?? false,
            $deviceInfo['fda_class'] ?? '',
            $deviceInfo['udi'] ?? '',
            $deviceInfo['confidence_score'] ?? 0.0,
            $user['user_id'],
            $deviceId
        ]);
        
        $db->commit();
        
        // Log action
        $auth->logUserAction($user['user_id'], 'UPDATE_DEVICE_MAPPING', 'medical_devices', $deviceId);
        
        echo json_encode(['success' => true, 'message' => 'Device mapping updated successfully']);
        
    } catch (Exception $e) {
        $db->rollback();
        http_response_code(500);
        echo json_encode(['error' => 'Failed to update device mapping: ' . $e->getMessage()]);
    }
}

function unmapDevice() {
    global $db, $auth, $user;
    
    if (!$auth->hasPermission('devices.map')) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient permissions']);
        return;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    $deviceId = $input['device_id'] ?? '';
    
    if (empty($deviceId)) {
        http_response_code(400);
        echo json_encode(['error' => 'Device ID is required']);
        return;
    }
    
    try {
        $db->beginTransaction();
        
        // Delete medical device record
        $sql = "DELETE FROM medical_devices WHERE device_id = ?";
        $stmt = $db->prepare($sql);
        $stmt->execute([$deviceId]);
        
        if ($stmt->rowCount() === 0) {
            throw new Exception('Device not found');
        }
        
        $db->commit();
        
        // Log action
        $auth->logUserAction($user['user_id'], 'UNMAP_DEVICE', 'medical_devices', $deviceId);
        
        echo json_encode(['success' => true, 'message' => 'Device unmapped successfully']);
        
    } catch (Exception $e) {
        $db->rollback();
        http_response_code(500);
        echo json_encode(['error' => 'Failed to unmap device: ' . $e->getMessage()]);
    }
}
