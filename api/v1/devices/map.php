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
require_once __DIR__ . '/../../../services/shell_command_utilities.php';

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
        case 'check_jobs':
            checkFDAJobs();
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
        // Call Python FDA service with limit parameter (non-blocking)
        $logFile = _ROOT . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . 'fda_search_' . uniqid() . '.log';
        $command = "cd " . _ROOT . " && python3 python/services/fda_integration.py search_devices '$manufacturer' '$model' $limit";
        $result = ShellCommandUtilities::executeShellCommand($command, [
            'blocking' => false,
            'log_file' => $logFile
        ]);
        
        if (!$result['success']) {
            echo json_encode(['success' => false, 'error' => 'Failed to start FDA search: ' . ($result['error'] ?? 'Unknown error')]);
            return;
        }
        
        // Return job info for polling
        echo json_encode([
            'success' => true,
            'job' => [
                'job_id' => uniqid('fda_search_'),
                'pid' => $result['pid'],
                'log_file' => $result['log_file'],
                'status' => 'running',
                'type' => 'search',
                'manufacturer' => $manufacturer,
                'model' => $model
            ]
        ]);
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
        // Call Python FDA service for suggestions (non-blocking)
        $logFile = _ROOT . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . 'fda_suggestions_' . uniqid() . '.log';
        $command = "cd " . _ROOT . " && python3 python/services/fda_integration.py get_suggestions '$partial'";
        $result = ShellCommandUtilities::executeShellCommand($command, [
            'blocking' => false,
            'log_file' => $logFile
        ]);
        
        if (!$result['success']) {
            echo json_encode([
                'success' => false, 
                'error' => 'Failed to start suggestion lookup'
            ]);
            return;
        }
        
        // Return job info for polling
        echo json_encode([
            'success' => true,
            'job' => [
                'job_id' => uniqid('fda_suggest_'),
                'pid' => $result['pid'],
                'log_file' => $result['log_file'],
                'status' => 'running',
                'type' => 'suggestions',
                'partial' => $partial
            ]
        ]);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
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
        
        // If we have a K number, fetch the full 510k details (non-blocking)
        $k510kJob = null;
        if ($kNumber) {
            try {
                $logFile = _ROOT . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . 'fda_510k_' . uniqid() . '.log';
                $command = "cd " . _ROOT . " && python3 python/services/fda_integration.py search_510k '$kNumber'";
                $cmdResult = ShellCommandUtilities::executeShellCommand($command, [
                    'blocking' => false,
                    'log_file' => $logFile
                ]);
                
                if ($cmdResult['success']) {
                    $k510kJob = [
                        'job_id' => uniqid('fda_510k_'),
                        'pid' => $cmdResult['pid'],
                        'log_file' => $cmdResult['log_file'],
                        'status' => 'running',
                        'type' => '510k',
                        'k_number' => $kNumber,
                        'asset_id' => $assetId
                    ];
                }
            } catch (Exception $e) {
                // Continue without 510k details if fetch fails
                error_log("Failed to start 510k fetch for $kNumber: " . $e->getMessage());
            }
        }
        
        // Insert medical device record (without 510k data initially - will be updated async)
        $sql = "INSERT INTO medical_devices (
            asset_id, device_identifier, brand_name, model_number, 
            manufacturer_name, device_description, gmdn_term, 
            is_implantable, fda_class, udi, mapping_confidence, mapping_method, 
            mapped_by, mapped_at, k_number
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual', ?, CURRENT_TIMESTAMP, ?)";
        
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
            $kNumber
        ]);
        
        $db->commit();
        
        // Log action
        $auth->logUserAction($user['user_id'], 'MAP_DEVICE', 'medical_devices', $assetId);
        
        // Return success with optional 510k job info
        $response = [
            'success' => true, 
            'message' => 'Device mapped successfully'
        ];
        
        if ($k510kJob !== null) {
            $response['k510k_job'] = $k510kJob;
            $response['message'] .= ' - 510k details are being fetched in the background';
        }
        
        echo json_encode($response);
        
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
        // Start auto-mapping as a background job
        $logFile = _ROOT . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . 'automap_' . uniqid() . '.json';
        $command = "cd " . _ROOT . " && php scripts/auto-map-devices.php {$user['user_id']} $logFile";
        
        $result = ShellCommandUtilities::executeShellCommand($command, [
            'blocking' => false,
            'log_file' => $logFile
        ]);
        
        if (!$result['success']) {
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => 'Failed to start auto-mapping: ' . ($result['error'] ?? 'Unknown error')
            ]);
            return;
        }
        
        // Log action
        $auth->logUserAction($user['user_id'], 'AUTO_MAP_DEVICES_STARTED', 'medical_devices', null, [
            'pid' => $result['pid'],
            'log_file' => $logFile
        ]);
        
        // Return job info for polling
        echo json_encode([
            'success' => true,
            'message' => 'Auto-mapping started in background',
            'job' => [
                'job_id' => uniqid('automap_'),
                'pid' => $result['pid'],
                'log_file' => $logFile,
                'status' => 'running',
                'type' => 'automap'
            ]
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'Auto-mapping failed: ' . $e->getMessage()]);
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

/**
 * Check status of FDA background jobs
 */
function checkFDAJobs() {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input || !isset($input['jobs'])) {
        echo json_encode(['success' => false, 'error' => 'No jobs provided']);
        return;
    }
    
    $results = [];
    
    foreach ($input['jobs'] as $job) {
        if (!isset($job['pid']) || !isset($job['log_file'])) {
            $results[] = [
                'job_id' => $job['job_id'] ?? null,
                'status' => 'error',
                'error' => 'Invalid job data'
            ];
            continue;
        }
        
        // Check if process is still running
        $isRunning = ShellCommandUtilities::isProcessRunning($job['pid']);
        
        if ($isRunning) {
            $results[] = [
                'job_id' => $job['job_id'],
                'type' => $job['type'] ?? 'unknown',
                'pid' => $job['pid'],
                'status' => 'running'
            ];
        } else {
            // Process completed, get results from log file
            $output = ShellCommandUtilities::getCommandOutput($job['log_file']);
            
            if ($output) {
                // Parse the output based on job type
                $jobType = $job['type'] ?? 'unknown';
                
                switch ($jobType) {
                    case 'search':
                        $devices = json_decode($output, true);
                        if (json_last_error() === JSON_ERROR_NONE) {
                            $results[] = [
                                'job_id' => $job['job_id'],
                                'type' => 'search',
                                'status' => 'completed',
                                'data' => [
                                    'devices' => $devices,
                                    'count' => count($devices),
                                    'manufacturer' => $job['manufacturer'] ?? '',
                                    'model' => $job['model'] ?? ''
                                ]
                            ];
                        } else {
                            $results[] = [
                                'job_id' => $job['job_id'],
                                'type' => 'search',
                                'status' => 'failed',
                                'error' => 'Failed to parse search results: ' . $output
                            ];
                        }
                        break;
                        
                    case 'suggestions':
                        $suggestions = json_decode($output, true);
                        if (json_last_error() === JSON_ERROR_NONE) {
                            $results[] = [
                                'job_id' => $job['job_id'],
                                'type' => 'suggestions',
                                'status' => 'completed',
                                'data' => [
                                    'suggestions' => $suggestions
                                ]
                            ];
                        } else {
                            $results[] = [
                                'job_id' => $job['job_id'],
                                'type' => 'suggestions',
                                'status' => 'failed',
                                'error' => 'Failed to parse suggestions'
                            ];
                        }
                        break;
                        
                    case '510k':
                        $k510kResults = json_decode($output, true);
                        if (json_last_error() === JSON_ERROR_NONE) {
                            $results[] = [
                                'job_id' => $job['job_id'],
                                'type' => '510k',
                                'status' => 'completed',
                                'data' => [
                                    'k510k_data' => $k510kResults,
                                    'k_number' => $job['k_number'] ?? ''
                                ]
                            ];
                        } else {
                            $results[] = [
                                'job_id' => $job['job_id'],
                                'type' => '510k',
                                'status' => 'failed',
                                'error' => 'Failed to parse 510k data'
                            ];
                        }
                        break;
                        
                    case 'automap':
                        $automapResults = json_decode($output, true);
                        if (json_last_error() === JSON_ERROR_NONE && is_array($automapResults)) {
                            $results[] = [
                                'job_id' => $job['job_id'],
                                'type' => 'automap',
                                'status' => 'completed',
                                'data' => [
                                    'mapped' => $automapResults['mapped'] ?? 0,
                                    'skipped' => $automapResults['skipped'] ?? 0,
                                    'errors' => $automapResults['errors'] ?? [],
                                    'timestamp' => $automapResults['timestamp'] ?? date('c')
                                ]
                            ];
                        } else {
                            $results[] = [
                                'job_id' => $job['job_id'],
                                'type' => 'automap',
                                'status' => 'failed',
                                'error' => 'Failed to parse auto-map results: ' . $output
                            ];
                        }
                        break;
                        
                    default:
                        $results[] = [
                            'job_id' => $job['job_id'],
                            'type' => $jobType,
                            'status' => 'completed',
                            'data' => $output
                        ];
                }
            } else {
                $results[] = [
                    'job_id' => $job['job_id'],
                    'type' => $job['type'] ?? 'unknown',
                    'status' => 'failed',
                    'error' => 'No output from command'
                ];
            }
        }
    }
    
    echo json_encode([
        'success' => true,
        'results' => $results
    ]);
}

/*
 * FRONTEND POLLING EXAMPLE
 * 
 * Example JavaScript code for polling FDA device search/mapping jobs:
 * 
 * // 1. Start an FDA search (non-blocking)
 * fetch('/api/v1/devices/map.php?path=search&manufacturer=Siemens&model=Example')
 *     .then(response => response.json())
 *     .then(data => {
 *         if (data.success && data.job) {
 *             pollFDAJobs([data.job], handleSearchComplete);
 *         }
 *     });
 * 
 * // 2. Poll for job completion
 * function pollFDAJobs(jobs, onComplete) {
 *     const pollInterval = setInterval(() => {
 *         fetch('/api/v1/devices/map.php?path=check_jobs', {
 *             method: 'POST',
 *             headers: { 'Content-Type': 'application/json' },
 *             body: JSON.stringify({ jobs: jobs })
 *         })
 *         .then(response => response.json())
 *         .then(data => {
 *             if (data.success && data.results) {
 *                 // Update jobs with current status
 *                 data.results.forEach(result => {
 *                     const jobIndex = jobs.findIndex(j => j.job_id === result.job_id);
 *                     if (jobIndex !== -1) {
 *                         jobs[jobIndex] = result;
 *                     }
 *                 });
 *                 
 *                 // Check if all completed
 *                 const runningCount = jobs.filter(j => j.status === 'running').length;
 *                 if (runningCount === 0) {
 *                     clearInterval(pollInterval);
 *                     onComplete(jobs);
 *                 }
 *             }
 *         })
 *         .catch(error => {
 *             console.error('Polling error:', error);
 *             clearInterval(pollInterval);
 *         });
 *     }, 2000); // Poll every 2 seconds
 * }
 * 
 * // 3. Handle completed jobs
 * function handleSearchComplete(jobs) {
 *     jobs.forEach(job => {
 *         if (job.status === 'completed' && job.type === 'search') {
 *             console.log('Found devices:', job.data.devices);
 *             displayDevices(job.data.devices);
 *         } else if (job.status === 'failed') {
 *             console.error('Search failed:', job.error);
 *         }
 *     });
 * }
 * 
 * // 4. Example: Map a device with 510k background fetch
 * function mapDeviceWithPolling(assetId, deviceData) {
 *     fetch('/api/v1/devices/map.php?path=map', {
 *         method: 'POST',
 *         headers: { 'Content-Type': 'application/json' },
 *         body: JSON.stringify({
 *             asset_id: assetId,
 *             device_data: JSON.stringify(deviceData)
 *         })
 *     })
 *     .then(response => response.json())
 *     .then(data => {
 *         if (data.success) {
 *             showNotification(data.message, 'success');
 *             
 *             // If there's a 510k job, poll for it
 *             if (data.k510k_job) {
 *                 pollFDAJobs([data.k510k_job], (completedJobs) => {
 *                     showNotification('510k details loaded', 'success');
 *                     // Refresh device display to show 510k data
 *                     refreshDeviceDetails(assetId);
 *                 });
 *             }
 *         }
 *     });
 * }
 */
