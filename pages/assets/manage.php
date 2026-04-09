<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../services/shell_command_utilities.php';
require_once __DIR__ . '/../../includes/cache.php';

// Authentication required
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Helper function to extract JSON array/object from output that may contain debug messages
function extractJsonFromOutput($output) {
    if (empty($output)) {
        return null;
    }
    
    // Try to find JSON array or object in the output
    // Look for [ or { at the start of a line
    $lines = explode("\n", $output);
    $jsonLines = [];
    $inJson = false;
    $depth = 0;
    
    foreach ($lines as $line) {
        $trimmed = trim($line);
        
        // Skip empty lines
        if (empty($trimmed)) {
            continue;
        }
        
        // Start of JSON array or object
        // Make sure it's actually JSON, not a log timestamp like [2026-03-18 15:19:30]
        if (!$inJson) {
            $firstChar = substr($trimmed, 0, 1);
            if ($firstChar === '[') {
                // Check if it looks like a timestamp (has a digit after the bracket)
                if (preg_match('/^\[\d{4}-\d{2}-\d{2}/', $trimmed)) {
                    continue; // Skip timestamp lines
                }
                // Check if it's actually a JSON array
                if ($trimmed === '[' || substr($trimmed, 1, 1) === '{' || substr($trimmed, 1, 1) === ']') {
                    $inJson = true;
                }
            } elseif ($firstChar === '{') {
                $inJson = true;
            }
        }
        
        if ($inJson) {
            $jsonLines[] = $line;
            
            // Count brackets to know when JSON ends
            $depth += substr_count($line, '[') + substr_count($line, '{');
            $depth -= substr_count($line, ']') + substr_count($line, '}');
            
            if ($depth === 0) {
                break; // End of JSON
            }
        }
    }
    
    if (empty($jsonLines)) {
        return null;
    }
    
    $jsonString = implode("\n", $jsonLines);
    $decoded = json_decode($jsonString, true);
    
    return (json_last_error() === JSON_ERROR_NONE) ? $decoded : null;
}

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    // Handle job polling request
    if ($_GET['ajax'] === 'check_jobs') {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input || !isset($input['jobs'])) {
            echo json_encode(['success' => false, 'error' => 'No jobs provided']);
            exit;
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
                    $jobType = $job['type'] ?? 'unknown';
                    
                    switch ($jobType) {
                        case 'fda_search':
                            $devices = extractJsonFromOutput($output);
                            if ($devices !== null && is_array($devices)) {
                                $results[] = [
                                    'job_id' => $job['job_id'],
                                    'type' => 'fda_search',
                                    'status' => 'completed',
                                    'data' => [
                                        'devices' => $devices,
                                        'count' => count($devices)
                                    ]
                                ];
                            } else {
                                $results[] = [
                                    'job_id' => $job['job_id'],
                                    'type' => 'fda_search',
                                    'status' => 'failed',
                                    'error' => 'No devices found'
                                ];
                            }
                            break;
                            
                        case '510k_search':
                            // Extract JSON from log file (skip debug messages)
                            error_log('510k search raw output: ' . substr($output, 0, 500)); // Log first 500 chars
                            $k510kData = extractJsonFromOutput($output);
                            error_log('510k search extracted data: ' . ($k510kData !== null ? 'FOUND' : 'NULL'));
                            
                            if ($k510kData !== null) {
                                $results[] = [
                                    'job_id' => $job['job_id'],
                                    'type' => '510k_search',
                                    'status' => 'completed',
                                    'data' => $k510kData
                                ];
                            } else {
                                $results[] = [
                                    'job_id' => $job['job_id'],
                                    'type' => '510k_search',
                                    'status' => 'failed',
                                    'error' => 'No 510k data found',
                                    'raw_output_preview' => substr($output, 0, 200) // Include preview for debugging
                                ];
                            }
                            break;
                            
                        case 'manufacturer_suggestions':
                            $suggestions = extractJsonFromOutput($output);
                            if ($suggestions !== null && is_array($suggestions)) {
                                $results[] = [
                                    'job_id' => $job['job_id'],
                                    'type' => 'manufacturer_suggestions',
                                    'status' => 'completed',
                                    'data' => [
                                        'suggestions' => $suggestions
                                    ]
                                ];
                            } else {
                                $results[] = [
                                    'job_id' => $job['job_id'],
                                    'type' => 'manufacturer_suggestions',
                                    'status' => 'failed',
                                    'error' => 'No suggestions found'
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
                    
                    // Clean up log file after processing
                    if (isset($job['log_file']) && file_exists($job['log_file'])) {
                        @unlink($job['log_file']);
                    }
                } else {
                    $results[] = [
                        'job_id' => $job['job_id'],
                        'type' => $job['type'] ?? 'unknown',
                        'status' => 'failed',
                        'error' => 'No output from command'
                    ];
                    
                    // Clean up log file even on failure
                    if (isset($job['log_file']) && file_exists($job['log_file'])) {
                        @unlink($job['log_file']);
                    }
                }
            }
        }
        
        echo json_encode([
            'success' => true,
            'results' => $results
        ]);
        exit;
    }
    
    switch ($_GET['ajax']) {
        case 'get_assets':
            $page = intval($_GET['page'] ?? 1);
            $limit = intval($_GET['limit'] ?? 25);
            $offset = ($page - 1) * $limit;
            
            // Debug: Log all received parameters
            error_log('get_assets called with parameters: ' . json_encode($_GET));
            
            // Build filters
            $filters = [];
            $params = [];
            
            if (!empty($_GET['search'])) {
                $filters[] = "(a.hostname ILIKE ? OR a.ip_address::text ILIKE ? OR a.mac_address::text ILIKE ? OR a.manufacturer ILIKE ? OR a.model ILIKE ? OR md.brand_name ILIKE ? OR md.device_name ILIKE ? OR md.manufacturer_name ILIKE ?)";
                $searchTerm = '%' . $_GET['search'] . '%';
                $params = array_merge($params, [$searchTerm, $searchTerm, $searchTerm, $searchTerm, $searchTerm, $searchTerm, $searchTerm, $searchTerm]);
            }
            
            if (!empty($_GET['asset_type'])) {
                $filters[] = "a.asset_type = ?";
                $params[] = $_GET['asset_type'];
            }
            
            if (!empty($_GET['status'])) {
                if ($_GET['status'] === 'mapped') {
                    $filters[] = "md.device_id IS NOT NULL";
                } elseif ($_GET['status'] === 'unmapped') {
                    $filters[] = "md.device_id IS NULL";
                } else {
                    $filters[] = "a.status = ?";
                    $params[] = $_GET['status'];
                }
            }
            
            if (!empty($_GET['department'])) {
                $filters[] = "a.department = ?";
                $params[] = $_GET['department'];
            }
            
            if (!empty($_GET['criticality'])) {
                $filters[] = "a.criticality = ?";
                $params[] = $_GET['criticality'];
            }
            
            if (!empty($_GET['location_id'])) {
                if ($_GET['location_id'] === 'unassigned') {
                    $filters[] = "a.location_id IS NULL";
                } else {
                    $filters[] = "a.location_id = ?";
                    $params[] = $_GET['location_id'];
                }
            }
            
            $whereClause = !empty($filters) ? 'WHERE ' . implode(' AND ', $filters) : '';
            
            // Debug: Log the SQL query and parameters
            error_log('SQL WHERE clause: ' . $whereClause);
            error_log('SQL parameters: ' . json_encode($params));
            
            // Get total count
            $countSql = "SELECT COUNT(*) as total FROM assets a LEFT JOIN medical_devices md ON a.asset_id = md.asset_id $whereClause";
            error_log('Count SQL: ' . $countSql);
            $countStmt = $db->query($countSql, $params);
            $total = $countStmt->fetch()['total'];
            
            // Get sort parameters
            $sortColumn = $_GET['sort_column'] ?? 'last_seen';
            $sortDirection = strtoupper($_GET['sort_direction'] ?? 'DESC');
            
            // Validate sort direction
            if (!in_array($sortDirection, ['ASC', 'DESC'])) {
                $sortDirection = 'DESC';
            }
            
            // Map frontend column names to database columns
            $columnMap = [
                'hostname' => 'a.hostname',
                'ip_address' => 'a.ip_address',
                'asset_type' => 'a.asset_type',
                'department' => 'a.department',
                'location' => 'l.location_name',
                'criticality' => 'COALESCE(l.criticality, a.criticality)',
                'status' => 'a.status',
                'mapping_status' => 'mapping_status',
                'last_seen' => 'a.last_seen'
            ];
            
            // Get the actual database column for sorting
            $orderByColumn = $columnMap[$sortColumn] ?? 'a.last_seen';
            
            // Special handling for mapping_status (computed column)
            if ($sortColumn === 'mapping_status') {
                $orderByColumn = "CASE WHEN md.device_id IS NOT NULL THEN 'Mapped' ELSE 'Unmapped' END";
            }
            
            // Get assets
            $sql = "SELECT 
                a.asset_id,
                a.hostname,
                a.ip_address,
                a.mac_address,
                a.asset_type,
                a.asset_subtype,
                a.manufacturer,
                a.model,
                a.serial_number,
                a.location,
                a.department,
                a.criticality,
                a.status,
                a.last_seen,
                a.location_id,
                a.location_assignment_method,
                a.location_assigned_at,
                CASE WHEN md.device_id IS NOT NULL THEN 'Mapped' ELSE 'Unmapped' END as mapping_status,
                md.brand_name,
                md.model_number,
                md.manufacturer_name,
                md.device_name,
                l.location_name as assigned_location_name,
                l.location_code as assigned_location_code,
                l.criticality as location_criticality,
                lh.hierarchy_path as location_hierarchy_path
                FROM assets a
                LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
                LEFT JOIN locations l ON a.location_id = l.location_id
                LEFT JOIN location_hierarchy lh ON l.location_id = lh.location_id
                $whereClause
                ORDER BY $orderByColumn $sortDirection
                LIMIT ? OFFSET ?";
            
            $params[] = $limit;
            $params[] = $offset;
            $stmt = $db->query($sql, $params);
            $assets = $stmt->fetchAll();
            
            echo json_encode([
                'assets' => $assets,
                'total' => $total,
                'page' => $page,
                'limit' => $limit,
                'pages' => ceil($total / $limit)
            ]);
            exit;
            
        case 'delete_asset':
            $assetId = $_POST['asset_id'] ?? '';
            
            if (!$auth->hasPermission('assets.delete')) {
                echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                exit;
            }
            
            if (empty($assetId)) {
                echo json_encode(['success' => false, 'message' => 'Asset ID is required']);
                exit;
            }
            
            $conn = null;
            try {
                $conn = $db->getConnection();
                $conn->beginTransaction();
                
                // Delete related records first (in order of dependencies)
                // 1. Delete device vulnerability links for devices associated with this asset
                $stmt = $conn->prepare("
                    DELETE FROM device_vulnerabilities_link 
                    WHERE device_id IN (
                        SELECT device_id FROM medical_devices WHERE asset_id = ?
                    )
                ");
                $stmt->execute([$assetId]);
                
                // 2. Delete action device links for devices associated with this asset
                $stmt = $conn->prepare("
                    DELETE FROM action_device_links 
                    WHERE device_id IN (
                        SELECT device_id FROM medical_devices WHERE asset_id = ?
                    )
                ");
                $stmt->execute([$assetId]);
                
                // 3. Delete SBOMs for devices associated with this asset
                // SBOMs cascade to software_components via foreign keys
                $stmt = $conn->prepare("
                    DELETE FROM sboms 
                    WHERE device_id IN (
                        SELECT device_id FROM medical_devices WHERE asset_id = ?
                    )
                ");
                $stmt->execute([$assetId]);
                
                // 4. Delete medical devices associated with this asset
                $stmt = $conn->prepare("DELETE FROM medical_devices WHERE asset_id = ?");
                $stmt->execute([$assetId]);
                
                // 5. Finally, delete the asset itself
                $stmt = $conn->prepare("DELETE FROM assets WHERE asset_id = ?");
                $stmt->execute([$assetId]);
                
                // Check if asset was actually deleted
                $checkStmt = $conn->prepare("SELECT COUNT(*) as count FROM assets WHERE asset_id = ?");
                $checkStmt->execute([$assetId]);
                $result = $checkStmt->fetch();
                
                if ($result['count'] > 0) {
                    throw new Exception('Asset still exists after deletion attempt');
                }
                
                $conn->commit();
                
                // Log action
                $auth->logUserAction($user['user_id'], 'DELETE_ASSET', 'assets', $assetId);
                
                echo json_encode(['success' => true, 'message' => 'Asset deleted successfully']);
            } catch (Exception $e) {
                if ($conn->inTransaction()) {
                    $conn->rollBack();
                }
                error_log("Error deleting asset {$assetId}: " . $e->getMessage());
                echo json_encode(['success' => false, 'message' => 'Failed to delete asset: ' . $e->getMessage()]);
            }
            exit;
            
        case 'search_510k_devices':
    $deviceId = $_GET['device_id'] ?? '';
    $limit = $_GET['limit'] ?? '1000'; // Default to 1000 results
    
    if (empty($deviceId)) {
        echo json_encode(['success' => false, 'message' => 'Device search term required']);
        exit;
    }
    
    try {
        // Call Python FDA service for 510k data with limit (non-blocking)
        $logFile = _ROOT . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . '510k_search_' . uniqid() . '.log';
        $command = "python3 " . _ROOT . "/python/services/fda_integration.py search_510k " . escapeshellarg($deviceId) . " --limit " . escapeshellarg($limit);
        $result = ShellCommandUtilities::executeShellCommand($command, [
            'blocking' => false,
            'log_file' => $logFile
        ]);
        
        if (!$result['success']) {
            echo json_encode(['success' => false, 'message' => 'Failed to start 510k search']);
        } else {
            echo json_encode([
                'success' => true,
                'message' => '510k search started',
                'job' => [
                    'job_id' => uniqid('510k_search_'),
                    'pid' => $result['pid'],
                    'log_file' => $result['log_file'],
                    'status' => 'running',
                    'type' => '510k_search',
                    'device_id' => $deviceId
                ]
            ]);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Error fetching 510k data: ' . $e->getMessage()]);
    }
    exit;

case 'search_fda_devices':
            $manufacturer = trim($_GET['manufacturer'] ?? '');
            $brandName = trim($_GET['model'] ?? ''); // Note: GET parameter is still 'model' but now contains brand name
            
            if (empty($manufacturer)) {
                echo json_encode(['success' => false, 'message' => 'Manufacturer is required']);
                exit;
            }
            
            // Call Python FDA service (non-blocking)
            $logFile = _ROOT . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . 'fda_search_' . uniqid() . '.log';
            $command = "python3 " . _ROOT . "/python/services/fda_integration.py search_devices " . 
                       escapeshellarg($manufacturer) . " " . escapeshellarg($brandName) . " 1000";
            $result = ShellCommandUtilities::executeShellCommand($command, [
                'blocking' => false,
                'log_file' => $logFile
            ]);
            
            // Debug logging
            error_log("FDA Search Command: " . $command);
            
            if (!$result['success']) {
                error_log("FDA Search Failed: Could not start command");
                echo json_encode(['success' => false, 'message' => 'Failed to start FDA search']);
            } else {
                error_log("FDA Search Started: PID=" . $result['pid']);
                echo json_encode([
                    'success' => true,
                    'message' => 'FDA search started',
                    'job' => [
                        'job_id' => uniqid('fda_search_'),
                        'pid' => $result['pid'],
                        'log_file' => $result['log_file'],
                        'status' => 'running',
                        'type' => 'fda_search',
                        'manufacturer' => $manufacturer,
                        'brand_name' => $brandName
                    ]
                ]);
            }
            exit;
            
        case 'get_manufacturer_suggestions':
            $partial = trim($_GET['partial'] ?? '');
            
            if (strlen($partial) < 2) {
                echo json_encode(['suggestions' => []]);
                exit;
            }
            
            // Call Python FDA service for suggestions (non-blocking)
            $logFile = _ROOT . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . 'fda_suggestions_' . uniqid() . '.log';
            $command = "cd " . _ROOT . " && python3 python/services/fda_integration.py get_suggestions " . escapeshellarg($partial);
            $result = ShellCommandUtilities::executeShellCommand($command, [
                'blocking' => false,
                'log_file' => $logFile
            ]);
            
            if (!$result['success']) {
                echo json_encode(['suggestions' => []]);
            } else {
                echo json_encode([
                    'success' => true,
                    'message' => 'Suggestions lookup started',
                    'job' => [
                        'job_id' => uniqid('fda_suggest_'),
                        'pid' => $result['pid'],
                        'log_file' => $result['log_file'],
                        'status' => 'running',
                        'type' => 'manufacturer_suggestions',
                        'partial' => $partial
                    ]
                ]);
            }
            exit;
            
        case 'map_device':
            error_log('map_device endpoint called');
            $assetId = $_POST['asset_id'] ?? '';
            $deviceInfo = json_decode($_POST['device_info'] ?? '{}', true);
            
            if (!$assetId || !$deviceInfo) {
                echo json_encode(['success' => false, 'message' => 'Invalid request data']);
                exit;
            }
            
            if (!$auth->hasPermission('devices.map')) {
                echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                exit;
            }
            
            try {
                $db->beginTransaction();
                
                // Helper function to safely convert values to strings
                function safeString($value, $default = '') {
                    if ($value === null || $value === '' || !isset($value)) {
                        return $default;
                    }
                    return (string) $value;
                }
                
                $sql = "INSERT INTO medical_devices (
                    asset_id, mapping_confidence, mapping_method, mapped_by, mapped_at,
                    -- 510k specific fields only
                    k_number, decision_code, decision_date, decision_description, clearance_type, date_received,
                    statement_or_summary, applicant, contact, address_1, address_2, city, state, zip_code,
                    postal_code, country_code, advisory_committee, advisory_committee_description,
                    review_advisory_committee, expedited_review_flag, third_party_flag, device_class,
                    medical_specialty_description, registration_numbers, fei_numbers, device_name, product_code, regulation_number
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                
                $stmt = $db->prepare($sql);
                $stmt->execute([
                    $assetId,
                    1.0, // mapping_confidence - set to 1.0 for 510k mapping
                    '510k_manual', // mapping_method
                    $user['user_id'],
                    date('Y-m-d H:i:s'),
                    // 510k specific fields only
                    $deviceInfo['k_number'] ?? '',
                    $deviceInfo['decision_code'] ?? '',
                    $deviceInfo['decision_date'] ?? null,
                    $deviceInfo['decision_description'] ?? '',
                    $deviceInfo['clearance_type'] ?? '',
                    $deviceInfo['date_received'] ?? null,
                    $deviceInfo['statement_or_summary'] ?? '',
                    $deviceInfo['applicant'] ?? '',
                    $deviceInfo['contact'] ?? '',
                    $deviceInfo['address_1'] ?? '',
                    $deviceInfo['address_2'] ?? '',
                    $deviceInfo['city'] ?? '',
                    $deviceInfo['state'] ?? '',
                    $deviceInfo['zip_code'] ?? '',
                    $deviceInfo['postal_code'] ?? '',
                    $deviceInfo['country_code'] ?? '',
                    $deviceInfo['advisory_committee'] ?? '',
                    $deviceInfo['advisory_committee_description'] ?? '',
                    $deviceInfo['review_advisory_committee'] ?? '',
                    $deviceInfo['expedited_review_flag'] ?? '',
                    $deviceInfo['third_party_flag'] ?? '',
                    $deviceInfo['device_class'] ?? '',
                    $deviceInfo['medical_specialty_description'] ?? '',
                    $deviceInfo['registration_numbers'] ?? '',
                    $deviceInfo['fei_numbers'] ?? '',
                    $deviceInfo['device_name'] ?? '',
                    $deviceInfo['product_code'] ?? '',
                    $deviceInfo['regulation_number'] ?? ''
                ]);
                
                $db->commit();
                
                // Log action
                $auth->logUserAction($user['user_id'], 'MAP_DEVICE', 'medical_devices', $assetId);
                
                error_log('Device mapping successful for asset: ' . $assetId);
                echo json_encode(['success' => true, 'message' => 'Device mapped successfully']);
            } catch (Exception $e) {
                $db->rollback();
                error_log('Device mapping failed: ' . $e->getMessage());
                error_log('Stack trace: ' . $e->getTraceAsString());
                echo json_encode(['success' => false, 'message' => 'Failed to map device: ' . $e->getMessage()]);
            }
            exit;
            
        case 'map_device_enhanced':
            $assetId = $_POST['asset_id'] ?? '';
            $deviceInfo = json_decode($_POST['device_info'] ?? '{}', true);
            
            if (!$assetId || !$deviceInfo) {
                echo json_encode(['success' => false, 'message' => 'Invalid request data']);
                exit;
            }
            
            if (!$auth->hasPermission('devices.map')) {
                echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                exit;
            }
            
            try {
                $db->beginTransaction();
                
                // Step 1: Store 510k data with proper UUID generation
                $sql = "INSERT INTO medical_devices (
                    device_id, asset_id, mapping_confidence, mapping_method, mapped_by, mapped_at,
                    -- 510k specific fields
                    k_number, decision_code, decision_date, decision_description, clearance_type, date_received,
                    statement_or_summary, applicant, contact, address_1, address_2, city, state, zip_code,
                    postal_code, country_code, advisory_committee, advisory_committee_description,
                    review_advisory_committee, expedited_review_flag, third_party_flag, device_class,
                    medical_specialty_description, registration_numbers, fei_numbers, device_name, product_code, regulation_number
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                
                // Generate UUID for device_id
                $deviceId = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
                    mt_rand(0, 0xffff), mt_rand(0, 0xffff),
                    mt_rand(0, 0xffff),
                    mt_rand(0, 0x0fff) | 0x4000,
                    mt_rand(0, 0x3fff) | 0x8000,
                    mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
                );
                
                $stmt = $db->prepare($sql);
                $stmt->execute([
                    $deviceId, // Use generated UUID
                    $assetId,
                    1.0, // mapping_confidence
                    '510k_enhanced', // mapping_method
                    $user['user_id'],
                    date('Y-m-d H:i:s'),
                    // 510k fields
                    $deviceInfo['k_number'] ?? '',
                    $deviceInfo['decision_code'] ?? '',
                    $deviceInfo['decision_date'] ?? null,
                    $deviceInfo['decision_description'] ?? '',
                    $deviceInfo['clearance_type'] ?? '',
                    $deviceInfo['date_received'] ?? null,
                    $deviceInfo['statement_or_summary'] ?? '',
                    $deviceInfo['applicant'] ?? '',
                    $deviceInfo['contact'] ?? '',
                    $deviceInfo['address_1'] ?? '',
                    $deviceInfo['address_2'] ?? '',
                    $deviceInfo['city'] ?? '',
                    $deviceInfo['state'] ?? '',
                    $deviceInfo['zip_code'] ?? '',
                    $deviceInfo['postal_code'] ?? '',
                    $deviceInfo['country_code'] ?? '',
                    $deviceInfo['advisory_committee'] ?? '',
                    $deviceInfo['advisory_committee_description'] ?? '',
                    $deviceInfo['review_advisory_committee'] ?? '',
                    $deviceInfo['expedited_review_flag'] ?? '',
                    $deviceInfo['third_party_flag'] ?? '',
                    $deviceInfo['device_class'] ?? '',
                    $deviceInfo['medical_specialty_description'] ?? '',
                    $deviceInfo['registration_numbers'] ?? '',
                    $deviceInfo['fei_numbers'] ?? '',
                    $deviceInfo['device_name'] ?? '',
                    $deviceInfo['product_code'] ?? '',
                    $deviceInfo['regulation_number'] ?? ''
                ]);
                
                // Step 2: Populate additional fields from 510k data
                $updateSql = "UPDATE medical_devices SET 
                    manufacturer_name = ?,
                    device_description = ?,
                    updated_at = CURRENT_TIMESTAMP
                    WHERE device_id = ?";
                
                $updateStmt = $db->prepare($updateSql);
                $updateStmt->execute([
                    $deviceInfo['applicant'] ?? '', // Use applicant as manufacturer
                    $deviceInfo['device_name'] ?? '', // Use device_name as description
                    $deviceId
                ]);
                
                $db->commit();
                
                // Log action
                $auth->logUserAction($user['user_id'], 'MAP_DEVICE_ENHANCED', 'medical_devices', $assetId);
                
                echo json_encode(['success' => true, 'message' => 'Device mapped successfully with enhanced 510k data', 'device_id' => $deviceId]);
            } catch (Exception $e) {
                $db->rollback();
                error_log('Enhanced device mapping failed: ' . $e->getMessage());
                echo json_encode(['success' => false, 'message' => 'Failed to map device: ' . $e->getMessage()]);
            }
            exit;
            
        case 'recalculate_metrics':
            try {
                // Get asset types data
                $assetTypesSql = "SELECT 
                    CASE 
                        WHEN md.device_id IS NOT NULL THEN 'Medical Device'
                        ELSE COALESCE(a.asset_type, 'Unknown')
                    END as asset_type,
                    COUNT(*) as count 
                FROM assets a
                LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
                WHERE a.status = 'Active' 
                GROUP BY 
                    CASE 
                        WHEN md.device_id IS NOT NULL THEN 'Medical Device'
                        ELSE COALESCE(a.asset_type, 'Unknown')
                    END
                ORDER BY count DESC";
                $assetTypesStmt = $db->query($assetTypesSql);
                $assetTypes = $assetTypesStmt->fetchAll(PDO::FETCH_ASSOC);

                // Get total assets
                $totalAssetsSql = "SELECT COUNT(*) as total FROM assets WHERE status = 'Active'";
                $totalAssetsStmt = $db->query($totalAssetsSql);
                $totalAssets = $totalAssetsStmt->fetch()['total'] ?? 0;

                echo json_encode([
                    'success' => true,
                    'assetTypes' => $assetTypes,
                    'totalAssets' => $totalAssets
                ]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'message' => 'Failed to recalculate metrics: ' . $e->getMessage()]);
            }
            exit;
    }
}

// Page initialization - only runs when rendering HTML (not for AJAX requests)

// Get asset types data
$sql = "SELECT 
            CASE 
                WHEN md.device_id IS NOT NULL THEN 'Medical Device'
                ELSE COALESCE(a.asset_type, 'Unknown')
            END as asset_type,
            COUNT(*) as count 
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        WHERE a.status = 'Active' 
        GROUP BY 
            CASE 
                WHEN md.device_id IS NOT NULL THEN 'Medical Device'
                ELSE COALESCE(a.asset_type, 'Unknown')
            END
        ORDER BY count DESC";

$stmt = $db->query($sql);
$assetTypes = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get total assets
$totalAssetsSql = "SELECT COUNT(*) as total FROM assets WHERE status = 'Active'";
$totalAssetsStmt = $db->query($totalAssetsSql);
$totalAssets = $totalAssetsStmt->fetch()['total'] ?? 0;

// Get filter options
$assetTypeOptions = $db->query("SELECT DISTINCT asset_type FROM assets WHERE asset_type IS NOT NULL ORDER BY asset_type")->fetchAll(PDO::FETCH_COLUMN);
$departments = $db->query("SELECT DISTINCT department FROM assets WHERE department IS NOT NULL ORDER BY department")->fetchAll(PDO::FETCH_COLUMN);
$criticalities = $db->query("SELECT DISTINCT criticality FROM assets WHERE criticality IS NOT NULL ORDER BY criticality")->fetchAll(PDO::FETCH_COLUMN);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Asset Management - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-server"></i> Asset Management</h1>
                    <p>Manage and monitor your organization's assets</p>
                </div>
                <div class="page-actions">
                    <?php if ($auth->hasPermission('assets.create')): ?>
                    <a href="/pages/assets/add.php" class="btn btn-primary">
                        <i class="fas fa-plus"></i>
                        Add Asset
                    </a>
                    <?php endif; ?>
                    <a href="/pages/assets/upload.php" class="btn btn-secondary">
                        <i class="fas fa-upload"></i>
                        Upload Files
                    </a>
                </div>
            </div>

            <!-- Asset Types Overview -->
            <div class="asset-types-section" style="margin: 2rem 0;">
                <div class="dashboard-widget asset-types-chart" style="background: linear-gradient(135deg, var(--bg-card, #111111) 0%, var(--bg-tertiary, #1a1a1a) 100%); border: 1px solid var(--border-card, #1f2937); border-radius: var(--radius-lg, 0.75rem); box-shadow: var(--shadow-lg, 0 10px 15px rgba(0, 0, 0, 0.5));">
                    <div class="widget-header" style="padding: var(--spacing-md, 1rem) var(--spacing-lg, 1.5rem); border-bottom: 1px solid var(--border-card, #1f2937); background: linear-gradient(135deg, var(--bg-tertiary, #1a1a1a) 0%, var(--bg-card, #111111) 100%); display: flex; justify-content: space-between; align-items: center;">
                        <h3 style="font-size: var(--font-size-h3, 1.5rem); margin: 0; font-weight: var(--font-weight-semibold, 600); color: var(--text-primary, #ffffff); display: flex; align-items: center; font-family: var(--font-family, 'Siemens Sans', sans-serif);">
                            <i class="fas fa-chart-pie" style="color: var(--siemens-petrol-light, #00bbbb); margin-right: var(--spacing-sm, 0.5rem); font-size: 1.1rem;"></i>
                            Asset Types
                        </h3>
                        <button type="button" id="recalculateMetricsBtn" class="btn btn-secondary btn-sm">
                            <i class="fas fa-sync-alt"></i> Recalculate
                        </button>
                    </div>
                    <div class="widget-content" style="padding: var(--spacing-lg, 1.5rem); display: flex; flex-direction: column; gap: var(--spacing-md, 1rem);">
                        <div class="chart-container" style="height: 120px; background: var(--bg-secondary, #0a0a0a); border-radius: var(--radius-md, 0.5rem); padding: var(--spacing-sm, 0.5rem) var(--spacing-md, 1rem); border: 1px solid var(--border-secondary, #374151);">
                            <canvas id="assetTypesChart" width="600" height="100"></canvas>
                        </div>
                        <div class="stats-grid" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: var(--spacing-md, 1rem);">
                            <div class="stat-card" style="background: rgba(0, 153, 153, 0.1); border: 1px solid var(--siemens-petrol, #009999); border-radius: var(--radius-md, 0.5rem); padding: var(--spacing-md, 1rem); text-align: center;">
                                <div id="assetTypesCount" class="stat-value" style="font-size: 1.25rem; font-weight: var(--font-weight-bold, 700); color: var(--siemens-petrol-light, #00bbbb); margin-bottom: var(--spacing-xs, 0.25rem);"><?php echo count($assetTypes); ?></div>
                                <div class="stat-label" style="font-size: var(--font-size-small, 0.875rem); color: var(--text-muted, #9ca3af); font-weight: var(--font-weight-medium, 500); text-transform: uppercase; letter-spacing: 0.5px;">Asset Types</div>
                            </div>
                            <div class="stat-card" style="background: rgba(16, 185, 129, 0.1); border: 1px solid var(--success-green, #10b981); border-radius: var(--radius-md, 0.5rem); padding: var(--spacing-md, 1rem); text-align: center;">
                                <div id="totalAssetsCount" class="stat-value" style="font-size: 1.25rem; font-weight: var(--font-weight-bold, 700); color: var(--success-green, #10b981); margin-bottom: var(--spacing-xs, 0.25rem);"><?php echo $totalAssets; ?></div>
                                <div class="stat-label" style="font-size: var(--font-size-small, 0.875rem); color: var(--text-muted, #9ca3af); font-weight: var(--font-weight-medium, 500); text-transform: uppercase; letter-spacing: 0.5px;">Total Assets</div>
                            </div>
                            <div class="stat-card" style="background: rgba(255, 107, 53, 0.1); border: 1px solid var(--siemens-orange, #ff6b35); border-radius: var(--radius-md, 0.5rem); padding: var(--spacing-md, 1rem); text-align: center;">
                                <div id="topAssetType" class="stat-value" style="font-size: 1.25rem; font-weight: var(--font-weight-bold, 700); color: var(--siemens-orange, #ff6b35); margin-bottom: var(--spacing-xs, 0.25rem);"><?php echo (!empty($assetTypes) && is_array($assetTypes) && isset($assetTypes[0]) && is_array($assetTypes[0]) && isset($assetTypes[0]['asset_type'])) ? dave_htmlspecialchars($assetTypes[0]['asset_type']) : 'N/A'; ?></div>
                                <div class="stat-label" style="font-size: var(--font-size-small, 0.875rem); color: var(--text-muted, #9ca3af); font-weight: var(--font-weight-medium, 500); text-transform: uppercase; letter-spacing: 0.5px;">Top Type</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Modern Filters Section -->
            <div class="filters-section">
                <!-- Search Bar -->
                <div class="search-bar-container">
                    <div class="search-input-wrapper">
                        <i class="fas fa-search search-icon"></i>
                        <input 
                            type="text" 
                            id="search" 
                            class="search-input" 
                            placeholder="Search by hostname, IP, MAC, manufacturer, model..."
                            autocomplete="off"
                        >
                        <button type="button" id="clearSearch" class="clear-search-btn" style="display: none;">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <button type="button" id="toggleFilters" class="btn-toggle-filters">
                        <i class="fas fa-sliders-h"></i>
                        <span>Filters</span>
                        <span class="filter-count" id="filterCount" style="display: none;"></span>
                    </button>
                </div>

                <!-- Collapsible Advanced Filters -->
                <div class="filters-panel" id="filtersPanel" style="display: none;">
                    <div class="filters-header">
                        <h4><i class="fas fa-filter"></i> Advanced Filters</h4>
                        <button type="button" id="clearFilters" class="btn-clear-filters">
                            <i class="fas fa-undo"></i> Reset All
                        </button>
                    </div>
                    
                    <div class="filters-grid">
                        <div class="filter-group">
                            <label for="asset_type">
                                <i class="fas fa-server"></i> Asset Type
                            </label>
                            <select id="asset_type" class="filter-select">
                                <option value="">All Types</option>
                                <?php foreach ($assetTypeOptions as $type): ?>
                                    <option value="<?php echo dave_htmlspecialchars($type); ?>">
                                        <?php echo dave_htmlspecialchars($type); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        
                        <div class="filter-group">
                            <label for="status">
                                <i class="fas fa-signal"></i> Status
                            </label>
                            <select id="status" class="filter-select">
                                <option value="">All Status</option>
                                <option value="mapped">Mapped to FDA Device</option>
                                <option value="unmapped">Not Mapped</option>
                                <option value="Active">Active</option>
                                <option value="Inactive">Inactive</option>
                            </select>
                        </div>
                        
                        <div class="filter-group">
                            <label for="department">
                                <i class="fas fa-building"></i> Department
                            </label>
                            <select id="department" class="filter-select">
                                <option value="">All Departments</option>
                                <?php foreach ($departments as $dept): ?>
                                    <option value="<?php echo dave_htmlspecialchars($dept); ?>">
                                        <?php echo dave_htmlspecialchars($dept); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        
                        <div class="filter-group">
                            <label for="location_id">
                                <i class="fas fa-map-marker-alt"></i> Location
                            </label>
                            <select id="location_id" class="filter-select">
                                <option value="">All Locations</option>
                                <option value="unassigned">Unassigned</option>
                                <?php 
                                $locations = $db->query("SELECT location_id, location_name, location_code FROM locations WHERE is_active = TRUE ORDER BY location_name")->fetchAll();
                                foreach ($locations as $location): ?>
                                    <option value="<?php echo dave_htmlspecialchars($location['location_id']); ?>">
                                        <?php echo dave_htmlspecialchars($location['location_name'] . ' (' . $location['location_code'] . ')'); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        
                        <div class="filter-group">
                            <label for="criticality">
                                <i class="fas fa-exclamation-triangle"></i> Criticality
                            </label>
                            <select id="criticality" class="filter-select">
                                <option value="">All Criticality Levels</option>
                                <?php foreach ($criticalities as $crit): ?>
                                    <option value="<?php echo dave_htmlspecialchars($crit); ?>">
                                        <?php echo dave_htmlspecialchars($crit); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>
                    
                    <div class="filters-footer">
                        <div class="filter-results-info">
                            <span id="filteredCount">Showing all assets</span>
                        </div>
                        <div class="filter-actions-group">
                            <button type="button" id="applyFilters" class="btn btn-primary">
                                <i class="fas fa-check"></i>
                                Apply Filters
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Assets Table Card -->
            <div class="assets-card" style="background: linear-gradient(135deg, var(--bg-card, #111111) 0%, var(--bg-tertiary, #1a1a1a) 100%); border: 1px solid var(--border-card, #1f2937); border-radius: var(--radius-lg, 0.75rem); box-shadow: var(--shadow-lg, 0 10px 15px rgba(0, 0, 0, 0.5)); margin: 2rem 0;">
                <div class="card-header" style="padding: var(--spacing-md, 1rem) var(--spacing-lg, 1.5rem); border-bottom: 1px solid var(--border-card, #1f2937); background: linear-gradient(135deg, var(--bg-tertiary, #1a1a1a) 0%, var(--bg-card, #111111) 100%);">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <h2 style="margin: 0; font-size: 1.5rem; font-weight: 600; color: var(--text-primary, #ffffff); display: flex; align-items: center; font-family: var(--font-family, 'Siemens Sans', sans-serif);">
                            <i class="fas fa-server" style="color: var(--siemens-petrol-light, #00bbbb); margin-right: 0.5rem; font-size: 1.1rem;"></i>
                            Assets
                        </h2>
                        <div class="section-actions">
                            <div class="view-toggle">
                                <button type="button" class="view-btn active" data-view="table">
                                    <i class="fas fa-table"></i>
                                </button>
                                <button type="button" class="view-btn" data-view="grid">
                                    <i class="fas fa-th"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="pagination-controls-top" style="display: flex; justify-content: flex-start; align-items: center;">
                        <div class="per-page-selector">
                            <label for="perPageSelect" style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; margin-right: 0.5rem;">Show:</label>
                            <select id="perPageSelect" class="per-page-select" onchange="changePerPage(this.value)">
                                <option value="25" selected>25</option>
                                <option value="50">50</option>
                                <option value="100">100</option>
                                <option value="200">200</option>
                            </select>
                            <span style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; margin-left: 0.5rem;">per page</span>
                        </div>
                    </div>
                </div>

                <div class="card-content" style="padding: var(--spacing-lg, 1.5rem);">
                    <div class="assets-container">
                        <div id="assetsTable" class="assets-table">
                            <div class="table-header">
                                <div class="table-row">
                                    <div class="table-cell sortable" data-sort="hostname">
                                        Hostname
                                        <span class="sort-indicator"></span>
                                    </div>
                                    <div class="table-cell sortable" data-sort="ip_address">
                                        IP Address
                                        <span class="sort-indicator"></span>
                                    </div>
                                    <div class="table-cell sortable" data-sort="asset_type">
                                        Type
                                        <span class="sort-indicator"></span>
                                    </div>
                                    <div class="table-cell sortable" data-sort="department">
                                        Department
                                        <span class="sort-indicator"></span>
                                    </div>
                                    <div class="table-cell sortable" data-sort="location">
                                        Location
                                        <span class="sort-indicator"></span>
                                    </div>
                                    <div class="table-cell sortable" data-sort="criticality">
                                        Criticality
                                        <span class="sort-indicator"></span>
                                    </div>
                                    <div class="table-cell sortable" data-sort="status">
                                        Status
                                        <span class="sort-indicator"></span>
                                    </div>
                                    <div class="table-cell sortable" data-sort="mapping_status">
                                        Mapping
                                        <span class="sort-indicator"></span>
                                    </div>
                                    <div class="table-cell">Actions</div>
                                </div>
                            </div>
                            <div id="assetsTableBody" class="table-body">
                                <!-- Assets will be loaded here via AJAX -->
                            </div>
                        </div>

                        <div id="assetsGrid" class="assets-grid" style="display: none;">
                            <!-- Grid view will be loaded here -->
                        </div>
                    </div>
                </div>

                <!-- Pagination Controls -->
                <div class="pagination-section" style="padding: 0 var(--spacing-lg, 1.5rem) var(--spacing-lg, 1.5rem);">
                    <div id="pagination" class="pagination">
                        <!-- Pagination will be loaded here -->
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- Delete Confirmation Modal -->
    <div id="deleteModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Confirm Delete</h3>
                <button type="button" class="modal-close">&times;</button>
            </div>
            <div class="modal-body">
                <p>Are you sure you want to delete this asset? This action cannot be undone.</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" id="cancelDelete">Cancel</button>
                <button type="button" class="btn btn-danger" id="confirmDelete">Delete</button>
            </div>
        </div>
    </div>

    <script>
        // Asset Management JavaScript
        let currentPage = 1;
        let currentLimit = 25;
        let currentFilters = {};
        let deleteAssetId = null;
        let assetTypesChart; // Global chart variable for recalculate functionality
        let currentSort = { column: 'last_seen', direction: 'DESC' }; // Default sort

        // Define clearFilters function early to ensure it's available
        function clearFilters() {
            // Clear all filter form elements
            const searchInput = document.getElementById('search');
            const assetTypeSelect = document.getElementById('asset_type');
            const statusSelect = document.getElementById('status');
            const departmentSelect = document.getElementById('department');
            const locationSelect = document.getElementById('location_id');
            const criticalitySelect = document.getElementById('criticality');
            
            if (searchInput) {
                searchInput.value = '';
                searchInput.dispatchEvent(new Event('input', { bubbles: true }));
            }
            if (assetTypeSelect) {
                assetTypeSelect.value = '';
                assetTypeSelect.dispatchEvent(new Event('change', { bubbles: true }));
            }
            if (statusSelect) {
                statusSelect.value = '';
                statusSelect.dispatchEvent(new Event('change', { bubbles: true }));
            }
            if (departmentSelect) {
                departmentSelect.value = '';
                departmentSelect.dispatchEvent(new Event('change', { bubbles: true }));
            }
            if (locationSelect) {
                locationSelect.value = '';
                locationSelect.dispatchEvent(new Event('change', { bubbles: true }));
            }
            if (criticalitySelect) {
                criticalitySelect.value = '';
                criticalitySelect.dispatchEvent(new Event('change', { bubbles: true }));
            }
            
            // Reset filters object
            currentFilters = {};
            
            // Reload assets
            loadAssets();
        }
        

        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {
            loadAssets();
            setupEventListeners();
            loadAssetTypesChart();
            
            // Set the per page selector to current limit
            const perPageSelect = document.getElementById('perPageSelect');
            if (perPageSelect) {
                perPageSelect.value = currentLimit;
            }
            
            // Recalculate Metrics Button
            const recalculateBtn = document.getElementById('recalculateMetricsBtn');
            if (recalculateBtn) {
                recalculateBtn.addEventListener('click', function() {
                    const btn = this;
                    const icon = btn.querySelector('i');
                    
                    // Set loading state
                    btn.disabled = true;
                    icon.classList.add('fa-spin');

                    fetch('?ajax=recalculate_metrics')
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                // Update stat cards
                                document.getElementById('assetTypesCount').textContent = data.assetTypes.length;
                                document.getElementById('totalAssetsCount').textContent = data.totalAssets;
                                document.getElementById('topAssetType').textContent = data.assetTypes.length > 0 ? data.assetTypes[0].asset_type : 'N/A';
                                
                                // Update chart
                                if (typeof assetTypesChart !== 'undefined') {
                                    assetTypesChart.data.labels = data.assetTypes.map(d => d.asset_type);
                                    assetTypesChart.data.datasets[0].data = data.assetTypes.map(d => d.count);
                                    assetTypesChart.update();
                                }
                                
                                showNotification('Metrics recalculated successfully!', 'success');
                            } else {
                                showNotification(data.message || 'Failed to recalculate metrics', 'error');
                            }
                        })
                        .catch(error => {
                            console.error('Error recalculating metrics:', error);
                            showNotification('An error occurred while recalculating metrics.', 'error');
                        })
                        .finally(() => {
                            // Reset button state
                            btn.disabled = false;
                            icon.classList.remove('fa-spin');
                        });
                });
            }
        });
        
        // Load Asset Types Chart
        function loadAssetTypesChart() {
            try {
                
                // Get asset types data from PHP
                const assetTypes = <?php echo json_encode($assetTypes); ?>;
                
                createAssetTypesChart(assetTypes);
            } catch (error) {
                console.error('Error loading asset types chart:', error);
            }
        }

        function createAssetTypesChart(assetTypes) {
            
            // Check if Chart.js is available
            if (typeof Chart === 'undefined') {
                console.error('Chart.js is not loaded!');
                return;
            }
            
            const ctx = document.getElementById('assetTypesChart');
            if (!ctx) {
                console.error('Canvas element not found: assetTypesChart');
                return;
            }
            
            if (!assetTypes || assetTypes.length === 0) {
                return;
            }
            
            // Prepare chart data
            const labels = assetTypes.map(type => {
                // Truncate long type names
                const name = type.asset_type || type;
                return name.length > 12 ? name.substring(0, 12) + '...' : name;
            });
            const data = assetTypes.map(type => {
                return parseInt(type.count || 1);
            });
            
            // Generate colors for each bar
            const colors = [
                'rgba(0, 153, 153, 0.8)',   // Siemens Petrol
                'rgba(0, 187, 187, 0.8)',   // Siemens Petrol Light
                'rgba(255, 107, 53, 0.8)',  // Siemens Orange
                'rgba(16, 185, 129, 0.8)',  // Success Green
                'rgba(168, 85, 247, 0.8)',  // Purple
                'rgba(236, 72, 153, 0.8)'   // Pink
            ];
            
            const borderColors = [
                'rgba(0, 153, 153, 1)',
                'rgba(0, 187, 187, 1)',
                'rgba(255, 107, 53, 1)',
                'rgba(16, 185, 129, 1)',
                'rgba(168, 85, 247, 1)',
                'rgba(236, 72, 153, 1)'
            ];
            
            assetTypesChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Asset Count',
                        data: data,
                        backgroundColor: colors.slice(0, data.length),
                        borderColor: borderColors.slice(0, data.length),
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: '#94a3b8',
                                font: {
                                    size: 9
                                },
                                maxRotation: 45
                            },
                            grid: {
                                color: '#374151'
                            }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: {
                                color: '#94a3b8',
                                font: {
                                    size: 10
                                }
                            },
                            grid: {
                                color: '#374151'
                            }
                        }
                    }
                }
            });
            
        }

        function setupEventListeners() {
            
            // Filter controls
            const applyFiltersBtn = document.getElementById('applyFilters');
            const clearFiltersBtn = document.getElementById('clearFilters');
            
            if (applyFiltersBtn) {
                applyFiltersBtn.addEventListener('click', applyFilters);
            } else {
                console.error('Apply filters button not found!');
            }
            
            if (clearFiltersBtn) {
                clearFiltersBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    try {
                        if (typeof clearFilters === 'function') {
                            clearFilters();
                        } else {
                            console.error('clearFilters is not a function!');
                        }
                    } catch (error) {
                        console.error('Error calling clearFilters:', error);
                    }
                });
            } else {
                console.error('Clear filters button not found!');
            }
            
            // Toggle filters panel
            document.getElementById('toggleFilters').addEventListener('click', toggleFiltersPanel);
            
            // Search input with real-time filtering
            const searchInput = document.getElementById('search');
            const clearSearchBtn = document.getElementById('clearSearch');
            
            searchInput.addEventListener('input', function(e) {
                const value = e.target.value;
                if (value.length > 0) {
                    clearSearchBtn.style.display = 'flex';
                } else {
                    clearSearchBtn.style.display = 'none';
                }
                
                // Real-time search after 500ms pause
                clearTimeout(searchInput.searchTimeout);
                searchInput.searchTimeout = setTimeout(() => {
                    if (value.length === 0 || value.length >= 2) {
                        applyFilters();
                    }
                }, 500);
            });
            
            clearSearchBtn.addEventListener('click', function() {
                searchInput.value = '';
                clearSearchBtn.style.display = 'none';
                applyFilters();
            });
            
            // Column sorting
            document.querySelectorAll('.sortable').forEach(header => {
                header.addEventListener('click', function() {
                    const column = this.dataset.sort;
                    
                    // Toggle sort direction if clicking the same column
                    if (currentSort.column === column) {
                        currentSort.direction = currentSort.direction === 'ASC' ? 'DESC' : 'ASC';
                    } else {
                        currentSort.column = column;
                        currentSort.direction = 'ASC';
                    }
                    
                    // Reset to first page when sorting
                    currentPage = 1;
                    
                    // Update sort indicators
                    updateSortIndicators();
                    
                    // Reload assets with new sort
                    loadAssets();
                });
                
                // Add cursor pointer style
                header.style.cursor = 'pointer';
                header.style.userSelect = 'none';
            });
            
            // Initialize sort indicators
            updateSortIndicators();
            
            // View toggle
            document.querySelectorAll('.view-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
                    this.classList.add('active');
                    toggleView(this.dataset.view);
                });
            });

            // Modal controls
            document.getElementById('cancelDelete').addEventListener('click', closeDeleteModal);
            document.getElementById('confirmDelete').addEventListener('click', confirmDelete);
            document.querySelector('.modal-close').addEventListener('click', closeDeleteModal);
        }
        
        // Toggle filters panel visibility
        function toggleFiltersPanel() {
            const panel = document.getElementById('filtersPanel');
            const button = document.getElementById('toggleFilters');
            
            if (panel.style.display === 'none' || !panel.style.display) {
                panel.style.display = 'block';
                button.classList.add('active');
            } else {
                panel.style.display = 'none';
                button.classList.remove('active');
            }
        }
        
        // Update filter count badge
        function updateFilterCount() {
            const filterCount = Object.keys(currentFilters).filter(key => 
                key !== 'search' && currentFilters[key] && currentFilters[key] !== ''
            ).length;
            
            const countBadge = document.getElementById('filterCount');
            if (filterCount > 0) {
                countBadge.textContent = filterCount;
                countBadge.style.display = 'inline-block';
            } else {
                countBadge.style.display = 'none';
            }
        }
        
        // Update sort indicators in table headers
        function updateSortIndicators() {
            document.querySelectorAll('.sortable').forEach(header => {
                const indicator = header.querySelector('.sort-indicator');
                const column = header.dataset.sort;
                
                if (currentSort.column === column) {
                    indicator.textContent = currentSort.direction === 'ASC' ? ' ▲' : ' ▼';
                    indicator.style.color = 'var(--siemens-petrol, #009999)';
                    header.style.color = 'var(--siemens-petrol, #009999)';
                    header.style.fontWeight = '600';
                } else {
                    indicator.textContent = ' ⇅';
                    indicator.style.color = 'var(--text-muted, #94a3b8)';
                    header.style.color = '';
                    header.style.fontWeight = '';
                }
            });
        }

        function loadAssets() {
            const params = new URLSearchParams({
                ajax: 'get_assets',
                page: currentPage,
                limit: currentLimit,
                sort_column: currentSort.column,
                sort_direction: currentSort.direction,
                ...currentFilters
            });


            fetch('?' + params.toString())
                .then(response => response.json())
                .then(data => {
                    displayAssets(data.assets);
                    updatePagination(data);
                    updateFilteredCountDisplay(data.total, data.assets.length);
                })
                .catch(error => {
                    console.error('Error loading assets:', error);
                    showNotification('Error loading assets', 'error');
                });
        }
        
        // Update the filtered count display
        function updateFilteredCountDisplay(total, showing) {
            const filteredCountEl = document.getElementById('filteredCount');
            const hasActiveFilters = Object.values(currentFilters).some(val => val && val !== '');
            
            if (hasActiveFilters) {
                filteredCountEl.textContent = `Showing ${showing} of ${total} assets (filtered)`;
                filteredCountEl.style.color = 'var(--siemens-petrol)';
                filteredCountEl.style.fontWeight = '600';
            } else {
                filteredCountEl.textContent = `Showing ${showing} of ${total} assets`;
                filteredCountEl.style.color = 'var(--text-secondary)';
                filteredCountEl.style.fontWeight = '500';
            }
        }

        function displayAssets(assets) {
            
            const tableBody = document.getElementById('assetsTableBody');
            const gridContainer = document.getElementById('assetsGrid');
            
            if (assets.length === 0) {
                tableBody.innerHTML = '<div class="empty-state"><i class="fas fa-inbox"></i><p>No assets found</p></div>';
                gridContainer.innerHTML = '<div class="empty-state"><i class="fas fa-inbox"></i><p>No assets found</p></div>';
                return;
            }

            // Table view
            tableBody.innerHTML = assets.map(asset => `
                <div class="table-row">
                    <div class="table-cell">
                        <div class="asset-name">${asset.hostname || asset.brand_name || asset.device_name || 'Unknown'}</div>
                        <div class="asset-subtitle">${asset.asset_subtype || ''}</div>
                        <div class="manufacturer-info">
                            <div class="manufacturer-name">${asset.manufacturer_name || asset.manufacturer || '-'}</div>
                        </div>
                    </div>
                    <div class="table-cell">${asset.ip_address || '-'}</div>
                    <div class="table-cell">
                        <span class="type-badge ${asset.mapping_status === 'Mapped' ? 'medical-device' : ''}">
                            ${asset.mapping_status === 'Mapped' ? 'Medical Device' : asset.asset_type}
                        </span>
                    </div>
                    <div class="table-cell">${asset.assigned_location_name || (asset.department || '-')}</div>
                    <div class="table-cell">
                        ${asset.location_hierarchy_path ? `
                            <div class="location-info">
                                <div class="location-name">${asset.assigned_location_name || 'Unknown'}</div>
                                <div class="location-path">${asset.location_hierarchy_path}</div>
                                <div class="location-method">${asset.location_assignment_method || 'Manual'}</div>
                            </div>
                        ` : '<span class="text-muted">Unassigned</span>'}
                    </div>
                    <div class="table-cell">
                        <span class="criticality-badge criticality-${asset.location_criticality || asset.criticality || 'unknown'}">
                            ${asset.location_criticality || asset.criticality || '-'}
                        </span>
                    </div>
                    <div class="table-cell">
                        <span class="status-badge ${asset.status.toLowerCase()}">${asset.status}</span>
                    </div>
                    <div class="table-cell">
                        <span class="mapping-badge ${asset.mapping_status.toLowerCase()}">${asset.mapping_status}</span>
                    </div>
                    <div class="table-cell">
                        <div class="action-dropdown">
                            <button type="button" class="dropdown-trigger" onclick="toggleDropdown('${asset.asset_id}')" title="Actions">
                                <i class="fas fa-ellipsis-v"></i>
                            </button>
                            <div class="dropdown-menu" id="dropdown-${asset.asset_id}">
                                <button type="button" class="dropdown-item view" onclick="openAssetModal('${asset.asset_id}')">
                                    <i class="fas fa-eye"></i>
                                    <span>View Details</span>
                                </button>
                                ${'<?php echo $auth->hasPermission("devices.map") ? "true" : "false"; ?>' === 'true' ? `
                                <button type="button" class="dropdown-item map" onclick="open510kMappingModal('${asset.asset_id}')">
                                    <i class="fas fa-file-medical"></i>
                                    <span>Map Device to 510k</span>
                                </button>
                                ` : ''}
                                ${'<?php echo $auth->hasPermission("assets.edit") ? "true" : "false"; ?>' === 'true' ? `
                                <a href="/pages/assets/edit.php?id=${asset.asset_id}" class="dropdown-item edit">
                                    <i class="fas fa-edit"></i>
                                    <span>Edit Asset</span>
                                </a>
                                ` : ''}
                                ${'<?php echo $auth->hasPermission("assets.delete") ? "true" : "false"; ?>' === 'true' ? `
                                <button type="button" class="dropdown-item delete" onclick="showDeleteModal('${asset.asset_id}')">
                                    <i class="fas fa-trash"></i>
                                    <span>Delete Asset</span>
                                </button>
                                ` : ''}
                            </div>
                        </div>
                    </div>
                </div>
            `).join('');

            // Grid view
            gridContainer.innerHTML = assets.map(asset => `
                <div class="asset-card">
                    <div class="asset-card-header">
                        <div class="asset-name">${asset.hostname || asset.brand_name || 'Unknown'}</div>
                        <div class="asset-ip">${asset.ip_address || '-'}</div>
                    </div>
                    <div class="asset-card-body">
                        <div class="asset-details">
                            <div class="detail-item">
                                <span class="label">Type:</span>
                                <span class="value">
                                    <span class="type-badge ${asset.mapping_status === 'Mapped' ? 'medical-device' : ''}">
                                        ${asset.mapping_status === 'Mapped' ? 'Medical Device' : asset.asset_type}
                                    </span>
                                </span>
                            </div>
                            <div class="detail-item">
                                <span class="label">Manufacturer:</span>
                                <span class="value">${asset.manufacturer_name || asset.manufacturer || '-'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="label">Department:</span>
                                <span class="value">${asset.assigned_location_name || (asset.department || '-')}</span>
                            </div>
                            <div class="detail-item">
                                <span class="label">Criticality:</span>
                                <span class="criticality-badge criticality-${asset.location_criticality || asset.criticality || 'unknown'}">
                                    ${asset.location_criticality || asset.criticality || '-'}
                                </span>
                            </div>
                        </div>
                        <div class="asset-status">
                            <span class="status-badge ${asset.status.toLowerCase()}">${asset.status}</span>
                            <span class="mapping-badge ${asset.mapping_status.toLowerCase()}">${asset.mapping_status}</span>
                        </div>
                    </div>
                    <div class="asset-card-footer">
                        <div class="action-buttons">
                            <a href="/pages/assets/view.php?id=${asset.asset_id}" class="btn btn-sm btn-primary">
                                <i class="fas fa-eye"></i> View
                            </a>
                            ${'<?php echo $auth->hasPermission("vulnerabilities.manage") ? "true" : "false"; ?>' === 'true' ? `
                            <button type="button" class="btn btn-sm btn-accent" onclick="scanAsset('${asset.asset_id}')">
                                <i class="fas fa-search"></i> Scan
                            </button>
                            ` : ''}
                            ${'<?php echo $auth->hasPermission("assets.edit") ? "true" : "false"; ?>' === 'true' ? `
                            <a href="/pages/assets/edit.php?id=${asset.asset_id}" class="btn btn-sm btn-secondary">
                                <i class="fas fa-edit"></i> Edit
                            </a>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `).join('');
        }

        function updatePagination(data) {
            const pagination = document.getElementById('pagination');
            if (data.pages <= 1) {
                pagination.innerHTML = '';
                return;
            }
            

            let paginationHTML = '<div class="pagination-controls">';
            
            // Previous button
            if (data.page > 1) {
                paginationHTML += `<button type="button" class="btn btn-sm btn-secondary" onclick="changePage(${data.page - 1})">
                    <i class="fas fa-chevron-left"></i> Previous
                </button>`;
            }

            // Page numbers
            const startPage = Math.max(1, data.page - 2);
            const endPage = Math.min(data.pages, data.page + 2);

            for (let i = startPage; i <= endPage; i++) {
                paginationHTML += `<button type="button" class="btn btn-sm ${i === data.page ? 'btn-primary' : 'btn-secondary'}" onclick="changePage(${i})">${i}</button>`;
            }

            // Next button
            if (data.page < data.pages) {
                paginationHTML += `<button type="button" class="btn btn-sm btn-secondary" onclick="changePage(${data.page + 1})">
                    Next <i class="fas fa-chevron-right"></i>
                </button>`;
            }

            paginationHTML += '</div>';
            pagination.innerHTML = paginationHTML;
        }

        function changePage(page) {
            currentPage = page;
            loadAssets();
        }
        
        function changePerPage(perPage) {
            currentLimit = parseInt(perPage);
            currentPage = 1; // Reset to first page when changing per page
            loadAssets();
        }

        function applyFilters() {
            currentFilters = {
                search: document.getElementById('search').value,
                asset_type: document.getElementById('asset_type').value,
                status: document.getElementById('status').value,
                department: document.getElementById('department').value,
                location_id: document.getElementById('location_id').value,
                criticality: document.getElementById('criticality').value
            };
            currentPage = 1;
            updateFilterCount();
            loadAssets();
        }

        function toggleView(view) {
            const tableView = document.getElementById('assetsTable');
            const gridView = document.getElementById('assetsGrid');
            
            if (view === 'table') {
                tableView.style.display = 'block';
                gridView.style.display = 'none';
            } else {
                tableView.style.display = 'none';
                gridView.style.display = 'grid';
            }
        }

        function showDeleteModal(assetId) {
            if (!assetId) {
                console.error('showDeleteModal called without assetId');
                showNotification('Error: Cannot delete asset - asset ID is missing', 'error');
                return;
            }
            console.log('Opening delete modal for asset:', assetId);
            deleteAssetId = assetId;
            const modal = document.getElementById('deleteModal');
            if (modal) {
                modal.classList.add('show');
            } else {
                console.error('Delete modal element not found');
                showNotification('Error: Delete modal not found', 'error');
            }
        }

        function closeDeleteModal() {
            document.getElementById('deleteModal').classList.remove('show');
            deleteAssetId = null;
        }

        function confirmDelete() {
            if (!deleteAssetId) {
                console.error('Cannot delete: deleteAssetId is not set', deleteAssetId);
                showNotification('Error: Asset ID is missing. Please close and try again.', 'error');
                return;
            }

            console.log('Deleting asset:', deleteAssetId);
            
            // Disable the delete button to prevent double-clicks
            const confirmBtn = document.getElementById('confirmDelete');
            if (confirmBtn) {
                confirmBtn.disabled = true;
                confirmBtn.textContent = 'Deleting...';
            }

            fetch('?ajax=delete_asset', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'asset_id=' + encodeURIComponent(deleteAssetId)
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('HTTP error! status: ' + response.status);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    showNotification('Asset deleted successfully', 'success');
                    loadAssets();
                } else {
                    showNotification(data.message || 'Failed to delete asset', 'error');
                }
                closeDeleteModal();
            })
            .catch(error => {
                console.error('Error deleting asset:', error);
                showNotification('Error deleting asset: ' + error.message, 'error');
                closeDeleteModal();
            })
            .finally(() => {
                // Re-enable the delete button
                if (confirmBtn) {
                    confirmBtn.disabled = false;
                    confirmBtn.textContent = 'Delete';
                }
            });
        }

        function scanAsset(assetId) {
            // Show scan modal
            showScanModal(assetId);
        }

        function showScanModal(assetId) {
            const modal = document.createElement('div');
            modal.className = 'modal-overlay';
            modal.innerHTML = `
                <div class="modal-content">
                    <div class="modal-header">
                        <h3><i class="fas fa-search"></i> Scan Asset for Vulnerabilities</h3>
                        <button type="button" class="modal-close" onclick="closeScanModal()">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label for="scan_type">Scan Type</label>
                            <select id="scan_type" class="form-control">
                                <option value="full">Full Scan - Comprehensive vulnerability analysis</option>
                                <option value="quick">Quick Scan - Fast vulnerability check</option>
                                <option value="deep">Deep Scan - Detailed component analysis</option>
                                <option value="sbom">SBOM Scan - Software bill of materials analysis</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="checkbox-label">
                                <input type="checkbox" id="include_sbom">
                                <span class="checkmark"></span>
                                Include SBOM Analysis
                            </label>
                        </div>
                        <div class="scan-info">
                            <p><strong>Asset ID:</strong> ${assetId}</p>
                            <p><strong>Note:</strong> This will trigger a vulnerability scan using the integrated Python scanner and NVD database.</p>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" onclick="closeScanModal()">Cancel</button>
                        <button type="button" class="btn btn-primary" onclick="startScan('${assetId}')">
                            <i class="fas fa-search"></i> Start Scan
                        </button>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }

        function startScan(assetId) {
            const scanType = document.getElementById('scan_type').value;
            const includeSbom = document.getElementById('include_sbom').checked;
            
            // Close modal
            closeScanModal();
            
            // Show loading notification
            showNotification('Starting vulnerability scan...', 'info');
            
            // Make API call to scan endpoint
            fetch('/api/v1/vulnerabilities/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    asset_id: assetId,
                    scan_type: scanType,
                    include_sbom: includeSbom
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(`Vulnerability scan started successfully. Scan ID: ${data.data.scan_id}`, 'success');
                    // Optionally refresh the page to show updated data
                    setTimeout(() => location.reload(), 3000);
                } else {
                    showNotification(data.error?.message || 'Failed to start vulnerability scan', 'error');
                }
            })
            .catch(error => {
                console.error('Error starting scan:', error);
                showNotification('Error starting vulnerability scan', 'error');
            });
        }

        function closeScanModal() {
            const modal = document.querySelector('.modal-overlay');
            if (modal) {
                modal.remove();
            }
        }

        function showNotification(message, type) {
            // Simple notification system
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
                ${message}
            `;
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 3000);
        }
    </script>

    <style>
        /* ========================================
           MODERN FILTERS SECTION STYLING
           ======================================== */
        
        .filters-section {
            background: var(--bg-card);
            border-radius: 0.75rem;
            border: 1px solid var(--border-primary);
            margin-bottom: 2rem;
            overflow: hidden;
        }
        
        /* Search Bar Container */
        .search-bar-container {
            display: flex;
            gap: 1rem;
            padding: 1.25rem;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-primary);
        }
        
        .search-input-wrapper {
            flex: 1;
            position: relative;
            display: flex;
            align-items: center;
        }
        
        .search-icon {
            position: absolute;
            left: 1rem;
            color: var(--text-secondary);
            font-size: 1rem;
            pointer-events: none;
        }
        
        .search-input {
            width: 100%;
            padding: 0.875rem 3rem 0.875rem 3rem;
            border: 2px solid var(--border-primary);
            border-radius: 0.5rem;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 0.95rem;
            transition: all 0.2s ease;
            font-family: 'Siemens Sans', sans-serif;
        }
        
        .search-input:focus {
            outline: none;
            border-color: var(--siemens-petrol);
            box-shadow: 0 0 0 4px rgba(0, 153, 153, 0.1);
            background: var(--bg-card);
        }
        
        .search-input::placeholder {
            color: var(--text-muted);
        }
        
        .clear-search-btn {
            position: absolute;
            right: 1rem;
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 0.5rem;
            border-radius: 0.25rem;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .clear-search-btn:hover {
            color: var(--text-primary);
            background: var(--bg-hover);
        }
        
        .btn-toggle-filters {
            display: flex;
            align-items: center;
            gap: 0.625rem;
            padding: 0.875rem 1.5rem;
            background: var(--bg-tertiary);
            border: 2px solid var(--border-primary);
            border-radius: 0.5rem;
            color: var(--text-primary);
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            white-space: nowrap;
        }
        
        .btn-toggle-filters:hover {
            background: var(--siemens-petrol);
            border-color: var(--siemens-petrol);
            color: white;
            transform: translateY(-1px);
        }
        
        .btn-toggle-filters.active {
            background: var(--siemens-petrol);
            border-color: var(--siemens-petrol);
            color: white;
        }
        
        .filter-count {
            background: var(--siemens-orange);
            color: white;
            padding: 0.25rem 0.625rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 700;
            min-width: 1.5rem;
            text-align: center;
        }
        
        /* Filters Panel */
        .filters-panel {
            background: var(--bg-primary);
            border-top: 2px solid var(--border-primary);
            animation: slideDown 0.3s ease;
        }
        
        @keyframes slideDown {
            from {
                opacity: 0;
                max-height: 0;
            }
            to {
                opacity: 1;
                max-height: 500px;
            }
        }
        
        .filters-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.25rem 1.5rem;
            border-bottom: 1px solid var(--border-secondary);
        }
        
        .filters-header h4 {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            color: var(--text-primary);
            font-size: 1.125rem;
            font-weight: 600;
            margin: 0;
        }
        
        .filters-header h4 i {
            color: var(--siemens-petrol);
        }
        
        .btn-clear-filters {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.375rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .btn-clear-filters:hover {
            background: var(--bg-hover);
            border-color: var(--siemens-orange);
            color: var(--siemens-orange);
        }
        
        /* Filters Grid */
        .filters-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.25rem;
            padding: 1.5rem;
        }
        
        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        
        .filter-group label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-primary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .filter-group label i {
            color: var(--siemens-petrol);
            font-size: 0.9rem;
        }
        
        .filter-select {
            padding: 0.75rem 1rem;
            border: 2px solid var(--border-primary);
            border-radius: 0.5rem;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 0.9rem;
            font-family: 'Siemens Sans', sans-serif;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .filter-select:focus {
            outline: none;
            border-color: var(--siemens-petrol);
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
            background: var(--bg-card);
        }
        
        .filter-select:hover {
            border-color: var(--siemens-petrol);
        }
        
        .filter-select option {
            background: var(--bg-secondary);
            color: var(--text-primary);
            padding: 0.5rem;
        }
        
        /* Filters Footer */
        .filters-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.25rem 1.5rem;
            background: var(--bg-secondary);
            border-top: 1px solid var(--border-secondary);
        }
        
        .filter-results-info {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .filter-results-info span {
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 500;
        }
        
        .filter-actions-group {
            display: flex;
            gap: 0.75rem;
        }
        
        /* Responsive Design */
        @media (max-width: 1024px) {
            .filters-grid {
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            }
        }
        
        @media (max-width: 768px) {
            .search-bar-container {
                flex-direction: column;
            }
            
            .btn-toggle-filters {
                width: 100%;
                justify-content: center;
            }
            
            .filters-grid {
                grid-template-columns: 1fr;
            }
            
            .filters-footer {
                flex-direction: column;
                gap: 1rem;
            }
            
            .filter-actions-group {
                width: 100%;
            }
            
            .filter-actions-group button {
                flex: 1;
            }
        }
        
        /* ========================================
           END MODERN FILTERS STYLING
           ======================================== */
        
        /* Delete Modal Styles - Ensure it appears above all content */
        #deleteModal {
            display: none !important;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 5000;
            align-items: center;
            justify-content: center;
        }
        
        #deleteModal.show {
            display: flex !important;
        }
        
        /* Scan Button Styles */
        .btn-icon.scan {
            background: var(--siemens-orange);
            color: white;
        }

        .btn-icon.scan:hover {
            background: var(--siemens-orange-dark);
            color: white;
        }

        /* Scan Modal Styles */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 1000;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background: var(--bg-card);
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
        }

        .modal-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-header h3 {
            margin: 0;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .modal-close {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0.25rem;
        }

        .modal-close:hover {
            color: var(--text-primary);
        }

        .modal-body {
            padding: 1.5rem;
        }

        .modal-footer {
            padding: 1.5rem;
            border-top: 1px solid var(--border-primary);
            display: flex;
            gap: 1rem;
            justify-content: flex-end;
        }

        .scan-info {
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: 4px;
            margin-top: 1rem;
        }

        .scan-info p {
            margin: 0.25rem 0;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            cursor: pointer;
            margin: 0.5rem 0;
        }

        .checkbox-label input[type="checkbox"] {
            margin: 0;
        }

        /* FDA Badge */
        .fda-badge {
            display: inline-block;
            margin-left: 0.5rem;
            padding: 0.2rem 0.4rem;
            background: var(--siemens-petrol);
            color: white;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 500;
            vertical-align: middle;
        }

        .fda-badge i {
            margin-right: 0.2rem;
        }

        /* Medical Device Type Badge - Override existing styles */
        .type-badge.medical-device {
            background: var(--siemens-petrol) !important;
            color: white !important;
            border: 1px solid var(--siemens-petrol) !important;
            font-weight: 600 !important;
            padding: 4px 12px !important;
            border-radius: 20px !important;
            white-space: normal !important;
            word-wrap: break-word !important;
            overflow-wrap: break-word !important;
            line-height: 1.2 !important;
            text-align: center !important;
        }

        /* Mapping Modal Styles */
        #mappingModal {
            display: none !important;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        
        #mappingModal.show {
            display: flex !important;
        }
        
        #mappingModal .modal-content.large {
            max-width: 924px;
            width: 95%;
        }
        
        #mappingModal .mapping-form {
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }
        
        #mappingModal .asset-info {
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            padding: 1rem;
            border: 1px solid var(--border-primary);
        }
        
        #mappingModal .asset-info h4 {
            color: var(--text-primary);
            margin: 0 0 1rem 0;
            font-size: 1rem;
            font-weight: 600;
        }
        
        #mappingModal .asset-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        
        #mappingModal .asset-detail {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        #mappingModal .asset-detail label {
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-secondary);
        }
        
        #mappingModal .asset-detail span {
            color: var(--text-primary);
            font-weight: 500;
        }
        
        #mappingModal .fda-search {
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            padding: 1rem;
            border: 1px solid var(--border-primary);
        }
        
        #mappingModal .fda-search h4 {
            color: var(--text-primary);
            margin: 0 0 1rem 0;
            font-size: 1rem;
            font-weight: 600;
        }
        
        #mappingModal .search-form {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        #mappingModal .form-group {
            position: relative;
        }
        
        #mappingModal .search-results {
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            padding: 1rem;
            border: 1px solid var(--border-primary);
        }
        
        #mappingModal .results-list {
            max-height: 400px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        #mappingModal .device-card {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        #mappingModal .device-card:hover {
            border-color: var(--siemens-petrol);
            box-shadow: 0 2px 8px rgba(0, 153, 153, 0.1);
        }
        
        #mappingModal .device-card.selected {
            border-color: var(--siemens-petrol);
            background: rgba(0, 153, 153, 0.05);
            box-shadow: 0 2px 8px rgba(0, 153, 153, 0.2);
        }
        
        #mappingModal .device-card-header {
            padding: 1rem;
            border-bottom: 1px solid var(--border-primary);
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
        }
        
        #mappingModal .device-title h5 {
            margin: 0 0 0.25rem 0;
            color: var(--text-primary);
            font-size: 1rem;
            font-weight: 600;
        }
        
        #mappingModal .device-brand {
            color: var(--text-secondary);
            font-size: 0.875rem;
        }
        
        #mappingModal .device-model {
            color: var(--text-primary);
            font-weight: 500;
            font-size: 0.875rem;
        }
        
        #mappingModal .device-confidence {
            background: var(--siemens-petrol);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        #mappingModal .device-card-body {
            padding: 1rem;
        }
        
        #mappingModal .device-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        #mappingModal .info-section {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        #mappingModal .info-label {
            font-size: 0.75rem;
            font-weight: 500;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        #mappingModal .info-value {
            color: var(--text-primary);
            font-weight: 500;
            font-size: 0.875rem;
        }
        
        #mappingModal .device-description {
            margin-bottom: 1rem;
        }
        
        #mappingModal .description-label {
            font-size: 0.75rem;
            font-weight: 500;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.5rem;
        }
        
        #mappingModal .description-text {
            color: var(--text-primary);
            font-size: 0.875rem;
            line-height: 1.4;
        }
        
        #mappingModal .device-characteristics {
            margin-top: 1rem;
        }
        
        #mappingModal .characteristics-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        
        #mappingModal .characteristic-tag {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.25rem 0.5rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        
        #mappingModal .characteristic-tag.implantable {
            background: rgba(239, 68, 68, 0.1);
            color: var(--error-red);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        #mappingModal .characteristic-tag.single-use {
            background: rgba(245, 158, 11, 0.1);
            color: var(--warning-orange);
            border: 1px solid rgba(245, 158, 11, 0.3);
        }
        
        #mappingModal .characteristic-tag.sterile {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success-green);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        
        #mappingModal .characteristic-tag.kit {
            background: rgba(99, 102, 241, 0.1);
            color: #6366f1;
            border: 1px solid rgba(99, 102, 241, 0.3);
        }
        
        #mappingModal .characteristic-tag.otc {
            background: rgba(34, 197, 94, 0.1);
            color: #22c55e;
            border: 1px solid rgba(34, 197, 94, 0.3);
        }
        
        #mappingModal .characteristic-tag.rx {
            background: rgba(168, 85, 247, 0.1);
            color: #a855f7;
            border: 1px solid rgba(168, 85, 247, 0.3);
        }
        
        #mappingModal .suggestions {
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.375rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            z-index: 1000;
            max-height: 200px;
            overflow-y: auto;
            display: none;
        }
        
        #mappingModal .suggestion-item {
            padding: 0.5rem 0.75rem;
            cursor: pointer;
            color: var(--text-primary);
            border-bottom: 1px solid var(--border-primary);
        }
        
        #mappingModal .suggestion-item:hover {
            background: var(--bg-hover);
        }

        /* ===== COMPACT 510k DETAILS MODAL ===== */
        
        /* Modal Size */
        .modal-content.medium {
            max-width: 600px;
            width: 90vw;
            max-height: 80vh;
        }
        
        /* Compact Header */
        .device-header-compact {
            background: var(--bg-card, #111111);
            border: 1px solid var(--border-primary, #374151);
            border-radius: 0.375rem;
            padding: 0.75rem;
            margin-bottom: 0.75rem;
        }
        
        .device-header-compact h4 {
            margin: 0 0 0.25rem 0;
            color: var(--text-primary, #ffffff);
            font-size: 1rem;
            font-weight: 600;
        }
        
        .device-meta-compact {
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            color: var(--text-secondary, #9ca3af);
            font-size: 0.75rem;
        }
        
        .device-meta-compact span {
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }
        
        /* Compact Info Grid */
        .compact-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 0.75rem;
            margin-bottom: 1rem;
        }
        
        .info-section-compact {
            background: var(--bg-secondary, #1a1a1a);
            border: 1px solid var(--border-primary, #374151);
            border-radius: 0.375rem;
            padding: 0.75rem;
        }
        
        .info-section-compact h5 {
            margin: 0 0 0.5rem 0;
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.375rem;
        }
        
        .info-section-compact h5 i {
            color: var(--siemens-petrol-light, #00bbbb);
            font-size: 0.75rem;
        }
        
        .info-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.25rem 0;
            font-size: 0.75rem;
        }
        
        .info-row .label {
            color: var(--text-secondary, #9ca3af);
            font-weight: 500;
            flex-shrink: 0;
        }
        
        .info-row .value {
            color: var(--text-primary, #ffffff);
            font-weight: 500;
            text-align: right;
            word-break: break-word;
            max-width: 120px;
        }
        
        /* More Info Section */
        .more-info-section {
            margin-bottom: 1rem;
        }
        
        .more-info-toggle {
            width: 100%;
            padding: 0.75rem;
            background: var(--bg-secondary, #1a1a1a);
            border: 1px solid var(--border-primary, #374151);
            border-radius: 0.375rem;
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }
        
        .more-info-toggle:hover {
            background: var(--bg-hover, #333333);
            border-color: var(--siemens-petrol-light, #00bbbb);
        }
        
        .more-info-toggle.active {
            background: var(--siemens-petrol, #009999);
            border-color: var(--siemens-petrol, #009999);
        }
        
        .more-info-toggle i {
            transition: transform 0.2s ease;
        }
        
        .more-info-toggle.active i {
            transform: rotate(180deg);
        }
        
        .more-info-content {
            margin-top: 0.75rem;
            animation: slideDown 0.3s ease;
        }
        
        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        /* Summary Section */
        .summary-section-compact {
            background: var(--bg-secondary, #1a1a1a);
            border: 1px solid var(--border-primary, #374151);
            border-radius: 0.375rem;
            padding: 0.75rem;
            margin-bottom: 1rem;
        }
        
        .summary-section-compact h5 {
            margin: 0 0 0.5rem 0;
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.375rem;
        }
        
        .summary-section-compact h5 i {
            color: var(--siemens-petrol-light, #00bbbb);
            font-size: 0.75rem;
        }
        
        .summary-text {
            color: var(--text-primary, #ffffff);
            font-size: 0.75rem;
            line-height: 1.4;
            background: var(--bg-tertiary, #0a0a0a);
            padding: 0.5rem;
            border-radius: 0.25rem;
            border: 1px solid var(--border-secondary, #2d3748);
            max-height: 100px;
            overflow-y: auto;
        }
        
        /* Flag Badges */
        .flag-badge {
            display: inline-block;
            padding: 0.125rem 0.375rem;
            border-radius: 0.25rem;
            font-size: 0.625rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            min-width: 40px;
            text-align: center;
        }
        
        .flag-badge.true {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success-green, #10b981);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        
        .flag-badge.false {
            background: rgba(239, 68, 68, 0.1);
            color: var(--error-red, #ef4444);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .compact-info-grid {
                grid-template-columns: 1fr;
            }
            
            .device-meta-compact {
                flex-direction: column;
                gap: 0.5rem;
            }
        }
        
        #mappingModal .suggestion-item:last-child {
            border-bottom: none;
        }

        /* FDA Results Modal Styles */
        #fdaResultsModal {
            display: none !important;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 2000;
            align-items: center;
            justify-content: center;
        }
        
        #fdaResultsModal.show {
            display: flex !important;
        }
        
        #fdaResultsModal .modal-content.extra-large {
            max-width: 95vw;
            max-height: 95vh;
            width: 95vw;
            height: 95vh;
            display: flex;
            flex-direction: column;
        }
        
        #fdaResultsModal .modal-body {
            flex: 1;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
        
        #fdaResultsModal .fda-results-container {
            height: 100%;
            display: flex;
            flex-direction: column;
        }
        
        #fdaResultsModal .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            margin-bottom: 1rem;
        }
        
        #fdaResultsModal .search-info p {
            margin: 0.25rem 0;
            color: var(--text-primary);
        }
        
        #fdaResultsModal .results-list {
            flex: 1;
            overflow-y: auto;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            padding: 1rem;
            background: var(--bg-primary);
            border-radius: 0.5rem;
        }
        
        #fdaResultsModal .fda-device-card {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            overflow: hidden;
            transition: all 0.2s ease;
            min-height: 120px;
            width: 100%;
            display: grid;
            grid-template-columns: 1fr auto auto;
            gap: 1rem;
            padding: 1rem;
            margin-bottom: 0.75rem;
            align-items: center;
        }
        
        #fdaResultsModal .fda-device-card:hover {
            border-color: var(--siemens-petrol);
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.15);
            transform: translateY(-2px);
        }
        
        #fdaResultsModal .fda-device-card.selected {
            border-color: var(--siemens-petrol);
            background: rgba(0, 153, 153, 0.05);
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.2);
        }
        
        #fdaResultsModal .device-product-info {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        #fdaResultsModal .device-confidence-column {
            display: flex;
            align-items: center;
            justify-content: center;
            min-width: 80px;
        }
        
        #fdaResultsModal .device-action-column {
            display: flex;
            align-items: center;
            justify-content: center;
            min-width: 100px;
        }
        
        
        #fdaResultsModal .device-title {
            color: var(--text-primary);
            font-size: 1rem;
            font-weight: 600;
            line-height: 1.3;
            margin: 0;
        }
        
        #fdaResultsModal .device-confidence {
            background: var(--siemens-petrol);
            color: white;
            padding: 0.5rem 0.75rem;
            border-radius: 0.5rem;
            font-size: 0.875rem;
            font-weight: 700;
            white-space: nowrap;
            text-align: center;
            min-width: 60px;
        }
        
        #fdaResultsModal .device-manufacturer {
            color: var(--text-secondary);
            font-size: 0.8rem;
            line-height: 1.2;
            margin: 0;
        }
        
        #fdaResultsModal .device-model {
            color: var(--text-primary);
            font-weight: 500;
            font-size: 0.8rem;
            margin: 0;
        }
        
        #fdaResultsModal .device-version {
            font-size: 0.8rem;
            color: var(--siemens-petrol);
            font-weight: 500;
            margin: 0;
        }
        
        
        #fdaResultsModal .device-description {
            margin-bottom: 1.5rem;
        }
        
        #fdaResultsModal .description-label {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }
        
        #fdaResultsModal .description-text {
            color: var(--text-primary);
            font-size: 0.875rem;
            line-height: 1.5;
        }
        
        #fdaResultsModal .device-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        
        #fdaResultsModal .detail-group {
            display: flex;
            flex-direction: column;
        }
        
        #fdaResultsModal .detail-label {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.25rem;
        }
        
        #fdaResultsModal .detail-value {
            color: var(--text-primary);
            font-weight: 500;
            font-size: 0.875rem;
        }
        
        #fdaResultsModal .device-characteristics {
            margin-top: 1rem;
        }
        
        #fdaResultsModal .characteristics-label {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.75rem;
        }
        
        #fdaResultsModal .characteristics-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        
        #fdaResultsModal .characteristic-tag {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.25rem 0.5rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            font-weight: 500;
        }
        
        #fdaResultsModal .characteristic-tag.implantable {
            background: rgba(239, 68, 68, 0.1);
            color: var(--error-red);
        }
        
        #fdaResultsModal .characteristic-tag.single-use {
            background: rgba(245, 158, 11, 0.1);
            color: var(--warning-orange);
        }
        
        #fdaResultsModal .characteristic-tag.sterile {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success-green);
        }
        
        #fdaResultsModal .characteristic-tag.kit {
            background: rgba(99, 102, 241, 0.1);
            color: #6366f1;
        }
        
        #fdaResultsModal .characteristic-tag.otc {
            background: rgba(34, 197, 94, 0.1);
            color: #22c55e;
        }
        
        #fdaResultsModal .characteristic-tag.rx {
            background: rgba(168, 85, 247, 0.1);
            color: #a855f7;
        }
        
        /* Filter Controls */
        .filter-controls {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .filter-row {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .filter-group {
            display: flex;
            flex-direction: column;
        }
        
        .filter-group label {
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }
        
        .filter-group input,
        .filter-group select {
            padding: 0.5rem 0.75rem;
            border: 1px solid var(--border-primary);
            border-radius: 0.375rem;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 0.875rem;
            transition: border-color 0.2s ease;
        }
        
        .filter-group input:focus,
        .filter-group select:focus {
            outline: none;
            border-color: var(--siemens-petrol);
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
        }
        
        .filter-actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-top: 1rem;
            border-top: 1px solid var(--border-primary);
        }
        
        .filtered-count {
            font-size: 0.875rem;
            color: var(--text-secondary);
        }
        
        /* Location Display Styles */
        .location-info {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        .location-name {
            font-weight: 600;
            color: var(--text-primary);
            font-size: 0.875rem;
        }
        
        .location-path {
            font-size: 0.75rem;
            color: var(--text-secondary);
            font-style: italic;
        }
        
        .location-method {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }
        
        .location-method.auto-ip {
            color: var(--siemens-petrol);
        }
        
        .location-method.manual {
            color: var(--siemens-orange);
        }
        
        .btn-outline {
            background: transparent;
            border: 1px solid var(--border-secondary);
            color: var(--text-secondary);
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .btn-outline:hover {
            background: var(--bg-hover);
            border-color: var(--siemens-petrol);
            color: var(--siemens-petrol);
        }
        
        /* Device Details Modal */
        #deviceDetailsModal {
            display: none !important;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 3000;
            align-items: center;
            justify-content: center;
        }
        
        #deviceDetailsModal.show {
            display: flex !important;
        }
        
        #deviceDetailsModal .modal-content.extra-large {
            max-width: 90vw;
            max-height: 90vh;
            width: 90vw;
            height: 90vh;
            display: flex;
            flex-direction: column;
        }
        
        #deviceDetailsModal .modal-body {
            flex: 1;
            overflow-y: auto;
            padding: 1.5rem;
        }
        
        .device-details-container {
            max-width: 100%;
        }
        
        .device-details-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 2px solid var(--border-primary);
        }
        
        .device-title-section h2 {
            margin: 0 0 0.5rem 0;
            color: var(--text-primary);
            font-size: 1.75rem;
            font-weight: 700;
        }
        
        .device-manufacturer-detail {
            color: var(--text-secondary);
            font-size: 1.125rem;
            margin-bottom: 0.5rem;
        }
        
        .device-model-detail {
            color: var(--text-primary);
            font-size: 1rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
        }
        
        .device-version-detail {
            color: var(--siemens-petrol);
            font-size: 1rem;
            font-weight: 600;
        }
        
        .device-confidence-detail {
            background: var(--siemens-petrol);
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 1rem;
            font-size: 1rem;
            font-weight: 600;
            white-space: nowrap;
        }
        
        .device-details-content {
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }
        
        .details-section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            padding: 1.5rem;
        }
        
        .details-section h4 {
            margin: 0 0 1.5rem 0;
            color: var(--text-primary);
            font-size: 1.25rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .details-section h4 i {
            color: var(--siemens-petrol);
        }
        
        .details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }
        
        .detail-item {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        
        .detail-item label {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .detail-item span {
            color: var(--text-primary);
            font-weight: 500;
            font-size: 1rem;
            word-break: break-word;
        }
        
        .characteristics-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
        }
        
        .characteristics-grid .characteristic-tag {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        .description-content {
            background: var(--bg-primary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
            color: var(--text-primary);
            line-height: 1.6;
            font-size: 1rem;
        }
        
        
        #fdaResultsModal .btn-select {
            background: var(--siemens-petrol);
            color: white;
            border: 1px solid var(--siemens-petrol);
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        #fdaResultsModal .btn-select:hover {
            background: var(--siemens-petrol-dark);
            border-color: var(--siemens-petrol-dark);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.3);
        }
        
        #fdaResultsModal .btn-primary {
            background: var(--siemens-petrol);
            color: white;
            border: 1px solid var(--siemens-petrol);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.8rem;
            min-width: 80px;
            justify-content: center;
        }
        
        #fdaResultsModal .btn-primary:hover {
            background: var(--siemens-petrol-dark);
            border-color: var(--siemens-petrol-dark);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.3);
        }

        .btn-info {
            background: #17a2b8;
            color: white;
            border: 1px solid #17a2b8;
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.9rem;
        }

        .btn-info:hover {
            background: #138496;
            border-color: #138496;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(23, 162, 184, 0.3);
        }

        /* Override manufacturer column width to ensure visibility */
        .table-row {
            grid-template-columns: 2fr 1fr 1fr 2.5fr 1fr 1fr 1fr 1fr 1fr !important;
        }

        /* Action Dropdown Styles */
        .action-dropdown {
            position: relative;
            display: inline-block;
        }

        .dropdown-trigger {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 2rem;
            height: 2rem;
            border: 1px solid var(--border-secondary);
            background: var(--bg-secondary);
            color: var(--text-secondary);
            border-radius: 0.375rem;
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 0.875rem;
        }

        .dropdown-trigger:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
            border-color: var(--border-primary);
        }

        .dropdown-menu {
            position: absolute;
            top: calc(166px / -2);
            right: 0;
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            z-index: 1000;
            min-width: 180px;
            display: none;
            overflow: hidden;
        }

        .dropdown-menu.show {
            display: block;
        }

        /* Red background for table cells when dropdown is shown */
        .dropdown-menu.show ~ * .table-row,
        .dropdown-menu.show + .table-row,
        .table-row:has(.dropdown-menu.show) {
            height: 166px !important;
        }

        .dropdown-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            width: 100%;
            padding: 0.75rem 1rem;
            border: none;
            background: none;
            color: var(--text-primary);
            text-decoration: none;
            cursor: pointer;
            transition: background-color 0.2s ease;
            font-size: 0.875rem;
            text-align: left;
        }

        .dropdown-item:hover {
            background: var(--bg-hover);
        }

        .dropdown-item i {
            width: 1rem;
            text-align: center;
            font-size: 0.875rem;
        }

        .dropdown-item span {
            flex: 1;
        }

        /* Action Icon Colors */
        .dropdown-item.view i {
            color: var(--siemens-petrol);
        }

        .dropdown-item.map i {
            color: var(--siemens-orange);
        }

        .dropdown-item.scan i {
            color: var(--warning-orange);
        }

        .dropdown-item.edit i {
            color: var(--info-blue);
        }

        .dropdown-item.delete i {
            color: var(--error-red);
        }

        /* Hover effects for action icons */
        .dropdown-item.view:hover i {
            color: var(--siemens-petrol-dark);
        }

        .dropdown-item.map:hover i {
            color: var(--siemens-orange-dark);
        }

        .dropdown-item.scan:hover i {
            color: #d97706;
        }

        .dropdown-item.edit:hover i {
            color: #0284c7;
        }

        .dropdown-item.delete:hover i {
            color: #dc2626;
        }
        
        /* Asset Types Chart Item Hover Effects */
        .chart-item:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md, 0 4px 6px rgba(0, 0, 0, 0.4));
            border-color: var(--siemens-petrol-light, #00bbbb);
            background: rgba(0, 187, 187, 0.05);
        }
        
        .chart-item:hover .chart-fill {
            background: linear-gradient(90deg, var(--siemens-petrol-light, #00bbbb), var(--siemens-petrol, #009999));
        }
        
        /* Dashboard Widget Hover Effects */
        .dashboard-widget:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-xl, 0 20px 25px rgba(0, 0, 0, 0.6));
        }
        
        .stat-card:hover {
            transform: translateY(-1px);
            box-shadow: var(--shadow-md, 0 4px 6px rgba(0, 0, 0, 0.3));
        }
        
        .chart-container:hover {
            border-color: var(--siemens-petrol-light, #00bbbb);
            background: rgba(0, 187, 187, 0.02);
        }
        
        /* Asset Types Chart Hover Effects */
        .dashboard-widget.asset-types-chart:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-xl, 0 20px 25px rgba(0, 0, 0, 0.6));
        }
        
        .dashboard-widget.asset-types-chart .widget-action:hover {
            color: var(--siemens-petrol, #009999);
        }
        
        .dashboard-widget.asset-types-chart .stat-card:hover {
            transform: translateY(-1px);
            box-shadow: var(--shadow-md, 0 4px 6px rgba(0, 0, 0, 0.3));
        }
        
        .dashboard-widget.asset-types-chart .chart-container:hover {
            border-color: var(--siemens-petrol-light, #00bbbb);
            background: rgba(0, 187, 187, 0.02);
        }
        
        /* Pagination Controls */
        .pagination-section {
            margin: 2rem 0;
        }
        
        .pagination-controls-top {
            display: flex;
            justify-content: flex-start;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .per-page-selector {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .per-page-select {
            padding: 0.375rem 0.75rem;
            border: 1px solid var(--border-primary, #374151);
            border-radius: 0.375rem;
            background-color: var(--bg-secondary, #1a1a1a);
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            transition: all 0.2s ease;
        }
        
        .per-page-select:focus {
            outline: none;
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
        }
        
        .per-page-select:hover {
            border-color: var(--siemens-petrol-light, #00bbbb);
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
        }
        
        .pagination-controls {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }
        
        .pagination-controls .btn {
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.2s ease;
            border: 1px solid transparent;
        }
        
        .pagination-controls .btn-primary {
            background-color: var(--siemens-petrol, #009999);
            color: white;
            border-color: var(--siemens-petrol, #009999);
        }
        
        .pagination-controls .btn-secondary {
            background-color: var(--bg-secondary, #1a1a1a);
            color: var(--text-primary, #ffffff);
            border-color: var(--border-primary, #374151);
        }
        
        .pagination-controls .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
        }
        
        .pagination-controls .btn-primary:hover {
            background-color: var(--siemens-petrol-dark, #007777);
        }
        
        .pagination-controls .btn-secondary:hover {
            background-color: var(--bg-hover, #333333);
            border-color: var(--siemens-petrol-light, #00bbbb);
        }
        
        /* Assets Card Styling */
        .assets-card {
            transition: all 0.3s ease;
        }
        
        .assets-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-xl, 0 20px 25px rgba(0, 0, 0, 0.6));
        }
        
        .assets-card .card-header {
            transition: all 0.2s ease;
        }
        
        .assets-card:hover .card-header {
            background: linear-gradient(135deg, var(--bg-card, #111111) 0%, var(--bg-tertiary, #1a1a1a) 100%);
        }
        
        /* Professional FDA Modal Styling */
        #fdaResultsModal .modal-content.large {
            max-width: 1000px;
            width: 90vw;
            max-height: 85vh;
        }
        
        #fdaResultsModal .modal-body {
            padding: 1.5rem;
            max-height: calc(85vh - 120px);
            overflow-y: auto;
        }
        
        /* Search Summary */
        #fdaResultsModal .search-summary {
            background: var(--bg-secondary, #1a1a1a);
            border: 1px solid var(--border-primary, #374151);
            border-radius: 0.5rem;
            padding: 1rem;
            margin-bottom: 1.5rem;
        }
        
        #fdaResultsModal .summary-stats {
            display: flex;
            gap: 2rem;
            align-items: center;
        }
        
        #fdaResultsModal .stat-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        #fdaResultsModal .stat-item i {
            color: var(--siemens-petrol-light, #00bbbb);
            font-size: 0.875rem;
        }
        
        #fdaResultsModal .stat-label {
            color: var(--text-secondary, #9ca3af);
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        #fdaResultsModal .stat-value {
            color: var(--text-primary, #ffffff);
            font-weight: 600;
            font-size: 0.875rem;
        }
        
        /* Filter Toggle Button */
        #fdaResultsModal .filter-toggle-section {
            margin-bottom: 1rem;
        }
        
        #fdaResultsModal .btn-toggle-filters {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1rem;
            background: var(--bg-secondary, #1a1a1a);
            border: 1px solid var(--border-primary, #374151);
            border-radius: 0.5rem;
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        #fdaResultsModal .btn-toggle-filters:hover {
            background: var(--bg-hover, #333333);
            border-color: var(--siemens-petrol-light, #00bbbb);
        }
        
        #fdaResultsModal .btn-toggle-filters.active {
            background: var(--siemens-petrol, #009999);
            border-color: var(--siemens-petrol, #009999);
            color: white;
        }
        
        #fdaResultsModal .filter-count {
            background: var(--siemens-petrol-light, #00bbbb);
            color: white;
            padding: 0.125rem 0.5rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        /* Filter Controls */
        #fdaResultsModal .filter-controls {
            background: var(--bg-card, #111111);
            border: 1px solid var(--border-primary, #374151);
            border-radius: 0.5rem;
            padding: 1rem;
            margin-bottom: 1.5rem;
        }
        
        #fdaResultsModal .filter-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        #fdaResultsModal .filter-header h4 {
            margin: 0;
            color: var(--text-primary, #ffffff);
            font-size: 1rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        #fdaResultsModal .filter-header h4 i {
            color: var(--siemens-petrol-light, #00bbbb);
        }
        
        #fdaResultsModal .btn-clear-filters {
            padding: 0.5rem 1rem;
            background: transparent;
            border: 1px solid var(--border-primary, #374151);
            border-radius: 0.375rem;
            color: var(--text-secondary, #9ca3af);
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        #fdaResultsModal .btn-clear-filters:hover {
            background: var(--bg-hover, #333333);
            border-color: var(--siemens-petrol-light, #00bbbb);
            color: var(--text-primary, #ffffff);
        }
        
        #fdaResultsModal .filter-row {
            display: flex;
            gap: 1rem;
            align-items: end;
        }
        
        #fdaResultsModal .filter-group {
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        
        #fdaResultsModal .filter-group label {
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        #fdaResultsModal .filter-group input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border-primary, #374151);
            border-radius: 0.375rem;
            background-color: var(--bg-secondary, #1a1a1a);
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            transition: all 0.2s ease;
        }
        
        #fdaResultsModal .filter-group input:focus {
            outline: none;
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
        }
        
        #fdaResultsModal .filter-group input:hover {
            border-color: var(--siemens-petrol-light, #00bbbb);
        }
        
        #fdaResultsModal .filter-group input::placeholder {
            color: var(--text-secondary, #9ca3af);
        }
        
        #fdaResultsModal .filter-actions {
            display: flex;
            align-items: center;
        }
        
        /* Results Container */
        #fdaResultsModal .results-container {
            background: var(--bg-card, #111111);
            border: 1px solid var(--border-primary, #374151);
            border-radius: 0.5rem;
            padding: 1rem;
            max-height: 50vh;
            overflow-y: auto;
        }
        
        #fdaResultsModal .results-list {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }
        
        /* Custom Scrollbar */
        #fdaResultsModal .results-container::-webkit-scrollbar {
            width: 8px;
        }
        
        #fdaResultsModal .results-container::-webkit-scrollbar-track {
            background: var(--bg-secondary, #1a1a1a);
            border-radius: 4px;
        }
        
        #fdaResultsModal .results-container::-webkit-scrollbar-thumb {
            background: var(--siemens-petrol, #009999);
            border-radius: 4px;
        }
        
        #fdaResultsModal .results-container::-webkit-scrollbar-thumb:hover {
            background: var(--siemens-petrol-light, #00bbbb);
        }
        
        /* Device Cards */
        #fdaResultsModal .fda-device-card {
            background: var(--bg-secondary, #1a1a1a);
            border: 1px solid var(--border-primary, #374151);
            border-radius: 0.5rem;
            padding: 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        
        #fdaResultsModal .fda-device-card:hover {
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 2px 8px rgba(0, 153, 153, 0.1);
        }
        
        #fdaResultsModal .device-product-info {
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        #fdaResultsModal .device-title {
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
        }
        
        #fdaResultsModal .device-manufacturer {
            color: var(--text-secondary, #9ca3af);
            font-size: 0.75rem;
        }
        
        #fdaResultsModal .device-model {
            color: var(--text-primary, #ffffff);
            font-size: 0.75rem;
            font-weight: 500;
        }
        
        #fdaResultsModal .device-version {
            color: var(--text-secondary, #9ca3af);
            font-size: 0.75rem;
        }
        
        #fdaResultsModal .device-confidence-column {
            display: flex;
            align-items: center;
        }
        
        #fdaResultsModal .device-confidence {
            background: var(--siemens-petrol, #009999);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        #fdaResultsModal .device-action-column {
            display: flex;
            align-items: center;
        }
    </style>
    <!-- Asset Modal Component -->
    <?php include __DIR__ . '/asset_modal_component.php'; ?>

    <!-- Common Dashboard JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="/assets/js/dashboard-common.js"></script>

    <!-- Mapping Modal -->
    <div id="mappingModal" class="modal">
        <div class="modal-content large">
            <div class="modal-header">
                <h3><i class="fas fa-file-medical"></i> Map Device to 510k Record</h3>
                <button type="button" class="modal-close">&times;</button>
            </div>
            <div class="modal-body">
                <div class="mapping-form">
                    <div class="asset-info">
                        <h4>Asset Information</h4>
                        <div id="selectedAsset" class="asset-details">
                            <!-- Selected asset info will be loaded here -->
                        </div>
                    </div>

                    <div class="k510-search">
                        <h4>510k Search</h4>
                        <div class="search-form">
                            <div class="form-group">
                                <label for="k510SearchTerm">Device Name or Model *</label>
                                <input type="text" id="k510SearchTerm" placeholder="Enter device name (e.g., ARTIS pheno)" autocomplete="off">
                            </div>
                            <button type="button" id="search510k" class="btn btn-primary">
                                <i class="fas fa-search"></i>
                                Search 510k Database
                            </button>
                        </div>
                    </div>

                    <div class="search-results" id="searchResults" style="display: none;">
                        <h4>510k Search Results</h4>
                        <div id="k510Results" class="results-list">
                            <!-- 510k search results will be loaded here -->
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeMappingModal()">Cancel</button>
            </div>
        </div>
    </div>

    <!-- FDA Results Modal -->
    <div id="fdaResultsModal" class="modal">
        <div class="modal-content large">
            <div class="modal-header">
                <h3><i class="fas fa-search"></i> FDA Device Search Results</h3>
                <button type="button" class="modal-close">&times;</button>
            </div>
            <div class="modal-body">
                <!-- Search Summary -->
                <div class="search-summary">
                    <div class="summary-stats">
                        <span class="stat-item">
                            <i class="fas fa-list"></i>
                            <span class="stat-label">Results:</span>
                            <span class="stat-value" id="resultCount">0</span>
                        </span>
                    </div>
                </div>

                <!-- Filter Toggle Button -->
                <div class="filter-toggle-section">
                    <button type="button" id="toggleFDAFilters" class="btn-toggle-filters" onclick="toggleFDAFilters()">
                        <i class="fas fa-sliders-h"></i>
                        <span>Filters</span>
                        <span class="filter-count" id="fdaFilterCount" style="display: none;"></span>
                    </button>
                </div>

                <!-- Collapsible Filter Controls -->
                <div class="filter-controls" id="fdaFiltersPanel" style="display: none;">
                    <div class="filter-header">
                        <h4><i class="fas fa-filter"></i> Filter Results</h4>
                        <button type="button" id="clearFDAFilters" class="btn-clear-filters" onclick="clearFDAFilters()">
                            <i class="fas fa-undo"></i> Reset All
                        </button>
                    </div>
                    <div class="filter-row">
                        <div class="filter-group">
                            <label for="filterManufacturer">Manufacturer</label>
                            <input type="text" id="filterManufacturer" placeholder="Filter by manufacturer..." onkeyup="filterDevices()">
                        </div>
                        <div class="filter-group">
                            <label for="filterBrandName">Brand Name</label>
                            <input type="text" id="filterBrandName" placeholder="Filter by brand name..." onkeyup="filterDevices()">
                        </div>
                    </div>
                </div>

                <!-- Results List -->
                <div class="results-container">
                    <div class="results-list" id="fdaResultsList">
                        <!-- FDA search results will be loaded here -->
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Device Details Modal -->
        <div id="deviceDetailsModal" class="modal">
            <div class="modal-content medium">
                <div class="modal-header">
                    <h3><i class="fas fa-file-medical"></i> 510k Details: <span id="modalKNumber">-</span></h3>
                    <button type="button" class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                    <!-- Compact Header -->
                    <div class="device-header-compact">
                        <h4 id="deviceName">Device Name</h4>
                        <div class="device-meta-compact">
                            <span><strong>Decision:</strong> <span id="decisionCode">-</span></span>
                            <span><strong>Date:</strong> <span id="version">-</span></span>
                        </div>
                    </div>

                    <!-- Compact Info Grid -->
                    <div class="compact-info-grid">
                        <div class="info-section-compact">
                            <h5><i class="fas fa-building"></i> Applicant</h5>
                            <div class="info-row">
                                <span class="label">Company:</span>
                                <span class="value" id="applicant">-</span>
                            </div>
                            <div class="info-row">
                                <span class="label">Contact:</span>
                                <span class="value" id="contact">-</span>
                            </div>
                            <div class="info-row">
                                <span class="label">Address:</span>
                                <span class="value" id="address1">-</span>
                            </div>
                            <div class="info-row">
                                <span class="label">City, State:</span>
                                <span class="value" id="cityState">-</span>
                            </div>
                        </div>

                        <div class="info-section-compact">
                            <h5><i class="fas fa-info-circle"></i> Details</h5>
                            <div class="info-row">
                                <span class="label">Product Code:</span>
                                <span class="value" id="productCode">-</span>
                            </div>
                            <div class="info-row">
                                <span class="label">Device Class:</span>
                                <span class="value" id="deviceClass">-</span>
                            </div>
                            <div class="info-row">
                                <span class="label">Clearance Type:</span>
                                <span class="value" id="clearanceType">-</span>
                            </div>
                            <div class="info-row">
                                <span class="label">Date Received:</span>
                                <span class="value" id="dateReceived">-</span>
                            </div>
                        </div>

                        <div class="info-section-compact">
                            <h5><i class="fas fa-clipboard-check"></i> Review</h5>
                            <div class="info-row">
                                <span class="label">Committee:</span>
                                <span class="value" id="advisoryCommittee">-</span>
                            </div>
                            <div class="info-row">
                                <span class="label">Expedited:</span>
                                <span class="value">
                                    <span class="flag-badge" id="expeditedReviewFlag">-</span>
                                </span>
                            </div>
                            <div class="info-row">
                                <span class="label">Third Party:</span>
                                <span class="value">
                                    <span class="flag-badge" id="thirdPartyFlag">-</span>
                                </span>
                            </div>
                        </div>

                    </div>

                    <!-- More Info Section -->
                    <div class="more-info-section">
                        <button type="button" class="more-info-toggle" onclick="toggleMoreInfo()">
                            <i class="fas fa-chevron-down"></i>
                            <span>More Technical Information</span>
                        </button>
                        <div class="more-info-content" id="moreInfoContent" style="display: none;">
                            <div class="compact-info-grid">
                                <div class="info-section-compact">
                                    <h5><i class="fas fa-cogs"></i> Technical</h5>
                                    <div class="info-row">
                                        <span class="label">Medical Specialty:</span>
                                        <span class="value" id="medicalSpecialtyDescription">-</span>
                                    </div>
                                    <div class="info-row">
                                        <span class="label">Regulation #:</span>
                                        <span class="value" id="regulationNumber">-</span>
                                    </div>
                                    <div class="info-row">
                                        <span class="label">Registration #:</span>
                                        <span class="value" id="registrationNumbers">-</span>
                                    </div>
                                    <div class="info-row">
                                        <span class="label">FEI Numbers:</span>
                                        <span class="value" id="feiNumbers">-</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Summary Section -->
                    <div class="summary-section-compact">
                        <h5><i class="fas fa-file-text"></i> Summary</h5>
                        <div class="summary-text" id="statementOrSummary">No summary available</div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeDeviceDetailsModal()">
                        <i class="fas fa-times"></i>
                        Close
                    </button>
                    <button type="button" class="btn btn-info" id="viewFDADocument" onclick="viewFDADocument()">
                        <i class="fas fa-external-link-alt"></i>
                        View FDA Document
                    </button>
                    <button type="button" class="btn btn-primary" id="selectFromDetails" onclick="selectDeviceFromDetails()">
                        <i class="fas fa-map"></i>
                        Map Device
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Mapping Modal JavaScript - Updated: <?php echo date('Y-m-d H:i:s'); ?>
        let selectedDevice = null;
        let currentAssetId = null;

        function open510kMappingModal(assetId) {
            currentAssetId = assetId;
            const modal = document.getElementById('mappingModal');
            if (modal) {
                modal.classList.add('show');
                
                // Wait for modal to be fully rendered before attaching listeners
                setTimeout(() => {
                    attachManufacturerListeners();
                    attachSearch510kListener();
                }, 300);
            } else {
                console.error('Mapping modal not found!');
            }
        }

        function closeMappingModal() {
            const modal = document.getElementById('mappingModal');
            if (modal) {
                modal.classList.remove('show');
                selectedDevice = null;
                currentAssetId = null;
                
                // Safely clear form elements - check if they exist first
                const searchResults = document.getElementById('searchResults');
                const fdaResults = document.getElementById('fdaResults');
                const mappingManufacturer = document.getElementById('mappingManufacturer');
                const model = document.getElementById('model');
                
                if (searchResults) searchResults.style.display = 'none';
                if (fdaResults) fdaResults.innerHTML = '';
                if (mappingManufacturer) mappingManufacturer.value = '';
                if (model) model.value = '';
                // confirmMapping button removed - no longer needed in initial modal
            }
        }

        function loadAssetInfo(assetId) {
            // Load asset information for display in modal
            fetch(`?ajax=get_assets&page=1&limit=1&asset_id=${assetId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success && data.assets.length > 0) {
                        const asset = data.assets[0];
                        document.getElementById('selectedAsset').innerHTML = `
                            <div class="asset-detail">
                                <label>Hostname:</label>
                                <span>${asset.hostname || 'Unknown'}</span>
                            </div>
                            <div class="asset-detail">
                                <label>IP Address:</label>
                                <span>${asset.ip_address || '-'}</span>
                            </div>
                            <div class="asset-detail">
                                <label>Manufacturer:</label>
                                <span>${asset.manufacturer || 'Unknown'}</span>
                            </div>
                            <div class="asset-detail">
                                <label>Model:</label>
                                <span>${asset.model || 'Unknown'}</span>
                            </div>
                            <div class="asset-detail">
                                <label>Type:</label>
                                <span>${asset.asset_type || '-'}</span>
                            </div>
                        `;
                    }
                })
                .catch(error => {
                    console.error('Error loading asset info:', error);
                });
        }

        // Attach manufacturer listeners
        function attachManufacturerListeners() {
            const manufacturerInput = document.getElementById('mappingManufacturer');
            if (manufacturerInput) {
                
                // Remove existing listeners to avoid duplicates
                manufacturerInput.removeEventListener('input', handleManufacturerInput);
                manufacturerInput.addEventListener('input', handleManufacturerInput);
                
                // Test the input by triggering a focus event
                manufacturerInput.focus();
            } else {
                console.error('Mapping manufacturer input not found!');
                const elements = document.querySelectorAll('[id*="manufacturer"]');
            }
        }

        function handleManufacturerInput() {
            
            if (!this.value) {
                return;
            }
            
            const partial = this.value.trim();
            if (partial.length >= 2) {
                const url = window.location.pathname + `?ajax=get_manufacturer_suggestions&partial=${encodeURIComponent(partial)}`;
                
                fetch(url, {
                    method: 'GET',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    return response.json();
                })
                .then(data => {
                    const suggestions = document.getElementById('mappingManufacturerSuggestions');
                    
                    if (data.success && data.job) {
                        // Non-blocking: poll for suggestions
                        pollManufacturerSuggestionsJob(data.job, suggestions);
                    } else if (data.suggestions && data.suggestions.length > 0) {
                        // Blocking (backward compatibility): show suggestions directly
                        const suggestionHTML = data.suggestions.map(suggestion => 
                            `<div class="suggestion-item" onclick="selectSuggestion('${suggestion}')">${suggestion}</div>`
                        ).join('');
                        suggestions.innerHTML = suggestionHTML;
                        suggestions.style.display = 'block';
                    } else {
                        suggestions.style.display = 'none';
                    }
                })
                .catch(error => {
                    console.error('Error fetching manufacturer suggestions:', error);
                    const suggestions = document.getElementById('mappingManufacturerSuggestions');
                    suggestions.innerHTML = '<div class="suggestion-item">Error loading suggestions</div>';
                    suggestions.style.display = 'block';
                });
            } else {
                document.getElementById('mappingManufacturerSuggestions').style.display = 'none';
            }
        }
        
        function pollManufacturerSuggestionsJob(job, suggestions) {
            suggestions.innerHTML = '<div class="suggestion-item"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
            suggestions.style.display = 'block';
            
            const pollInterval = setInterval(() => {
                fetch('?ajax=check_jobs', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ jobs: [job] })
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    return response.text();
                })
                .then(text => {
                    let data;
                    try {
                        data = JSON.parse(text);
                    } catch (e) {
                        console.error('Invalid JSON response:', text.substring(0, 500));
                        throw new Error('Invalid JSON response from server');
                    }
                    
                    if (data.success && data.results && data.results.length > 0) {
                        const result = data.results[0];
                        
                        if (result.status === 'completed') {
                            clearInterval(pollInterval);
                            
                            if (result.data && result.data.suggestions && result.data.suggestions.length > 0) {
                                const suggestionHTML = result.data.suggestions.map(suggestion => 
                                    `<div class="suggestion-item" onclick="selectSuggestion('${suggestion}')">${suggestion}</div>`
                                ).join('');
                                suggestions.innerHTML = suggestionHTML;
                                suggestions.style.display = 'block';
                            } else {
                                suggestions.style.display = 'none';
                            }
                        } else if (result.status === 'failed') {
                            clearInterval(pollInterval);
                            console.error('Suggestions job failed:', result.error);
                            suggestions.innerHTML = '<div class="suggestion-item">Error loading suggestions</div>';
                        }
                        // If still running, keep polling
                    }
                })
                .catch(error => {
                    console.error('Polling error:', error);
                    clearInterval(pollInterval);
                    suggestions.innerHTML = '<div class="suggestion-item">Error: ' + error.message + '</div>';
                });
            }, 1000); // Poll every 1 second for suggestions (faster feedback)
        }

        function selectSuggestion(suggestion) {
            document.getElementById('mappingManufacturer').value = suggestion;
            document.getElementById('mappingManufacturerSuggestions').style.display = 'none';
        }

        // Search 510k devices - will be attached when modal opens
        function attachSearch510kListener() {
            const searchBtn = document.getElementById('search510k');
            if (searchBtn) {
                // Remove existing listener to avoid duplicates
                searchBtn.removeEventListener('click', handleSearch510k);
                searchBtn.addEventListener('click', handleSearch510k);
            }
        }
        
        function handleSearch510k() {
            const searchTermInput = document.getElementById('k510SearchTerm');
            
            if (!searchTermInput) {
                console.error('Required input element not found');
                return;
            }
            
            const searchTerm = searchTermInput.value ? searchTermInput.value.trim() : '';
            
            
            if (!searchTerm) {
                showNotification('Please enter a device name or model', 'error');
                return;
            }

            const searchBtn = document.getElementById('search510k');
            searchBtn.disabled = true;
            searchBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Searching...';

            const url = `?ajax=search_510k_devices&device_id=${encodeURIComponent(searchTerm)}&limit=1000`;

            fetch(url)
                .then(response => {
                    return response.json();
                })
                .then(data => {
                    if (data.success && data.job) {
                        // Non-blocking: start polling for results
                        poll510kJob(data.job, searchBtn);
                    } else if (data.success && data.data) {
                        // Blocking (backward compatibility): show results directly
                        if (data.data.length > 0) {
                            openFDAResultsModal(data.data);
                        } else {
                            showNotification('No 510k records found', 'warning');
                        }
                        searchBtn.disabled = false;
                        searchBtn.innerHTML = '<i class="fas fa-search"></i> Search 510k Database';
                    } else {
                        showNotification(data.message || 'Search failed', 'error');
                        searchBtn.disabled = false;
                        searchBtn.innerHTML = '<i class="fas fa-search"></i> Search 510k Database';
                    }
                })
                .catch(error => {
                    console.error('Error searching 510k:', error);
                    showNotification('Error searching 510k database', 'error');
                    searchBtn.disabled = false;
                    searchBtn.innerHTML = '<i class="fas fa-search"></i> Search 510k Database';
                });
        }
        
        function poll510kJob(job, searchBtn) {
            const pollInterval = setInterval(() => {
                fetch('?ajax=check_jobs', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ jobs: [job] })
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    return response.text();
                })
                .then(text => {
                    // Try to parse as JSON
                    let data;
                    try {
                        data = JSON.parse(text);
                    } catch (e) {
                        console.error('Invalid JSON response:', text.substring(0, 500));
                        throw new Error('Invalid JSON response from server');
                    }
                    
                    if (data.success && data.results && data.results.length > 0) {
                        const result = data.results[0];
                        
                        if (result.status === 'running') {
                            // Still running, keep polling
                            searchBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Searching...';
                        } else {
                            // Job completed
                            clearInterval(pollInterval);
                            searchBtn.disabled = false;
                            searchBtn.innerHTML = '<i class="fas fa-search"></i> Search 510k Database';
                            
                            if (result.status === 'completed') {
                                if (result.data && Array.isArray(result.data) && result.data.length > 0) {
                                    openFDAResultsModal(result.data);
                                } else if (result.data && Array.isArray(result.data)) {
                                    // Empty array - valid response but no results
                                    showNotification('No 510k records found matching your search', 'info');
                                } else {
                                    showNotification('No 510k records found', 'warning');
                                }
                            } else {
                                // Log raw output preview for debugging
                                if (result.raw_output_preview) {
                                    console.log('Raw output preview:', result.raw_output_preview);
                                }
                                showNotification(result.error || 'Search failed', 'error');
                            }
                        }
                    } else {
                        console.error('Unexpected response structure:', data);
                        clearInterval(pollInterval);
                        searchBtn.disabled = false;
                        searchBtn.innerHTML = '<i class="fas fa-search"></i> Search 510k Database';
                        showNotification('Unexpected response from server', 'error');
                    }
                })
                .catch(error => {
                    console.error('Polling error:', error);
                    clearInterval(pollInterval);
                    searchBtn.disabled = false;
                    searchBtn.innerHTML = '<i class="fas fa-search"></i> Search 510k Database';
                    showNotification('Error checking search status: ' + error.message, 'error');
                });
            }, 2000); // Poll every 2 seconds
        }

        function displayFDAResults(devices) {
            const container = document.getElementById('fdaResults');
            container.innerHTML = devices.map(device => `
                <div class="device-card" data-device='${JSON.stringify(device)}' onclick="selectDevice(event, this)">
                    <div class="device-card-header">
                        <div class="device-title">
                            <h5>${device.brand_name || 'Unknown Brand'}</h5>
                            <div class="device-brand">${device.manufacturer_name || 'Unknown Manufacturer'}</div>
                        </div>
                        <div class="device-model">${device.model_number || 'Unknown Model'}</div>
                        <div class="device-confidence">${Math.round((device.confidence_score || 0) * 100)}% Match</div>
                    </div>
                    <div class="device-card-body">
                        <div class="device-info-grid">
                            <div class="info-section">
                                <div class="info-label">FDA Class:</div>
                                <div class="info-value">${device.fda_class || '-'}</div>
                            </div>
                            <div class="info-section">
                                <div class="info-label">GMDN Code:</div>
                                <div class="info-value">${device.gmdn_code || '-'}</div>
                            </div>
                            <div class="info-section">
                                <div class="info-label">UDI:</div>
                                <div class="info-value">${device.udi || '-'}</div>
                            </div>
                        </div>
                        ${device.device_description ? `
                            <div class="device-description">
                                <div class="description-label">Description:</div>
                                <div class="description-text">${device.device_description}</div>
                            </div>
                        ` : ''}
                        <div class="device-characteristics">
                            <div class="characteristics-tags">
                                ${device.is_implantable ? '<span class="characteristic-tag implantable"><i class="fas fa-heart"></i> Implantable</span>' : ''}
                                ${device.is_single_use ? '<span class="characteristic-tag single-use"><i class="fas fa-times"></i> Single Use</span>' : ''}
                                ${device.is_sterile ? '<span class="characteristic-tag sterile"><i class="fas fa-shield-alt"></i> Sterile</span>' : ''}
                                ${device.is_kit ? '<span class="characteristic-tag kit"><i class="fas fa-box"></i> Kit</span>' : ''}
                                ${device.is_otc ? '<span class="characteristic-tag otc"><i class="fas fa-shopping-cart"></i> OTC</span>' : ''}
                                ${device.is_rx ? '<span class="characteristic-tag rx"><i class="fas fa-prescription"></i> Rx</span>' : ''}
                            </div>
                        </div>
                    </div>
                </div>
            `).join('');
        }

        function selectDevice(event, element) {
            // Remove previous selection
            document.querySelectorAll('.device-card').forEach(card => {
                card.classList.remove('selected');
            });
            
            // Add selection to clicked card
            element.classList.add('selected');
            
            // Get device data
            const deviceData = JSON.parse(element.getAttribute('data-device'));
            selectedDevice = deviceData;
            
            // confirmMapping button removed - no longer needed in initial modal
        }
        
       // FDA Results Modal Functions

        function openFDAResultsModal(devices) {
           const modal = document.getElementById('fdaResultsModal');
           if (modal) {
               // Store all devices globally for filtering
               allDevices = devices;
               filteredDevices = [...devices];
               
               // Update counts
               document.getElementById('resultCount').textContent = devices.length;
               
               // Initialize filters (no dropdown population needed)
               
               // Clear filters
               document.getElementById('filterManufacturer').value = '';
               document.getElementById('filterBrandName').value = '';
               
               // Display devices
               displayFDAResultsInModal(devices);
               
               // Show modal
               modal.classList.add('show');
           } else {
               console.error('FDA Results Modal not found!');
           }
        }
        
        function closeFDAResultsModal() {
            const modal = document.getElementById('fdaResultsModal');
            if (modal) {
                modal.classList.remove('show');
            }
        }
        
        function display510kResultsInModal(records) {
            const container = document.getElementById('fdaResultsList');
            if (!container) {
                console.error('Results container not found');
                return;
            }
            
            container.innerHTML = records.map(record => `
                <div class="fda-device-card" data-device='${JSON.stringify(record)}'>
                    <div class="device-product-info">
                        <div class="device-title">${record.device_name || 'Unknown Device'}</div>
                        <div class="device-manufacturer">${record.applicant || 'Unknown Applicant'}</div>
                        <div class="device-model">510k: ${record.k_number || 'Unknown'}</div>
                        <div class="device-version">Date: ${record.decision_date || 'Unknown'}</div>
                    </div>
                    <div class="device-confidence-column">
                        <div class="device-confidence">${record.decision_code || 'N/A'}</div>
                    </div>
                    <div class="device-action-column">
                        <button type="button" class="btn btn-primary" onclick="view510kDetails(event, this)">
                            <i class="fas fa-eye"></i>
                            View
                        </button>
                    </div>
                </div>
            `).join('');
        }

        function displayFDAResultsInModal(records) {
           const container = document.getElementById('fdaResultsList');
           
           if (!container) {
               console.error('fdaResultsList container not found!');
               return;
           }
           
           container.innerHTML = records.map(record => `
               <div class="fda-device-card" data-device='${JSON.stringify(record)}'>
                   <div class="device-product-info">
                       <div class="device-title">${record.device_name || 'Unknown Device'}</div>
                       <div class="device-manufacturer">${record.applicant || 'Unknown Applicant'}</div>
                       <div class="device-model">510k: ${record.k_number || 'Unknown'}</div>
                       <div class="device-version">Date: ${record.decision_date || 'Unknown'}</div>
                   </div>
                   <div class="device-confidence-column">
                       <div class="device-confidence">${record.decision_code || 'N/A'}</div>
                   </div>
                   <div class="device-action-column">
                       <button type="button" class="btn btn-primary" onclick="view510kDetails(event, this)">
                           <i class="fas fa-eye"></i>
                           View
                       </button>
                   </div>
               </div>
           `).join('');
       }
        
        function selectFDADevice(event, element) {
            // Remove previous selection
            document.querySelectorAll('.fda-device-card').forEach(card => {
                card.classList.remove('selected');
            });
            
            // Add selection to clicked card
            element.classList.add('selected');
        }
        
        function selectFDADeviceForMapping(event, button) {
            event.stopPropagation();
            
            const card = button.closest('.fda-device-card');
            
            if (!card) {
                console.error('Could not find device card');
                return;
            }
            
            const deviceData = JSON.parse(card.dataset.device);
            
            // Close the FDA results modal
            closeFDAResultsModal();
            
            // Set the selected device in the mapping modal
            selectedDevice = deviceData;
            
            // Update the mapping modal to show the selected device
            updateMappingModalWithSelectedDevice(deviceData);
            
            // Enable the confirm mapping button
            const confirmBtn = document.getElementById('confirmMapping');
            if (confirmBtn) {
                confirmBtn.disabled = false;
            } else {
                console.error('Confirm mapping button not found');
            }
            
            showNotification('Device selected for mapping', 'success');
        }
        
       function updateMappingModalWithSelectedDevice(device) {
           // Update the search results section in the mapping modal
           const searchResults = document.getElementById('searchResults');
           const fdaResults = document.getElementById('fdaResults');
           
           if (searchResults && fdaResults) {
               searchResults.style.display = 'block';
               fdaResults.innerHTML = `
                   <div class="device-card selected">
                       <div class="device-card-header">
                           <div class="device-title">
                               <h5>${device.brand_name || 'Unknown Brand'}</h5>
                               <div class="device-brand">${device.manufacturer_name || 'Unknown Manufacturer'}</div>
                           </div>
                           <div class="device-model">${device.model_number || 'Unknown Model'}</div>
                           <div class="device-confidence">${Math.round((device.confidence_score || 0) * 100)}% Match</div>
                       </div>
                       <div class="device-card-body">
                           <div class="device-info-grid">
                               <div class="info-section">
                                   <div class="info-label">FDA Class</div>
                                   <div class="info-value">${device.fda_class || 'N/A'}</div>
                               </div>
                               <div class="info-section">
                                   <div class="info-label">Medical Specialty</div>
                                   <div class="info-value">${device.medical_specialty || 'N/A'}</div>
                               </div>
                               <div class="info-section">
                                   <div class="info-label">Commercial Status</div>
                                   <div class="info-value">${device.commercial_status || 'N/A'}</div>
                               </div>
                               <div class="info-section">
                                   <div class="info-label">Record Status</div>
                                   <div class="info-value">${device.record_status || 'N/A'}</div>
                               </div>
                           </div>
                           
                           ${device.device_description ? `
                               <div class="device-description">
                                   <div class="description-label">Description</div>
                                   <div class="description-text">${device.device_description}</div>
                               </div>
                           ` : ''}
                           
                           <div class="device-characteristics">
                               <div class="characteristics-tags">
                                   ${device.is_implantable === 'true' ? '<span class="characteristic-tag implantable"><i class="fas fa-heart"></i> Implantable</span>' : ''}
                                   ${device.is_single_use === 'true' ? '<span class="characteristic-tag single-use"><i class="fas fa-times"></i> Single Use</span>' : ''}
                                   ${device.is_sterile === 'true' ? '<span class="characteristic-tag sterile"><i class="fas fa-shield-alt"></i> Sterile</span>' : ''}
                                   ${device.is_kit === 'true' ? '<span class="characteristic-tag kit"><i class="fas fa-box"></i> Kit</span>' : ''}
                                   ${device.is_otc === 'true' ? '<span class="characteristic-tag otc"><i class="fas fa-shopping-cart"></i> OTC</span>' : ''}
                                   ${device.is_rx === 'true' ? '<span class="characteristic-tag rx"><i class="fas fa-prescription"></i> Rx</span>' : ''}
                               </div>
                           </div>
                       </div>
                   </div>
               `;
           }
       }
       
       // Global variables for filtering
       let allDevices = [];
       let filteredDevices = [];
       
       
       // Toggle filters panel visibility
       function toggleFDAFilters() {
           const panel = document.getElementById('fdaFiltersPanel');
           const button = document.getElementById('toggleFDAFilters');
           
           if (panel.style.display === 'none' || !panel.style.display) {
               panel.style.display = 'block';
               button.classList.add('active');
           } else {
               panel.style.display = 'none';
               button.classList.remove('active');
           }
       }
       
       // Update filter count badge
       function updateFDAFilterCount() {
           const manufacturerFilter = document.getElementById('filterManufacturer').value;
           const brandNameFilter = document.getElementById('filterBrandName').value;
           
           const filterCount = (manufacturerFilter ? 1 : 0) + (brandNameFilter ? 1 : 0);
           
           const countBadge = document.getElementById('fdaFilterCount');
           if (filterCount > 0) {
               countBadge.textContent = filterCount;
               countBadge.style.display = 'inline-block';
           } else {
               countBadge.style.display = 'none';
           }
       }
       
       // Filter functions
       function filterDevices() {
           const manufacturerFilter = document.getElementById('filterManufacturer').value.toLowerCase();
           const brandNameFilter = document.getElementById('filterBrandName').value.toLowerCase();
           
           filteredDevices = allDevices.filter(device => {
               // Manufacturer filter (case-insensitive partial match) - using 'applicant' for 510k records
               if (manufacturerFilter && !device.applicant?.toLowerCase().includes(manufacturerFilter)) {
                   return false;
               }
               
               // Brand name filter (case-insensitive partial match) - using 'device_name' for 510k records
               if (brandNameFilter && !device.device_name?.toLowerCase().includes(brandNameFilter)) {
                   return false;
               }
               
               return true;
           });
           
           // Filter count is now only shown in the filter button badge
           
           // Update filter count badge
           updateFDAFilterCount();
           
           // Re-render filtered devices
           displayFDAResultsInModal(filteredDevices);
       }
       
       function sortDevices() {
           // Sort by confidence score by default
           filteredDevices.sort((a, b) => {
               return (b.confidence_score || 0) - (a.confidence_score || 0);
           });
           
           // Re-render sorted devices
           displayFDAResultsInModal(filteredDevices);
       }
       
       function clearFDAFilters() {
           document.getElementById('filterManufacturer').value = '';
           document.getElementById('filterBrandName').value = '';
           
           filteredDevices = [...allDevices];
           
           // Update filter count badge
           updateFDAFilterCount();
           
           displayFDAResultsInModal(filteredDevices);
       }
       
       // Device Details Modal Functions
       let currentDetailDevice = null;
       
        function view510kDetails(event, button) {
            event.stopPropagation();
            const card = button.closest('.fda-device-card');
            const deviceData = JSON.parse(card.getAttribute('data-device'));
            
            // Store current device for selection
            currentDetailDevice = deviceData;
            
            // Populate and show device details modal
            populate510kDetails(deviceData);
            const modal = document.getElementById('deviceDetailsModal');
            if (modal) {
                modal.classList.add('show');
            }
        }

        function viewDeviceDetails(event, button) {
           event.stopPropagation();
           
           const card = button.closest('.fda-device-card');
           if (!card) {
               console.error('Could not find device card');
               return;
           }
           
           const deviceData = JSON.parse(card.dataset.device);
           currentDetailDevice = deviceData;
           
           // Populate the details modal
           populateDeviceDetails(deviceData);
           
           // Show the modal
           const modal = document.getElementById('deviceDetailsModal');
           if (modal) {
               modal.classList.add('show');
           }
       }
       
        function populate510kDetails(record) {
            // Populate modal header
            const modalKNumberEl = document.getElementById('modalKNumber');
            if (modalKNumberEl) modalKNumberEl.textContent = record.k_number || '-';
            
            // Populate compact header
            const deviceNameEl = document.getElementById('deviceName');
            const decisionCodeEl = document.getElementById('decisionCode');
            const versionEl = document.getElementById('version');
            
            if (deviceNameEl) deviceNameEl.textContent = record.device_name || 'Unknown Device';
            if (decisionCodeEl) decisionCodeEl.textContent = record.decision_code || '-';
            if (versionEl) versionEl.textContent = record.decision_date || '-';
            
            // Populate applicant section
            const applicantEl = document.getElementById('applicant');
            const contactEl = document.getElementById('contact');
            const address1El = document.getElementById('address1');
            const cityStateEl = document.getElementById('cityState');
            
            if (applicantEl) applicantEl.textContent = record.applicant || '-';
            if (contactEl) contactEl.textContent = record.contact || '-';
            if (address1El) address1El.textContent = record.address_1 || '-';
            if (cityStateEl) {
                const cityState = [];
                if (record.city) cityState.push(record.city);
                if (record.state) cityState.push(record.state);
                if (record.zip_code) cityState.push(record.zip_code);
                cityStateEl.textContent = cityState.join(', ') || '-';
            }
            
            // Populate details section
            const productCodeEl = document.getElementById('productCode');
            const deviceClassEl = document.getElementById('deviceClass');
            const clearanceTypeEl = document.getElementById('clearanceType');
            const dateReceivedEl = document.getElementById('dateReceived');
            
            if (productCodeEl) productCodeEl.textContent = record.product_code || '-';
            if (deviceClassEl) deviceClassEl.textContent = record.device_class || '-';
            if (clearanceTypeEl) clearanceTypeEl.textContent = record.clearance_type || '-';
            if (dateReceivedEl) dateReceivedEl.textContent = record.date_received || '-';
            
            // Populate review section
            const advisoryCommitteeEl = document.getElementById('advisoryCommittee');
            const expeditedReviewFlagEl = document.getElementById('expeditedReviewFlag');
            const thirdPartyFlagEl = document.getElementById('thirdPartyFlag');
            
            if (advisoryCommitteeEl) advisoryCommitteeEl.textContent = record.advisory_committee || '-';
            
            // Handle flag badges with proper styling
            if (expeditedReviewFlagEl) {
                expeditedReviewFlagEl.textContent = record.expedited_review_flag || '-';
                expeditedReviewFlagEl.className = 'flag-badge ' + (record.expedited_review_flag === 'true' ? 'true' : 'false');
            }
            if (thirdPartyFlagEl) {
                thirdPartyFlagEl.textContent = record.third_party_flag || '-';
                thirdPartyFlagEl.className = 'flag-badge ' + (record.third_party_flag === 'true' ? 'true' : 'false');
            }
            
            // Populate technical section
            const medicalSpecialtyDescriptionEl = document.getElementById('medicalSpecialtyDescription');
            const regulationNumberEl = document.getElementById('regulationNumber');
            const registrationNumbersEl = document.getElementById('registrationNumbers');
            const feiNumbersEl = document.getElementById('feiNumbers');
            
            if (medicalSpecialtyDescriptionEl) medicalSpecialtyDescriptionEl.textContent = record.medical_specialty_description || '-';
            if (regulationNumberEl) regulationNumberEl.textContent = record.regulation_number || '-';
            if (registrationNumbersEl) registrationNumbersEl.textContent = record.registration_numbers || '-';
            if (feiNumbersEl) feiNumbersEl.textContent = record.fei_numbers || '-';
            
            // Populate summary
            const statementOrSummaryEl = document.getElementById('statementOrSummary');
            if (statementOrSummaryEl) statementOrSummaryEl.textContent = record.statement_or_summary || 'No summary available';
        }

        function populateDeviceDetails(device) {
           // Header information - Updated for 510k data
           document.getElementById('deviceName').textContent = device.device_name || 'Unknown Device';
           document.getElementById('version').textContent = device.decision_date || 'Unknown Date';
           
           // 510k Information
           document.getElementById('deviceIdentifier').textContent = device.k_number || '-';
           document.getElementById('productCode').textContent = device.product_code || '-';
           document.getElementById('regulationNumber').textContent = device.regulation_number || '-';
           document.getElementById('decisionCode').textContent = device.decision_code || '-';
           document.getElementById('decisionDescription').textContent = device.decision_description || '-';
           document.getElementById('clearanceType').textContent = device.clearance_type || '-';
           document.getElementById('dateReceived').textContent = device.date_received || '-';
           document.getElementById('statementOrSummary').textContent = device.statement_or_summary || '-';
           
           // Applicant Information
           document.getElementById('applicant').textContent = device.applicant || '-';
           document.getElementById('contact').textContent = device.contact || '-';
           document.getElementById('address1').textContent = device.address_1 || '-';
           document.getElementById('address2').textContent = device.address_2 || '-';
           document.getElementById('city').textContent = device.city || '-';
           document.getElementById('state').textContent = device.state || '-';
           document.getElementById('zipCode').textContent = device.zip_code || '-';
           document.getElementById('postalCode').textContent = device.postal_code || '-';
           document.getElementById('countryCode').textContent = device.country_code || '-';
           
           // Device Characteristics
           const characteristicsContainer = document.getElementById('detailCharacteristics');
           characteristicsContainer.innerHTML = '';
           
           const characteristics = [];
           if (device.is_implantable === 'true') characteristics.push({type: 'implantable', label: 'Implantable', icon: 'fas fa-heart'});
           if (device.is_single_use === 'true') characteristics.push({type: 'single-use', label: 'Single Use', icon: 'fas fa-times'});
           if (device.is_sterile === 'true') characteristics.push({type: 'sterile', label: 'Sterile', icon: 'fas fa-shield-alt'});
           if (device.is_kit === 'true') characteristics.push({type: 'kit', label: 'Kit', icon: 'fas fa-box'});
           if (device.is_otc === 'true') characteristics.push({type: 'otc', label: 'OTC', icon: 'fas fa-shopping-cart'});
           if (device.is_rx === 'true') characteristics.push({type: 'rx', label: 'Rx', icon: 'fas fa-prescription'});
           
           if (characteristics.length > 0) {
               characteristics.forEach(char => {
                   const tag = document.createElement('span');
                   tag.className = `characteristic-tag ${char.type}`;
                   tag.innerHTML = `<i class="${char.icon}"></i> ${char.label}`;
                   characteristicsContainer.appendChild(tag);
               });
           } else {
               characteristicsContainer.innerHTML = '<span class="text-muted">No special characteristics</span>';
           }
           
           // Description
           const descriptionSection = document.getElementById('detailDescriptionSection');
           const descriptionContent = document.getElementById('detailDescription');
           if (device.device_description) {
               descriptionContent.textContent = device.device_description;
               descriptionSection.style.display = 'block';
           } else {
               descriptionSection.style.display = 'none';
           }
           
           // Contact Information
           document.getElementById('detailCustomerPhone').textContent = device.customer_phone || '-';
           document.getElementById('detailCustomerEmail').textContent = device.customer_email || '-';
           document.getElementById('detailLabelerDunsNumber').textContent = device.labeler_duns_number || '-';
       }
       
       function closeDeviceDetailsModal() {
           const modal = document.getElementById('deviceDetailsModal');
           if (modal) {
               modal.classList.remove('show');
           }
           currentDetailDevice = null;
       }

        function viewFDADocument() {
            if (!currentDetailDevice || !currentDetailDevice.k_number) {
                showNotification('No 510k number available for this device.', 'error');
                return;
            }
            const kNumber = currentDetailDevice.k_number;
            const fdaUrl = `https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfPMN/pmn.cfm?ID=${encodeURIComponent(kNumber)}`;
            window.open(fdaUrl, '_blank');
        }
       
       function selectDeviceFromDetails() {
           // CACHE BUST: Fixed asset ID clearing issue - <?php echo time(); ?>
           
           if (!currentDetailDevice || !currentAssetId) {
               console.error('No device or asset selected for mapping');
               showNotification('Error: Missing device or asset information', 'error');
               return;
           }
           
           // Store the asset ID before closing modals (which will clear it)
           const assetIdToMap = currentAssetId;
           const deviceToMap = currentDetailDevice;
           
           // Close the device details modal
           closeDeviceDetailsModal();
           
           // Close the FDA results modal
           closeFDAResultsModal();
           
           // Note: Don't close mapping modal here as it might not be open
           // The user is mapping directly from the device details modal
           
           // Perform the actual mapping
           const formData = new FormData();
           formData.append('asset_id', assetIdToMap);
           formData.append('device_info', JSON.stringify(deviceToMap));
           

           fetch(window.location.pathname + '?ajax=map_device_enhanced', {
               method: 'POST',
               body: formData,
               headers: {
                   'X-Requested-With': 'XMLHttpRequest'
               }
           })
           .then(response => {
               
               // Get the response text first to debug
               return response.text().then(text => {
                   try {
                       return JSON.parse(text);
                   } catch (e) {
                       console.error('JSON parse error:', e);
                       console.error('Response text that failed to parse:', text);
                       throw new Error('Invalid JSON response: ' + text.substring(0, 200));
                   }
               });
           })
           .then(data => {
               if (data.success) {
                   showNotification('Device mapped successfully!', 'success');
                   // Refresh the page to update the mapping status
                   setTimeout(() => {
                       window.location.reload();
                   }, 1000);
               } else {
                   showNotification(data.message || 'Failed to map device', 'error');
               }
           })
           .catch(error => {
               console.error('Error mapping device:', error);
               showNotification('Error mapping device', 'error');
           });
       }

        // confirmMapping function removed - no longer needed since mapping happens directly from device details modal

        // Close modal when clicking outside
        document.getElementById('mappingModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeMappingModal();
            }
        });

        // Close modal with X button
        document.querySelector('#mappingModal .modal-close').addEventListener('click', closeMappingModal);
        
        // FDA Results Modal Event Listeners
        document.getElementById('fdaResultsModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeFDAResultsModal();
            }
        });
        
        document.querySelector('#fdaResultsModal .modal-close').addEventListener('click', closeFDAResultsModal);

        // Dropdown functionality
        function toggleDropdown(assetId) {
            // Close all other dropdowns
            document.querySelectorAll('.dropdown-menu').forEach(dropdown => {
                if (dropdown.id !== `dropdown-${assetId}`) {
                    dropdown.classList.remove('show');
                }
            });
            
            // Toggle current dropdown
            const dropdown = document.getElementById(`dropdown-${assetId}`);
            if (dropdown) {
                dropdown.classList.toggle('show');
            } else {
                console.error('Dropdown not found for asset:', assetId);
            }
        }

        // Close dropdowns when clicking outside
        document.addEventListener('click', function(event) {
            if (!event.target.closest('.action-dropdown')) {
                document.querySelectorAll('.dropdown-menu').forEach(dropdown => {
                    dropdown.classList.remove('show');
                });
            }
        });
        
        // Event listeners for Device Details Modal
        document.addEventListener('click', function(event) {
            if (event.target.id === 'deviceDetailsModal') {
                closeDeviceDetailsModal();
            }
            if (event.target.classList.contains('modal-close') && event.target.closest('#deviceDetailsModal')) {
                closeDeviceDetailsModal();
            }
        });

        // Toggle More Info section
        function toggleMoreInfo() {
            const content = document.getElementById('moreInfoContent');
            const button = document.querySelector('.more-info-toggle');
            const icon = button.querySelector('i');
            
            if (content.style.display === 'none' || !content.style.display) {
                content.style.display = 'block';
                button.classList.add('active');
                icon.style.transform = 'rotate(180deg)';
            } else {
                content.style.display = 'none';
                button.classList.remove('active');
                icon.style.transform = 'rotate(0deg)';
            }
        }

    </script>
</body>
</html>
