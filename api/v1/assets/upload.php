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
require_once __DIR__ . '/../../../includes/unified-auth.php';
require_once __DIR__ . '/../../../config/database.php';
require_once __DIR__ . '/../../../includes/functions.php';
require_once __DIR__ . '/../../../includes/oui-lookup.php';

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
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
    ob_clean();
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

// Check if user has permission to write assets (upload requires write permission)
$unifiedAuth->requirePermission('assets', 'write');

$db = DatabaseConfig::getInstance();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Check if file was uploaded
        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => ['code' => 'NO_FILE', 'message' => 'No file uploaded or upload error occurred']
            ]);
            exit;
        }

        $file = $_FILES['file'];
        $uploadType = $_POST['type'] ?? 'nmap'; // Default to nmap
        $department = $_POST['department'] ?? null;
        $location = $_POST['location'] ?? null;

        // Validate file type
        $allowedTypes = ['nmap', 'nessus', 'csv'];
        if (!in_array($uploadType, $allowedTypes)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => ['code' => 'INVALID_TYPE', 'message' => 'Invalid upload type. Must be: ' . implode(', ', $allowedTypes)]
            ]);
            exit;
        }

        // Validate file extension
        $allowedExtensions = ['xml', 'csv'];
        $fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($fileExtension, $allowedExtensions)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => ['code' => 'INVALID_EXTENSION', 'message' => 'Invalid file extension. Must be: ' . implode(', ', $allowedExtensions)]
            ]);
            exit;
        }

        // Create upload directory if it doesn't exist
        $uploadDir = _ROOT . '/uploads/';
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0755, true);
        }

        // Generate unique filename
        $filename = uniqid() . '_' . $file['name'];
        $filepath = $uploadDir . $filename;

        // Move uploaded file
        if (!move_uploaded_file($file['tmp_name'], $filepath)) {
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => ['code' => 'UPLOAD_FAILED', 'message' => 'Failed to save uploaded file']
            ]);
            exit;
        }

        // Process file based on type
        $results = processUploadedFile($filepath, $uploadType, $user['user_id'], $department, $location);

        // Clean up uploaded file
        unlink($filepath);

        if ($results['processed'] > 0) {
            // Note: UnifiedAuth doesn't have logUserAction, audit logging can be added if needed

            http_response_code(200);
            echo json_encode([
                'success' => true,
                'data' => [
                    'processed' => $results['processed'],
                    'errors' => $results['errors'],
                    'file_type' => $uploadType,
                    'filename' => $file['name']
                ],
                'message' => 'File uploaded and processed successfully',
                'timestamp' => date('Y-m-d\TH:i:s\Z')
            ]);
        } else {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => ['code' => 'PROCESSING_FAILED', 'message' => 'No assets were processed from the uploaded file'],
                'details' => $results['errors']
            ]);
        }

    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => ['code' => 'SERVER_ERROR', 'message' => 'An unexpected error occurred: ' . $e->getMessage()]
        ]);
    }
} else {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => ['code' => 'METHOD_NOT_ALLOWED', 'message' => 'Method not allowed']]);
}

/**
 * Process uploaded file based on type
 */
function processUploadedFile($filepath, $type, $userId, $department = null, $location = null) {
    $db = DatabaseConfig::getInstance();
    $results = ['processed' => 0, 'errors' => []];
    
    try {
        switch ($type) {
            case 'nmap':
                $results = processNmapFile($filepath, $userId, $department, $location);
                break;
            case 'nessus':
                $results = processNessusFile($filepath, $userId, $department, $location);
                break;
            case 'csv':
                $results = processCsvFile($filepath, $userId, $department, $location);
                break;
            default:
                throw new Exception('Unknown upload type: ' . $type);
        }
    } catch (Exception $e) {
        $results['errors'][] = $e->getMessage();
    }
    
    return $results;
}

/**
 * Process Nmap XML file
 */
function processNmapFile($filepath, $userId, $department = null, $location = null) {
    $db = DatabaseConfig::getInstance();
    $results = ['processed' => 0, 'errors' => []];
    
    try {
        $xml = simplexml_load_file($filepath);
        if (!$xml) {
            throw new Exception('Invalid XML file');
        }
        
        foreach ($xml->host as $host) {
            try {
                $hostname = (string)$host->hostnames->hostname['name'] ?? null;
                $ip = (string)$host->address['addr'] ?? null;
                $mac = null;
                
                // Get MAC address if available
                $manufacturer = null;
                foreach ($host->address as $address) {
                    if ((string)$address['addrtype'] === 'mac') {
                        $mac = (string)$address['addr'];
                        // Auto-lookup manufacturer from MAC address
                        if (!empty($mac)) {
                            $manufacturer = lookupManufacturerFromMac($mac);
                        }
                        break;
                    }
                }
                
                if (!$ip) continue;
                
                // Extract OS information if available
                $os = null;
                if (isset($host->os->osmatch)) {
                    $os = (string)$host->os->osmatch['name'];
                }
                
                // Extract open ports
                $openPorts = [];
                if (isset($host->ports->port)) {
                    foreach ($host->ports->port as $port) {
                        if ((string)$port->state['state'] === 'open') {
                            $openPorts[] = [
                                'port' => (string)$port['portid'],
                                'protocol' => (string)$port['protocol'],
                                'service' => (string)$port->service['name'] ?? 'unknown',
                                'version' => (string)$port->service['version'] ?? null
                            ];
                        }
                    }
                }
                
                // Insert or update asset
                $sql = "INSERT INTO assets (
                    hostname, ip_address, mac_address, manufacturer, source, raw_data, status,
                    department, location, os, created_by, updated_by
                ) VALUES (
                    ?, ?, ?, ?, 'nmap', ?, 'Active', ?, ?, ?, ?, ?
                ) ON CONFLICT (ip_address) DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    mac_address = EXCLUDED.mac_address,
                    manufacturer = COALESCE(EXCLUDED.manufacturer, assets.manufacturer),
                    raw_data = EXCLUDED.raw_data,
                    os = EXCLUDED.os,
                    last_seen = CURRENT_TIMESTAMP,
                    updated_by = EXCLUDED.updated_by";
                
                $rawData = json_encode([
                    'nmap_data' => json_decode(json_encode($host), true),
                    'open_ports' => $openPorts,
                    'uploaded_by' => $userId,
                    'uploaded_at' => date('Y-m-d H:i:s')
                ]);
                
                $db->query($sql, [
                    $hostname, $ip, $mac, $manufacturer, $rawData, $department, $location, $os, $userId, $userId
                ]);
                $results['processed']++;
                
            } catch (Exception $e) {
                $results['errors'][] = 'Error processing host ' . $ip . ': ' . $e->getMessage();
            }
        }
        
    } catch (Exception $e) {
        $results['errors'][] = 'Error parsing Nmap file: ' . $e->getMessage();
    }
    
    return $results;
}

/**
 * Process Nessus XML file
 */
function processNessusFile($filepath, $userId, $department = null, $location = null) {
    $db = DatabaseConfig::getInstance();
    $results = ['processed' => 0, 'errors' => []];
    
    try {
        $xml = simplexml_load_file($filepath);
        if (!$xml) {
            throw new Exception('Invalid XML file');
        }
        
        foreach ($xml->Report->ReportHost as $host) {
            try {
                $hostname = (string)$host['name'] ?? null;
                $ip = $hostname; // Nessus uses hostname as IP
                
                if (!$ip) continue;
                
                // Insert or update asset
                $sql = "INSERT INTO assets (
                    hostname, ip_address, source, raw_data, status,
                    department, location, created_by, updated_by
                ) VALUES (
                    ?, ?, 'nessus', ?, 'Active', ?, ?, ?, ?
                ) ON CONFLICT (ip_address) DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    raw_data = EXCLUDED.raw_data,
                    last_seen = CURRENT_TIMESTAMP,
                    updated_by = EXCLUDED.updated_by";
                
                $rawData = json_encode([
                    'nessus_data' => json_decode(json_encode($host), true),
                    'uploaded_by' => $userId,
                    'uploaded_at' => date('Y-m-d H:i:s')
                ]);
                
                $db->query($sql, [$hostname, $ip, $rawData, $department, $location, $userId, $userId]);
                $results['processed']++;
                
            } catch (Exception $e) {
                $results['errors'][] = 'Error processing host ' . $ip . ': ' . $e->getMessage();
            }
        }
        
    } catch (Exception $e) {
        $results['errors'][] = 'Error parsing Nessus file: ' . $e->getMessage();
    }
    
    return $results;
}

/**
 * Process CSV file
 */
function processCsvFile($filepath, $userId, $department = null, $location = null) {
    $db = DatabaseConfig::getInstance();
    $results = ['processed' => 0, 'errors' => []];
    
    try {
        $handle = fopen($filepath, 'r');
        if (!$handle) {
            throw new Exception('Cannot open CSV file');
        }
        
        $headers = fgetcsv($handle);
        if (!$headers) {
            throw new Exception('Invalid CSV file - no headers found');
        }
        
        while (($row = fgetcsv($handle)) !== false) {
            try {
                $data = array_combine($headers, $row);
                
                // Normalize fields - convert empty strings to null
                $hostname = isset($data['hostname']) ? (trim($data['hostname']) ?: null) : (isset($data['name']) ? (trim($data['name']) ?: null) : null);
                $ip = isset($data['ip_address']) ? (trim($data['ip_address']) ?: null) : (isset($data['ip']) ? (trim($data['ip']) ?: null) : null);
                $mac = isset($data['mac_address']) ? (trim($data['mac_address']) ?: null) : (isset($data['mac']) ? (trim($data['mac']) ?: null) : null);
                $manufacturer = isset($data['manufacturer']) ? (trim($data['manufacturer']) ?: null) : null;
                $model = isset($data['model']) ? (trim($data['model']) ?: null) : null;
                $serial = isset($data['serial_number']) ? (trim($data['serial_number']) ?: null) : (isset($data['serial']) ? (trim($data['serial']) ?: null) : null);
                
                // Auto-lookup manufacturer from MAC address if not provided
                if (empty($manufacturer) && !empty($mac)) {
                    $manufacturer = lookupManufacturerFromMac($mac);
                }
                
                if (!$ip) continue;
                
                // Determine asset_type from CSV or infer from data
                $assetType = null;
                if (isset($data['asset_type']) && !empty($data['asset_type'])) {
                    // Use asset_type from CSV if provided
                    $validTypes = ['Server', 'Laptop', 'Switch', 'Software', 'Cloud Resource', 'IoT Gateway', 'IoMT Sensor', 'Smart Device', 'Medical Device'];
                    if (in_array($data['asset_type'], $validTypes)) {
                        $assetType = $data['asset_type'];
                    }
                }
                
                // If not provided or invalid, try to determine from hostname
                if (!$assetType && $hostname) {
                    $assetType = determineAssetTypeFromHostname($hostname);
                }
                
                // Default to 'Server' if still not determined
                if (!$assetType) {
                    $assetType = 'Server';
                }
                
                // Insert or update asset
                $sql = "INSERT INTO assets (
                    hostname, ip_address, mac_address, manufacturer, model, serial_number,
                    asset_type, source, raw_data, status, department, location, created_by, updated_by
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, 'csv', ?, 'Active', ?, ?, ?, ?
                ) ON CONFLICT (ip_address) DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    mac_address = EXCLUDED.mac_address,
                    manufacturer = EXCLUDED.manufacturer,
                    model = EXCLUDED.model,
                    serial_number = EXCLUDED.serial_number,
                    asset_type = EXCLUDED.asset_type,
                    raw_data = EXCLUDED.raw_data,
                    last_seen = CURRENT_TIMESTAMP,
                    updated_by = EXCLUDED.updated_by";
                
                $rawData = json_encode([
                    'csv_data' => $data,
                    'uploaded_by' => $userId,
                    'uploaded_at' => date('Y-m-d H:i:s')
                ]);
                
                $db->query($sql, [
                    $hostname, $ip, $mac, $manufacturer, $model, $serial, $assetType,
                    $rawData, $department, $location, $userId, $userId
                ]);
                $results['processed']++;
                
            } catch (Exception $e) {
                $results['errors'][] = 'Error processing CSV row: ' . $e->getMessage();
            }
        }
        
        fclose($handle);
        
    } catch (Exception $e) {
        $results['errors'][] = 'Error parsing CSV file: ' . $e->getMessage();
    }
    
    return $results;
}

/**
 * Determine asset type from hostname
 */
function determineAssetTypeFromHostname($hostname) {
    $hostname = strtolower($hostname ?? '');
    
    // Medical device patterns
    $medicalPatterns = [
        'artis', 'pheno', 'mri', 'ct', 'ultrasound', 'xray', 'defibrillator', 'ventilator',
        'monitor', 'pump', 'analyzer', 'scanner', 'camera', 'scope', 'sensor', 'device',
        'siemens', 'ge', 'philips', 'medtronic', 'baxter', 'abbott', 'bd', 'covidien'
    ];
    
    // IoT/Smart device patterns
    $iotPatterns = ['iot', 'sensor', 'gateway', 'hub', 'bridge', 'relay', 'beacon', 'tag'];
    
    // Network device patterns
    $networkPatterns = ['switch', 'router', 'firewall', 'access-point', 'ap-', 'wlc', 'controller'];
    
    // Check for medical devices first
    foreach ($medicalPatterns as $pattern) {
        if (strpos($hostname, $pattern) !== false) {
            return 'Medical Device';
        }
    }
    
    // Check for IoT devices
    foreach ($iotPatterns as $pattern) {
        if (strpos($hostname, $pattern) !== false) {
            return 'IoMT Sensor';
        }
    }
    
    // Check for network devices
    foreach ($networkPatterns as $pattern) {
        if (strpos($hostname, $pattern) !== false) {
            return 'Switch';
        }
    }
    
    // Default to Server if no patterns match
    return 'Server';
}
?>
