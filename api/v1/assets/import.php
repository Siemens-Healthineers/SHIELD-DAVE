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

// Check if user has permission to write assets
$unifiedAuth->requirePermission('assets', 'write');

$db = DatabaseConfig::getInstance();

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'METHOD_NOT_ALLOWED',
            'message' => 'Only POST method is allowed'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

// Check if file was uploaded
if (!isset($_FILES['scan_file']) || $_FILES['scan_file']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'NO_FILE_UPLOADED',
            'message' => 'No scan file uploaded or upload error occurred'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

$uploadedFile = $_FILES['scan_file'];
$fileType = $_POST['file_type'] ?? '';
$importOptions = json_decode($_POST['import_options'] ?? '{}', true);

// Validate file type
$allowedTypes = ['nmap', 'nessus', 'csv'];
if (!in_array($fileType, $allowedTypes)) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'INVALID_FILE_TYPE',
            'message' => 'Invalid file type. Supported types: ' . implode(', ', $allowedTypes)
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

// Validate file size (max 50MB)
$maxFileSize = 50 * 1024 * 1024; // 50MB
if ($uploadedFile['size'] > $maxFileSize) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'FILE_TOO_LARGE',
            'message' => 'File size exceeds maximum allowed size of 50MB'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

try {
    $importResult = processScanFile($uploadedFile, $fileType, $importOptions, $user['user_id']);
    
    echo json_encode([
        'success' => true,
        'data' => $importResult,
        'timestamp' => date('c')
    ]);
    
} catch (Exception $e) {
    error_log("Asset import error: " . $e->getMessage());
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'IMPORT_ERROR',
            'message' => 'Failed to process scan file: ' . $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
}

/**
 * Process uploaded scan file and import assets
 */
function processScanFile($file, $fileType, $options, $userId) {
    global $db;
    
    $filePath = $file['tmp_name'];
    $fileName = $file['name'];
    
    $importResult = [
        'file_name' => $fileName,
        'file_type' => $fileType,
        'total_processed' => 0,
        'assets_created' => 0,
        'assets_updated' => 0,
        'assets_skipped' => 0,
        'errors' => []
    ];
    
    switch ($fileType) {
        case 'nmap':
            $importResult = processNmapFile($filePath, $options, $userId);
            break;
            
        case 'nessus':
            $importResult = processNessusFile($filePath, $options, $userId);
            break;
            
        case 'csv':
            $importResult = processCsvFile($filePath, $options, $userId);
            break;
            
        default:
            throw new Exception("Unsupported file type: $fileType");
    }
    
    $importResult['file_name'] = $fileName;
    $importResult['file_type'] = $fileType;
    
    return $importResult;
}

/**
 * Process Nmap XML file
 */
function processNmapFile($filePath, $options, $userId) {
    global $db;
    
    $result = [
        'total_processed' => 0,
        'assets_created' => 0,
        'assets_updated' => 0,
        'assets_skipped' => 0,
        'errors' => []
    ];
    
    $xml = simplexml_load_file($filePath);
    if ($xml === false) {
        throw new Exception("Invalid XML file");
    }
    
    // Parse nmap results
    foreach ($xml->host as $host) {
        $result['total_processed']++;
        
        try {
            $ipAddress = (string)$host->address['addr'];
            $hostname = '';
            
            // Get hostname if available
            if (isset($host->hostnames->hostname)) {
                $hostname = (string)$host->hostnames->hostname['name'];
            }
            
            // Determine asset type based on open ports
            $assetType = determineAssetTypeFromPorts($host);
            $criticality = determineCriticality($assetType, $options);
            
            // Check if asset already exists
            $existingAsset = $db->query(
                "SELECT asset_id FROM assets WHERE ip_address = ?",
                [$ipAddress]
            )->fetch();
            
            $assetData = [
                'ip_address' => $ipAddress,
                'hostname' => $hostname,
                'asset_type' => $assetType,
                'criticality' => $criticality,
                'status' => 'Active',
                'last_seen' => date('Y-m-d H:i:s'),
                'created_by' => $userId,
                'updated_by' => $userId
            ];
            
            if ($existingAsset) {
                // Update existing asset
                $db->query(
                    "UPDATE assets SET hostname = ?, asset_type = ?, criticality = ?, last_seen = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE asset_id = ?",
                    [$assetData['hostname'], $assetData['asset_type'], $assetData['criticality'], $assetData['last_seen'], $assetData['updated_by'], $existingAsset['asset_id']]
                );
                $result['assets_updated']++;
            } else {
                // Create new asset
                $db->query(
                    "INSERT INTO assets (asset_id, ip_address, hostname, asset_type, criticality, status, last_seen, created_by, updated_by) VALUES (gen_random_uuid(), ?, ?, ?, ?, ?, ?, ?, ?)",
                    array_values($assetData)
                );
                $result['assets_created']++;
            }
            
        } catch (Exception $e) {
            $result['errors'][] = "Error processing host $ipAddress: " . $e->getMessage();
        }
    }
    
    return $result;
}

/**
 * Process Nessus XML file
 */
function processNessusFile($filePath, $options, $userId) {
    global $db;
    
    $result = [
        'total_processed' => 0,
        'assets_created' => 0,
        'assets_updated' => 0,
        'assets_skipped' => 0,
        'errors' => []
    ];
    
    $xml = simplexml_load_file($filePath);
    if ($xml === false) {
        throw new Exception("Invalid Nessus XML file");
    }
    
    // Parse Nessus results
    foreach ($xml->Report->ReportHost as $host) {
        $result['total_processed']++;
        
        try {
            $ipAddress = (string)$host['name'];
            $hostname = '';
            
            // Get hostname if available
            if (isset($host->HostProperties->tag)) {
                foreach ($host->HostProperties->tag as $tag) {
                    if ($tag['name'] == 'host-fqdn') {
                        $hostname = (string)$tag;
                        break;
                    }
                }
            }
            
            // Determine asset type and criticality based on vulnerabilities
            $assetType = determineAssetTypeFromNessus($host);
            $criticality = determineCriticalityFromNessus($host, $options);
            
            // Check if asset already exists
            $existingAsset = $db->query(
                "SELECT asset_id FROM assets WHERE ip_address = ?",
                [$ipAddress]
            )->fetch();
            
            $assetData = [
                'ip_address' => $ipAddress,
                'hostname' => $hostname,
                'asset_type' => $assetType,
                'criticality' => $criticality,
                'status' => 'Active',
                'last_seen' => date('Y-m-d H:i:s'),
                'created_by' => $userId,
                'updated_by' => $userId
            ];
            
            if ($existingAsset) {
                // Update existing asset
                $db->query(
                    "UPDATE assets SET hostname = ?, asset_type = ?, criticality = ?, last_seen = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE asset_id = ?",
                    [$assetData['hostname'], $assetData['asset_type'], $assetData['criticality'], $assetData['last_seen'], $assetData['updated_by'], $existingAsset['asset_id']]
                );
                $result['assets_updated']++;
            } else {
                // Create new asset
                $db->query(
                    "INSERT INTO assets (asset_id, ip_address, hostname, asset_type, criticality, status, last_seen, created_by, updated_by) VALUES (gen_random_uuid(), ?, ?, ?, ?, ?, ?, ?, ?)",
                    array_values($assetData)
                );
                $result['assets_created']++;
            }
            
        } catch (Exception $e) {
            $result['errors'][] = "Error processing host $ipAddress: " . $e->getMessage();
        }
    }
    
    return $result;
}

/**
 * Process CSV file
 */
function processCsvFile($filePath, $options, $userId) {
    global $db;
    
    $result = [
        'total_processed' => 0,
        'assets_created' => 0,
        'assets_updated' => 0,
        'assets_skipped' => 0,
        'errors' => []
    ];
    
    $handle = fopen($filePath, 'r');
    if ($handle === false) {
        throw new Exception("Cannot open CSV file");
    }
    
    // Read header row
    $headers = fgetcsv($handle);
    if ($headers === false) {
        throw new Exception("Invalid CSV file - no headers found");
    }
    
    // Map common column names
    $columnMap = [
        'ip' => 'ip_address',
        'ip_address' => 'ip_address',
        'hostname' => 'hostname',
        'host' => 'hostname',
        'type' => 'asset_type',
        'asset_type' => 'asset_type',
        'criticality' => 'criticality',
        'priority' => 'criticality',
        'status' => 'status',
        'manufacturer' => 'manufacturer',
        'model' => 'model',
        'serial' => 'serial_number',
        'serial_number' => 'serial_number',
        'department' => 'department',
        'location' => 'location'
    ];
    
    $mappedHeaders = [];
    foreach ($headers as $header) {
        $cleanHeader = strtolower(trim($header));
        $mappedHeaders[] = $columnMap[$cleanHeader] ?? $cleanHeader;
    }
    
    // Process each row
    while (($row = fgetcsv($handle)) !== false) {
        $result['total_processed']++;
        
        try {
            $assetData = array_combine($mappedHeaders, $row);
            
            // Validate required fields
            if (empty($assetData['ip_address'])) {
                $result['assets_skipped']++;
                continue;
            }
            
            // Set defaults
            $assetData['asset_type'] = $assetData['asset_type'] ?? 'Unknown';
            $assetData['criticality'] = $assetData['criticality'] ?? 'Non-Essential';
            $assetData['status'] = $assetData['status'] ?? 'Active';
            $assetData['last_seen'] = date('Y-m-d H:i:s');
            $assetData['created_by'] = $userId;
            $assetData['updated_by'] = $userId;
            
            // Check if asset already exists
            $existingAsset = $db->query(
                "SELECT asset_id FROM assets WHERE ip_address = ?",
                [$assetData['ip_address']]
            )->fetch();
            
            if ($existingAsset) {
                // Update existing asset
                $updateFields = [];
                $updateValues = [];
                
                foreach ($assetData as $field => $value) {
                    if ($field !== 'ip_address' && !empty($value)) {
                        $updateFields[] = "$field = ?";
                        $updateValues[] = $value;
                    }
                }
                
                if (!empty($updateFields)) {
                    $updateValues[] = $existingAsset['asset_id'];
                    $db->query(
                        "UPDATE assets SET " . implode(', ', $updateFields) . ", updated_at = CURRENT_TIMESTAMP WHERE asset_id = ?",
                        $updateValues
                    );
                    $result['assets_updated']++;
                } else {
                    $result['assets_skipped']++;
                }
            } else {
                // Create new asset
                $fields = array_keys($assetData);
                $placeholders = str_repeat('?,', count($fields) - 1) . '?';
                
                $db->query(
                    "INSERT INTO assets (asset_id, " . implode(', ', $fields) . ") VALUES (gen_random_uuid(), $placeholders)",
                    array_values($assetData)
                );
                $result['assets_created']++;
            }
            
        } catch (Exception $e) {
            $result['errors'][] = "Error processing row " . $result['total_processed'] . ": " . $e->getMessage();
        }
    }
    
    fclose($handle);
    return $result;
}

/**
 * Determine asset type from nmap port scan results
 */
function determineAssetTypeFromPorts($host) {
    $openPorts = [];
    
    if (isset($host->ports->port)) {
        foreach ($host->ports->port as $port) {
            if ($port['state'] == 'open') {
                $openPorts[] = (int)$port['portid'];
            }
        }
    }
    
    // Medical device ports
    $medicalPorts = [443, 80, 8080, 8443, 22, 23, 161, 162, 502, 102, 1883, 8883];
    $hasMedicalPorts = !empty(array_intersect($openPorts, $medicalPorts));
    
    // Server ports
    $serverPorts = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 3389, 1433, 3306, 5432];
    $hasServerPorts = !empty(array_intersect($openPorts, $serverPorts));
    
    // IoT/Sensor ports
    $iotPorts = [1883, 8883, 502, 102, 47808, 1900, 5353];
    $hasIotPorts = !empty(array_intersect($openPorts, $iotPorts));
    
    if ($hasMedicalPorts) {
        return 'Medical Device';
    } elseif ($hasIotPorts) {
        return 'IoMT Sensor';
    } elseif ($hasServerPorts) {
        return 'Server';
    } else {
        return 'Unknown';
    }
}

/**
 * Determine asset type from Nessus scan results
 */
function determineAssetTypeFromNessus($host) {
    // Look for medical device indicators in vulnerability descriptions
    $medicalKeywords = ['medical', 'dicom', 'pacs', 'hl7', 'fhir', 'patient', 'clinical'];
    $iotKeywords = ['iot', 'sensor', 'embedded', 'm2m', 'industrial'];
    $serverKeywords = ['server', 'database', 'web', 'mail', 'dns'];
    
    $description = '';
    foreach ($host->ReportItem as $item) {
        $description .= ' ' . strtolower($item->description);
    }
    
    foreach ($medicalKeywords as $keyword) {
        if (strpos($description, $keyword) !== false) {
            return 'Medical Device';
        }
    }
    
    foreach ($iotKeywords as $keyword) {
        if (strpos($description, $keyword) !== false) {
            return 'IoMT Sensor';
        }
    }
    
    foreach ($serverKeywords as $keyword) {
        if (strpos($description, $keyword) !== false) {
            return 'Server';
        }
    }
    
    return 'Unknown';
}

/**
 * Determine criticality based on asset type and options
 */
function determineCriticality($assetType, $options) {
    $defaultCriticality = [
        'Medical Device' => 'Clinical-High',
        'IoMT Sensor' => 'Business-Medium',
        'Server' => 'Clinical-High',
        'Unknown' => 'Non-Essential'
    ];
    
    return $options['default_criticality'][$assetType] ?? $defaultCriticality[$assetType] ?? 'Non-Essential';
}

/**
 * Determine criticality from Nessus scan results
 */
function determineCriticalityFromNessus($host, $options) {
    $highSeverityCount = 0;
    $mediumSeverityCount = 0;
    
    foreach ($host->ReportItem as $item) {
        $severity = (int)$item->severity;
        if ($severity >= 4) {
            $highSeverityCount++;
        } elseif ($severity >= 2) {
            $mediumSeverityCount++;
        }
    }
    
    if ($highSeverityCount > 0) {
        return 'Clinical-High';
    } elseif ($mediumSeverityCount > 2) {
        return 'Business-Medium';
    } else {
        return 'Non-Essential';
    }
}
?>
