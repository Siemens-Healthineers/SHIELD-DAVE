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
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
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

// Check if user has permission to write devices
$unifiedAuth->requirePermission('devices', 'write');

$db = DatabaseConfig::getInstance();

// Handle different HTTP methods
switch ($_SERVER['REQUEST_METHOD']) {
    case 'POST':
        handleSbomUpload();
        break;
    case 'GET':
        handleSbomRetrieval();
        break;
    default:
        http_response_code(405);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'METHOD_NOT_ALLOWED',
                'message' => 'Only POST and GET methods are allowed'
            ],
            'timestamp' => date('c')
        ]);
        exit;
}

/**
 * Handle SBOM upload
 */
function handleSbomUpload() {
    global $db, $user, $unifiedAuth;
    
    // Check if file was uploaded
    if (!isset($_FILES['sbom_file']) || $_FILES['sbom_file']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'NO_FILE_UPLOADED',
                'message' => 'No SBOM file uploaded or upload error occurred'
            ],
            'timestamp' => date('c')
        ]);
        exit;
    }
    
    $uploadedFile = $_FILES['sbom_file'];
    $deviceId = $_POST['device_id'] ?? '';
    $format = $_POST['format'] ?? 'SPDX';
    $description = $_POST['description'] ?? '';
    
    // Validate required fields
    if (empty($deviceId)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'MISSING_DEVICE_ID',
                'message' => 'Device ID is required'
            ],
            'timestamp' => date('c')
        ]);
        exit;
    }
    
    // Validate SBOM format
    $allowedFormats = ['CycloneDX', 'SPDX', 'spdx-tag-value', 'JSON', 'XML'];
    if (!in_array($format, $allowedFormats)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_SBOM_FORMAT',
                'message' => 'Invalid SBOM format. Supported formats: ' . implode(', ', $allowedFormats)
            ],
            'timestamp' => date('c')
        ]);
        exit;
    }
    
    // Validate file size (max 100MB for SBOM files)
    $maxFileSize = 100 * 1024 * 1024; // 100MB
    if ($uploadedFile['size'] > $maxFileSize) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'FILE_TOO_LARGE',
                'message' => 'File size exceeds maximum allowed size of 100MB'
            ],
            'timestamp' => date('c')
        ]);
        exit;
    }
    
    // Verify device exists and user has access
    $device = $db->query(
        "SELECT device_id, device_name, manufacturer FROM medical_devices WHERE device_id = ?",
        [$deviceId]
    )->fetch();
    
    if (!$device) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'DEVICE_NOT_FOUND',
                'message' => 'Medical device not found'
            ],
            'timestamp' => date('c')
        ]);
        exit;
    }
    
    try {
        $result = processSbomFile($uploadedFile, $deviceId, $format, $description, $user['user_id']);
        
        echo json_encode([
            'success' => true,
            'data' => $result,
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        error_log("SBOM upload error: " . $e->getMessage());
        
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'SBOM_PROCESSING_ERROR',
                'message' => 'Failed to process SBOM file: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

/**
 * Handle SBOM retrieval
 */
function handleSbomRetrieval() {
    global $db, $user, $unifiedAuth;
    
    $deviceId = $_GET['device_id'] ?? '';
    $sbomId = $_GET['sbom_id'] ?? '';
    
    if (empty($deviceId) && empty($sbomId)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'MISSING_PARAMETERS',
                'message' => 'Either device_id or sbom_id is required'
            ],
            'timestamp' => date('c')
        ]);
        exit;
    }
    
    try {
        if (!empty($sbomId)) {
            // Get specific SBOM
            $sbom = $db->query(
                "SELECT s.*, d.device_name, d.manufacturer 
                 FROM sboms s 
                 JOIN medical_devices d ON s.device_id = d.device_id 
                 WHERE s.sbom_id = ?",
                [$sbomId]
            )->fetch();
            
            if (!$sbom) {
                http_response_code(404);
                echo json_encode([
                    'success' => false,
                    'error' => [
                        'code' => 'SBOM_NOT_FOUND',
                        'message' => 'SBOM not found'
                    ],
                    'timestamp' => date('c')
                ]);
                exit;
            }
            
            echo json_encode([
                'success' => true,
                'data' => $sbom,
                'timestamp' => date('c')
            ]);
        } else {
            // Get all SBOMs for device
            $sboms = $db->query(
                "SELECT s.*, d.device_name, d.manufacturer 
                 FROM sboms s 
                 JOIN medical_devices d ON s.device_id = d.device_id 
                 WHERE s.device_id = ? 
                 ORDER BY s.uploaded_at DESC",
                [$deviceId]
            )->fetchAll();
            
            echo json_encode([
                'success' => true,
                'data' => $sboms,
                'timestamp' => date('c')
            ]);
        }
        
    } catch (Exception $e) {
        error_log("SBOM retrieval error: " . $e->getMessage());
        
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'SBOM_RETRIEVAL_ERROR',
                'message' => 'Failed to retrieve SBOM data: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

/**
 * Process uploaded SBOM file
 */
function processSbomFile($file, $deviceId, $format, $description, $userId) {
    global $db;
    
    $filePath = $file['tmp_name'];
    $fileName = $file['name'];
    $fileSize = $file['size'];
    
    // Read file content
    $fileContent = file_get_contents($filePath);
    if ($fileContent === false) {
        throw new Exception("Cannot read uploaded file");
    }
    
    // Parse SBOM content based on format
    $parsedContent = parseSbomContent($fileContent, $format);
    
    // Generate unique SBOM ID
    $sbomId = $db->query("SELECT uuid_generate_v4()")->fetchColumn();
    
    // Store SBOM in database
    $db->query(
        "INSERT INTO sboms (
            sbom_id, device_id, format, content, file_name, file_size, 
            uploaded_by, uploaded_at, parsing_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'Success')",
        [
            $sbomId,
            $deviceId,
            $format,
            json_encode($parsedContent),
            $fileName,
            $fileSize,
            $userId
        ]
    );
    
    // Extract and store software components
    if (isset($parsedContent['components']) && is_array($parsedContent['components'])) {
        foreach ($parsedContent['components'] as $component) {
            $componentId = $db->query("SELECT uuid_generate_v4()")->fetchColumn();
            
            $db->query(
                "INSERT INTO software_components (
                    component_id, sbom_id, name, version, vendor, 
                    license, purl, cpe, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                [
                    $componentId,
                    $sbomId,
                    $component['name'] ?? '',
                    $component['version'] ?? '',
                    $component['vendor'] ?? '',
                    $component['license'] ?? null,
                    $component['purl'] ?? null,
                    $component['cpe'] ?? null
                ]
            );
        }
    }
    
    // Queue SBOM for evaluation
    $queueId = $db->query("SELECT uuid_generate_v4()")->fetchColumn();
    $db->query(
        "INSERT INTO sbom_evaluation_queue (
            queue_id, sbom_id, device_id, priority, status, 
            queued_by, queued_at
        ) VALUES (?, ?, ?, 5, 'Queued', ?, CURRENT_TIMESTAMP)",
        [$queueId, $sbomId, $deviceId, $userId]
    );
    
    return [
        'sbom_id' => $sbomId,
        'device_id' => $deviceId,
        'format' => $format,
        'file_name' => $fileName,
        'file_size' => $fileSize,
        'components_count' => count($parsedContent['components'] ?? []),
        'parsed_successfully' => true,
        'queued_for_evaluation' => true,
        'queue_id' => $queueId
    ];
}

/**
 * Parse SBOM content based on format
 */
function parseSbomContent($content, $format) {
    $data = json_decode($content, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Invalid JSON content");
    }
    
    switch ($format) {
        case 'SPDX':
        case 'spdx-tag-value':
            return parseSpdxSbom($data);
        case 'CycloneDX':
            return parseCycloneDxSbom($data);
        case 'JSON':
            return $data; // Already parsed JSON
        case 'XML':
            return parseXmlSbom($content);
        default:
            throw new Exception("Unsupported SBOM format: $format");
    }
}

/**
 * Parse SPDX SBOM format
 */
function parseSpdxSbom($data) {
    $result = [
        'document_info' => [],
        'packages' => [],
        'components' => []
    ];
    
    // Extract document information
    if (isset($data['documentInformation'])) {
        $result['document_info'] = $data['documentInformation'];
    }
    
    // Extract packages
    if (isset($data['packages']) && is_array($data['packages'])) {
        foreach ($data['packages'] as $package) {
            $component = [
                'name' => $package['name'] ?? '',
                'version' => $package['versionInfo'] ?? '',
                'vendor' => $package['supplier'] ?? '',
                'license' => $package['licenseDeclared'] ?? null,
                'purl' => $package['externalRefs'][0]['referenceLocator'] ?? null,
                'cpe' => $package['externalRefs'][1]['referenceLocator'] ?? null,
                'description' => $package['description'] ?? null
            ];
            
            $result['components'][] = $component;
        }
    }
    
    return $result;
}

/**
 * Parse CycloneDX SBOM format
 */
function parseCycloneDxSbom($data) {
    $result = [
        'bom_format' => $data['bomFormat'] ?? '',
        'spec_version' => $data['specVersion'] ?? '',
        'metadata' => $data['metadata'] ?? [],
        'components' => []
    ];
    
    // Extract components
    if (isset($data['components']) && is_array($data['components'])) {
        foreach ($data['components'] as $component) {
            $parsedComponent = [
                'name' => $component['name'] ?? '',
                'version' => $component['version'] ?? '',
                'vendor' => $component['publisher'] ?? '',
                'license' => $component['licenses'][0]['license']['id'] ?? null,
                'purl' => $component['purl'] ?? null,
                'cpe' => $component['cpe'] ?? null,
                'description' => $component['description'] ?? null
            ];
            
            $result['components'][] = $parsedComponent;
        }
    }
    
    return $result;
}

/**
 * Parse XML SBOM format
 */
function parseXmlSbom($content) {
    $xml = simplexml_load_string($content);
    if ($xml === false) {
        throw new Exception("Invalid XML content");
    }
    
    // Basic XML parsing - this would need to be enhanced based on specific XML format
    $result = [
        'format' => 'XML',
        'components' => []
    ];
    
    // This is a basic implementation - would need to be customized based on XML structure
    return $result;
}
?>
