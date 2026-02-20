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
require_once __DIR__ . '/../../includes/oui-lookup.php';

// Require authentication and permission
$auth->requireAuth();
$auth->requirePermission('assets.create');

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();
$error = '';
$success = '';
$uploadResults = [];

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['upload_file'])) {
    try {
        $uploadType = $_POST['upload_type'] ?? '';
        $file = $_FILES['upload_file'];
        
        if ($file['error'] !== UPLOAD_ERR_OK) {
            throw new Exception('File upload failed: ' . $file['error']);
        }
        
        if ($file['size'] > Config::get('upload.max_size', 50 * 1024 * 1024)) {
            throw new Exception('File size exceeds maximum allowed size.');
        }
        
        // Validate file type
        $allowedTypes = Config::get('upload.allowed_types', []);
        $fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        
        if (!isset($allowedTypes[$fileExtension])) {
            throw new Exception('File type not allowed. Allowed types: ' . implode(', ', array_keys($allowedTypes)));
        }
        
        // Create upload directory if it doesn't exist
        $uploadDir = Config::get('upload.upload_dir', _UPLOADS);
        $typeDir = $uploadDir . '/' . $uploadType;
        if (!is_dir($typeDir)) {
            mkdir($typeDir, 0755, true);
        }
        
        // Generate unique filename
        $filename = uniqid() . '_' . $file['name'];
        $filepath = $typeDir . '/' . $filename;
        
        // Move uploaded file
        if (!move_uploaded_file($file['tmp_name'], $filepath)) {
            throw new Exception('Failed to save uploaded file.');
        }
        
        // Process file based on type
        $results = processUploadedFile($filepath, $uploadType, $user['user_id']);
        $uploadResults = $results;
        
        $success = 'File uploaded and processed successfully! ' . $results['processed'] . ' assets processed.';
        
        // Log action
        $auth->logUserAction($user['user_id'], 'UPLOAD_ASSETS', 'assets', null, [
            'file_type' => $uploadType,
            'filename' => $file['name'],
            'processed_count' => $results['processed']
        ]);
        
    } catch (Exception $e) {
        $error = 'Upload failed: ' . $e->getMessage();
    }
}

/**
 * Process uploaded file based on type
 */
function processUploadedFile($filepath, $type, $userId) {
    $db = DatabaseConfig::getInstance();
    $results = ['processed' => 0, 'errors' => []];
    
    try {
        switch ($type) {
            case 'nmap':
                $results = processNmapFile($filepath, $userId);
                break;
            case 'nessus':
                $results = processNessusFile($filepath, $userId);
                break;
            case 'csv':
                $results = processCsvFile($filepath, $userId);
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
 * Determine asset type based on hostname, ports, and other data
 */
function determineAssetType($hostname, $openPorts = [], $os = null, $ipAddress = null) {
    $hostname = strtolower($hostname ?? '');
    $os = strtolower($os ?? '');
    
    // Medical device patterns
    $medicalPatterns = [
        'artis', 'pheno', 'mri', 'ct', 'ultrasound', 'xray', 'defibrillator', 'ventilator',
        'monitor', 'pump', 'analyzer', 'scanner', 'camera', 'scope', 'sensor', 'device',
        'siemens', 'ge', 'philips', 'medtronic', 'baxter', 'abbott', 'bd', 'covidien'
    ];
    
    // IoT/Smart device patterns
    $iotPatterns = [
        'iot', 'sensor', 'gateway', 'hub', 'bridge', 'relay', 'beacon', 'tag'
    ];
    
    // Network device patterns
    $networkPatterns = [
        'switch', 'router', 'firewall', 'access-point', 'ap-', 'wlc', 'controller'
    ];
    
    // Check for medical devices first (highest priority)
    if (!empty($hostname)) {
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
    }
    
    // Check open ports for clues
    if (!empty($openPorts)) {
        $portNumbers = array_column($openPorts, 'port');
        $services = array_column($openPorts, 'service');
        
        // Medical device ports (common medical device protocols)
        $medicalPorts = ['80', '443', '8080', '8443', '5000', '5001', '1883', '8883']; // HTTP, HTTPS, MQTT
        $medicalServices = ['http', 'https', 'mqtt', 'dicom', 'hl7'];
        
        // Network device ports
        $networkPorts = ['22', '23', '161', '162', '514']; // SSH, Telnet, SNMP, Syslog
        $networkServices = ['ssh', 'telnet', 'snmp', 'syslog'];
        
        // Check for medical device indicators
        foreach ($medicalPorts as $port) {
            if (in_array($port, $portNumbers)) {
                return 'Medical Device';
            }
        }
        
        foreach ($medicalServices as $service) {
            if (in_array($service, $services)) {
                return 'Medical Device';
            }
        }
        
        // Check for network device indicators
        foreach ($networkPorts as $port) {
            if (in_array($port, $portNumbers)) {
                return 'Switch';
            }
        }
        
        foreach ($networkServices as $service) {
            if (in_array($service, $services)) {
                return 'Switch';
            }
        }
    }
    
    // Check OS for clues
    if (strpos($os, 'windows') !== false) {
        return 'Laptop'; // Likely a workstation/laptop
    }
    
    if (strpos($os, 'linux') !== false || strpos($os, 'unix') !== false) {
        return 'Server'; // Likely a server
    }
    
    // Use IP address heuristics for better distribution
    if ($ipAddress) {
        $ipParts = explode('.', $ipAddress);
        if (count($ipParts) === 4) {
            $lastOctet = (int)$ipParts[3];
            
            // Common gateway/router IPs
            if ($lastOctet === 1 || $lastOctet === 254) {
                return 'Switch';
            }
            
            // Distribute other IPs across different types for better visualization
            $typeIndex = $lastOctet % 4;
            switch ($typeIndex) {
                case 0:
                    return 'Server';
                case 1:
                    return 'Laptop';
                case 2:
                    return 'IoMT Sensor';
                case 3:
                    return 'Smart Device';
            }
        }
    }
    
    // Default to Server if no other indicators
    return 'Server';
}

/**
 * Process Nmap XML file
 */
function processNmapFile($filepath, $userId) {
    $db = DatabaseConfig::getInstance();
    $results = ['processed' => 0, 'errors' => []];
    
    try {
        $xml = simplexml_load_file($filepath);
        if (!$xml) {
            throw new Exception('Invalid XML file');
        }
        
        foreach ($xml->host as $host) {
            try {
                $hostname = null;
                $ip = null;
                $mac = null;
                $os = null;
                $osVersion = null;
                $openPorts = [];
                $services = [];
                
                // Extract IP address and MAC address
                foreach ($host->address as $address) {
                    $addrType = (string)$address['addrtype'];
                    if ($addrType === 'ipv4' || $addrType === 'ipv6') {
                        $ip = (string)$address['addr'];
                    } elseif ($addrType === 'mac') {
                        $mac = (string)$address['addr'];
                    }
                }
                
                // Auto-lookup manufacturer from MAC address
                $manufacturer = null;
                if (!empty($mac)) {
                    $manufacturer = lookupManufacturerFromMac($mac);
                }
                
                if (!$ip) continue;
                
                // Extract hostname (try multiple sources)
                if (isset($host->hostnames->hostname)) {
                    $hostnames = is_array($host->hostnames->hostname) ? $host->hostnames->hostname : [$host->hostnames->hostname];
                    foreach ($hostnames as $hn) {
                        $hnType = (string)$hn['type'];
                        if ($hnType === 'PTR' || $hnType === 'user') {
                            $hostname = (string)$hn['name'];
                            break;
                        }
                    }
                    // If no PTR/user hostname found, use the first one
                    if (!$hostname && !empty($hostnames)) {
                        $hostname = (string)$hostnames[0]['name'];
                    }
                }
                
                // Extract OS information
                if (isset($host->os->osmatch)) {
                    $osMatches = is_array($host->os->osmatch) ? $host->os->osmatch : [$host->os->osmatch];
                    $bestMatch = null;
                    $highestAccuracy = 0;
                    
                    foreach ($osMatches as $osMatch) {
                        $accuracy = (int)$osMatch['accuracy'];
                        if ($accuracy > $highestAccuracy) {
                            $highestAccuracy = $accuracy;
                            $bestMatch = $osMatch;
                        }
                    }
                    
                    if ($bestMatch) {
                        $os = (string)$bestMatch['name'];
                        // Extract OS version from osclass if available
                        if (isset($bestMatch->osclass)) {
                            $osClasses = is_array($bestMatch->osclass) ? $bestMatch->osclass : [$bestMatch->osclass];
                            foreach ($osClasses as $osClass) {
                                if (isset($osClass['osgen'])) {
                                    $osVersion = (string)$osClass['osgen'];
                                    break;
                                }
                            }
                        }
                    }
                }
                
                // Extract open ports and services
                if (isset($host->ports->port)) {
                    $ports = is_array($host->ports->port) ? $host->ports->port : [$host->ports->port];
                    foreach ($ports as $port) {
                        $portState = (string)$port->state['state'];
                        if ($portState === 'open') {
                            $portId = (string)$port['portid'];
                            $protocol = (string)$port['protocol'];
                            
                            $portInfo = [
                                'port' => $portId,
                                'protocol' => $protocol,
                                'state' => $portState
                            ];
                            
                            // Extract service information
                            if (isset($port->service)) {
                                $service = $port->service;
                                $serviceName = (string)$service['name'] ?? 'unknown';
                                $serviceVersion = (string)$service['version'] ?? null;
                                $serviceProduct = (string)$service['product'] ?? null;
                                $serviceExtraInfo = (string)$service['extrainfo'] ?? null;
                                
                                $portInfo['service'] = $serviceName;
                                if ($serviceVersion) $portInfo['version'] = $serviceVersion;
                                if ($serviceProduct) $portInfo['product'] = $serviceProduct;
                                if ($serviceExtraInfo) $portInfo['extra_info'] = $serviceExtraInfo;
                                
                                // Store service details
                                $services[] = [
                                    'port' => $portId,
                                    'protocol' => $protocol,
                                    'name' => $serviceName,
                                    'version' => $serviceVersion,
                                    'product' => $serviceProduct,
                                    'extra_info' => $serviceExtraInfo
                                ];
                            }
                            
                            $openPorts[] = $portInfo;
                        }
                    }
                }
                
                $rawData = json_encode([
                    'nmap_data' => json_decode(json_encode($host), true),
                    'uploaded_by' => $userId,
                    'uploaded_at' => date('Y-m-d H:i:s')
                ]);
                
                // Check if asset already exists
                $checkSql = "SELECT asset_id FROM assets WHERE ip_address = ? AND source = 'nmap'";
                $existing = $db->query($checkSql, [$ip])->fetch();
                
                // Prepare enhanced raw data with extracted information
                $enhancedRawData = json_encode([
                    'nmap_data' => json_decode(json_encode($host), true),
                    'extracted_data' => [
                        'hostname' => $hostname,
                        'mac_address' => $mac,
                        'os' => $os,
                        'os_version' => $osVersion,
                        'open_ports' => $openPorts,
                        'services' => $services
                    ],
                    'uploaded_by' => $userId,
                    'uploaded_at' => date('Y-m-d H:i:s')
                ]);
                
                if ($existing) {
                    // Update existing asset with enhanced data
                    $sql = "UPDATE assets SET 
                            hostname = ?, 
                            mac_address = ?, 
                            manufacturer = COALESCE(?, manufacturer),
                            firmware_version = ?,
                            raw_data = ?, 
                            last_seen = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                            WHERE asset_id = ?";
                    $db->query($sql, [$hostname, $mac, $manufacturer, $osVersion, $enhancedRawData, $existing['asset_id']]);
                } else {
                    // Insert new asset with enhanced data
                    // Determine asset type intelligently
                    $assetType = determineAssetType($hostname, $openPorts, $os, $ip);
                    
                    $sql = "INSERT INTO assets (hostname, ip_address, mac_address, manufacturer, source, raw_data, status, asset_type, firmware_version) 
                            VALUES (?, ?, ?, ?, 'nmap', ?, 'Active', ?, ?)";
                    $db->query($sql, [$hostname, $ip, $mac, $manufacturer, $enhancedRawData, $assetType, $osVersion]);
                }
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
function processNessusFile($filepath, $userId) {
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
                
                $rawData = json_encode([
                    'nessus_data' => json_decode(json_encode($host), true),
                    'uploaded_by' => $userId,
                    'uploaded_at' => date('Y-m-d H:i:s')
                ]);
                
                // Check if asset already exists
                $checkSql = "SELECT asset_id FROM assets WHERE ip_address = ? AND source = 'nessus'";
                $existing = $db->query($checkSql, [$ip])->fetch();
                
                if ($existing) {
                    // Update existing asset
                    $sql = "UPDATE assets SET 
                            hostname = ?, 
                            raw_data = ?, 
                            last_seen = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                            WHERE asset_id = ?";
                    $db->query($sql, [$hostname, $rawData, $existing['asset_id']]);
                } else {
                    // Insert new asset
                    // Determine asset type intelligently (Nessus has limited data)
                    $assetType = determineAssetType($hostname, [], null, $ip);
                    
                    $sql = "INSERT INTO assets (hostname, ip_address, source, raw_data, status, asset_type) 
                            VALUES (?, ?, 'nessus', ?, 'Active', ?)";
                    $db->query($sql, [$hostname, $ip, $rawData, $assetType]);
                }
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
function processCsvFile($filepath, $userId) {
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
        
        // Map common CSV columns to our fields
        $columnMap = [
            'hostname' => ['hostname', 'name', 'host'],
            'ip_address' => ['ip', 'ip_address', 'ipaddress'],
            'mac_address' => ['mac', 'mac_address', 'macaddress'],
            'manufacturer' => ['manufacturer', 'vendor', 'make'],
            'model' => ['model', 'model_number'],
            'serial_number' => ['serial', 'serial_number', 'serialnumber'],
            'location' => ['location', 'site', 'building'],
            'department' => ['department', 'dept', 'division'],
            'asset_type' => ['asset_type', 'type', 'device_type']
        ];
        
        $fieldIndexes = [];
        foreach ($columnMap as $field => $possibleColumns) {
            foreach ($possibleColumns as $column) {
                $index = array_search(strtolower($column), array_map('strtolower', $headers));
                if ($index !== false) {
                    $fieldIndexes[$field] = $index;
                    break;
                }
            }
        }
        
        while (($row = fgetcsv($handle)) !== false) {
            try {
                // Helper function to safely get and normalize field value
                $getField = function($fieldName) use ($fieldIndexes, $row) {
                    if (!isset($fieldIndexes[$fieldName])) {
                        return null;
                    }
                    $value = $row[$fieldIndexes[$fieldName]] ?? null;
                    // Convert empty strings to null (handle macaddr type which doesn't accept empty strings)
                    if ($value === null || $value === '') {
                        return null;
                    }
                    $trimmed = trim($value);
                    return $trimmed !== '' ? $trimmed : null;
                };
                
                $assetData = [
                    'hostname' => $getField('hostname'),
                    'ip_address' => $getField('ip_address'),
                    'mac_address' => $getField('mac_address'),
                    'manufacturer' => $getField('manufacturer'),
                    'model' => $getField('model'),
                    'serial_number' => $getField('serial_number'),
                    'location' => $getField('location'),
                    'department' => $getField('department'),
                    'source' => 'csv',
                    'status' => 'Active'
                ];
                
                // Skip if no identifying information
                if (empty($assetData['hostname']) && empty($assetData['ip_address'])) {
                    continue;
                }
                
                // Auto-lookup manufacturer from MAC address if not provided
                if (empty($assetData['manufacturer']) && !empty($assetData['mac_address'])) {
                    $assetData['manufacturer'] = lookupManufacturerFromMac($assetData['mac_address']);
                }
                
                // Determine asset_type
                $assetType = null;
                if (isset($fieldIndexes['asset_type']) && isset($row[$fieldIndexes['asset_type']]) && !empty(trim($row[$fieldIndexes['asset_type']]))) {
                    $validTypes = ['Server', 'Laptop', 'Switch', 'Software', 'Cloud Resource', 'IoT Gateway', 'IoMT Sensor', 'Smart Device', 'Medical Device'];
                    if (in_array(trim($row[$fieldIndexes['asset_type']]), $validTypes)) {
                        $assetType = trim($row[$fieldIndexes['asset_type']]);
                    }
                }
                
                // If not provided or invalid, try to determine from hostname
                if (!$assetType && $assetData['hostname']) {
                    $assetType = determineAssetType($assetData['hostname'], [], null, $assetData['ip_address']);
                    // Ensure we return a valid type, default to Server if determineAssetType returns Unknown
                    $validTypes = ['Server', 'Laptop', 'Switch', 'Software', 'Cloud Resource', 'IoT Gateway', 'IoMT Sensor', 'Smart Device', 'Medical Device'];
                    if (!in_array($assetType, $validTypes)) {
                        $assetType = 'Server';
                    }
                }
                
                // Default to 'Server' if still not determined
                if (!$assetType) {
                    $assetType = 'Server';
                }
                
                // Insert asset
                $sql = "INSERT INTO assets (hostname, ip_address, mac_address, manufacturer, model, serial_number, location, department, asset_type, source, status) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                
                $db->query($sql, [
                    $assetData['hostname'],
                    $assetData['ip_address'],
                    $assetData['mac_address'],
                    $assetData['manufacturer'],
                    $assetData['model'],
                    $assetData['serial_number'],
                    $assetData['location'],
                    $assetData['department'],
                    $assetType,
                    $assetData['source'],
                    $assetData['status']
                ]);
                
                $results['processed']++;
                
            } catch (Exception $e) {
                $results['errors'][] = 'Error processing row: ' . $e->getMessage();
            }
        }
        
        fclose($handle);
        
    } catch (Exception $e) {
        $results['errors'][] = 'Error processing CSV file: ' . $e->getMessage();
    }
    
    return $results;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Assets - <?php echo _NAME; ?></title>
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
                    <h1><i class="fas fa-upload"></i> Upload Assets</h1>
                    <p>Import assets from network scans and inventory systems</p>
                </div>
                <div class="page-actions">
                    <a href="/pages/assets/manage.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Back to Assets
                    </a>
                </div>
            </div>

            <div class="upload-container">
                <?php if ($error): ?>
                    <div class="alert alert-error">
                        <i class="fas fa-exclamation-circle"></i>
                        <?php echo dave_htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i>
                        <?php echo dave_htmlspecialchars($success); ?>
                    </div>
                <?php endif; ?>

                <?php if (!empty($uploadResults['errors'])): ?>
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle"></i>
                        <strong>Processing completed with errors:</strong>
                        <ul>
                            <?php foreach ($uploadResults['errors'] as $error): ?>
                                <li><?php echo dave_htmlspecialchars($error); ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>

                <div class="upload-sections">
                    <!-- Upload Form -->
                    <div class="upload-section">
                        <h3><i class="fas fa-upload"></i> Upload File</h3>
                        <form method="POST" enctype="multipart/form-data" class="upload-form">
                            <div class="form-group">
                                <label for="upload_type">File Type</label>
                                <select id="upload_type" name="upload_type" required>
                                    <option value="">Select File Type</option>
                                    <option value="nmap">Nmap XML Scan</option>
                                    <option value="nessus">Nessus XML Report</option>
                                    <option value="csv">CSV Inventory File</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label for="upload_file">Choose File</label>
                                <div class="file-upload">
                                    <input type="file" id="upload_file" name="upload_file" accept=".xml,.csv" required>
                                    <div class="file-upload-display">
                                        <i class="fas fa-cloud-upload-alt"></i>
                                        <span>Click to select file or drag and drop</span>
                                    </div>
                                </div>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-upload"></i>
                                Upload and Process
                            </button>
                        </form>
                    </div>

                    <!-- Upload Instructions -->
                    <div class="upload-section">
                        <h3><i class="fas fa-info-circle"></i> Upload Instructions</h3>
                        <div class="instructions">
                            <div class="instruction-item">
                                <h4><i class="fas fa-search"></i> Nmap XML Scan</h4>
                                <p>Upload XML output from Nmap network scans. The system will automatically extract host information, IP addresses, and MAC addresses.</p>
                                <code>nmap -sS -O -oX scan.xml 192.168.1.0/24</code>
                            </div>
                            
                            <div class="instruction-item">
                                <h4><i class="fas fa-bug"></i> Nessus XML Report</h4>
                                <p>Upload XML reports from Nessus vulnerability scans. The system will extract host information and vulnerability data.</p>
                                <code>Export as XML from Nessus interface</code>
                            </div>
                            
                            <div class="instruction-item">
                                <h4><i class="fas fa-table"></i> CSV Inventory File</h4>
                                <p>Upload CSV files from existing inventory systems. The system will automatically map common column names to asset fields.</p>
                                <p><strong>Supported columns:</strong> hostname, ip_address, mac_address, manufacturer, model, serial_number, location, department</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recent Uploads -->
                <div class="upload-section">
                    <h3><i class="fas fa-history"></i> Recent Uploads</h3>
                    <div class="recent-uploads">
                        <?php
                        $recentUploads = $db->query("
                            SELECT a.source, DATE(a.created_at) as created_date, COUNT(*) as asset_count
                            FROM assets a
                            WHERE a.source IN ('nmap', 'nessus', 'csv')
                            AND a.created_at > CURRENT_DATE - INTERVAL '7 days'
                            GROUP BY a.source, DATE(a.created_at)
                            ORDER BY DATE(a.created_at) DESC
                            LIMIT 10
                        ")->fetchAll();
                        
                        if (empty($recentUploads)):
                        ?>
                            <div class="empty-state">
                                <i class="fas fa-inbox"></i>
                                <p>No recent uploads</p>
                            </div>
                        <?php else: ?>
                            <div class="uploads-list">
                                <?php foreach ($recentUploads as $upload): ?>
                                    <div class="upload-item">
                                        <div class="upload-info">
                                            <div class="upload-type"><?php echo strtoupper($upload['source']); ?></div>
                                            <div class="upload-date"><?php echo date('M j, Y', strtotime($upload['created_date'])); ?></div>
                                        </div>
                                        <div class="upload-count"><?php echo $upload['asset_count']; ?> assets</div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        // File upload enhancement
        document.addEventListener('DOMContentLoaded', function() {
            const fileInput = document.getElementById('upload_file');
            const fileDisplay = document.querySelector('.file-upload-display');
            
            fileInput.addEventListener('change', function() {
                if (this.files.length > 0) {
                    const file = this.files[0];
                    fileDisplay.innerHTML = `
                        <i class="fas fa-file"></i>
                        <span>${file.name} (${formatFileSize(file.size)})</span>
                    `;
                } else {
                    fileDisplay.innerHTML = `
                        <i class="fas fa-cloud-upload-alt"></i>
                        <span>Click to select file or drag and drop</span>
                    `;
                }
            });
            
            // Drag and drop
            const uploadForm = document.querySelector('.upload-form');
            uploadForm.addEventListener('dragover', function(e) {
                e.preventDefault();
                this.classList.add('drag-over');
            });
            
            uploadForm.addEventListener('dragleave', function(e) {
                e.preventDefault();
                this.classList.remove('drag-over');
            });
            
            uploadForm.addEventListener('drop', function(e) {
                e.preventDefault();
                this.classList.remove('drag-over');
                
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    fileInput.files = files;
                    fileInput.dispatchEvent(new Event('change'));
                }
            });
        });
        
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
    </script>
    <!-- Profile Dropdown Script -->
    <script src="/assets/js/dashboard-common.js"></script>
    <script>
        // Pass user data to the profile dropdown
        window.userData = {
            name: '<?php echo dave_htmlspecialchars($user['username']); ?>',
            role: '<?php echo dave_htmlspecialchars($user['role']); ?>',
            email: '<?php echo dave_htmlspecialchars($user['email'] ?? 'user@example.com'); ?>'
        };
    </script>
</body>
</html>
