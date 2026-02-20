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
require_once __DIR__ . '/../../includes/version-comparison.php';

// Require authentication and permission
$auth->requireAuth();
$auth->requirePermission('vulnerabilities.manage');

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
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['sbom_file'])) {
    try {
        $deviceId = $_POST['device_id'] ?? '';
        $file = $_FILES['sbom_file'];
        
        if (empty($deviceId)) {
            throw new Exception('Device selection is required');
        }
        
        if ($file['error'] !== UPLOAD_ERR_OK) {
            throw new Exception('File upload failed: ' . $file['error']);
        }
        
        if ($file['size'] > Config::get('upload.max_size', 50 * 1024 * 1024)) {
            throw new Exception('File size exceeds maximum allowed size.');
        }
        
        // Validate file type
        $allowedTypes = ['xml', 'json', 'txt', 'spdx'];
        $fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        
        // Special handling for SPDX files that might have .spdx.json extension
        $filename = strtolower($file['name']);
        $isSpdxFile = $fileExtension === 'spdx' || 
                      $fileExtension === 'json' && (strpos($filename, '.spdx.') !== false || strpos($filename, 'spdx') !== false);
        
        if (!in_array($fileExtension, $allowedTypes) && !$isSpdxFile) {
            throw new Exception('File type not allowed. Allowed types: ' . implode(', ', $allowedTypes) . ', .spdx, .spdx.json');
        }
        
        // Create upload directory if it doesn't exist
        $uploadDir = Config::get('upload.upload_dir', _UPLOADS);
        $sbomDir = $uploadDir . '/sbom';
        if (!is_dir($sbomDir)) {
            mkdir($sbomDir, 0755, true);
        }
        
        // Generate unique filename
        $filename = uniqid() . '_' . $file['name'];
        $filepath = $sbomDir . '/' . $filename;
        
        // Move uploaded file
        if (!move_uploaded_file($file['tmp_name'], $filepath)) {
            throw new Exception('Failed to save uploaded file.');
        }
        
        // Process SBOM file
        $results = processSBOMFile($filepath, $deviceId, $user['user_id']);
        $uploadResults = $results;
        
        if ($results['success']) {
            $success = 'SBOM file uploaded and processed successfully! ' . $results['components_processed'] . ' components processed.';
            
            if ($results['cves_auto_closed'] > 0) {
                $success .= ' <strong>' . $results['cves_auto_closed'] . ' CVE(s) automatically resolved</strong> due to software version updates.';
            }
            
            if ($results['version_changes_detected'] > 0) {
                $success .= ' Detected ' . $results['version_changes_detected'] . ' software version change(s).';
            }
            
            $success .= ' Vulnerability evaluation has been queued and will run automatically in the background.';
        } else {
            $error = 'SBOM processing failed: ' . $results['error'];
        }
        
        // Log action
        $auth->logUserAction($user['user_id'], 'UPLOAD_SBOM', 'sboms', $deviceId, [
            'filename' => $file['name'],
            'components_processed' => $results['components_processed']
        ]);
        
    } catch (Exception $e) {
        // Log the full error for debugging
        error_log("SBOM Upload Error: " . $e->getMessage() . "\nStack Trace: " . $e->getTraceAsString());
        
        // Provide user-friendly error message
        $error = 'Upload failed: ' . $e->getMessage();
        
        // If it's a database error, provide more specific guidance
        if (strpos($e->getMessage(), 'Database') !== false) {
            $error .= ' Please check your database connection and try again.';
        }
    }
}

/**
 * Process SBOM file using Python service
 */
function processSBOMFile($filepath, $deviceId, $userId) {
    try {
        // Call Python SBOM parser with better error handling
        $command = "cd /var/www/html && python3 python/services/sbom_parser.py '$filepath'";
        $output = shell_exec($command . ' 2>&1');
        
        // Check if command executed successfully
        if ($output === null) {
            throw new Exception("Failed to execute Python SBOM parser. Please check if Python 3 is installed and the parser script exists.");
        }
        
        // Check for Python errors in output
        if (strpos($output, 'Traceback') !== false || strpos($output, 'Error') !== false) {
            error_log("Python SBOM Parser Error: " . $output);
            throw new Exception("Python SBOM parser encountered an error. Please check the server logs for details.");
        }
        
        $sbomData = json_decode($output, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $error = json_last_error_msg();
            error_log("JSON Decode Error: $error. Python Output: " . $output);
            throw new Exception("Failed to parse SBOM file. JSON Error: $error. The SBOM file may be corrupted or in an unsupported format.");
        }
        
        if (!$sbomData['success']) {
            throw new Exception("SBOM parsing failed: " . $sbomData['error']);
        }
        
        // Store SBOM in database with error handling
        try {
            $db = DatabaseConfig::getInstance();
            $db->beginTransaction();
        } catch (Exception $dbError) {
            throw new Exception("Database connection failed: " . $dbError->getMessage());
        }
        
        // Check if this is a mapped device or just an asset
        $actualDeviceId = null;
        $actualAssetId = null;
        $isMappedDevice = false;
        
        try {
            // First, check if the provided ID is a device_id in medical_devices
            $deviceCheckSql = "SELECT md.device_id, md.asset_id 
                              FROM medical_devices md 
                              WHERE md.device_id = ?";
            $deviceCheckStmt = $db->prepare($deviceCheckSql);
            $deviceCheckStmt->execute([$deviceId]);
            $mappedDevice = $deviceCheckStmt->fetch(PDO::FETCH_ASSOC);
            
            if ($mappedDevice) {
                // It's a mapped device
                $isMappedDevice = true;
                $actualDeviceId = $mappedDevice['device_id'];
                $actualAssetId = $mappedDevice['asset_id'];
            } else {
                // Not found as device_id, check if it's an asset_id
                $assetCheckSql = "SELECT asset_id FROM assets WHERE asset_id = ?";
                $assetCheckStmt = $db->prepare($assetCheckSql);
                $assetCheckStmt->execute([$deviceId]);
                $asset = $assetCheckStmt->fetch(PDO::FETCH_ASSOC);
                
                if ($asset) {
                    // It's an unmapped asset
                    $isMappedDevice = false;
                    $actualDeviceId = null; // No device_id for unmapped assets
                    $actualAssetId = $asset['asset_id'];
                } else {
                    throw new Exception("Invalid device/asset ID provided");
                }
            }
        } catch (Exception $queryError) {
            throw new Exception("Database query failed while checking device mapping: " . $queryError->getMessage());
        }
        
        try {
            // Insert SBOM with proper device_id and asset_id handling
            $sql = "INSERT INTO sboms (device_id, asset_id, format, content, file_name, file_size, uploaded_by, parsing_status) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING sbom_id";
            
            $stmt = $db->prepare($sql);
            $stmt->execute([
                $actualDeviceId,  // NULL for unmapped assets
                $actualAssetId,   // Always populated
                $sbomData['format'],
                json_encode($sbomData),
                basename($filepath),
                filesize($filepath),
                $userId,
                'Success'
            ]);
            
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$result) {
                throw new Exception("Failed to insert SBOM record into database");
            }
            $sbomId = $result['sbom_id'];
        } catch (Exception $insertError) {
            throw new Exception("Database insertion failed: " . $insertError->getMessage());
        }
        
        // Store software components and detect version changes
        $componentsProcessed = 0;
        $versionChanges = [];
        
        foreach ($sbomData['components'] as $component) {
            try {
                // Check for existing component with different version
                // Use asset_id for comparison since both mapped and unmapped devices have it
                $existingCompSql = "SELECT sc.component_id, sc.version, sc.name, sc.vendor
                                   FROM software_components sc
                                   JOIN sboms s ON sc.sbom_id = s.sbom_id
                                   WHERE s.asset_id = ?
                                     AND sc.name = ?
                                     AND sc.vendor = ?
                                   ORDER BY s.uploaded_at DESC
                                   LIMIT 1";
                
                $existingStmt = $db->prepare($existingCompSql);
                $existingStmt->execute([
                    $actualAssetId,
                    $component['name'],
                    $component['vendor'] ?? ''
                ]);
                $existingComponent = $existingStmt->fetch(PDO::FETCH_ASSOC);
                
                // Store new component
                $compSql = "INSERT INTO software_components (sbom_id, name, version, vendor, license, purl, cpe) 
                           VALUES (?, ?, ?, ?, ?, ?, ?)";
                
                $compStmt = $db->prepare($compSql);
                $compStmt->execute([
                    $sbomId,
                    $component['name'],
                    $component['version'],
                    $component['vendor'],
                    $component['license'],
                    $component['purl'],
                    $component['cpe']
                ]);
                
                $componentsProcessed++;
            } catch (Exception $componentError) {
                error_log("Error processing component: " . $component['name'] . " - " . $componentError->getMessage());
                // Continue processing other components even if one fails
                continue;
            }
            
            // If version changed, track it for automatic CVE resolution
            if ($existingComponent && $existingComponent['version'] !== $component['version']) {
                $versionChanges[] = [
                    'name' => $component['name'],
                    'vendor' => $component['vendor'] ?? '',
                    'old_version' => $existingComponent['version'],
                    'new_version' => $component['version']
                ];
            }
        }
        
        // Process automatic CVE resolution for version changes
        $totalCvesAutoClosed = 0;
        $autoClosureDetails = [];
        
        foreach ($versionChanges as $change) {
            // Find the package in software_packages
            $pkgSql = "SELECT package_id FROM software_packages 
                      WHERE name = ? AND (vendor = ? OR (vendor IS NULL AND ? = ''))";
            $pkgStmt = $db->prepare($pkgSql);
            $pkgStmt->execute([
                $change['name'],
                $change['vendor'],
                $change['vendor']
            ]);
            $package = $pkgStmt->fetch(PDO::FETCH_ASSOC);
            
            if ($package) {
                // We already have actualAssetId from above, so just use it
                if ($actualAssetId) {
                    // Call automatic CVE closure
                    $closureResult = autoCloseResolvedVulnerabilities(
                        $actualAssetId,
                        $package['package_id'],
                        $change['old_version'],
                        $change['new_version'],
                        $userId,
                        'SBOM Upload'
                    );
                    
                    if ($closureResult['success'] && $closureResult['closed_count'] > 0) {
                        $totalCvesAutoClosed += $closureResult['closed_count'];
                        $autoClosureDetails[] = [
                            'package' => $change['name'],
                            'old_version' => $change['old_version'],
                            'new_version' => $change['new_version'],
                            'cves_closed' => $closureResult['closed_count'],
                            'cve_ids' => $closureResult['cves']
                        ];
                    }
                }
            }
        }
        
        // Process SBOM evaluation asynchronously (no service required)
        try {
            // Start async evaluation process with proper device and asset IDs
            $deviceParam = $actualDeviceId ? "--device-id=$actualDeviceId" : "";
            $assetParam = $actualAssetId ? "--asset-id=$actualAssetId" : "";
            $command = "cd /var/www/html && /usr/bin/php /var/www/html/services/async_sbom_processor.php --sbom-id=$sbomId $deviceParam $assetParam --user-id=$userId > /dev/null 2>&1 &";
            exec($command);
            
            error_log("Started async SBOM evaluation for SBOM: $sbomId (Device: " . ($actualDeviceId ?? 'null') . ", Asset: $actualAssetId)");
        } catch (Exception $asyncError) {
            error_log("Failed to start async SBOM evaluation: " . $asyncError->getMessage());
            // Don't fail the entire operation if async processing fails
        }
        
        try {
            $db->commit();
        } catch (Exception $commitError) {
            throw new Exception("Failed to commit database transaction: " . $commitError->getMessage());
        }
        
        return [
            'success' => true,
            'components_processed' => $componentsProcessed,
            'sbom_id' => $sbomId,
            'queued_for_evaluation' => true,
            'version_changes_detected' => count($versionChanges),
            'cves_auto_closed' => $totalCvesAutoClosed,
            'auto_closure_details' => $autoClosureDetails
        ];
        
    } catch (Exception $e) {
        // Log the full error for debugging
        error_log("SBOM Processing Error: " . $e->getMessage() . "\nStack Trace: " . $e->getTraceAsString());
        
        // Rollback database transaction if it exists
        if (isset($db)) {
            try {
                $db->rollback();
            } catch (Exception $rollbackError) {
                error_log("Database rollback failed: " . $rollbackError->getMessage());
            }
        }
        
        // Provide user-friendly error message
        $errorMessage = $e->getMessage();
        
        // Add specific guidance based on error type
        if (strpos($errorMessage, 'Database') !== false) {
            $errorMessage .= ' Please check your database connection and try again.';
        } elseif (strpos($errorMessage, 'JSON') !== false) {
            $errorMessage .= ' The SBOM file may be corrupted or in an unsupported format.';
        } elseif (strpos($errorMessage, 'Python') !== false) {
            $errorMessage .= ' The SBOM parser service is unavailable. Please contact the administrator.';
        }
        
        return [
            'success' => false,
            'error' => $errorMessage,
            'components_processed' => 0
        ];
    }
}

// Get device_id from URL parameter
$selectedDeviceId = $_GET['device_id'] ?? '';


// Get devices for dropdown - show all active assets, not just mapped ones
$sql = "SELECT 
            COALESCE(md.device_id, a.asset_id) as device_id,
            TRIM(a.hostname) as hostname, 
            TRIM(a.asset_tag) as asset_tag,
            NULLIF(TRIM(md.brand_name), '') as brand_name, 
            COALESCE(md.model_number, 'N/A') as model_number, 
            NULLIF(TRIM(md.device_name), '') as device_name,
            a.asset_id,
            CASE 
                WHEN md.device_id IS NOT NULL THEN 'Mapped'
                ELSE 'Unmapped'
            END as mapping_status
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        WHERE a.status = 'Active'
        ORDER BY COALESCE(NULLIF(TRIM(a.hostname), ''), NULLIF(TRIM(md.brand_name), ''), NULLIF(TRIM(md.device_name), ''), TRIM(a.asset_tag))";
$stmt = $db->query($sql);
$devices = $stmt->fetchAll();

// If device_id is provided, try to find the corresponding device
$preSelectedDevice = null;
if (!empty($selectedDeviceId)) {
    // First, check if the selectedDeviceId is actually an asset_id
    // and if so, find the corresponding device_id for mapped devices
    $assetToDeviceSql = "SELECT md.device_id 
                        FROM medical_devices md 
                        WHERE md.asset_id = ?";
    $assetToDeviceStmt = $db->prepare($assetToDeviceSql);
    $assetToDeviceStmt->execute([$selectedDeviceId]);
    $mappedDeviceId = $assetToDeviceStmt->fetch(PDO::FETCH_ASSOC);
    
    // Use the mapped device_id if found, otherwise use the original selectedDeviceId
    $actualSelectedId = $mappedDeviceId ? $mappedDeviceId['device_id'] : $selectedDeviceId;
    
    // Now find the device in our devices list
    foreach ($devices as $device) {
        if ($device['device_id'] === $actualSelectedId) {
            $preSelectedDevice = $device;
            break;
        }
    }
}

// Get recent SBOM uploads - handle both mapped and unmapped devices
$sql = "SELECT s.sbom_id, s.file_name, s.format, s.uploaded_at, s.parsing_status,
               a.hostname, 
               COALESCE(md.brand_name, 'Unmapped Device') as brand_name, 
               COALESCE(md.model_number, 'N/A') as model_number,
               COUNT(sc.component_id) as component_count,
               CASE 
                   WHEN s.device_id IS NOT NULL THEN 'Mapped'
                   ELSE 'Unmapped'
               END as device_status
        FROM sboms s
        LEFT JOIN medical_devices md ON s.device_id = md.device_id
        JOIN assets a ON s.asset_id = a.asset_id
        LEFT JOIN software_components sc ON s.sbom_id = sc.sbom_id
        GROUP BY s.sbom_id, s.file_name, s.format, s.uploaded_at, s.parsing_status, 
                 a.hostname, md.brand_name, md.model_number
        ORDER BY s.uploaded_at DESC
        LIMIT 10";
$stmt = $db->query($sql);
$recentUploads = $stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload SBOM - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/vulnerabilities.css">
    <link rel="stylesheet" href="/assets/css/sbom-upload.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <header class="dashboard-header">
            <div class="header-left">
                <div class="logo">
                    <i class="fas fa-shield-alt"></i>
                    <span><?php echo _NAME; ?></span>
                </div>
            </div>
            <div class="header-right">
                <div class="user-info">
                    <span class="user-name"><?php echo dave_htmlspecialchars($user['username']); ?></span>
                    <span class="user-role"><?php echo dave_htmlspecialchars($user['role']); ?></span>
                </div>
                <a href="/pages/logout.php" class="logout-btn">
                    <i class="fas fa-sign-out-alt"></i>
                    Logout
                </a>
            </div>
        </header>

        <!-- Navigation -->
        <nav class="dashboard-nav">
            <a href="/pages/dashboard.php" class="nav-item">
                <i class="fas fa-tachometer-alt"></i>
                Dashboard
            </a>
            <a href="/pages/assets/manage.php" class="nav-item">
                <i class="fas fa-server"></i>
                Assets
            </a>
            <a href="/pages/recalls/dashboard.php" class="nav-item">
                <i class="fas fa-exclamation-triangle"></i>
                Recalls
            </a>
            <a href="/pages/vulnerabilities/dashboard.php" class="nav-item active">
                <i class="fas fa-bug"></i>
                Vulnerabilities
            </a>
            <a href="/pages/reports/generate.php" class="nav-item">
                <i class="fas fa-chart-bar"></i>
                Reports
            </a>
        </nav>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-upload"></i> Upload SBOM</h1>
                    <p>Upload Software Bill of Materials for vulnerability analysis</p>
                </div>
                <div class="page-actions">
                    <a href="/pages/vulnerabilities/dashboard.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Back to Vulnerabilities
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
                        <h3><i class="fas fa-upload"></i> Upload SBOM File</h3>
                        <form method="POST" enctype="multipart/form-data" class="upload-form">
                            <div class="form-group">
                                <label for="device_id">Select Device *</label>
                                <select id="device_id" name="device_id" required class="device-select">
                                    <option value="">Search for a device...</option>
                                    <?php foreach ($devices as $device): ?>
                                        <option value="<?php echo dave_htmlspecialchars($device['device_id']); ?>" 
                                                <?php echo ($preSelectedDevice && $preSelectedDevice['device_id'] === $device['device_id']) ? 'selected' : ''; ?>
                                                data-hostname="<?php echo dave_htmlspecialchars($device['hostname'] ?? ''); ?>"
                                                data-asset-tag="<?php echo dave_htmlspecialchars($device['asset_tag'] ?? ''); ?>"
                                                data-brand="<?php echo dave_htmlspecialchars($device['brand_name'] ?? ''); ?>"
                                                data-model="<?php echo dave_htmlspecialchars($device['model_number'] ?? ''); ?>"
                                                data-device-name="<?php echo dave_htmlspecialchars($device['device_name'] ?? ''); ?>"
                                                data-status="<?php echo dave_htmlspecialchars($device['mapping_status']); ?>">
                                            <?php 
                                            // Match assets table: hostname → brand_name → device_name → asset_tag (trim and ignore placeholders)
                                            $hostname = trim($device['hostname'] ?? '');
                                            $brand = trim($device['brand_name'] ?? '');
                                            $devName = trim($device['device_name'] ?? '');
                                            $assetTag = trim($device['asset_tag'] ?? '');
                                            // Guard against legacy placeholder values
                                            if (strcasecmp($brand, 'Unmapped Device') === 0) { $brand = ''; }
                                            $displayName = $hostname ?: $brand ?: $devName ?: $assetTag ?: 'Unknown Device';
                                            $deviceInfo = '';
                                            
                                            if ($device['mapping_status'] === 'Mapped') {
                                                $deviceInfo = $device['brand_name'] . ' ' . $device['model_number'];
                                            } else {
                                                $deviceInfo = 'Unmapped Device';
                                            }
                                            
                                            $statusIndicator = $device['mapping_status'] === 'Mapped' ? '✓' : '○';
                                            echo dave_htmlspecialchars($statusIndicator . ' ' . $displayName . ' - ' . $deviceInfo);
                                            ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                <?php if ($preSelectedDevice): ?>
                    <div class="form-help">
                        <i class="fas fa-info-circle"></i>
                        Device pre-selected from asset details: <?php echo dave_htmlspecialchars($preSelectedDevice['hostname'] ?: $preSelectedDevice['asset_tag']); ?> 
                        (<?php echo $preSelectedDevice['mapping_status']; ?>)
                    </div>
                <?php else: ?>
                    <div class="form-help">
                        <i class="fas fa-exclamation-triangle"></i>
                        No device pre-selected. Please select a device from the dropdown.
                    </div>
                <?php endif; ?>
                
                            </div>
                            
                            <div class="form-group">
                                <label for="sbom_file">Choose SBOM File *</label>
                                <div class="file-upload">
                                    <input type="file" id="sbom_file" name="sbom_file" accept=".xml,.json,.txt" required>
                                    <div class="file-upload-display">
                                        <i class="fas fa-cloud-upload-alt"></i>
                                        <span>Click to select SBOM file or drag and drop</span>
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
                        <h3><i class="fas fa-info-circle"></i> SBOM Upload Instructions</h3>
                        <div class="instructions">
                            <div class="instruction-item">
                                <h4><i class="fas fa-file-code"></i> Supported Formats</h4>
                                <ul>
                                    <li><strong>CycloneDX:</strong> JSON format with bomFormat: "CycloneDX" (.json)</li>
                                    <li><strong>SPDX:</strong> SPDX format files (.spdx, .spdx.json)</li>
                                    <li><strong>Generic JSON:</strong> Any JSON with components array (.json)</li>
                                    <li><strong>XML:</strong> XML files with component information (.xml)</li>
                                    <li><strong>Text:</strong> Plain text files (.txt)</li>
                                </ul>
                            </div>
                            
                            <div class="instruction-item">
                                <h4><i class="fas fa-cogs"></i> Processing</h4>
                                <p>The system will automatically:</p>
                                <ul>
                                    <li>Parse the SBOM file and extract software components</li>
                                    <li>Store component information in the database</li>
                                    <li>Enable vulnerability scanning for the device</li>
                                    <li>Link components to the selected device</li>
                                </ul>
                            </div>
                            
                            <div class="instruction-item">
                                <h4><i class="fas fa-shield-alt"></i> Security Benefits</h4>
                                <p>After uploading an SBOM, you can:</p>
                                <ul>
                                    <li>Scan for known vulnerabilities in software components</li>
                                    <li>Track component versions and dependencies</li>
                                    <li>Monitor for new vulnerabilities affecting your devices</li>
                                    <li>Generate compliance reports</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recent Uploads -->
                <div class="upload-section">
                    <h3><i class="fas fa-history"></i> Recent SBOM Uploads</h3>
                    <div class="recent-uploads">
                        <?php if (empty($recentUploads)): ?>
                            <div class="empty-state">
                                <i class="fas fa-inbox"></i>
                                <p>No recent SBOM uploads</p>
                            </div>
                        <?php else: ?>
                            <div class="uploads-list">
                                <?php foreach ($recentUploads as $upload): ?>
                                    <div class="upload-item">
                                        <div class="upload-info">
                                            <div class="upload-file"><?php echo dave_htmlspecialchars($upload['file_name']); ?></div>
                                            <div class="upload-device">
                                                <?php echo dave_htmlspecialchars($upload['hostname'] ?: $upload['brand_name']); ?> - 
                                                <?php echo dave_htmlspecialchars($upload['brand_name']); ?> 
                                                <?php echo dave_htmlspecialchars($upload['model_number']); ?>
                                            </div>
                                            <div class="upload-meta">
                                                <?php echo strtoupper($upload['format']); ?> • 
                                                <?php echo $upload['component_count']; ?> components • 
                                                <?php echo date('M j, Y g:i A', strtotime($upload['uploaded_at'])); ?>
                                            </div>
                                        </div>
                                        <div class="upload-status">
                                            <span class="status-badge <?php echo strtolower($upload['parsing_status']); ?>">
                                                <?php echo $upload['parsing_status']; ?>
                                            </span>
                                        </div>
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
        // SBOM Upload JavaScript
        document.addEventListener('DOMContentLoaded', function() {
            const fileInput = document.getElementById('sbom_file');
            const fileDisplay = document.querySelector('.file-upload-display');
            const uploadForm = document.querySelector('.upload-form');
            const submitBtn = uploadForm.querySelector('button[type="submit"]');
            
            // Initialize Select2 for device dropdown
            $('#device_id').select2({
                placeholder: 'Search for a device...',
                allowClear: true,
                width: '100%',
                templateResult: formatDeviceOption,
                templateSelection: formatDeviceSelection,
                escapeMarkup: function(markup) {
                    return markup; // Allow HTML in results
                },
                matcher: function(params, data) {
                    // If there are no search terms, return all data
                    if ($.trim(params.term) === '') {
                        return data;
                    }
                    
                    // Skip if this is an optgroup
                    if (typeof data.text === 'undefined') {
                        return null;
                    }
                    
                    // Search across multiple fields
                    const searchTerm = params.term.toLowerCase();
                    const hostname = $(data.element).data('hostname') || '';
                    const assetTag = $(data.element).data('asset-tag') || '';
                    const brand = $(data.element).data('brand') || '';
                    const model = $(data.element).data('model') || '';
                    const status = $(data.element).data('status') || '';
                    
                    const searchableText = (hostname + ' ' + assetTag + ' ' + brand + ' ' + model + ' ' + status).toLowerCase();
                    
                    if (searchableText.indexOf(searchTerm) > -1) {
                        return data;
                    }
                    
                    return null;
                }
            });
            
            // (Button removed per request; preselection logic remains based on URL)
            
            // File input change handler
            fileInput.addEventListener('change', function() {
                if (this.files.length > 0) {
                    const file = this.files[0];
                    fileDisplay.innerHTML = `
                        <i class="fas fa-file"></i>
                        <span>${file.name} (${formatFileSize(file.size)})</span>
                    `;
                    fileDisplay.classList.add('file-selected');
                    
                    // Validate file type
                    const allowedTypes = ['xml', 'json', 'txt', 'spdx'];
                    const fileExtension = file.name.split('.').pop().toLowerCase();
                    const isSpdxFile = fileExtension === 'spdx' || 
                                      (fileExtension === 'json' && file.name.toLowerCase().includes('spdx'));
                    
                    if (!allowedTypes.includes(fileExtension) && !isSpdxFile) {
                        showNotification('File type not supported. Please select a valid SBOM file.', 'error');
                        fileInput.value = '';
                        resetFileDisplay();
                        return;
                    }
                    
                    // Validate file size (50MB limit)
                    const maxSize = 50 * 1024 * 1024; // 50MB
                    if (file.size > maxSize) {
                        showNotification('File size exceeds 50MB limit. Please select a smaller file.', 'error');
                        fileInput.value = '';
                        resetFileDisplay();
                        return;
                    }
                } else {
                    resetFileDisplay();
                }
            });
            
            // Drag and drop handlers
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
            
            // Form submission handler
            uploadForm.addEventListener('submit', function(e) {
                if (!fileInput.files.length) {
                    e.preventDefault();
                    showNotification('Please select a file to upload.', 'error');
                    return;
                }
                
                if (!document.getElementById('device_id').value) {
                    e.preventDefault();
                    showNotification('Please select a device.', 'error');
                    return;
                }
                
                // Show loading state
                submitBtn.classList.add('loading');
                submitBtn.disabled = true;
                
                // Show progress message
                showNotification('Uploading and processing SBOM file...', 'info');
            });
            
            function resetFileDisplay() {
                fileDisplay.innerHTML = `
                    <i class="fas fa-cloud-upload-alt"></i>
                    <span>Click to select SBOM file or drag and drop</span>
                `;
                fileDisplay.classList.remove('file-selected');
            }
            
            function showNotification(message, type = 'info') {
                // Remove existing notifications
                const existingAlerts = document.querySelectorAll('.alert');
                existingAlerts.forEach(alert => alert.remove());
                
                // Create new notification
                const alert = document.createElement('div');
                alert.className = `alert alert-${type}`;
                alert.innerHTML = `
                    <i class="fas fa-${type === 'error' ? 'exclamation-circle' : type === 'success' ? 'check-circle' : 'info-circle'}"></i>
                    ${message}
                `;
                
                // Insert at the top of upload container
                const uploadContainer = document.querySelector('.upload-container');
                uploadContainer.insertBefore(alert, uploadContainer.firstChild);
                
                // Auto-remove after 5 seconds
                setTimeout(() => {
                    if (alert.parentNode) {
                        alert.remove();
                    }
                }, 5000);
            }
        });
        
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // Format device options for Select2 dropdown
        function formatDeviceOption(device) {
            if (device.loading) {
                return device.text;
            }
            
            const $option = $(device.element);
            let hostname = ($option.data('hostname') || '').trim();
            let assetTag = ($option.data('asset-tag') || '').trim();
            let brand = ($option.data('brand') || '').trim();
            const model = ($option.data('model') || '').trim();
            let deviceName = ($option.data('device-name') || '').trim();
            const status = $option.data('status') || '';
            
            // Match assets table: hostname → brand → deviceName → assetTag
            if (brand.toLowerCase() === 'unmapped device') brand = '';
            const displayName = hostname || brand || deviceName || assetTag || 'Unknown Device';
            const deviceInfo = status === 'Mapped' ? (brand + ' ' + model).trim() : 'Unmapped Device';
            const statusIcon = status === 'Mapped' ? '✓' : '○';
            const statusClass = status === 'Mapped' ? 'mapped' : 'unmapped';
            
            return $(`
                <div class="device-option ${statusClass}">
                    <div class="device-main">
                        <span class="status-icon">${statusIcon}</span>
                        <span class="device-name">${displayName}</span>
                    </div>
                    <div class="device-info">${deviceInfo}</div>
                    ${hostname && assetTag ? `<div class="device-tag">Tag: ${assetTag}</div>` : ''}
                </div>
            `);
        }
        
        // Format selected device for Select2
        function formatDeviceSelection(device) {
            const $option = $(device.element);
            let hostname = ($option.data('hostname') || '').trim();
            let assetTag = ($option.data('asset-tag') || '').trim();
            let brand = ($option.data('brand') || '').trim();
            const model = ($option.data('model') || '').trim();
            let deviceName = ($option.data('device-name') || '').trim();
            const status = $option.data('status') || '';
            
            // Match assets table: hostname → brand → deviceName → assetTag (normalize placeholders)
            if (brand.toLowerCase() === 'unmapped device') brand = '';
            const displayName = hostname || brand || deviceName || assetTag || 'Unknown Device';
            const deviceInfo = status === 'Mapped' ? (brand + ' ' + model).trim() : 'Unmapped Device';
            const statusIcon = status === 'Mapped' ? '✓' : '○';
            
            return `${statusIcon} ${displayName} - ${deviceInfo}`;
        }
    </script>
    <!-- jQuery and Select2 JavaScript -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>
    
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
