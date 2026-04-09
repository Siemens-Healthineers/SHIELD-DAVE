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

// Authentication required
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Handle job polling request
if (isset($_GET['ajax']) && $_GET['ajax'] === 'check_jobs') {
    header('Content-Type: application/json');
    
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
                    case 'sbom_evaluation':
                        $sbomResult = json_decode($output, true);
                        if (json_last_error() === JSON_ERROR_NONE && isset($sbomResult['success'])) {
                            if ($sbomResult['success']) {
                                $results[] = [
                                    'job_id' => $job['job_id'],
                                    'type' => 'sbom_evaluation',
                                    'status' => 'completed',
                                    'data' => [
                                        'vulnerabilities_found' => $sbomResult['vulnerabilities_found'] ?? 0,
                                        'vulnerabilities_stored' => $sbomResult['vulnerabilities_stored'] ?? 0,
                                        'asset_id' => $job['asset_id'] ?? null
                                    ]
                                ];
                            } else {
                                $results[] = [
                                    'job_id' => $job['job_id'],
                                    'type' => 'sbom_evaluation',
                                    'status' => 'failed',
                                    'error' => $sbomResult['reason'] ?? 'SBOM evaluation failed'
                                ];
                            }
                        } else {
                            $results[] = [
                                'job_id' => $job['job_id'],
                                'type' => 'sbom_evaluation',
                                'status' => 'failed',
                                'error' => 'Failed to parse SBOM evaluation results'
                            ];
                        }
                        break;
                        
                    case '510k':
                        $k510kData = json_decode($output, true);
                        if (json_last_error() === JSON_ERROR_NONE && !empty($k510kData)) {
                            $results[] = [
                                'job_id' => $job['job_id'],
                                'type' => '510k',
                                'status' => 'completed',
                                'data' => $k510kData
                            ];
                        } else {
                            $results[] = [
                                'job_id' => $job['job_id'],
                                'type' => '510k',
                                'status' => 'failed',
                                'error' => 'No 510k data found or failed to parse'
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
    exit;
}

// Handle SBOM evaluation request
if (isset($_GET['ajax']) && $_GET['ajax'] === 'evaluate_sbom') {
    header('Content-Type: application/json');
    
    $assetId = $_GET['asset_id'] ?? '';
    
    if (empty($assetId)) {
        echo json_encode(['success' => false, 'error' => 'Asset ID required']);
        exit;
    }
    
    try {
        // Get device_id from asset_id
        $deviceSql = "SELECT device_id FROM medical_devices WHERE asset_id = ?";
        $deviceStmt = $db->prepare($deviceSql);
        $deviceStmt->execute([$assetId]);
        $device = $deviceStmt->fetch();
        
        if (!$device) {
            echo json_encode(['success' => false, 'error' => 'Device not found for asset']);
            exit;
        }
        
        $deviceId = $device['device_id'];
        
        // Execute Python vulnerability scanner (non-blocking)
        $pythonScript = _ROOT . '/python/services/vulnerability_scanner.py';
        $logFile = _ROOT . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . 'sbom_eval_' . $assetId . '_' . uniqid() . '.log';
        $command = "cd " . _ROOT . " && python3 $pythonScript --device-id " . escapeshellarg($deviceId) . " --scan-type sbom";
        
        $result = ShellCommandUtilities::executeShellCommand($command, [
            'blocking' => false,
            'log_file' => $logFile
        ]);
        
        if (!$result['success']) {
            throw new Exception('Failed to start vulnerability scanner: ' . ($result['error'] ?? 'Unknown error'));
        }
        
        // Return job info for polling
        echo json_encode([
            'success' => true,
            'message' => 'SBOM evaluation started',
            'job' => [
                'job_id' => uniqid('sbom_eval_'),
                'pid' => $result['pid'],
                'log_file' => $result['log_file'],
                'status' => 'running',
                'type' => 'sbom_evaluation',
                'asset_id' => $assetId,
                'device_id' => $deviceId
            ]
        ]);
        
    } catch (Exception $e) {
        error_log("SBOM evaluation error: " . $e->getMessage());
        echo json_encode([
            'success' => false,
            'error' => 'Internal server error: ' . $e->getMessage()
        ]);
    }
    exit;
}

// Handle 510k API request first (before main asset data logic)
if (isset($_GET['ajax']) && $_GET['ajax'] === 'get_510k') {
    error_log('510k API called');
    $deviceId = $_GET['device_id'] ?? '';
    error_log('Device ID received: ' . $deviceId);
    
    if (empty($deviceId)) {
        error_log('No device ID provided');
        echo json_encode(['success' => false, 'message' => 'Device ID required']);
        exit;
    }
    
    try {
        // Call Python FDA service for 510k data (non-blocking)
        $logFile = _ROOT . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . '510k_' . uniqid() . '.log';
        $command = "python3 " . _ROOT . "/python/services/fda_integration.py search_510k " . escapeshellarg($deviceId);
        error_log('510k command: ' . $command);
        
        $result = ShellCommandUtilities::executeShellCommand($command, [
            'blocking' => false,
            'log_file' => $logFile
        ]);
        
        if (!$result['success']) {
            error_log('Failed to start 510k lookup: ' . ($result['error'] ?? 'Unknown error'));
            echo json_encode(['success' => false, 'message' => 'Failed to start 510k lookup']);
        } else {
            error_log('510k lookup started with PID: ' . $result['pid']);
            // Return job info for polling
            echo json_encode([
                'success' => true,
                'message' => '510k lookup started',
                'job' => [
                    'job_id' => uniqid('510k_'),
                    'pid' => $result['pid'],
                    'log_file' => $result['log_file'],
                    'status' => 'running',
                    'type' => '510k',
                    'device_id' => $deviceId
                ]
            ]);
        }
    } catch (Exception $e) {
        error_log('510k error: ' . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Error fetching 510k data: ' . $e->getMessage()]);
    }
    exit;
}

// Get asset ID from request
$assetId = $_GET['asset_id'] ?? '';

if (empty($assetId)) {
    echo json_encode(['success' => false, 'message' => 'Asset ID required']);
    exit;
}

// Get comprehensive asset data
try {
    $sql = "SELECT 
        a.*,
        md.device_id,
        md.device_identifier,
        md.brand_name,
        md.model_number,
        md.manufacturer_name,
        md.device_description,
        md.gmdn_term,
        md.gmdn_code,
        md.gmdn_definition,
        md.is_implantable,
        md.fda_class,
        md.fda_class_name,
        md.regulation_number,
        md.medical_specialty,
        md.udi,
        md.primary_udi,
        md.package_udi,
        md.issuing_agency,
        md.commercial_status,
        md.record_status,
        md.is_single_use,
        md.is_kit,
        md.is_combination_product,
        md.is_otc,
        md.is_rx,
        md.is_sterile,
        md.sterilization_methods,
        md.is_sterilization_prior_use,
        md.is_pm_exempt,
        md.is_direct_marking_exempt,
        md.has_serial_number,
        md.has_lot_batch_number,
        md.has_expiration_date,
        md.has_manufacturing_date,
        md.mri_safety,
        md.product_code,
        md.product_code_name,
        md.customer_phone,
        md.customer_email,
        md.public_version_number,
        md.public_version_date,
        md.public_version_status,
        md.publish_date,
        md.device_count_in_base_package,
        md.labeler_duns_number,
        md.mapping_confidence,
        md.mapping_method,
        md.mapped_at,
        -- 510k specific fields
        md.k_number,
        md.decision_code,
        md.decision_date,
        md.decision_description,
        md.clearance_type,
        md.date_received,
        md.statement_or_summary,
        md.applicant,
        md.contact,
        md.address_1,
        md.address_2,
        md.city,
        md.state,
        md.zip_code,
        md.postal_code,
        md.country_code,
        md.advisory_committee,
        md.advisory_committee_description,
        md.review_advisory_committee,
        md.expedited_review_flag,
        md.third_party_flag,
        md.device_class,
        md.medical_specialty_description,
        md.registration_numbers,
        md.fei_numbers,
        md.device_name,
        u.username as mapped_by_username,
        CASE WHEN md.device_id IS NOT NULL THEN 'Mapped' ELSE 'Unmapped' END as mapping_status,
        l.location_name as assigned_location_name,
        l.location_code as assigned_location_code,
        l.criticality as location_criticality,
        lh.hierarchy_path as location_hierarchy_path
    FROM assets a
    LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
    LEFT JOIN users u ON md.mapped_by = u.user_id
    LEFT JOIN locations l ON a.location_id = l.location_id
    LEFT JOIN location_hierarchy lh ON l.location_id = lh.location_id
    WHERE a.asset_id = ?";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([$assetId]);
    $asset = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$asset) {
        echo json_encode(['success' => false, 'message' => 'Asset not found']);
        exit;
    }
    
    // Get vulnerabilities with KEV information
    // Updated to support both SBOM-based links and direct asset links
    // Using DISTINCT ON to handle potential duplicates from both link paths
    // Supports both cve_id and vulnerability_id linking
    $vulnSql = "SELECT DISTINCT ON (v.vulnerability_id)
        v.vulnerability_id,
        v.cve_id,
        v.description,
        v.cvss_v4_score,
        v.cvss_v3_score,
        v.cvss_v2_score,
        v.severity,
        v.published_date,
        v.is_kev,
        v.kev_date_added,
        v.kev_due_date,
        v.priority,
        k.vulnerability_name as kev_name,
        k.required_action as kev_required_action,
        k.known_ransomware_campaign_use as kev_ransomware,
        dvl.remediation_status,
        dvl.remediation_notes,
        dvl.assigned_to,
        dvl.due_date,
        u.username as assigned_to_username,
        sc.name as component_name,
        sc.version as component_version
    FROM vulnerabilities v
    JOIN device_vulnerabilities_link dvl ON (v.cve_id = dvl.cve_id OR v.vulnerability_id = dvl.vulnerability_id)
    LEFT JOIN software_components sc ON dvl.component_id = sc.component_id
    LEFT JOIN sboms s ON sc.sbom_id = s.sbom_id
    LEFT JOIN medical_devices md ON s.device_id = md.device_id
    LEFT JOIN users u ON dvl.assigned_to = u.user_id
    LEFT JOIN cisa_kev_catalog k ON v.cve_id = k.cve_id AND v.is_kev = true
    WHERE (md.asset_id = ? OR dvl.asset_id = ?)
    ORDER BY v.vulnerability_id, v.is_kev DESC, COALESCE(v.cvss_v4_score, v.cvss_v3_score, v.cvss_v2_score) DESC";
    
    $vulnStmt = $db->prepare($vulnSql);
    $vulnStmt->execute([$assetId, $assetId]);
    $vulnerabilities = $vulnStmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Debug logging
    error_log("Asset ID: " . $assetId);
    error_log("Vulnerabilities found: " . count($vulnerabilities));
    error_log("Vulnerability query: " . $vulnSql);
    if (empty($vulnerabilities)) {
        // Check if there are any links at all for this asset
        $debugSql = "SELECT COUNT(*) as link_count FROM device_vulnerabilities_link WHERE asset_id = ?";
        $debugStmt = $db->prepare($debugSql);
        $debugStmt->execute([$assetId]);
        $linkCount = $debugStmt->fetch(PDO::FETCH_ASSOC);
        error_log("Direct links for asset: " . json_encode($linkCount));
    }
    
    // Get recalls
    $recallSql = "SELECT 
        r.*,
        drl.remediation_status as device_recall_status,
        drl.remediation_notes,
        drl.assigned_to,
        drl.due_date,
        u.username as assigned_to_username
    FROM recalls r
    JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
    JOIN medical_devices md ON drl.device_id = md.device_id
    LEFT JOIN users u ON drl.assigned_to = u.user_id
    WHERE md.asset_id = ?
    ORDER BY r.recall_date DESC";
    
    $recallStmt = $db->prepare($recallSql);
    $recallStmt->execute([$assetId]);
    $recalls = $recallStmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get audit logs
    $auditSql = "SELECT 
        al.*,
        u.username
    FROM audit_logs al
    LEFT JOIN users u ON al.user_id = u.user_id
    WHERE al.table_name = 'assets' AND al.record_id = ?
    ORDER BY al.timestamp DESC
    LIMIT 20";
    
    $auditStmt = $db->prepare($auditSql);
    $auditStmt->execute([$assetId]);
    $auditLogs = $auditStmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get SBOM data
    $sbomSql = "SELECT 
        s.sbom_id,
        s.format,
        s.file_name,
        s.file_size,
        s.uploaded_at,
        s.parsing_status,
        s.content,
        u.username as uploaded_by_username
    FROM sboms s
    JOIN medical_devices md ON s.device_id = md.device_id
    LEFT JOIN users u ON s.uploaded_by = u.user_id
    WHERE md.asset_id = ?
    ORDER BY s.uploaded_at DESC";
    
    $sbomStmt = $db->prepare($sbomSql);
    $sbomStmt->execute([$assetId]);
    $sboms = $sbomStmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get software components for each SBOM
    $components = [];
    foreach ($sboms as $sbom) {
        $componentSql = "SELECT 
            sc.component_id,
            sc.name,
            sc.version,
            sc.vendor,
            sc.license,
            sc.purl,
            sc.cpe,
            sc.created_at
        FROM software_components sc
        WHERE sc.sbom_id = ?
        ORDER BY sc.name";
        
        $componentStmt = $db->prepare($componentSql);
        $componentStmt->execute([$sbom['sbom_id']]);
        $sbomComponents = $componentStmt->fetchAll(PDO::FETCH_ASSOC);
        
        $components[$sbom['sbom_id']] = $sbomComponents;
    }
    
    echo json_encode([
        'success' => true,
        'asset' => $asset,
        'vulnerabilities' => $vulnerabilities,
        'recalls' => $recalls,
        'auditLogs' => $auditLogs,
        'sboms' => $sboms,
        'components' => $components
    ]);
    
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'Error fetching asset data: ' . $e->getMessage()]);
}
?>
