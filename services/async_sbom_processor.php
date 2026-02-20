<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
/**
 * Process SBOM evaluation asynchronously
 * This function can be called from the upload process to start evaluation immediately
 */
function processSBOMAsync($sbomId, $deviceId, $userId) {
    // Start background process
    $command = "cd /var/www/html && /usr/bin/php /var/www/html/services/async_sbom_processor.php --sbom-id=$sbomId --device-id=$deviceId --user-id=$userId > /dev/null 2>&1 &";
    
    // Execute in background
    exec($command);
    
    return true;
}

/**
 * Create remediation action for a vulnerability if it doesn't exist
 */
function createRemediationActionForVulnerability($db, $cveId, $userId) {
    try {
        // Check if remediation action already exists
        $checkStmt = $db->prepare("SELECT action_id FROM remediation_actions WHERE cve_id = ?");
        $checkStmt->execute([$cveId]);
        
        if ($checkStmt->fetch()) {
            return true; // Action already exists
        }
        
        // Get vulnerability details
        $vulnStmt = $db->prepare("SELECT severity, cvss_v3_score FROM vulnerabilities WHERE cve_id = ?");
        $vulnStmt->execute([$cveId]);
        $vuln = $vulnStmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$vuln) {
            return false;
        }
        
        // Determine action type based on severity
        $actionType = 'Patch';
        if ($vuln['severity'] === 'Critical') {
            $actionType = 'Patch';
        } elseif ($vuln['severity'] === 'High') {
            $actionType = 'Upgrade';
        } elseif ($vuln['severity'] === 'Medium') {
            $actionType = 'Configuration';
        } else {
            $actionType = 'Mitigation';
        }
        
        $description = "Remediate {$cveId} - {$vuln['severity']} severity vulnerability";
        
        // Create remediation action
        $actionSql = "INSERT INTO remediation_actions (
            action_type,
            action_description,
            cve_id,
            status,
            created_by,
            created_at
        ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)";
        
        $actionStmt = $db->prepare($actionSql);
        $actionStmt->execute([
            $actionType,
            $description,
            $cveId,
            'Pending',
            $userId
        ]);
        
        // Get the action ID
        $actionIdStmt = $db->prepare("SELECT action_id FROM remediation_actions WHERE cve_id = ? ORDER BY created_at DESC LIMIT 1");
        $actionIdStmt->execute([$cveId]);
        $actionResult = $actionIdStmt->fetch();
        $actionId = $actionResult['action_id'];
        
        // Calculate urgency score based on severity and CVSS
        $urgencyScore = calculateUrgencyScore($vuln['severity'], $vuln['cvss_v3_score']);
        $efficiencyScore = calculateEfficiencyScore($vuln['severity'], $vuln['cvss_v3_score']);
        
        // Create action risk score
        $riskScoreSql = "INSERT INTO action_risk_scores (
            action_id,
            urgency_score,
            efficiency_score,
            affected_device_count,
            highest_risk_device_id,
            kev_count,
            critical_asset_count,
            calculated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)";
        
        $riskScoreStmt = $db->prepare($riskScoreSql);
        $riskScoreStmt->execute([
            $actionId,
            $urgencyScore,
            $efficiencyScore,
            1, // Default to 1 device
            null, // highest_risk_device_id (NULL for now)
            0, // Default to 0 KEV
            0  // Default to 0 critical assets
        ]);
        
        // Link action to devices that have this vulnerability
        $deviceLinkSql = "INSERT INTO action_device_links (action_id, device_id)
            SELECT ?, dvl.device_id
            FROM device_vulnerabilities_link dvl
            WHERE dvl.cve_id = ?
            ON CONFLICT (action_id, device_id) DO NOTHING";
        
        $deviceLinkStmt = $db->prepare($deviceLinkSql);
        $deviceLinkStmt->execute([$actionId, $cveId]);
        
        // Calculate device risk scores for affected devices
        calculateDeviceRiskScores($db, $cveId);
        
        return true;
        
    } catch (Exception $e) {
        error_log("Error creating remediation action for {$cveId}: " . $e->getMessage());
        return false;
    }
}

/**
 * Calculate urgency score based on severity and CVSS
 */
function calculateUrgencyScore($severity, $cvssScore) {
    $baseScore = 0;
    
    switch ($severity) {
        case 'Critical':
            $baseScore = 1000;
            break;
        case 'High':
            $baseScore = 500;
            break;
        case 'Medium':
            $baseScore = 200;
            break;
        case 'Low':
            $baseScore = 100;
            break;
        default:
            $baseScore = 50;
    }
    
    // Add CVSS score multiplier
    $cvssMultiplier = $cvssScore ? ($cvssScore / 10) : 1;
    return round($baseScore * $cvssMultiplier);
}

/**
 * Calculate efficiency score based on severity and CVSS
 */
function calculateEfficiencyScore($severity, $cvssScore) {
    $baseScore = 0;
    
    switch ($severity) {
        case 'Critical':
            $baseScore = 90;
            break;
        case 'High':
            $baseScore = 75;
            break;
        case 'Medium':
            $baseScore = 60;
            break;
        case 'Low':
            $baseScore = 45;
            break;
        default:
            $baseScore = 30;
    }
    
    // Add CVSS score adjustment
    $cvssAdjustment = $cvssScore ? ($cvssScore / 10) : 0;
    return min(100, round($baseScore + $cvssAdjustment));
}

/**
 * Calculate device risk scores for devices affected by a vulnerability
 */
function calculateDeviceRiskScores($db, $cveId) {
    try {
        // Get all devices affected by this vulnerability
        $deviceSql = "SELECT DISTINCT dvl.device_id 
                      FROM device_vulnerabilities_link dvl 
                      WHERE dvl.cve_id = ?";
        $deviceStmt = $db->prepare($deviceSql);
        $deviceStmt->execute([$cveId]);
        $devices = $deviceStmt->fetchAll(PDO::FETCH_ASSOC);
        
        foreach ($devices as $device) {
            $deviceId = $device['device_id'];
            
            // Get device configuration for risk calculation
            $configSql = "SELECT 
                            a.asset_id,
                            a.criticality,
                            a.status,
                            l.criticality as location_criticality,
                            lh.hierarchy_path
                          FROM assets a
                          LEFT JOIN locations l ON a.location_id = l.location_id
                          LEFT JOIN location_hierarchy lh ON l.location_id = lh.location_id
                          WHERE a.asset_id = ?";
            $configStmt = $db->prepare($configSql);
            $configStmt->execute([$deviceId]);
            $config = $configStmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$config) {
                continue; // Skip if device not found
            }
            
            // Calculate risk score using the PostgreSQL function
            $riskScoreSql = "SELECT calculate_device_risk_score(?, ROW(?, ?, ?, ?, ?)) as risk_score";
            $riskStmt = $db->prepare($riskScoreSql);
            $riskStmt->execute([
                $deviceId,
                $config['asset_id'],
                $config['criticality'],
                $config['status'],
                $config['location_criticality'],
                $config['hierarchy_path']
            ]);
            $result = $riskStmt->fetch(PDO::FETCH_ASSOC);
            
            if ($result && $result['risk_score'] !== null) {
                // Update the risk score in device_vulnerabilities_link
                $updateSql = "UPDATE device_vulnerabilities_link 
                             SET risk_score = ? 
                             WHERE device_id = ? AND cve_id = ?";
                $updateStmt = $db->prepare($updateSql);
                $updateStmt->execute([$result['risk_score'], $deviceId, $cveId]);
            }
        }
        
        return true;
        
    } catch (Exception $e) {
        error_log("Error calculating device risk scores for {$cveId}: " . $e->getMessage());
        return false;
    }
}

/**
 * Main processing function
 */
function evaluateSBOM($sbomId, $deviceId, $userId) {
    try {
        require_once __DIR__ . '/../config/database.php';
        
        $db = DatabaseConfig::getInstance();
        
        // Get SBOM data
        $stmt = $db->prepare("SELECT content FROM sboms WHERE sbom_id = ?");
        $stmt->execute([$sbomId]);
        $sbomData = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$sbomData) {
            throw new Exception("SBOM not found");
        }
        
        $sbomJson = json_decode($sbomData['content'], true);
        $components = $sbomJson['components'] ?? [];
        
        $stats = [
            'components_evaluated' => 0,
            'vulnerabilities_found' => 0,
            'vulnerabilities_stored' => 0
        ];
        
        foreach ($components as $component) {
            $stats['components_evaluated']++;
            
            $cpe = $component['cpe'] ?? '';
            if (!$cpe) {
                continue;
            }
            
            // Search NVD for vulnerabilities
            $vulnerabilities = searchNVDForCPE($cpe);
            $stats['vulnerabilities_found'] += count($vulnerabilities);
            
            // Store vulnerabilities
            foreach ($vulnerabilities as $vuln) {
                if (storeVulnerability($db, $vuln, $component['bom-ref'] ?? '', $deviceId)) {
                    $stats['vulnerabilities_stored']++;
                }
            }
        }
        
        // Update SBOM evaluation status
        $updateStmt = $db->prepare("
            UPDATE sboms 
            SET evaluation_status = 'Completed', 
                last_evaluated_at = CURRENT_TIMESTAMP,
                vulnerabilities_count = ?
            WHERE sbom_id = ?
        ");
        $updateStmt->execute([$stats['vulnerabilities_stored'], $sbomId]);
        
        // Log evaluation
        error_log("SBOM Evaluation completed: {$stats['components_evaluated']} components, {$stats['vulnerabilities_stored']} vulnerabilities stored");
        
        return $stats;
        
    } catch (Exception $e) {
        error_log("SBOM Evaluation failed: " . $e->getMessage());
        
        // Update SBOM status to failed
        $db = DatabaseConfig::getInstance();
        $updateStmt = $db->prepare("
            UPDATE sboms 
            SET evaluation_status = 'Failed'
            WHERE sbom_id = ?
        ");
        $updateStmt->execute([$sbomId]);
        
        return false;
    }
}

/**
 * Search NVD for vulnerabilities by CPE
 */
function searchNVDForCPE($cpe) {
    $vulnerabilities = [];
    
    try {
        $url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        $params = [
            'cpeName' => $cpe,
            'resultsPerPage' => 2000
        ];
        
        // Add API key if available
        $apiKeyFile = '/var/www/html/config/nvd_api_key.txt';
        if (file_exists($apiKeyFile)) {
            $params['apiKey'] = trim(file_get_contents($apiKeyFile));
        }
        
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 30,
                'header' => 'User-Agent: /1.0'
            ]
        ]);
        
        $response = file_get_contents($url . '?' . http_build_query($params), false, $context);
        
        if ($response === false) {
            throw new Exception("Failed to fetch NVD data");
        }
        
        $data = json_decode($response, true);
        
        foreach ($data['vulnerabilities'] ?? [] as $vuln) {
            $cve = $vuln['cve'] ?? [];
            
            $vulnerabilities[] = [
                'cve_id' => $cve['id'] ?? '',
                'description' => $cve['descriptions'][0]['value'] ?? '',
                'severity' => extractSeverity($cve),
                'cvss_v3_score' => extractCVSSScore($cve),
                'published_date' => $cve['published'] ?? '',
                'last_modified_date' => $cve['lastModified'] ?? '',
                'nvd_data' => $vuln
            ];
        }
        
    } catch (Exception $e) {
        error_log("Error searching NVD for CPE $cpe: " . $e->getMessage());
    }
    
    return $vulnerabilities;
}

/**
 * Extract severity from CVE data
 */
function extractSeverity($cveData) {
    $metrics = $cveData['metrics'] ?? [];
    $cvssV3 = $metrics['cvssMetricV31'] ?? [];
    
    if (!empty($cvssV3)) {
        return $cvssV3[0]['cvssData']['baseSeverity'] ?? 'Unknown';
    }
    
    return 'Unknown';
}

/**
 * Extract CVSS score from CVE data
 */
function extractCVSSScore($cveData) {
    $metrics = $cveData['metrics'] ?? [];
    $cvssV3 = $metrics['cvssMetricV31'] ?? [];
    
    if (!empty($cvssV3)) {
        return floatval($cvssV3[0]['cvssData']['baseScore'] ?? 0);
    }
    
    return 0.0;
}

/**
 * Store vulnerability in database
 */
function storeVulnerability($db, $vulnData, $componentId, $deviceId) {
    try {
        $db->beginTransaction();
        
        // Insert vulnerability
        $stmt = $db->prepare("
            INSERT INTO vulnerabilities (cve_id, description, cvss_v3_score, severity, published_date, last_modified_date, nvd_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (cve_id) DO UPDATE SET
                description = EXCLUDED.description,
                cvss_v3_score = EXCLUDED.cvss_v3_score,
                severity = EXCLUDED.severity,
                published_date = EXCLUDED.published_date,
                last_modified_date = EXCLUDED.last_modified_date,
                nvd_data = EXCLUDED.nvd_data,
                updated_at = CURRENT_TIMESTAMP
        ");
        
        $stmt->execute([
            $vulnData['cve_id'],
            $vulnData['description'],
            $vulnData['cvss_v3_score'],
            $vulnData['severity'],
            $vulnData['published_date'],
            $vulnData['last_modified_date'],
            json_encode($vulnData['nvd_data'])
        ]);
        
        // Link to device
        $linkStmt = $db->prepare("
            INSERT INTO device_vulnerabilities_link (device_id, component_id, cve_id, discovered_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT (device_id, component_id, cve_id) DO NOTHING
        ");
        
        $linkStmt->execute([$deviceId, $componentId, $vulnData['cve_id']]);
        
        // Create remediation action if it doesn't exist
        createRemediationActionForVulnerability($db, $vulnData['cve_id'], $userId);
        
        $db->commit();
        return true;
        
    } catch (Exception $e) {
        $db->rollBack();
        error_log("Error storing vulnerability: " . $e->getMessage());
        return false;
    }
}

// Command line interface
if (php_sapi_name() === 'cli') {
    $options = getopt('', ['sbom-id:', 'device-id:', 'user-id:']);
    
    if (isset($options['sbom-id']) && isset($options['device-id']) && isset($options['user-id'])) {
        evaluateSBOM($options['sbom-id'], $options['device-id'], $options['user-id']);
    } else {
        echo "Usage: php async_sbom_processor.php --sbom-id=ID --device-id=ID --user-id=ID\n";
        exit(1);
    }
}
?>
