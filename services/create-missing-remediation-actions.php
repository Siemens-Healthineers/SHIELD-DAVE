<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';

/**
 * Create remediation actions for vulnerabilities that don't have them
 */
function createMissingRemediationActions() {
    try {
        $db = DatabaseConfig::getInstance();
        
        echo "🔍 Analyzing device-vulnerability links without remediation actions...\n";
        
        // Find device-vulnerability links that don't have remediation actions
        $sql = "SELECT DISTINCT dvl.cve_id, v.severity, v.cvss_v3_score, v.description
                FROM device_vulnerabilities_link dvl
                LEFT JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
                LEFT JOIN remediation_actions ra ON dvl.cve_id = ra.cve_id
                WHERE ra.cve_id IS NULL
                ORDER BY v.cvss_v3_score DESC, v.severity DESC";
        
        $stmt = $db->query($sql);
        $vulnerabilities = $stmt->fetchAll();
        
        echo "📊 Found " . count($vulnerabilities) . " vulnerabilities without remediation actions\n";
        
        if (empty($vulnerabilities)) {
            echo "✅ All vulnerabilities already have remediation actions\n";
            return;
        }
        
        $created = 0;
        $errors = 0;
        
        foreach ($vulnerabilities as $vuln) {
            try {
                $db->beginTransaction();
                
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
                
                // Determine action type based on severity
                $actionType = 'Patch';
                
                if ($vuln['severity'] === 'Critical') {
                    $actionType = 'Patch';
                } elseif ($vuln['severity'] === 'High') {
                    $actionType = 'Patch';
                } elseif ($vuln['severity'] === 'Medium') {
                    $actionType = 'Patch';
                } else {
                    $actionType = 'Patch';
                }
                
                $description = "Patch {$vuln['cve_id']} - {$vuln['description']}";
                if (strlen($description) > 500) {
                    $description = substr($description, 0, 497) . '...';
                }
                
                $actionStmt->execute([
                    $actionType,
                    $description,
                    $vuln['cve_id'],
                    'Pending',
                    'a1edd3fa-c5fd-45c7-a054-54079dc7f33f' // Admin user
                ]);
                
                // Get the action ID using RETURNING clause
                $actionIdStmt = $db->prepare("SELECT action_id FROM remediation_actions WHERE cve_id = ? ORDER BY created_at DESC LIMIT 1");
                $actionIdStmt->execute([$vuln['cve_id']]);
                $actionIdResult = $actionIdStmt->fetch();
                $actionId = $actionIdResult['action_id'];
                
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
                    WHERE dvl.cve_id = ?";
                
                $deviceLinkStmt = $db->prepare($deviceLinkSql);
                $deviceLinkStmt->execute([$actionId, $vuln['cve_id']]);
                
                $db->commit();
                $created++;
                
                if ($created % 100 === 0) {
                    echo "✅ Created {$created} remediation actions...\n";
                }
                
            } catch (Exception $e) {
                $db->rollBack();
                $errors++;
                echo "❌ Error creating action for {$vuln['cve_id']}: " . $e->getMessage() . "\n";
            }
        }
        
        echo "\n📋 Summary:\n";
        echo "✅ Created: {$created} remediation actions\n";
        echo "❌ Errors: {$errors}\n";
        echo "📊 Total processed: " . count($vulnerabilities) . "\n";
        
        return $created;
        
    } catch (Exception $e) {
        echo "❌ Fatal error: " . $e->getMessage() . "\n";
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
    $cvssMultiplier = $cvssScore > 0 ? ($cvssScore / 10) : 1;
    
    return intval($baseScore * $cvssMultiplier);
}

/**
 * Calculate efficiency score based on severity and CVSS
 */
function calculateEfficiencyScore($severity, $cvssScore) {
    $baseScore = 0;
    
    switch ($severity) {
        case 'Critical':
            $baseScore = 900;
            break;
        case 'High':
            $baseScore = 700;
            break;
        case 'Medium':
            $baseScore = 500;
            break;
        case 'Low':
            $baseScore = 300;
            break;
        default:
            $baseScore = 200;
    }
    
    // Add CVSS score multiplier
    $cvssMultiplier = $cvssScore > 0 ? ($cvssScore / 10) : 1;
    
    return intval($baseScore * $cvssMultiplier);
}

// Run if called directly
if (php_sapi_name() === 'cli') {
    echo "🚀 Starting remediation action creation process...\n\n";
    $result = createMissingRemediationActions();
    
    if ($result !== false) {
        echo "\n✅ Process completed successfully!\n";
        exit(0);
    } else {
        echo "\n❌ Process failed!\n";
        exit(1);
    }
}
?>
