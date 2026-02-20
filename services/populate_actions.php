<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/


require_once __DIR__ . '/../config/database.php';

try {
    $db = DatabaseConfig::getInstance();
    
    echo "Starting action population from existing vulnerability data...\n";
    
    // Get unique CVEs from risk_priority_view
    $sql = "SELECT DISTINCT 
                rpv.cve_id,
                v.description,
                v.severity,
                MAX(CASE WHEN rpv.is_kev = TRUE THEN 1 ELSE 0 END) as has_kev
            FROM risk_priority_view rpv
            LEFT JOIN vulnerabilities v ON rpv.cve_id = v.cve_id
            GROUP BY rpv.cve_id, v.description, v.severity
            ORDER BY rpv.cve_id";
    
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute();
    $cves = $stmt->fetchAll();
    
    echo "Found " . count($cves) . " unique CVEs to process\n";
    
    $createdActions = 0;
    $createdLinks = 0;
    
    foreach ($cves as $cve) {
        echo "Processing CVE: " . $cve['cve_id'] . "\n";
        
        // Create remediation action
        $actionSql = "INSERT INTO remediation_actions (
                        cve_id,
                        action_type,
                        action_description,
                        status,
                        created_at
                      ) VALUES (?, ?, ?, ?, ?) RETURNING action_id";
        
        $actionStmt = $db->getConnection()->prepare($actionSql);
        $actionDescription = 'Patch ' . $cve['cve_id'] . ' - ' . 
                           ($cve['description'] ? substr($cve['description'], 0, 100) : 'Security vulnerability');
        
        $actionStmt->execute([
            $cve['cve_id'],
            'Patch',
            $actionDescription,
            'Pending',
            date('Y-m-d H:i:s')
        ]);
        
        $actionId = $actionStmt->fetch()['action_id'];
        $createdActions++;
        
        // Get affected devices for this CVE
        $deviceSql = "SELECT 
                        link_id,
                        calculated_risk_score,
                        asset_criticality,
                        location_criticality,
                        severity,
                        is_kev
                      FROM risk_priority_view 
                      WHERE cve_id = ?";
        
        $deviceStmt = $db->getConnection()->prepare($deviceSql);
        $deviceStmt->execute([$cve['cve_id']]);
        $devices = $deviceStmt->fetchAll();
        
        echo "  - Found " . count($devices) . " affected devices\n";
        
        // Create device links
        foreach ($devices as $device) {
            $linkSql = "INSERT INTO action_device_links (
                          action_id,
                          device_id,
                          device_risk_score,
                          patch_status,
                          created_at
                        ) VALUES (?, ?, ?, ?, ?)";
            
            $linkStmt = $db->getConnection()->prepare($linkSql);
            $linkStmt->execute([
                $actionId,
                $device['link_id'],
                $device['calculated_risk_score'],
                'Pending',
                date('Y-m-d H:i:s')
            ]);
            
            $createdLinks++;
        }
    }
    
    echo "\nCalculating risk scores for all actions...\n";
    
    // Calculate urgency and efficiency scores for all actions
    $calcSql = "SELECT action_id FROM remediation_actions WHERE status != 'Cancelled'";
    $calcStmt = $db->getConnection()->prepare($calcSql);
    $calcStmt->execute();
    $actions = $calcStmt->fetchAll();
    
    foreach ($actions as $action) {
        // Calculate urgency (max device score)
        $urgencySql = "SELECT COALESCE(MAX(device_risk_score), 0) as urgency_score
                       FROM action_device_links 
                       WHERE action_id = ?";
        $urgencyStmt = $db->getConnection()->prepare($urgencySql);
        $urgencyStmt->execute([$action['action_id']]);
        $urgency = $urgencyStmt->fetch()['urgency_score'];
        
        // Calculate efficiency (sum of all device scores)
        $efficiencySql = "SELECT COALESCE(SUM(device_risk_score), 0) as efficiency_score
                          FROM action_device_links 
                          WHERE action_id = ?";
        $efficiencyStmt = $db->getConnection()->prepare($efficiencySql);
        $efficiencyStmt->execute([$action['action_id']]);
        $efficiency = $efficiencyStmt->fetch()['efficiency_score'];
        
        // Get device count and KEV count
        $statsSql = "SELECT 
                        COUNT(*) as device_count,
                        COUNT(CASE WHEN device_risk_score >= 180 THEN 1 END) as critical_count
                     FROM action_device_links 
                     WHERE action_id = ?";
        $statsStmt = $db->getConnection()->prepare($statsSql);
        $statsStmt->execute([$action['action_id']]);
        $stats = $statsStmt->fetch();
        
        // Get KEV count - number of devices affected by the action's KEV CVE
        // This counts devices with the KEV vulnerability, regardless of whether they're linked via action_device_links
        $kevSql = "SELECT COUNT(DISTINCT dvl.device_id) as kev_count
                   FROM remediation_actions ra
                   JOIN vulnerabilities v ON ra.cve_id = v.cve_id
                   JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
                   WHERE ra.action_id = ?
                     AND v.is_kev = TRUE
                     AND dvl.remediation_status IN ('Open', 'In Progress')";
        $kevStmt = $db->getConnection()->prepare($kevSql);
        $kevStmt->execute([$action['action_id']]);
        $kevCount = $kevStmt->fetch()['kev_count'] ?? 0;
        
        // Insert or update risk scores
        $scoreSql = "INSERT INTO action_risk_scores (
                        action_id, urgency_score, efficiency_score, 
                        affected_device_count, kev_count, critical_asset_count,
                        calculated_at, last_updated
                      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                      ON CONFLICT (action_id) DO UPDATE SET
                        urgency_score = EXCLUDED.urgency_score,
                        efficiency_score = EXCLUDED.efficiency_score,
                        affected_device_count = EXCLUDED.affected_device_count,
                        kev_count = EXCLUDED.kev_count,
                        critical_asset_count = EXCLUDED.critical_asset_count,
                        last_updated = EXCLUDED.last_updated";
        
        $scoreStmt = $db->getConnection()->prepare($scoreSql);
        $scoreStmt->execute([
            $action['action_id'],
            $urgency,
            $efficiency,
            $stats['device_count'],
            $kevCount,
            $stats['critical_count'],
            date('Y-m-d H:i:s'),
            date('Y-m-d H:i:s')
        ]);
    }
    
    // Refresh materialized view
    echo "Refreshing materialized view...\n";
    $db->getConnection()->exec("REFRESH MATERIALIZED VIEW CONCURRENTLY action_priority_view");
    
    // Get final statistics
    $finalSql = "SELECT 
                    priority_tier,
                    COUNT(*) as count,
                    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM action_priority_view), 1) as percentage
                 FROM action_priority_view
                 GROUP BY priority_tier
                 ORDER BY priority_tier";
    
    $finalStmt = $db->getConnection()->prepare($finalSql);
    $finalStmt->execute();
    $finalStats = $finalStmt->fetchAll();
    
    echo "\n" . str_repeat("=", 60) . "\n";
    echo "ACTION POPULATION COMPLETED SUCCESSFULLY\n";
    echo str_repeat("=", 60) . "\n";
    echo "Created Actions: " . $createdActions . "\n";
    echo "Created Device Links: " . $createdLinks . "\n";
    echo "\nFinal Tier Distribution:\n";
    
    foreach ($finalStats as $stat) {
        echo "Tier " . $stat['priority_tier'] . ": " . $stat['count'] . " actions (" . $stat['percentage'] . "%)\n";
    }
    
    echo "\nAction-based remediation system is ready!\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
}
?>
