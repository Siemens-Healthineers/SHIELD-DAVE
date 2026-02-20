<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Define access flag (allows config.php to load)
if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';

try {
    $db = DatabaseConfig::getInstance();
    $conn = $db->getConnection();
    
    echo "Matching vulnerabilities with KEV catalog...\n";
    echo str_repeat("=", 60) . "\n\n";
    
    // Start transaction
    $conn->beginTransaction();
    
    // Step 1: Match existing vulnerabilities with KEV catalog
    // This updates the is_kev flag for all vulnerabilities that match KEV entries
    echo "Step 1: Matching vulnerabilities with KEV catalog entries...\n";
    $matchSql = "UPDATE vulnerabilities v
                 SET is_kev = TRUE,
                     kev_id = k.kev_id,
                     kev_date_added = k.date_added,
                     kev_due_date = k.due_date,
                     kev_required_action = k.required_action,
                     priority = 'Critical-KEV',
                     updated_at = CURRENT_TIMESTAMP
                 FROM cisa_kev_catalog k
                 WHERE v.cve_id = k.cve_id
                   AND v.is_kev = FALSE";
    
    $matchStmt = $conn->prepare($matchSql);
    $matchStmt->execute();
    $matchedCount = $matchStmt->rowCount();
    echo "Matched {$matchedCount} vulnerabilities with KEV catalog\n\n";
    
    // Step 2: Recalculate device risk scores (since is_kev affects risk scores)
    // Use bulk UPDATE with calculate_risk_score function for efficiency
    echo "Step 2: Recalculating device risk scores...\n";
    
    // Bulk update all open/in-progress links using calculate_risk_score function
    $recalcSql = "UPDATE device_vulnerabilities_link dvl
                  SET risk_score = calculate_risk_score(dvl.link_id),
                      updated_at = CURRENT_TIMESTAMP
                  WHERE dvl.remediation_status IN ('Open', 'In Progress')
                    AND dvl.device_id IS NOT NULL
                    AND dvl.cve_id IS NOT NULL";
    
    $recalcStmt = $conn->prepare($recalcSql);
    $recalcStmt->execute();
    $updatedLinks = $recalcStmt->rowCount();
    echo "Recalculated risk scores for {$updatedLinks} device-vulnerability links\n\n";
    
    // Step 3: Recalculate action urgency scores for all actions
    echo "Step 3: Recalculating action urgency scores...\n";
    $recalcActionsSql = "SELECT COUNT(*) FROM remediation_actions 
                         WHERE status != 'Completed' AND status != 'Cancelled'";
    $countStmt = $conn->prepare($recalcActionsSql);
    $countStmt->execute();
    $totalActions = $countStmt->fetchColumn();
    
    $recalcActionsSql = "SELECT recalculate_action_urgency_score(action_id) 
                         FROM remediation_actions 
                         WHERE status != 'Completed' AND status != 'Cancelled'";
    $recalcActionsStmt = $conn->prepare($recalcActionsSql);
    $recalcActionsStmt->execute();
    echo "Recalculated urgency scores for {$totalActions} actions\n\n";
    
    // Step 4: Update KEV counts in action_risk_scores
    // kev_count should be the number of devices affected by the action's KEV CVE
    // This counts devices with the KEV vulnerability, regardless of whether they're linked via action_device_links
    echo "Step 4: Updating KEV counts in action risk scores...\n";
    $updateKevCountSql = "UPDATE action_risk_scores ars
                          SET kev_count = COALESCE((
                              SELECT COUNT(DISTINCT dvl.device_id)
                              FROM remediation_actions ra
                              JOIN vulnerabilities v ON ra.cve_id = v.cve_id
                              JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
                              WHERE ra.action_id = ars.action_id
                                AND v.is_kev = TRUE
                                AND dvl.remediation_status IN ('Open', 'In Progress')
                          ), 0),
                          last_updated = CURRENT_TIMESTAMP";
    
    $updateKevStmt = $conn->prepare($updateKevCountSql);
    $updateKevStmt->execute();
    $updatedActionsCount = $updateKevStmt->rowCount();
    echo "Updated KEV counts for {$updatedActionsCount} actions\n\n";
    
    // Step 5: Refresh materialized views that depend on is_kev
    echo "Step 5: Refreshing materialized views...\n";
    $conn->exec("REFRESH MATERIALIZED VIEW CONCURRENTLY risk_priority_view");
    echo "Refreshed risk_priority_view\n";
    $conn->exec("REFRESH MATERIALIZED VIEW CONCURRENTLY action_priority_view");
    echo "Refreshed action_priority_view\n\n";
    
    // Commit transaction
    $conn->commit();
    
    echo str_repeat("=", 60) . "\n";
    echo "KEV MATCHING COMPLETED SUCCESSFULLY\n";
    echo str_repeat("=", 60) . "\n";
    echo "Summary:\n";
    echo "  Vulnerabilities matched: {$matchedCount}\n";
    echo "  Actions updated: {$updatedActionsCount}\n";
    echo "  Urgency scores recalculated: {$totalActions}\n";
    echo "  Materialized views refreshed: 2\n";
    echo "\n";
    
} catch (Exception $e) {
    if (isset($conn) && $conn->inTransaction()) {
        $conn->rollBack();
    }
    
    echo "ERROR: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
    exit(1);
}

