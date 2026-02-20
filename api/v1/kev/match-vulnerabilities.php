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
require_once __DIR__ . '/../../../config/database.php';
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

// Check if user has permission to manage vulnerabilities
$unifiedAuth->requirePermission('vulnerabilities', 'write');

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    ob_clean();
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'error' => 'Method not allowed'
    ]);
    exit;
}

try {
    $db = DatabaseConfig::getInstance();
    $conn = $db->getConnection();
    
    // Start transaction
    $conn->beginTransaction();
    
    // Step 1: Match existing vulnerabilities with KEV catalog
    // This updates the is_kev flag for all vulnerabilities that match KEV entries
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
    
    // Step 2: Recalculate device risk scores (since is_kev affects risk scores)
    // This updates device_vulnerabilities_link.risk_score for all devices
    $conn->exec("SELECT trigger_recalculate_device_risk_scores()");
    
    // Step 3: Recalculate action urgency scores for all actions
    // This ensures urgency_score reflects the updated is_kev flags
    $recalcActionsSql = "SELECT recalculate_action_urgency_score(action_id) 
                         FROM remediation_actions 
                         WHERE status != 'Completed' AND status != 'Cancelled'";
    $recalcActionsStmt = $conn->prepare($recalcActionsSql);
    $recalcActionsStmt->execute();
    
    // Step 4: Update KEV counts in action_risk_scores
    // kev_count should be the number of devices affected by the action's KEV CVE
    // This counts devices with the KEV vulnerability, regardless of whether they're linked via action_device_links
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
    
    // Step 5: Refresh materialized views that depend on is_kev
    $conn->exec("REFRESH MATERIALIZED VIEW CONCURRENTLY risk_priority_view");
    $conn->exec("REFRESH MATERIALIZED VIEW CONCURRENTLY action_priority_view");
    
    // Commit transaction
    $conn->commit();
    
    ob_clean();
    echo json_encode([
        'success' => true,
        'message' => 'KEV matching completed successfully',
        'data' => [
            'vulnerabilities_matched' => $matchedCount,
            'action_scores_updated' => $updatedActionsCount
        ],
        'timestamp' => date('c')
    ]);
    exit;
    
} catch (Exception $e) {
    if (isset($conn) && $conn->inTransaction()) {
        $conn->rollBack();
    }
    
    ob_clean();
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'MATCH_ERROR',
            'message' => 'Failed to match KEV vulnerabilities: ' . $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

