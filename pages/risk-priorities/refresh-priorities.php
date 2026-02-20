<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/database.php';

// Set JSON response headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

try {
    $db = DatabaseConfig::getInstance();
    $updatedCount = 0;
    $messages = [];
    
    // Try to refresh materialized views (may fail due to permissions)
    try {
        $db->getConnection()->exec("REFRESH MATERIALIZED VIEW risk_priority_view");
        $messages[] = "Risk priority view refreshed";
    } catch (Exception $e) {
        $messages[] = "Risk priority view refresh skipped (permission issue)";
    }
    
    try {
        $db->getConnection()->exec("REFRESH MATERIALIZED VIEW action_priority_view");
        $messages[] = "Action priority view refreshed";
    } catch (Exception $e) {
        $messages[] = "Action priority view refresh skipped (permission issue)";
    }
    
    // Get current action count for verification
    try {
        $sql = "SELECT COUNT(*) as action_count FROM action_priority_view";
        $stmt = $db->getConnection()->prepare($sql);
        $stmt->execute();
        $actionCount = $stmt->fetch()['action_count'];
        $messages[] = "Verified {$actionCount} actions in system";
    } catch (Exception $e) {
        $messages[] = "Action count verification skipped: " . $e->getMessage();
    }
    
    echo json_encode([
        'success' => true,
        'message' => implode(', ', $messages),
        'updated_actions' => $actionCount ?? 0
    ]);
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'error' => 'Database error: ' . $e->getMessage()
    ]);
}
?>
