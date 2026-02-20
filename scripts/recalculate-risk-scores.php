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

$db = DatabaseConfig::getInstance();

echo "=== Recalculate Risk Scores ===\n\n";

try {
    // Get count of links with NULL risk scores
    $countSql = "SELECT COUNT(*) as count FROM device_vulnerabilities_link WHERE risk_score IS NULL";
    $countResult = $db->query($countSql, [])->fetch();
    $totalNull = $countResult['count'];
    
    echo "Found {$totalNull} device-vulnerability links with NULL risk scores\n\n";
    
    if ($totalNull === 0) {
        echo "✓ No links need risk score recalculation.\n";
        exit(0);
    }
    
    // Get all links with NULL risk scores
    $sql = "SELECT link_id, device_id, cve_id 
            FROM device_vulnerabilities_link 
            WHERE risk_score IS NULL
            ORDER BY created_at ASC";
    
    $stmt = $db->query($sql, []);
    $links = $stmt->fetchAll();
    
    $processed = 0;
    $updated = 0;
    $errors = 0;
    $skipped = 0;
    
    echo "Processing {$totalNull} links...\n\n";
    
    foreach ($links as $link) {
        $processed++;
        
        try {
            // Calculate risk score using the database function
            $calculateSql = "SELECT calculate_risk_score(?) as risk_score";
            $calculateStmt = $db->prepare($calculateSql);
            $calculateStmt->execute([$link['link_id']]);
            $result = $calculateStmt->fetch();
            
            if ($result && $result['risk_score'] !== null) {
                // Update the risk score
                $updateSql = "UPDATE device_vulnerabilities_link 
                             SET risk_score = ?, 
                                 updated_at = CURRENT_TIMESTAMP 
                             WHERE link_id = ?";
                $db->query($updateSql, [$result['risk_score'], $link['link_id']]);
                
                $updated++;
                
                // Progress indicator
                if ($processed % 100 === 0) {
                    echo "[{$processed}/{$totalNull}] Processed {$processed} links, updated {$updated} risk scores...\n";
                }
            } else {
                // Could not calculate risk score (missing data?)
                $skipped++;
                if ($processed % 500 === 0) {
                    echo "[{$processed}/{$totalNull}] Processed {$processed} links, {$skipped} skipped (missing data)...\n";
                }
            }
            
        } catch (Exception $e) {
            $errors++;
            if ($errors <= 10) { // Only show first 10 errors
                echo "  ✗ Error processing link {$link['link_id']}: " . $e->getMessage() . "\n";
            }
        }
    }
    
    echo "\n=== Recalculation Complete ===\n";
    echo "Total processed: {$processed}\n";
    echo "Risk scores updated: {$updated}\n";
    echo "Skipped (could not calculate): {$skipped}\n";
    echo "Errors: {$errors}\n";
    
    // Verify results
    $verifySql = "SELECT COUNT(*) as count FROM device_vulnerabilities_link WHERE risk_score IS NULL";
    $verifyResult = $db->query($verifySql, [])->fetch();
    $remainingNull = $verifyResult['count'];
    
    echo "\nRemaining NULL risk scores: {$remainingNull}\n";
    
    if ($remainingNull === 0) {
        echo "✓ All risk scores have been calculated!\n";
    } else {
        echo "⚠ {$remainingNull} links still have NULL risk scores (likely missing required data)\n";
    }
    
    exit(0);
    
} catch (Exception $e) {
    echo "✗ Fatal error: " . $e->getMessage() . "\n";
    echo "Stack trace: " . $e->getTraceAsString() . "\n";
    exit(1);
}




