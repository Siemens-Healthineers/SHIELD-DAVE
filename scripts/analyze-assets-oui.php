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
require_once __DIR__ . '/../includes/oui-lookup.php';

$db = DatabaseConfig::getInstance();

echo "=== OUI Analysis for Assets ===\n";
echo "Analyzing assets with MAC addresses but no manufacturer...\n\n";

try {
    // Get assets that need OUI lookup
    $sql = "SELECT asset_id, hostname, ip_address, mac_address, manufacturer 
            FROM assets 
            WHERE mac_address IS NOT NULL 
            AND (manufacturer IS NULL OR manufacturer = '')
            AND status = 'Active'
            ORDER BY last_seen DESC";
    
    $stmt = $db->query($sql, []);
    $assets = $stmt->fetchAll();
    
    $totalAssets = count($assets);
    echo "Found {$totalAssets} assets that need manufacturer lookup\n\n";
    
    if ($totalAssets === 0) {
        echo "No assets need manufacturer lookup.\n";
        exit(0);
    }
    
    $processed = 0;
    $updated = 0;
    $skipped = 0;
    $errors = 0;
    
    foreach ($assets as $asset) {
        $processed++;
        
        try {
            echo "[{$processed}/{$totalAssets}] Processing asset {$asset['asset_id']}... ";
            echo "(MAC: {$asset['mac_address']}, IP: {$asset['ip_address']})\n";
            
            // Look up manufacturer
            $manufacturer = lookupManufacturerFromMac($asset['mac_address']);
            
            if (!empty($manufacturer)) {
                // Update asset with manufacturer
                $updateSql = "UPDATE assets 
                             SET manufacturer = ?, 
                                 updated_at = CURRENT_TIMESTAMP 
                             WHERE asset_id = ?";
                $db->query($updateSql, [$manufacturer, $asset['asset_id']]);
                
                echo "  ✓ Found manufacturer: {$manufacturer}\n";
                $updated++;
            } else {
                echo "  - No manufacturer found for MAC address\n";
                $skipped++;
            }
            
        } catch (Exception $e) {
            echo "  ✗ Error: " . $e->getMessage() . "\n";
            $errors++;
        }
        
        // Add small delay to respect rate limits
        if ($processed % 10 === 0) {
            sleep(1); // Brief pause every 10 lookups
        }
    }
    
    echo "\n=== Analysis Complete ===\n";
    echo "Total processed: {$processed}\n";
    echo "Manufacturers found and updated: {$updated}\n";
    echo "No manufacturer found: {$skipped}\n";
    echo "Errors: {$errors}\n";
    
    exit(0);
    
} catch (Exception $e) {
    echo "Fatal error: " . $e->getMessage() . "\n";
    echo "Stack trace: " . $e->getTraceAsString() . "\n";
    exit(1);
}

