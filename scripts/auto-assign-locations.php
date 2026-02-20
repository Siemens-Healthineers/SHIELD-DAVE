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
require_once __DIR__ . '/../includes/location-assignment.php';

echo "==========================================================\n";
echo "Auto-Assign Locations to Assets Based on IP Address\n";
echo "==========================================================\n\n";

$db = DatabaseConfig::getInstance();

try {
    // Get all assets with IP addresses but no location_id
    $sql = "SELECT asset_id, hostname, ip_address 
            FROM assets 
            WHERE ip_address IS NOT NULL 
              AND location_id IS NULL
            ORDER BY hostname";
    
    $stmt = $db->query($sql);
    $assets = $stmt->fetchAll();
    
    if (empty($assets)) {
        echo "✓ No unassigned assets found.\n";
        exit(0);
    }
    
    echo "Found " . count($assets) . " asset(s) with IP addresses but no location assignment.\n\n";
    
    $assignedCount = 0;
    $notFoundCount = 0;
    
    foreach ($assets as $asset) {
        echo "Processing: " . $asset['hostname'] . " (" . $asset['ip_address'] . ")... ";
        
        $result = autoAssignAssetLocation($db, $asset['asset_id'], $asset['ip_address']);
        
        if ($result['success']) {
            echo "✓ Assigned to: " . $result['location_name'] . "\n";
            $assignedCount++;
        } else {
            echo "✗ " . $result['error'] . "\n";
            $notFoundCount++;
        }
    }
    
    echo "\n==========================================================\n";
    echo "Summary:\n";
    echo "  Total assets processed: " . count($assets) . "\n";
    echo "  Successfully assigned:  " . $assignedCount . "\n";
    echo "  No location found:      " . $notFoundCount . "\n";
    echo "==========================================================\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
}
