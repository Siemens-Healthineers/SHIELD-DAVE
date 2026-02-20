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

echo "=== Clear Asset Manufacturers ===\n\n";

try {
    // Get count before clearing
    $beforeCount = $db->query('SELECT COUNT(*) as count FROM assets WHERE manufacturer IS NOT NULL', [])->fetch();
    $beforeTotal = $beforeCount['count'];
    
    echo "Assets with manufacturer before: {$beforeTotal}\n";
    
    // Clear all manufacturer values
    $result = $db->query('UPDATE assets SET manufacturer = NULL, updated_at = CURRENT_TIMESTAMP WHERE manufacturer IS NOT NULL', []);
    
    // Get count after clearing
    $afterCount = $db->query('SELECT COUNT(*) as count FROM assets WHERE manufacturer IS NOT NULL', [])->fetch();
    $afterTotal = $afterCount['count'];
    
    echo "Assets with manufacturer after: {$afterTotal}\n";
    echo "Cleared: " . ($beforeTotal - $afterTotal) . " assets\n\n";
    
    // Show stats for assets that can be looked up
    $stats = $db->query('SELECT COUNT(*) as total, COUNT(manufacturer) as with_manufacturer, COUNT(mac_address) as with_mac FROM assets WHERE mac_address IS NOT NULL AND status = \'Active\'', [])->fetch();
    
    echo "=== Assets Ready for OUI Lookup ===\n";
    echo "Active assets with MAC addresses: {$stats['total']}\n";
    echo "Without manufacturer: " . ($stats['total'] - $stats['with_manufacturer']) . "\n";
    
    echo "\n✓ Manufacturer values cleared successfully!\n";
    echo "You can now run the 'Analyze Assets OUI' task to populate manufacturers.\n";
    
    exit(0);
    
} catch (Exception $e) {
    echo "✗ Error: " . $e->getMessage() . "\n";
    echo "Stack trace: " . $e->getTraceAsString() . "\n";
    exit(1);
}

