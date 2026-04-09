<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Background script for auto-mapping devices to FDA database
if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../services/shell_command_utilities.php';

// Get command line arguments
$userId = $argv[1] ?? null;
$outputFile = $argv[2] ?? '/tmp/automap_' . uniqid() . '.json';

if (!$userId) {
    error_log("Auto-map script: User ID required");
    exit(1);
}

$db = DatabaseConfig::getInstance();

try {
    $result = [
        'success' => true,
        'mapped' => 0,
        'skipped' => 0,
        'errors' => [],
        'timestamp' => date('c')
    ];
    
    // Get unmapped assets with manufacturer information
    $sql = "SELECT asset_id, manufacturer, model, hostname
            FROM assets 
            WHERE asset_id NOT IN (SELECT asset_id FROM medical_devices) 
            AND status = 'Active' 
            AND manufacturer IS NOT NULL 
            AND manufacturer != ''
            LIMIT 100"; // Limit to prevent excessive processing
    
    $stmt = $db->query($sql);
    $assets = $stmt->fetchAll();
    
    error_log("Auto-map: Processing " . count($assets) . " assets");
    
    foreach ($assets as $asset) {
        try {
            // Search FDA database
            $command = "cd " . _ROOT . " && python3 python/services/fda_integration.py search_devices " . 
                       escapeshellarg($asset['manufacturer']) . " " . 
                       escapeshellarg($asset['model']) . " 50";
            
            $cmdResult = ShellCommandUtilities::executeShellCommand($command, [
                'blocking' => true,
                'timeout' => 30
            ]);
            
            if (!$cmdResult['success'] || !$cmdResult['output']) {
                $result['skipped']++;
                $result['errors'][] = "Asset {$asset['asset_id']}: Failed to search FDA database";
                continue;
            }
            
            $devices = json_decode($cmdResult['output'], true);
            if (!$devices || count($devices) === 0) {
                $result['skipped']++;
                continue;
            }
            
            // Use the device with highest confidence
            $bestDevice = $devices[0];
            foreach ($devices as $device) {
                if (($device['confidence_score'] ?? 0) > ($bestDevice['confidence_score'] ?? 0)) {
                    $bestDevice = $device;
                }
            }
            
            // Only auto-map if confidence is high enough
            if (($bestDevice['confidence_score'] ?? 0) < 0.7) {
                $result['skipped']++;
                continue;
            }
            
            // Extract K number if available
            $kNumber = '';
            if (isset($bestDevice['premarket_submissions']) && is_array($bestDevice['premarket_submissions'])) {
                foreach ($bestDevice['premarket_submissions'] as $submission) {
                    if (isset($submission['submission_number']) && strpos($submission['submission_number'], 'K') === 0) {
                        $kNumber = $submission['submission_number'];
                        break;
                    }
                }
            }
            
            // Insert device mapping
            $insertSql = "INSERT INTO medical_devices (
                asset_id, device_identifier, brand_name, model_number, 
                manufacturer_name, device_description, gmdn_term, 
                is_implantable, fda_class, udi, mapping_confidence, mapping_method, 
                mapped_by, mapped_at, k_number
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'automatic', ?, CURRENT_TIMESTAMP, ?)";
            
            $insertStmt = $db->prepare($insertSql);
            $insertStmt->execute([
                $asset['asset_id'],
                $bestDevice['device_identifier'] ?? '',
                $bestDevice['brand_name'] ?? '',
                $bestDevice['model_number'] ?? '',
                $bestDevice['manufacturer_name'] ?? '',
                $bestDevice['device_description'] ?? '',
                $bestDevice['gmdn_term'] ?? '',
                $bestDevice['is_implantable'] ?? false,
                $bestDevice['fda_class'] ?? '',
                $bestDevice['udi'] ?? '',
                $bestDevice['confidence_score'] ?? 0.0,
                $userId,
                $kNumber
            ]);
            
            $result['mapped']++;
            error_log("Auto-map: Mapped asset {$asset['asset_id']} ({$asset['hostname']}) with confidence " . 
                     ($bestDevice['confidence_score'] ?? 0));
            
        } catch (Exception $e) {
            $result['errors'][] = "Asset {$asset['asset_id']}: " . $e->getMessage();
            error_log("Auto-map error for asset {$asset['asset_id']}: " . $e->getMessage());
        }
    }
    
    // Write results to output file
    file_put_contents($outputFile, json_encode($result));
    error_log("Auto-map complete: {$result['mapped']} mapped, {$result['skipped']} skipped, " . 
             count($result['errors']) . " errors");
    
    exit(0);
    
} catch (Exception $e) {
    error_log("Auto-map fatal error: " . $e->getMessage());
    file_put_contents($outputFile, json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'mapped' => 0,
        'skipped' => 0,
        'errors' => [$e->getMessage()]
    ]));
    exit(1);
}
