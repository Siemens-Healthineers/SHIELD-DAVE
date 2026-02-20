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
    
    $actionId = $_GET['action_id'] ?? null;
    if (!$actionId) {
        echo json_encode(['success' => false, 'error' => 'Action ID required']);
        exit;
    }
    
    // Get affected devices for this action - return ALL devices first, then filter in PHP
    // This ensures we see devices even if the patch_status filter is too strict
    $sql = "SELECT 
                adl.device_id,
                adl.device_risk_score,
                adl.patch_status,
                -- Use real device information from the actual device
                CASE 
                    WHEN a.hostname IS NOT NULL AND a.hostname != '' THEN a.hostname
                    WHEN a.asset_tag IS NOT NULL AND a.asset_tag != '' THEN a.asset_tag
                    WHEN md.device_name IS NOT NULL AND md.device_name != '' THEN md.device_name
                    WHEN md.brand_name IS NOT NULL AND md.brand_name != '' THEN md.brand_name || ' ' || COALESCE(md.model_number, '') || COALESCE(' (' || md.manufacturer_name || ')', '')
                    WHEN a.asset_type IS NOT NULL AND a.asset_type != '' THEN a.asset_type || COALESCE(' ' || a.manufacturer, '') || COALESCE(' ' || a.model, '')
                    WHEN adl.device_id IS NOT NULL THEN 'Device ' || SUBSTRING(adl.device_id::text, 1, 8)
                    ELSE 'Unidentified Device'
                END as device_name,
                COALESCE(l.location_name, 'Location Not Mapped') as location_name,
                COALESCE(a.criticality, 
                    CASE 
                        WHEN adl.device_risk_score >= 1000 THEN 'Clinical-High'
                        WHEN adl.device_risk_score >= 500 THEN 'Business-Medium'
                        ELSE 'Business-Low'
                    END
                ) as device_criticality,
                COALESCE(l.criticality::text, '5') as location_criticality,
                COALESCE(a.status, 'Active') as device_status,
                a.hostname,
                a.asset_tag,
                md.device_id as md_exists,
                md.device_name as md_device_name,
                md.brand_name,
                md.model_number,
                a.asset_id as asset_exists
            FROM action_device_links adl
            LEFT JOIN medical_devices md ON adl.device_id = md.device_id
            LEFT JOIN assets a ON md.asset_id = a.asset_id
            LEFT JOIN locations l ON a.location_id = l.location_id
            WHERE adl.action_id = ?
            ORDER BY COALESCE(adl.device_risk_score, 0) DESC";
    
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute([$actionId]);
    $allDevices = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Filter out completed devices in PHP (more reliable than SQL for edge cases)
    $devices = array_filter($allDevices, function($device) {
        $status = strtoupper(trim($device['patch_status'] ?? ''));
        return empty($status) || $status !== 'COMPLETED';
    });
    $devices = array_values($devices); // Re-index array
    
    echo json_encode([
        'success' => true,
        'data' => $devices
    ]);
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'error' => 'Database error: ' . $e->getMessage()
    ]);
}
?>
