<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
ob_start();

require_once __DIR__ . '/../../../config/database.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

// Basic validation - allow requests from the same domain
if (!isset($_SERVER['HTTP_REFERER']) || strpos($_SERVER['HTTP_REFERER'], $_SERVER['HTTP_HOST']) === false) {
    http_response_code(403);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'FORBIDDEN',
            'message' => 'Request must come from the same domain'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

try {
    $db = DatabaseConfig::getInstance();
    
    // Get consolidation opportunities from the view
    $sql = "SELECT * FROM device_task_consolidation_view ORDER BY scheduled_dates, total_downtime DESC";
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute();
    $opportunities = $stmt->fetchAll();
    
    
    // Convert PostgreSQL arrays to proper JSON arrays
    foreach ($opportunities as &$opp) {
        // Debug logging
        error_log("Processing opportunity - approval_statuses: " . var_export($opp['approval_statuses'], true));
        if (isset($opp['task_ids']) && $opp['task_ids'] !== null) {
            if (is_string($opp['task_ids'])) {
                // Convert PostgreSQL array string to PHP array
                $converted = str_replace(['{', '}'], ['[', ']'], $opp['task_ids']);
                // Quote the UUIDs to make valid JSON
                $converted = preg_replace('/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/', '"$1"', $converted);
                $opp['task_ids'] = json_decode($converted, true);
            }
        } else {
            $opp['task_ids'] = [];
        }
        
        if (isset($opp['packages']) && $opp['packages'] !== null) {
            if (is_string($opp['packages'])) {
                $converted = str_replace(['{', '}'], ['[', ']'], $opp['packages']);
                // Handle NULL values in packages array
                $converted = str_replace('NULL', 'null', $converted);
                $opp['packages'] = json_decode($converted, true);
            }
        } else {
            $opp['packages'] = [];
        }
        
        if (isset($opp['cves']) && $opp['cves'] !== null) {
            if (is_string($opp['cves'])) {
                $converted = str_replace(['{', '}'], ['[', ']'], $opp['cves']);
                // Quote the CVE IDs to make valid JSON
                $converted = preg_replace('/(CVE-\d{4}-\d+)/', '"$1"', $converted);
                $opp['cves'] = json_decode($converted, true);
            }
        } else {
            $opp['cves'] = [];
        }
        
        if (isset($opp['task_types']) && $opp['task_types'] !== null) {
            if (is_string($opp['task_types'])) {
                $converted = str_replace(['{', '}'], ['[', ']'], $opp['task_types']);
                // Quote the task types to make valid JSON
                $converted = preg_replace('/([a-zA-Z_]+)/', '"$1"', $converted);
                $opp['task_types'] = json_decode($converted, true);
            }
        } else {
            $opp['task_types'] = [];
        }
        
        if (isset($opp['device_ids']) && $opp['device_ids'] !== null) {
            if (is_string($opp['device_ids'])) {
                $converted = str_replace(['{', '}'], ['[', ']'], $opp['device_ids']);
                // Quote the UUIDs to make valid JSON
                $converted = preg_replace('/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/', '"$1"', $converted);
                $opp['device_ids'] = json_decode($converted, true);
            }
        } else {
            $opp['device_ids'] = [];
        }
        
        if (isset($opp['device_names']) && $opp['device_names'] !== null) {
            if (is_string($opp['device_names'])) {
                // PostgreSQL array format: {"item1","item2","item3"}
                // Convert to JSON array format: ["item1","item2","item3"]
                $converted = str_replace(['{', '}'], ['[', ']'], $opp['device_names']);
                $opp['device_names'] = json_decode($converted, true);
            }
        } else {
            $opp['device_names'] = [];
        }
        
        if (isset($opp['task_details']) && $opp['task_details'] !== null) {
            if (is_string($opp['task_details'])) {
                // PostgreSQL array format: {"item1","item2","item3"}
                // Convert to JSON array format: ["item1","item2","item3"]
                $converted = str_replace(['{', '}'], ['[', ']'], $opp['task_details']);
                $decoded = json_decode($converted, true);
                
                // Parse each JSON object in the array
                if (is_array($decoded)) {
                    $parsed_details = [];
                    foreach ($decoded as $detail) {
                        if (is_string($detail)) {
                            // Fix the malformed JSON that starts with [ instead of {
                            $fixed_detail = $detail;
                            if (strpos($detail, '[') === 0) {
                                $fixed_detail = '{' . substr($detail, 1);
                            }
                            if (substr($fixed_detail, -1) === ']') {
                                $fixed_detail = substr($fixed_detail, 0, -1) . '}';
                            }
                            
                            $parsed = json_decode($fixed_detail, true);
                            if ($parsed !== null) {
                                $parsed_details[] = $parsed;
                            }
                        } else {
                            $parsed_details[] = $detail;
                        }
                    }
                    $opp['task_details'] = $parsed_details;
                } else {
                    $opp['task_details'] = [];
                }
            }
        } else {
            $opp['task_details'] = [];
        }
        
        // Also convert scheduled_dates array
        if (isset($opp['scheduled_dates']) && $opp['scheduled_dates'] !== null) {
            if (is_string($opp['scheduled_dates'])) {
                // PostgreSQL array format: {"item1","item2","item3"}
                // Convert to JSON array format: ["item1","item2","item3"]
                $converted = str_replace(['{', '}'], ['[', ']'], $opp['scheduled_dates']);
                $opp['scheduled_dates'] = json_decode($converted, true);
            }
        } else {
            $opp['scheduled_dates'] = [];
        }
        
        // Convert approval_statuses array
        if (isset($opp['approval_statuses']) && $opp['approval_statuses'] !== null) {
            if (is_string($opp['approval_statuses'])) {
                // PostgreSQL array format: {item1,item2,item3} (unquoted)
                // Convert to JSON array format: ["item1","item2","item3"]
                $converted = str_replace(['{', '}'], ['[', ']'], $opp['approval_statuses']);
                // Manually quote each value
                $converted = str_replace(',', '","', $converted);
                $converted = str_replace('[', '["', $converted);
                $converted = str_replace(']', '"]', $converted);
                $opp['approval_statuses'] = json_decode($converted, true);
            }
        } else {
            $opp['approval_statuses'] = [];
        }
        
        // Convert package_cve_displays array
        if (isset($opp['package_cve_displays']) && $opp['package_cve_displays'] !== null) {
            if (is_string($opp['package_cve_displays'])) {
                // PostgreSQL array format: {item1,"item2","item3"} (mixed quoted/unquoted)
                // Convert to JSON array format: ["item1","item2","item3"]
                $converted = str_replace(['{', '}'], ['[', ']'], $opp['package_cve_displays']);
                
                // Simple approach: split by comma and handle each item
                $items = [];
                $inQuotes = false;
                $currentItem = '';
                $chars = str_split($converted);
                
                for ($i = 0; $i < count($chars); $i++) {
                    $char = $chars[$i];
                    
                    if ($char === '"' && ($i === 0 || $chars[$i-1] !== '\\')) {
                        $inQuotes = !$inQuotes;
                    }
                    
                    if ($char === ',' && !$inQuotes) {
                        $items[] = trim($currentItem);
                        $currentItem = '';
                    } else {
                        $currentItem .= $char;
                    }
                }
                
                if ($currentItem !== '') {
                    $items[] = trim($currentItem);
                }
                
                // Clean up the items
                $cleanedItems = [];
                foreach ($items as $item) {
                    $item = trim($item);
                    if ($item === '[' || $item === ']') continue;
                    
                    // Remove surrounding quotes if present
                    if (preg_match('/^"(.*)"$/', $item, $matches)) {
                        $cleanedItems[] = $matches[1];
                    } else {
                        // Remove any remaining brackets
                        $item = str_replace(['[', ']'], '', $item);
                        $cleanedItems[] = $item;
                    }
                }
                
                $opp['package_cve_displays'] = $cleanedItems;
            }
        } else {
            $opp['package_cve_displays'] = [];
        }
    }
    
    echo json_encode([
        'success' => true,
        'data' => $opportunities,
        'count' => count($opportunities)
    ]);

} catch (Exception $e) {
    error_log("Consolidation Opportunities API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'CONSOLIDATION_OPPORTUNITIES_FAILED',
            'message' => $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
}

ob_end_flush();
?>
