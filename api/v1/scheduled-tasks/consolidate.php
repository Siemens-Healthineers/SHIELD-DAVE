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

// UUID generation function
function generateUUID() {
    return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
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
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        throw new Exception('Invalid JSON input');
    }
    
    // Validate required fields
    if (!isset($input['task_ids']) || !is_array($input['task_ids']) || count($input['task_ids']) < 2) {
        throw new Exception('At least 2 task IDs are required for consolidation');
    }
    
    $task_ids = $input['task_ids'];
    $consolidated_time = $input['consolidated_time'] ?? null;
    $consolidated_date = $input['consolidated_date'] ?? null;
    
    // Validate task IDs are UUIDs
    foreach ($task_ids as $task_id) {
        if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $task_id)) {
            throw new Exception('Invalid task ID format: ' . $task_id);
        }
    }
    
    // Get task details for validation and original information
    $placeholders = str_repeat('?,', count($task_ids) - 1) . '?';
    $sql = "SELECT task_id, device_id, scheduled_date, estimated_downtime, status, task_type, assigned_to, assigned_by,
                   task_description, notes, package_id, cve_id, action_id, recall_id, patch_id,
                   original_action_description, original_action_patch_reference, original_action_target_version,
                   original_action_type, original_action_vendor, original_brand_name, original_cve_description,
                   original_cve_id, original_cve_modified_date, original_cve_published_date, original_cve_severity,
                   original_cvss_v3_score, original_department, original_device_identifier, original_device_name,
                   original_fda_recall_number, original_hostname, original_ip_address, original_k_number,
                   original_location, original_manufacturer_name, original_model_number, original_patch_description,
                   original_patch_name, original_patch_release_date, original_patch_requires_reboot,
                   original_patch_type, original_patch_vendor, original_patch_version, original_product_code,
                   original_product_description, original_reason_for_recall, original_recall_date,
                   original_recall_status, original_udi
            FROM scheduled_tasks 
            WHERE task_id IN ($placeholders)";
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute($task_ids);
    $tasks = $stmt->fetchAll();
    
    if (count($tasks) !== count($task_ids)) {
        throw new Exception('One or more tasks not found');
    }
    
    // Validate all tasks are on the same device
    $device_ids = array_unique(array_column($tasks, 'device_id'));
    if (count($device_ids) > 1) {
        throw new Exception('All tasks must be on the same device for consolidation');
    }
    
    // Validate all tasks are in a consolidatable status
    $valid_statuses = ['Scheduled', 'In Progress'];
    foreach ($tasks as $task) {
        if (!in_array($task['status'], $valid_statuses)) {
            throw new Exception('Task ' . $task['task_id'] . ' is not in a consolidatable status');
        }
    }
    
    $device_id = $device_ids[0];
    
    // Get assigned user from the first task (assuming all tasks are assigned to the same user)
    $assigned_to = $tasks[0]['assigned_to'];
    $assigned_by = $tasks[0]['assigned_by'];
    
    // Calculate consolidated time if not provided
    if (!$consolidated_time || !$consolidated_date) {
        $earliest_time = min(array_column($tasks, 'scheduled_date'));
        $consolidated_time = $earliest_time;
        $consolidated_date = date('Y-m-d', strtotime($consolidated_time));
    } else {
        $consolidated_time = $consolidated_date . ' ' . $consolidated_time;
    }
    
    // Calculate total downtime
    $total_downtime = array_sum(array_column($tasks, 'estimated_downtime'));
    
    // Preload patch details for tasks that reference patches
    $patchIdList = array_values(array_filter(array_unique(array_column($tasks, 'patch_id'))));
    $patchById = [];
    if (!empty($patchIdList)) {
        $placeholdersPatch = str_repeat('?,', count($patchIdList) - 1) . '?';
        $patchSql = "SELECT patch_id, patch_name, patch_type, target_device_type, target_package_id, target_version, cve_list, description, release_date, vendor, kb_article, download_url, install_instructions, prerequisites, estimated_install_time, requires_reboot, estimated_downtime FROM patches WHERE patch_id IN ($placeholdersPatch)";
        $patchStmt = $db->getConnection()->prepare($patchSql);
        $patchStmt->execute($patchIdList);
        while ($row = $patchStmt->fetch(PDO::FETCH_ASSOC)) {
            $patchById[$row['patch_id']] = $row;
        }
    }

    // Collect detailed information from each task for the consolidated task
    $consolidated_details = [];
    foreach ($tasks as $task) {
        $patchRow = null;
        if (!empty($task['patch_id']) && isset($patchById[$task['patch_id']])) {
            $patchRow = $patchById[$task['patch_id']];
        }
        $task_details = [
            'task_id' => $task['task_id'],
            'task_type' => $task['task_type'],
            'task_description' => $task['task_description'],
            'notes' => $task['notes'],
            'scheduled_date' => $task['scheduled_date'],
            'estimated_downtime' => $task['estimated_downtime'],
            'package_id' => $task['package_id'],
            'cve_id' => $task['cve_id'],
            'action_id' => $task['action_id'],
            'recall_id' => $task['recall_id'],
            'patch_id' => $task['patch_id'],
            'original_information' => [
                'action' => [
                    'description' => $task['original_action_description'],
                    'patch_reference' => $task['original_action_patch_reference'],
                    'target_version' => $task['original_action_target_version'],
                    'type' => $task['original_action_type'],
                    'vendor' => $task['original_action_vendor']
                ],
                'cve' => [
                    'id' => $task['original_cve_id'],
                    'description' => $task['original_cve_description'],
                    'severity' => $task['original_cve_severity'],
                    'cvss_v3_score' => $task['original_cvss_v3_score'],
                    'published_date' => $task['original_cve_published_date'],
                    'modified_date' => $task['original_cve_modified_date']
                ],
                'device' => [
                    'name' => $task['original_device_name'],
                    'brand_name' => $task['original_brand_name'],
                    'model_number' => $task['original_model_number'],
                    'device_identifier' => $task['original_device_identifier'],
                    'k_number' => $task['original_k_number'],
                    'udi' => $task['original_udi'],
                    'hostname' => $task['original_hostname'],
                    'ip_address' => $task['original_ip_address'],
                    'location' => $task['original_location'],
                    'department' => $task['original_department']
                ],
                'patch' => array_filter([
                    'name' => $task['original_patch_name'] ?? ($patchRow['patch_name'] ?? null),
                    'type' => $task['original_patch_type'] ?? ($patchRow['patch_type'] ?? null),
                    'vendor' => $task['original_patch_vendor'] ?? ($patchRow['vendor'] ?? null),
                    'version' => $task['original_patch_version'] ?? ($patchRow['target_version'] ?? null),
                    'description' => $task['original_patch_description'] ?? ($patchRow['description'] ?? null),
                    'release_date' => $task['original_patch_release_date'] ?? ($patchRow['release_date'] ?? null),
                    'requires_reboot' => $task['original_patch_requires_reboot'] ?? ($patchRow['requires_reboot'] ?? null),
                    'kb_article' => $patchRow['kb_article'] ?? null,
                    'download_url' => $patchRow['download_url'] ?? null,
                    'install_instructions' => $patchRow['install_instructions'] ?? null,
                    'prerequisites' => $patchRow['prerequisites'] ?? null,
                    'estimated_install_time' => $patchRow['estimated_install_time'] ?? null,
                    'estimated_downtime' => $patchRow['estimated_downtime'] ?? null,
                    'target_device_type' => $patchRow['target_device_type'] ?? null,
                    'target_package_id' => $patchRow['target_package_id'] ?? null,
                    'cve_list' => $patchRow['cve_list'] ?? null,
                ]),
                'recall' => [
                    'fda_recall_number' => $task['original_fda_recall_number'],
                    'manufacturer_name' => $task['original_manufacturer_name'],
                    'product_description' => $task['original_product_description'],
                    'product_code' => $task['original_product_code'],
                    'recall_date' => $task['original_recall_date'],
                    'reason_for_recall' => $task['original_reason_for_recall'],
                    'recall_status' => $task['original_recall_status']
                ]
            ]
        ];
        $consolidated_details[] = $task_details;
    }
    
    // Start transaction
    $db->getConnection()->beginTransaction();
    
    try {
        // Create a new consolidated task
        $consolidated_task_id = generateUUID();
        
        // Get device and asset information for the consolidated task
        $device_sql = "SELECT md.device_id, a.asset_id, a.hostname, a.location_id, l.location_name
                       FROM medical_devices md
                       LEFT JOIN assets a ON md.asset_id = a.asset_id
                       LEFT JOIN locations l ON a.location_id = l.location_id
                       WHERE md.device_id = ?";
        $device_stmt = $db->getConnection()->prepare($device_sql);
        $device_stmt->execute([$device_id]);
        $device_info = $device_stmt->fetch();
        
        // Derive package_id from original tasks
        // Priority: 1. Direct package_id from tasks, 2. target_package_id from patches
        $consolidated_package_id = null;
        
        // First, check if any original task has a direct package_id
        foreach ($tasks as $task) {
            if (!empty($task['package_id'])) {
                $consolidated_package_id = $task['package_id'];
                break; // Use first found package_id
            }
        }
        
        // If no direct package_id, try to get from patches.target_package_id
        if (!$consolidated_package_id && !empty($patchIdList)) {
            $package_sql = "SELECT DISTINCT target_package_id 
                           FROM patches 
                           WHERE patch_id IN ($placeholdersPatch) 
                           AND target_package_id IS NOT NULL 
                           LIMIT 1";
            $package_stmt = $db->getConnection()->prepare($package_sql);
            $package_stmt->execute($patchIdList);
            $package_result = $package_stmt->fetch();
            if ($package_result && !empty($package_result['target_package_id'])) {
                $consolidated_package_id = $package_result['target_package_id'];
            }
        }
        
        // Create consolidated task
        $consolidated_sql = "INSERT INTO scheduled_tasks 
                            (task_id, task_type, package_id, device_id, assigned_to, assigned_by, scheduled_date, estimated_downtime, 
                             status, task_description, notes, created_at, updated_at)
                            VALUES (?, 'package_remediation', ?, ?, ?, ?, ?, ?, 'Scheduled', ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)";
        
        $consolidated_description = "Consolidated task containing " . count($tasks) . " individual tasks";
        $consolidated_notes = "Consolidated from tasks: " . implode(', ', $task_ids) . "\n\n" . 
                             "DETAILED TASK INFORMATION:\n" . 
                             json_encode($consolidated_details, JSON_PRETTY_PRINT);
        
        $consolidated_stmt = $db->getConnection()->prepare($consolidated_sql);
        $consolidated_stmt->execute([
            $consolidated_task_id,
            $consolidated_package_id, // package_id (can be null)
            $device_id,
            $assigned_to,
            $assigned_by,
            $consolidated_time,
            $total_downtime,
            $consolidated_description,
            $consolidated_notes
        ]);
        
        // Create a mapping table to track consolidated tasks
        $mapping_sql = "CREATE TABLE IF NOT EXISTS task_consolidation_mapping (
                        consolidated_task_id UUID NOT NULL,
                        original_task_id UUID NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (consolidated_task_id, original_task_id),
                        FOREIGN KEY (consolidated_task_id) REFERENCES scheduled_tasks(task_id) ON DELETE CASCADE,
                        FOREIGN KEY (original_task_id) REFERENCES scheduled_tasks(task_id) ON DELETE CASCADE
                        )";
        $db->getConnection()->exec($mapping_sql);
        
        // Insert mapping records
        $mapping_insert_sql = "INSERT INTO task_consolidation_mapping (consolidated_task_id, original_task_id) VALUES (?, ?)";
        $mapping_stmt = $db->getConnection()->prepare($mapping_insert_sql);
        
        foreach ($task_ids as $original_task_id) {
            $mapping_stmt->execute([$consolidated_task_id, $original_task_id]);
        }
        
        // (Deprecated) marking originals; we will delete originals after capturing their details
        
        // Get consolidated task details
        $consolidated_sql = "SELECT st.*, 
                                   CASE
                                       WHEN a.hostname IS NOT NULL AND a.hostname != '' THEN a.hostname
                                       WHEN a.asset_tag IS NOT NULL AND a.asset_tag != '' THEN a.asset_tag
                                       WHEN md.brand_name IS NOT NULL THEN md.brand_name || ' ' || COALESCE(md.model_number, '')
                                       ELSE 'Unknown Device'
                                   END as device_name,
                                   a.location,
                                   a.department,
                                   l.location_name
                            FROM scheduled_tasks st
                            LEFT JOIN medical_devices md ON st.device_id = md.device_id
                            LEFT JOIN assets a ON md.asset_id = a.asset_id
                            LEFT JOIN locations l ON a.location_id = l.location_id
                            WHERE st.task_id = ?";
        
        $consolidated_stmt = $db->getConnection()->prepare($consolidated_sql);
        $consolidated_stmt->execute([$consolidated_task_id]);
        $consolidated_task = $consolidated_stmt->fetch();
        
        // Get original task details for reference
        $original_sql = "SELECT st.*, 
                                CASE
                                    WHEN a.hostname IS NOT NULL AND a.hostname != '' THEN a.hostname
                                    WHEN a.asset_tag IS NOT NULL AND a.asset_tag != '' THEN a.asset_tag
                                    WHEN md.brand_name IS NOT NULL THEN md.brand_name || ' ' || COALESCE(md.model_number, '')
                                    ELSE 'Unknown Device'
                                END as device_name,
                                a.location,
                                a.department
                         FROM scheduled_tasks st
                         LEFT JOIN medical_devices md ON st.device_id = md.device_id
                         LEFT JOIN assets a ON md.asset_id = a.asset_id
                         WHERE st.task_id IN ($placeholders)";
        
        $original_stmt = $db->getConnection()->prepare($original_sql);
        $original_stmt->execute($task_ids);
        $original_tasks = $original_stmt->fetchAll();

        // Mark original tasks as 'Consolidated' instead of deleting them
        // This preserves them for the completion function while hiding them from normal views
        $update_sql = "UPDATE scheduled_tasks 
                       SET status = 'Consolidated',
                           updated_at = CURRENT_TIMESTAMP
                       WHERE task_id IN ($placeholders)";
        $update_stmt = $db->getConnection()->prepare($update_sql);
        $update_stmt->execute($task_ids);
        
        $db->getConnection()->commit();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'consolidated_task' => $consolidated_task,
                'original_tasks' => $original_tasks,
                'consolidated_time' => $consolidated_time,
                'total_downtime' => $total_downtime,
                'consolidated_task_id' => $consolidated_task_id
            ],
            'message' => 'Tasks consolidated successfully'
        ]);
        
    } catch (Exception $e) {
        $db->getConnection()->rollBack();
        throw $e;
    }

} catch (Exception $e) {
    error_log("Task Consolidation API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'CONSOLIDATION_FAILED',
            'message' => $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
}

ob_end_flush();
?>


