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
    
    // Get consolidated task ID from query parameter
    $consolidated_task_id = $_GET['consolidated_task_id'] ?? null;
    
    if (!$consolidated_task_id) {
        throw new Exception('Consolidated task ID is required');
    }
    
    // Validate UUID format
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $consolidated_task_id)) {
        throw new Exception('Invalid consolidated task ID format');
    }
    
    // Get all original tasks that were consolidated into this task
    $sql = "SELECT st.*, 
                   CASE
                       WHEN a.hostname IS NOT NULL AND a.hostname != '' THEN a.hostname
                       WHEN a.asset_tag IS NOT NULL AND a.asset_tag != '' THEN a.asset_tag
                       WHEN md.brand_name IS NOT NULL THEN md.brand_name || ' ' || COALESCE(md.model_number, '')
                       ELSE 'Unknown Device'
                   END as device_name,
                   a.location,
                   a.department,
                   l.location_name,
                   -- Format estimated downtime
                   CASE 
                       WHEN st.estimated_downtime IS NULL THEN 'N/A'
                       WHEN st.estimated_downtime = 0 THEN 'No downtime'
                       WHEN st.estimated_downtime < 60 THEN st.estimated_downtime || ' minutes'
                       ELSE ROUND(st.estimated_downtime / 60.0, 1) || ' hours'
                   END as estimated_downtime_display,
                   -- Status class for styling
                   CASE 
                       WHEN st.status = 'Pending' THEN 'pending'
                       WHEN st.status = 'Scheduled' THEN 'scheduled'
                       WHEN st.status = 'In Progress' THEN 'in-progress'
                       WHEN st.status = 'Completed' THEN 'completed'
                       WHEN st.status = 'Cancelled' THEN 'cancelled'
                       WHEN st.status = 'Consolidated' THEN 'consolidated'
                       ELSE 'unknown'
                   END as status_class
            FROM task_consolidation_mapping tcm
            JOIN scheduled_tasks st ON tcm.original_task_id = st.task_id
            LEFT JOIN medical_devices md ON st.device_id = md.device_id
            LEFT JOIN assets a ON md.asset_id = a.asset_id
            LEFT JOIN locations l ON a.location_id = l.location_id
            WHERE tcm.consolidated_task_id = ?
            ORDER BY st.scheduled_date ASC";
    
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute([$consolidated_task_id]);
    $tasks = $stmt->fetchAll();
    
    if (empty($tasks)) {
        throw new Exception('No consolidated tasks found for the given consolidated task ID');
    }
    
    echo json_encode([
        'success' => true,
        'data' => $tasks,
        'message' => 'Consolidated tasks retrieved successfully'
    ]);
    
} catch (Exception $e) {
    error_log("Consolidated Tasks API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'CONSOLIDATED_TASKS_FAILED',
            'message' => $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
}

ob_end_flush();
?>


