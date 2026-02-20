<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

require_once __DIR__ . '/../../../config/database.php';

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
    
    // Get filter parameters
    $filters = [];
    $where_conditions = [];
    $params = [];
    
    if (isset($_GET['assigned_to']) && !empty($_GET['assigned_to'])) {
        $where_conditions[] = "st.assigned_to = ?";
        $params[] = $_GET['assigned_to'];
    }
    
    // Status filtering
    // Always exclude 'Consolidated' tasks from normal views (they are linked via consolidation mapping)
    $where_conditions[] = "st.status != 'Consolidated'";
    
    $includeCompleted = isset($_GET['include_completed']) && ($_GET['include_completed'] === '1' || $_GET['include_completed'] === 'true');
    if (isset($_GET['status']) && !empty($_GET['status']) && $_GET['status'] !== 'all') {
        $where_conditions[] = "st.status = ?";
        $params[] = $_GET['status'];
    } else if (!$includeCompleted) {
        // Default: show only active tasks (Scheduled + In Progress)
        $where_conditions[] = "st.status IN ('Scheduled','In Progress')";
    }
    
    // Support filtering by scheduled_date (for active tasks) or completed_at (for completed tasks)
    if (isset($_GET['completed_date_from']) && !empty($_GET['completed_date_from'])) {
        $where_conditions[] = "st.completed_at >= ?";
        $params[] = $_GET['completed_date_from'];
    }
    
    if (isset($_GET['completed_date_to']) && !empty($_GET['completed_date_to'])) {
        $where_conditions[] = "st.completed_at <= ?";
        $params[] = $_GET['completed_date_to'];
    }
    
    // Only use scheduled_date filtering if completed_date filters are not set
    if (!isset($_GET['completed_date_from']) && !isset($_GET['completed_date_to'])) {
        if (isset($_GET['date_from']) && !empty($_GET['date_from'])) {
            $where_conditions[] = "st.scheduled_date >= ?";
            $params[] = $_GET['date_from'];
        }
        
        if (isset($_GET['date_to']) && !empty($_GET['date_to'])) {
            $where_conditions[] = "st.scheduled_date <= ?";
            $params[] = $_GET['date_to'];
        }
    }
    
    // Note: Location and department filters would need joins - for now keep simple
    // Package name and severity would also need joins - simplified for now
    // These filters may not work perfectly until view is updated, but basic functionality will work
    
    // Build the query
    // Query directly from scheduled_tasks with joins to ensure completed_by fields are included
    // since the view may not have them updated yet
    $where_clause = '';
    if (!empty($where_conditions)) {
        // Replace scheduled_tasks_view columns with scheduled_tasks columns
        $where_clause = 'WHERE ' . implode(' AND ', $where_conditions);
    }
    
    // Use direct query with joins to ensure completed_by fields are included
    // Also include device_name and location from related tables
    $sql = "SELECT st.*,
            u_assigned.username AS assigned_to_username,
            u_assigned.email AS assigned_to_email,
            u_creator.username AS assigned_by_username,
            u_creator.email AS assigned_by_email,
            u_approver.username AS approval_by_username,
            u_approver.email AS approval_by_email,
            u_completed.username AS completed_by_username,
            u_completed.email AS completed_by_email,
            CASE
                WHEN st.original_device_name IS NOT NULL AND st.original_device_name != '' THEN st.original_device_name
                WHEN a.hostname IS NOT NULL AND a.hostname != '' THEN a.hostname
                WHEN a.asset_tag IS NOT NULL AND a.asset_tag != '' THEN a.asset_tag
                WHEN md.brand_name IS NOT NULL THEN md.brand_name || ' ' || COALESCE(md.model_number, '')
                WHEN st.original_brand_name IS NOT NULL AND st.original_brand_name != '' THEN st.original_brand_name || ' ' || COALESCE(st.original_model_number, '')
                ELSE 'Unknown Device'
            END AS device_name,
            CASE
                WHEN st.original_location IS NOT NULL AND st.original_location != '' THEN st.original_location
                WHEN a.location IS NOT NULL AND a.location != '' THEN a.location
                WHEN l.location_name IS NOT NULL AND l.location_name != '' THEN l.location_name
                ELSE NULL
            END AS location,
            COALESCE(st.original_department, a.department) AS department,
            a.criticality AS device_criticality
        FROM scheduled_tasks st
        LEFT JOIN users u_assigned ON st.assigned_to = u_assigned.user_id
        LEFT JOIN users u_creator ON st.assigned_by = u_creator.user_id
        LEFT JOIN users u_approver ON st.department_approval_by = u_approver.user_id
        LEFT JOIN users u_completed ON st.completed_by = u_completed.user_id
        LEFT JOIN medical_devices md ON st.device_id = md.device_id
        LEFT JOIN assets a ON md.asset_id = a.asset_id
        LEFT JOIN locations l ON a.location_id = l.location_id
        $where_clause 
        ORDER BY st.scheduled_date DESC";
    
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute($params);
    $tasks = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo json_encode([
        'success' => true,
        'data' => $tasks,
        'count' => count($tasks)
    ]);
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'TASK_LOAD_FAILED',
            'message' => $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
}
?>
