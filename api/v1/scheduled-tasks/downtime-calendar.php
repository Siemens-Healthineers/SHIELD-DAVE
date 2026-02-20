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
    
    // Default to a wider range if not specified
    $start_date = $_GET['start_date'] ?? date('Y-m-d', strtotime('-3 months'));
    $end_date = $_GET['end_date'] ?? date('Y-m-d', strtotime('+3 months'));
    
    // Check if we need to show completed tasks
    $show_completed = isset($_GET['status']) && $_GET['status'] === 'Completed';
    
    if ($show_completed) {
        // Query completed tasks directly - group by completed_at date, not scheduled_date
        $sql = "SELECT 
                    DATE(st.completed_at) as calendar_date,
                    COUNT(*) as total_tasks,
                    COUNT(CASE WHEN st.status = 'Completed' THEN 1 END) as completed_count,
                    SUM(st.estimated_downtime) as total_estimated_downtime,
                    SUM(st.actual_downtime) as total_actual_downtime,
                    COUNT(DISTINCT st.device_id) as affected_devices,
                    COUNT(DISTINCT st.assigned_to) as assigned_users,
                    COUNT(DISTINCT COALESCE(a.location, l.location_name)) as affected_locations,
                    COUNT(DISTINCT a.department) as affected_departments,
                    COUNT(CASE WHEN a.criticality = 'Clinical-High' THEN 1 END) as critical_devices_affected,
                    COUNT(CASE WHEN v.severity = 'Critical' THEN 1 END) as critical_cves,
                    COUNT(CASE WHEN v.severity = 'High' THEN 1 END) as high_cves,
                    0 as scheduled_count,
                    0 as in_progress_count,
                    0 as cancelled_count,
                    0 as failed_count
                FROM scheduled_tasks st
                LEFT JOIN medical_devices md ON st.device_id = md.device_id
                LEFT JOIN assets a ON md.asset_id = a.asset_id
                LEFT JOIN locations l ON a.location_id = l.location_id
                LEFT JOIN vulnerabilities v ON st.cve_id = v.cve_id
                WHERE st.status = 'Completed'
                AND st.completed_at IS NOT NULL
                AND DATE(st.completed_at) >= ?
                AND DATE(st.completed_at) <= ?
                GROUP BY DATE(st.completed_at)
                ORDER BY calendar_date ASC";
        
        $stmt = $db->getConnection()->prepare($sql);
        $stmt->execute([$start_date, $end_date]);
    } else {
        // Use the existing view for active tasks
        $where_conditions[] = "calendar_date >= ?";
        $params[] = $start_date;
        
        $where_conditions[] = "calendar_date <= ?";
        $params[] = $end_date;
        
        // Build the query
        $where_clause = '';
        if (!empty($where_conditions)) {
            $where_clause = 'WHERE ' . implode(' AND ', $where_conditions);
        }
        
        $sql = "SELECT * FROM downtime_calendar_view $where_clause ORDER BY calendar_date ASC";
        
        $stmt = $db->getConnection()->prepare($sql);
        $stmt->execute($params);
    }
    
    $calendar_data = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $calendar_data,
        'count' => count($calendar_data)
    ]);
    
} catch (Exception $e) {
    error_log("Error in downtime-calendar.php: " . $e->getMessage());
    error_log("Stack trace: " . $e->getTraceAsString());
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'CALENDAR_LOAD_FAILED',
            'message' => $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
}
?>







