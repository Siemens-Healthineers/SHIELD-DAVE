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
// Note: HTTP_REFERER may not be set in all cases, so we'll be more lenient
$referer = $_SERVER['HTTP_REFERER'] ?? '';
$host = $_SERVER['HTTP_HOST'] ?? '';
if (!empty($referer) && !empty($host) && strpos($referer, $host) === false) {
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
    
    // Get overdue tasks: scheduled_date < today AND status NOT IN (Completed, Cancelled, Failed)
    $sql = "SELECT 
                st.*,
                stv.device_name,
                stv.location,
                stv.department,
                stv.package_name,
                stv.cve_severity,
                stv.estimated_downtime_display,
                (CURRENT_DATE - DATE(st.scheduled_date))::integer as days_overdue
            FROM scheduled_tasks st
            INNER JOIN scheduled_tasks_view stv ON st.task_id = stv.task_id
            WHERE DATE(st.scheduled_date) < CURRENT_DATE
            AND st.status NOT IN ('Completed', 'Cancelled', 'Failed')
            ORDER BY st.scheduled_date ASC, days_overdue DESC";
    
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute();
    $overdue_tasks = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $overdue_tasks,
        'count' => count($overdue_tasks)
    ]);
    
} catch (Exception $e) {
    error_log("Error in overdue.php: " . $e->getMessage());
    error_log("Stack trace: " . $e->getTraceAsString());
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'OVERDUE_LOAD_FAILED',
            'message' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ],
        'timestamp' => date('c')
    ]);
}
?>

