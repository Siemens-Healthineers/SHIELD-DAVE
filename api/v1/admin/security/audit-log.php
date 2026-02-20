<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../../config/config.php';
require_once __DIR__ . '/../../../../includes/auth.php';
require_once __DIR__ . '/../../../../includes/security-audit.php';

// Set JSON response headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Initialize authentication
$auth = new Auth();
$auth->requireAuth();

// Check if user has admin privileges
$user = $_SESSION['user'] ?? [];
if (!isset($user['role']) || strtolower($user['role']) !== 'admin') {
    http_response_code(403);
    echo json_encode(['error' => 'Admin access required']);
    exit();
}

// Initialize services
$securityAudit = new SecurityAudit();

// Get request method and path
$method = $_SERVER['REQUEST_METHOD'];
$path = $_SERVER['PATH_INFO'] ?? '';

try {
    switch ($method) {
        case 'GET':
            handleGetRequest($securityAudit, $path);
            break;
        case 'POST':
            handlePostRequest($securityAudit, $path);
            break;
        default:
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            break;
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error: ' . $e->getMessage()]);
}

/**
 * Handle GET requests
 */
function handleGetRequest($securityAudit, $path) {
    switch ($path) {
        case '':
        case '/':
            // Get audit trail with filters
            $filters = [
                'event_type' => $_GET['event_type'] ?? null,
                'user_id' => $_GET['user_id'] ?? null,
                'username' => $_GET['username'] ?? null,
                'ip_address' => $_GET['ip_address'] ?? null,
                'start_date' => $_GET['start_date'] ?? null,
                'end_date' => $_GET['end_date'] ?? null,
                'limit' => (int) ($_GET['limit'] ?? 100)
            ];
            
            $auditTrail = $securityAudit->getAuditTrail($filters);
            
            echo json_encode([
                'success' => true,
                'data' => $auditTrail,
                'count' => count($auditTrail)
            ]);
            break;
            
        case '/recent':
            // Get recent security events
            $limit = (int) ($_GET['limit'] ?? 20);
            $events = $securityAudit->getRecentEvents($limit);
            
            echo json_encode([
                'success' => true,
                'data' => $events
            ]);
            break;
            
        case '/statistics':
            // Get audit statistics
            $days = (int) ($_GET['days'] ?? 30);
            $stats = $securityAudit->getAuditStatistics($days);
            
            echo json_encode([
                'success' => true,
                'data' => $stats
            ]);
            break;
            
        case '/export':
            // Export audit log to CSV
            $startDate = $_GET['start_date'] ?? date('Y-m-d', strtotime('-30 days'));
            $endDate = $_GET['end_date'] ?? date('Y-m-d');
            
            $filters = [
                'event_type' => $_GET['event_type'] ?? null,
                'user_id' => $_GET['user_id'] ?? null,
                'username' => $_GET['username'] ?? null,
                'ip_address' => $_GET['ip_address'] ?? null
            ];
            
            $csv = $securityAudit->exportAuditLog($startDate, $endDate, $filters);
            
            // Set CSV headers
            header('Content-Type: text/csv');
            header('Content-Disposition: attachment; filename="security_audit_log_' . $startDate . '_to_' . $endDate . '.csv"');
            echo $csv;
            exit();
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

/**
 * Handle POST requests
 */
function handlePostRequest($securityAudit, $path) {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON input']);
        return;
    }
    
    switch ($path) {
        case '/log':
            // Manually log an audit event
            $eventType = $input['event_type'] ?? '';
            $userId = $input['user_id'] ?? null;
            $description = $input['description'] ?? '';
            $metadata = $input['metadata'] ?? null;
            $ipAddress = $input['ip_address'] ?? null;
            $username = $input['username'] ?? null;
            
            if (empty($eventType) || empty($description)) {
                http_response_code(400);
                echo json_encode(['error' => 'Event type and description are required']);
                return;
            }
            
            if ($securityAudit->logEvent($eventType, $userId, $description, $metadata, $ipAddress, $username)) {
                echo json_encode([
                    'success' => true,
                    'message' => 'Audit event logged successfully'
                ]);
            } else {
                http_response_code(500);
                echo json_encode([
                    'success' => false,
                    'error' => 'Failed to log audit event'
                ]);
            }
            break;
            
        case '/cleanup':
            // Clean up old audit logs
            $daysOld = (int) ($input['days_old'] ?? 90);
            $deletedCount = $securityAudit->cleanupAuditLogs($daysOld);
            
            echo json_encode([
                'success' => true,
                'message' => "Cleaned up {$deletedCount} old audit log entries",
                'deleted_count' => $deletedCount
            ]);
            break;
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}


