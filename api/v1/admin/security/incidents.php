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
require_once __DIR__ . '/../../../../includes/security-monitor.php';
require_once __DIR__ . '/../../../../includes/security-audit.php';
require_once __DIR__ . '/../../../../includes/security-settings.php';

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
$securityMonitor = new SecurityMonitor();
$securityAudit = new SecurityAudit();

// Get request method and path
$method = $_SERVER['REQUEST_METHOD'];
$path = $_SERVER['PATH_INFO'] ?? '';
$action = $_GET['action'] ?? '';


try {
    // Handle action-based routing for POST requests
    if ($method === 'POST' && !empty($action)) {
        handlePostRequest($securityMonitor, $securityAudit, "/$action");
    } else {
        switch ($method) {
            case 'GET':
                handleGetRequest($securityMonitor, $path);
                break;
            case 'POST':
                handlePostRequest($securityMonitor, $securityAudit, $path);
                break;
            default:
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed']);
                break;
        }
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error: ' . $e->getMessage()]);
}

/**
 * Handle GET requests
 */
function handleGetRequest($securityMonitor, $path) {
    switch ($path) {
        case '':
        case '/':
            // Get security incidents
            $status = $_GET['status'] ?? null;
            $severity = $_GET['severity'] ?? null;
            $limit = (int) ($_GET['limit'] ?? 50);
            
            $incidents = $securityMonitor->getSecurityIncidents($status, $severity, $limit);
            
            echo json_encode([
                'success' => true,
                'data' => $incidents
            ]);
            break;
            
        case '/metrics':
            // Get security metrics
            $metrics = $securityMonitor->getSecurityMetrics();
            
            echo json_encode([
                'success' => true,
                'data' => $metrics
            ]);
            break;
            
        case '/lockdown-status':
            // Get system lockdown status
            $securitySettings = new SecuritySettings();
            $lockdownStatus = $securitySettings->isSystemLockedDown();
            
            echo json_encode([
                'success' => true,
                'data' => $lockdownStatus
            ]);
            break;
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

/**
 * Handle POST requests
 */
function handlePostRequest($securityMonitor, $securityAudit, $path) {
    $input = json_decode(file_get_contents('php://input'), true);
    $userId = $_SESSION['user']['id'] ?? null;
    
    // Debug: Log the current user ID
    error_log("Current user ID from session: " . $userId);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON input']);
        return;
    }
    
    switch ($path) {
        case '/block-ip':
            // Block an IP address
            $ip = $input['ip'] ?? '';
            $duration = (int) ($input['duration'] ?? 60); // minutes
            $reason = $input['reason'] ?? 'Manual block by admin';
            
            if (empty($ip)) {
                http_response_code(400);
                echo json_encode(['error' => 'IP address is required']);
                return;
            }
            
            if ($securityMonitor->blockIp($ip, $duration, $reason, $userId)) {
                $securityAudit->logIpBlocked($ip, $reason, $userId);
                
                echo json_encode([
                    'success' => true,
                    'message' => "IP address {$ip} blocked successfully"
                ]);
            } else {
                http_response_code(500);
                echo json_encode([
                    'success' => false,
                    'error' => 'Failed to block IP address'
                ]);
            }
            break;
            
        case '/suspend-user':
            // Suspend a user account
            $username = $input['username'] ?? '';
            $reason = $input['reason'] ?? 'Manual suspension by admin';
            
            if (empty($username)) {
                http_response_code(400);
                echo json_encode(['error' => 'Username is required']);
                return;
            }
            
            // This would require user management functionality
            // For now, we'll log the action
            $securityAudit->logAdminAction(
                'user_suspend',
                $userId,
                $username,
                ['reason' => $reason]
            );
            
            echo json_encode([
                'success' => true,
                'message' => "User {$username} suspension logged (user management not implemented)"
            ]);
            break;
            
        case '/terminate-sessions':
            // Terminate user sessions
            $targetUser = $input['target_user'] ?? null;
            $reason = $input['reason'] ?? 'Manual session termination by admin';
            
            try {
                $db = DatabaseConfig::getInstance();
                $terminatedCount = 0;
                
                if ($targetUser) {
                    // Terminate sessions for specific user
                    $sql = "UPDATE user_sessions 
                            SET is_active = FALSE, 
                                terminated_at = CURRENT_TIMESTAMP,
                                terminated_by = ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = (SELECT user_id FROM users WHERE username = ?) 
                            AND is_active = TRUE";
                    
                    $stmt = $db->query($sql, [$userId, $targetUser]);
                    $terminatedCount = $stmt->rowCount();
                    
                    $securityAudit->logAdminAction(
                        'session_terminate',
                        $userId,
                        $targetUser,
                        ['reason' => $reason, 'terminated_count' => $terminatedCount]
                    );
                    
                    echo json_encode([
                        'success' => true,
                        'message' => "Terminated {$terminatedCount} sessions for user {$targetUser}"
                    ]);
                } else {
                    // Terminate all user sessions (except current session)
                    $currentSessionId = session_id();
                    $sql = "UPDATE user_sessions 
                            SET is_active = FALSE, 
                                terminated_at = CURRENT_TIMESTAMP,
                                terminated_by = ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE session_id != ? AND is_active = TRUE";
                    
                    // Debug: Log the query and parameters
                    error_log("Terminate all sessions query: " . $sql);
                    error_log("Parameters: userId=" . $userId . ", currentSessionId=" . $currentSessionId);
                    
                    $stmt = $db->query($sql, [$userId, $currentSessionId]);
                    $terminatedCount = $stmt->rowCount();
                    
                    // Debug: Log the result
                    error_log("Terminated count: " . $terminatedCount);
                    
                    $securityAudit->logAdminAction(
                        'session_terminate_all',
                        $userId,
                        'All users',
                        ['reason' => $reason, 'terminated_count' => $terminatedCount]
                    );
                    
                    echo json_encode([
                        'success' => true,
                        'message' => "Terminated {$terminatedCount} user sessions"
                    ]);
                }
            } catch (Exception $e) {
                error_log("Error terminating sessions: " . $e->getMessage());
                echo json_encode([
                    'success' => false,
                    'error' => 'Failed to terminate sessions: ' . $e->getMessage()
                ]);
            }
            break;
            
        case '/lockdown':
            // Emergency system lockdown
            $reason = $input['reason'] ?? 'Emergency lockdown by admin';
            $duration = (int) ($input['duration'] ?? 60); // minutes
            
            // Set lockdown flag in security settings
            $securitySettings = new SecuritySettings();
            $securitySettings->updateSetting('system_lockdown', '1', $userId);
            $securitySettings->updateSetting('lockdown_reason', $reason, $userId);
            $securitySettings->updateSetting('lockdown_initiated_by', $userId, $userId);
            $securitySettings->updateSetting('lockdown_initiated_at', date('Y-m-d H:i:s'), $userId);
            $securitySettings->updateSetting('lockdown_duration', $duration, $userId);
            
            // Log the lockdown event
            $securityAudit->logEvent(
                SecurityAudit::EVENT_SYSTEM_LOCKDOWN,
                $userId,
                "System lockdown initiated: {$reason}",
                ['reason' => $reason, 'duration' => $duration]
            );
            
            // Create a critical security incident
            $securityMonitor->createSecurityIncident(
                'system_lockdown',
                'critical',
                "Emergency system lockdown initiated: {$reason}",
                ['reason' => $reason, 'duration' => $duration],
                $userId
            );
            
            echo json_encode([
                'success' => true,
                'message' => "System lockdown initiated successfully. All non-admin access will be restricted."
            ]);
            break;
            
        case '/clear-lockdown':
            // Clear system lockdown
            $securitySettings = new SecuritySettings();
            
            if ($securitySettings->clearSystemLockdown($userId)) {
                $securityAudit->logEvent(
                    SecurityAudit::EVENT_SYSTEM_LOCKDOWN,
                    $userId,
                    "System lockdown cleared by admin",
                    ['action' => 'clear_lockdown']
                );
                
                echo json_encode([
                    'success' => true,
                    'message' => "System lockdown cleared successfully"
                ]);
            } else {
                http_response_code(500);
                echo json_encode([
                    'success' => false,
                    'error' => 'Failed to clear system lockdown'
                ]);
            }
            break;
            
        case '/create-incident':
            // Create a security incident
            $incidentType = $input['incident_type'] ?? '';
            $severity = $input['severity'] ?? 'medium';
            $description = $input['description'] ?? '';
            $actions = $input['actions'] ?? null;
            
            if (empty($incidentType) || empty($description)) {
                http_response_code(400);
                echo json_encode(['error' => 'Incident type and description are required']);
                return;
            }
            
            if ($securityMonitor->createSecurityIncident($incidentType, $severity, $description, $actions, $userId)) {
                $securityAudit->logEvent(
                    SecurityAudit::EVENT_SECURITY_INCIDENT,
                    $userId,
                    "Security incident created: {$description}",
                    [
                        'incident_type' => $incidentType,
                        'severity' => $severity,
                        'actions' => $actions
                    ]
                );
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Security incident created successfully'
                ]);
            } else {
                http_response_code(500);
                echo json_encode([
                    'success' => false,
                    'error' => 'Failed to create security incident'
                ]);
            }
            break;
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}


