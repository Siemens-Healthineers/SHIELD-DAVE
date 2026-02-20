<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../config/database.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check if user is logged in
if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

// Get current user
$currentUser = [
    'user_id' => $_SESSION['user_id'],
    'username' => $_SESSION['username'] ?? 'Unknown',
    'role' => $_SESSION['role'] ?? 'User'
];

// Make currentUser available globally
$GLOBALS['currentUser'] = $currentUser;

// Set content type
header('Content-Type: application/json');

// Get request method and path
$method = $_SERVER['REQUEST_METHOD'];
$path = $_SERVER['REQUEST_URI'];
$pathParts = explode('/', trim($path, '/'));

// Route the request
if ($method === 'GET' && count($pathParts) >= 4 && $pathParts[3] === 'sessions') {
    handleGetSessions();
} elseif ($method === 'DELETE' && count($pathParts) >= 5 && $pathParts[3] === 'sessions') {
    $sessionId = $pathParts[4];
    handleDeleteSession($sessionId);
} else {
    http_response_code(404);
    echo json_encode(['error' => 'Endpoint not found']);
}

/**
 * Handle GET /api/v1/security/sessions
 * Get active sessions for the current user
 */
function handleGetSessions() {
    try {
        $db = DatabaseConfig::getInstance();
        $currentUser = $GLOBALS['currentUser'];
        
        // Get current session ID
        $currentSessionId = session_id();
        
        // Query active sessions for the current user
        $sql = "SELECT 
                    session_id,
                    user_id,
                    ip_address,
                    user_agent,
                    login_time,
                    last_activity,
                    is_active
                FROM user_sessions 
                WHERE user_id = ? AND is_active = TRUE
                ORDER BY last_activity DESC";
        
        $stmt = $db->query($sql, [$currentUser['user_id']]);
        $sessions = $stmt->fetchAll();
        
        // Process sessions data
        $processedSessions = [];
        foreach ($sessions as $session) {
            $processedSessions[] = [
                'session_id' => $session['session_id'],
                'user_id' => $session['user_id'],
                'ip_address' => $session['ip_address'],
                'location' => getLocationFromIP($session['ip_address']),
                'device_type' => getDeviceType($session['user_agent']),
                'device_name' => getDeviceName($session['user_agent']),
                'browser' => getBrowserName($session['user_agent']),
                'login_time' => $session['login_time'],
                'last_activity' => $session['last_activity'],
                'is_current' => $session['session_id'] === $currentSessionId
            ];
        }
        
        echo json_encode([
            'success' => true,
            'sessions' => $processedSessions,
            'total' => count($processedSessions)
        ]);
        
    } catch (Exception $e) {
        error_log("Error getting sessions: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Failed to retrieve sessions']);
    }
}

/**
 * Handle DELETE /api/v1/security/sessions/{sessionId}
 * Terminate a specific session
 */
function handleDeleteSession($sessionId) {
    try {
        $db = DatabaseConfig::getInstance();
        $currentUser = $GLOBALS['currentUser'];
        
        // Don't allow terminating current session
        if ($sessionId === session_id()) {
            http_response_code(400);
            echo json_encode(['error' => 'Cannot terminate current session']);
            return;
        }
        
        // Verify the session belongs to the current user
        $sql = "SELECT session_id FROM user_sessions 
                WHERE session_id = ? AND user_id = ? AND is_active = TRUE";
        $stmt = $db->query($sql, [$sessionId, $currentUser['user_id']]);
        $session = $stmt->fetch();
        
        if (!$session) {
            http_response_code(404);
            echo json_encode(['error' => 'Session not found or access denied']);
            return;
        }
        
        // Terminate the session
        $sql = "UPDATE user_sessions 
                SET is_active = FALSE, 
                    terminated_at = CURRENT_TIMESTAMP,
                    terminated_by = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE session_id = ?";
        
        $stmt = $db->query($sql, [$currentUser['user_id'], $sessionId]);
        
        // Log the action
        logUserAction($currentUser['user_id'], 'SESSION_TERMINATED', 'user_sessions', $sessionId, [
            'terminated_session_id' => $sessionId,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
        
        echo json_encode([
            'success' => true,
            'message' => 'Session terminated successfully'
        ]);
        
    } catch (Exception $e) {
        error_log("Error terminating session: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Failed to terminate session']);
    }
}


/**
 * Get location information from IP address
 */
function getLocationFromIP($ip) {
    // In a real implementation, you would use a geolocation service
    // For now, return a mock location
    $locations = [
        '192.168.1.1' => 'Local Network',
        '10.0.0.1' => 'Local Network',
        '127.0.0.1' => 'Local Network'
    ];
    
    return $locations[$ip] ?? 'Unknown Location';
}

/**
 * Get device type from user agent
 */
function getDeviceType($userAgent) {
    $userAgent = strtolower($userAgent);
    
    if (strpos($userAgent, 'mobile') !== false || strpos($userAgent, 'android') !== false) {
        return 'mobile';
    } elseif (strpos($userAgent, 'tablet') !== false || strpos($userAgent, 'ipad') !== false) {
        return 'tablet';
    } elseif (strpos($userAgent, 'laptop') !== false) {
        return 'laptop';
    } else {
        return 'desktop';
    }
}

/**
 * Get device name from user agent
 */
function getDeviceName($userAgent) {
    $userAgent = strtolower($userAgent);
    
    // Extract device information
    if (preg_match('/iphone|ipad|ipod/', $userAgent, $matches)) {
        return ucfirst($matches[0]);
    } elseif (preg_match('/android/', $userAgent)) {
        return 'Android Device';
    } elseif (preg_match('/windows/', $userAgent)) {
        return 'Windows PC';
    } elseif (preg_match('/macintosh|mac os/', $userAgent)) {
        return 'Mac';
    } elseif (preg_match('/linux/', $userAgent)) {
        return 'Linux PC';
    } else {
        return 'Unknown Device';
    }
}

/**
 * Get browser name from user agent
 */
function getBrowserName($userAgent) {
    $userAgent = strtolower($userAgent);
    
    if (strpos($userAgent, 'chrome') !== false) {
        return 'Chrome';
    } elseif (strpos($userAgent, 'firefox') !== false) {
        return 'Firefox';
    } elseif (strpos($userAgent, 'safari') !== false) {
        return 'Safari';
    } elseif (strpos($userAgent, 'edge') !== false) {
        return 'Edge';
    } elseif (strpos($userAgent, 'opera') !== false) {
        return 'Opera';
    } else {
        return 'Unknown Browser';
    }
}

/**
 * Log user action
 */
function logUserAction($userId, $action, $tableName, $recordId, $details = []) {
    try {
        $db = DatabaseConfig::getInstance();
        
        $sql = "INSERT INTO audit_logs (user_id, action, table_name, record_id, old_values, new_values, ip_address, user_agent, timestamp) 
                VALUES (?, ?, ?, ?, NULL, ?, ?, ?, CURRENT_TIMESTAMP)";
        
        $stmt = $db->query($sql, [
            $userId,
            $action,
            $tableName,
            $recordId,
            json_encode($details),
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ]);
        
    } catch (Exception $e) {
        error_log("Error logging user action: " . $e->getMessage());
    }
}
?>
