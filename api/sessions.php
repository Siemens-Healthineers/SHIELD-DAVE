<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Set content type
header('Content-Type: application/json');

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

try {
    $db = DatabaseConfig::getInstance();
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

/**
 * Get location information from IP address
 */
function getLocationFromIP($ip) {
    $locations = [
        '127.0.0.1' => 'Local Network',
        '192.168.1.1' => 'Local Network',
        '10.0.0.1' => 'Local Network'
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
?>
