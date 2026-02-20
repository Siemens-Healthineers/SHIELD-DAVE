<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/security-settings.php';
require_once __DIR__ . '/security-audit.php';

/**
 * Lockdown Enforcement Class
 * Handles system-wide lockdown enforcement
 */
class LockdownEnforcement {
    
    private $securitySettings;
    private $securityAudit;
    private $allowedPages = [
        'login.php',
        'logout.php',
        '403.php',
        '404.php',
        '500.php'
    ];
    
    public function __construct() {
        $this->securitySettings = new SecuritySettings();
        $this->securityAudit = new SecurityAudit();
    }
    
    /**
     * Check if system is in lockdown and enforce restrictions
     * 
     * @param string $currentPage Current page being accessed
     * @return bool True if access is allowed, false if blocked
     */
    public function enforceLockdown($currentPage = null) {
        $lockdownStatus = $this->securitySettings->isSystemLockedDown();
        
        if (!$lockdownStatus['locked']) {
            return true; // No lockdown active
        }
        
        // Check if current page is allowed during lockdown
        if ($currentPage && in_array(basename($currentPage), $this->allowedPages)) {
            return true; // Allow access to essential pages
        }
        
        // Check if user is admin
        $user = $_SESSION['user'] ?? [];
        $userRole = strtolower($user['role'] ?? '');
        
        if ($userRole === 'admin') {
            return true; // Allow admin access during lockdown
        }
        
        // Block non-admin access during lockdown
        $this->logLockdownAccess($user, $currentPage, $lockdownStatus);
        $this->showLockdownPage($lockdownStatus);
        return false;
    }
    
    /**
     * Log lockdown access attempt
     * 
     * @param array $user User information
     * @param string $currentPage Page being accessed
     * @param array $lockdownStatus Lockdown status
     * @return void
     */
    private function logLockdownAccess($user, $currentPage, $lockdownStatus) {
        try {
            $this->securityAudit->logEvent(
                SecurityAudit::EVENT_ACCESS_DENIED,
                $user['id'] ?? null,
                "Access denied during system lockdown",
                [
                    'reason' => $lockdownStatus['reason'] ?? 'System lockdown active',
                    'user_role' => $user['role'] ?? 'unknown',
                    'attempted_page' => $currentPage,
                    'lockdown_initiated_at' => $lockdownStatus['initiated_at'] ?? null,
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
                    'ip_address' => $this->getClientIP()
                ],
                $this->getClientIP()
            );
        } catch (Exception $e) {
            error_log("LockdownEnforcement::logLockdownAccess error: " . $e->getMessage());
        }
    }
    
    /**
     * Show lockdown page
     * 
     * @param array $lockdownStatus Lockdown status information
     * @return void
     */
    private function showLockdownPage($lockdownStatus) {
        // Set appropriate HTTP status
        http_response_code(503); // Service Unavailable
        
        $reason = $lockdownStatus['reason'] ?? 'Emergency system maintenance';
        $expiresAt = $lockdownStatus['expires_at'] ?? null;
        
        echo '<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Temporarily Unavailable - ' . _NAME . '</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {
            font-family: "Siemens Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #000000 0%, #1a1a1a 100%);
            color: #f8fafc;
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .lockdown-container {
            text-align: center;
            max-width: 600px;
            padding: 2rem;
            background: #1a1a1a;
            border-radius: 1rem;
            border: 1px solid #333333;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            position: relative;
            overflow: hidden;
        }
        .lockdown-container::before {
            content: \'\';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #ef4444 0%, #dc2626 100%);
            animation: pulse 2s infinite;
        }
        .lockdown-icon {
            font-size: 4rem;
            color: #ef4444;
            margin-bottom: 1rem;
            animation: pulse 2s infinite;
        }
        .lockdown-title {
            font-size: 2rem;
            font-weight: 700;
            color: #f8fafc;
            margin-bottom: 1rem;
        }
        .lockdown-message {
            font-size: 1.1rem;
            color: #cbd5e1;
            margin-bottom: 1.5rem;
            line-height: 1.6;
        }
        .lockdown-details {
            background: #333333;
            padding: 1.5rem;
            border-radius: 0.5rem;
            margin-bottom: 1.5rem;
            text-align: left;
        }
        .lockdown-details h3 {
            color: #ff6b35;
            margin-top: 0;
            margin-bottom: 1rem;
        }
        .lockdown-details p {
            margin: 0.5rem 0;
            color: #cbd5e1;
        }
        .retry-button {
            background: #009999;
            color: white;
            border: none;
            padding: 1rem 2rem;
            border-radius: 0.5rem;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            font-family: "Siemens Sans", sans-serif;
        }
        .retry-button:hover {
            background: #007777;
            transform: translateY(-2px);
        }
        .contact-info {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid #333333;
            color: #94a3b8;
            font-size: 0.9rem;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
    </style>
</head>
<body>
    <div class="lockdown-container">
        <div class="lockdown-icon">🔒</div>
        <h1 class="lockdown-title">System Temporarily Unavailable</h1>
        <p class="lockdown-message">
            The system is currently in emergency lockdown mode for security reasons.
            Access has been temporarily restricted to authorized personnel only.
        </p>
        <div class="lockdown-details">
            <h3>Lockdown Information</h3>
            <p><strong>Reason:</strong> ' . dave_htmlspecialchars($reason) . '</p>';
            
        if ($expiresAt) {
            echo '<p><strong>Expected Resolution:</strong> ' . date('M j, Y \a\t g:i A', strtotime($expiresAt)) . '</p>';
        }
        
        echo '<p><strong>Status:</strong> Emergency Security Lockdown</p>
        </div>
        <button class="retry-button" onclick="window.location.reload()">
            <i class="fas fa-refresh"></i> Try Again
        </button>
        <div class="contact-info">
            <p>If you believe this is an error, please contact your system administrator.</p>
            <p>For emergency access, contact: ' . (defined('_ADMIN_EMAIL') ? _ADMIN_EMAIL : 'admin@' . $_SERVER['HTTP_HOST']) . '</p>
        </div>
    </div>
</body>
</html>';
        
        exit;
    }
    
    /**
     * Get client IP address
     * 
     * @return string Client IP address
     */
    private function getClientIP() {
        $ipKeys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
        
        foreach ($ipKeys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }
    
    /**
     * Check if current user session should be terminated
     * 
     * @return bool True if session should be terminated
     */
    public function shouldTerminateSession() {
        $lockdownStatus = $this->securitySettings->isSystemLockedDown();
        
        if (!$lockdownStatus['locked']) {
            return false; // No lockdown active
        }
        
        // Check if user is admin
        $user = $_SESSION['user'] ?? [];
        $userRole = strtolower($user['role'] ?? '');
        
        if ($userRole === 'admin') {
            return false; // Don\'t terminate admin sessions
        }
        
        return true; // Terminate non-admin sessions
    }
    
    /**
     * Terminate non-admin sessions during lockdown
     * 
     * @return void
     */
    public function terminateNonAdminSessions() {
        if (!$this->shouldTerminateSession()) {
            return;
        }
        
        // Log session termination
        $user = $_SESSION['user'] ?? [];
        $this->securityAudit->logEvent(
            SecurityAudit::EVENT_SESSION_TERMINATED,
            $user['id'] ?? null,
            "Session terminated due to system lockdown",
            [
                'reason' => 'System lockdown active',
                'user_role' => $user['role'] ?? 'unknown',
                'ip_address' => $this->getClientIP()
            ],
            $this->getClientIP()
        );
        
        // Clear session
        session_destroy();
        session_start();
        
        // Redirect to login
        header('Location: /pages/login.php?reason=lockdown');
        exit;
    }
}

/**
 * Global function to enforce lockdown
 * 
 * @param string $currentPage Current page being accessed
 * @return bool True if access is allowed
 */
function enforceSystemLockdown($currentPage = null) {
    static $lockdownEnforcement = null;
    
    if ($lockdownEnforcement === null) {
        $lockdownEnforcement = new LockdownEnforcement();
    }
    
    return $lockdownEnforcement->enforceLockdown($currentPage);
}

/**
 * Global function to check if session should be terminated
 * 
 * @return bool True if session should be terminated
 */
function shouldTerminateSessionForLockdown() {
    static $lockdownEnforcement = null;
    
    if ($lockdownEnforcement === null) {
        $lockdownEnforcement = new LockdownEnforcement();
    }
    
    return $lockdownEnforcement->shouldTerminateSession();
}

/**
 * Global function to terminate non-admin sessions
 * 
 * @return void
 */
function terminateNonAdminSessionsForLockdown() {
    static $lockdownEnforcement = null;
    
    if ($lockdownEnforcement === null) {
        $lockdownEnforcement = new LockdownEnforcement();
    }
    
    $lockdownEnforcement->terminateNonAdminSessions();
}
