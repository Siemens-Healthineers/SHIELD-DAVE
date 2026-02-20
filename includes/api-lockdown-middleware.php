<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

require_once __DIR__ . '/security-settings.php';
require_once __DIR__ . '/security-audit.php';

/**
 * API Lockdown Middleware
 * Handles lockdown enforcement for API endpoints
 */
class ApiLockdownMiddleware {
    
    private $securitySettings;
    private $securityAudit;
    private $allowedEndpoints = [
        'auth/login',
        'auth/logout',
        'system/status'
    ];
    
    public function __construct() {
        $this->securitySettings = new SecuritySettings();
        $this->securityAudit = new SecurityAudit();
    }
    
    /**
     * Check if API access is allowed during lockdown
     * 
     * @param string $endpoint API endpoint being accessed
     * @param string $method HTTP method
     * @return bool True if access is allowed
     */
    public function checkApiAccess($endpoint, $method = 'GET') {
        $lockdownStatus = $this->securitySettings->isSystemLockedDown();
        
        if (!$lockdownStatus['locked']) {
            return true; // No lockdown active
        }
        
        // Check if endpoint is allowed during lockdown
        if (in_array($endpoint, $this->allowedEndpoints)) {
            return true; // Allow access to essential endpoints
        }
        
        // Check if user is admin
        $user = $_SESSION['user'] ?? [];
        $userRole = strtolower($user['role'] ?? '');
        
        if ($userRole === 'admin') {
            return true; // Allow admin access during lockdown
        }
        
        // Block non-admin API access during lockdown
        $this->logApiLockdownAccess($user, $endpoint, $method, $lockdownStatus);
        $this->sendLockdownResponse($lockdownStatus);
        return false;
    }
    
    /**
     * Log API lockdown access attempt
     * 
     * @param array $user User information
     * @param string $endpoint API endpoint
     * @param string $method HTTP method
     * @param array $lockdownStatus Lockdown status
     * @return void
     */
    private function logApiLockdownAccess($user, $endpoint, $method, $lockdownStatus) {
        try {
            $this->securityAudit->logEvent(
                SecurityAudit::EVENT_ACCESS_DENIED,
                $user['id'] ?? null,
                "API access denied during system lockdown",
                [
                    'reason' => $lockdownStatus['reason'] ?? 'System lockdown active',
                    'user_role' => $user['role'] ?? 'unknown',
                    'endpoint' => $endpoint,
                    'method' => $method,
                    'lockdown_initiated_at' => $lockdownStatus['initiated_at'] ?? null,
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
                    'ip_address' => $this->getClientIP()
                ],
                $this->getClientIP()
            );
        } catch (Exception $e) {
            error_log("ApiLockdownMiddleware::logApiLockdownAccess error: " . $e->getMessage());
        }
    }
    
    /**
     * Send lockdown response
     * 
     * @param array $lockdownStatus Lockdown status information
     * @return void
     */
    private function sendLockdownResponse($lockdownStatus) {
        http_response_code(503); // Service Unavailable
        
        $response = [
            'success' => false,
            'error' => 'System temporarily unavailable',
            'message' => 'The system is currently in emergency lockdown mode. Access has been restricted to authorized personnel only.',
            'lockdown' => [
                'active' => true,
                'reason' => $lockdownStatus['reason'] ?? 'Emergency lockdown',
                'expires_at' => $lockdownStatus['expires_at'] ?? null
            ],
            'timestamp' => date('c')
        ];
        
        header('Content-Type: application/json');
        echo json_encode($response, JSON_PRETTY_PRINT);
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
}

/**
 * Global function to enforce API lockdown
 * 
 * @param string $endpoint API endpoint being accessed
 * @param string $method HTTP method
 * @return bool True if access is allowed
 */
function enforceApiLockdown($endpoint, $method = 'GET') {
    static $apiLockdownMiddleware = null;
    
    if ($apiLockdownMiddleware === null) {
        $apiLockdownMiddleware = new ApiLockdownMiddleware();
    }
    
    return $apiLockdownMiddleware->checkApiAccess($endpoint, $method);
}
