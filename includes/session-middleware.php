<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

// Include required dependencies
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/lockdown-enforcement.php';

/**
 * Session Middleware Class
 * Handles consistent session management across all pages
 */
class SessionMiddleware {
    
    private $auth;
    private $sessionStarted = false;
    
    public function __construct() {
        $this->auth = new Auth();
    }
    
    /**
     * Initialize session management
     */
    public function init() {
        // Start session if not already started
        if (session_status() === PHP_SESSION_NONE) {
            $this->startSession();
        }
        
        // Check for lockdown and terminate non-admin sessions if needed
        if (shouldTerminateSessionForLockdown()) {
            terminateNonAdminSessionsForLockdown();
        }
        
        // Validate and update session
        $this->validateAndUpdateSession();
    }
    
    /**
     * Start session with proper configuration
     */
    private function startSession() {
        // Configure session settings
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', 0); // Set to 1 for HTTPS
        ini_set('session.use_only_cookies', 1);
        ini_set('session.cookie_samesite', 'Strict');
        
        // Set session name
        session_name(_SESSION_NAME);
        
        // Set session lifetime
        ini_set('session.gc_maxlifetime', _SESSION_LIFETIME);
        
        // Start session
        session_start();
        $this->sessionStarted = true;
        
        // Track session in database if user is logged in
        if (isset($_SESSION['user_id'])) {
            $this->trackSessionInDatabase();
        }
        
        // Regenerate session ID periodically for security
        $this->regenerateSessionIdIfNeeded();
    }
    
    /**
     * Validate and update session
     */
    private function validateAndUpdateSession() {
        try {
            // Check if user is logged in
            if (!$this->auth->isLoggedIn()) {
                $this->redirectToLogin();
                return;
            }
            
            // Basic session timeout check first (no database query)
            if (!$this->checkSessionTimeout()) {
                $this->redirectToLogin();
                return;
            }
            
            // Only validate in database if session is recent (avoid frequent DB queries)
            if ($this->shouldValidateInDatabase()) {
                if (!$this->validateSessionInDatabase()) {
                    $this->redirectToLogin();
                    return;
                }
                
                // Update session activity
                $this->updateSessionActivity();
            }
            
        } catch (Exception $e) {
            error_log("Session middleware error: " . $e->getMessage());
            $this->redirectToLogin();
        }
    }
    
    /**
     * Validate session in database
     */
    private function validateSessionInDatabase() {
        try {
            $sessionId = session_id();
            $userId = $_SESSION['user_id'] ?? null;
            
            if (!$sessionId || !$userId) {
                return false;
            }
            
            $db = DatabaseConfig::getInstance();
            
            // Check if session exists and is active
            $sql = "SELECT session_id, last_activity FROM user_sessions 
                    WHERE session_id = ? AND user_id = ? AND is_active = TRUE";
            $stmt = $db->query($sql, [$sessionId, $userId]);
            $session = $stmt->fetch();
            
            if (!$session) {
                return false;
            }
            
            // Check session timeout
            $timeoutMinutes = _SESSION_TIMEOUT;
            $sql = "SELECT last_activity FROM user_sessions 
                    WHERE session_id = ? AND last_activity > NOW() - INTERVAL '{$timeoutMinutes} minutes'";
            $stmt = $db->query($sql, [$sessionId]);
            $activeSession = $stmt->fetch();
            
            if (!$activeSession) {
                // Session expired, mark as inactive
                $this->markSessionInactive($sessionId);
                return false;
            }
            
            return true;
            
        } catch (Exception $e) {
            error_log("Session validation error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Update session activity
     */
    private function updateSessionActivity() {
        try {
            $sessionId = session_id();
            $db = DatabaseConfig::getInstance();
            
            $sql = "UPDATE user_sessions 
                    SET last_activity = CURRENT_TIMESTAMP, 
                        updated_at = CURRENT_TIMESTAMP 
                    WHERE session_id = ? AND is_active = TRUE";
            $db->query($sql, [$sessionId]);
            
        } catch (Exception $e) {
            error_log("Error updating session activity: " . $e->getMessage());
        }
    }
    
    /**
     * Get client IP address
     */
    private function getClientIP() {
        $ipKeys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
        
        foreach ($ipKeys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                $ip = $_SERVER[$key];
                if (strpos($ip, ',') !== false) {
                    $ip = explode(',', $ip)[0];
                }
                $ip = trim($ip);
                
                // Validate IP address
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        // Fallback to localhost if no valid IP found
        return '127.0.0.1';
    }
    
    /**
     * Mark session as inactive
     */
    private function markSessionInactive($sessionId) {
        try {
            $db = DatabaseConfig::getInstance();
            
            $sql = "UPDATE user_sessions 
                    SET is_active = FALSE, 
                        terminated_at = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP 
                    WHERE session_id = ?";
            $db->query($sql, [$sessionId]);
            
        } catch (Exception $e) {
            error_log("Error marking session inactive: " . $e->getMessage());
        }
    }
    
    /**
     * Regenerate session ID if needed
     */
    private function regenerateSessionIdIfNeeded() {
        // Regenerate session ID every 15 minutes for security
        if (!isset($_SESSION['last_regeneration'])) {
            $_SESSION['last_regeneration'] = time();
        } elseif (time() - $_SESSION['last_regeneration'] > 900) { // 15 minutes
            session_regenerate_id(true);
            $_SESSION['last_regeneration'] = time();
        }
    }
    
    /**
     * Check session timeout (basic check without database)
     */
    private function checkSessionTimeout() {
        $timeout = _SESSION_TIMEOUT * 60; // Convert to seconds
        
        if (isset($_SESSION['last_activity'])) {
            if (time() - $_SESSION['last_activity'] > $timeout) {
                return false;
            }
        }
        
        // Update last activity
        $_SESSION['last_activity'] = time();
        return true;
    }
    
    /**
     * Check if we should validate in database (avoid frequent DB queries)
     */
    private function shouldValidateInDatabase() {
        // Only validate in database every 5 minutes or if last validation was more than 5 minutes ago
        $lastValidation = $_SESSION['last_db_validation'] ?? 0;
        $now = time();
        
        if ($now - $lastValidation > 300) { // 5 minutes
            $_SESSION['last_db_validation'] = $now;
            return true;
        }
        
        return false;
    }
    
    /**
     * Track session in database
     */
    private function trackSessionInDatabase() {
        try {
            $sessionId = session_id();
            $userId = $_SESSION['user_id'] ?? null;
            
            if (!$sessionId || !$userId) {
                return;
            }
            
            $db = DatabaseConfig::getInstance();
            $ipAddress = $this->getClientIP();
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
            
            // Insert or update session record
            $sql = "INSERT INTO user_sessions (session_id, user_id, ip_address, user_agent, login_time, last_activity, is_active)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)
                    ON CONFLICT (session_id) 
                    DO UPDATE SET
                        last_activity = CURRENT_TIMESTAMP,
                        is_active = TRUE,
                        updated_at = CURRENT_TIMESTAMP";
            
            $db->query($sql, [$sessionId, $userId, $ipAddress, $userAgent]);
            
        } catch (Exception $e) {
            error_log("Error tracking session in database: " . $e->getMessage());
        }
    }
    
    /**
     * Redirect to login with proper headers
     */
    private function redirectToLogin() {
        // Clear any existing session data
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        
        // Set proper headers to prevent caching
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        header('Location: /pages/login.php');
        exit;
    }
    
    /**
     * Get current user data
     */
    public function getCurrentUser() {
        return $_SESSION['user'] ?? null;
    }
    
    /**
     * Check if user has permission
     */
    public function hasPermission($permission) {
        return $this->auth->hasPermission($permission);
    }
    
    /**
     * Require specific permission
     */
    public function requirePermission($permission) {
        if (!$this->hasPermission($permission)) {
            http_response_code(403);
            die('Access denied. Insufficient permissions.');
        }
    }
    
    /**
     * Logout user
     */
    public function logout() {
        $this->auth->logout();
    }
}

// Auto-initialize session middleware
$sessionMiddleware = new SessionMiddleware();
$sessionMiddleware->init();
?>
