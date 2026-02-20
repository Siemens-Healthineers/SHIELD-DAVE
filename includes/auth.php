<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/security-settings.php';
require_once __DIR__ . '/security-monitor.php';
require_once __DIR__ . '/security-audit.php';
require_once __DIR__ . '/mfa-service.php';

/**
 * Authentication class
 */
class Auth {
    
    private $db;
    private $sessionName;
    private $securitySettings;
    private $securityMonitor;
    private $securityAudit;
    private $mfaService;
    
    public function __construct() {
        $this->db = DatabaseConfig::getInstance();
        $this->sessionName = Config::get('security.session_name', '_SESSION');
        $this->securitySettings = new SecuritySettings();
        $this->securityMonitor = new SecurityMonitor();
        $this->securityAudit = new SecurityAudit();
        $this->mfaService = new MFAService();
    }
    
    /**
     * User login
     */
    public function login($username, $password, $mfaCode = null) {
        try {
            $clientIp = $this->getClientIP();
            
            // Check if IP is blocked
            if ($this->securityMonitor->isIpBlocked($clientIp)) {
                $this->securityAudit->logEvent(
                    SecurityAudit::EVENT_LOGIN_FAILED,
                    null,
                    "Login attempt from blocked IP: {$clientIp}",
                    ['username' => $username, 'ip' => $clientIp],
                    $clientIp,
                    $username
                );
                throw new Exception('Access denied from this IP address.');
            }
            
            // Check for account lockout
            if ($this->isAccountLocked($username)) {
                $this->securityMonitor->logFailedLogin($username, $clientIp, 'Account locked');
                $this->securityAudit->logEvent(
                    SecurityAudit::EVENT_LOGIN_FAILED,
                    null,
                    "Login attempt on locked account: {$username}",
                    ['username' => $username, 'ip' => $clientIp],
                    $clientIp,
                    $username
                );
                throw new Exception('Account is temporarily locked due to too many failed login attempts.');
            }
            
            // Get user data
            $user = $this->getUserByUsername($username);
            if (!$user) {
                $this->securityMonitor->logFailedLogin($username, $clientIp, 'Invalid username');
                $this->securityAudit->logFailedLogin($username, 'Invalid username', $clientIp);
                throw new Exception('Invalid username or password.');
            }
            
            // Check if user is active
            if (!$user['is_active']) {
                $this->securityMonitor->logFailedLogin($username, $clientIp, 'Account deactivated');
                $this->securityAudit->logEvent(
                    SecurityAudit::EVENT_LOGIN_FAILED,
                    $user['id'],
                    "Login attempt on deactivated account: {$username}",
                    ['username' => $username, 'ip' => $clientIp],
                    $clientIp,
                    $username
                );
                throw new Exception('Account is deactivated.');
            }
            
            // Verify password
            if (!password_verify($password, $user['password_hash'])) {
                $this->securityMonitor->logFailedLogin($username, $clientIp, 'Invalid password');
                $this->securityAudit->logFailedLogin($username, 'Invalid password', $clientIp);
                throw new Exception('Invalid username or password.');
            }
            
            // Check MFA if enabled
            if ($user['mfa_enabled']) {
                if (!$mfaCode) {
                    throw new Exception('MFA code required.');
                }
                
                if (!$this->mfaService->verifyCode($user['mfa_secret'], $mfaCode)) {
                    $this->recordFailedLogin($username);
                    logAuthEvent('LOGIN', $username, false, ['reason' => 'Invalid MFA code']);
                    throw new Exception('Invalid MFA code.');
                }
            }
            
            // Clear failed login attempts
            $this->clearFailedLogins($username);
            
            // Create session
            $this->createSession($user);
            
            // Update last login
            $this->updateLastLogin($user['user_id']);
            
            // Log successful login
            $this->logUserAction($user['user_id'], 'LOGIN', 'users', $user['user_id']);
            
            // Log authentication event
            logAuthEvent('LOGIN', $username, true, [
                'user_id' => $user['user_id'],
                'role' => $user['role'],
                'mfa_used' => $user['mfa_enabled']
            ]);
            
            // Log successful login to security audit
            $this->securityAudit->logLogin($user['user_id'], $username, $clientIp);
            
            return [
                'success' => true,
                'user' => $this->sanitizeUserData($user),
                'message' => 'Login successful.'
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => $e->getMessage()
            ];
        }
    }
    
    /**
     * User logout
     */
    public function logout() {
        try {
            if ($this->isLoggedIn()) {
                $userId = $this->getCurrentUserId();
                $sessionId = session_id();
                $username = $_SESSION['username'] ?? 'unknown';
                
                // Mark session as inactive in database
                $sql = "UPDATE user_sessions 
                        SET is_active = FALSE, 
                            terminated_at = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP 
                        WHERE session_id = ?";
                $this->db->query($sql, [$sessionId]);
                
                // Log the logout action
                $this->logUserAction($userId, 'LOGOUT', 'users', $userId);
                
                // Log authentication event
                logAuthEvent('LOGOUT', $username, true, [
                    'user_id' => $userId,
                    'session_id' => $sessionId
                ]);
            }
        } catch (Exception $e) {
            error_log("Error during logout: " . $e->getMessage());
        }
        
        // Destroy session
        session_destroy();
        return true;
    }
    
    /**
     * Check if user is logged in
     */
    public function isLoggedIn() {
        return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
    }
    
    /**
     * Get current user data
     */
    public function getCurrentUser() {
        if (!$this->isLoggedIn()) {
            return null;
        }
        
        $userId = $_SESSION['user_id'];
        return $this->getUserById($userId);
    }
    
    /**
     * Get current user ID
     */
    public function getCurrentUserId() {
        return $this->isLoggedIn() ? $_SESSION['user_id'] : null;
    }
    
    /**
     * Check if user has permission
     */
    public function hasPermission($permission) {
        if (!$this->isLoggedIn()) {
            return false;
        }
        
        $user = $this->getCurrentUser();
        if (!$user) {
            return false;
        }
        
        $role = $user['role'];
        
        // Define role permissions
        $permissions = [
            'Admin' => ['*'], // All permissions
            'Clinical Engineer' => [
                'assets.view', 'assets.create', 'assets.edit', 'assets.delete',
                'devices.view', 'devices.map', 'recalls.view', 'reports.view'
            ],
            'IT Security Analyst' => [
                'assets.view', 'assets.create', 'assets.edit',
                'devices.view', 'vulnerabilities.view', 'vulnerabilities.manage',
                'reports.view', 'reports.generate'
            ],
            'Read-Only' => [
                'assets.view', 'devices.view', 'recalls.view', 
                'vulnerabilities.view', 'reports.view'
            ]
        ];
        
        if (!isset($permissions[$role])) {
            return false;
        }
        
        return in_array('*', $permissions[$role]) || in_array($permission, $permissions[$role]);
    }
    
    /**
     * Require authentication
     */
    public function requireAuth() {
        // Session should already be started by session middleware
        // Only start if absolutely necessary
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // Check if user is logged in
        if (!$this->isLoggedIn()) {
            $this->redirectToLogin();
            return;
        }
        
        // Validate session in database
        if (!$this->validateSession()) {
            $this->redirectToLogin();
            return;
        }
        
        // Update session activity
        $this->updateSessionActivity();
    }
    
    /**
     * Validate session against database
     */
    private function validateSession() {
        try {
            $sessionId = session_id();
            $userId = $_SESSION['user_id'] ?? null;
            
            if (!$sessionId || !$userId) {
                return false;
            }
            
            // Check if session exists and is active in database
            $sql = "SELECT session_id FROM user_sessions 
                    WHERE session_id = ? AND user_id = ? AND is_active = TRUE";
            $stmt = $this->db->query($sql, [$sessionId, $userId]);
            $session = $stmt->fetch();
            
            if (!$session) {
                return false;
            }
            
            // Check session timeout
            $timeoutMinutes = Config::get('security.session_timeout', 30);
            $sql = "SELECT last_activity FROM user_sessions 
                    WHERE session_id = ? AND last_activity > NOW() - INTERVAL '{$timeoutMinutes} minutes'";
            $stmt = $this->db->query($sql, [$sessionId]);
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
     * Mark session as inactive
     */
    private function markSessionInactive($sessionId) {
        try {
            $sql = "UPDATE user_sessions 
                    SET is_active = FALSE, 
                        terminated_at = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP 
                    WHERE session_id = ?";
            $this->db->query($sql, [$sessionId]);
        } catch (Exception $e) {
            error_log("Error marking session inactive: " . $e->getMessage());
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
     * Require specific permission
     */
    public function requirePermission($permission) {
        $this->requireAuth();
        
        if (!$this->hasPermission($permission)) {
            http_response_code(403);
            die('Access denied. Insufficient permissions.');
        }
    }
    
    /**
     * Check if user has specific role
     */
    public function hasRole($role) {
        if (!$this->isLoggedIn()) {
            return false;
        }
        
        $user = $this->getCurrentUser();
        if (!$user) {
            return false;
        }
        
        return strtolower($user['role']) === strtolower($role);
    }
    
    /**
     * Require specific role
     */
    public function requireRole($role) {
        $this->requireAuth();
        
        if (!$this->hasRole($role)) {
            http_response_code(403);
            die('Access denied. Insufficient role permissions.');
        }
    }
    
    /**
     * Get user by username
     */
    private function getUserByUsername($username) {
        $sql = "SELECT * FROM users WHERE username = ? AND is_active = TRUE";
        $stmt = $this->db->query($sql, [$username]);
        return $stmt->fetch();
    }
    
    /**
     * Get user by ID
     */
    private function getUserById($userId) {
        $sql = "SELECT * FROM users WHERE user_id = ? AND is_active = TRUE";
        $stmt = $this->db->query($sql, [$userId]);
        return $stmt->fetch();
    }
    
    /**
     * Create user session
     */
    private function createSession($user) {
        // Set session data
        $_SESSION['user_id'] = $user['user_id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['login_time'] = time();
        $_SESSION['user'] = $user; // Store full user data
        
        // Track session in database
        $this->trackSession($user);
        
        // Regenerate session ID for security (only if headers not sent)
        if (!headers_sent()) {
            session_regenerate_id(true);
            // Update session tracking with new ID
            $this->trackSession($user);
        }
    }
    
    /**
     * Track session in database
     */
    private function trackSession($user) {
        try {
            $sessionId = session_id();
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
            
            $this->db->query($sql, [$sessionId, $user['user_id'], $ipAddress, $userAgent]);
            
        } catch (Exception $e) {
            error_log("Error tracking session: " . $e->getMessage());
            // Don't fail login if session tracking fails
        }
    }
    
    /**
     * Get client IP address
     */
    public function getClientIP() {
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
     * Update last login timestamp
     */
    private function updateLastLogin($userId) {
        $sql = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?";
        $this->db->query($sql, [$userId]);
    }
    
    /**
     * Update session activity
     */
    public function updateSessionActivity() {
        try {
            $sessionId = session_id();
            $sql = "UPDATE user_sessions 
                    SET last_activity = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP 
                    WHERE session_id = ? AND is_active = TRUE";
            $this->db->query($sql, [$sessionId]);
        } catch (Exception $e) {
            error_log("Error updating session activity: " . $e->getMessage());
        }
    }
    
    
    /**
     * Check if account is locked
     */
    private function isAccountLocked($username) {
        $sql = "SELECT COUNT(*) as attempts FROM audit_logs 
                WHERE action = 'FAILED_LOGIN' 
                AND new_values->>'username' = ? 
                AND timestamp > NOW() - INTERVAL '" . Config::get('security.lockout_duration', 900) . " seconds'";
        
        $stmt = $this->db->query($sql, [$username]);
        $result = $stmt->fetch();
        
        return $result['attempts'] >= Config::get('security.max_login_attempts', 5);
    }
    
    /**
     * Record failed login attempt
     */
    private function recordFailedLogin($username) {
        $this->logUserAction(null, 'FAILED_LOGIN', 'users', null, [
            'username' => $username,
            'ip_address' => $this->getClientIP(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        ]);
    }
    
    /**
     * Clear failed login attempts
     */
    private function clearFailedLogins($username) {
        // This could be implemented to clear old failed login records
        // For now, we rely on the time-based check in isAccountLocked
    }
    
    /**
     * Verify MFA code
     */
    private function verifyMFACode($secret, $code) {
        return $this->mfaService->verifyCode($secret, $code);
    }
    
    /**
     * Sanitize user data for response
     */
    private function sanitizeUserData($user) {
        unset($user['password_hash']);
        unset($user['mfa_secret']);
        return $user;
    }
    
    /**
     * Log user action
     */
    public function logUserAction($userId, $action, $tableName = null, $recordId = null, $data = null) {
        $sql = "INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values, ip_address, user_agent, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)";
        
        $this->db->query($sql, [
            $userId,
            $action,
            $tableName,
            $recordId,
            $data ? json_encode($data) : null,
            $this->getClientIP(),
            $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        ]);
    }
    
    /**
     * Check if system is in lockdown mode and enforce restrictions
     * 
     * @return bool True if access is allowed, false if blocked
     */
    public function checkSystemLockdown() {
        $lockdownStatus = $this->securitySettings->isSystemLockedDown();
        
        if ($lockdownStatus['locked']) {
            // Check if current user is admin
            $user = $_SESSION['user'] ?? [];
            $userRole = strtolower($user['role'] ?? '');
            
            // Allow admin access during lockdown
            if ($userRole === 'admin') {
                return true;
            }
            
            // Block non-admin access during lockdown
            $this->securityAudit->logEvent(
                SecurityAudit::EVENT_ACCESS_DENIED,
                $user['id'] ?? null,
                "Access denied during system lockdown",
                [
                    'reason' => $lockdownStatus['reason'] ?? 'System lockdown active',
                    'user_role' => $userRole,
                    'lockdown_initiated_at' => $lockdownStatus['initiated_at'] ?? null
                ],
                $this->getClientIP()
            );
            
            return false;
        }
        
        return true;
    }
    
    /**
     * Require authentication and check system lockdown
     * 
     * @return void
     */
    public function requireAuthWithLockdownCheck() {
        $this->requireAuth();
        
        if (!$this->checkSystemLockdown()) {
            // System is in lockdown and user is not admin
            $this->handleLockdownAccess();
        }
    }
    
    /**
     * Handle access during system lockdown
     * 
     * @return void
     */
    private function handleLockdownAccess() {
        $lockdownStatus = $this->securitySettings->isSystemLockedDown();
        
        // Set appropriate HTTP status
        http_response_code(503); // Service Unavailable
        
        // Show lockdown page
        $this->showLockdownPage($lockdownStatus);
        exit;
    }
    
    /**
     * Show system lockdown page
     * 
     * @param array $lockdownStatus Lockdown status information
     * @return void
     */
    private function showLockdownPage($lockdownStatus) {
        $reason = $lockdownStatus['reason'] ?? 'Emergency system maintenance';
        $expiresAt = $lockdownStatus['expires_at'] ?? null;
        
        echo '<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Temporarily Unavailable - ' . _NAME . '</title>
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
        }
        .lockdown-icon {
            font-size: 4rem;
            color: #ff6b35;
            margin-bottom: 1rem;
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
        }
        .retry-button:hover {
            background: #007777;
            transform: translateY(-2px);
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
            Try Again
        </button>
    </div>
</body>
</html>';
    }
}

/**
 * Password utility class
 */
class PasswordUtils {
    
    /**
     * Hash password
     */
    public static function hash($password) {
        return password_hash($password, PASSWORD_DEFAULT);
    }
    
    /**
     * Verify password
     */
    public static function verify($password, $hash) {
        return password_verify($password, $hash);
    }
    
    /**
     * Validate password strength
     */
    public static function validate($password) {
        $errors = [];
        
        if (strlen($password) < Config::get('security.password_min_length', 8)) {
            $errors[] = 'Password must be at least ' . Config::get('security.password_min_length', 8) . ' characters long.';
        }
        
        if (Config::get('security.password_require_uppercase', true) && !preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter.';
        }
        
        if (Config::get('security.password_require_numbers', true) && !preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must contain at least one number.';
        }
        
        if (Config::get('security.password_require_special', true) && !preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one special character.';
        }
        
        return $errors;
    }
    
    /**
     * Generate secure random password
     */
    public static function generate($length = 12) {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
        $password = '';
        
        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, strlen($chars) - 1)];
        }
        
        return $password;
    }
}

/**
 * Session utility class
 */
class SessionUtils {
    
    /**
     * Check if session is valid
     */
    public static function isValid() {
        if (!isset($_SESSION['login_time'])) {
            return false;
        }
        
        $sessionLifetime = Config::get('security.session_lifetime', 3600);
        return (time() - $_SESSION['login_time']) < $sessionLifetime;
    }
    
    /**
     * Refresh session
     */
    public static function refresh() {
        if (self::isValid()) {
            $_SESSION['login_time'] = time();
            return true;
        }
        return false;
    }
    
    /**
     * Destroy session
     */
    public static function destroy() {
        session_destroy();
        session_start();
    }
    
    /**
     * Get client IP address
     * @return string
     */
    private function getClientIP() {
        $ipKeys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
        
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
     * Get client IP address (new method for security monitoring)
     */
    public function getClientIpAddress() {
        $ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        
        foreach ($ipKeys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                // Handle comma-separated IPs (from proxies)
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }
}

// Initialize authentication
$auth = new Auth();

// Global function wrappers for backward compatibility with tests
function hashPassword($password) {
    global $auth;
    return $auth->hashPassword($password);
}

function verifyPassword($password, $hash) {
    global $auth;
    return $auth->verifyPassword($password, $hash);
}

function loginUser($username, $password, $mfaCode = null) {
    global $auth;
    return $auth->login($username, $password, $mfaCode);
}

function logoutUser() {
    global $auth;
    return $auth->logout();
}

function checkAuth() {
    global $auth;
    return $auth->isLoggedIn();
}

function hasRole($role) {
    global $auth;
    return $auth->hasRole($role);
}

function requireRole($role) {
    global $auth;
    return $auth->requireRole($role);
}

function getUserId() {
    global $auth;
    return $auth->getUserId();
}

function getUserRole() {
    global $auth;
    return $auth->getUserRole();
}

function getUserDetails() {
    global $auth;
    return $auth->getUserDetails();
}

function updateLastLogin($userId) {
    global $auth;
    return $auth->updateLastLogin($userId);
}

function isAccountLocked($username) {
    global $auth;
    return $auth->isAccountLocked($username);
}

function lockAccount($username) {
    global $auth;
    return $auth->lockAccount($username);
}

function unlockAccount($username) {
    global $auth;
    return $auth->unlockAccount($username);
}

function generateMFASecret() {
    global $auth;
    return $auth->generateMFASecret();
}

function verifyMFA($secret, $code) {
    global $auth;
    return $auth->verifyMFA($secret, $code);
}

function logAudit($action, $details = '') {
    global $auth;
    return $auth->logAudit($action, $details);
}

function redirectIfNotLoggedIn() {
    global $auth;
    return $auth->redirectIfNotLoggedIn();
}

function redirectIfLoggedIn() {
    global $auth;
    return $auth->redirectIfLoggedIn();
}

function requireAuthWithLockdownCheck() {
    global $auth;
    return $auth->requireAuthWithLockdownCheck();
}

function checkSystemLockdown() {
    global $auth;
    return $auth->checkSystemLockdown();
}
