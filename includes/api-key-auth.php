<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

require_once __DIR__ . '/api-key-manager.php';

// Define the integration API key name constant
define('DAVE_API_INTEGRATION_KEY', 'dave-api-integration');

/**
 * Get the integration API key name
 * @return string The integration API key name
 */
function getDaveIntegrationKeyName() {
    return DAVE_API_INTEGRATION_KEY;
}

/**
 * API Key Authentication Middleware
 * Handles authentication for external systems using API keys
 */
class ApiKeyAuth {
    
    private $apiKeyManager;
    private $clientIp;
    
    public function __construct() {
        $this->apiKeyManager = new ApiKeyManager();
        $this->clientIp = $this->getClientIP();
    }
    
    /**
     * Authenticate API request using API key
     */
    public function authenticate($requiredScope = null) {
        // Get API key from headers
        $apiKey = $this->getApiKeyFromRequest();
        
        if (!$apiKey) {
            return false;
        }
        
        // Validate API key
        $validation = $this->apiKeyManager->validateApiKey($apiKey, $requiredScope, $this->clientIp);
        
        if (!$validation['valid']) {
            $this->sendUnauthorizedResponse($validation['error']);
            return false;
        }
        
        // Set up session-like data for the API request
        $this->setApiUserSession($validation);
        
        return true;
    }
    
    /**
     * Get API key from request headers
     */
    private function getApiKeyFromRequest() {
        // Check Authorization header (Bearer token)
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return $matches[1];
        }
        
        // Check X-API-Key header
        if (isset($_SERVER['HTTP_X_API_KEY'])) {
            return $_SERVER['HTTP_X_API_KEY'];
        }
        
        // Check query parameter (less secure, but sometimes needed)
        if (isset($_GET['api_key'])) {
            return $_GET['api_key'];
        }
        
        return null;
    }
    
    /**
     * Set up user session data for API requests
     */
    private function setApiUserSession($validation) {
        // Set global variables that can be used by API endpoints
        $GLOBALS['api_user'] = [
            'user_id' => $validation['user_id'],
            'username' => $validation['username'],
            'email' => $validation['user_email'],
            'role' => $validation['user_role'],
            'permissions' => $validation['user_permissions'],
            'api_key_data' => $validation['key_data'],
            'scopes' => $validation['scopes'],
            'is_api_request' => true
        ];
        
        // Also set in session for compatibility with existing code
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $_SESSION['user_id'] = $validation['user_id'];
        $_SESSION['username'] = $validation['username'];
        $_SESSION['role'] = $validation['user_role'];
        $_SESSION['user'] = $GLOBALS['api_user'];
        $_SESSION['is_api_request'] = true;
    }
    
    /**
     * Get current API user
     */
    public function getCurrentApiUser() {
        return $GLOBALS['api_user'] ?? null;
    }
    
    /**
     * Check if current request is authenticated via API key
     */
    public function isApiAuthenticated() {
        return isset($GLOBALS['api_user']) && $GLOBALS['api_user']['is_api_request'] === true;
    }
    
    /**
     * Check if API user has specific permission
     */
    public function hasPermission($permission) {
        $user = $this->getCurrentApiUser();
        if (!$user) {
            return false;
        }
        
        return isset($user['permissions'][$permission]) && $user['permissions'][$permission] === true;
    }
    
    /**
     * Check if API user has specific role
     */
    public function hasRole($role) {
        $user = $this->getCurrentApiUser();
        if (!$user) {
            return false;
        }
        
        return strtolower($user['role']) === strtolower($role);
    }
    
    /**
     * Check if API user has specific scope
     */
    public function hasScope($scope) {
        $user = $this->getCurrentApiUser();
        if (!$user) {
            return false;
        }
        
        return in_array($scope, $user['scopes']);
    }
    
    /**
     * Require specific permission
     */
    public function requirePermission($permission) {
        if (!$this->hasPermission($permission)) {
            $this->sendForbiddenResponse("Permission required: {$permission}");
            return false;
        }
        return true;
    }
    
    /**
     * Require specific role
     */
    public function requireRole($role) {
        if (!$this->hasRole($role)) {
            $this->sendForbiddenResponse("Role required: {$role}");
            return false;
        }
        return true;
    }
    
    /**
     * Require specific scope
     */
    public function requireScope($scope) {
        if (!$this->hasScope($scope)) {
            $this->sendForbiddenResponse("Scope required: {$scope}");
            return false;
        }
        return true;
    }
    
    /**
     * Log API usage
     */
    public function logUsage($endpoint, $method, $responseCode, $responseTime, $requestSize = 0, $responseSize = 0) {
        $user = $this->getCurrentApiUser();
        if (!$user) {
            return;
        }
        
        $keyId = $user['api_key_data']['key_id'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        $this->apiKeyManager->logUsage(
            $keyId,
            $endpoint,
            $method,
            $this->clientIp,
            $userAgent,
            $responseCode,
            $responseTime,
            $requestSize,
            $responseSize
        );
    }
    
    /**
     * Send unauthorized response
     */
    private function sendUnauthorizedResponse($message) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'UNAUTHORIZED',
                'message' => $message
            ],
            'timestamp' => date('c')
        ]);
        exit;
    }
    
    /**
     * Send forbidden response
     */
    private function sendForbiddenResponse($message) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'FORBIDDEN',
                'message' => $message
            ],
            'timestamp' => date('c')
        ]);
        exit;
    }
    
    /**
     * Get client IP address
     */
    private function getClientIP() {
        $ipKeys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
        
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

// Global function for easy access
function getApiUser() {
    global $apiKeyAuth;
    if (!isset($apiKeyAuth)) {
        $apiKeyAuth = new ApiKeyAuth();
    }
    return $apiKeyAuth->getCurrentApiUser();
}

function isApiAuthenticated() {
    global $apiKeyAuth;
    if (!isset($apiKeyAuth)) {
        $apiKeyAuth = new ApiKeyAuth();
    }
    return $apiKeyAuth->isApiAuthenticated();
}
