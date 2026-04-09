<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/api-key-auth.php';

/**
 * Unified Authentication Middleware
 * Handles both session-based and API key authentication seamlessly
 */
class UnifiedAuth {
    
    private $sessionAuth;
    private $apiKeyAuth;
    private $user;
    private $authMethod;
    private $permissions;
    private $scopes;
    
    public function __construct() {
        $this->sessionAuth = new Auth();
        $this->apiKeyAuth = new ApiKeyAuth();
        $this->user = null;
        $this->authMethod = null;
        $this->permissions = null;
        $this->scopes = null;
    }
    
    /**
     * Authenticate user using either session or API key
     * @param string|null $requiredScope Optional scope requirement for API key auth
     * @return bool True if authenticated successfully
     */
    public function authenticate($requiredScope = null) {
        // Try API key authentication first
        if ($this->apiKeyAuth->authenticate($requiredScope)) {
            $this->user = $this->apiKeyAuth->getCurrentApiUser();
            $this->authMethod = 'api_key';
            $this->permissions = $this->apiKeyAuth->getCurrentApiUser()['permissions'] ?? [];
            $this->scopes = $this->apiKeyAuth->getCurrentApiUser()['scopes'] ?? [];
            return true;
        }
        
        // Fall back to session authentication
        try {
            $this->sessionAuth->requireAuth();
            $this->user = $this->sessionAuth->getCurrentUser();
            if ($this->user) {
                $this->authMethod = 'session';
                $this->permissions = $this->getUserPermissions($this->user['role']);
                $this->scopes = $this->getDefaultScopesForRole($this->user['role']);
                return true;
            }
        } catch (Exception $e) {
            // Session auth failed, continue to return false
        }
        
        return false;
    }
    
    /**
     * Get current authenticated user
     * @return array|null User data or null if not authenticated
     */
    public function getCurrentUser() {
        return $this->user;
    }
    
    /**
     * Get authentication method used
     * @return string|null 'session', 'api_key', or null
     */
    public function getAuthMethod() {
        return $this->authMethod;
    }
    
    /**
     * Check if user has specific permission
     * @param string $resource Resource name (e.g., 'users', 'assets')
     * @param string $action Action name (e.g., 'read', 'write', 'delete')
     * @return bool True if user has permission
     */
    public function hasPermission($resource, $action) {
        if (!$this->permissions) {
            return false;
        }
        
        // For API key auth, check both scopes and permissions
        if ($this->authMethod === 'api_key') {
            // First check if scope exists
            $scope = $resource . ':' . $action;
            if ($this->hasScope($scope)) {
                return true;
            }
            // Fall back to permission check
            return isset($this->permissions[$resource][$action]) && $this->permissions[$resource][$action];
        }
        
        // For session auth, check role-based permissions
        return isset($this->permissions[$resource][$action]) && $this->permissions[$resource][$action];
    }
    
    /**
     * Check if user has specific scope (API key only)
     * @param string $scope Scope to check (e.g., 'assets:read')
     * @return bool True if user has scope
     */
    public function hasScope($scope) {
        if ($this->authMethod !== 'api_key' || !$this->scopes) {
            return false;
        }
        
        return in_array($scope, $this->scopes);
    }
    
    /**
     * Require specific permission or throw exception
     * @param string $resource Resource name
     * @param string $action Action name
     * @throws Exception If permission not granted
     */
    public function requirePermission($resource, $action) {
        if (!$this->hasPermission($resource, $action)) {
            $this->sendUnauthorizedResponse("Insufficient permissions for {$resource}:{$action}");
        }
    }
    
    /**
     * Require specific scope or throw exception (API key only)
     * @param string $scope Scope to require
     * @throws Exception If scope not granted
     */
    public function requireScope($scope) {
        if (!$this->hasScope($scope)) {
            $this->sendUnauthorizedResponse("Insufficient scope: {$scope}");
        }
    }
    
    /**
     * Check if user has admin role
     * @return bool True if user is admin
     */
    public function isAdmin() {
        return $this->user && $this->user['role'] === 'Admin';
    }
    
    /**
     * Require admin role or throw exception
     * @throws Exception If user is not admin
     */
    public function requireAdmin() {
        if (!$this->isAdmin()) {
            $this->sendUnauthorizedResponse('Admin privileges required');
        }
    }
    
    /**
     * Log API usage for API key authentication
     * @param string $endpoint Endpoint accessed
     * @param string $method HTTP method
     * @param int $responseCode HTTP response code
     * @param int $responseTime Response time in milliseconds
     * @param int $requestSize Request size in bytes
     * @param int $responseSize Response size in bytes
     */
    public function logUsage($endpoint, $method, $responseCode, $responseTime, $requestSize = 0, $responseSize = 0) {
        if ($this->authMethod === 'api_key') {
            $this->apiKeyAuth->logUsage($endpoint, $method, $responseCode, $responseTime, $requestSize, $responseSize);
        }
    }
    
    /**
     * Get user permissions based on role
     * @param string $role User role
     * @return array Permissions array
     */
    private function getUserPermissions($role) {
        $permissions = [
            'Admin' => [
                'users' => ['read' => true, 'write' => true, 'delete' => true],
                'assets' => ['read' => true, 'write' => true, 'delete' => true],
                'vulnerabilities' => ['read' => true, 'write' => true, 'delete' => true],
                'recalls' => ['read' => true, 'write' => true, 'delete' => true],
                'reports' => ['read' => true, 'write' => true, 'delete' => true],
                'system' => ['read' => true, 'write' => true],
                'analytics' => ['read' => true, 'write' => true],
                'patches' => ['read' => true, 'write' => true],
                'remediations' => ['read' => true, 'write' => true, 'delete' => true],
                'locations' => ['read' => true, 'write' => true, 'delete' => true],
                'api_keys' => ['read' => true, 'write' => true, 'delete' => true]
            ],
            'User' => [
                'users' => ['read' => false, 'write' => false, 'delete' => false],
                'assets' => ['read' => true, 'write' => false, 'delete' => false],
                'vulnerabilities' => ['read' => true, 'write' => false, 'delete' => false],
                'recalls' => ['read' => true, 'write' => false, 'delete' => false],
                'reports' => ['read' => true, 'write' => false, 'delete' => false],
                'system' => ['read' => false, 'write' => false],
                'analytics' => ['read' => true, 'write' => false],
                'patches' => ['read' => true, 'write' => false],
                'remediations' => ['read' => true, 'write' => true, 'delete' => false],
                'locations' => ['read' => true, 'write' => false, 'delete' => false],
                'api_keys' => ['read' => false, 'write' => false, 'delete' => false]
            ]
        ];
        
        return $permissions[$role] ?? $permissions['User'];
    }
    
    /**
     * Get default scopes for role
     * @param string $role User role
     * @return array Scopes array
     */
    private function getDefaultScopesForRole($role) {
        $scopes = [
            'Admin' => [
                'users:read', 'users:write', 'users:delete',
                'assets:read', 'assets:write', 'assets:delete',
                'vulnerabilities:read', 'vulnerabilities:write', 'vulnerabilities:delete',
                'components:read', 'components:write', 'components:delete',
                'recalls:read', 'recalls:write', 'recalls:delete',
                'reports:read', 'reports:write', 'reports:delete',
                'risks:read', 'risks:write', 'risks:delete',
                'system:read', 'system:write',
                'analytics:read', 'analytics:write',
                'patches:read', 'patches:write',
                'remediations:read', 'remediations:write', 'remediations:delete',
                'locations:read', 'locations:write', 'locations:delete',
                'api_keys:read', 'api_keys:write', 'api_keys:delete'
            ],
            'User' => [
                'assets:read', 'assets:write',
                'vulnerabilities:read', 'vulnerabilities:write',
                'risks:read', 'risks:write',
                'components:read', 'components:write',
                'recalls:read', 'recalls:write',
                'reports:read', 'reports:write',
                'analytics:read', 'analytics:write',
                'patches:read', 'patches:write',                
                'remediations:read', 'remediations:write',
                'locations:read', 'locations:write',
                'api_keys:read', 'api_keys:write'
            ]
        ];
        
        return $scopes[$role] ?? $scopes['User'];
    }
    
    /**
     * Send unauthorized response
     * @param string $message Error message
     * @throws Exception Always throws exception
     */
    private function sendUnauthorizedResponse($message) {
        ob_clean();
        http_response_code(401);
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
}
?>
