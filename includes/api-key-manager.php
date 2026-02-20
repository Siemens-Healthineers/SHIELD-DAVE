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

/**
 * API Key Manager class for handling external system authentication
 */
class ApiKeyManager {
    
    private $db;
    
    public function __construct() {
        $this->db = DatabaseConfig::getInstance();
    }
    
    /**
     * Generate a new API key
     */
    public function generateApiKey($prefix = 'dave') {
        $randomBytes = random_bytes(32);
        $key = $prefix . '_' . bin2hex($randomBytes);
        return $key;
    }
    
    /**
     * Hash an API key for secure storage
     */
    public function hashApiKey($apiKey) {
        return password_hash($apiKey, PASSWORD_DEFAULT);
    }
    
    /**
     * Verify an API key against its hash
     */
    public function verifyApiKey($apiKey, $hash) {
        return password_verify($apiKey, $hash);
    }
    
    /**
     * Create a new API key
     */
    public function createApiKey($data) {
        try {
            // Validate required fields
            if (empty($data['user_id'])) {
                return [
                    'success' => false,
                    'error' => 'User ID is required'
                ];
            }
            
            // Verify user exists and is active
            $user = $this->getUserById($data['user_id']);
            if (!$user || !$user['is_active']) {
                return [
                    'success' => false,
                    'error' => 'User not found or inactive'
                ];
            }
            
            $apiKey = $this->generateApiKey();
            $keyHash = $this->hashApiKey($apiKey);
            
            // Set default scopes based on user role if not provided
            $defaultScopes = $this->getDefaultScopesForRole($user['role']);
            $scopes = $data['scopes'] ?? $defaultScopes;
            
            // Set default permissions based on user role if not provided
            $defaultPermissions = $this->getDefaultPermissionsForRole($user['role']);
            $permissions = $data['permissions'] ?? $defaultPermissions;
            
            $sql = "INSERT INTO dave_api_keys (
                key_name, 
                description, 
                api_key, 
                key_hash, 
                user_id, 
                permissions, 
                scopes, 
                is_active, 
                rate_limit_per_hour,
                ip_whitelist,
                expires_at,
                created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            
            $params = [
                $data['key_name'],
                $data['description'] ?? '',
                $apiKey, // Store plain text for external use
                $keyHash, // Store hash for verification
                $data['user_id'],
                json_encode($permissions),
                json_encode($scopes),
                $data['is_active'] ?? true,
                $data['rate_limit_per_hour'] ?? 1000,
                isset($data['ip_whitelist']) && $data['ip_whitelist'] ? json_encode($data['ip_whitelist']) : null,
                $data['expires_at'] ?? null,
                $data['created_by'] ?? $data['user_id']
            ];
            
            $this->db->query($sql, $params);
            
            // Get the created key ID by querying the database
            $keyId = $this->db->query("SELECT key_id FROM dave_api_keys WHERE api_key = ?", [$apiKey])->fetch()['key_id'];
            
            return [
                'success' => true,
                'key_id' => $keyId,
                'api_key' => $apiKey, // Return plain text key for user
                'user_id' => $data['user_id'],
                'username' => $user['username'],
                'role' => $user['role'],
                'scopes' => $scopes,
                'permissions' => $permissions,
                'message' => 'API key created successfully'
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Get API key by key string
     */
    public function getApiKeyByKey($apiKey) {
        $sql = "SELECT * FROM dave_api_keys WHERE api_key = ? AND is_active = TRUE";
        $stmt = $this->db->query($sql, [$apiKey]);
        return $stmt->fetch();
    }
    
    /**
     * Get API key with user information
     */
    public function getApiKeyWithUser($apiKey) {
        $sql = "SELECT 
                    k.*,
                    u.username,
                    u.email as user_email,
                    u.role as user_role,
                    u.is_active as user_is_active,
                    u.last_login
                FROM dave_api_keys k
                JOIN users u ON k.user_id = u.user_id
                WHERE k.api_key = ? AND k.is_active = TRUE";
        $stmt = $this->db->query($sql, [$apiKey]);
        return $stmt->fetch();
    }
    
    /**
     * Get API key by ID
     */
    public function getApiKeyById($keyId) {
        $sql = "SELECT * FROM dave_api_keys WHERE key_id = ?";
        $stmt = $this->db->query($sql, [$keyId]);
        return $stmt->fetch();
    }
    
    /**
     * List all API keys for a user
     */
    public function listApiKeys($userId, $includeInactive = false) {
        $sql = "SELECT key_id, key_name, description, scopes, permissions, is_active, created_at, last_used, usage_count, expires_at, rate_limit_per_hour, ip_whitelist, user_id
                FROM dave_api_keys 
                WHERE user_id = ?";
        
        if (!$includeInactive) {
            $sql .= " AND is_active = TRUE";
        }
        
        $sql .= " ORDER BY created_at DESC";
        
        $stmt = $this->db->query($sql, [$userId]);
        return $stmt->fetchAll();
    }
    
    /**
     * List all API keys (admin only)
     */
    public function listAllApiKeys($includeInactive = false) {
        $sql = "SELECT key_id, key_name, description, scopes, permissions, is_active, created_at, last_used, usage_count, expires_at, rate_limit_per_hour, ip_whitelist, user_id
                FROM dave_api_keys";
        
        if (!$includeInactive) {
            $sql .= " WHERE is_active = TRUE";
        }
        
        $sql .= " ORDER BY created_at DESC";
        
        $stmt = $this->db->query($sql);
        return $stmt->fetchAll();
    }
    
    /**
     * Update API key
     */
    public function updateApiKey($keyId, $data) {
        try {
            $updateFields = [];
            $params = [];
            
            if (isset($data['key_name'])) {
                $updateFields[] = "key_name = ?";
                $params[] = $data['key_name'];
            }
            
            if (isset($data['description'])) {
                $updateFields[] = "description = ?";
                $params[] = $data['description'];
            }
            
            if (isset($data['permissions'])) {
                $updateFields[] = "permissions = ?";
                $params[] = json_encode($data['permissions']);
            }
            
            if (isset($data['scopes'])) {
                $updateFields[] = "scopes = ?";
                $params[] = json_encode($data['scopes']);
            }
            
            if (isset($data['is_active'])) {
                $updateFields[] = "is_active = ?";
                $params[] = $data['is_active'];
            }
            
            if (isset($data['rate_limit_per_hour'])) {
                $updateFields[] = "rate_limit_per_hour = ?";
                $params[] = $data['rate_limit_per_hour'];
            }
            
            if (isset($data['ip_whitelist'])) {
                $updateFields[] = "ip_whitelist = ?";
                $params[] = $data['ip_whitelist'] ? json_encode($data['ip_whitelist']) : null;
            }
            
            if (isset($data['expires_at'])) {
                $updateFields[] = "expires_at = ?";
                $params[] = $data['expires_at'];
            }
            
            if (empty($updateFields)) {
                return ['success' => false, 'error' => 'No fields to update'];
            }
            
            $updateFields[] = "updated_at = CURRENT_TIMESTAMP";
            $params[] = $keyId;
            
            $sql = "UPDATE dave_api_keys SET " . implode(', ', $updateFields) . " WHERE key_id = ?";
            $this->db->query($sql, $params);
            
            return ['success' => true, 'message' => 'API key updated successfully'];
            
        } catch (Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * Delete API key
     */
    public function deleteApiKey($keyId) {
        try {
            $sql = "DELETE FROM dave_api_keys WHERE key_id = ?";
            $this->db->query($sql, [$keyId]);
            
            return ['success' => true, 'message' => 'API key deleted successfully'];
            
        } catch (Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * Regenerate API key
     */
    public function regenerateApiKey($keyId) {
        try {
            // Get the existing key name before regenerating
            $existingKey = $this->getApiKeyById($keyId);
            if (!$existingKey) {
                return ['success' => false, 'error' => 'API key not found'];
            }
            
            $newApiKey = $this->generateApiKey();
            $newKeyHash = $this->hashApiKey($newApiKey);
            
            $sql = "UPDATE dave_api_keys 
                    SET api_key = ?, key_hash = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE key_id = ?";
            
            $this->db->query($sql, [$newApiKey, $newKeyHash, $keyId]);
            
            return [
                'success' => true,
                'api_key' => $newApiKey,
                'key_name' => $existingKey['key_name'],
                'message' => 'API key regenerated successfully'
            ];
            
        } catch (Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * Check if API key is valid and has required permissions
     */
    public function validateApiKey($apiKey, $requiredScope = null, $clientIp = null) {
        try {
            // Get API key data with user information
            $keyData = $this->getApiKeyWithUser($apiKey);
            
            if (!$keyData) {
                return [
                    'valid' => false,
                    'error' => 'Invalid API key'
                ];
            }
            
            // Check if key is active
            if (!$keyData['is_active']) {
                return [
                    'valid' => false,
                    'error' => 'API key is disabled'
                ];
            }
            
            // Check if associated user is active
            if (!$keyData['user_is_active']) {
                return [
                    'valid' => false,
                    'error' => 'Associated user account is disabled'
                ];
            }
            
            // Check expiration
            if ($keyData['expires_at'] && strtotime($keyData['expires_at']) < time()) {
                return [
                    'valid' => false,
                    'error' => 'API key has expired'
                ];
            }
            
            // Check IP whitelist
            if ($keyData['ip_whitelist'] && $clientIp) {
                $allowedIps = json_decode($keyData['ip_whitelist'], true);
                if (!in_array($clientIp, $allowedIps)) {
                    return [
                        'valid' => false,
                        'error' => 'IP address not allowed'
                    ];
                }
            }
            
            // Check rate limiting
            if (!$this->checkRateLimit($keyData['key_id'], $keyData['rate_limit_per_hour'])) {
                return [
                    'valid' => false,
                    'error' => 'Rate limit exceeded'
                ];
            }
            
            // Check scope if required
            if ($requiredScope) {
                $scopes = json_decode($keyData['scopes'], true);
                if (!in_array($requiredScope, $scopes)) {
                    return [
                        'valid' => false,
                        'error' => 'Insufficient permissions for this scope'
                    ];
                }
            }
            
            // Update usage statistics
            $this->updateUsageStats($keyData['key_id']);
            
            return [
                'valid' => true,
                'key_data' => $keyData,
                'user_id' => $keyData['user_id'],
                'username' => $keyData['username'],
                'user_role' => $keyData['user_role'],
                'user_email' => $keyData['user_email'],
                'permissions' => json_decode($keyData['permissions'], true),
                'scopes' => json_decode($keyData['scopes'], true),
                'user_permissions' => $this->getUserPermissions($keyData['user_role'])
            ];
            
        } catch (Exception $e) {
            return [
                'valid' => false,
                'error' => 'Validation error: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Check rate limiting for API key
     */
    private function checkRateLimit($keyId, $rateLimitPerHour) {
        $sql = "SELECT COUNT(*) as count 
                FROM dave_api_key_usage 
                WHERE key_id = ? 
                AND created_at > NOW() - INTERVAL '1 hour'";
        
        $stmt = $this->db->query($sql, [$keyId]);
        $result = $stmt->fetch();
        
        return $result['count'] < $rateLimitPerHour;
    }
    
    /**
     * Update usage statistics
     */
    private function updateUsageStats($keyId) {
        $sql = "UPDATE dave_api_keys 
                SET last_used = CURRENT_TIMESTAMP, 
                    usage_count = usage_count + 1 
                WHERE key_id = ?";
        
        $this->db->query($sql, [$keyId]);
    }
    
    /**
     * Log API key usage
     */
    public function logUsage($keyId, $endpoint, $method, $ipAddress, $userAgent, $responseCode, $responseTime, $requestSize = 0, $responseSize = 0) {
        try {
            $sql = "INSERT INTO dave_api_key_usage (
                key_id, endpoint, method, ip_address, user_agent, 
                response_code, response_time_ms, request_size, response_size
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
            
            $this->db->query($sql, [
                $keyId, $endpoint, $method, $ipAddress, $userAgent,
                $responseCode, $responseTime, $requestSize, $responseSize
            ]);
            
        } catch (Exception $e) {
            // Log error but don't fail the request
            error_log("Failed to log API key usage: " . $e->getMessage());
        }
    }
    
    /**
     * Get usage statistics for an API key
     */
    public function getUsageStats($keyId, $days = 30) {
        $sql = "SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as requests,
                    AVG(response_time_ms) as avg_response_time,
                    COUNT(CASE WHEN response_code >= 400 THEN 1 END) as error_count
                FROM dave_api_key_usage 
                WHERE key_id = ? 
                AND created_at > NOW() - INTERVAL ? DAY
                GROUP BY DATE(created_at)
                ORDER BY date DESC";
        
        $stmt = $this->db->query($sql, [$keyId, $days]);
        return $stmt->fetchAll();
    }
    
    /**
     * Get user by ID
     */
    private function getUserById($userId) {
        $sql = "SELECT * FROM users WHERE user_id = ?";
        $stmt = $this->db->query($sql, [$userId]);
        return $stmt->fetch();
    }
    
    /**
     * Get default scopes for a user role
     */
    private function getDefaultScopesForRole($role) {
        switch (strtolower($role)) {
            case 'admin':
                return [
                    'assets:read', 'assets:write', 'assets:delete',
                    'vulnerabilities:read', 'vulnerabilities:write', 'vulnerabilities:delete',
                    'recalls:read', 'recalls:write', 'recalls:delete',
                    'users:read', 'users:write', 'users:delete',
                    'reports:read', 'reports:write', 'reports:delete',
                    'risks:read', 'risks:write', 'risks:delete',
                    'components:read', 'components:write', 'components:delete',
                    'system:read', 'system:write'
                ];
            case 'user':
                return [
                    'assets:read',
                    'vulnerabilities:read',
                    'components:read',
                    'recalls:read',
                    'reports:read'
                ];
            default:
                return ['assets:read'];
        }
    }
    
    /**
     * Get default permissions for a user role
     */
    private function getDefaultPermissionsForRole($role) {
        switch (strtolower($role)) {
            case 'admin':
                return [
                    'assets' => ['read' => true, 'write' => true, 'delete' => true],
                    'vulnerabilities' => ['read' => true, 'write' => true, 'delete' => true],
                    'components' => ['read' => true, 'write' => true, 'delete' => true],
                    'patches' => ['read' => true, 'write' => true, 'delete' => true],
                    'recalls' => ['read' => true, 'write' => true, 'delete' => true],
                    'users' => ['read' => true, 'write' => true, 'delete' => true],
                    'reports' => ['read' => true, 'write' => true, 'delete' => true],
                    'system' => ['read' => true, 'write' => true],
                    'risks' => ['read' => true, 'write' => true, 'delete' => true]
                ];
            case 'user':
                return [
                    'assets' => ['read' => true, 'write' => false, 'delete' => false],
                    'vulnerabilities' => ['read' => true, 'write' => false, 'delete' => false],
                    'components' => ['read' => true, 'write' => true, 'delete' => true],
                    'patches' => ['read' => true, 'write' => true, 'delete' => true],
                    'recalls' => ['read' => true, 'write' => false, 'delete' => false],
                    'reports' => ['read' => true, 'write' => false, 'delete' => false],
                    'risks' => ['read' => true, 'write' => true, 'delete' => true],
                ];
            default:
                return [
                    'assets' => ['read' => true, 'write' => false, 'delete' => false]
                ];
        }
    }
    
    /**
     * Get user permissions based on role
     */
    private function getUserPermissions($role) {
        // This should match the permissions system in the Auth class
        $permissions = [];
        
        switch (strtolower($role)) {
            case 'admin':
                $permissions = [
                    'manage_users' => true,
                    'manage_assets' => true,
                    'manage_vulnerabilities' => true,
                    'manage_recalls' => true,
                    'view_reports' => true,
                    'manage_system' => true,
                    'view_analytics' => true,
                    'manage_api_keys' => true
                ];
                break;
            case 'user':
                $permissions = [
                    'manage_users' => false,
                    'manage_assets' => false,
                    'manage_vulnerabilities' => false,
                    'manage_recalls' => false,
                    'view_reports' => true,
                    'manage_system' => false,
                    'view_analytics' => true,
                    'manage_api_keys' => false
                ];
                break;
            default:
                $permissions = [
                    'manage_users' => false,
                    'manage_assets' => false,
                    'manage_vulnerabilities' => false,
                    'manage_recalls' => false,
                    'view_reports' => false,
                    'manage_system' => false,
                    'view_analytics' => false,
                    'manage_api_keys' => false
                ];
        }
        
        return $permissions;
    }
}
