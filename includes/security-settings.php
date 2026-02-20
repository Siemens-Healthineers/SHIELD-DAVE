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
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/cache.php';

/**
 * Security Settings Service
 * Manages all security-related configuration settings
 */
class SecuritySettings {
    
    private $db;
    private $cachePrefix = 'security_settings_';
    
    public function __construct() {
        $this->db = DatabaseConfig::getInstance();
    }
    
    /**
     * Get a security setting value
     * 
     * @param string $key Setting key
     * @param mixed $default Default value if setting not found
     * @return mixed Setting value or default
     */
    public function getSetting($key, $default = null) {
        $cacheKey = $this->cachePrefix . $key;
        
        // Try cache first
        $cached = Cache::get($cacheKey);
        if ($cached !== false && $cached !== null) {
            return $cached;
        }
        
        try {
            $stmt = $this->db->prepare("SELECT setting_value FROM security_settings WHERE setting_key = ?");
            $stmt->execute([$key]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($result && isset($result['setting_value'])) {
                $value = $result['setting_value'];
                // Cache the result
                Cache::set($cacheKey, $value, 3600); // Cache for 1 hour
                return $value;
            }
            
            return $default;
        } catch (Exception $e) {
            error_log("SecuritySettings::getSetting error: " . $e->getMessage());
            return $default;
        }
    }
    
    /**
     * Update a security setting
     * 
     * @param string $key Setting key
     * @param mixed $value Setting value
     * @param int $userId User ID making the change
     * @return bool Success status
     */
    public function updateSetting($key, $value, $userId = null) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO security_settings (setting_key, setting_value, updated_by) 
                VALUES (?, ?, ?)
                ON CONFLICT (setting_key) DO UPDATE SET 
                    setting_value = EXCLUDED.setting_value,
                    updated_at = CURRENT_TIMESTAMP,
                    updated_by = EXCLUDED.updated_by
            ");
            $result = $stmt->execute([$key, $value, $userId]);
            
            if ($result) {
                // Clear cache
                Cache::delete($this->cachePrefix . $key);
                
                // Log the change
                $this->logSettingChange($key, $value, $userId);
                
                return true;
            }
            
            return false;
        } catch (Exception $e) {
            error_log("SecuritySettings::updateSetting error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get all settings grouped by category
     * 
     * @return array Settings grouped by category
     */
    public function getAllSettings() {
        try {
            $stmt = $this->db->query("
                SELECT setting_key, setting_value, category, updated_at, updated_by
                FROM security_settings 
                ORDER BY category, setting_key
            ");
            $settings = $stmt->fetchAll();
            
            $grouped = [];
            foreach ($settings as $setting) {
                $grouped[$setting['category']][] = $setting;
            }
            
            return $grouped;
        } catch (Exception $e) {
            error_log("SecuritySettings::getAllSettings error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get password policy settings
     * 
     * @return array Password policy configuration
     */
    public function getPasswordPolicy() {
        return [
            'min_length' => (int) $this->getSetting('password_min_length', 8),
            'require_uppercase' => (bool) $this->getSetting('password_require_uppercase', true),
            'require_lowercase' => (bool) $this->getSetting('password_require_lowercase', true),
            'require_numbers' => (bool) $this->getSetting('password_require_numbers', true),
            'require_special' => (bool) $this->getSetting('password_require_special', true),
            'expiration_days' => (int) $this->getSetting('password_expiration_days', 90),
            'history_count' => (int) $this->getSetting('password_history_count', 5)
        ];
    }
    
    /**
     * Update password policy
     * 
     * @param array $policy Password policy settings
     * @param int $userId User ID making the change
     * @return bool Success status
     */
    public function updatePasswordPolicy($policy, $userId = null) {
        $settings = [
            'password_min_length' => $policy['min_length'] ?? 8,
            'password_require_uppercase' => isset($policy['require_uppercase']) ? ($policy['require_uppercase'] ? '1' : '0') : '0',
            'password_require_lowercase' => isset($policy['require_lowercase']) ? ($policy['require_lowercase'] ? '1' : '0') : '0',
            'password_require_numbers' => isset($policy['require_numbers']) ? ($policy['require_numbers'] ? '1' : '0') : '0',
            'password_require_special' => isset($policy['require_special']) ? ($policy['require_special'] ? '1' : '0') : '0',
            'password_expiration_days' => $policy['expiration_days'] ?? 90,
            'password_history_count' => $policy['history_count'] ?? 5
        ];
        
        $success = true;
        foreach ($settings as $key => $value) {
            if (!$this->updateSetting($key, $value, $userId)) {
                $success = false;
            }
        }
        
        return $success;
    }
    
    /**
     * Validate password against current policy
     * 
     * @param string $password Password to validate
     * @return array Validation result with success status and errors
     */
    public function validatePassword($password) {
        $policy = $this->getPasswordPolicy();
        $errors = [];
        
        // Check minimum length
        if (strlen($password) < $policy['min_length']) {
            $errors[] = "Password must be at least {$policy['min_length']} characters long";
        }
        
        // Check for uppercase
        if ($policy['require_uppercase'] && !preg_match('/[A-Z]/', $password)) {
            $errors[] = "Password must contain at least one uppercase letter";
        }
        
        // Check for lowercase
        if ($policy['require_lowercase'] && !preg_match('/[a-z]/', $password)) {
            $errors[] = "Password must contain at least one lowercase letter";
        }
        
        // Check for numbers
        if ($policy['require_numbers'] && !preg_match('/[0-9]/', $password)) {
            $errors[] = "Password must contain at least one number";
        }
        
        // Check for special characters
        if ($policy['require_special'] && !preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = "Password must contain at least one special character";
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors
        ];
    }
    
    /**
     * Get authentication settings
     * 
     * @return array Authentication configuration
     */
    public function getAuthenticationSettings() {
        return [
            'max_login_attempts' => (int) $this->getSetting('max_login_attempts', 5),
            'lockout_duration_minutes' => (int) $this->getSetting('lockout_duration_minutes', 15),
            'session_timeout_minutes' => (int) $this->getSetting('session_timeout_minutes', 30),
            'require_2fa' => (bool) $this->getSetting('require_2fa', false)
        ];
    }
    
    /**
     * Get security monitoring settings
     * 
     * @return array Monitoring configuration
     */
    public function getMonitoringSettings() {
        return [
            'enable_failed_login_tracking' => (bool) $this->getSetting('enable_failed_login_tracking', true),
            'enable_audit_logging' => (bool) $this->getSetting('enable_audit_logging', true),
            'auto_block_ips' => (bool) $this->getSetting('auto_block_ips', true),
            'brute_force_threshold' => (int) $this->getSetting('brute_force_threshold', 10)
        ];
    }
    
    /**
     * Get system security settings
     * 
     * @return array System security configuration
     */
    public function getSystemSecuritySettings() {
        return [
            'enable_csrf_protection' => (bool) $this->getSetting('enable_csrf_protection', true),
            'enable_xss_protection' => (bool) $this->getSetting('enable_xss_protection', true),
            'enable_sql_injection_protection' => (bool) $this->getSetting('enable_sql_injection_protection', true),
            'security_headers_enabled' => (bool) $this->getSetting('security_headers_enabled', true)
        ];
    }
    
    /**
     * Reset settings to defaults
     * 
     * @param int $userId User ID making the change
     * @return bool Success status
     */
    public function resetToDefaults($userId = null) {
        try {
            // Delete all current settings
            $this->db->query("DELETE FROM security_settings");
            
            // Clear all cache
            Cache::flush();
            
            // Re-insert default settings
            $defaultSettings = [
                // Password Policy
                ['password_min_length', '8', 'password_policy'],
                ['password_require_uppercase', '1', 'password_policy'],
                ['password_require_lowercase', '1', 'password_policy'],
                ['password_require_numbers', '1', 'password_policy'],
                ['password_require_special', '1', 'password_policy'],
                ['password_expiration_days', '90', 'password_policy'],
                ['password_history_count', '5', 'password_policy'],
                
                // Authentication
                ['max_login_attempts', '5', 'authentication'],
                ['lockout_duration_minutes', '15', 'authentication'],
                ['session_timeout_minutes', '30', 'authentication'],
                ['require_2fa', '0', 'authentication'],
                
                // Monitoring
                ['enable_failed_login_tracking', '1', 'monitoring'],
                ['enable_audit_logging', '1', 'monitoring'],
                ['auto_block_ips', '1', 'monitoring'],
                ['brute_force_threshold', '10', 'monitoring'],
                
                // System Security
                ['enable_csrf_protection', '1', 'system'],
                ['enable_xss_protection', '1', 'system'],
                ['enable_sql_injection_protection', '1', 'system'],
                ['security_headers_enabled', '1', 'system']
            ];
            
            $stmt = $this->db->prepare("
                INSERT INTO security_settings (setting_key, setting_value, category, updated_by) 
                VALUES (?, ?, ?, ?)
            ");
            
            foreach ($defaultSettings as $setting) {
                $stmt->execute([$setting[0], $setting[1], $setting[2], $userId]);
            }
            
            return true;
        } catch (Exception $e) {
            error_log("SecuritySettings::resetToDefaults error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Log setting change for audit trail
     * 
     * @param string $key Setting key
     * @param mixed $value New value
     * @param int $userId User ID
     */
    private function logSettingChange($key, $value, $userId) {
        try {
            // This would integrate with SecurityAudit class when implemented
            // For now, just log to error log
            error_log("Security setting changed: {$key} = {$value} by user {$userId}");
        } catch (Exception $e) {
            error_log("SecuritySettings::logSettingChange error: " . $e->getMessage());
        }
    }
    
    /**
     * Set a security setting (private method for internal use)
     * 
     * @param string $key Setting key
     * @param string $value Setting value
     * @param string $category Setting category
     * @param int $userId User ID making the change
     * @return bool Success status
     */
    private function setSetting($key, $value, $category = 'general', $userId = null) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO security_settings (setting_key, setting_value, category, updated_by) 
                VALUES (?, ?, ?, ?)
                ON CONFLICT (setting_key) DO UPDATE SET 
                    setting_value = EXCLUDED.setting_value,
                    category = EXCLUDED.category,
                    updated_at = CURRENT_TIMESTAMP,
                    updated_by = EXCLUDED.updated_by
            ");
            
            $result = $stmt->execute([$key, $value, $category, $userId]);
            
            // Clear cache for this setting
            $cacheKey = $this->cachePrefix . $key;
            Cache::delete($cacheKey);
            
            return $result;
        } catch (Exception $e) {
            error_log("SecuritySettings::setSetting error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Check if system is in lockdown mode
     * 
     * @return array Lockdown status information
     */
    public function isSystemLockedDown() {
        $lockdown = $this->getSetting('system_lockdown', '0');
        
        if ($lockdown === '1') {
            $initiatedAt = $this->getSetting('lockdown_initiated_at');
            $duration = (int) $this->getSetting('lockdown_duration', 60);
            
            // Check if lockdown has expired
            if ($initiatedAt) {
                $lockdownTime = strtotime($initiatedAt);
                $expiryTime = $lockdownTime + ($duration * 60); // Convert minutes to seconds
                
                if (time() > $expiryTime) {
                    // Lockdown has expired, clear it
                    $this->setSetting('system_lockdown', '0', 'emergency');
                    $this->setSetting('lockdown_reason', '', 'emergency');
                    $this->setSetting('lockdown_initiated_by', '', 'emergency');
                    $this->setSetting('lockdown_initiated_at', '', 'emergency');
                    $this->setSetting('lockdown_duration', '', 'emergency');
                    
                    return [
                        'locked' => false,
                        'expired' => true
                    ];
                }
            }
            
            return [
                'locked' => true,
                'reason' => $this->getSetting('lockdown_reason', 'Emergency lockdown'),
                'initiated_by' => $this->getSetting('lockdown_initiated_by'),
                'initiated_at' => $initiatedAt,
                'duration' => $duration,
                'expires_at' => $initiatedAt ? date('Y-m-d H:i:s', strtotime($initiatedAt) + ($duration * 60)) : null
            ];
        }
        
        return ['locked' => false];
    }
    
    /**
     * Clear system lockdown
     * 
     * @param int $userId User ID clearing the lockdown
     * @return bool Success status
     */
    public function clearSystemLockdown($userId = null) {
        try {
            $this->setSetting('system_lockdown', '0', 'emergency');
            $this->setSetting('lockdown_reason', '', 'emergency');
            $this->setSetting('lockdown_initiated_by', '', 'emergency');
            $this->setSetting('lockdown_initiated_at', '', 'emergency');
            $this->setSetting('lockdown_duration', '', 'emergency');
            
            // Log the lockdown clearance
            if ($userId) {
                $this->logSettingChange('system_lockdown', '0', $userId, 'Lockdown cleared by admin');
            }
            
            return true;
        } catch (Exception $e) {
            error_log("SecuritySettings::clearSystemLockdown error: " . $e->getMessage());
            return false;
        }
    }
}
