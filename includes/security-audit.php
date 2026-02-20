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
require_once __DIR__ . '/geoip-service.php';

/**
 * Security Audit Service
 * Handles security event logging and audit trail management
 */
class SecurityAudit {
    
    private $db;
    private $geoip;
    
    // Event types
    const EVENT_LOGIN = 'login';
    const EVENT_LOGOUT = 'logout';
    const EVENT_LOGIN_FAILED = 'login_failed';
    const EVENT_PASSWORD_CHANGE = 'password_change';
    const EVENT_ACCOUNT_LOCKED = 'account_locked';
    const EVENT_ACCOUNT_UNLOCKED = 'account_unlocked';
    const EVENT_IP_BLOCKED = 'ip_blocked';
    const EVENT_IP_UNBLOCKED = 'ip_unblocked';
    const EVENT_PERMISSION_CHANGE = 'permission_change';
    const EVENT_SETTING_CHANGE = 'setting_change';
    const EVENT_SECURITY_INCIDENT = 'security_incident';
    const EVENT_SYSTEM_LOCKDOWN = 'system_lockdown';
    const EVENT_SESSION_TERMINATED = 'session_terminated';
    const EVENT_FILE_UPLOAD = 'file_upload';
    const EVENT_DATA_EXPORT = 'data_export';
    const EVENT_ADMIN_ACTION = 'admin_action';
    
    public function __construct() {
        $this->db = DatabaseConfig::getInstance();
        $this->geoip = new GeoIPService();
    }
    
    /**
     * Log a security event
     * 
     * @param string $eventType Event type constant
     * @param int $userId User ID (optional)
     * @param string $description Event description
     * @param array $metadata Additional metadata (optional)
     * @param string $ipAddress IP address (optional)
     * @param string $username Username (optional)
     * @return bool Success status
     */
    public function logEvent($eventType, $userId = null, $description, $metadata = null, $ipAddress = null, $username = null) {
        try {
            // Get IP address if not provided
            if (!$ipAddress) {
                $ipAddress = $this->getClientIpAddress();
            }
            
            // Get username if not provided but user ID is
            if (!$username && $userId) {
                $username = $this->getUsernameById($userId);
            }
            
            // Get location information for the IP address
            $location = $this->geoip->getLocation($ipAddress);
            $locationString = $this->geoip->getLocationString($ipAddress);
            
            // Add location data to metadata
            if ($metadata === null) {
                $metadata = [];
            }
            $metadata['location'] = $locationString;
            $metadata['location_data'] = $location;
            
            $stmt = $this->db->prepare("
                INSERT INTO security_audit_log (event_type, user_id, username, ip_address, description, metadata) 
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            
            $metadataJson = $metadata ? json_encode($metadata) : null;
            
            $result = $stmt->execute([
                $eventType,
                $userId,
                $username,
                $ipAddress,
                $description,
                $metadataJson
            ]);
            
            return $result;
        } catch (Exception $e) {
            error_log("SecurityAudit::logEvent error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get audit trail with filters and location information
     * 
     * @param array $filters Filter options
     * @return array Audit log entries with location data
     */
    public function getAuditTrail($filters = []) {
        try {
            $where = [];
            $params = [];
            
            // Event type filter
            if (!empty($filters['event_type'])) {
                $where[] = "event_type = ?";
                $params[] = $filters['event_type'];
            }
            
            // User filter
            if (!empty($filters['user_id'])) {
                $where[] = "user_id = ?";
                $params[] = $filters['user_id'];
            }
            
            if (!empty($filters['username'])) {
                $where[] = "username = ?";
                $params[] = $filters['username'];
            }
            
            // IP filter
            if (!empty($filters['ip_address'])) {
                $where[] = "ip_address = ?";
                $params[] = $filters['ip_address'];
            }
            
            // Date range filter
            if (!empty($filters['start_date'])) {
                $where[] = "created_at >= ?";
                $params[] = $filters['start_date'];
            }
            
            if (!empty($filters['end_date'])) {
                $where[] = "created_at <= ?";
                $params[] = $filters['end_date'];
            }
            
            // Build query
            $sql = "SELECT * FROM security_audit_log";
            if (!empty($where)) {
                $sql .= " WHERE " . implode(' AND ', $where);
            }
            $sql .= " ORDER BY created_at DESC";
            
            // Limit
            $limit = $filters['limit'] ?? 100;
            if ($limit > 0) {
                $sql .= " LIMIT " . (int) $limit;
            }
            
            $stmt = $this->db->prepare($sql);
            $stmt->execute($params);
            $entries = $stmt->fetchAll();
            
            // Process entries to add location information
            foreach ($entries as &$entry) {
                // Parse metadata to get location info
                $metadata = $entry['metadata'] ? json_decode($entry['metadata'], true) : [];
                
                // Add location string for display
                $entry['location'] = $metadata['location'] ?? 'Unknown Location';
                
                // Add country flag if available
                if (isset($metadata['location_data']['country_code'])) {
                    $entry['country_flag'] = $this->geoip->getCountryFlag($metadata['location_data']['country_code']);
                } else {
                    $entry['country_flag'] = '';
                }
                
                // Add formatted location data
                $entry['location_data'] = $metadata['location_data'] ?? null;
            }
            
            return $entries;
        } catch (Exception $e) {
            error_log("SecurityAudit::getAuditTrail error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Export audit log to CSV
     * 
     * @param string $startDate Start date (Y-m-d format)
     * @param string $endDate End date (Y-m-d format)
     * @param array $filters Additional filters
     * @return string CSV content
     */
    public function exportAuditLog($startDate, $endDate, $filters = []) {
        try {
            $filters['start_date'] = $startDate . ' 00:00:00';
            $filters['end_date'] = $endDate . ' 23:59:59';
            $filters['limit'] = 0; // No limit for export
            
            $entries = $this->getAuditTrail($filters);
            
            // Create CSV content
            $csv = "Date,Time,Event Type,User,IP Address,Description,Metadata\n";
            
            foreach ($entries as $entry) {
                $date = date('Y-m-d', strtotime($entry['created_at']));
                $time = date('H:i:s', strtotime($entry['created_at']));
                $user = $entry['username'] ?: ($entry['user_id'] ? "User ID: {$entry['user_id']}" : 'System');
                $metadata = $entry['metadata'] ? str_replace(["\n", "\r"], ' ', $entry['metadata']) : '';
                
                $csv .= sprintf(
                    "%s,%s,%s,%s,%s,\"%s\",\"%s\"\n",
                    $date,
                    $time,
                    $entry['event_type'],
                    $user,
                    $entry['ip_address'],
                    str_replace('"', '""', $entry['description']),
                    str_replace('"', '""', $metadata)
                );
            }
            
            return $csv;
        } catch (Exception $e) {
            error_log("SecurityAudit::exportAuditLog error: " . $e->getMessage());
            return '';
        }
    }
    
    /**
     * Get audit statistics
     * 
     * @param int $days Number of days to analyze
     * @return array Statistics
     */
    public function getAuditStatistics($days = 30) {
        try {
            $stmt = $this->db->prepare("
                SELECT 
                    event_type,
                    COUNT(*) as count,
                    COUNT(DISTINCT user_id) as unique_users,
                    COUNT(DISTINCT ip_address) as unique_ips
                FROM security_audit_log 
                WHERE created_at >= NOW() - INTERVAL '{$days} days'
                GROUP BY event_type
                ORDER BY count DESC
            ");
            $stmt->execute();
            
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log("SecurityAudit::getAuditStatistics error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get recent security events
     * 
     * @param int $limit Number of events to return
     * @return array Recent events
     */
    public function getRecentEvents($limit = 20) {
        try {
            $stmt = $this->db->prepare("
                SELECT event_type, username, ip_address, description, created_at
                FROM security_audit_log 
                WHERE event_type IN (?, ?, ?, ?, ?)
                ORDER BY created_at DESC 
                LIMIT ?
            ");
            $stmt->execute([
                self::EVENT_LOGIN_FAILED,
                self::EVENT_ACCOUNT_LOCKED,
                self::EVENT_IP_BLOCKED,
                self::EVENT_SECURITY_INCIDENT,
                self::EVENT_SYSTEM_LOCKDOWN,
                $limit
            ]);
            
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log("SecurityAudit::getRecentEvents error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Log user login
     * 
     * @param int $userId User ID
     * @param string $username Username
     * @param string $ipAddress IP address
     * @return bool Success status
     */
    public function logLogin($userId, $username, $ipAddress = null) {
        return $this->logEvent(
            self::EVENT_LOGIN,
            $userId,
            "User {$username} logged in successfully",
            null,
            $ipAddress,
            $username
        );
    }
    
    /**
     * Log user logout
     * 
     * @param int $userId User ID
     * @param string $username Username
     * @param string $ipAddress IP address
     * @return bool Success status
     */
    public function logLogout($userId, $username, $ipAddress = null) {
        return $this->logEvent(
            self::EVENT_LOGOUT,
            $userId,
            "User {$username} logged out",
            null,
            $ipAddress,
            $username
        );
    }
    
    /**
     * Log failed login attempt
     * 
     * @param string $username Username attempted
     * @param string $reason Reason for failure
     * @param string $ipAddress IP address
     * @return bool Success status
     */
    public function logFailedLogin($username, $reason, $ipAddress = null) {
        return $this->logEvent(
            self::EVENT_LOGIN_FAILED,
            null,
            "Failed login attempt for user {$username}: {$reason}",
            ['username' => $username, 'reason' => $reason],
            $ipAddress,
            $username
        );
    }
    
    /**
     * Log password change
     * 
     * @param int $userId User ID
     * @param string $username Username
     * @param string $ipAddress IP address
     * @return bool Success status
     */
    public function logPasswordChange($userId, $username, $ipAddress = null) {
        return $this->logEvent(
            self::EVENT_PASSWORD_CHANGE,
            $userId,
            "User {$username} changed password",
            null,
            $ipAddress,
            $username
        );
    }
    
    /**
     * Log account lockout
     * 
     * @param string $username Username
     * @param string $reason Reason for lockout
     * @param string $ipAddress IP address
     * @return bool Success status
     */
    public function logAccountLocked($username, $reason, $ipAddress = null) {
        return $this->logEvent(
            self::EVENT_ACCOUNT_LOCKED,
            null,
            "Account locked for user {$username}: {$reason}",
            ['username' => $username, 'reason' => $reason],
            $ipAddress,
            $username
        );
    }
    
    /**
     * Log IP blocking
     * 
     * @param string $ipAddress IP address
     * @param string $reason Reason for blocking
     * @param int $blockedBy User ID who blocked
     * @return bool Success status
     */
    public function logIpBlocked($ipAddress, $reason, $blockedBy = null) {
        return $this->logEvent(
            self::EVENT_IP_BLOCKED,
            $blockedBy,
            "IP address {$ipAddress} blocked: {$reason}",
            ['ip_address' => $ipAddress, 'reason' => $reason],
            $ipAddress
        );
    }
    
    /**
     * Log security setting change
     * 
     * @param string $settingKey Setting key
     * @param mixed $oldValue Old value
     * @param mixed $newValue New value
     * @param int $userId User ID making change
     * @return bool Success status
     */
    public function logSettingChange($settingKey, $oldValue, $newValue, $userId) {
        return $this->logEvent(
            self::EVENT_SETTING_CHANGE,
            $userId,
            "Security setting '{$settingKey}' changed from '{$oldValue}' to '{$newValue}'",
            [
                'setting_key' => $settingKey,
                'old_value' => $oldValue,
                'new_value' => $newValue
            ]
        );
    }
    
    /**
     * Log admin action
     * 
     * @param string $action Admin action performed
     * @param int $userId Admin user ID
     * @param string $target Target of action
     * @param array $details Action details
     * @return bool Success status
     */
    public function logAdminAction($action, $userId, $target = null, $details = []) {
        $description = "Admin action: {$action}";
        if ($target) {
            $description .= " on {$target}";
        }
        
        return $this->logEvent(
            self::EVENT_ADMIN_ACTION,
            $userId,
            $description,
            array_merge(['action' => $action, 'target' => $target], $details)
        );
    }
    
    /**
     * Clean up old audit logs
     * 
     * @param int $daysOld Days old to clean up (default: 90)
     * @return int Number of records deleted
     */
    public function cleanupAuditLogs($daysOld = 90) {
        try {
            $stmt = $this->db->prepare("
                DELETE FROM security_audit_log 
                WHERE created_at < NOW() - INTERVAL '{$daysOld} days'
            ");
            $stmt->execute();
            
            return $stmt->rowCount();
        } catch (Exception $e) {
            error_log("SecurityAudit::cleanupAuditLogs error: " . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Get client IP address
     * 
     * @return string IP address
     */
    private function getClientIpAddress() {
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
    
    /**
     * Get username by user ID
     * 
     * @param int $userId User ID
     * @return string|null Username or null
     */
    private function getUsernameById($userId) {
        try {
            $stmt = $this->db->prepare("SELECT username FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $result = $stmt->fetch();
            
            return $result ? $result['username'] : null;
        } catch (Exception $e) {
            return null;
        }
    }
}


