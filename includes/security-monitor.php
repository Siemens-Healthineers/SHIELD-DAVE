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
require_once __DIR__ . '/security-settings.php';

/**
 * Security Monitor Service
 * Handles failed login tracking, IP blocking, and threat detection
 */
class SecurityMonitor {
    
    private $db;
    private $settings;
    
    public function __construct() {
        $this->db = DatabaseConfig::getInstance();
        $this->settings = new SecuritySettings();
    }
    
    /**
     * Log a failed login attempt
     * 
     * @param string $username Username attempted
     * @param string $ip IP address
     * @param string $reason Reason for failure
     * @param string $userAgent User agent string
     * @return bool Success status
     */
    public function logFailedLogin($username, $ip, $reason = 'Invalid credentials', $userAgent = null) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO failed_login_attempts (username, ip_address, user_agent, reason) 
                VALUES (?, ?, ?, ?)
            ");
            $result = $stmt->execute([$username, $ip, $userAgent, $reason]);
            
            if ($result) {
                // Check for brute force attacks
                $this->checkBruteForceAttack($username, $ip);
                
                // Auto-block IP if configured
                if ($this->settings->getSetting('auto_block_ips', true)) {
                    $this->checkAutoBlock($ip);
                }
                
                return true;
            }
            
            return false;
        } catch (Exception $e) {
            error_log("SecurityMonitor::logFailedLogin error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get failed login attempts for a user or IP
     * 
     * @param string $username Username (optional)
     * @param string $ip IP address (optional)
     * @param int $timeframe Timeframe in minutes (default: 60)
     * @return array Failed attempts
     */
    public function getFailedAttempts($username = null, $ip = null, $timeframe = 60) {
        try {
            $where = ["attempt_time >= NOW() - INTERVAL '{$timeframe} minutes'"];
            $params = [];
            
            if ($username) {
                $where[] = "username = ?";
                $params[] = $username;
            }
            
            if ($ip) {
                $where[] = "ip_address = ?";
                $params[] = $ip;
            }
            
            $sql = "SELECT * FROM failed_login_attempts WHERE " . implode(' AND ', $where) . " ORDER BY attempt_time DESC";
            $stmt = $this->db->prepare($sql);
            $stmt->execute($params);
            
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log("SecurityMonitor::getFailedAttempts error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get count of failed attempts
     * 
     * @param string $username Username (optional)
     * @param string $ip IP address (optional)
     * @param int $timeframe Timeframe in minutes (default: 60)
     * @return int Count of failed attempts
     */
    public function getFailedAttemptsCount($username = null, $ip = null, $timeframe = 60) {
        try {
            $where = ["attempt_time >= NOW() - INTERVAL '{$timeframe} minutes'"];
            $params = [];
            
            if ($username) {
                $where[] = "username = ?";
                $params[] = $username;
            }
            
            if ($ip) {
                $where[] = "ip_address = ?";
                $params[] = $ip;
            }
            
            $sql = "SELECT COUNT(*) as count FROM failed_login_attempts WHERE " . implode(' AND ', $where);
            $stmt = $this->db->prepare($sql);
            $stmt->execute($params);
            $result = $stmt->fetch();
            
            return (int) $result['count'];
        } catch (Exception $e) {
            error_log("SecurityMonitor::getFailedAttemptsCount error: " . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Check if an IP is blocked
     * 
     * @param string $ip IP address to check
     * @return bool True if blocked
     */
    public function isIpBlocked($ip) {
        try {
            $stmt = $this->db->prepare("
                SELECT id FROM ip_blocklist 
                WHERE ip_address = ? 
                AND (is_permanent = TRUE OR expires_at > NOW())
            ");
            $stmt->execute([$ip]);
            $result = $stmt->fetch();
            
            return !empty($result);
        } catch (Exception $e) {
            error_log("SecurityMonitor::isIpBlocked error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Block an IP address
     * 
     * @param string $ip IP address to block
     * @param int $duration Duration in minutes (0 for permanent)
     * @param string $reason Reason for blocking
     * @param int $blockedBy User ID who blocked the IP
     * @return bool Success status
     */
    public function blockIp($ip, $duration = 0, $reason = 'Security violation', $blockedBy = null) {
        try {
            $expiresAt = null;
            $isPermanent = false;
            
            if ($duration > 0) {
                $expiresAt = date('Y-m-d H:i:s', time() + ($duration * 60));
            } else {
                $isPermanent = true;
            }
            
            $stmt = $this->db->prepare("
                INSERT INTO ip_blocklist (ip_address, reason, expires_at, is_permanent, blocked_by) 
                VALUES (?, ?, ?, ?, ?)
            ");
            $result = $stmt->execute([$ip, $reason, $expiresAt, $isPermanent, $blockedBy]);
            
            return $result;
        } catch (Exception $e) {
            error_log("SecurityMonitor::blockIp error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Unblock an IP address
     * 
     * @param string $ip IP address to unblock
     * @return bool Success status
     */
    public function unblockIp($ip) {
        try {
            $stmt = $this->db->prepare("
                UPDATE ip_blocklist 
                SET expires_at = NOW() 
                WHERE ip_address = ? AND (expires_at > NOW() OR is_permanent = TRUE)
            ");
            $result = $stmt->execute([$ip]);
            
            return $result;
        } catch (Exception $e) {
            error_log("SecurityMonitor::unblockIp error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get blocked IPs
     * 
     * @param bool $activeOnly Only return currently active blocks
     * @return array Blocked IPs
     */
    public function getBlockedIps($activeOnly = true) {
        try {
            $sql = "SELECT * FROM ip_blocklist";
            $params = [];
            
            if ($activeOnly) {
                $sql .= " WHERE (is_permanent = TRUE OR expires_at > NOW())";
            }
            
            $sql .= " ORDER BY blocked_at DESC";
            
            $stmt = $this->db->prepare($sql);
            $stmt->execute($params);
            
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log("SecurityMonitor::getBlockedIps error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Check for brute force attacks
     * 
     * @param string $username Username
     * @param string $ip IP address
     * @return bool True if brute force detected
     */
    public function detectBruteForce($username, $ip) {
        $threshold = (int) $this->settings->getSetting('brute_force_threshold', 10);
        $timeframe = 60; // 1 hour
        
        // Check attempts by username
        $usernameAttempts = $this->getFailedAttemptsCount($username, null, $timeframe);
        
        // Check attempts by IP
        $ipAttempts = $this->getFailedAttemptsCount(null, $ip, $timeframe);
        
        return ($usernameAttempts >= $threshold || $ipAttempts >= $threshold);
    }
    
    /**
     * Check for brute force attack and create incident if needed
     * 
     * @param string $username Username
     * @param string $ip IP address
     */
    private function checkBruteForceAttack($username, $ip) {
        if ($this->detectBruteForce($username, $ip)) {
            // Create security incident
            $this->createSecurityIncident(
                'brute_force_attack',
                'high',
                "Brute force attack detected from IP {$ip} targeting user {$username}",
                "Multiple failed login attempts detected. IP: {$ip}, Username: {$username}"
            );
        }
    }
    
    /**
     * Check if IP should be auto-blocked
     * 
     * @param string $ip IP address
     */
    private function checkAutoBlock($ip) {
        $maxAttempts = (int) $this->settings->getSetting('max_login_attempts', 5);
        $timeframe = 60; // 1 hour
        
        $attempts = $this->getFailedAttemptsCount(null, $ip, $timeframe);
        
        if ($attempts >= $maxAttempts) {
            $this->blockIp($ip, 60, 'Auto-blocked due to excessive failed login attempts');
        }
    }
    
    /**
     * Create a security incident
     * 
     * @param string $type Incident type
     * @param string $severity Severity level
     * @param string $description Description
     * @param string $actions Actions taken
     * @param int $createdBy User ID who created the incident
     * @return bool Success status
     */
    public function createSecurityIncident($type, $severity, $description, $actions = null, $createdBy = null) {
        try {
            // Convert actions array to string if needed
            $actionsString = is_array($actions) ? json_encode($actions) : $actions;
            
            $stmt = $this->db->prepare("
                INSERT INTO security_incidents (incident_type, severity, description, actions_taken, created_by) 
                VALUES (?, ?, ?, ?, ?)
            ");
            $result = $stmt->execute([$type, $severity, $description, $actionsString, $createdBy]);
            
            return $result;
        } catch (Exception $e) {
            error_log("SecurityMonitor::createSecurityIncident error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get security incidents
     * 
     * @param string $status Filter by status (optional)
     * @param string $severity Filter by severity (optional)
     * @param int $limit Limit results
     * @return array Security incidents
     */
    public function getSecurityIncidents($status = null, $severity = null, $limit = 50) {
        try {
            $where = [];
            $params = [];
            
            if ($status) {
                $where[] = "status = ?";
                $params[] = $status;
            }
            
            if ($severity) {
                $where[] = "severity = ?";
                $params[] = $severity;
            }
            
            $sql = "SELECT * FROM security_incidents";
            if (!empty($where)) {
                $sql .= " WHERE " . implode(' AND ', $where);
            }
            $sql .= " ORDER BY created_at DESC LIMIT ?";
            $params[] = $limit;
            
            $stmt = $this->db->prepare($sql);
            $stmt->execute($params);
            
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log("SecurityMonitor::getSecurityIncidents error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Clean up old failed login attempts
     * 
     * @param int $daysOld Days old to clean up (default: 30)
     * @return int Number of records deleted
     */
    public function cleanupFailedLogins($daysOld = 30) {
        try {
            $stmt = $this->db->prepare("
                DELETE FROM failed_login_attempts 
                WHERE attempt_time < NOW() - INTERVAL '{$daysOld} days'
            ");
            $stmt->execute();
            
            return $stmt->rowCount();
        } catch (Exception $e) {
            error_log("SecurityMonitor::cleanupFailedLogins error: " . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Get recent failed login attempts for dashboard
     * 
     * @param int $limit Number of recent attempts to return
     * @return array Recent failed attempts
     */
    public function getRecentFailedLogins($limit = 10) {
        try {
            $stmt = $this->db->prepare("
                SELECT username, ip_address, reason, attempt_time, user_agent
                FROM failed_login_attempts 
                ORDER BY attempt_time DESC 
                LIMIT ?
            ");
            $stmt->execute([$limit]);
            
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log("SecurityMonitor::getRecentFailedLogins error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get security metrics for dashboard
     * @return array Security metrics
     */
    public function getSecurityMetrics() {
        try {
            $sql = "SELECT * FROM security_metrics";
            $stmt = $this->db->prepare($sql);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$result) {
                // Return default metrics if view doesn't exist or is empty
                return [
                    'failed_logins_24h' => 0,
                    'active_incidents' => 0,
                    'blocked_ips_permanent' => 0,
                    'blocked_ips_temporary' => 0,
                    'unique_ips_last_hour' => 0
                ];
            }
            
            return $result;
        } catch (Exception $e) {
            error_log("Error getting security metrics: " . $e->getMessage());
            return [
                'failed_logins_24h' => 0,
                'active_incidents' => 0,
                'blocked_ips_permanent' => 0,
                'blocked_ips_temporary' => 0,
                'unique_ips_last_hour' => 0
            ];
        }
    }
}

