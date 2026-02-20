<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

require_once __DIR__ . '/../config/config.php';

/**
 * Clean up expired sessions
 */
function cleanupExpiredSessions() {
    try {
        $db = DatabaseConfig::getInstance();
        
        // Get session timeout from config (default 30 minutes)
        $timeoutMinutes = Config::get('security.session_timeout', 30);
        
        // Clean up sessions that haven't been active for the timeout period
        $sql = "UPDATE user_sessions 
                SET is_active = FALSE, 
                    terminated_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE is_active = TRUE 
                AND last_activity < NOW() - INTERVAL '{$timeoutMinutes} minutes'";
        
        $stmt = $db->query($sql);
        $affectedRows = $stmt->rowCount();
        
        error_log("Session cleanup: Marked {$affectedRows} expired sessions as inactive");
        
        return $affectedRows;
        
    } catch (Exception $e) {
        error_log("Error during session cleanup: " . $e->getMessage());
        return false;
    }
}

/**
 * Clean up old session records (older than 30 days)
 */
function cleanupOldSessionRecords() {
    try {
        $db = DatabaseConfig::getInstance();
        
        // Delete old session records (older than 30 days)
        $sql = "DELETE FROM user_sessions 
                WHERE terminated_at IS NOT NULL 
                AND terminated_at < NOW() - INTERVAL '30 days'";
        
        $stmt = $db->query($sql);
        $affectedRows = $stmt->rowCount();
        
        error_log("Session cleanup: Deleted {$affectedRows} old session records");
        
        return $affectedRows;
        
    } catch (Exception $e) {
        error_log("Error during old session cleanup: " . $e->getMessage());
        return false;
    }
}

/**
 * Update session activity
 */
function updateSessionActivity($sessionId) {
    try {
        $db = DatabaseConfig::getInstance();
        
        $sql = "UPDATE user_sessions 
                SET last_activity = CURRENT_TIMESTAMP, 
                    updated_at = CURRENT_TIMESTAMP 
                WHERE session_id = ? AND is_active = TRUE";
        
        $stmt = $db->query($sql, [$sessionId]);
        
        return $stmt->rowCount() > 0;
        
    } catch (Exception $e) {
        error_log("Error updating session activity: " . $e->getMessage());
        return false;
    }
}

/**
 * Get session statistics
 */
function getSessionStats() {
    try {
        $db = DatabaseConfig::getInstance();
        
        $sql = "SELECT 
                    COUNT(*) as total_sessions,
                    COUNT(CASE WHEN is_active = TRUE THEN 1 END) as active_sessions,
                    COUNT(CASE WHEN is_active = FALSE THEN 1 END) as inactive_sessions,
                    COUNT(CASE WHEN last_activity > NOW() - INTERVAL '1 hour' THEN 1 END) as recent_activity
                FROM user_sessions";
        
        $stmt = $db->query($sql);
        return $stmt->fetch();
        
    } catch (Exception $e) {
        error_log("Error getting session stats: " . $e->getMessage());
        return false;
    }
}

/**
 * Run complete session maintenance
 */
function runSessionMaintenance() {
    $results = [
        'expired_cleaned' => cleanupExpiredSessions(),
        'old_cleaned' => cleanupOldSessionRecords(),
        'stats' => getSessionStats()
    ];
    
    return $results;
}

// If called directly, run maintenance
if (basename(__FILE__) == basename($_SERVER['SCRIPT_NAME'])) {
    $results = runSessionMaintenance();
    echo json_encode($results);
}
?>
