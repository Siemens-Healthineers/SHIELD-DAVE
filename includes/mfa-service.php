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
 * Multi-Factor Authentication Service
 * Handles TOTP generation, validation, and MFA setup
 */
class MFAService {
    
    private $db;
    private $issuer = ' Security';
    private $algorithm = 'sha1';
    private $digits = 6;
    private $period = 30;
    
    public function __construct() {
        $this->db = DatabaseConfig::getInstance();
    }
    
    /**
     * Generate a new MFA secret for a user
     * 
     * @param int $userId User ID
     * @return array Secret and QR code data
     */
    public function generateSecret($userId) {
        try {
            // Generate a random secret (32 characters)
            $secret = $this->generateRandomSecret();
            
            // Get user information
            $user = $this->getUserById($userId);
            if (!$user) {
                throw new Exception('User not found');
            }
            
            // Create account name for QR code
            $accountName = $user['username'] . '@' . $this->issuer;
            
            // Generate QR code URL
            $qrCodeUrl = $this->generateQRCodeUrl($accountName, $secret);
            
            // Store the secret temporarily (not activated yet)
            $this->storeTemporarySecret($userId, $secret);
            
            return [
                'secret' => $secret,
                'qr_code_url' => $qrCodeUrl,
                'account_name' => $accountName,
                'manual_entry_key' => $this->formatSecretForDisplay($secret)
            ];
            
        } catch (Exception $e) {
            error_log("MFAService::generateSecret error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Verify a TOTP code
     * 
     * @param string $secret MFA secret
     * @param string $code TOTP code to verify
     * @return bool True if valid
     */
    public function verifyCode($secret, $code) {
        try {
            // Get current time window
            $timeWindow = floor(time() / $this->period);
            
            // Check current window and previous/next windows for clock drift
            for ($i = -1; $i <= 1; $i++) {
                $testTime = $timeWindow + $i;
                $expectedCode = $this->generateTOTP($secret, $testTime);
                
                if (hash_equals($expectedCode, $code)) {
                    return true;
                }
            }
            
            return false;
        } catch (Exception $e) {
            error_log("MFAService::verifyCode error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Activate MFA for a user
     * 
     * @param int $userId User ID
     * @param string $code Verification code
     * @return bool Success status
     */
    public function activateMFA($userId, $code) {
        try {
            // Get temporary secret
            $tempSecret = $this->getTemporarySecret($userId);
            if (!$tempSecret) {
                throw new Exception('No temporary secret found');
            }
            
            // Verify the code
            if (!$this->verifyCode($tempSecret, $code)) {
                throw new Exception('Invalid verification code');
            }
            
            // Generate backup codes
            $backupCodes = $this->generateBackupCodes();
            
            // Activate MFA
            $stmt = $this->db->prepare("
                UPDATE users 
                SET mfa_enabled = true, 
                    mfa_secret = ?, 
                    mfa_backup_codes = ?,
                    updated_at = NOW()
                WHERE user_id = ?
            ");
            
            $result = $stmt->execute([
                $tempSecret,
                json_encode($backupCodes),
                $userId
            ]);
            
            if ($result) {
                // Clear temporary secret
                $this->clearTemporarySecret($userId);
                return $backupCodes;
            }
            
            return false;
        } catch (Exception $e) {
            error_log("MFAService::activateMFA error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Disable MFA for a user
     * 
     * @param int $userId User ID
     * @param string $code Current TOTP code or backup code
     * @return bool Success status
     */
    public function disableMFA($userId, $code) {
        try {
            $user = $this->getUserById($userId);
            if (!$user || !$user['mfa_enabled']) {
                throw new Exception('MFA not enabled for this user');
            }
            
            // Check if it's a backup code
            if ($this->verifyBackupCode($userId, $code)) {
                $this->useBackupCode($userId, $code);
            } else {
                // Verify TOTP code
                if (!$this->verifyCode($user['mfa_secret'], $code)) {
                    throw new Exception('Invalid verification code');
                }
            }
            
            // Disable MFA
            $stmt = $this->db->prepare("
                UPDATE users 
                SET mfa_enabled = false, 
                    mfa_secret = NULL, 
                    mfa_backup_codes = NULL,
                    updated_at = NOW()
                WHERE user_id = ?
            ");
            
            return $stmt->execute([$userId]);
        } catch (Exception $e) {
            error_log("MFAService::disableMFA error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Verify backup code
     * 
     * @param int $userId User ID
     * @param string $code Backup code to verify
     * @return bool True if valid
     */
    public function verifyBackupCode($userId, $code) {
        try {
            $user = $this->getUserById($userId);
            if (!$user || !$user['mfa_backup_codes']) {
                return false;
            }
            
            $backupCodes = json_decode($user['mfa_backup_codes'], true);
            return in_array($code, $backupCodes);
        } catch (Exception $e) {
            error_log("MFAService::verifyBackupCode error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Use a backup code (mark as used)
     * 
     * @param int $userId User ID
     * @param string $code Backup code to use
     * @return bool Success status
     */
    private function useBackupCode($userId, $code) {
        try {
            $user = $this->getUserById($userId);
            $backupCodes = json_decode($user['mfa_backup_codes'], true);
            
            // Remove the used code
            $backupCodes = array_filter($backupCodes, function($c) use ($code) {
                return $c !== $code;
            });
            
            // Update backup codes
            $stmt = $this->db->prepare("
                UPDATE users 
                SET mfa_backup_codes = ?, 
                    updated_at = NOW()
                WHERE user_id = ?
            ");
            
            return $stmt->execute([json_encode(array_values($backupCodes)), $userId]);
        } catch (Exception $e) {
            error_log("MFAService::useBackupCode error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Generate TOTP code
     * 
     * @param string $secret Secret key
     * @param int $time Time window
     * @return string TOTP code
     */
    private function generateTOTP($secret, $time) {
        $timeBytes = pack('N*', 0, $time);
        $hash = hash_hmac($this->algorithm, $timeBytes, $this->base32Decode($secret), true);
        
        $offset = ord($hash[strlen($hash) - 1]) & 0xF;
        $code = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        ) % pow(10, $this->digits);
        
        return str_pad($code, $this->digits, '0', STR_PAD_LEFT);
    }
    
    /**
     * Generate QR code URL
     * 
     * @param string $accountName Account name
     * @param string $secret Secret key
     * @return string QR code URL
     */
    private function generateQRCodeUrl($accountName, $secret) {
        $otpauthUrl = sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d',
            urlencode($accountName),
            $secret,
            urlencode($this->issuer),
            strtoupper($this->algorithm),
            $this->digits,
            $this->period
        );
        
        return 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . urlencode($otpauthUrl);
    }
    
    /**
     * Generate random secret
     * 
     * @return string Base32 encoded secret
     */
    private function generateRandomSecret() {
        $bytes = random_bytes(20); // 160 bits
        return $this->base32Encode($bytes);
    }
    
    /**
     * Generate backup codes
     * 
     * @return array Array of backup codes
     */
    private function generateBackupCodes() {
        $codes = [];
        for ($i = 0; $i < 10; $i++) {
            $codes[] = strtoupper(substr(md5(uniqid(rand(), true)), 0, 8));
        }
        return $codes;
    }
    
    /**
     * Format secret for manual entry
     * 
     * @param string $secret Secret key
     * @return string Formatted secret
     */
    private function formatSecretForDisplay($secret) {
        return chunk_split($secret, 4, ' ');
    }
    
    /**
     * Base32 encode
     * 
     * @param string $data Data to encode
     * @return string Base32 encoded string
     */
    private function base32Encode($data) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $output = '';
        $v = 0;
        $vbits = 0;
        
        for ($i = 0, $j = strlen($data); $i < $j; $i++) {
            $v <<= 8;
            $v += ord($data[$i]);
            $vbits += 8;
            
            while ($vbits >= 5) {
                $vbits -= 5;
                $output .= $alphabet[($v >> $vbits) & 31];
            }
        }
        
        if ($vbits > 0) {
            $v <<= (5 - $vbits);
            $output .= $alphabet[$v & 31];
        }
        
        return $output;
    }
    
    /**
     * Base32 decode
     * 
     * @param string $data Base32 encoded string
     * @return string Decoded data
     */
    private function base32Decode($data) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $output = '';
        $v = 0;
        $vbits = 0;
        
        for ($i = 0, $j = strlen($data); $i < $j; $i++) {
            $v <<= 5;
            $v += strpos($alphabet, $data[$i]);
            $vbits += 5;
            
            if ($vbits >= 8) {
                $vbits -= 8;
                $output .= chr(($v >> $vbits) & 255);
            }
        }
        
        return $output;
    }
    
    /**
     * Get user by ID
     * 
     * @param int $userId User ID
     * @return array|null User data
     */
    private function getUserById($userId) {
        try {
            $stmt = $this->db->prepare("SELECT * FROM users WHERE user_id = ?");
            $stmt->execute([$userId]);
            return $stmt->fetch();
        } catch (Exception $e) {
            error_log("MFAService::getUserById error: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Store temporary secret
     * 
     * @param int $userId User ID
     * @param string $secret Secret to store
     * @return bool Success status
     */
    private function storeTemporarySecret($userId, $secret) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO mfa_sessions (user_id, secret, created_at) 
                VALUES (?, ?, NOW())
                ON CONFLICT (user_id) 
                DO UPDATE SET secret = EXCLUDED.secret, created_at = EXCLUDED.created_at
            ");
            return $stmt->execute([$userId, $secret]);
        } catch (Exception $e) {
            error_log("MFAService::storeTemporarySecret error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get temporary secret
     * 
     * @param int $userId User ID
     * @return string|null Secret or null
     */
    private function getTemporarySecret($userId) {
        try {
            $stmt = $this->db->prepare("
                SELECT secret FROM mfa_sessions 
                WHERE user_id = ? AND created_at > NOW() - INTERVAL '10 minutes'
            ");
            $stmt->execute([$userId]);
            $result = $stmt->fetch();
            return $result ? $result['secret'] : null;
        } catch (Exception $e) {
            error_log("MFAService::getTemporarySecret error: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Clear temporary secret
     * 
     * @param int $userId User ID
     * @return bool Success status
     */
    private function clearTemporarySecret($userId) {
        try {
            $stmt = $this->db->prepare("DELETE FROM mfa_sessions WHERE user_id = ?");
            return $stmt->execute([$userId]);
        } catch (Exception $e) {
            error_log("MFAService::clearTemporarySecret error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Check if user has MFA enabled
     * 
     * @param int $userId User ID
     * @return bool True if MFA enabled
     */
    public function isMFAEnabled($userId) {
        try {
            $stmt = $this->db->prepare("SELECT mfa_enabled FROM users WHERE user_id = ?");
            $stmt->execute([$userId]);
            $result = $stmt->fetch();
            return $result ? (bool) $result['mfa_enabled'] : false;
        } catch (Exception $e) {
            error_log("MFAService::isMFAEnabled error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get user's backup codes
     * 
     * @param int $userId User ID
     * @return array Backup codes
     */
    public function getBackupCodes($userId) {
        try {
            $stmt = $this->db->prepare("SELECT mfa_backup_codes FROM users WHERE user_id = ?");
            $stmt->execute([$userId]);
            $result = $stmt->fetch();
            
            if ($result && $result['mfa_backup_codes']) {
                return json_decode($result['mfa_backup_codes'], true);
            }
            
            return [];
        } catch (Exception $e) {
            error_log("MFAService::getBackupCodes error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Simple disable MFA for a user (without verification code)
     * Used for admin-initiated disables or user settings
     * 
     * @param int $userId User ID
     * @return bool Success status
     */
    public function disableMFASimple($userId) {
        try {
            $user = $this->getUserById($userId);
            if (!$user || !$user['mfa_enabled']) {
                // MFA not enabled, consider it successful
                return true;
            }
            
            // Disable MFA
            $stmt = $this->db->prepare("
                UPDATE users 
                SET mfa_enabled = false, 
                    mfa_secret = NULL, 
                    mfa_backup_codes = NULL,
                    updated_at = NOW()
                WHERE user_id = ?
            ");
            
            $result = $stmt->execute([$userId]);
            
            if ($result) {
                error_log("MFA disabled for user: $userId");
                return true;
            } else {
                error_log("Failed to disable MFA for user: $userId");
                return false;
            }
        } catch (Exception $e) {
            error_log("MFAService::disableMFA error: " . $e->getMessage());
            return false;
        }
    }
}
?>
