<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

// Ensure config is loaded for helper functions
require_once __DIR__ . '/../config/config.php';

/**
 * Sanitize input data to prevent XSS attacks
 * 
 * @param mixed $data The data to sanitize (string or array)
 * @return mixed Sanitized data with HTML entities encoded
 * @throws InvalidArgumentException If data is not string or array
 * @example
 * $clean = sanitizeInput('<script>alert("xss")</script>');
 * // Returns: &lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;
 */
function sanitizeInput($data) {
    if (is_array($data)) {
        return array_map('sanitizeInput', $data);
    }
    if (!is_string($data)) {
        throw new InvalidArgumentException('Data must be string or array');
    }
    return dave_htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

/**
 * Validate email address format
 * 
 * @param string $email The email address to validate
 * @return bool True if email is valid, false otherwise
 * @example
 * $valid = isValidEmail('user@example.com'); // Returns: true
 * $invalid = isValidEmail('invalid-email'); // Returns: false
 */
function isValidEmail($email) {
    if (!is_string($email)) {
        return false;
    }
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Generate cryptographically secure random string
 * 
 * @param int $length The length of the random string (default: 32)
 * @return string Random hexadecimal string
 * @throws InvalidArgumentException If length is not positive integer
 * @example
 * $token = generateRandomString(16); // Returns: "a1b2c3d4e5f6g7h8"
 */
function generateRandomString($length = 32) {
    if (!is_int($length) || $length <= 0) {
        throw new InvalidArgumentException('Length must be positive integer');
    }
    return bin2hex(random_bytes($length / 2));
}

/**
 * Format date for display with timezone support
 * 
 * @param mixed $date The date to format (string, timestamp, or DateTime object)
 * @param string $format The date format (default: 'Y-m-d H:i:s')
 * @return string Formatted date string or 'N/A' if invalid
 * @example
 * $formatted = formatDate('2024-01-01 12:00:00', 'M j, Y'); // Returns: "Jan 1, 2024"
 * $formatted = formatDate(time(), 'Y-m-d'); // Returns: "2024-01-01"
 */
function formatDate($date, $format = 'Y-m-d H:i:s') {
    if (empty($date)) {
        return 'N/A';
    }
    
    try {
        if ($date instanceof DateTime) {
            return $date->format($format);
        }
        
        $timestamp = is_string($date) ? strtotime($date) : $date;
        if ($timestamp === false) {
            return 'N/A';
        }
        
        return date($format, $timestamp);
    } catch (Exception $e) {
        return 'N/A';
    }
}

/**
 * Format file size
 */
function formatFileSize($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } else {
        return $bytes . ' bytes';
    }
}

/**
 * Get client IP address
 */
function getClientIP() {
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
    
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Log message to file with level enforcement and rotation
 */
function logMessage($level, $message, $context = [], $logFile = null) {
    // Get current log level from configuration
    $currentLevel = defined('_LOG_LEVEL') ? _LOG_LEVEL : 'INFO';
    $levels = ['DEBUG' => 0, 'INFO' => 1, 'WARNING' => 2, 'ERROR' => 3];
    
    // Check if we should log this message
    if (!isset($levels[$level]) || !isset($levels[$currentLevel])) {
        return; // Invalid level
    }
    
    if ($levels[$level] < $levels[$currentLevel]) {
        return; // Don't log if below current level
    }
    
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[$timestamp] [$level] $message";
    
    if (!empty($context)) {
        $logEntry .= ' ' . json_encode($context);
    }
    
    $logEntry .= PHP_EOL;
    
    // Use custom log file if provided, otherwise use default
    if ($logFile === null) {
        $logFile = defined('_LOG_FILE') ? _LOG_FILE : '/var/www/html/logs/dave.log';
    }
    
    $logDir = dirname($logFile);
    
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }
    
    // Check if log rotation is needed
    if (file_exists($logFile)) {
        $maxSize = defined('_LOG_MAX_SIZE') ? _LOG_MAX_SIZE : (10 * 1024 * 1024);
        if (filesize($logFile) >= $maxSize) {
            rotateLogFile($logFile);
        }
    }
    
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
}

/**
 * Log authentication events to dedicated authentication log
 */
function logAuthEvent($event, $username, $success, $details = []) {
    $logFile = _LOGS . '/authentication.log';
    $level = $success ? 'INFO' : 'WARNING';
    $status = $success ? 'SUCCESS' : 'FAILED';
    
    $context = array_merge([
        'event' => $event,
        'username' => $username,
        'status' => $status,
        'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ], $details);
    
    logMessage($level, "{$event} {$status} for user: {$username}", $context, $logFile);
}

/**
 * Rotate log file
 */
function rotateLogFile($logFile) {
    $maxFiles = defined('_LOG_MAX_FILES') ? _LOG_MAX_FILES : 5;
    $logDir = dirname($logFile);
    $baseName = basename($logFile, '.log');
    
    // Move existing files
    for ($i = $maxFiles - 1; $i > 0; $i--) {
        $oldFile = $logDir . '/' . $baseName . '.' . $i . '.log';
        $newFile = $logDir . '/' . $baseName . '.' . ($i + 1) . '.log';
        
        if (file_exists($oldFile)) {
            if ($i + 1 > $maxFiles) {
                unlink($oldFile); // Remove oldest file
            } else {
                rename($oldFile, $newFile);
            }
        }
    }
    
    // Move current log to .1
    if (file_exists($logFile)) {
        rename($logFile, $logDir . '/' . $baseName . '.1.log');
    }
}

/**
 * Get log statistics
 */
function getLogStats() {
    $logDir = _LOGS;
    $stats = [
        'total_files' => 0,
        'total_size' => 0,
        'files' => []
    ];
    
    if (is_dir($logDir)) {
        $files = glob($logDir . '/*.log');
        $stats['total_files'] = count($files);
        
        foreach ($files as $file) {
            $size = filesize($file);
            $stats['total_size'] += $size;
            $stats['files'][] = [
                'name' => basename($file),
                'size' => $size,
                'modified' => filemtime($file)
            ];
        }
    }
    
    return $stats;
}

/**
 * Clean old log files
 */
function cleanOldLogs($days = 30) {
    $logDir = _LOGS;
    $cutoff = time() - ($days * 24 * 60 * 60);
    $cleaned = 0;
    
    if (is_dir($logDir)) {
        $files = glob($logDir . '/*.log');
        foreach ($files as $file) {
            if (filemtime($file) < $cutoff) {
                if (unlink($file)) {
                    $cleaned++;
                }
            }
        }
    }
    
    return $cleaned;
}

/**
 * Check if user has permission
 */
function hasPermission($permission) {
    if (!isset($_SESSION['user_id'])) {
        return false;
    }
    
    // Get user role
    $role = $_SESSION['user_role'] ?? 'viewer';
    
    // Define role permissions
    $permissions = [
        'admin' => ['*'], // Admin has all permissions
        'clinical_engineer' => [
            'assets.read', 'assets.write', 'assets.delete',
            'devices.read', 'devices.write', 'devices.map',
            'vulnerabilities.read', 'vulnerabilities.write',
            'recalls.read', 'recalls.write',
            'reports.read', 'reports.write'
        ],
        'risk_manager' => [
            'assets.read', 'devices.read', 'vulnerabilities.read',
            'recalls.read', 'recalls.write',
            'reports.read', 'reports.write'
        ],
        'viewer' => [
            'assets.read', 'devices.read', 'vulnerabilities.read',
            'recalls.read', 'reports.read'
        ]
    ];
    
    $userPermissions = $permissions[$role] ?? [];
    
    return in_array('*', $userPermissions) || in_array($permission, $userPermissions);
}

/**
 * Redirect to URL
 */
function redirect($url, $statusCode = 302) {
    header("Location: $url", true, $statusCode);
    exit;
}

/**
 * Get current URL
 */
function getCurrentUrl() {
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    $uri = $_SERVER['REQUEST_URI'];
    return "$protocol://$host$uri";
}

/**
 * Check if request is AJAX
 */
function isAjaxRequest() {
    return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
           strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

/**
 * Send JSON response
 */
function sendJsonResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

/**
 * Validate CSRF token
 */
function validateCSRFToken($token) {
    if (!isset($_SESSION['csrf_token'])) {
        return false;
    }
    
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Generate CSRF token
 */
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    
    return $_SESSION['csrf_token'];
}

/**
 * Escape HTML output
 */
function escapeHtml($string) {
    return dave_htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

/**
 * Get file extension
 */
function getFileExtension($filename) {
    return strtolower(pathinfo($filename, PATHINFO_EXTENSION));
}

/**
 * Check if file type is allowed
 */
function isAllowedFileType($filename) {
    $extension = getFileExtension($filename);
    $allowedTypes = ['xml', 'csv', 'json', 'txt', 'pdf', 'xlsx', 'docx'];
    
    return in_array($extension, $allowedTypes);
}

/**
 * Create directory if it doesn't exist
 */
function ensureDirectory($path) {
    if (!is_dir($path)) {
        return mkdir($path, 0755, true);
    }
    return true;
}

/**
 * Delete file safely
 */
function safeDeleteFile($filepath) {
    if (file_exists($filepath) && is_file($filepath)) {
        return unlink($filepath);
    }
    return false;
}

/**
 * Get pagination info
 */
function getPaginationInfo($page, $limit, $total) {
    $totalPages = ceil($total / $limit);
    $offset = ($page - 1) * $limit;
    
    return [
        'page' => $page,
        'limit' => $limit,
        'total' => $total,
        'total_pages' => $totalPages,
        'offset' => $offset,
        'has_next' => $page < $totalPages,
        'has_prev' => $page > 1
    ];
}

/**
 * Format number with commas
 */
function formatNumber($number) {
    return number_format($number);
}

/**
 * Get time ago string
 */
function getTimeAgo($datetime) {
    $time = time() - strtotime($datetime);
    
    if ($time < 60) {
        return 'just now';
    } elseif ($time < 3600) {
        return floor($time / 60) . ' minutes ago';
    } elseif ($time < 86400) {
        return floor($time / 3600) . ' hours ago';
    } elseif ($time < 2592000) {
        return floor($time / 86400) . ' days ago';
    } else {
        return date('M j, Y', strtotime($datetime));
    }
}

/**
 * Check if string is JSON
 */
function isJson($string) {
    json_decode($string);
    return json_last_error() === JSON_ERROR_NONE;
}

/**
 * Generate UUID
 */
function generateUUID() {
    return sprintf(
        '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}

/**
 * Validate URL
 */
function isValidUrl($url) {
    return filter_var($url, FILTER_VALIDATE_URL) !== false;
}

/**
 * Get base URL
 */
function getBaseUrl() {
    // First try to use configured base URL
    if (defined('_BASE_URL') && !empty(_BASE_URL)) {
        return rtrim(_BASE_URL, '/');
    }
    
    // Fallback to server detection
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    $script = $_SERVER['SCRIPT_NAME'];
    $path = dirname($script);
    
    return "$protocol://$host$path";
}

/**
 * Get API URL
 */
function getApiUrl() {
    if (defined('_API_URL') && !empty(_API_URL)) {
        return rtrim(_API_URL, '/');
    }
    
    return getBaseUrl() . '/api';
}

/**
 * Get assets URL
 */
function getAssetsUrl() {
    return getBaseUrl() . '/assets';
}

/**
 * Get page URL
 */
function getPageUrl($page = '') {
    $baseUrl = getBaseUrl();
    if (empty($page)) {
        return $baseUrl;
    }
    
    // Remove leading slash if present
    $page = ltrim($page, '/');
    return $baseUrl . '/' . $page;
}

/**
 * Generate full URL for any path
 */
function url($path = '') {
    $baseUrl = getBaseUrl();
    if (empty($path)) {
        return $baseUrl;
    }
    
    // Remove leading slash if present
    $path = ltrim($path, '/');
    return $baseUrl . '/' . $path;
}

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

/**
 * Require login
 */
function requireLogin() {
    if (!isLoggedIn()) {
        redirect('/pages/login.php');
    }
}

/**
 * Require permission
 */
function requirePermission($permission) {
    requireLogin();
    
    if (!hasPermission($permission)) {
        http_response_code(403);
        include __DIR__ . '/../pages/403.php';
        exit;
    }
}

/**
 * Get user ID from session
 */
function getCurrentUserId() {
    return $_SESSION['user_id'] ?? null;
}

/**
 * Get user role from session
 */
function getCurrentUserRole() {
    return $_SESSION['user_role'] ?? 'viewer';
}

/**
 * Check if user is admin
 */
function isAdmin() {
    return getCurrentUserRole() === 'admin';
}

/**
 * Get current timestamp
 */
function getCurrentTimestamp() {
    return date('Y-m-d H:i:s');
}

/**
 * Convert timestamp to Unix timestamp
 */
function toUnixTimestamp($datetime) {
    return strtotime($datetime);
}

/**
 * Get difference between two dates
 */
function getDateDifference($date1, $date2) {
    $datetime1 = new DateTime($date1);
    $datetime2 = new DateTime($date2);
    $interval = $datetime1->diff($datetime2);
    
    return $interval;
}
