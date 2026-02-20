<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

// Define _ROOT if not already defined
if (!defined('_ROOT')) {
    define('_ROOT', dirname(dirname(__FILE__)));
}

/**
 * Environment Configuration Manager
 * Handles environment variable loading and configuration management
 */
class EnvConfig {
    
    private static $config = [];
    private static $envFile = null;
    
    /**
     * Initialize environment configuration
     */
    public static function init() {
        self::loadEnvFile();
        self::loadEnvironmentVariables();
        self::setDefaultValues();
    }
    
    /**
     * Load .env file if it exists
     */
    private static function loadEnvFile() {
        $envFiles = [
            _ROOT . '/.env',
            _ROOT . '/.env.local',
            _ROOT . '/.env.production',
            _ROOT . '/config/.env'
        ];
        
        foreach ($envFiles as $file) {
            if (file_exists($file)) {
                self::$envFile = $file;
                self::parseEnvFile($file);
                break;
            }
        }
    }
    
    /**
     * Parse .env file
     */
    private static function parseEnvFile($file) {
        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        
        foreach ($lines as $line) {
            if (strpos(trim($line), '#') === 0) {
                continue; // Skip comments
            }
            
            if (strpos($line, '=') !== false) {
                list($key, $value) = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                
                // Remove quotes if present
                if ((substr($value, 0, 1) === '"' && substr($value, -1) === '"') ||
                    (substr($value, 0, 1) === "'" && substr($value, -1) === "'")) {
                    $value = substr($value, 1, -1);
                }
                
                $_ENV[$key] = $value;
                putenv("$key=$value");
            }
        }
    }
    
    /**
     * Load environment variables
     */
    private static function loadEnvironmentVariables() {
        // Core application settings
        self::$config['base_url'] = self::getEnv('_BASE_URL', 'http://localhost');
        self::$config['api_url'] = self::getEnv('_API_URL', self::$config['base_url'] . '/api');
        self::$config['debug'] = self::getEnv('_DEBUG', 'true') === 'true';
        
        // Database configuration
        self::$config['db_host'] = self::getEnv('DB_HOST');
        self::$config['db_port'] = self::getEnv('DB_PORT');
        self::$config['db_name'] = self::getEnv('DB_NAME');
        self::$config['db_user'] = self::getEnv('DB_USER');
        self::$config['db_password'] = self::getEnv('DB_PASSWORD');

        // Email configuration
        self::$config['smtp_host'] = self::getEnv('_SMTP_HOST', 'localhost');
        self::$config['smtp_port'] = self::getEnv('_SMTP_PORT', '587');
        self::$config['smtp_username'] = self::getEnv('_SMTP_USERNAME', '');
        self::$config['smtp_password'] = self::getEnv('_SMTP_PASSWORD', '');
        self::$config['smtp_encryption'] = self::getEnv('_SMTP_ENCRYPTION', 'tls');
        self::$config['from_email'] = self::getEnv('_FROM_EMAIL', 'noreply@localhost');
        self::$config['from_name'] = self::getEnv('_FROM_NAME', ' System');
        
        // Security settings
        self::$config['session_domain'] = self::getEnv('_SESSION_DOMAIN', self::extractDomain(self::$config['base_url']));
        self::$config['cookie_domain'] = self::getEnv('_COOKIE_DOMAIN', self::extractDomain(self::$config['base_url']));
        self::$config['session_lifetime'] = self::getEnv('_SESSION_LIFETIME', '3600');
        self::$config['max_login_attempts'] = self::getEnv('_MAX_LOGIN_ATTEMPTS', '5');
        self::$config['lockout_duration'] = self::getEnv('_LOCKOUT_DURATION', '900');
        
        // External API keys
        self::$config['openfda_api_key'] = self::getEnv('OPENFDA_API_KEY', '');
        self::$config['nvd_api_key'] = self::getEnv('NVD_API_KEY', '');
        self::$config['maxmind_api_key'] = self::getEnv('MAXMIND_API_KEY', '');
        self::$config['maxmind_account_id'] = self::getEnv('MAXMIND_ACCOUNT_ID', '');
        
        // File upload settings
        self::$config['max_upload_size'] = self::getEnv('_MAX_UPLOAD_SIZE', '52428800'); // 50MB
        self::$config['upload_dir'] = self::getEnv('_UPLOAD_DIR', _ROOT . '/uploads');
        self::$config['temp_dir'] = self::getEnv('_TEMP_DIR', _ROOT . '/temp');
        
        // Logging settings
        self::$config['log_level'] = self::getEnv('_LOG_LEVEL', 'INFO');
        self::$config['log_file'] = self::getEnv('_LOG_FILE', _ROOT . '/logs/dave.log');
        self::$config['log_max_size'] = self::getEnv('_LOG_MAX_SIZE', '10485760'); // 10MB
        self::$config['log_max_files'] = self::getEnv('_LOG_MAX_FILES', '5');
        
        // Cache settings
        self::$config['cache_enabled'] = self::getEnv('_CACHE_ENABLED', 'true') === 'true';
        self::$config['cache_dir'] = self::getEnv('_CACHE_DIR', _ROOT . '/temp/cache');
        self::$config['cache_lifetime'] = self::getEnv('_CACHE_LIFETIME', '3600');
    }
    
    /**
     * Set default values and update constants
     */
    private static function setDefaultValues() {
        // Update constants with environment values
        if (!defined('_BASE_URL')) {
            define('_BASE_URL', self::$config['base_url']);
        }
        if (!defined('_API_URL')) {
            define('_API_URL', self::$config['api_url']);
        }
        if (!defined('_DEBUG')) {
            define('_DEBUG', self::$config['debug']);
        }
    }
    
    /**
     * Get environment variable with fallback
     */
    private static function getEnv($key, $default = null) {
        $value = getenv($key);
        if ($value === false) {
            $value = $_ENV[$key] ?? $default;
        }
        return $value;
    }
    
    /**
     * Extract domain from URL
     */
    private static function extractDomain($url) {
        $parsed = parse_url($url);
        return $parsed['host'] ?? 'localhost';
    }
    
    /**
     * Get configuration value
     */
    public static function get($key, $default = null) {
        return self::$config[$key] ?? $default;
    }
    
    /**
     * Get all configuration
     */
    public static function getAll() {
        return self::$config;
    }
    
    /**
     * Update configuration value
     */
    public static function set($key, $value) {
        self::$config[$key] = $value;
    }
    
    /**
     * Save configuration to .env file
     */
    public static function saveToEnvFile($config = null) {
        if ($config === null) {
            $config = self::$config;
        }
        
        $envFile = self::$envFile ?: _ROOT . '/.env';
        $content = "#  Environment Configuration\n";
        $content .= "# Generated on " . date('Y-m-d H:i:s') . "\n\n";
        
        // Core settings
        $content .= "# Core Application Settings\n";
        $content .= "_BASE_URL=" . $config['base_url'] . "\n";
        $content .= "_API_URL=" . $config['api_url'] . "\n";
        $content .= "_DEBUG=" . ($config['debug'] ? 'true' : 'false') . "\n\n";
        
        // Database settings
        $content .= "# Database Configuration\n";
        $content .= "DB_HOST=" . $config['db_host'] . "\n";
        $content .= "DB_PORT=" . $config['db_port'] . "\n";
        $content .= "DB_NAME=" . $config['db_name'] . "\n";
        $content .= "DB_USER=" . $config['db_user'] . "\n";
        $content .= "DB_PASSWORD=" . $config['db_password'] . "\n\n";
        
        // Email settings
        $content .= "# Email Configuration\n";
        $content .= "_SMTP_HOST=" . $config['smtp_host'] . "\n";
        $content .= "_SMTP_PORT=" . $config['smtp_port'] . "\n";
        $content .= "_SMTP_USERNAME=" . $config['smtp_username'] . "\n";
        $content .= "_SMTP_PASSWORD=" . $config['smtp_password'] . "\n";
        $content .= "_SMTP_ENCRYPTION=" . $config['smtp_encryption'] . "\n";
        $content .= "_FROM_EMAIL=" . $config['from_email'] . "\n";
        $content .= "_FROM_NAME=" . $config['from_name'] . "\n\n";
        
        // Security settings
        $content .= "# Security Configuration\n";
        $content .= "_SESSION_DOMAIN=" . $config['session_domain'] . "\n";
        $content .= "_COOKIE_DOMAIN=" . $config['cookie_domain'] . "\n";
        $content .= "_SESSION_LIFETIME=" . $config['session_lifetime'] . "\n";
        $content .= "_MAX_LOGIN_ATTEMPTS=" . $config['max_login_attempts'] . "\n";
        $content .= "_LOCKOUT_DURATION=" . $config['lockout_duration'] . "\n\n";
        
        // API keys
        $content .= "# External API Keys\n";
        $content .= "OPENFDA_API_KEY=" . $config['openfda_api_key'] . "\n";
        $content .= "NVD_API_KEY=" . $config['nvd_api_key'] . "\n";
        $content .= "MAXMIND_API_KEY=" . $config['maxmind_api_key'] . "\n";
        $content .= "MAXMIND_ACCOUNT_ID=" . $config['maxmind_account_id'] . "\n\n";
        
        // File upload settings
        $content .= "# File Upload Settings\n";
        $content .= "_MAX_UPLOAD_SIZE=" . $config['max_upload_size'] . "\n";
        $content .= "_UPLOAD_DIR=" . $config['upload_dir'] . "\n";
        $content .= "_TEMP_DIR=" . $config['temp_dir'] . "\n\n";
        
        // Logging settings
        $content .= "# Logging Configuration\n";
        $content .= "_LOG_LEVEL=" . $config['log_level'] . "\n";
        $content .= "_LOG_FILE=" . $config['log_file'] . "\n";
        $content .= "_LOG_MAX_SIZE=" . $config['log_max_size'] . "\n";
        $content .= "_LOG_MAX_FILES=" . $config['log_max_files'] . "\n\n";
        
        // Cache settings
        $content .= "# Cache Configuration\n";
        $content .= "_CACHE_ENABLED=" . ($config['cache_enabled'] ? 'true' : 'false') . "\n";
        $content .= "_CACHE_DIR=" . $config['cache_dir'] . "\n";
        $content .= "_CACHE_LIFETIME=" . $config['cache_lifetime'] . "\n";
        
        return file_put_contents($envFile, $content) !== false;
    }
    
    /**
     * Validate configuration
     */
    public static function validate() {
        $errors = [];
        
        // Validate URLs
        if (!filter_var(self::$config['base_url'], FILTER_VALIDATE_URL)) {
            $errors[] = 'Invalid base URL format';
        }
        
        // Validate database connection
        try {
            $pdo = new PDO(
                "pgsql:host=" . self::$config['db_host'] . ";port=" . self::$config['db_port'] . ";dbname=" . self::$config['db_name'],
                self::$config['db_user'],
                self::$config['db_password']
            );
        } catch (PDOException $e) {
            $errors[] = 'Database connection failed: ' . $e->getMessage();
        }
        
        // Validate email settings
        if (!empty(self::$config['from_email']) && !filter_var(self::$config['from_email'], FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Invalid from email address';
        }
        
        // Allow localhost email for development (when debug mode is enabled)
        if (self::$config['from_email'] === 'noreply@localhost' && self::$config['debug'] === true) {
            // Remove the email validation error for localhost in development
            $errors = array_filter($errors, function($error) {
                return $error !== 'Invalid from email address';
            });
        }
        
        return $errors;
    }
    
    /**
     * Get configuration for UI display (without sensitive data)
     */
    public static function getPublicConfig() {
        $public = self::$config;
        
        // Mask sensitive values
        $sensitive = ['db_password', 'smtp_password', 'openfda_api_key', 'nvd_api_key', 'maxmind_api_key'];
        foreach ($sensitive as $key) {
            if (isset($public[$key]) && !empty($public[$key])) {
                $public[$key] = str_repeat('*', strlen($public[$key]));
            }
        }
        
        return $public;
    }
}

// Initialize environment configuration
EnvConfig::init();
