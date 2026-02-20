<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

// Load environment configuration first
require_once __DIR__ . '/../includes/env-config.php';

// Initialize sessions properly for CI environment
$sessionPath = sys_get_temp_dir() . '/php_sessions';
if (!file_exists($sessionPath)) {
    @mkdir($sessionPath, 0777, true);
    @chmod($sessionPath, 0777);
}
ini_set('session.save_path', $sessionPath);

// Define application constants
if (!defined('_VERSION')) {
    define('_VERSION', '1.0.0');
}
if (!defined('_DEBUG')) {
    define('_DEBUG', true); // Set to false in production
}

// Application paths
if (!defined('_ROOT')) {
    define('_ROOT', dirname(__DIR__));
}
if (!defined('_INCLUDES')) {
    define('_INCLUDES', _ROOT . '/includes');
}
if (!defined('_API')) {
    define('_API', _ROOT . '/api');
}
if (!defined('_PAGES')) {
    define('_PAGES', _ROOT . '/pages');
}
if (!defined('_ASSETS')) {
    define('_ASSETS', _ROOT . '/assets');
}
if (!defined('_UPLOADS')) {
    define('_UPLOADS', _ROOT . '/uploads');
}
if (!defined('_LOGS')) {
    define('_LOGS', _ROOT . '/logs');
}
if (!defined('_TEMP')) {
    define('_TEMP', _ROOT . '/temp');
}

// URL configuration (now handled by EnvConfig)
// _BASE_URL, _API_URL, and _ASSETS_URL are defined in EnvConfig

// Security configuration
define('_SESSION_NAME', '_SESSION');
define('_SESSION_LIFETIME', 3600); // 1 hour

// GeoIP configuration
define('MAXMIND_API_KEY', ''); // MaxMind API key - leave empty to disable GeoIP
define('MAXMIND_ACCOUNT_ID', ''); // MaxMind Account ID - leave empty to disable GeoIP
define('_SESSION_TIMEOUT', 30); // 30 minutes of inactivity
define('_MAX_LOGIN_ATTEMPTS', 5);
define('_LOCKOUT_DURATION', 900); // 15 minutes
define('_PASSWORD_MIN_LENGTH', 8);
define('_PASSWORD_REQUIRE_SPECIAL', true);
define('_PASSWORD_REQUIRE_NUMBERS', true);

// External API Keys
define('_PASSWORD_REQUIRE_UPPERCASE', true);

// File upload configuration
define('_MAX_UPLOAD_SIZE', 50 * 1024 * 1024); // 50MB
define('_ALLOWED_UPLOAD_TYPES', [
    'xml' => 'text/xml',
    'csv' => 'text/csv',
    'json' => 'application/json',
    'txt' => 'text/plain'
]);

// API configuration
define('_API_RATE_LIMIT', 100); // requests per minute
define('_API_RATE_WINDOW', 60); // seconds

// External API configuration
define('OPENFDA_API_URL', 'https://api.fda.gov');
define('OPENFDA_API_KEY', ''); // Set your API key
define('OPENFDA_RATE_LIMIT', 1000); // requests per hour

define('NVD_API_URL', 'https://services.nvd.nist.gov/rest/json/cves/2.0');
define('NVD_API_KEY', ''); // Set your API key
define('NVD_RATE_LIMIT', 50); // requests per minute

define('OUI_API_URL', 'https://api.macvendors.com');
define('OUI_RATE_LIMIT', 100); // requests per minute

// Email configuration
define('_SMTP_HOST', 'localhost');
define('_SMTP_PORT', 587);
define('_SMTP_USERNAME', '');
define('_SMTP_PASSWORD', '');
define('_SMTP_ENCRYPTION', 'tls');
define('_FROM_EMAIL', 'noreply@dave.local');
define('_FROM_NAME', ' System');

// Logging configuration
define('_LOG_LEVEL', 'INFO'); // DEBUG, INFO, WARNING, ERROR
define('_LOG_FILE', _LOGS . '/dave.log');
define('_LOG_MAX_SIZE', 10 * 1024 * 1024); // 10MB
define('_LOG_MAX_FILES', 5);

// Cache configuration
define('_CACHE_ENABLED', true);
define('_CACHE_DIR', _TEMP . '/cache');
define('_CACHE_LIFETIME', 3600); // 1 hour

// Dashboard configuration
define('_DASHBOARD_REFRESH_INTERVAL', 30); // seconds
define('_DASHBOARD_MAX_ITEMS', 100);

// Report configuration
define('_REPORT_MAX_RECORDS', 10000);
define('_REPORT_TIMEOUT', 300); // 5 minutes

// Background service configuration
define('_BACKGROUND_SERVICES_ENABLED', true);
define('_RECALL_CHECK_INTERVAL', 86400); // 24 hours
define('_VULNERABILITY_SCAN_INTERVAL', 3600); // 1 hour
define('_CLEANUP_INTERVAL', 604800); // 7 days

// Application settings array
$dave_config = [
    'app' => [
        'name' => 'Device Assessment and Vulnerability Exposure',
        'version' => _VERSION,
        'debug' => _DEBUG,
        'timezone' => 'UTC',
        'locale' => 'en_US',
        'charset' => 'UTF-8'
    ],
    'database' => [
        'host' => EnvConfig::get('db_host'),
        'port' => EnvConfig::get('db_port'),
        'name' => EnvConfig::get('db_name'),
        'user' => EnvConfig::get('db_user'),
        'pass' => EnvConfig::get('db_password'),
        'charset' => 'utf8'
    ],
    'security' => [
        'session_name' => _SESSION_NAME,
        'session_lifetime' => _SESSION_LIFETIME,
        'max_login_attempts' => _MAX_LOGIN_ATTEMPTS,
        'lockout_duration' => _LOCKOUT_DURATION,
        'password_min_length' => _PASSWORD_MIN_LENGTH,
        'password_require_special' => _PASSWORD_REQUIRE_SPECIAL,
        'password_require_numbers' => _PASSWORD_REQUIRE_NUMBERS,
        'password_require_uppercase' => _PASSWORD_REQUIRE_UPPERCASE
    ],
    'upload' => [
        'max_size' => _MAX_UPLOAD_SIZE,
        'allowed_types' => _ALLOWED_UPLOAD_TYPES,
        'upload_dir' => _UPLOADS,
        'temp_dir' => _TEMP
    ],
    'api' => [
        'rate_limit' => _API_RATE_LIMIT,
        'rate_window' => _API_RATE_WINDOW,
        'base_url' => _API_URL
    ],
    'external_apis' => [
        'openfda' => [
            'url' => OPENFDA_API_URL,
            'key' => OPENFDA_API_KEY,
            'rate_limit' => OPENFDA_RATE_LIMIT
        ],
        'nvd' => [
            'url' => NVD_API_URL,
            'key' => NVD_API_KEY,
            'rate_limit' => NVD_RATE_LIMIT
        ],
        'oui' => [
            'url' => OUI_API_URL,
            'rate_limit' => OUI_RATE_LIMIT
        ]
    ],
    'email' => [
        'smtp_host' => EnvConfig::get('smtp_host', 'localhost'),
        'smtp_port' => EnvConfig::get('smtp_port', '587'),
        'smtp_username' => EnvConfig::get('smtp_username', ''),
        'smtp_password' => EnvConfig::get('smtp_password', ''),
        'smtp_encryption' => EnvConfig::get('smtp_encryption', 'tls'),
        'from_email' => EnvConfig::get('from_email', 'noreply@localhost'),
        'from_name' => EnvConfig::get('from_name', ' System')
    ],
    'logging' => [
        'level' => _LOG_LEVEL,
        'file' => _LOG_FILE,
        'max_size' => _LOG_MAX_SIZE,
        'max_files' => _LOG_MAX_FILES
    ],
    'cache' => [
        'enabled' => _CACHE_ENABLED,
        'dir' => _CACHE_DIR,
        'lifetime' => _CACHE_LIFETIME
    ],
    'dashboard' => [
        'refresh_interval' => _DASHBOARD_REFRESH_INTERVAL,
        'max_items' => _DASHBOARD_MAX_ITEMS
    ],
    'reports' => [
        'max_records' => _REPORT_MAX_RECORDS,
        'timeout' => _REPORT_TIMEOUT
    ],
    'background_services' => [
        'enabled' => _BACKGROUND_SERVICES_ENABLED,
        'recall_check_interval' => _RECALL_CHECK_INTERVAL,
        'vulnerability_scan_interval' => _VULNERABILITY_SCAN_INTERVAL,
        'cleanup_interval' => _CLEANUP_INTERVAL
    ],
    'cynerio' => [
        'client_id' => '',
        'client_secret' => '',
        'endpoint' => '',
        'auth_endpoint' => ''
    ]
];

/**
 * Configuration utility class
 */
class Config {
    
    /**
     * Get configuration value
     */
    public static function get($key, $default = null) {
        global $dave_config;
        
        $keys = explode('.', $key);
        $value = $dave_config;
        
        foreach ($keys as $k) {
            if (isset($value[$k])) {
                $value = $value[$k];
            } else {
                return $default;
            }
        }
        
        return $value;
    }
    
    /**
     * Set configuration value
     */
    public static function set($key, $value) {
        global $dave_config;
        
        $keys = explode('.', $key);
        $config = &$dave_config;
        
        foreach ($keys as $k) {
            if (!isset($config[$k])) {
                $config[$k] = [];
            }
            $config = &$config[$k];
        }
        
        $config = $value;
    }
    
    /**
     * Check if configuration key exists
     */
    public static function has($key) {
        return self::get($key) !== null;
    }
    
    /**
     * Get all configuration
     */
    public static function all() {
        global $dave_config;
        return $dave_config;
    }
    
    /**
     * Save configuration to file
     */
    public static function save() {
        global $dave_config;
        
        $configFile = _ROOT . '/config/settings.json';
        
        // Create config directory if it doesn't exist
        if (!is_dir(dirname($configFile))) {
            mkdir(dirname($configFile), 0775, true);
        }
        
        // Save configuration to JSON file
        $result = file_put_contents($configFile, json_encode($dave_config, JSON_PRETTY_PRINT));
        
        if ($result === false) {
            // Try to set proper permissions and retry
            chmod(dirname($configFile), 0775);
            $result = file_put_contents($configFile, json_encode($dave_config, JSON_PRETTY_PRINT));
            
            if ($result === false) {
                throw new Exception('Failed to save configuration file. Please check directory permissions.');
            }
        }
        
        // File permissions are managed by the system
        
        return true;
    }
    
    /**
     * Load configuration from file
     */
    public static function load() {
        global $dave_config;
        
        $configFile = _ROOT . '/config/settings.json';
        
        if (file_exists($configFile)) {
            $savedConfig = json_decode(file_get_contents($configFile), true);
            if ($savedConfig !== null) {
                $dave_config = array_merge($dave_config, $savedConfig);
            }
        }
    }
}

/**
 * Environment detection
 */
class Environment {
    
    /**
     * Check if running in development mode
     */
    public static function isDevelopment() {
        return _DEBUG === true;
    }
    
    /**
     * Check if running in production mode
     */
    public static function isProduction() {
        return _DEBUG === false;
    }
    
    /**
     * Get current environment
     */
    public static function get() {
        return self::isDevelopment() ? 'development' : 'production';
    }
    
    /**
     * Check if debug mode is enabled
     */
    public static function isDebugEnabled() {
        return _DEBUG === true;
    }
}

/**
 * Path utilities
 */
class Path {
    
    /**
     * Get absolute path
     */
    public static function absolute($path) {
        if (strpos($path, '/') === 0) {
            return $path;
        }
        return _ROOT . '/' . ltrim($path, '/');
    }
    
    /**
     * Get relative path
     */
    public static function relative($path) {
        return str_replace(_ROOT . '/', '', $path);
    }
    
    /**
     * Join paths
     */
    public static function join(...$paths) {
        return implode('/', array_filter($paths));
    }
    
    /**
     * Check if path exists
     */
    public static function exists($path) {
        return file_exists(self::absolute($path));
    }
    
    /**
     * Create directory if it doesn't exist
     */
    public static function ensureDir($path) {
        $fullPath = self::absolute($path);
        if (!is_dir($fullPath)) {
            return mkdir($fullPath, 0755, true);
        }
        return true;
    }
}

/**
 * Initialize application
 */
function initialize() {
    // Set timezone
    date_default_timezone_set(Config::get('app.timezone', 'UTC'));
    
    // Set locale
    setlocale(LC_ALL, Config::get('app.locale', 'en_US'));
    
    // Create necessary directories
    $directories = [
        _LOGS,
        _TEMP,
        _UPLOADS,
        _CACHE_DIR,
        _UPLOADS . '/nmap',
        _UPLOADS . '/nessus',
        _UPLOADS . '/csv',
        _UPLOADS . '/sbom'
    ];
    
    foreach ($directories as $dir) {
        Path::ensureDir($dir);
    }
    
    // Start session
    if (session_status() === PHP_SESSION_NONE) {
        session_name(_SESSION_NAME);
        session_start();
    }
    
    // Set error reporting based on environment
    if (Environment::isDevelopment()) {
        error_reporting(E_ALL);
        ini_set('display_errors', 1);
    } else {
        error_reporting(E_ERROR | E_WARNING | E_PARSE);
        ini_set('display_errors', 0);
    }
}

// Initialize the application
initialize();

// Load saved configuration
Config::load();

// Define _NAME constant dynamically after loading configuration
if (!defined('_NAME')) {
    define('_NAME', Config::get('app.name', 'Device Assessment and Vulnerability Exposure'));
}

/**
 * Get the current application name (dynamic)
 */
function getApplicationName() {
    return Config::get('app.name', 'Device Assessment and Vulnerability Exposure');
}

/**
 * Safe htmlspecialchars wrapper that handles null values
 * 
 * @param mixed $string The string to escape (can be null)
 * @param int $flags Optional flags for htmlspecialchars
 * @param string|null $encoding Optional character encoding
 * @param bool $double_encode Optional double encoding flag
 * @return string The escaped string, or empty string if input is null
 */
function dave_htmlspecialchars($string, $flags = ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401, $encoding = null, $double_encode = true) {
    // Return empty string if input is null
    if ($string === null) {
        return '';
    }
    
    // Use default encoding if not specified
    if ($encoding === null) {
        $encoding = 'UTF-8';
    }
    
    return htmlspecialchars($string, $flags, $encoding, $double_encode);
}
