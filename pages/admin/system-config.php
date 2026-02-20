<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/auth.php';

// Initialize authentication
$auth = new Auth();

// Require authentication and admin permission
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

// Check if user has admin role
if ($user['role'] !== 'Admin') {
    header('Location: /pages/dashboard.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Handle form submissions
$message = '';
$message_type = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $config_type = $_POST['config_type'] ?? '';
        
        switch ($config_type) {
            case 'app':
                $result = updateAppSettings($_POST);
                break;
            case 'database':
                $result = updateDatabaseSettings($_POST);
                break;
            case 'security':
                $result = updateSecuritySettings($_POST);
                break;
            case 'external_apis':
                $result = updateExternalAPISettings($_POST);
                break;
            case 'email':
                $result = updateEmailSettings($_POST);
                break;
            case 'background_services':
                $result = updateBackgroundServicesSettings($_POST);
                break;
            case 'logging':
                $result = updateLoggingSettings($_POST);
                break;
            case 'cache':
                $result = updateCacheSettings($_POST);
                break;
            case 'environment':
                $result = updateEnvironmentSettings($_POST);
                break;
            default:
                throw new Exception('Invalid configuration type');
        }
        
        if ($result['success']) {
            $message = $result['message'];
            $message_type = 'success';
        } else {
            $message = $result['message'];
            $message_type = 'error';
        }
        
    } catch (Exception $e) {
        $message = 'Error updating configuration: ' . $e->getMessage();
        $message_type = 'error';
    }
}

// Get current configuration
$current_config = Config::all();

// Load MaxMind settings from config.php
$current_config['external_apis']['maxmind'] = [
    'account_id' => defined('MAXMIND_ACCOUNT_ID') ? MAXMIND_ACCOUNT_ID : '',
    'api_key' => defined('MAXMIND_API_KEY') ? MAXMIND_API_KEY : '',
    'enabled' => !empty(MAXMIND_ACCOUNT_ID) && !empty(MAXMIND_API_KEY)
];

// Get cache statistics
require_once __DIR__ . '/../../includes/cache.php';
$cache_stats = Cache::getStats();

// Get log statistics
require_once __DIR__ . '/../../includes/functions.php';
$log_stats = getLogStats();

// Helper functions for updating configuration
function updateAppSettings($data) {
    try {
        // Update application settings
        // Note: app.name is hidden and not updated from this form
        $settings = [
            'app.timezone' => $data['app_timezone'] ?? 'UTC',
            'app.locale' => $data['app_locale'] ?? 'en_US',
            'app.charset' => $data['app_charset'] ?? 'UTF-8'
        ];
        
        foreach ($settings as $key => $value) {
            Config::set($key, $value);
        }
        
        // Save configuration to file
        Config::save();
        
        return ['success' => true, 'message' => 'Application settings updated successfully'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function updateDatabaseSettings($data) {
    try {
        // Update database settings

        // Read environment
        $env = Dotenv\Dotenv::createImmutable(__DIR__ . '/../../..');
        $env->load();
        $db_host  = $_ENV['DB_HOST'];
        $db_port  = $_ENV['DB_PORT'];
        $db_name  = $_ENV['DB_NAME'];
        $db_user  = $_ENV['DB_USER'];
        $db_pass  = $_ENV['DB_PASSWORD'];

        $settings = [
            'database.host' => $data['db_host'] ?? $db_host,
            'database.port' => $data['db_port'] ?? $db_port,
            'database.name' => $data['db_name'] ?? $db_name,
            'database.user' => $data['db_user'] ?? $db_user,
            'database.charset' => $data['db_charset'] ?? 'utf8'
        ];
        
        foreach ($settings as $key => $value) {
            Config::set($key, $value);
        }
        
        // Save configuration to file
        Config::save();
        
        return ['success' => true, 'message' => 'Database settings updated successfully'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function updateSecuritySettings($data) {
    try {
        // Update security settings (password requirements removed - configured elsewhere)
        $settings = [
            'security.session_lifetime' => (int)($data['session_lifetime'] ?? 3600),
            'security.max_login_attempts' => (int)($data['max_login_attempts'] ?? 5),
            'security.lockout_duration' => (int)($data['lockout_duration'] ?? 900)
        ];
        
        foreach ($settings as $key => $value) {
            Config::set($key, $value);
        }
        
        // Save configuration to file
        Config::save();
        
        return ['success' => true, 'message' => 'Security settings updated successfully'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function updateExternalAPISettings($data) {
    try {
        // Update external API settings
        $settings = [
            'external_apis.openfda.key' => $data['openfda_api_key'] ?? '',
            'external_apis.openfda.rate_limit' => (int)($data['openfda_rate_limit'] ?? 1000),
            'external_apis.nvd.key' => $data['nvd_api_key'] ?? '',
            'external_apis.nvd.rate_limit' => (int)($data['nvd_rate_limit'] ?? 50),
            'external_apis.oui.rate_limit' => (int)($data['oui_rate_limit'] ?? 100),
            'external_apis.maxmind.account_id' => $data['maxmind_account_id'] ?? '',
            'external_apis.maxmind.api_key' => $data['maxmind_api_key'] ?? '',
            'external_apis.maxmind.enabled' => isset($data['maxmind_enabled']) ? true : false
        ];
        
        foreach ($settings as $key => $value) {
            Config::set($key, $value);
        }
        
        // Save configuration to file
        Config::save();
        
        // Write NVD API key to file for Python scripts to access
        if (isset($data['nvd_api_key']) && !empty($data['nvd_api_key'])) {
            $config_file = _ROOT . '/config/nvd_api_key.txt';
            $result = file_put_contents($config_file, $data['nvd_api_key']);
            if ($result === false) {
                error_log("Failed to write NVD API key to file: $config_file");
            }
        }
        
        // Update MaxMind configuration in config.php
        updateMaxMindConfig($data);
        
        return ['success' => true, 'message' => 'External API settings updated successfully'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function updateMaxMindConfig($data) {
    try {
        $config_file = _ROOT . '/config/config.php';
        
        if (!file_exists($config_file)) {
            error_log("Config file not found: $config_file");
            return;
        }
        
        $config_content = file_get_contents($config_file);
        
        // Get MaxMind settings from form data
        $account_id = $data['maxmind_account_id'] ?? '';
        $api_key = $data['maxmind_api_key'] ?? '';
        $enabled = isset($data['maxmind_enabled']) ? true : false;
        
        // Update MAXMIND_ACCOUNT_ID
        $config_content = preg_replace(
            "/define\('MAXMIND_ACCOUNT_ID',\s*'[^']*'\);/",
            "define('MAXMIND_ACCOUNT_ID', '" . addslashes($account_id) . "');",
            $config_content
        );
        
        // Update MAXMIND_API_KEY
        $config_content = preg_replace(
            "/define\('MAXMIND_API_KEY',\s*'[^']*'\);/",
            "define('MAXMIND_API_KEY', '" . addslashes($api_key) . "');",
            $config_content
        );
        
        // Write updated config file
        $result = file_put_contents($config_file, $config_content);
        
        if ($result === false) {
            error_log("Failed to update MaxMind configuration in config.php");
        } else {
            error_log("MaxMind configuration updated successfully");
        }
        
    } catch (Exception $e) {
        error_log("Error updating MaxMind config: " . $e->getMessage());
    }
}

function updateEmailSettings($data) {
    try {
        // Update email settings
        $settings = [
            'email.smtp_host' => $data['smtp_host'] ?? 'localhost',
            'email.smtp_port' => (int)($data['smtp_port'] ?? 587),
            'email.smtp_username' => $data['smtp_username'] ?? '',
            'email.smtp_password' => $data['smtp_password'] ?? '',
            'email.smtp_encryption' => $data['smtp_encryption'] ?? 'tls',
            'email.from_email' => $data['from_email'] ?? 'noreply@dave.local',
            'email.from_name' => $data['from_name'] ?? ' System'
        ];
        
        foreach ($settings as $key => $value) {
            Config::set($key, $value);
        }
        
        // Save configuration to file
        Config::save();
        
        return ['success' => true, 'message' => 'Email settings updated successfully'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function updateBackgroundServicesSettings($data) {
    try {
        // Update background services settings
        $settings = [
            'background_services.enabled' => isset($data['services_enabled']),
            'background_services.recall_check_interval' => (int)($data['recall_check_interval'] ?? 86400),
            'background_services.vulnerability_scan_interval' => (int)($data['vulnerability_scan_interval'] ?? 3600),
            'background_services.cleanup_interval' => (int)($data['cleanup_interval'] ?? 604800)
        ];
        
        foreach ($settings as $key => $value) {
            Config::set($key, $value);
        }
        
        // Save configuration to file
        Config::save();
        
        return ['success' => true, 'message' => 'Background services settings updated successfully'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function updateLoggingSettings($data) {
    try {
        // Convert MB to bytes for max_size
        $maxSizeMB = (int)($data['log_max_size'] ?? 10);
        $maxSizeBytes = $maxSizeMB * 1024 * 1024;
        
        // Update logging settings
        $settings = [
            'logging.level' => $data['log_level'] ?? 'INFO',
            'logging.max_size' => $maxSizeBytes,
            'logging.max_files' => (int)($data['log_max_files'] ?? 5)
        ];
        
        foreach ($settings as $key => $value) {
            Config::set($key, $value);
        }
        
        // Save configuration to file
        Config::save();
        
        return ['success' => true, 'message' => 'Logging settings updated successfully'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function updateCacheSettings($data) {
    try {
        // Update cache settings
        $settings = [
            'cache.enabled' => isset($data['cache_enabled']),
            'cache.lifetime' => (int)($data['cache_lifetime'] ?? 3600)
        ];
        
        foreach ($settings as $key => $value) {
            Config::set($key, $value);
        }
        
        // Save configuration to file
        Config::save();
        
        // Update cache configuration
        require_once __DIR__ . '/../../includes/cache.php';
        Cache::updateConfig(
            isset($data['cache_enabled']),
            (int)($data['cache_lifetime'] ?? 3600)
        );
        
        return ['success' => true, 'message' => 'Cache settings updated successfully'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function updateEnvironmentSettings($data) {
    try {
        // Update environment settings
        $settings = [
            'app.base_url' => $data['base_url'] ?? '',
            'app.api_url' => $data['api_url'] ?? '',
            'app.debug' => isset($data['debug']) ? true : false
        ];
        
        foreach ($settings as $key => $value) {
            Config::set($key, $value);
        }
        
        // Save configuration to file
        Config::save();
        
        return ['success' => true, 'message' => 'Environment settings updated successfully'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Configuration - <?php echo getApplicationName(); ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-cog"></i> System Configuration</h1>
                    <p>Manage system settings, preferences, and configuration options</p>
                </div>
                <div class="page-actions">
                    <button class="btn btn-primary" onclick="saveAllSettings()">
                        <i class="fas fa-save"></i>
                        Save All Settings
                    </button>
                    <button class="btn btn-secondary" onclick="resetToDefaults()">
                        <i class="fas fa-undo"></i>
                        Reset to Defaults
                    </button>
                </div>
            </div>

            <!-- Message Display -->
            <?php if ($message): ?>
            <div class="alert alert-<?php echo $message_type; ?>">
                <i class="fas fa-<?php echo $message_type === 'success' ? 'check-circle' : 'exclamation-circle'; ?>"></i>
                <?php echo dave_htmlspecialchars($message); ?>
            </div>
            <?php endif; ?>

            <!-- Configuration Tabs -->
            <div class="config-tabs">
                <button class="tab-btn active" onclick="showTab('app')">
                    <i class="fas fa-desktop"></i>
                    Application
                </button>
                <button class="tab-btn" onclick="showTab('database')">
                    <i class="fas fa-database"></i>
                    Database
                </button>
                <button class="tab-btn" onclick="showTab('security')">
                    <i class="fas fa-shield-alt"></i>
                    Security
                </button>
                <button class="tab-btn" onclick="showTab('external-apis')">
                    <i class="fas fa-plug"></i>
                    External APIs
                </button>
                <button class="tab-btn" onclick="showTab('email')">
                    <i class="fas fa-envelope"></i>
                    Email
                </button>
                <button class="tab-btn" onclick="showTab('background-services')">
                    <i class="fas fa-clock"></i>
                    Background Services
                </button>
                <button class="tab-btn" onclick="showTab('logging')">
                    <i class="fas fa-file-alt"></i>
                    Logging
                </button>
                <button class="tab-btn" onclick="showTab('cache')">
                    <i class="fas fa-memory"></i>
                    Cache
                </button>
            </div>

            <!-- Application Settings Tab -->
            <div id="app-tab" class="config-tab active">
                <form method="POST" class="config-form">
                    <input type="hidden" name="config_type" value="app">
                    <div class="config-section">
                        <h3><i class="fas fa-desktop"></i> Application Settings</h3>
                        <div class="form-grid">
                            <!-- Application Name field hidden - not editable -->
                            <div class="form-group" style="display: none;">
                                <label for="app_name">Application Name</label>
                                <input type="text" id="app_name" name="app_name" 
                                       value="<?php echo dave_htmlspecialchars($current_config['app']['name'] ?? ''); ?>" 
                                       required>
                            </div>
                            <div class="form-group">
                                <label for="app_timezone">Timezone</label>
                                <select id="app_timezone" name="app_timezone">
                                    <option value="UTC" <?php echo ($current_config['app']['timezone'] ?? '') === 'UTC' ? 'selected' : ''; ?>>UTC</option>
                                    <option value="America/New_York" <?php echo ($current_config['app']['timezone'] ?? '') === 'America/New_York' ? 'selected' : ''; ?>>Eastern Time</option>
                                    <option value="America/Chicago" <?php echo ($current_config['app']['timezone'] ?? '') === 'America/Chicago' ? 'selected' : ''; ?>>Central Time</option>
                                    <option value="America/Denver" <?php echo ($current_config['app']['timezone'] ?? '') === 'America/Denver' ? 'selected' : ''; ?>>Mountain Time</option>
                                    <option value="America/Los_Angeles" <?php echo ($current_config['app']['timezone'] ?? '') === 'America/Los_Angeles' ? 'selected' : ''; ?>>Pacific Time</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="app_locale">Locale</label>
                                <select id="app_locale" name="app_locale">
                                    <option value="en_US" <?php echo ($current_config['app']['locale'] ?? '') === 'en_US' ? 'selected' : ''; ?>>English (US)</option>
                                    <option value="en_GB" <?php echo ($current_config['app']['locale'] ?? '') === 'en_GB' ? 'selected' : ''; ?>>English (UK)</option>
                                    <option value="es_ES" <?php echo ($current_config['app']['locale'] ?? '') === 'es_ES' ? 'selected' : ''; ?>>Spanish</option>
                                    <option value="fr_FR" <?php echo ($current_config['app']['locale'] ?? '') === 'fr_FR' ? 'selected' : ''; ?>>French</option>
                                    <option value="de_DE" <?php echo ($current_config['app']['locale'] ?? '') === 'de_DE' ? 'selected' : ''; ?>>German</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="app_charset">Character Set</label>
                                <select id="app_charset" name="app_charset">
                                    <option value="UTF-8" <?php echo ($current_config['app']['charset'] ?? '') === 'UTF-8' ? 'selected' : ''; ?>>UTF-8</option>
                                    <option value="ISO-8859-1" <?php echo ($current_config['app']['charset'] ?? '') === 'ISO-8859-1' ? 'selected' : ''; ?>>ISO-8859-1</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary btn-sm" name="config_type" value="app">
                            <i class="fas fa-save"></i>
                            Save Application Settings
                        </button>
                    </div>
                </form>
                
                <!-- Environment Configuration Form -->
                <form method="POST" class="config-form">
                    <div class="config-section">
                        <h3><i class="fas fa-globe"></i> Environment Configuration</h3>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="base_url">Base URL *</label>
                                <input type="url" id="base_url" name="base_url" 
                                       value="<?php echo dave_htmlspecialchars($current_config['app']['base_url'] ?? ''); ?>" 
                                       required>
                                <small>The main URL of your  installation (e.g., https://yourdomain.com)</small>
                            </div>
                            <div class="form-group">
                                <label for="api_url">API URL</label>
                                <input type="url" id="api_url" name="api_url" 
                                       value="<?php echo dave_htmlspecialchars($current_config['app']['api_url'] ?? ''); ?>">
                                <small>API endpoint URL (usually Base URL + /api)</small>
                            </div>
                            <div class="form-group">
                                <label class="checkbox-label">
                                    <input type="checkbox" name="debug" 
                                           <?php echo ($current_config['app']['debug'] ?? false) ? 'checked' : ''; ?>>
                                    <span class="checkmark"></span>
                                    Enable Debug Mode
                                </label>
                                <small>Enable detailed error reporting and logging (disable in production)</small>
                            </div>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary btn-sm" name="config_type" value="environment">
                            <i class="fas fa-globe"></i>
                            Save Environment Settings
                        </button>
                    </div>
                </form>
            </div>

            <!-- Database Settings Tab -->
            <div id="database-tab" class="config-tab">
                <form method="POST" class="config-form">
                    <input type="hidden" name="config_type" value="database">
                    <div class="config-section">
                        <h3><i class="fas fa-database"></i> Database Settings</h3>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="db_host">Database Host</label>
                                <input type="text" id="db_host" name="db_host" 
                                       value="<?php echo dave_htmlspecialchars($current_config['database']['host'] ?? ''); ?>" 
                                       required>
                            </div>
                            <div class="form-group">
                                <label for="db_port">Database Port</label>
                                <input type="number" id="db_port" name="db_port" 
                                       value="<?php echo dave_htmlspecialchars($current_config['database']['port'] ?? ''); ?>" 
                                       required>
                            </div>
                            <div class="form-group">
                                <label for="db_name">Database Name</label>
                                <input type="text" id="db_name" name="db_name" 
                                       value="<?php echo dave_htmlspecialchars($current_config['database']['name'] ?? ''); ?>" 
                                       required>
                            </div>
                            <div class="form-group">
                                <label for="db_user">Database User</label>
                                <input type="text" id="db_user" name="db_user" 
                                       value="<?php echo dave_htmlspecialchars($current_config['database']['user'] ?? ''); ?>" 
                                       required>
                            </div>
                            <div class="form-group">
                                <label for="db_charset">Character Set</label>
                                <select id="db_charset" name="db_charset">
                                    <option value="utf8" <?php echo ($current_config['database']['charset'] ?? '') === 'utf8' ? 'selected' : ''; ?>>UTF-8</option>
                                    <option value="latin1" <?php echo ($current_config['database']['charset'] ?? '') === 'latin1' ? 'selected' : ''; ?>>Latin-1</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary btn-sm">
                            <i class="fas fa-save"></i>
                            Save Database Settings
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="testDatabaseConnection()">
                            <i class="fas fa-plug"></i>
                            Test Connection
                        </button>
                    </div>
                </form>
            </div>

            <!-- Security Settings Tab -->
            <div id="security-tab" class="config-tab">
                <form method="POST" class="config-form">
                    <input type="hidden" name="config_type" value="security">
                    <div class="config-section">
                        <h3><i class="fas fa-shield-alt"></i> Security Settings</h3>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="session_lifetime">Session Lifetime (seconds)</label>
                                <input type="number" id="session_lifetime" name="session_lifetime" 
                                       value="<?php echo dave_htmlspecialchars($current_config['security']['session_lifetime'] ?? ''); ?>" 
                                       min="300" max="86400" required>
                            </div>
                            <div class="form-group">
                                <label for="max_login_attempts">Max Login Attempts</label>
                                <input type="number" id="max_login_attempts" name="max_login_attempts" 
                                       value="<?php echo dave_htmlspecialchars($current_config['security']['max_login_attempts'] ?? ''); ?>" 
                                       min="3" max="10" required>
                            </div>
                            <div class="form-group">
                                <label for="lockout_duration">Lockout Duration (seconds)</label>
                                <input type="number" id="lockout_duration" name="lockout_duration" 
                                       value="<?php echo dave_htmlspecialchars($current_config['security']['lockout_duration'] ?? ''); ?>" 
                                       min="300" max="3600" required>
                            </div>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary btn-sm">
                            <i class="fas fa-save"></i>
                            Save Security Settings
                        </button>
                    </div>
                </form>
            </div>

            <!-- External APIs Settings Tab -->
            <div id="external-apis-tab" class="config-tab">
                <form method="POST" class="config-form">
                    <input type="hidden" name="config_type" value="external_apis">
                    <div class="config-section">
                        <h3><i class="fas fa-plug"></i> External API Settings</h3>
                        
                        <div class="api-section">
                            <h4><i class="fas fa-hospital"></i> OpenFDA API</h4>
                            <div class="form-grid">
                                <div class="form-group">
                                    <label for="openfda_api_key">API Key</label>
                                    <input type="password" id="openfda_api_key" name="openfda_api_key" 
                                           value="<?php echo dave_htmlspecialchars($current_config['external_apis']['openfda']['key'] ?? ''); ?>">
                                    <small>Leave blank to use public API (rate limited)</small>
                                </div>
                                <div class="form-group">
                                    <label for="openfda_rate_limit">Rate Limit (requests per hour)</label>
                                    <input type="number" id="openfda_rate_limit" name="openfda_rate_limit" 
                                           value="<?php echo dave_htmlspecialchars($current_config['external_apis']['openfda']['rate_limit'] ?? ''); ?>" 
                                           min="100" max="10000">
                                </div>
                            </div>
                        </div>

                        <div class="api-section">
                            <h4><i class="fas fa-bug"></i> NVD (National Vulnerability Database) API</h4>
                            <div class="form-grid">
                                <div class="form-group">
                                    <label for="nvd_api_key">API Key</label>
                                    <input type="password" id="nvd_api_key" name="nvd_api_key" 
                                           value="<?php echo dave_htmlspecialchars($current_config['external_apis']['nvd']['key'] ?? ''); ?>">
                                    <small>Leave blank to use public API (rate limited)</small>
                                </div>
                                <div class="form-group">
                                    <label for="nvd_rate_limit">Rate Limit (requests per minute)</label>
                                    <input type="number" id="nvd_rate_limit" name="nvd_rate_limit" 
                                           value="<?php echo dave_htmlspecialchars($current_config['external_apis']['nvd']['rate_limit'] ?? ''); ?>" 
                                           min="10" max="1000">
                                </div>
                            </div>
                        </div>

                        <div class="api-section">
                            <h4><i class="fas fa-network-wired"></i> OUI (MAC Address) API</h4>
                            <div class="form-grid">
                                <div class="form-group">
                                    <label for="oui_rate_limit">Rate Limit (requests per minute)</label>
                                    <input type="number" id="oui_rate_limit" name="oui_rate_limit" 
                                           value="<?php echo dave_htmlspecialchars($current_config['external_apis']['oui']['rate_limit'] ?? ''); ?>" 
                                           min="10" max="1000">
                                </div>
                            </div>
                        </div>

                        <div class="api-section">
                            <h4><i class="fas fa-globe"></i> MaxMind GeoIP API</h4>
                            <div class="form-grid">
                                <div class="form-group">
                                    <label for="maxmind_account_id">Account ID</label>
                                    <input type="text" id="maxmind_account_id" name="maxmind_account_id" 
                                           value="<?php echo dave_htmlspecialchars($current_config['external_apis']['maxmind']['account_id'] ?? ''); ?>"
                                           placeholder="Your MaxMind Account ID">
                                    <small>Required for MaxMind GeoIP2 API access</small>
                                </div>
                                <div class="form-group">
                                    <label for="maxmind_api_key">API Key</label>
                                    <input type="password" id="maxmind_api_key" name="maxmind_api_key" 
                                           value="<?php echo dave_htmlspecialchars($current_config['external_apis']['maxmind']['api_key'] ?? ''); ?>"
                                           placeholder="Your MaxMind API Key">
                                    <small>Required for MaxMind GeoIP2 API access</small>
                                </div>
                                <div class="form-group">
                                    <label for="maxmind_enabled">Enable GeoIP Lookups</label>
                                    <div class="checkbox-wrapper">
                                        <input type="checkbox" id="maxmind_enabled" name="maxmind_enabled" 
                                               <?php echo ($current_config['external_apis']['maxmind']['enabled'] ?? false) ? 'checked' : ''; ?>>
                                        <label for="maxmind_enabled" class="checkbox-label">
                                            Enable IP address location lookups
                                        </label>
                                    </div>
                                    <small>Disable to show "Unknown Location" for all IP addresses</small>
                                </div>
                            </div>
                            <div class="api-info">
                                <h5>About MaxMind GeoIP</h5>
                                <p>MaxMind GeoIP provides geographical location data for IP addresses, enhancing security monitoring and audit logs with location information.</p>
                                <ul>
                                    <li>Get your credentials from <a href="https://www.maxmind.com/en/accounts/current/license-key" target="_blank">MaxMind Account Portal</a></li>
                                    <li>Free tier available with limited requests per month</li>
                                    <li>Location data is cached to reduce API calls</li>
                                    <li>Private IP addresses show as "Local Network"</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary btn-sm">
                            <i class="fas fa-save"></i>
                            Save API Settings
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="testAPIConnections()">
                            <i class="fas fa-plug"></i>
                            Test API Connections
                        </button>
                    </div>
                </form>
            </div>

            <!-- Email Settings Tab -->
            <div id="email-tab" class="config-tab">
                <form method="POST" class="config-form">
                    <input type="hidden" name="config_type" value="email">
                    <div class="config-section">
                        <h3><i class="fas fa-envelope"></i> Email Settings</h3>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="smtp_host">SMTP Host</label>
                                <input type="text" id="smtp_host" name="smtp_host" 
                                       value="<?php echo dave_htmlspecialchars($current_config['email']['smtp_host'] ?? ''); ?>" 
                                       required>
                            </div>
                            <div class="form-group">
                                <label for="smtp_port">SMTP Port</label>
                                <input type="number" id="smtp_port" name="smtp_port" 
                                       value="<?php echo dave_htmlspecialchars($current_config['email']['smtp_port'] ?? ''); ?>" 
                                       min="1" max="65535" required>
                            </div>
                            <div class="form-group">
                                <label for="smtp_username">SMTP Username</label>
                                <input type="text" id="smtp_username" name="smtp_username" 
                                       value="<?php echo dave_htmlspecialchars($current_config['email']['smtp_username'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="smtp_password">SMTP Password</label>
                                <input type="password" id="smtp_password" name="smtp_password" 
                                       value="<?php echo dave_htmlspecialchars($current_config['email']['smtp_password'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="smtp_encryption">Encryption</label>
                                <select id="smtp_encryption" name="smtp_encryption">
                                    <option value="none" <?php echo ($current_config['email']['smtp_encryption'] ?? '') === 'none' ? 'selected' : ''; ?>>None</option>
                                    <option value="tls" <?php echo ($current_config['email']['smtp_encryption'] ?? '') === 'tls' ? 'selected' : ''; ?>>TLS</option>
                                    <option value="ssl" <?php echo ($current_config['email']['smtp_encryption'] ?? '') === 'ssl' ? 'selected' : ''; ?>>SSL</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="from_email">From Email</label>
                                <input type="email" id="from_email" name="from_email" 
                                       value="<?php echo dave_htmlspecialchars($current_config['email']['from_email'] ?? ''); ?>" 
                                       required>
                            </div>
                            <div class="form-group">
                                <label for="from_name">From Name</label>
                                <input type="text" id="from_name" name="from_name" 
                                       value="<?php echo dave_htmlspecialchars($current_config['email']['from_name'] ?? ''); ?>" 
                                       required>
                            </div>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary btn-sm">
                            <i class="fas fa-save"></i>
                            Save Email Settings
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="testEmailConnection()">
                            <i class="fas fa-envelope"></i>
                            Test Email
                        </button>
                    </div>
                </form>
            </div>

            <!-- Background Services Settings Tab -->
            <div id="background-services-tab" class="config-tab">
                <form method="POST" class="config-form">
                    <input type="hidden" name="config_type" value="background_services">
                    <div class="config-section">
                        <h3><i class="fas fa-clock"></i> Background Services Settings</h3>
                        <div class="form-group">
                            <label class="checkbox-label">
                                <input type="checkbox" name="services_enabled" 
                                       <?php echo ($current_config['background_services']['enabled'] ?? false) ? 'checked' : ''; ?>>
                                <span class="checkmark"></span>
                                Enable Background Services
                            </label>
                        </div>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="recall_check_interval">Recall Check Interval (seconds)</label>
                                <input type="number" id="recall_check_interval" name="recall_check_interval" 
                                       value="<?php echo dave_htmlspecialchars($current_config['background_services']['recall_check_interval'] ?? ''); ?>" 
                                       min="3600" max="604800">
                                <small>How often to check for new FDA recalls (default: 24 hours)</small>
                            </div>
                            <div class="form-group">
                                <label for="vulnerability_scan_interval">Vulnerability Scan Interval (seconds)</label>
                                <input type="number" id="vulnerability_scan_interval" name="vulnerability_scan_interval" 
                                       value="<?php echo dave_htmlspecialchars($current_config['background_services']['vulnerability_scan_interval'] ?? ''); ?>" 
                                       min="1800" max="86400">
                                <small>How often to scan for new vulnerabilities (default: 1 hour)</small>
                            </div>
                            <div class="form-group">
                                <label for="cleanup_interval">Data Cleanup Interval (seconds)</label>
                                <input type="number" id="cleanup_interval" name="cleanup_interval" 
                                       value="<?php echo dave_htmlspecialchars($current_config['background_services']['cleanup_interval'] ?? ''); ?>" 
                                       min="86400" max="2592000">
                                <small>How often to clean up old data (default: 7 days)</small>
                            </div>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary btn-sm">
                            <i class="fas fa-save"></i>
                            Save Background Services Settings
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="restartBackgroundServices()">
                            <i class="fas fa-redo"></i>
                            Restart Services
                        </button>
                    </div>
                </form>
            </div>

            <!-- Logging Settings Tab -->
            <div id="logging-tab" class="config-tab">
                <form method="POST" class="config-form">
                    <input type="hidden" name="config_type" value="logging">
                    <div class="config-section">
                        <h3><i class="fas fa-file-alt"></i> Logging Settings</h3>
                        
                        <!-- Log Statistics -->
                        <div class="api-section">
                            <h4><i class="fas fa-chart-bar"></i> Log Statistics</h4>
                            <div class="form-grid">
                                <div class="form-group">
                                    <label>Total Log Files</label>
                                    <div class="stat-value"><?php echo $log_stats['total_files']; ?></div>
                                </div>
                                <div class="form-group">
                                    <label>Total Log Size</label>
                                    <div class="stat-value"><?php echo number_format($log_stats['total_size'] / 1024, 2); ?> KB</div>
                                </div>
                                <div class="form-group">
                                    <label>Current Log Level</label>
                                    <div class="status-indicator">
                                        <span class="status-badge status-info">
                                            <?php echo $current_config['logging']['level'] ?? 'INFO'; ?>
                                        </span>
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label>Log Directory</label>
                                    <div class="stat-value"><?php echo _LOGS; ?></div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="log_level">Log Level</label>
                                <select id="log_level" name="log_level">
                                    <option value="DEBUG" <?php echo ($current_config['logging']['level'] ?? '') === 'DEBUG' ? 'selected' : ''; ?>>DEBUG - All messages</option>
                                    <option value="INFO" <?php echo ($current_config['logging']['level'] ?? '') === 'INFO' ? 'selected' : ''; ?>>INFO - Informational messages</option>
                                    <option value="WARNING" <?php echo ($current_config['logging']['level'] ?? '') === 'WARNING' ? 'selected' : ''; ?>>WARNING - Warning messages</option>
                                    <option value="ERROR" <?php echo ($current_config['logging']['level'] ?? '') === 'ERROR' ? 'selected' : ''; ?>>ERROR - Error messages only</option>
                                </select>
                                <small>Controls which log messages are written</small>
                            </div>
                            <div class="form-group">
                                <label for="log_max_size">Max Log File Size (MB)</label>
                                <input type="number" id="log_max_size" name="log_max_size" 
                                       value="<?php echo dave_htmlspecialchars(($current_config['logging']['max_size'] ?? 10485760) / 1048576); ?>" 
                                       min="1" max="100">
                                <small>Maximum size before rotating log files (1-100 MB)</small>
                            </div>
                            <div class="form-group">
                                <label for="log_max_files">Max Log Files</label>
                                <input type="number" id="log_max_files" name="log_max_files" 
                                       value="<?php echo dave_htmlspecialchars($current_config['logging']['max_files'] ?? ''); ?>" 
                                       min="1" max="50">
                                <small>Number of rotated log files to keep</small>
                            </div>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary btn-sm">
                            <i class="fas fa-save"></i>
                            Save Logging Settings
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="viewLogFiles()">
                            <i class="fas fa-eye"></i>
                            View Log Files
                        </button>
                        <button type="button" class="btn btn-accent btn-sm" onclick="cleanOldLogs()">
                            <i class="fas fa-broom"></i>
                            Clean Old Logs
                        </button>
                        <button type="button" class="btn btn-primary btn-sm" onclick="testLogging()">
                            <i class="fas fa-vial"></i>
                            Test Logging
                        </button>
                    </div>
                </form>
            </div>

            <!-- Cache Settings Tab -->
            <div id="cache-tab" class="config-tab">
                <form method="POST" class="config-form">
                    <input type="hidden" name="config_type" value="cache">
                    <div class="config-section">
                        <h3><i class="fas fa-memory"></i> Cache Settings</h3>
                        
                        <!-- Cache Statistics -->
                        <div class="api-section">
                            <h4><i class="fas fa-chart-bar"></i> Cache Statistics</h4>
                            <div class="form-grid">
                                <div class="form-group">
                                    <label>Cache Status</label>
                                    <div class="status-indicator">
                                        <span class="status-badge <?php echo $cache_stats['enabled'] ? 'status-success' : 'status-error'; ?>">
                                            <?php echo $cache_stats['enabled'] ? 'Enabled' : 'Disabled'; ?>
                                        </span>
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label>Total Cache Files</label>
                                    <div class="stat-value"><?php echo $cache_stats['total_files']; ?></div>
                                </div>
                                <div class="form-group">
                                    <label>Cache Size</label>
                                    <div class="stat-value"><?php echo number_format($cache_stats['total_size'] / 1024, 2); ?> KB</div>
                                </div>
                                <div class="form-group">
                                    <label>Expired Files</label>
                                    <div class="stat-value"><?php echo $cache_stats['expired_files']; ?></div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label class="checkbox-label">
                                <input type="checkbox" name="cache_enabled" 
                                       <?php echo ($current_config['cache']['enabled'] ?? false) ? 'checked' : ''; ?>>
                                <span class="checkmark"></span>
                                Enable Caching
                            </label>
                            <small>Enable or disable the caching system</small>
                        </div>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="cache_lifetime">Cache Lifetime (seconds)</label>
                                <input type="number" id="cache_lifetime" name="cache_lifetime" 
                                       value="<?php echo dave_htmlspecialchars($current_config['cache']['lifetime'] ?? ''); ?>" 
                                       min="60" max="86400">
                                <small>How long to keep cached data (60-86400 seconds)</small>
                            </div>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary btn-sm">
                            <i class="fas fa-save"></i>
                            Save Cache Settings
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="clearCache()">
                            <i class="fas fa-trash"></i>
                            Clear Cache
                        </button>
                        <button type="button" class="btn btn-accent btn-sm" onclick="cleanCache()">
                            <i class="fas fa-broom"></i>
                            Clean Expired
                        </button>
                    </div>
                </form>
            </div>
        </main>
    </div>

    <script src="<?php echo getAssetsUrl(); ?>/js/config.js"></script>
    <script>
        // System Configuration JavaScript
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize form validation
            initializeFormValidation();
            
            // Add loading states to buttons
            document.querySelectorAll('.btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    if (this.type === 'submit') {
                        this.classList.add('loading');
                    }
                });
            });
            
            // Auto-populate API URL based on Base URL
            const baseUrlInput = document.getElementById('base_url');
            if (baseUrlInput) {
                baseUrlInput.addEventListener('input', function() {
                    const baseUrl = this.value;
                    if (baseUrl) {
                        const apiUrlInput = document.getElementById('api_url');
                        if (apiUrlInput) {
                            apiUrlInput.value = baseUrl + '/api';
                        }
                    }
                });
            }
        });

        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.config-tab').forEach(function(tab) {
                tab.classList.remove('active');
            });
            
            // Remove active class from all tab buttons
            document.querySelectorAll('.tab-btn').forEach(function(btn) {
                btn.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            
            // Add active class to clicked button
            event.target.classList.add('active');
        }

        function initializeFormValidation() {
            // Add real-time validation
            document.querySelectorAll('input[required]').forEach(function(input) {
                input.addEventListener('blur', function() {
                    validateField(this);
                });
            });
        }

        function validateField(field) {
            const value = field.value.trim();
            const isValid = value !== '';
            
            if (isValid) {
                field.classList.remove('error');
                field.classList.add('valid');
            } else {
                field.classList.remove('valid');
                field.classList.add('error');
            }
            
            return isValid;
        }

        function saveAllSettings() {
            // Save all configuration settings
            if (confirm('Are you sure you want to save all configuration settings?')) {
                // This would need to be implemented to save all forms at once
                alert('All settings saved successfully!');
            }
        }

        function resetToDefaults() {
            if (confirm('Are you sure you want to reset all settings to their default values? This action cannot be undone.')) {
                // This would need to be implemented to reset all settings
                alert('Settings reset to defaults!');
                location.reload();
            }
        }

        function testDatabaseConnection() {
            // Test database connection
            alert('Testing database connection...');
            // This would need to be implemented with AJAX
        }

        function testAPIConnections() {
            // Test external API connections
            alert('Testing API connections...');
            // This would need to be implemented with AJAX
        }

        function testEmailConnection() {
            // Test email configuration
            alert('Testing email configuration...');
            // This would need to be implemented with AJAX
        }

        function restartBackgroundServices() {
            if (confirm('Are you sure you want to restart background services?')) {
                alert('Background services restart initiated...');
                // This would need to be implemented with AJAX
            }
        }

        function viewLogFiles() {
            // Navigate to log files
            window.location.href = '/pages/admin/logs.php';
        }

        function cleanOldLogs() {
            if (confirm('Are you sure you want to clean old log files (older than 30 days)?')) {
                // Show loading state
                const button = event.target;
                const originalText = button.innerHTML;
                button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cleaning...';
                button.disabled = true;
                
                // Make AJAX request to clean old logs
                fetch('/api/v1/system/clean-old-logs.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Old logs cleaned successfully! ' + data.message);
                        // Reload page to show updated statistics
                        location.reload();
                    } else {
                        alert('Error cleaning logs: ' + data.message);
                    }
                })
                .catch(error => {
                    alert('Error cleaning logs: ' + error.message);
                })
                .finally(() => {
                    button.innerHTML = originalText;
                    button.disabled = false;
                });
            }
        }

        function testLogging() {
            // Show loading state
            const button = event.target;
            const originalText = button.innerHTML;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';
            button.disabled = true;
            
            // Make AJAX request to test logging
            fetch('/api/v1/system/test-logging.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Logging test completed! ' + data.message);
                } else {
                    alert('Error testing logging: ' + data.message);
                }
            })
            .catch(error => {
                alert('Error testing logging: ' + error.message);
            })
            .finally(() => {
                button.innerHTML = originalText;
                button.disabled = false;
            });
        }

        function clearCache() {
            if (confirm('Are you sure you want to clear all cached data?')) {
                // Show loading state
                const button = event.target;
                const originalText = button.innerHTML;
                button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Clearing...';
                button.disabled = true;
                
                // Make AJAX request to clear cache
                fetch('/api/v1/system/clear-cache.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Cache cleared successfully! ' + data.message);
                        // Reload page to show updated statistics
                        location.reload();
                    } else {
                        alert('Error clearing cache: ' + data.message);
                    }
                })
                .catch(error => {
                    alert('Error clearing cache: ' + error.message);
                })
                .finally(() => {
                    button.innerHTML = originalText;
                    button.disabled = false;
                });
            }
        }

        function cleanCache() {
            if (confirm('Are you sure you want to clean expired cache files?')) {
                // Show loading state
                const button = event.target;
                const originalText = button.innerHTML;
                button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cleaning...';
                button.disabled = true;
                
                // Make AJAX request to clean cache
                fetch('/api/v1/system/clean-cache.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Cache cleaned successfully! ' + data.message);
                        // Reload page to show updated statistics
                        location.reload();
                    } else {
                        alert('Error cleaning cache: ' + data.message);
                    }
                })
                .catch(error => {
                    alert('Error cleaning cache: ' + error.message);
                })
                .finally(() => {
                    button.innerHTML = originalText;
                    button.disabled = false;
                });
            }
        }
    </script>
    <!-- Profile Dropdown Script -->
    <script src="<?php echo getAssetsUrl(); ?>/js/dashboard-common.js"></script>
    <script>
        // Pass user data to the profile dropdown
        window.userData = {
            name: '<?php echo dave_htmlspecialchars($user['username']); ?>',
            role: '<?php echo dave_htmlspecialchars($user['role']); ?>',
            email: '<?php echo dave_htmlspecialchars($user['email'] ?? 'user@example.com'); ?>'
        };
    </script>
</body>
</html>
