<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Security check
if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}

// Load config for helper functions
require_once __DIR__ . '/config/config.php';

// Check if already configured
$configFile = __DIR__ . '/config/settings.json';
$isConfigured = file_exists($configFile) && filesize($configFile) > 0;

// Get base URL from config if already configured
$baseUrl = '/';
if ($isConfigured) {
    $configData = json_decode(file_get_contents($configFile), true);
    $baseUrl = $configData['app']['base_url'] ?? '/';
}

// Auto-detect base URL from current request
$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$detectedBaseUrl = $protocol . '://' . $host;

// Handle form submission
$message = '';
$messageType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$isConfigured) {
    try {
        // Validate required fields
        $baseUrl = $_POST['base_url'] ?? '';
        $dbHost = $_POST['db_host'] ?? '';
        $dbPort = $_POST['db_port'] ?? '';
        $dbName = $_POST['db_name'] ?? '';
        $dbUser = $_POST['db_user'] ?? '';
        $dbPassword = $_POST['db_password'] ?? '';
        $admin_user =   getenv('DAVE_ADMIN_USER');
        $integration_api_key = '';

        if (empty($baseUrl) || empty($dbHost) || empty($dbPort) || empty($dbName) || empty($dbUser) || empty($dbPassword)) {
            throw new Exception('All fields are required');
        }
        
        // Validate base URL
        if (!filter_var($baseUrl, FILTER_VALIDATE_URL)) {
            throw new Exception('Invalid base URL format');
        }
        
        // Test database connection
        try {
            $pdo = new PDO(
                "pgsql:host=$dbHost;port=" . ($_POST['db_port'] ?? '5432') . ";dbname=$dbName",
                $dbUser,
                $dbPassword
            );
        } catch (PDOException $e) {
            throw new Exception('Database connection failed: ' . $e->getMessage());
        }
        
        // Set up initial configuration
        $config = [
            'app' => [
                'name' => 'Device Assessment and Vulnerability Exposure',
                'base_url' => rtrim($baseUrl, '/'),
                'api_url' => rtrim($baseUrl, '/') . '/api',
                'debug' => $_POST['debug'] ?? false
            ],
            'database' => [
                'host' => $dbHost,
                'port' => $_POST['db_port'] ?? '5432',
                'name' => $dbName,
                'user' => $dbUser,
                'password' => $dbPassword
            ],
            'security' => [
                'session_lifetime' => 3600,
                'max_login_attempts' => 5,
                'lockout_duration' => 900
            ],
            'email' => [
                'smtp_host' => $_POST['smtp_host'] ?? 'localhost',
                'smtp_port' => $_POST['smtp_port'] ?? '587',
                'smtp_username' => $_POST['smtp_username'] ?? '',
                'smtp_password' => $_POST['smtp_password'] ?? '',
                'smtp_encryption' => $_POST['smtp_encryption'] ?? 'tls',
                'from_email' => $_POST['from_email'] ?? 'noreply@localhost',
                'from_name' => $_POST['from_name'] ?? '\'DAVE System\''
            ],
            'cynerio' => [
                'client_id' => $_POST['cynerio_client_id'] ?? '',
                'client_secret' => $_POST['cynerio_client_secret'] ?? '',
                'endpoint' => $_POST['cynerio_endpoint'] ?? '',
                'auth_endpoint' => $_POST['cynerio_auth_endpoint'] ?? '',
            ],
            'blueflow' => [
                'endpoint' => $_POST['blueflow_endpoint'] ?? ''
            ],
            'netdisco' => [
                'endpoint' => $_POST['netdisco_endpoint'] ?? ''
            ]

        ];
        
        // Save configuration
        Config::set('app', $config['app']);
        Config::set('database', $config['database']);
        Config::set('security', $config['security']);
        Config::set('email', $config['email']);
        Config::set('cynerio', $config['cynerio']);
        Config::save();
        
        // Now setup integration user and API key (after database config is saved)
        try {
            // Load configuration system
            require_once __DIR__ . '/includes/functions.php';
            require_once __DIR__ . '/config/database.php';
            require_once __DIR__ . '/includes/api-key-manager.php';
            require_once __DIR__ . '/includes/api-key-auth.php';
            
            // Get the user ID for the integration user
            $db = DatabaseConfig::getInstance();
            $stmt = $db->query("SELECT user_id, username, role, is_active FROM users WHERE username = ? AND is_active = TRUE", [$admin_user]);
            $user = $stmt->fetch();
            
            if (!$user) {
                throw new Exception("Integration user '$admin_user' not found or is inactive. Please ensure the database schema is imported and the user exists.");
            }
            
            // Create API key for integration user
            $apiKeyManager = new ApiKeyManager();
            $integrationKeyName = getDaveIntegrationKeyName();
            
            // Check if integration API key already exists and delete it
            $stmt = $db->query("SELECT key_id FROM dave_api_keys WHERE key_name = ?", [$integrationKeyName]);
            $existingKey = $stmt->fetch();
            
            if ($existingKey) {
                // Delete the existing integration API key
                $deleteResult = $apiKeyManager->deleteApiKey($existingKey['key_id']);
                if (!$deleteResult['success']) {
                    error_log('Warning: Failed to delete existing integration API key: ' . ($deleteResult['error'] ?? 'Unknown error'));
                }
            }
            
            // Create new API key for integration user
            $apiKeyResult = $apiKeyManager->createApiKey([
                'user_id' => $user['user_id'],
                'key_name' => $integrationKeyName,
                'description' => 'API key for external system integration',
                'is_active' => true,
                'rate_limit_per_hour' => 10000,
                'created_by' => $user['user_id']
            ]);
            
            if (!$apiKeyResult['success']) {
                throw new Exception('Failed to create API key: ' . ($apiKeyResult['error'] ?? 'Unknown error'));
            }
            
            $integration_api_key = $apiKeyResult['api_key'];
            
        } catch (Exception $e) {
            // Log the error but don't fail the entire setup
            error_log('Warning: Failed to setup integration API key: ' . $e->getMessage());
            $integration_api_key = 'SETUP_REQUIRED'; // Placeholder value
        }
        
        // Create .env file
        $envContent = "# DAVE Environment Configuration\n";
        $envContent .= "# Generated on " . date('Y-m-d H:i:s') . "\n\n";
        $envContent .= "# Core Application Settings\n";
        $envContent .= "DAVE_BASE_URL=" . $config['app']['base_url'] . "\n";
        $envContent .= "DAVE_API_URL=" . $config['app']['api_url'] . "\n";
        $envContent .= "DAVE_ADMIN_USER=" . getenv('DAVE_ADMIN_USER') . "\n";
        $envContent .= "DAVE_ADMIN_DEFAULT_PASSWORD=" . getenv('DAVE_ADMIN_DEFAULT_PASSWORD') . "\n";        
        $envContent .= "DAVE_INTEGRATION_API_KEY=" . $integration_api_key . "\n";
        $envContent .= "DAVE_DEBUG=" . ($config['app']['debug'] ? 'true' : 'false') . "\n\n";
        $envContent .= "# Database Configuration\n";
        $envContent .= "DB_HOST=" . $config['database']['host'] . "\n";
        $envContent .= "DB_PORT=" . $config['database']['port'] . "\n";
        $envContent .= "DB_NAME=" . $config['database']['name'] . "\n";
        $envContent .= "DB_USER=" . $config['database']['user'] . "\n";
        $envContent .= "DB_PASSWORD=" . $config['database']['password'] . "\n\n";
        $envContent .= "# Email Configuration\n";
        $envContent .= "DAVE_SMTP_HOST=" . $config['email']['smtp_host'] . "\n";
        $envContent .= "DAVE_SMTP_PORT=" . $config['email']['smtp_port'] . "\n";
        $envContent .= "DAVE_SMTP_USERNAME=" . $config['email']['smtp_username'] . "\n";
        $envContent .= "DAVE_SMTP_PASSWORD=" . $config['email']['smtp_password'] . "\n";
        $envContent .= "DAVE_SMTP_ENCRYPTION=" . $config['email']['smtp_encryption'] . "\n";
        $envContent .= "DAVE_FROM_EMAIL=" . $config['email']['from_email'] . "\n";
        $envContent .= "DAVE_FROM_NAME=" . $config['email']['from_name'] . "\n";

        $envContent .= "CYNERIO_CLIENT_ID=" . $config['cynerio']['client_id'] . "\n";
        $envContent .= "CYNERIO_CLIENT_SECRET=" . $config['cynerio']['client_secret'] . "\n";
        $envContent .= "CYNERIO_ENDPOINT=" . $config['cynerio']['endpoint'] . "\n";
        $envContent .= "CYNERIO_AUTH_ENDPOINT=" . $config['cynerio']['auth_endpoint'] . "\n";

        $envContent .= "BLUEFLOW_API_URL=" . $config['blueflow']['endpoint'] . "\n";

        $envContent .= "NETDISCO_API_URL=" . $config['netdisco']['endpoint'] . "\n";

        file_put_contents(__DIR__ . '/.env', $envContent);
        
        // Update $baseUrl to the saved value (not from POST) for the success page
        $baseUrl = $config['app']['base_url'];
        
        $message = 'Setup completed successfully! You can now access the application.';
        $messageType = 'success';
        $isConfigured = true;
        
    } catch (Exception $e) {
        $message = 'Setup failed: ' . $e->getMessage();
        $messageType = 'error';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DAVE Setup - Device Assessment and Vulnerability Exposure</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Siemens Sans', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #000000 0%, #1a1a1a 50%, #333333 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .setup-container {
            background: #1a1a1a;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
            border: 1px solid #333333;
            padding: 40px;
            max-width: 600px;
            width: 100%;
        }
        
        .setup-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
        }
        
        .logo-image {
            height: 60px;
            width: auto;
            object-fit: contain;
            filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3));
            max-width: 250px;
        }
        
        .setup-header h1 {
            color: #f8fafc;
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 700;
        }
        
        .setup-header p {
            color: #cbd5e1;
            font-size: 1.1rem;
        }
        
        .icon {
            font-size: 4rem;
            color: #009999;
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #f8fafc;
            font-weight: 600;
        }
        
        .form-group input,
        .form-group select {
            width: 100%;
            padding: 12px 16px;
            background: #000000;
            color: #f8fafc;
            border: 2px solid #333333;
            border-radius: 8px;
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: #009999;
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
        }
        
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
        }
        
        .btn {
            background: #009999;
            color: white;
            border: 1px solid #009999;
            padding: 14px 30px;
            border-radius: 8px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            width: 100%;
        }
        
        .btn:hover {
            background: #007777;
            border-color: #007777;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.3);
        }
        
        .btn:disabled {
            background: #a0aec0;
            cursor: not-allowed;
        }
        
        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid #10b981;
            color: #10b981;
        }
        
        .alert-error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid #ef4444;
            color: #ef4444;
        }
        
        .success-message {
            text-align: center;
            padding: 40px;
        }
        
        .success-message h2 {
            color: #10b981;
            margin-bottom: 20px;
        }
        
        .success-message p {
            color: #cbd5e1;
            margin-bottom: 30px;
        }
        
        .btn-success {
            background: #10b981;
            border: 1px solid #10b981;
        }
        
        .btn-success:hover {
            background: #059669;
            border-color: #059669;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
        }
        
        .help-text {
            font-size: 0.9rem;
            color: #94a3b8;
            margin-top: 5px;
        }
        
        h3 {
            color: #f8fafc;
        }
    </style>
</head>
<body>
    <div class="setup-container">
        <?php if ($isConfigured): ?>
            <div class="success-message">
                <div class="icon">
                    <i class="fas fa-check-circle"></i>
                </div>
                <h2>Setup Complete!</h2>
                <p>Your DAVE installation has been configured successfully. You can now access the application using the configured base URL.</p>
                <p style="font-size: 0.9rem; color: #94a3b8; margin-bottom: 20px;">
                    Redirecting to: <strong style="color: #10b981;"><?php echo dave_htmlspecialchars($baseUrl); ?></strong>
                </p>
                <a href="<?php echo dave_htmlspecialchars($baseUrl); ?>" class="btn btn-success">
                    <i class="fas fa-arrow-right"></i> Access Application
                </a>
            </div>
        <?php else: ?>
            <div class="setup-header">
                <div class="logo">
                    <img src="/assets/images/siemens-healthineers-logo.png" alt="Siemens Healthineers" class="logo-image">
                </div>
                <h1>DAVE Setup</h1>
                <p>Device Assessment and Vulnerability Exposure</p>
                <p style="font-size: 0.95rem; margin-top: 10px; color: #94a3b8;">Configure your system</p>
            </div>
            
            <?php if ($message): ?>
                <div class="alert alert-<?php echo $messageType; ?>">
                    <i class="fas fa-<?php echo $messageType === 'success' ? 'check-circle' : 'exclamation-circle'; ?>"></i>
                    <?php echo dave_htmlspecialchars($message); ?>
                </div>
            <?php endif; ?>
            
            <form method="POST">
                <h3 style="margin-bottom: 20px; color: #2d3748;">Application Configuration</h3>
                
                <div class="form-group">
                    <label for="base_url">Base URL *</label>
                    <input type="url" id="base_url" name="base_url" 
                           value="<?php echo dave_htmlspecialchars($_POST['base_url'] ?? $detectedBaseUrl); ?>" 
                           placeholder="https://yourdomain.com" required>
                    <div class="help-text">The main URL where DAVE will be accessible</div>
                </div>
                
                <div class="form-group">
                    <div class="checkbox-group">
                        <input type="checkbox" id="debug" name="debug" 
                               <?php echo ($_POST['debug'] ?? false) ? 'checked' : ''; ?>>
                        <label for="debug">Enable Debug Mode</label>
                    </div>
                    <div class="help-text">Enable detailed error reporting (disable in production)</div>
                </div>
                
                <h3 style="margin: 30px 0 20px 0; color: #2d3748;">Database Configuration</h3>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="db_host">Database Host *</label>
                        <input type="text" id="db_host" name="db_host" 
                               value="<?php echo dave_htmlspecialchars($_POST['db_host'] ?? getenv('DB_HOST') ?: ''); ?>" required>
                    </div>
                    <div class="form-group">
                        <label for="db_port">Database Port *</label>
                        <input type="number" id="db_port" name="db_port" 
                               value="<?php echo dave_htmlspecialchars($_POST['db_port'] ?? getenv('DB_PORT') ?: ''); ?>">
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="db_name">Database Name *</label>
                        <input type="text" id="db_name" name="db_name" 
                               value="<?php echo dave_htmlspecialchars($_POST['db_name'] ?? getenv('DB_NAME') ?: ''); ?>" required>
                    </div>
                    <div class="form-group">
                        <label for="db_user">Database User *</label>
                        <input type="text" id="db_user" name="db_user" 
                               value="<?php echo dave_htmlspecialchars($_POST['db_user'] ?? getenv('DB_USER') ?: ''); ?>" required>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="db_password">Database Password *</label>
                    <input type="password" id="db_password" name="db_password" required>
                </div>
                
                <h3 style="margin: 30px 0 20px 0; color: #2d3748;">Email Configuration (Optional)</h3>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="smtp_host">SMTP Host</label>
                        <input type="text" id="smtp_host" name="smtp_host" 
                               value="<?php echo dave_htmlspecialchars($_POST['smtp_host'] ?? 'localhost'); ?>">
                    </div>
                    <div class="form-group">
                        <label for="smtp_port">SMTP Port</label>
                        <input type="number" id="smtp_port" name="smtp_port" 
                               value="<?php echo dave_htmlspecialchars($_POST['smtp_port'] ?? '587'); ?>">
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="smtp_username">SMTP Username</label>
                        <input type="text" id="smtp_username" name="smtp_username" 
                               value="<?php echo dave_htmlspecialchars($_POST['smtp_username'] ?? ''); ?>">
                    </div>
                    <div class="form-group">
                        <label for="smtp_password">SMTP Password</label>
                        <input type="password" id="smtp_password" name="smtp_password">
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="smtp_encryption">SMTP Encryption</label>
                    <select id="smtp_encryption" name="smtp_encryption">
                        <option value="none" <?php echo ($_POST['smtp_encryption'] ?? 'tls') === 'none' ? 'selected' : ''; ?>>None</option>
                        <option value="tls" <?php echo ($_POST['smtp_encryption'] ?? 'tls') === 'tls' ? 'selected' : ''; ?>>TLS</option>
                        <option value="ssl" <?php echo ($_POST['smtp_encryption'] ?? 'tls') === 'ssl' ? 'selected' : ''; ?>>SSL</option>
                    </select>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="from_email">From Email</label>
                        <input type="email" id="from_email" name="from_email" 
                               value="<?php echo dave_htmlspecialchars($_POST['from_email'] ?? 'noreply@localhost'); ?>">
                    </div>
                    <div class="form-group">
                        <label for="from_name">From Name</label>
                        <input type="text" id="from_name" name="from_name" 
                               value="<?php echo dave_htmlspecialchars($_POST['from_name'] ?? '\'DAVE System\''); ?>">
                    </div>
                </div>

                <h3 style="margin: 30px 0 20px 0; color: #2d3748;">Cynerio Configuration (Optional)</h3>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="cynerio_client_id">Cynerio Client ID</label>
                        <input type="text" id="cynerio_client_id" name="cynerio_client_id" 
                               value="<?php echo dave_htmlspecialchars($_POST['cynerio_client_id'] ?? ''); ?>">
                    </div>
                    <div class="form-group">
                        <label for="cynerio_client_secret">Cynerio Client Secret</label>
                        <input type="text" id="cynerio_client_secret" name="cynerio_client_secret" 
                               value="<?php echo dave_htmlspecialchars($_POST['cynerio_client_secret'] ?? ''); ?>">
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label for="cynerio_endpoint">Cynerio Endpoint</label>
                        <input type="text" id="cynerio_endpoint" name="cynerio_endpoint" 
                               value="<?php echo dave_htmlspecialchars($_POST['cynerio_endpoint'] ?? ''); ?>">
                    </div>
                    <div class="form-group">
                        <label for="cynerio_auth_endpoint">Cynerio Auth Endpoint</label>
                        <input type="text" id="cynerio_auth_endpoint" name="cynerio_auth_endpoint" 
                               value="<?php echo dave_htmlspecialchars($_POST['cynerio_auth_endpoint'] ?? ''); ?>">
                    </div>
                </div>   

                <h3 style="margin: 30px 0 20px 0; color: #2d3748;">Blueflow Configuration (Optional)</h3>
                
                <div class="form-group">
                    <label for="blueflow_endpoint">Blueflow Endpoint</label>
                    <input type="text" id="blueflow_endpoint" name="blueflow_endpoint" 
                            value="<?php echo dave_htmlspecialchars($_POST['blueflow_endpoint'] ?? ''); ?>">
                </div>
                
                <h3 style="margin: 30px 0 20px 0; color: #2d3748;">Netdisco Configuration (Optional)</h3>
                
                <div class="form-group">
                    <label for="netdisco_endpoint">Netdisco Endpoint</label>
                    <input type="text" id="netdisco_endpoint" name="netdisco_endpoint" 
                            value="<?php echo dave_htmlspecialchars($_POST['netdisco_endpoint'] ?? ''); ?>">
                </div>

                <button type="submit" class="btn">
                    <i class="fas fa-cog"></i> Complete Setup
                </button>
            </form>
        <?php endif; ?>
    </div>
    
    <script>
        // Auto-populate API URL based on Base URL
        document.getElementById('base_url').addEventListener('input', function() {
            const baseUrl = this.value;
            if (baseUrl) {
                // You could add API URL field if needed
                console.log('Base URL set to:', baseUrl);
            }
        });
    </script>
</body>
</html>
