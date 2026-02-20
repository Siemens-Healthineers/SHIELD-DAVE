<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Security check
if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}

require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';
require_once __DIR__ . '/../../../includes/functions.php';

// Set JSON response header
header('Content-Type: application/json');

// Initialize authentication
$auth = new Auth();
$auth->requireAuth();
$auth->requireRole('Admin');

$method = $_SERVER['REQUEST_METHOD'];
$response = ['success' => false, 'message' => '', 'data' => null];

try {
    switch ($method) {
        case 'GET':
            // Get current configuration
            $config = EnvConfig::getPublicConfig();
            $response = [
                'success' => true,
                'message' => 'Configuration retrieved successfully',
                'data' => $config
            ];
            break;
            
        case 'POST':
            // Update configuration
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (!$input) {
                throw new Exception('Invalid JSON input');
            }
            
            // Validate required fields
            $required = ['base_url', 'db_host', 'db_name', 'db_user', 'db_password'];
            foreach ($required as $field) {
                if (empty($input[$field])) {
                    throw new Exception("Required field missing: $field");
                }
            }
            
            // Validate URLs
            if (!filter_var($input['base_url'], FILTER_VALIDATE_URL)) {
                throw new Exception('Invalid base URL format');
            }
            
            // Validate email if provided
            if (!empty($input['from_email']) && !filter_var($input['from_email'], FILTER_VALIDATE_EMAIL)) {
                throw new Exception('Invalid email address format');
            }
            
            // Update configuration
            $config = [
                'base_url' => $input['base_url'],
                'api_url' => $input['api_url'] ?? $input['base_url'] . '/api',
                'debug' => $input['debug'] ?? false,
                'db_host' => $input['db_host'],
                'db_port' => $input['db_port'] ?? '5432',
                'db_name' => $input['db_name'],
                'db_user' => $input['db_user'],
                'db_password' => $input['db_password'],
                'smtp_host' => $input['smtp_host'] ?? 'localhost',
                'smtp_port' => $input['smtp_port'] ?? '587',
                'smtp_username' => $input['smtp_username'] ?? '',
                'smtp_password' => $input['smtp_password'] ?? '',
                'smtp_encryption' => $input['smtp_encryption'] ?? 'tls',
                'from_email' => $input['from_email'] ?? '',
                'from_name' => $input['from_name'] ?? ' System',
                'session_domain' => $input['session_domain'] ?? '',
                'cookie_domain' => $input['cookie_domain'] ?? '',
                'session_lifetime' => $input['session_lifetime'] ?? '3600',
                'max_login_attempts' => $input['max_login_attempts'] ?? '5',
                'lockout_duration' => $input['lockout_duration'] ?? '900',
                'openfda_api_key' => $input['openfda_api_key'] ?? '',
                'nvd_api_key' => $input['nvd_api_key'] ?? '',
                'maxmind_api_key' => $input['maxmind_api_key'] ?? '',
                'maxmind_account_id' => $input['maxmind_account_id'] ?? '',
                'max_upload_size' => $input['max_upload_size'] ?? '52428800',
                'upload_dir' => $input['upload_dir'] ?? '',
                'temp_dir' => $input['temp_dir'] ?? '',
                'log_level' => $input['log_level'] ?? 'INFO',
                'log_file' => $input['log_file'] ?? '',
                'log_max_size' => $input['log_max_size'] ?? '10485760',
                'log_max_files' => $input['log_max_files'] ?? '5',
                'cache_enabled' => $input['cache_enabled'] ?? false,
                'cache_dir' => $input['cache_dir'] ?? '',
                'cache_lifetime' => $input['cache_lifetime'] ?? '3600'
            ];
            
            // Validate configuration
            $errors = EnvConfig::validate();
            if (!empty($errors)) {
                throw new Exception('Configuration validation failed: ' . implode(', ', $errors));
            }
            
            // Save configuration
            if (EnvConfig::saveToEnvFile($config)) {
                $response = [
                    'success' => true,
                    'message' => 'Configuration saved successfully',
                    'data' => EnvConfig::getPublicConfig()
                ];
            } else {
                throw new Exception('Failed to save configuration file');
            }
            break;
            
        case 'PUT':
            // Validate configuration without saving
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (!$input) {
                throw new Exception('Invalid JSON input');
            }
            
            // Test database connection
            try {
                $pdo = new PDO(
                    "pgsql:host=" . $input['db_host'] . ";port=" . ($input['db_port'] ?? '5432') . ";dbname=" . $input['db_name'],
                    $input['db_user'],
                    $input['db_password']
                );
                $response = [
                    'success' => true,
                    'message' => 'Configuration validation successful',
                    'data' => ['database_connection' => 'success']
                ];
            } catch (PDOException $e) {
                throw new Exception('Database connection failed: ' . $e->getMessage());
            }
            break;
            
        default:
            throw new Exception('Method not allowed');
    }
    
} catch (Exception $e) {
    $response = [
        'success' => false,
        'message' => $e->getMessage(),
        'data' => null
    ];
    http_response_code(400);
}

echo json_encode($response, JSON_PRETTY_PRINT);

