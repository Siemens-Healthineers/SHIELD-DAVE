<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/


if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}

// Start output buffering to prevent any output before JSON
ob_start();

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 0); // Don't display errors in response
ini_set('log_errors', 1); // Log errors instead

require_once __DIR__ . '/../../../../config/config.php';

// Set JSON content type after config is loaded
header('Content-Type: application/json');
require_once __DIR__ . '/../../../../includes/auth.php';
require_once __DIR__ . '/../../../../includes/security-settings.php';
require_once __DIR__ . '/../../../../includes/security-audit.php';
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Initialize authentication
$auth = new Auth();
$auth->requireAuth();

// Check if user has admin privileges
$user = $_SESSION['user'] ?? [];
if (!isset($user['role']) || strtolower($user['role']) !== 'admin') {
    http_response_code(403);
    echo json_encode(['error' => 'Admin access required']);
    exit();
}

// Initialize services
$securitySettings = new SecuritySettings();
$securityAudit = new SecurityAudit();

// Get request method and path
$method = $_SERVER['REQUEST_METHOD'];
$path = $_SERVER['PATH_INFO'] ?? '';
$action = $_GET['action'] ?? '';

// For GET requests, also check action parameter if PATH_INFO is empty
if ($method === 'GET' && empty($path) && !empty($action)) {
    $path = '/' . $action;
}

// Wrap everything in try-catch to ensure JSON response
try {
    switch ($method) {
        case 'GET':
            handleGetRequest($securitySettings, $path);
            break;
        case 'POST':
            // Check for action parameter first, then fall back to path
            if ($action) {
                handlePostRequest($securitySettings, $securityAudit, '/' . $action);
            } else {
                handlePostRequest($securitySettings, $securityAudit, $path);
            }
            break;
        case 'PUT':
            handlePutRequest($securitySettings, $securityAudit, $path);
            break;
        default:
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            break;
    }
} catch (Exception $e) {
    error_log("Security Settings API Error: " . $e->getMessage());
    error_log("Stack trace: " . $e->getTraceAsString());
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error: ' . $e->getMessage()]);
} catch (Error $e) {
    error_log("Security Settings API Fatal Error: " . $e->getMessage());
    error_log("Stack trace: " . $e->getTraceAsString());
    http_response_code(500);
    echo json_encode(['error' => 'Fatal error: ' . $e->getMessage()]);
}

/**
 * Handle GET requests
 */
function handleGetRequest($securitySettings, $path) {
    switch ($path) {
        case '':
        case '/':
            // Get all security settings
            $settings = $securitySettings->getAllSettings();
            echo json_encode([
                'success' => true,
                'data' => $settings
            ]);
            break;
            
        case '/password-policy':
            // Get password policy settings
            $policy = $securitySettings->getPasswordPolicy();
            echo json_encode([
                'success' => true,
                'data' => $policy
            ]);
            break;
            
        case '/authentication':
            // Get authentication settings
            $authSettings = $securitySettings->getAuthenticationSettings();
            echo json_encode([
                'success' => true,
                'data' => $authSettings
            ]);
            break;
            
        case '/monitoring':
            // Get monitoring settings
            $monitoringSettings = $securitySettings->getMonitoringSettings();
            echo json_encode([
                'success' => true,
                'data' => $monitoringSettings
            ]);
            break;
            
        case '/system':
            // Get system security settings
            $systemSettings = $securitySettings->getSystemSecuritySettings();
            echo json_encode([
                'success' => true,
                'data' => $systemSettings
            ]);
            break;
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

/**
 * Handle POST requests
 */
function handlePostRequest($securitySettings, $securityAudit, $path) {
    $input = json_decode(file_get_contents('php://input'), true);
    
    // Debug logging
    error_log("Password policy API - Path: " . $path);
    error_log("Password policy API - Input: " . print_r($input, true));
    
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON input']);
        return;
    }
    
    $userId = $_SESSION['user']['id'] ?? null;
    
    switch ($path) {
        case '/update':
            // Update multiple settings
            $success = true;
            $updated = [];
            $errors = [];
            
            foreach ($input as $key => $value) {
                if ($securitySettings->updateSetting($key, $value, $userId)) {
                    $updated[] = $key;
                } else {
                    $success = false;
                    $errors[] = "Failed to update setting: {$key}";
                }
            }
            
            // Log the changes
            if (!empty($updated)) {
                $securityAudit->logAdminAction(
                    'security_settings_update',
                    $userId,
                    'Multiple settings',
                    ['updated_settings' => $updated]
                );
            }
            
            echo json_encode([
                'success' => $success,
                'updated' => $updated,
                'errors' => $errors
            ]);
            break;
            
        case '/password-policy':
            // Update password policy
            if ($securitySettings->updatePasswordPolicy($input, $userId)) {
                $securityAudit->logAdminAction(
                    'password_policy_update',
                    $userId,
                    'Password policy',
                    $input
                );
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Password policy updated successfully'
                ]);
            } else {
                http_response_code(500);
                echo json_encode([
                    'success' => false,
                    'error' => 'Failed to update password policy'
                ]);
            }
            break;
            
        case '/validate-password':
            // Validate password against current policy
            $password = $input['password'] ?? '';
            $validation = $securitySettings->validatePassword($password);
            
            echo json_encode([
                'success' => true,
                'data' => $validation
            ]);
            break;
            
        case '/test':
            // Simple test endpoint
            echo json_encode([
                'success' => true,
                'message' => 'API is working',
                'timestamp' => date('c'),
                'path' => $path
            ]);
            break;
            
        default:
            error_log("Password policy API - Unknown path: " . $path);
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found: ' . $path]);
            break;
    }
}

/**
 * Handle PUT requests
 */
function handlePutRequest($securitySettings, $securityAudit, $path) {
    $userId = $_SESSION['user']['id'] ?? null;
    
    switch ($path) {
        case '/reset-defaults':
            // Reset all settings to defaults
            if ($securitySettings->resetToDefaults($userId)) {
                $securityAudit->logAdminAction(
                    'security_settings_reset',
                    $userId,
                    'All settings',
                    ['action' => 'reset_to_defaults']
                );
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Settings reset to defaults successfully'
                ]);
            } else {
                http_response_code(500);
                echo json_encode([
                    'success' => false,
                    'error' => 'Failed to reset settings'
                ]);
            }
            break;
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

