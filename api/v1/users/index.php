<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}

// Start output buffering to prevent PHP warnings/notices from corrupting JSON
ob_start();

// Enable error reporting for debugging (can be disabled in production)
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Initialize unified authentication
$unifiedAuth = new UnifiedAuth();

// Authenticate user (supports both session and API key)
if (!$unifiedAuth->authenticate()) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'UNAUTHORIZED',
            'message' => 'Authentication required'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

// Get authenticated user
$user = $unifiedAuth->getCurrentUser();

$db = DatabaseConfig::getInstance();
$method = $_SERVER['REQUEST_METHOD'];
$path = $_GET['path'] ?? '';

// Route requests and check permissions per method
try {
    switch ($method) {
        case 'GET':
            $unifiedAuth->requirePermission('users', 'read');
            handleGetRequest($path);
            break;
        case 'POST':
            $unifiedAuth->requirePermission('users', 'write');
            handlePostRequest($path);
            break;
        case 'PUT':
            $unifiedAuth->requirePermission('users', 'write');
            handlePutRequest($path);
            break;
        case 'DELETE':
            $unifiedAuth->requirePermission('users', 'write');
            handleDeleteRequest($path);
            break;
        default:
            ob_clean();
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            exit;
    }
} catch (Exception $e) {
    ob_clean();
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'INTERNAL_ERROR',
            'message' => 'Internal server error: ' . $e->getMessage()
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

function handleGetRequest($path) {
    global $db, $user;
    
    try {
        if (empty($path)) {
            // List all users
            listUsers();
        } else {
            // Get specific user
            getUser($path);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function listUsers() {
    global $db, $user;
    
    // Get query parameters
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = min(100, max(1, intval($_GET['limit'] ?? 25)));
    $search = $_GET['search'] ?? '';
    $role = $_GET['role'] ?? '';
    $is_active = $_GET['is_active'] ?? '';
    
    $offset = ($page - 1) * $limit;
    
    // Build query
    $where_conditions = [];
    $params = [];
    
    if (!empty($search)) {
        $where_conditions[] = "(username ILIKE :search OR email ILIKE :search)";
        $params[':search'] = "%$search%";
    }
    
    if (!empty($role)) {
        $where_conditions[] = "role = :role";
        $params[':role'] = $role;
    }
    
    if ($is_active !== '') {
        $where_conditions[] = "is_active = :is_active";
        $params[':is_active'] = $is_active === 'true' ? 'true' : 'false';
    }
    
    $where_clause = empty($where_conditions) ? '1=1' : implode(' AND ', $where_conditions);
    
    // Get total count
    $count_sql = "SELECT COUNT(*) as total FROM users WHERE $where_clause";
    $count_stmt = $db->prepare($count_sql);
    $count_stmt->execute($params);
    $total = $count_stmt->fetch()['total'];
    
    // Get users
    $sql = "SELECT 
        user_id,
        username,
        email,
        role,
        is_active,
        last_login,
        created_at,
        updated_at
        FROM users
        WHERE $where_clause
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    
    $stmt->execute();
    $users = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $users,
        'pagination' => [
            'page' => $page,
            'limit' => $limit,
            'total' => $total,
            'pages' => ceil($total / $limit)
        ],
        'timestamp' => date('c')
    ]);
}

function getUser($user_id) {
    global $db, $user;
    
    $sql = "SELECT 
        user_id,
        username,
        email,
        role,
        is_active,
        last_login,
        created_at,
        updated_at
        FROM users
        WHERE user_id = :user_id";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':user_id', $user_id);
    $stmt->execute();
    $user_data = $stmt->fetch();
    
    if (!$user_data) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'USER_NOT_FOUND',
                'message' => 'User not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'data' => $user_data,
        'timestamp' => date('c')
    ]);
}

function handlePostRequest($path) {
    global $db, $user;
    
    try {
        // Get JSON input
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_JSON',
                    'message' => 'Invalid JSON input'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        // Route based on action
        $action = $input['action'] ?? '';
        
        switch ($action) {
            case 'create_user':
                createUser($input);
                break;
            case 'update_user':
                updateUser($input);
                break;
            case 'reset_password':
                resetPassword($input);
                break;
            default:
                // Default to create user for backward compatibility
                createUser($input);
                break;
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function createUser($input = null) {
    global $db, $user;
    
    // Get JSON input if not provided
    if ($input === null) {
        $input = json_decode(file_get_contents('php://input'), true);
    }
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_JSON',
                'message' => 'Invalid JSON input'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Validate required fields
    $required_fields = ['username', 'email', 'password', 'role'];
    foreach ($required_fields as $field) {
        if (empty($input[$field])) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_FIELD',
                    'message' => "Field '$field' is required"
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    // Validate role
    $valid_roles = ['Admin', 'User'];
    if (!in_array($input['role'], $valid_roles)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_ROLE',
                'message' => 'Role must be Admin or User'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Validate password against current policy
    require_once __DIR__ . '/../../includes/security-settings.php';
    $securitySettings = new SecuritySettings();
    $passwordValidation = $securitySettings->validatePassword($input['password']);
    
    if (!$passwordValidation['valid']) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'PASSWORD_POLICY_VIOLATION',
                'message' => 'Password does not meet policy requirements',
                'details' => $passwordValidation['errors']
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Check if username already exists
    $check_sql = "SELECT user_id FROM users WHERE username = :username";
    $check_stmt = $db->prepare($check_sql);
    $check_stmt->bindValue(':username', $input['username']);
    $check_stmt->execute();
    
    if ($check_stmt->fetch()) {
        http_response_code(409);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'USERNAME_EXISTS',
                'message' => 'Username already exists'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Check if email already exists
    $check_sql = "SELECT user_id FROM users WHERE email = :email";
    $check_stmt = $db->prepare($check_sql);
    $check_stmt->bindValue(':email', $input['email']);
    $check_stmt->execute();
    
    if ($check_stmt->fetch()) {
        http_response_code(409);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'EMAIL_EXISTS',
                'message' => 'Email already exists'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Hash password
    $hashed_password = password_hash($input['password'], PASSWORD_DEFAULT);
    
    // Insert user
    $sql = "INSERT INTO users (
        username, email, password_hash, role, is_active, 
        created_at, updated_at
    ) VALUES (
        :username, :email, :password_hash, :role, :is_active,
        :created_at, :updated_at
    ) RETURNING user_id";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':username', $input['username']);
    $stmt->bindValue(':email', $input['email']);
    $stmt->bindValue(':password_hash', $hashed_password);
    $stmt->bindValue(':role', $input['role']);
    $stmt->bindValue(':is_active', $input['is_active'] ?? true);
    $stmt->bindValue(':created_at', date('Y-m-d H:i:s'));
    $stmt->bindValue(':updated_at', date('Y-m-d H:i:s'));
    
    $stmt->execute();
    $new_user_id = $stmt->fetch()['user_id'];
    
    echo json_encode([
        'success' => true,
        'data' => [
            'user_id' => $new_user_id,
            'username' => $input['username'],
            'email' => $input['email'],
            'role' => $input['role'],
            'message' => 'User created successfully'
        ],
        'timestamp' => date('c')
    ]);
}

function handlePutRequest($path) {
    global $db, $user;
    
    try {
        if (empty($path)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_USER_ID',
                    'message' => 'User ID is required'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        updateUser($path);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function updateUser($user_id) {
    global $db, $user;
    
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_JSON',
                'message' => 'Invalid JSON input'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Build update query
    $update_fields = [];
    $params = [':user_id' => $user_id];
    
    $allowed_fields = ['username', 'email', 'role', 'is_active'];
    
    foreach ($allowed_fields as $field) {
        if (isset($input[$field])) {
            $update_fields[] = "$field = :$field";
            $params[":$field"] = $input[$field];
        }
    }
    
    // Handle password update separately
    if (isset($input['password']) && !empty($input['password'])) {
        // Validate password against current policy
        require_once __DIR__ . '/../../includes/security-settings.php';
        $securitySettings = new SecuritySettings();
        $passwordValidation = $securitySettings->validatePassword($input['password']);
        
        if (!$passwordValidation['valid']) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'PASSWORD_POLICY_VIOLATION',
                    'message' => 'Password does not meet policy requirements',
                    'details' => $passwordValidation['errors']
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        $update_fields[] = "password_hash = :password_hash";
        $params[':password_hash'] = password_hash($input['password'], PASSWORD_DEFAULT);
    }
    
    if (empty($update_fields)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'NO_FIELDS_TO_UPDATE',
                'message' => 'No valid fields to update'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    $update_fields[] = "updated_at = :updated_at";
    $params[':updated_at'] = date('Y-m-d H:i:s');
    
    $sql = "UPDATE users SET " . implode(', ', $update_fields) . " WHERE user_id = :user_id";
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    
    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'USER_NOT_FOUND',
                'message' => 'User not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'data' => [
            'user_id' => $user_id,
            'message' => 'User updated successfully'
        ],
        'timestamp' => date('c')
    ]);
}

function handleDeleteRequest($path) {
    global $db, $user;
    
    // Clean output buffer before any output
    ob_clean();
    
    try {
        if (empty($path)) {
            ob_clean();
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_USER_ID',
                    'message' => 'User ID is required'
                ],
                'timestamp' => date('c')
            ]);
            exit;
        }
        
        // Validate user exists and is set
        if (!isset($user) || !is_array($user)) {
            ob_clean();
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'USER_NOT_LOADED',
                    'message' => 'User session not properly loaded'
                ],
                'timestamp' => date('c')
            ]);
            exit;
        }
        
        deleteUser($path);
        exit;
    } catch (Exception $e) {
        ob_clean();
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
        exit;
    } catch (Error $e) {
        ob_clean();
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'FATAL_ERROR',
                'message' => 'Fatal error: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine()
            ],
            'timestamp' => date('c')
        ]);
        exit;
    }
}

function deleteUser($user_id) {
    global $db, $user;
    
    // Clean output buffer before sending JSON
    ob_clean();
    
    try {
        // Prevent deleting self
        if ($user_id == $user['user_id']) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'CANNOT_DELETE_SELF',
                    'message' => 'Cannot delete your own account'
                ],
                'timestamp' => date('c')
            ]);
            exit;
        }
        
        // Soft delete - set is_active to false (cast UUID to ensure proper comparison)
        // First check if user exists and get current status
        $check_sql = "SELECT user_id, username, is_active FROM users WHERE user_id = :user_id::uuid";
        $check_stmt = $db->prepare($check_sql);
        $check_stmt->bindValue(':user_id', $user_id);
        $check_stmt->execute();
        $existing_user = $check_stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$existing_user) {
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'USER_NOT_FOUND',
                    'message' => 'User not found'
                ],
                'timestamp' => date('c')
            ]);
            exit;
        }
        
        // If already inactive, still return success (idempotent operation)
        if (!$existing_user['is_active']) {
            ob_clean();
            echo json_encode([
                'success' => true,
                'data' => [
                    'user_id' => $user_id,
                    'message' => 'User already deactivated'
                ],
                'timestamp' => date('c')
            ]);
            exit;
        }
        
        // Soft delete - set is_active to false
        // Use explicit UUID cast to ensure proper comparison
        $sql = "UPDATE users SET is_active = false, updated_at = :updated_at WHERE user_id = :user_id::uuid";
        
        $stmt = $db->prepare($sql);
        if (!$stmt) {
            throw new Exception('Failed to prepare SQL statement: ' . implode(', ', $db->errorInfo()));
        }
        
        $stmt->bindValue(':user_id', $user_id, PDO::PARAM_STR);
        $stmt->bindValue(':updated_at', date('Y-m-d H:i:s'), PDO::PARAM_STR);
        $result = $stmt->execute();
        
        if (!$result) {
            throw new Exception('Failed to execute SQL statement: ' . implode(', ', $stmt->errorInfo()));
        }
        
        $rows_affected = $stmt->rowCount();
        
        if ($rows_affected === 0) {
            // This shouldn't happen since we checked above, but handle it
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'UPDATE_FAILED',
                    'message' => 'User found but update failed to affect any rows'
                ],
                'timestamp' => date('c')
            ]);
            exit;
        }
        
        ob_clean();
        echo json_encode([
            'success' => true,
            'data' => [
                'user_id' => $user_id,
                'message' => 'User deleted successfully'
            ],
            'timestamp' => date('c')
        ]);
        exit;
    } catch (Exception $e) {
        ob_clean();
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'DELETE_ERROR',
                'message' => 'Failed to delete user: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
        exit;
    }
}

function resetPassword($input) {
    global $db, $user;
    
    // Validate required fields
    if (empty($input['user_id']) || empty($input['new_password'])) {
        http_response_code(400);
        ob_clean();
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'MISSING_FIELD',
                'message' => 'User ID and new password are required'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    $user_id = $input['user_id'];
    $new_password = $input['new_password'];
    
    // Validate password against policy
    require_once __DIR__ . '/../../../includes/security-settings.php';
    $securitySettings = new SecuritySettings();
    
    $validation_result = $securitySettings->validatePassword($new_password);
    if (!$validation_result['valid']) {
        http_response_code(400);
        ob_clean();
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'PASSWORD_POLICY_VIOLATION',
                'message' => 'Password does not meet policy requirements',
                'details' => $validation_result['errors']
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    try {
        // Hash the new password
        $password_hash = password_hash($new_password, PASSWORD_DEFAULT);
        
        // Update password in database
        $stmt = $db->prepare("UPDATE users SET password_hash = ?, updated_at = NOW() WHERE user_id = ?");
        $result = $stmt->execute([$password_hash, $user_id]);
        
        if ($result && $stmt->rowCount() > 0) {
            // Log the password reset event
            require_once __DIR__ . '/../../../includes/security-audit.php';
            $securityAudit = new SecurityAudit();
            $securityAudit->logEvent('password_reset', $user['user_id'], 'Password reset by admin', [
                'target_user_id' => $user_id,
                'admin_user_id' => $user['user_id'],
                'admin_username' => $user['username']
            ]);
            
            // Clean output buffer and send JSON response
            ob_clean();
            echo json_encode([
                'success' => true,
                'data' => [
                    'user_id' => $user_id,
                    'message' => 'Password reset successfully'
                ],
                'timestamp' => date('c')
            ]);
        } else {
            http_response_code(404);
            ob_clean();
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'USER_NOT_FOUND',
                    'message' => 'User not found'
                ],
                'timestamp' => date('c')
            ]);
        }
    } catch (Exception $e) {
        http_response_code(500);
        ob_clean();
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'DATABASE_ERROR',
                'message' => 'Failed to reset password: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}
?>
