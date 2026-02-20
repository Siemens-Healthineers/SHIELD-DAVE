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

// Require authentication and admin permission
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

// Check if user has admin role
if (strtolower($user['role']) !== 'admin') {
    header('Location: /pages/dashboard.php');
    exit;
}

$db = DatabaseConfig::getInstance();
$error = '';
$success = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'add_user':
            $username = trim($_POST['username'] ?? '');
            $email = trim($_POST['email'] ?? '');
            $password = $_POST['password'] ?? '';
            $role = $_POST['role'] ?? 'User';
            
            if (empty($username) || empty($email) || empty($password)) {
                $error = 'All fields are required';
            } else {
                // Validate password against policy
                require_once __DIR__ . '/../../includes/security-settings.php';
                $securitySettings = new SecuritySettings();
                $validation = $securitySettings->validatePassword($password);
                
                if (!$validation['valid']) {
                    $error = 'Password does not meet requirements: ' . implode(', ', $validation['errors']);
                } else {
                    try {
                        // Check if username already exists
                        $check_stmt = $db->prepare("SELECT user_id FROM users WHERE username = :username");
                        $check_stmt->bindValue(':username', $username);
                        $check_stmt->execute();
                        
                        if ($check_stmt->fetch()) {
                            $error = 'Username already exists';
                        } else {
                            // Check if email already exists
                            $check_stmt = $db->prepare("SELECT user_id FROM users WHERE email = :email");
                            $check_stmt->bindValue(':email', $email);
                            $check_stmt->execute();
                            
                            if ($check_stmt->fetch()) {
                                $error = 'Email already exists';
                            } else {
                                // Hash password and create user
                                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                                
                                $stmt = $db->prepare("INSERT INTO users (
                                    username, email, password_hash, role, is_active, 
                                    created_at, updated_at
                                ) VALUES (
                                    :username, :email, :password_hash, :role, :is_active,
                                    :created_at, :updated_at
                                ) RETURNING user_id");
                                
                                $stmt->bindValue(':username', $username);
                                $stmt->bindValue(':email', $email);
                                $stmt->bindValue(':password_hash', $hashed_password);
                                $stmt->bindValue(':role', $role);
                                $stmt->bindValue(':is_active', true);
                                $stmt->bindValue(':created_at', date('Y-m-d H:i:s'));
                                $stmt->bindValue(':updated_at', date('Y-m-d H:i:s'));
                                
                                $stmt->execute();
                                $new_user_id = $stmt->fetch()['user_id'];
                                
                                $success = 'User created successfully';
                            }
                        }
                    } catch (Exception $e) {
                        $error = 'Failed to create user: ' . $e->getMessage();
                    }
                }
            }
            break;
            
        case 'delete_user':
            $userId = $_POST['user_id'] ?? '';
            
            if (empty($userId)) {
                $error = 'User ID is required';
            } else {
                try {
                    // Soft delete user by setting is_active to false
                    $stmt = $db->prepare("UPDATE users SET is_active = false, updated_at = :updated_at WHERE user_id = :user_id");
                    $stmt->bindValue(':user_id', $userId);
                    $stmt->bindValue(':updated_at', date('Y-m-d H:i:s'));
                    $stmt->execute();
                    
                    if ($stmt->rowCount() > 0) {
                        $success = 'User deleted successfully';
                        // Redirect to avoid resubmission
                        header('Location: /pages/admin/users.php?success=user_deleted');
                        exit;
                    } else {
                        $error = 'User not found';
                    }
                } catch (Exception $e) {
                    $error = 'Failed to delete user: ' . $e->getMessage();
                }
            }
            break;
    }
}

// Get all users
$users = [];
try {
    $stmt = $db->query("SELECT user_id, username, email, role, is_active, last_login, created_at FROM users WHERE is_active = true ORDER BY created_at DESC");
    $users = $stmt->fetchAll();
} catch (Exception $e) {
    $error = 'Failed to load users: ' . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - </title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Password Requirements Styling - Siemens Healthineers Brand Compliant */
        .password-requirements {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-secondary);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 0.5rem;
            font-size: 0.875rem;
        }
        
        .password-requirements h4 {
            margin: 0 0 0.5rem 0;
            color: var(--text-primary);
            font-size: 0.875rem;
            font-weight: var(--font-weight-semibold);
        }
        
        .password-requirements ul {
            margin: 0;
            padding-left: 1.25rem;
        }
        
        .password-requirements li {
            margin-bottom: 0.25rem;
            transition: color 0.2s ease;
        }
        
        .password-requirements li.valid {
            color: var(--success-green);
        }
        
        .password-requirements li.invalid {
            color: var(--error-red);
        }
        
        .password-requirements li.optional {
            color: var(--text-muted);
        }
        
        .password-requirements li.required {
            font-weight: var(--font-weight-semibold);
        }
        
        .error-message {
            font-size: 0.85rem;
            font-weight: var(--font-weight-medium);
            color: var(--error-red);
        }

        /* User Actions Styling */
        .user-actions {
            display: flex;
            gap: 8px;
        }

        .user-actions .btn {
            padding: 8px 12px;
            font-size: 0.875rem;
        }

        /* Role and Status Badges */
        .role-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: var(--font-weight-semibold);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .role-badge.admin {
            background: rgba(0, 153, 153, 0.1);
            color: var(--siemens-petrol);
            border: 1px solid var(--siemens-petrol);
        }

        .role-badge.user {
            background: rgba(107, 114, 128, 0.1);
            color: var(--text-secondary);
            border: 1px solid var(--border-secondary);
        }

        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: var(--font-weight-semibold);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .status-badge.active {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success-green);
            border: 1px solid var(--success-green);
        }

        .status-badge.inactive {
            background: rgba(239, 68, 68, 0.1);
            color: var(--error-red);
            border: 1px solid var(--error-red);
        }

        /* Table Styling */
        .table-responsive {
            overflow-x: auto;
        }

        .table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
        }

        .table th {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            font-weight: var(--font-weight-semibold);
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-primary);
        }

        .table td {
            padding: 1rem;
            border-bottom: 1px solid var(--border-secondary);
            color: var(--text-primary);
        }

        .table tbody tr:hover {
            background: var(--bg-hover);
        }

        /* Modal Footer Styling */
        .modal-footer {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid var(--border-primary);
        }

        /* Alert Styling */
        .alert {
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: var(--font-weight-medium);
        }

        .alert-error {
            background: rgba(239, 68, 68, 0.1);
            color: var(--error-red);
            border: 1px solid var(--error-red);
        }

        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success-green);
            border: 1px solid var(--success-green);
        }

        /* Button Size Variants */
        .btn-sm {
            padding: 6px 12px;
            font-size: 0.875rem;
        }

        .btn-error {
            background-color: var(--error-red);
            color: white;
            border: 1px solid var(--error-red);
        }

        .btn-error:hover {
            background-color: #dc2626;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
        }

        /* Notification Styling */
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 1001;
            display: flex;
            align-items: center;
            gap: 10px;
            min-width: 300px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            animation: slideIn 0.3s ease;
        }

        .notification-success {
            background: var(--success-green);
            border: 1px solid var(--success-green);
        }

        .notification-error {
            background: var(--error-red);
            border: 1px solid var(--error-red);
        }

        .notification-info {
            background: var(--siemens-petrol);
            border: 1px solid var(--siemens-petrol);
        }

        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        /* Content Width Constraint */
        .main-content {
            max-width: 1440px;
            margin: 0 auto;
            padding: 0 20px;
        }

        @media (max-width: 1460px) {
            .main-content {
                padding: 0 15px;
            }
        }

        @media (max-width: 768px) {
            .main-content {
                padding: 0 10px;
            }
        }
    </style>
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>
    
    <div class="main-content">
        <div class="page-header">
            <div class="page-title">
                <h1><i class="fas fa-users"></i> User Management</h1>
                <p>Manage system users, roles, and permissions</p>
            </div>
            <div class="page-actions">
                <button class="btn btn-primary" onclick="showAddUserModal()">
                    <i class="fas fa-plus"></i> Add User
                </button>
            </div>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i>
                <?php echo dave_htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <?php echo dave_htmlspecialchars($success); ?>
            </div>
        <?php endif; ?>

        <!-- Users Table -->
        <div class="form-section">
            <h2><i class="fas fa-users"></i> System Users</h2>
            <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Last Login</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user_data): ?>
                            <tr>
                                <td><?php echo dave_htmlspecialchars($user_data['username']); ?></td>
                                <td><?php echo dave_htmlspecialchars($user_data['email']); ?></td>
                                <td>
                                    <span class="role-badge role-<?php echo strtolower($user_data['role']); ?>">
                                        <?php echo dave_htmlspecialchars($user_data['role']); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="status-badge status-<?php echo $user_data['is_active'] ? 'active' : 'inactive'; ?>">
                                        <?php echo $user_data['is_active'] ? 'Active' : 'Inactive'; ?>
                                    </span>
                                </td>
                                <td>
                                    <?php 
                                    if ($user_data['last_login']) {
                                        echo date('M j, Y g:i A', strtotime($user_data['last_login']));
                                    } else {
                                        echo 'Never';
                                    }
                                    ?>
                                </td>
                                <td>
                                    <div class="user-actions">
                                        <button class="btn btn-sm btn-secondary" onclick="editUser('<?php echo dave_htmlspecialchars($user_data['user_id']); ?>')" title="Edit User">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                        <button class="btn btn-sm btn-accent" onclick="resetPassword('<?php echo dave_htmlspecialchars($user_data['user_id']); ?>', '<?php echo dave_htmlspecialchars($user_data['username']); ?>')" title="Reset Password">
                                            <i class="fas fa-key"></i>
                                        </button>
                                        <?php if ($user_data['user_id'] != $user['user_id']): ?>
                                            <button class="btn btn-sm btn-error" onclick="deleteUser('<?php echo dave_htmlspecialchars($user_data['user_id']); ?>')" title="Delete User">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Add User Modal -->
    <div id="addUserModal" class="modal-overlay" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-user-plus"></i> Add New User</h3>
                <button class="modal-close" onclick="closeModal('addUserModal')">&times;</button>
            </div>
            <form method="POST" action="" id="addUserForm">
                <input type="hidden" name="action" value="add_user">
                <div class="modal-body">
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="username">Username</label>
                            <input type="text" id="username" name="username" required>
                        </div>
                        <div class="form-group">
                            <label for="email">Email</label>
                            <input type="email" id="email" name="email" required>
                        </div>
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" required oninput="validatePassword()">
                            <div id="password-requirements" class="password-requirements" style="display: none;">
                                <h4>Password Requirements:</h4>
                                <ul id="password-requirements-list">
                                    <!-- Requirements will be populated by JavaScript -->
                                </ul>
                            </div>
                            <div id="password-error" class="error-message" style="display: none; color: #ef4444; margin-top: 0.5rem;">
                                <!-- Error message will be shown here -->
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="role">Role</label>
                            <select id="role" name="role" required>
                                <option value="">Select Role</option>
                                <option value="Admin">Admin</option>
                                <option value="User">User</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('addUserModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Add User</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Edit User Modal -->
    <div id="editUserModal" class="modal-overlay" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-user-edit"></i> Edit User</h3>
                <button class="modal-close" onclick="closeModal('editUserModal')">&times;</button>
            </div>
            <form method="POST" action="" id="editUserForm">
                <input type="hidden" name="action" value="update_user">
                <input type="hidden" name="user_id" id="edit_user_id">
                <div class="modal-body">
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="edit_username">Username</label>
                            <input type="text" id="edit_username" name="username" required>
                        </div>
                        <div class="form-group">
                            <label for="edit_email">Email</label>
                            <input type="email" id="edit_email" name="email" required>
                        </div>
                        <div class="form-group">
                            <label for="edit_role">Role</label>
                            <select id="edit_role" name="role" required>
                                <option value="Admin">Admin</option>
                                <option value="User">User</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="edit_is_active">Status</label>
                            <select id="edit_is_active" name="is_active" required>
                                <option value="1">Active</option>
                                <option value="0">Inactive</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('editUserModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Update User</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Reset Password Modal -->
    <div id="resetPasswordModal" class="modal-overlay" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-key"></i> Reset Password</h3>
                <button class="modal-close" onclick="closeModal('resetPasswordModal')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <form id="resetPasswordForm">
                <input type="hidden" id="resetUserId" name="user_id">
                <div class="form-group">
                    <label for="resetUsername">Username:</label>
                    <input type="text" id="resetUsername" name="username" readonly class="form-control" style="background: var(--bg-tertiary); color: var(--text-muted);">
                </div>
                <div class="form-group">
                    <label for="newPassword">New Password:</label>
                    <input type="password" id="newPassword" name="new_password" class="form-control" required>
                    <div class="password-requirements" id="resetPasswordRequirements" style="display: none;">
                        <h4>Password Requirements:</h4>
                        <ul id="resetPasswordRequirementsList"></ul>
                    </div>
                    <div class="error-message" id="resetPasswordError" style="display: none;"></div>
                </div>
                <div class="form-group">
                    <label for="confirmPassword">Confirm Password:</label>
                    <input type="password" id="confirmPassword" name="confirm_password" class="form-control" required>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('resetPasswordModal')">Cancel</button>
                    <button type="submit" class="btn btn-accent">Reset Password</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        // Global variables
        let passwordPolicy = null;
        let isPasswordValid = false;

        // Load password policy on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadPasswordPolicy();
        });

        // Load password policy from API
        async function loadPasswordPolicy() {
            try {
                const response = await fetch('/api/v1/admin/security/settings.php?action=password-policy', {
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    if (data.success && data.data) {
                        passwordPolicy = {
                            min_length: parseInt(data.data.min_length) || 8,
                            require_uppercase: data.data.require_uppercase === true || data.data.require_uppercase === '1',
                            require_lowercase: data.data.require_lowercase === true || data.data.require_lowercase === '1',
                            require_numbers: data.data.require_numbers === true || data.data.require_numbers === '1',
                            require_special: data.data.require_special === true || data.data.require_special === '1'
                        };
                        displayPasswordRequirements();
                    }
                }
            } catch (error) {
                console.error('Error loading password policy:', error);
                // Use default policy
                passwordPolicy = {
                    min_length: 8,
                    require_uppercase: true,
                    require_lowercase: true,
                    require_numbers: true,
                    require_special: true
                };
                displayPasswordRequirements();
            }
        }

        // Display password requirements
        function displayPasswordRequirements(targetListId = 'password-requirements-list', password = '') {
            if (!passwordPolicy) return;
            
            const requirementsDiv = document.getElementById('password-requirements');
            const requirementsList = document.getElementById(targetListId);
            
            const minLength = passwordPolicy.min_length || 8;
            const requireUppercase = passwordPolicy.require_uppercase !== false;
            const requireLowercase = passwordPolicy.require_lowercase !== false;
            const requireNumbers = passwordPolicy.require_numbers !== false;
            const requireSpecial = passwordPolicy.require_special !== false;
            
            requirementsList.innerHTML = `
                <li id="req-length">At least ${minLength} characters</li>
                <li id="req-uppercase" class="${requireUppercase ? 'required' : 'optional'}">One uppercase letter ${requireUppercase ? '(required)' : '(optional)'}</li>
                <li id="req-lowercase" class="${requireLowercase ? 'required' : 'optional'}">One lowercase letter ${requireLowercase ? '(required)' : '(optional)'}</li>
                <li id="req-numbers" class="${requireNumbers ? 'required' : 'optional'}">One number ${requireNumbers ? '(required)' : '(optional)'}</li>
                <li id="req-special" class="${requireSpecial ? 'required' : 'optional'}">One special character ${requireSpecial ? '(required)' : '(optional)'}</li>
            `;
        }

        // Validate password in real-time
        function validatePassword(password = null, requirementsDivId = 'password-requirements', errorDivId = 'password-error') {
            if (password === null) {
                password = document.getElementById('password').value;
            }
            const requirementsDiv = document.getElementById(requirementsDivId);
            const errorDiv = document.getElementById(errorDivId);
            
            if (!passwordPolicy) {
                loadPasswordPolicy();
                return;
            }

            if (password.length > 0) {
                requirementsDiv.style.display = 'block';
            } else {
                requirementsDiv.style.display = 'none';
                errorDiv.style.display = 'none';
                isPasswordValid = false;
                return;
            }

            const minLength = passwordPolicy.min_length || 8;
            const requireUppercase = passwordPolicy.require_uppercase !== false;
            const requireLowercase = passwordPolicy.require_lowercase !== false;
            const requireNumbers = passwordPolicy.require_numbers !== false;
            const requireSpecial = passwordPolicy.require_special !== false;

            const errors = [];
            
            // Check minimum length
            const lengthValid = password.length >= minLength;
            const lengthElement = document.getElementById('req-length');
            if (lengthElement) lengthElement.className = lengthValid ? 'valid' : 'invalid';
            if (!lengthValid) {
                errors.push(`Password must be at least ${minLength} characters long`);
            }

            // Check uppercase
            const uppercaseValid = /[A-Z]/.test(password);
            const uppercaseClass = uppercaseValid ? 'valid' : (requireUppercase ? 'invalid' : 'optional');
            const uppercaseElement = document.getElementById('req-uppercase');
            if (uppercaseElement) uppercaseElement.className = `required ${uppercaseClass}`;
            if (requireUppercase && !uppercaseValid) {
                errors.push('Password must contain at least one uppercase letter');
            }

            // Check lowercase
            const lowercaseValid = /[a-z]/.test(password);
            const lowercaseClass = lowercaseValid ? 'valid' : (requireLowercase ? 'invalid' : 'optional');
            const lowercaseElement = document.getElementById('req-lowercase');
            if (lowercaseElement) lowercaseElement.className = `required ${lowercaseClass}`;
            if (requireLowercase && !lowercaseValid) {
                errors.push('Password must contain at least one lowercase letter');
            }

            // Check numbers
            const numbersValid = /\d/.test(password);
            const numbersClass = numbersValid ? 'valid' : (requireNumbers ? 'invalid' : 'optional');
            const numbersElement = document.getElementById('req-numbers');
            if (numbersElement) numbersElement.className = `required ${numbersClass}`;
            if (requireNumbers && !numbersValid) {
                errors.push('Password must contain at least one number');
            }

            // Check special characters
            const specialValid = /[^A-Za-z0-9]/.test(password);
            const specialClass = specialValid ? 'valid' : (requireSpecial ? 'invalid' : 'optional');
            const specialElement = document.getElementById('req-special');
            if (specialElement) specialElement.className = `required ${specialClass}`;
            if (requireSpecial && !specialValid) {
                errors.push('Password must contain at least one special character');
            }

            isPasswordValid = errors.length === 0;
            
            console.log('Password validation errors:', errors);
            console.log('isPasswordValid:', isPasswordValid);
            
            if (errors.length > 0) {
                errorDiv.textContent = errors.join(', ');
                errorDiv.style.display = 'block';
            } else {
                errorDiv.style.display = 'none';
            }
            
            return isPasswordValid;
        }

        // Modal functions
        function showAddUserModal() {
            document.getElementById('addUserModal').style.display = 'flex';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        // Reset Password Functions
        function resetPassword(userId, username) {
            document.getElementById('resetUserId').value = userId;
            document.getElementById('resetUsername').value = username;
            document.getElementById('newPassword').value = '';
            document.getElementById('confirmPassword').value = '';
            document.getElementById('resetPasswordRequirements').style.display = 'none';
            document.getElementById('resetPasswordError').style.display = 'none';
            
            // Load password requirements for reset password modal
            if (passwordPolicy) {
                displayPasswordRequirements('resetPasswordRequirementsList');
            } else {
                loadPasswordPolicy();
            }
            
            showModal('resetPasswordModal');
        }

        // Show modal
        function showModal(modalId) {
            document.getElementById(modalId).style.display = 'flex';
        }

        // Edit user function
        async function editUser(userId) {
            console.log('Edit user clicked with ID:', userId);
            
            try {
                const modal = document.getElementById('editUserModal');
                modal.style.display = 'flex';
                
                const response = await fetch(`/api/v1/users/index.php?path=${userId}`, {
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    if (data.success && data.data) {
                        const user = data.data;
                        
                        document.getElementById('edit_user_id').value = user.user_id;
                        document.getElementById('edit_username').value = user.username || '';
                        document.getElementById('edit_email').value = user.email || '';
                        document.getElementById('edit_role').value = user.role || 'User';
                        document.getElementById('edit_is_active').value = user.is_active ? '1' : '0';
                        
                        console.log('User data loaded for editing:', user);
                    } else {
                        console.error('Error loading user data:', data.message);
                        alert('Error loading user data: ' + (data.message || 'Unknown error'));
                        modal.style.display = 'none';
                    }
                } else {
                    console.error('Failed to fetch user data:', response.status, response.statusText);
                    alert('Failed to load user data. Please try again.');
                    modal.style.display = 'none';
                }
            } catch (error) {
                console.error('Error fetching user data:', error);
                alert('Error loading user data: ' + error.message);
                document.getElementById('editUserModal').style.display = 'none';
            }
        }

        // Helper function to escape HTML
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Delete user function
        function deleteUser(userId) {
            // Get user info for display
            const row = document.querySelector(`[onclick*="deleteUser('${userId}')"]`).closest('tr');
            const username = row ? row.querySelector('td:nth-child(1)')?.textContent?.trim() || 'this user' : 'this user';
            const email = row ? row.querySelector('td:nth-child(2)')?.textContent?.trim() || '' : '';
            
            // Create confirmation modal
            const modal = document.createElement('div');
            modal.id = 'user-deletion-confirmation-modal';
            modal.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0, 0, 0, 0.8);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 1000;
            `;
            
            modal.innerHTML = `
                <div style="
                    background: var(--bg-card, #1a1a1a);
                    border: 1px solid var(--border-primary, #333333);
                    border-radius: 0.75rem;
                    max-width: 500px;
                    width: 90%;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
                ">
                    <div style="
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 1.5rem;
                        border-bottom: 1px solid var(--border-primary, #333333);
                    ">
                        <h3 style="margin: 0; color: var(--text-primary, #ffffff); font-size: 1.25rem; font-weight: 600;">
                            Confirm User Deletion
                        </h3>
                        <button onclick="document.getElementById('user-deletion-confirmation-modal').remove()" style="
                            background: transparent;
                            border: none;
                            color: var(--text-secondary, #cbd5e1);
                            font-size: 1.5rem;
                            cursor: pointer;
                            padding: 0.5rem;
                            line-height: 1;
                        ">×</button>
                    </div>
                    <div style="padding: 1.5rem;">
                        <div style="margin-bottom: 1.5rem;">
                            <div style="
                                display: flex;
                                align-items: center;
                                gap: 1rem;
                                margin-bottom: 1rem;
                            ">
                                <i class="fas fa-exclamation-triangle" style="
                                    font-size: 2rem;
                                    color: var(--error-red, #ef4444);
                                "></i>
                                <div>
                                    <p style="margin: 0; color: var(--text-primary, #ffffff); font-weight: 500;">
                                        Are you sure you want to delete <strong>${escapeHtml(username)}</strong>?
                                    </p>
                                    ${email ? `<p style="margin: 0.25rem 0 0 0; color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">${escapeHtml(email)}</p>` : ''}
                                    <p style="margin: 1rem 0 0 0; color: var(--text-secondary, #cbd5e1);">
                                        This action will deactivate the user account. This action cannot be undone.
                                    </p>
                                </div>
                            </div>
                        </div>
                        <div style="display: flex; gap: 0.75rem; justify-content: flex-end;">
                            <button onclick="document.getElementById('user-deletion-confirmation-modal').remove()" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--bg-secondary, #0f0f0f);
                                color: var(--text-secondary, #cbd5e1);
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                                font-family: 'Siemens Sans', 'Inter', sans-serif;
                            ">Cancel</button>
                            <button onclick="confirmDeleteUser('${userId}')" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--error-red, #ef4444);
                                color: white;
                                border: none;
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                                font-family: 'Siemens Sans', 'Inter', sans-serif;
                            ">Delete User</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
        }
        
        // Confirm delete user function
        async function confirmDeleteUser(userId) {
            // Close the deletion confirmation modal
            const deletionModal = document.getElementById('user-deletion-confirmation-modal');
            if (deletionModal) {
                deletionModal.remove();
            }
            
            // Clear any password validation errors (they're unrelated to delete)
            const passwordErrorDiv = document.getElementById('password-error');
            if (passwordErrorDiv) {
                passwordErrorDiv.style.display = 'none';
            }
            
            try {
                console.log('Attempting to delete user:', userId);
                
                // Call the API to delete the user - use the correct URL format
                const url = `/api/v1/users/${encodeURIComponent(userId)}`;
                console.log('DELETE URL:', url);
                
                const response = await fetch(url, {
                    method: 'DELETE',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                console.log('Response status:', response.status, response.statusText);
                console.log('Response headers:', [...response.headers.entries()]);
                
                // Get response text first to check if it's empty
                const responseText = await response.text();
                console.log('Response text length:', responseText.length);
                console.log('Response text (first 500 chars):', responseText.substring(0, 500));
                
                if (!response.ok) {
                    console.error('Delete user error response:', responseText);
                    if (responseText && responseText.trim() !== '') {
                        try {
                            const errorData = JSON.parse(responseText);
                            showNotification('Error: ' + (errorData.error?.message || 'Failed to delete user'), 'error');
                        } catch (e) {
                            showNotification('Error: HTTP ' + response.status + ' - ' + (responseText.substring(0, 100) || 'Failed to delete user'), 'error');
                        }
                    } else {
                        showNotification('Error: HTTP ' + response.status + ' - Empty response from server', 'error');
                    }
                    return;
                }
                
                if (!responseText || responseText.trim() === '') {
                    console.error('Empty response from API');
                    showNotification('Error: Empty response from server (HTTP ' + response.status + ')', 'error');
                    return;
                }
                
                // Parse JSON
                let result;
                try {
                    result = JSON.parse(responseText);
                    console.log('Parsed result:', result);
                } catch (parseError) {
                    console.error('JSON parse error:', parseError);
                    console.error('Response text:', responseText);
                    showNotification('Error: Invalid JSON response from server. Check console for details.', 'error');
                    return;
                }
                
                if (result.success) {
                    showNotification('User deleted successfully', 'success');
                    // Reload the page to update the user list
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                } else {
                    const errorMsg = result.error?.message || result.message || 'Failed to delete user';
                    showNotification('Error: ' + errorMsg, 'error');
                }
            } catch (error) {
                console.error('Error deleting user:', error);
                console.error('Error stack:', error.stack);
                showNotification('Error deleting user: ' + error.message, 'error');
            }
        }

        // Form submission handlers
        document.getElementById('addUserForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const password = document.getElementById('password').value;
            
            if (!isPasswordValid) {
                const errorDiv = document.getElementById('password-error');
                errorDiv.textContent = 'Please fix password requirements before submitting';
                errorDiv.style.display = 'block';
                return;
            }
            
            this.submit();
        });

        document.getElementById('editUserForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const data = Object.fromEntries(formData.entries());
            
            updateUser(data);
        });

        // Update user via API
        async function updateUser(data) {
            try {
                const response = await fetch('/api/v1/users/index.php', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        action: 'update_user',
                        user_id: data.user_id,
                        username: data.username,
                        email: data.email,
                        role: data.role,
                        is_active: data.is_active
                    })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    if (result.success) {
                        alert('User updated successfully');
                        closeModal('editUserModal');
                        window.location.reload();
                    } else {
                        alert('Error updating user: ' + (result.message || 'Unknown error'));
                    }
                } else {
                    const error = await response.json();
                    alert('Error updating user: ' + (error.message || 'HTTP ' + response.status));
                }
            } catch (error) {
                console.error('Error updating user:', error);
                alert('Error updating user: ' + error.message);
            }
        }

        // Reset Password Form Handler
        document.getElementById('resetPasswordForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const data = Object.fromEntries(formData.entries());
            
            // Validate passwords match
            if (data.new_password !== data.confirm_password) {
                showNotification('Passwords do not match', 'error');
                return;
            }
            
            // Validate password against policy
            if (passwordPolicy) {
                console.log('Validating password:', data.new_password);
                console.log('Password policy:', passwordPolicy);
                const isValid = validatePassword(data.new_password, 'resetPasswordRequirements', 'resetPasswordError');
                console.log('Password validation result:', isValid);
                if (!isValid) {
                    showNotification('Password does not meet requirements', 'error');
                    return;
                }
            } else {
                console.log('No password policy loaded');
            }
            
            try {
                const response = await fetch('/api/v1/users/index.php', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        action: 'reset_password',
                        user_id: data.user_id,
                        new_password: data.new_password
                    })
                });
                
                if (response.ok) {
                    const responseText = await response.text();
                    console.log('Reset password response text:', responseText);
                    
                    try {
                        const result = JSON.parse(responseText);
                        console.log('Parsed result:', result);
                        
                        if (result.success) {
                            showNotification('Password reset successfully', 'success');
                            closeModal('resetPasswordModal');
                            setTimeout(() => window.location.reload(), 1500);
                        } else {
                            showNotification('Error resetting password: ' + (result.message || 'Unknown error'), 'error');
                        }
                    } catch (parseError) {
                        console.error('JSON parse error:', parseError);
                        console.log('Raw response:', responseText);
                        showNotification('Error resetting password: Server returned invalid JSON', 'error');
                    }
                } else {
                    const responseText = await response.text();
                    console.log('Error response text:', responseText);
                    
                    try {
                        const error = JSON.parse(responseText);
                        showNotification('Error resetting password: ' + (error.message || 'HTTP ' + response.status), 'error');
                    } catch (parseError) {
                        console.error('Error JSON parse error:', parseError);
                        showNotification('Error resetting password: HTTP ' + response.status, 'error');
                    }
                }
            } catch (error) {
                console.error('Error resetting password:', error);
                showNotification('Error resetting password: ' + error.message, 'error');
            }
        });

        // Password validation for reset password form
        document.getElementById('newPassword').addEventListener('input', function() {
            const password = this.value;
            if (password && passwordPolicy) {
                validatePassword(password, 'resetPasswordRequirements', 'resetPasswordError');
                displayPasswordRequirements('resetPasswordRequirementsList', password);
                document.getElementById('resetPasswordRequirements').style.display = 'block';
            } else {
                document.getElementById('resetPasswordRequirements').style.display = 'none';
            }
        });

        // Show notification function
        function showNotification(message, type = 'info') {
            // Remove existing notifications
            const existingNotifications = document.querySelectorAll('.notification');
            existingNotifications.forEach(notification => notification.remove());
            
            // Create notification element
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
                <span>${message}</span>
            `;
            
            // Add to page
            document.body.appendChild(notification);
            
            // Auto remove after 5 seconds
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 5000);
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const modals = document.querySelectorAll('.modal-overlay');
            modals.forEach(modal => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>