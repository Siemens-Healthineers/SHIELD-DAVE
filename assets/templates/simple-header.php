<?php
/**
 * ====================================================================================
 * Device Assessment and Vulnerability Exposure (DAVE)
 * ====================================================================================
 * 
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
 *
 * SECURITY & COMPLIANCE:
 * - HIPAA compliant medical device cybersecurity management
 * - FDA cybersecurity guidance compliance
 * - IEC 62304 and ISO 27001 standards
 * - Siemens Healthineers security standards
 * 
 * TECHNICAL REQUIREMENTS:
 * - PHP 7.4+ | PostgreSQL 12+ | Apache 2.4+
 * - Authentication required for protected pages
 * - Role-based access control (RBAC)
 * - Input validation and XSS protection
 * 
 * LOGGING & MONITORING:
 * - Application logs: /var/www/html/logs/dave.log
 * - Security logs: /var/www/html/logs/security.log
 * - Performance monitoring and error tracking
 * 
 * ====================================================================================
 */

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

// Required includes
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/functions.php';

// Initialize authentication
$auth = new Auth();

// Require authentication for protected pages
$auth->requireAuth();

// Set security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Log page access
logMessage('INFO', 'Page accessed', [
    'page' => basename(__FILE__),
    'user_id' => $_SESSION['user_id'] ?? 'anonymous',
    'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
]);

// Get current user
$user = $_SESSION['user'] ?? [
    'username' => $_SESSION['username'] ?? 'Unknown',
    'role' => $_SESSION['role'] ?? 'User',
    'email' => $_SESSION['email'] ?? 'Not provided'
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $pageTitle ?? ' - Device Assessment and Vulnerability Exposure'; ?></title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <!-- Custom CSS -->
    <link href="/assets/css/dashboard.css" rel="stylesheet">
    
    <style>
        .dashboard-header {
            background: linear-gradient(135deg, #009999 0%, #007777 100%);
            color: white;
            padding: 2rem 0;
            margin-bottom: 2rem;
        }
        .profile-trigger {
            background: none;
            border: none;
            color: white;
            font-size: 1.2rem;
            cursor: pointer;
        }
        .profile-dropdown-menu {
            display: none;
            position: absolute;
            right: 0;
            top: 100%;
            background: white;
            border: 1px solid #ddd;
            border-radius: 0.5rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 1000;
            min-width: 200px;
        }
        .profile-dropdown-menu.show {
            display: block;
        }
        .profile-link {
            display: block;
            padding: 0.75rem 1rem;
            color: #333;
            text-decoration: none;
            border-bottom: 1px solid #eee;
        }
        .profile-link:hover {
            background: #f8f9fa;
            color: #009999;
        }
        .profile-link:last-child {
            border-bottom: none;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/pages/dashboard.php">
                <i class="fas fa-shield-alt"></i> 
            </a>
            
            <div class="navbar-nav ms-auto">
                <div class="nav-item dropdown">
                    <button class="profile-trigger" onclick="toggleProfileDropdown()">
                        <i class="fas fa-user-circle"></i> <?php echo dave_htmlspecialchars($user['username']); ?>
                        <i class="fas fa-chevron-down ms-1"></i>
                    </button>
                    <div class="profile-dropdown-menu" id="profileDropdown">
                        <a href="/pages/settings.php" class="profile-link">
                            <i class="fas fa-cog"></i> Settings
                        </a>
                        <a href="/pages/about.php" class="profile-link">
                            <i class="fas fa-info-circle"></i> About
                        </a>
                        <a href="/docs/index.php" class="profile-link">
                            <i class="fas fa-question-circle"></i> Help
                        </a>
                        <a href="/api/logout.php" class="profile-link">
                            <i class="fas fa-sign-out-alt"></i> Logout
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <script>
        function toggleProfileDropdown() {
            const dropdown = document.getElementById('profileDropdown');
            dropdown.classList.toggle('show');
        }
        
        // Close dropdown when clicking outside
        document.addEventListener('click', function(event) {
            const dropdown = document.getElementById('profileDropdown');
            const trigger = document.querySelector('.profile-trigger');
            
            if (!trigger.contains(event.target) && !dropdown.contains(event.target)) {
                dropdown.classList.remove('show');
            }
        });
    </script>

