<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
/**
 * Notifications Page for 
 * User notification preferences and management
 */

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/session-middleware.php';

// Session middleware is auto-initialized

// Get current user data
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
    <title>Notifications - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <h1><i class="fas fa-bell"></i> Notifications</h1>
                <p>Manage your notification preferences</p>
            </div>

            <div class="notifications-content">
                <div class="notifications-card">
                    <h2>Notification Preferences</h2>
                    <p>Notification settings coming soon...</p>
                </div>
            </div>
        </main>
    </div>

    <!-- Common Dashboard JavaScript -->
    <script src="/assets/js/dashboard-common.js"></script>
</body>
</html>

