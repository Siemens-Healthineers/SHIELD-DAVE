<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

define('DAVE_ACCESS', true);
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/cache.php';
require_once __DIR__ . '/../../services/shell_command_utilities.php';

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

   
try {
    
    $log_file = "";

    if (is_dir(_LOGS)) {
        $log_file = _LOGS . DIRECTORY_SEPARATOR . "netdisco_background_job.log";
    }

    // Call Python service in background (non-blocking)
    $command = "cd " . _ROOT . " && python3 python/services/ingest_netdisco.py";
    $result = ShellCommandUtilities::executeShellCommand($command, [
        'blocking' => false,
        'log_file' => $log_file
    ]);
    if (!$result['success']) {
        error_log('NetDisco ingestion failed to start: ' . ($result['error'] ?? 'Unknown error'));
    }
} catch (Exception $e) {
    error_log('NetDisco ingestion failed to start: ' . $e->getMessage());
}
    
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cynerio Sync - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <main class="main-content">
        <div class="container" style="max-width: 1400px; margin: 0 auto; padding: 2rem;">
            <!-- Page Header -->
            <div style="margin-bottom: 2rem;">
                <h1 style="font-size: 1.875rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 0.5rem; display:flex;">
                    <div class="admin-card-icon">
                        <i class="fa-solid fa-n"></i>
                    </div>
                    <div class="admin-card-content">
                        <h3>NetDisco Integration</h3>
                        <p>Manage NetDisco integration settings</p>
                    </div>
                </h1>
            </div>
            <section class="center-content">
                <p>NetDisco data synchronization initiated. Please check system logs for details.</p>
                <br>
                <br>
                <a href="/pages/admin/index.php" class="admin-card">
                    <div class="admin-card-icon">
                        <i class="fas fa-cog"></i>
                    </div>
                    <div class="admin-card-content">
                        <h3>Admin Panel</h3>
                        <p>Go back to Admin Panel</p>
                    </div>
                </a>
            </section>
        </div>
    </main>

    <!-- Profile Dropdown Script -->
    <script src="/assets/js/dashboard-common.js"></script>
    <script>
        // Pass user data to the profile dropdown
        window.userData = {
            name: '<?php echo dave_htmlspecialchars($user['username']); ?>',
            role: '<?php echo dave_htmlspecialchars($user['role']); ?>',
            email: '<?php echo dave_htmlspecialchars($user['email'] ?? 'user@example.com'); ?>'
        };
    </script>
    <style>
        .center-content{
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 50vh;
        }
</body>
</html>
