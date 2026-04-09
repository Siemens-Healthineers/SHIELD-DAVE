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
require_once __DIR__ . '/../../includes/cache.php';
require_once __DIR__ . '/../../includes/lockdown-enforcement.php';

// Enforce system lockdown
enforceSystemLockdown(__FILE__);
require_once __DIR__ . '/../../includes/security.php';

// Initialize authentication
$auth = new Auth();

// Require authentication and admin permission
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    // Sanitize the current URL to prevent redirect injection
    $current_path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $safe_redirect = validate_redirect_url($current_path);
    $redirect_url = validate_redirect_url('/pages/login.php?redirect=' . urlencode($safe_redirect));
    header('Location: ' . $redirect_url);
    exit;
}

// Check if user has admin role
if ($user['role'] !== 'Admin') {
    header('Location: /pages/dashboard.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Get system statistics with caching
$admin_stats_cache_key = 'admin_stats_' . date('Y-m-d-H-i', floor(time() / 300) * 300);
$stats = Cache::get($admin_stats_cache_key);

if (!$stats) {
    $stats = [];
    
    // User statistics
    $sql = "SELECT COUNT(*) as total_users FROM users";
    $stmt = $db->query($sql);
    $stats['total_users'] = $stmt->fetch()['total_users'];

    $sql = "SELECT COUNT(*) as active_users FROM users WHERE last_login > NOW() - INTERVAL '7 days'";
    $stmt = $db->query($sql);
    $stats['active_users'] = $stmt->fetch()['active_users'];

    // Asset statistics
    $sql = "SELECT COUNT(*) as total_assets FROM assets";
    $stmt = $db->query($sql);
    $stats['total_assets'] = $stmt->fetch()['total_assets'];

    $sql = "SELECT COUNT(*) as mapped_assets FROM assets a JOIN medical_devices md ON a.asset_id = md.asset_id";
    $stmt = $db->query($sql);
    $stats['mapped_assets'] = $stmt->fetch()['mapped_assets'];

    // Vulnerability statistics
    $sql = "SELECT COUNT(*) as total_vulnerabilities FROM vulnerabilities";
    $stmt = $db->query($sql);
    $stats['total_vulnerabilities'] = $stmt->fetch()['total_vulnerabilities'];

    $sql = "SELECT COUNT(*) as critical_vulnerabilities FROM vulnerabilities WHERE severity = 'Critical'";
    $stmt = $db->query($sql);
    $stats['critical_vulnerabilities'] = $stmt->fetch()['critical_vulnerabilities'];

    // Recall statistics
    $sql = "SELECT COUNT(*) as total_recalls FROM recalls";
    $stmt = $db->query($sql);
    $stats['total_recalls'] = $stmt->fetch()['total_recalls'];

    $sql = "SELECT COUNT(*) as active_recalls FROM recalls WHERE recall_status = 'Active'";
    $stmt = $db->query($sql);
    $stats['active_recalls'] = $stmt->fetch()['active_recalls'];

    // Location statistics
    $sql = "SELECT COUNT(*) as total_locations FROM locations";
    $stmt = $db->query($sql);
    $stats['total_locations'] = $stmt->fetch()['total_locations'];

    $sql = "SELECT COUNT(*) as active_locations FROM locations WHERE is_active = TRUE";
    $stmt = $db->query($sql);
    $stats['active_locations'] = $stmt->fetch()['active_locations'];

    $sql = "SELECT COUNT(*) as high_criticality_locations FROM locations WHERE criticality >= 8 AND is_active = TRUE";
    $stmt = $db->query($sql);
    $stats['high_criticality_locations'] = $stmt->fetch()['high_criticality_locations'];
    
    // Cache the results for 5 minutes
    Cache::set($admin_stats_cache_key, $stats, 300);
}

// System health
$system_health = [
    'database' => 'healthy',
    'file_system' => 'healthy'
];

// Check database connection
try {
    $db->query("SELECT 1");
    $system_health['database'] = 'healthy';
} catch (Exception $e) {
    $system_health['database'] = 'error';
}


// Check file system
$uploads_dir = _ROOT . '/uploads';
$logs_dir = _ROOT . '/logs';
if (is_writable($uploads_dir) && is_writable($logs_dir)) {
    $system_health['file_system'] = 'healthy';
} else {
    $system_health['file_system'] = 'warning';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Reduce metric card sizes by 75% total (50% + 50%) to fit all on one row */
        .metrics-section .metric-card {
            padding: 0.375rem !important;
            min-height: auto !important;
            flex: 1 !important;
        }
        
        .metrics-section .metric-icon {
            width: 1rem !important;
            height: 1rem !important;
            font-size: 0.5rem !important;
        }
        
        .metrics-section .metric-content h3 {
            font-size: 0.625rem !important;
            margin-bottom: 0.125rem !important;
        }
        
        .metrics-section .metric-value {
            font-size: 1rem !important;
            font-weight: 600 !important;
            margin-bottom: 0.125rem !important;
        }
        
        .metrics-section .metric-detail {
            font-size: 0.5rem !important;
            opacity: 0.8 !important;
            line-height: 1.2 !important;
        }
        
        .metrics-section .metrics-grid {
            gap: 0.375rem !important;
            display: flex !important;
            flex-wrap: nowrap !important;
        }
        
        /* Ensure all 5 cards fit on one row */
        .metrics-section .metric-card {
            min-width: 0 !important;
            flex-basis: 20% !important;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-cog"></i> Admin Dashboard</h1>
                    <p>System administration, user management, and configuration</p>
                </div>
            </div>

            <!-- System Overview -->
            <section class="metrics-section">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-users"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Users</h3>
                            <div class="metric-value"><?php echo $stats['total_users']; ?></div>
                            <div class="metric-detail"><?php echo $stats['active_users']; ?> active (7 days)</div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-server"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Assets</h3>
                            <div class="metric-value"><?php echo $stats['total_assets']; ?></div>
                            <div class="metric-detail"><?php echo $stats['mapped_assets']; ?> mapped to FDA</div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-bug"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Vulnerabilities</h3>
                            <div class="metric-value"><?php echo $stats['total_vulnerabilities']; ?></div>
                            <div class="metric-detail"><?php echo $stats['critical_vulnerabilities']; ?> critical</div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Recalls</h3>
                            <div class="metric-value"><?php echo $stats['total_recalls']; ?></div>
                            <div class="metric-detail"><?php echo $stats['active_recalls']; ?> active</div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-map-marker-alt"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Locations</h3>
                            <div class="metric-value"><?php echo $stats['total_locations']; ?></div>
                            <div class="metric-detail"><?php echo $stats['high_criticality_locations']; ?> high criticality</div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Admin Actions -->
            <section class="admin-actions">
                <h2><i class="fas fa-tools"></i> Admin Actions</h2>
                <div class="admin-grid">
                    <a href="/pages/admin/users.php" class="admin-card">
                        <div class="admin-card-icon">
                            <i class="fas fa-users"></i>
                        </div>
                        <div class="admin-card-content">
                            <h3>User Management</h3>
                            <p>Manage users, roles, and permissions</p>
                        </div>
                    </a>

                    <a href="/pages/admin/api-keys.php" class="admin-card">
                        <div class="admin-card-icon">
                            <i class="fas fa-key"></i>
                        </div>
                        <div class="admin-card-content">
                            <h3>API Key Management</h3>
                            <p>Manage API keys for external system access</p>
                        </div>
                    </a>

                    <a href="/pages/admin/locations.php" class="admin-card">
                        <div class="admin-card-icon">
                            <i class="fas fa-map-marker-alt"></i>
                        </div>
                        <div class="admin-card-content">
                            <h3>Location Management</h3>
                            <p>Manage hospital locations and IP ranges</p>
                        </div>
                    </a>

                    <a href="/pages/admin/system-config.php" class="admin-card">
                        <div class="admin-card-icon">
                            <i class="fas fa-cog"></i>
                        </div>
                        <div class="admin-card-content">
                            <h3>System Configuration</h3>
                            <p>Configure system settings and preferences</p>
                        </div>
                    </a>


                    <a href="/pages/admin/risk-matrix.php" class="admin-card">
                        <div class="admin-card-icon">
                            <i class="fas fa-sliders-h"></i>
                        </div>
                        <div class="admin-card-content">
                            <h3>Risk Matrix Configuration</h3>
                            <p>Configure risk score calculations and criticality weights</p>
                        </div>
                    </a>

                    <a href="/pages/admin/scheduler.php" class="admin-card">
                        <div class="admin-card-icon">
                            <i class="fas fa-tasks"></i>
                        </div>
                        <div class="admin-card-content">
                            <h3>Manual Tasks</h3>
                            <p>Run system maintenance and monitoring tasks manually</p>
                        </div>
                    </a>


                    <a href="/pages/admin/security.php" class="admin-card">
                        <div class="admin-card-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div class="admin-card-content">
                            <h3>Security Settings</h3>
                            <p>Configure security policies and authentication</p>
                        </div>
                    </a>

                    <a href="/pages/admin/backup.php" class="admin-card">
                        <div class="admin-card-icon">
                            <i class="fas fa-download"></i>
                        </div>
                        <div class="admin-card-content">
                            <h3>Backup & Recovery</h3>
                            <p>System backup and recovery procedures</p>
                        </div>
                    </a>


                    <a href="/pages/admin/logs.php" class="admin-card">
                        <div class="admin-card-icon">
                            <i class="fas fa-file-alt"></i>
                        </div>
                        <div class="admin-card-content">
                            <h3>System Logs</h3>
                            <p>View and manage system logs</p>
                        </div>
                    </a>

                    <a href="/pages/admin/cynerio.php" class="admin-card">
                        <div class="admin-card-icon">
                            <i class="fa-solid fa-c"></i>
                        </div>
                        <div class="admin-card-content">
                            <h3>Cynerio Integration</h3>
                            <p>Manage Cynerio integration settings</p>
                        </div>
                    </a>

                    <a href="/pages/admin/netdisco.php" class="admin-card">
                        <div class="admin-card-icon">
                            <i class="fa-solid fa-n"></i>
                        </div>
                        <div class="admin-card-content">
                            <h3>NetDisco Integration</h3>
                            <p>Manage NetDisco integration settings</p>
                        </div>
                    </a>

                    <a href="/pages/admin/blueflow.php" class="admin-card">
                        <div class="admin-card-icon">
                            <i class="fa-solid fa-b"></i>
                        </div>
                        <div class="admin-card-content">
                            <h3>BlueFlow Integration</h3>
                            <p>Manage BlueFlow integration settings</p>
                        </div>
                    </a>
                </div>
            </section>

            <!-- System Health -->
            <section class="system-health">
                <h2><i class="fas fa-heartbeat"></i> System Health</h2>
                <div class="health-grid">
                    <div class="health-item">
                        <div class="health-icon">
                            <i class="fas fa-database"></i>
                        </div>
                        <div class="health-content">
                            <h3>Database</h3>
                            <div class="health-status <?php echo $system_health['database']; ?>">
                                <?php echo ucfirst($system_health['database']); ?>
                            </div>
                        </div>
                    </div>


                    <div class="health-item">
                        <div class="health-icon">
                            <i class="fas fa-folder"></i>
                        </div>
                        <div class="health-content">
                            <h3>File System</h3>
                            <div class="health-status <?php echo $system_health['file_system']; ?>">
                                <?php echo ucfirst($system_health['file_system']); ?>
                            </div>
                        </div>
                    </div>

                </div>
            </section>

        </main>
    </div>

    <script>
        // Admin Dashboard JavaScript
        document.addEventListener('DOMContentLoaded', function() {
            // Add loading states to admin cards
            document.querySelectorAll('.admin-card').forEach(function(card) {
                card.addEventListener('click', function() {
                    this.classList.add('loading');
                });
            });

        });

    </script>
    
    <!-- Common Dashboard JavaScript -->
    <script src="/assets/js/dashboard-common.js"></script>
</body>
</html>
