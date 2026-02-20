<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Ensure config is loaded for helper functions
if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';

// Ensure user data is available
if (!isset($user)) {
    $user = $_SESSION['user'] ?? [
        'username' => $_SESSION['username'] ?? 'Unknown',
        'role' => $_SESSION['role'] ?? 'User',
        'email' => $_SESSION['email'] ?? 'Not provided'
    ];
}

// Get current page for active navigation highlighting
$currentPage = basename($_SERVER['PHP_SELF']);
$currentPath = $_SERVER['REQUEST_URI'] ?? '/';

// Include URL configuration for JavaScript
include __DIR__ . '/url-config.php';
?>

<!-- Header -->
<header class="dashboard-header">
    <div class="header-left">
        <div class="logo">
            <img src="/assets/images/siemens-healthineers-logo.png" alt="Siemens Healthineers" class="logo-image">
            <span><?php echo getApplicationName(); ?></span>
        </div>
    </div>
    <div class="header-right">
        <div class="profile-dropdown">
            <button class="profile-trigger" id="profile-trigger">
                <div class="profile-avatar">
                    <i class="fas fa-user"></i>
                </div>
                <div class="profile-info">
                    <span class="profile-name"><?php echo dave_htmlspecialchars($user['username']); ?></span>
                    <span class="profile-role"><?php echo dave_htmlspecialchars($user['role']); ?></span>
                </div>
                <i class="fas fa-chevron-down profile-arrow"></i>
            </button>
            
            <div class="profile-dropdown-menu" id="profile-menu">
                <div class="profile-header">
                    <div class="profile-avatar-large">
                        <i class="fas fa-user"></i>
                    </div>
                    <div class="profile-details">
                        <div class="profile-name-large"><?php echo dave_htmlspecialchars($user['username']); ?></div>
                        <div class="profile-email"><?php echo dave_htmlspecialchars($user['email'] ?? 'user@example.com'); ?></div>
                        <div class="profile-role-badge"><?php echo dave_htmlspecialchars($user['role']); ?></div>
                    </div>
                </div>
                
                <div class="profile-divider"></div>
                
                <div class="profile-actions">
                    <a href="/pages/settings.php" class="profile-action">
                        <i class="fas fa-cog"></i>
                        <span>Settings</span>
                    </a>
                    
                    <?php if ($user['role'] === 'Admin'): ?>
                    <!--a href="/pages/admin/api-keys.php" class="profile-action">
                        <i class="fas fa-key"></i>
                        <span>API Key Management</span>
                    </a-->
                    <?php else: ?>
                    <a href="/pages/user/api-keys.php" class="profile-action">
                        <i class="fas fa-key"></i>
                        <span>My API Keys</span>
                    </a>
                    <?php endif; ?>
                    
                    <a href="/pages/notifications.php" class="profile-action">
                        <i class="fas fa-bell"></i>
                        <span>Notifications</span>
                        <span class="notification-badge">3</span>
                    </a>
                </div>
                
                <div class="profile-divider"></div>
                
                <div class="profile-links">
                    <a href="/pages/reports/generate.php" class="profile-link">
                        <i class="fas fa-chart-bar"></i>
                        <span>Reports</span>
                    </a>
                    
                    <a href="/pages/about.php" class="profile-link">
                        <i class="fas fa-info-circle"></i>
                        <span>About</span>
                    </a>
                    
                    <a href="/docs/index.php" class="profile-link">
                        <i class="fas fa-book"></i>
                        <span>Documentation</span>
                    </a>
                </div>
                
                <?php if ($user['role'] === 'Admin'): ?>
                <div class="profile-divider"></div>
                
                <div class="profile-admin">
                    <a href="/pages/admin/index.php" class="profile-admin-link">
                        <i class="fas fa-tools"></i>
                        <span>Admin Panel</span>
                        <i class="fas fa-external-link-alt"></i>
                    </a>
                </div>
                <?php endif; ?>
                
                <div class="profile-divider"></div>
                
                <div class="profile-footer">
                    <a href="/pages/logout.php" class="profile-logout">
                        <i class="fas fa-sign-out-alt"></i>
                        <span>Sign Out</span>
                    </a>
                </div>
            </div>
        </div>
    </div>
</header>

<!-- Navigation -->
<nav class="dashboard-nav">
    <!-- Lockdown Status Indicator -->
    <div class="lockdown-nav-indicator" id="lockdown-nav-indicator" style="display: none;">
        <i class="fas fa-lock"></i>
        <span>LOCKDOWN ACTIVE</span>
    </div>
    
    <a href="/pages/dashboard.php" class="nav-item <?php echo ($currentPage === 'dashboard.php') ? 'active' : ''; ?>">
        <i class="fas fa-tachometer-alt"></i>
        Dashboard
    </a>
    <a href="/pages/assets/manage.php" class="nav-item <?php echo (strpos($currentPath, '/assets/') !== false) ? 'active' : ''; ?>">
        <i class="fas fa-server"></i>
        Assets
    </a>
    <a href="/pages/recalls/dashboard.php" class="nav-item <?php echo (strpos($currentPath, '/recalls/') !== false) ? 'active' : ''; ?>">
        <i class="fas fa-exclamation-triangle"></i>
        Recalls
    </a>
    <a href="/pages/vulnerabilities/dashboard.php" class="nav-item <?php echo (strpos($currentPath, '/vulnerabilities/') !== false) ? 'active' : ''; ?>">
        <i class="fas fa-bug"></i>
        Vulnerabilities
    </a>
    <a href="/pages/risk-priorities/software-packages.php" class="nav-item <?php echo (strpos($currentPath, '/risk-priorities/') !== false) ? 'active' : ''; ?>">
        <i class="fas fa-exclamation-circle"></i>
        Risk Priorities
    </a>
    <a href="/pages/risks/index.php" class="nav-item <?php echo (strpos($currentPath, '/risks/') !== false) ? 'active' : ''; ?>">
        <i class="fas fa-shield-alt"></i>
        Risks
    </a>
    <a href="/pages/admin/patches.php" class="nav-item <?php echo (strpos($currentPath, '/patches.php') !== false) ? 'active' : ''; ?>">
        <i class="fas fa-band-aid"></i>
        Patches
    </a>
    <a href="/pages/schedule/index.php" class="nav-item <?php echo (strpos($currentPath, '/schedule/') !== false) ? 'active' : ''; ?>">
        <i class="fas fa-calendar-alt"></i>
        Schedule
    </a>
</nav>

<!-- Profile Dropdown Script -->
<script>
document.addEventListener('DOMContentLoaded', function() {
    const profileTrigger = document.getElementById('profile-trigger');
    const profileMenu = document.getElementById('profile-menu');
    
    if (profileTrigger && profileMenu) {
        profileTrigger.addEventListener('click', function(e) {
            e.stopPropagation();
            profileMenu.classList.toggle('show');
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', function(e) {
            if (!profileTrigger.contains(e.target) && !profileMenu.contains(e.target)) {
                profileMenu.classList.remove('show');
            }
        });
        
        // Close dropdown when pressing Escape
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                profileMenu.classList.remove('show');
            }
        });
    }
});
</script>

<!-- Global Lockdown Status -->
<script src="/assets/js/global-lockdown-status.js"></script>
