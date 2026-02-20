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
require_once __DIR__ . '/../../includes/lockdown-enforcement.php';

// Enforce system lockdown
enforceSystemLockdown(__FILE__);

// Initialize authentication
$auth = new Auth();

// Require authentication
$auth->requireAuth();

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
    <title>Security - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/admin-security.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <h1><i class="fas fa-shield-alt"></i> Security</h1>
                <p>Manage your security settings and preferences</p>
                <div class="user-info">
                    <p><strong>Current User:</strong> <?php echo dave_htmlspecialchars($user['username']); ?> 
                    <span class="user-role role-<?php echo strtolower($user['role']); ?>"><?php echo dave_htmlspecialchars($user['role']); ?></span></p>
                    <!-- Debug: Role value is: "<?php echo dave_htmlspecialchars($user['role']); ?>" -->
                    <?php if (strtolower($user['role']) !== 'admin'): ?>
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle"></i>
                            <strong>Access Restricted:</strong> Admin privileges required to access security settings.
                        </div>
                    <?php endif; ?>
                </div>
            </div>

        <!-- System Lockdown Status Banner -->
        <div class="lockdown-status-banner" id="lockdown-status-banner" style="display: none;">
            <!-- Lockdown status loaded via JavaScript -->
        </div>

        <!-- Security Metrics Dashboard -->
        <div class="metrics-section">
            <div class="metrics-header">
                <h2><i class="fas fa-chart-line"></i> Security Overview</h2>
                <p>Real-time security metrics and system status</p>
            </div>
            <div class="metrics-grid" id="security-metrics">
                <!-- Metrics will be loaded via JavaScript -->
            </div>
        </div>

            <!-- Security Management Tabs -->
            <div class="security-tabs">
                <div class="tab-navigation">
                    <button class="tab-button active" data-tab="password-policy">
                        <i class="fas fa-key"></i> Password Policy
                    </button>
                    <button class="tab-button" data-tab="authentication">
                        <i class="fas fa-shield-alt"></i> Authentication
                    </button>
                    <button class="tab-button" data-tab="audit-log">
                        <i class="fas fa-clipboard-list"></i> Audit Log
                    </button>
                    <button class="tab-button" data-tab="incidents">
                        <i class="fas fa-exclamation-circle"></i> Incident Response
                    </button>
                </div>

                <!-- Password Policy Tab -->
                <div class="tab-content active" id="password-policy">
                    <div class="security-card">
                        <h2><i class="fas fa-key"></i> Password Policy</h2>
                        <form id="password-policy-form">
                            <div class="form-group">
                                <label for="min_length">Minimum Length</label>
                                <div class="criticality-slider">
                                    <input type="range" id="min_length" name="min_length" min="6" max="20" value="8" class="slider">
                                    <div class="slider-labels">
                                        <span>6 (Min)</span>
                                        <span id="minLengthValue">8</span>
                                        <span>20 (Max)</span>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="form-group">
                                <label>Complexity Requirements</label>
                                <div class="checkbox-group">
                                    <label><input type="checkbox" name="require_uppercase" checked> Uppercase letters</label>
                                    <label><input type="checkbox" name="require_lowercase" checked> Lowercase letters</label>
                                    <label><input type="checkbox" name="require_numbers" checked> Numbers</label>
                                    <label><input type="checkbox" name="require_special" checked> Special characters</label>
                                </div>
                            </div>
                            
                            <div class="form-group">
                                <label for="expiration_days">Password Expiration</label>
                                <select id="expiration_days" name="expiration_days">
                                    <option value="30">30 days</option>
                                    <option value="60">60 days</option>
                                    <option value="90" selected>90 days</option>
                                    <option value="180">180 days</option>
                                    <option value="0">Never expire</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label for="history_count">Password History</label>
                                <input type="number" id="history_count" name="history_count" min="0" max="10" value="5">
                                <small>Number of previous passwords to remember</small>
                            </div>
                            
                            <div class="form-actions">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-save"></i> Save Password Policy
                                </button>
                                <button type="button" class="btn btn-secondary" id="test-password">
                                    <i class="fas fa-test-tube"></i> Test Password
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Authentication Tab -->
                <div class="tab-content" id="authentication">
                    <div class="security-card">
                        <h2><i class="fas fa-shield-alt"></i> Authentication Security</h2>
                        <form id="authentication-form">
                            <div class="form-group">
                                <label for="max_login_attempts">Maximum Login Attempts</label>
                                <input type="number" id="max_login_attempts" name="max_login_attempts" min="3" max="10" value="5">
                                <small>Number of failed attempts before account lockout</small>
                            </div>
                            
                            <div class="form-group">
                                <label for="lockout_duration">Lockout Duration (minutes)</label>
                                <input type="number" id="lockout_duration" name="lockout_duration_minutes" min="5" max="60" value="15">
                                <small>How long to lock account after max attempts</small>
                            </div>
                            
                            <div class="form-group">
                                <label for="session_timeout">Session Timeout (minutes)</label>
                                <input type="number" id="session_timeout" name="session_timeout_minutes" min="5" max="480" value="30">
                                <small>How long before session expires due to inactivity</small>
                            </div>
                            
                            <div class="form-group">
                                <label>
                                    <input type="checkbox" id="require_2fa" name="require_2fa"> Require Two-Factor Authentication
                                </label>
                                <small>Force all users to enable 2FA</small>
                            </div>
                            
                            <div class="form-actions">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-save"></i> Save Authentication Settings
                                </button>
                            </div>
                        </form>
                    </div>
                </div>


                <!-- Audit Log Tab -->
                <div class="tab-content" id="audit-log">
                    <div class="security-card">
                        <h2><i class="fas fa-clipboard-list"></i> Security Audit Log</h2>
                        
                        <div class="filter-controls">
                            <div class="filter-group">
                                <label for="event-type-filter">Event Type:</label>
                                <select id="event-type-filter">
                                    <option value="">All Events</option>
                                    <option value="login">Login</option>
                                    <option value="logout">Logout</option>
                                    <option value="login_failed">Failed Login</option>
                                    <option value="password_change">Password Change</option>
                                    <option value="admin_action">Admin Action</option>
                                </select>
                            </div>
                            <div class="filter-group">
                                <label for="user-filter">User:</label>
                                <input type="text" id="user-filter" placeholder="Filter by username">
                            </div>
                            <div class="filter-group">
                                <label for="date-from">From:</label>
                                <input type="date" id="date-from">
                            </div>
                            <div class="filter-group">
                                <label for="date-to">To:</label>
                                <input type="date" id="date-to">
                            </div>
                            <button class="btn btn-secondary" id="refresh-audit-log">
                                <i class="fas fa-refresh"></i> Refresh
                            </button>
                            <button class="btn btn-primary" id="export-audit-log">
                                <i class="fas fa-download"></i> Export CSV
                            </button>
                        </div>
                        
                        <div class="table-container">
                            <table class="data-table" id="audit-log-table">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Event Type</th>
                                        <th>User</th>
                                        <th>Location</th>
                                        <th>IP Address</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <!-- Data loaded via JavaScript -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>


                <!-- Incident Response Tab -->
                <div class="tab-content" id="incidents">
                    <div class="security-card">
                        <h2><i class="fas fa-exclamation-circle"></i> Incident Response</h2>
                        
                        <div class="incident-actions">
                            <h3>Emergency Actions</h3>
                            <div class="action-buttons">
                                <div class="btn-with-help">
                                    <button class="btn btn-danger" id="block-ip-btn" data-action="block-ip">
                                        <i class="fas fa-ban"></i> Block IP Address
                                    </button>
                                </div>
                                <div class="btn-with-help">
                                    <button class="btn btn-warning" id="suspend-user-btn" data-action="suspend-user">
                                        <i class="fas fa-user-slash"></i> Suspend User
                                    </button>
                                </div>
                                <div class="btn-with-help">
                                    <button class="btn btn-warning" id="terminate-sessions-btn" data-action="terminate-sessions">
                                        <i class="fas fa-sign-out-alt"></i> Terminate Sessions
                                    </button>
                                </div>
                                <div class="btn-with-help">
                                    <button class="btn btn-danger" id="system-lockdown-btn" data-action="system-lockdown">
                                        <i class="fas fa-lock"></i> System Lockdown
                                    </button>
                                    <i class="fas fa-question-circle help-icon" id="lockdown-help-icon"></i>
                                </div>
                            </div>
                        </div>
                        
                        <div class="lockdown-status" id="lockdown-status">
                            <!-- Lockdown status loaded via JavaScript -->
                        </div>
                        
                        <div class="active-incidents">
                            <h3>Active Security Incidents</h3>
                            <div class="incidents-list" id="incidents-list">
                                <!-- Incidents loaded via JavaScript -->
                            </div>
                        </div>
                        
                        <div class="security-metrics">
                            <h3>Security Metrics</h3>
                            <div class="metrics-grid" id="incident-metrics">
                                <!-- Metrics loaded via JavaScript -->
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- Help Modal -->
    <div class="help-modal" id="help-modal">
        <div class="help-modal-content">
            <div class="help-modal-header">
                <h3><i class="fas fa-info-circle"></i> System Lockdown Help</h3>
                <button class="help-modal-close" id="help-modal-close">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="help-modal-body">
                <p><strong>System Lockdown</strong> is an emergency security feature that:</p>
                <ul>
                    <li>Restricts all non-admin access to the system</li>
                    <li>Automatically expires after the specified duration</li>
                    <li>Can be manually cleared by administrators</li>
                    <li>Logs all access attempts during lockdown</li>
                    <li>Shows clear status indicators throughout the system</li>
                </ul>
                <p><strong>Use Cases:</strong></p>
                <ul>
                    <li>Security incidents requiring immediate access restriction</li>
                    <li>System maintenance requiring user access control</li>
                    <li>Emergency situations requiring temporary lockdown</li>
                </ul>
            </div>
            <div class="help-modal-footer">
                <button class="btn btn-primary" id="help-modal-ok">Got it</button>
            </div>
        </div>
    </div>

    <!-- Test Password Modal -->
    <div class="help-modal" id="test-password-modal">
        <div class="help-modal-content">
            <div class="help-modal-header">
                <h3><i class="fas fa-test-tube"></i> Test Password Policy</h3>
                <button class="help-modal-close" id="test-password-modal-close">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="help-modal-body">
                <p>Enter a password to test against the current password policy settings:</p>
                <div class="form-group">
                    <label for="test-password-input">Test Password:</label>
                    <input type="password" id="test-password-input" placeholder="Enter password to test" 
                           style="width: 100%; padding: 0.75rem 1rem; border: 1px solid var(--border-primary, #333); border-radius: 0.5rem; background: var(--bg-secondary, #333); color: var(--text-primary, #f8fafc); font-size: 1rem; outline: none; transition: border-color 0.3s ease;"
                           onfocus="this.style.borderColor='var(--siemens-petrol, #009999)'"
                           onblur="this.style.borderColor='var(--border-primary, #333)'">
                </div>
                <div id="password-test-results" style="margin-top: 1rem; padding: 1rem; border-radius: 0.5rem; background: var(--bg-secondary, #333); display: none;">
                    <!-- Results will be populated by JavaScript -->
                </div>
            </div>
            <div class="help-modal-footer">
                <button class="btn btn-secondary" id="test-password-modal-close-btn">Cancel</button>
                <button class="btn btn-primary" id="test-password-btn">
                    <i class="fas fa-test-tube"></i> Test Password
                </button>
            </div>
        </div>
    </div>

    <!-- Dashboard Common Scripts -->
    <script src="/assets/js/dashboard-common.js"></script>
    <script src="/assets/js/admin-security.js"></script>
</body>
</html>

