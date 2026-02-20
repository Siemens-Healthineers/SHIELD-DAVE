<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
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
    <title>Settings - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/security-settings.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="settings-container">
        <?php include __DIR__ . '/../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="settings-main">
            <div class="page-header">
                <h1><i class="fas fa-cog"></i> Settings</h1>
                <p>Manage your account settings and preferences</p>
            </div>

            <div class="settings-content">
                <!-- Security Dashboard Overview -->
                <div class="settings-card security-dashboard">
                    <h2><i class="fas fa-shield-alt"></i> Security Dashboard</h2>
                    <div class="security-overview">
                        <div class="security-score">
                            <div class="score-circle">
                                <span id="security-score">85</span>
                                <small>Security Score</small>
                            </div>
                            <button type="button" class="help-icon" id="security-score-help" title="Security Score Explanation">
                                <i class="fas fa-question-circle"></i>
                            </button>
                        </div>
                        <div class="security-status">
                            <div class="status-item">
                                <i class="fas fa-check-circle text-success"></i>
                                <span>Password: Strong</span>
                            </div>
                            <div class="status-item" id="mfa-status">
                                <i class="fas fa-times-circle text-warning"></i>
                                <span>MFA: Disabled</span>
                            </div>
                            <div class="status-item">
                                <i class="fas fa-check-circle text-success"></i>
                                <span>Session: Active</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Multi-Factor Authentication -->
                <div class="settings-card">
                    <h2><i class="fas fa-mobile-alt"></i> Multi-Factor Authentication</h2>
                    <div class="mfa-section">
                        <div class="mfa-status">
                            <div class="mfa-toggle">
                                <label class="switch">
                                    <input type="checkbox" id="mfa-enabled">
                                    <span class="slider"></span>
                                </label>
                                <span class="mfa-label">Enable MFA</span>
                            </div>
                            <p class="mfa-description">Add an extra layer of security to your account with time-based one-time passwords.</p>
                        </div>
                        
                        <div class="mfa-setup" id="mfa-setup" style="display: none;">
                            <h3>Setup MFA</h3>
                            <div class="setup-steps">
                                <div class="step">
                                    <h4>Step 1: Install Authenticator App</h4>
                                    <p>Install an authenticator app like Google Authenticator, Authy, or Microsoft Authenticator on your mobile device.</p>
                                </div>
                                <div class="step">
                                    <h4>Step 2: Scan QR Code</h4>
                                    <div class="qr-code-container">
                                        <div id="qr-code"></div>
                                        <p>Scan this QR code with your authenticator app</p>
                                    </div>
                                </div>
                                <div class="step">
                                    <h4>Step 3: Enter Verification Code</h4>
                                    <div class="verification-input">
                                        <input type="text" id="mfa-code" placeholder="Enter 6-digit code" maxlength="6">
                                        <button id="verify-mfa" class="btn btn-primary">Verify</button>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="mfa-manage" id="mfa-manage" style="display: none;">
                            <h3>MFA Management</h3>
                            <div class="backup-codes">
                                <h4>Backup Codes</h4>
                                <p>Save these backup codes in a secure location. Each code can only be used once.</p>
                                <div id="backup-codes-list" class="backup-codes-list"></div>
                                <button id="generate-backup-codes" class="btn btn-secondary">Generate New Codes</button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Password Settings -->
                <div class="settings-card">
                    <h2><i class="fas fa-key"></i> Password Security</h2>
                    <div class="password-section">
                        <div class="password-info">
                            <div class="password-status">
                                <span class="status-label">Current Password:</span>
                                <span class="status-value">Last changed 30 days ago</span>
                            </div>
                            <div class="password-strength">
                                <span class="strength-label">Strength:</span>
                                <div class="strength-meter">
                                    <div class="strength-bar" style="width: 85%"></div>
                                </div>
                                <span class="strength-text">Strong</span>
                            </div>
                        </div>
                        
                        <div class="password-actions">
                            <button id="change-password-btn" class="btn btn-primary">Change Password</button>
                        </div>

                        <!-- Change Password Modal -->
                        <div id="change-password-modal" class="modal" style="display: none;">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h3>Change Password</h3>
                                    <span class="close">&times;</span>
                                </div>
                                <div class="modal-body">
                                    <form id="change-password-form">
                                        <div class="form-group">
                                            <label for="current-password">Current Password</label>
                                            <input type="password" id="current-password" name="current_password" required>
                                        </div>
                                        <div class="form-group">
                                            <label for="new-password">New Password</label>
                                            <input type="password" id="new-password" name="new_password" required>
                                            <div class="password-requirements">
                                                <p>Password must contain:</p>
                                                <ul>
                                                    <li id="req-length">At least 8 characters</li>
                                                    <li id="req-uppercase">One uppercase letter</li>
                                                    <li id="req-lowercase">One lowercase letter</li>
                                                    <li id="req-number">One number</li>
                                                    <li id="req-special">One special character</li>
                                                </ul>
                                            </div>
                                        </div>
                                        <div class="form-group">
                                            <label for="confirm-password">Confirm New Password</label>
                                            <input type="password" id="confirm-password" name="confirm_password" required>
                                        </div>
                                        <div class="form-actions">
                                            <button type="button" class="btn btn-secondary" id="cancel-password">Cancel</button>
                                            <button type="submit" class="btn btn-primary">Change Password</button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Session Management -->
                <div class="settings-card">
                    <h2><i class="fas fa-desktop"></i> Active Sessions</h2>
                    <div class="sessions-section">
                        <div class="sessions-header">
                            <h3>Current Sessions</h3>
                            <button id="refresh-sessions" class="btn btn-secondary">
                                <i class="fas fa-sync-alt"></i> Refresh
                            </button>
                        </div>
                        <div class="sessions-list" id="sessions-list">
                            <!-- Sessions will be loaded here -->
                        </div>
                    </div>
                </div>


            </div>
        </main>
    </div>

    <!-- Security Score Explanation Modal -->
    <div id="security-score-modal" class="modal-overlay" style="display: none;">
        <div class="modal-content security-score-modal">
            <div class="modal-header">
                <h3><i class="fas fa-shield-alt"></i> Security Score Explanation</h3>
                <button type="button" class="modal-close" id="close-security-score-modal">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="score-explanation">
                    <p class="score-intro">
                        Your security score is calculated based on comprehensive security factors. 
                        A higher score indicates better security practices and system protection.
                    </p>
                    
                    <div class="score-breakdown">
                        <h4><i class="fas fa-calculator"></i> Scoring Breakdown (100 points total)</h4>
                        
                        <div class="score-category">
                            <div class="category-header">
                                <i class="fas fa-mobile-alt"></i>
                                <span class="category-name">Multi-Factor Authentication (MFA)</span>
                                <span class="category-points">25 points</span>
                            </div>
                            <div class="category-details">
                                <p>✅ <strong>Enabled (+25 points):</strong> MFA is active on your account</p>
                                <p>❌ <strong>Disabled (+0 points):</strong> MFA is not enabled</p>
                            </div>
                        </div>

                        <div class="score-category">
                            <div class="category-header">
                                <i class="fas fa-key"></i>
                                <span class="category-name">Password Policy Compliance</span>
                                <span class="category-points">20 points</span>
                            </div>
                            <div class="category-details">
                                <p>• <strong>Length ≥12 characters (+5 points)</strong></p>
                                <p>• <strong>Uppercase letters required (+3 points)</strong></p>
                                <p>• <strong>Lowercase letters required (+3 points)</strong></p>
                                <p>• <strong>Numbers required (+3 points)</strong></p>
                                <p>• <strong>Special characters required (+3 points)</strong></p>
                                <p>• <strong>Expiration ≤90 days (+3 points)</strong></p>
                            </div>
                        </div>

                        <div class="score-category">
                            <div class="category-header">
                                <i class="fas fa-lock"></i>
                                <span class="category-name">Session Security</span>
                                <span class="category-points">15 points</span>
                            </div>
                            <div class="category-details">
                                <p>• Secure session management and timeout settings</p>
                                <p>• Proper session cookie security</p>
                                <p>• Session invalidation on logout</p>
                            </div>
                        </div>

                        <div class="score-category">
                            <div class="category-header">
                                <i class="fas fa-user-shield"></i>
                                <span class="category-name">Account Security</span>
                                <span class="category-points">15 points</span>
                            </div>
                            <div class="category-details">
                                <p>• Recent password changes and account activity</p>
                                <p>• Account age and security history</p>
                                <p>• Proper account access controls</p>
                            </div>
                        </div>

                        <div class="score-category">
                            <div class="category-header">
                                <i class="fas fa-server"></i>
                                <span class="category-name">System Security</span>
                                <span class="category-points">15 points</span>
                            </div>
                            <div class="category-details">
                                <p>• System-level security measures</p>
                                <p>• Security configurations and hardening</p>
                                <p>• Infrastructure security controls</p>
                            </div>
                        </div>

                        <div class="score-category">
                            <div class="category-header">
                                <i class="fas fa-chart-line"></i>
                                <span class="category-name">Security Monitoring</span>
                                <span class="category-points">10 points</span>
                            </div>
                            <div class="category-details">
                                <p>• Active security monitoring and logging</p>
                                <p>• Threat detection and response</p>
                                <p>• Security event tracking</p>
                            </div>
                        </div>
                    </div>

                    <div class="score-ranges">
                        <h4><i class="fas fa-chart-pie"></i> Score Ranges</h4>
                        <div class="range-item">
                            <span class="range-color excellent"></span>
                            <span class="range-text"><strong>90-100:</strong> Excellent Security</span>
                        </div>
                        <div class="range-item">
                            <span class="range-color good"></span>
                            <span class="range-text"><strong>70-89:</strong> Good Security</span>
                        </div>
                        <div class="range-item">
                            <span class="range-color fair"></span>
                            <span class="range-text"><strong>50-69:</strong> Fair Security</span>
                        </div>
                        <div class="range-item">
                            <span class="range-color poor"></span>
                            <span class="range-text"><strong>0-49:</strong> Poor Security</span>
                        </div>
                    </div>

                    <div class="score-tips">
                        <h4><i class="fas fa-lightbulb"></i> Tips to Improve Your Score</h4>
                        <ul>
                            <li><strong>Enable MFA:</strong> Add an extra layer of security to your account</li>
                            <li><strong>Strengthen Password Policy:</strong> Use longer, more complex passwords</li>
                            <li><strong>Regular Updates:</strong> Keep your password fresh and secure</li>
                            <li><strong>Monitor Activity:</strong> Stay aware of your account security status</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- MFA Disable Confirmation Modal -->
    <div id="mfa-disable-modal" class="modal-overlay" style="display: none;">
        <div class="modal-content mfa-disable-modal">
            <div class="modal-header">
                <h3><i class="fas fa-exclamation-triangle"></i> Disable Multi-Factor Authentication</h3>
                <button type="button" class="modal-close" id="close-mfa-disable-modal">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="mfa-disable-warning">
                    <div class="warning-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <div class="warning-content">
                        <h4>Security Warning</h4>
                        <p>Disabling MFA will significantly reduce your account security. Without MFA, your account will only be protected by your password.</p>
                        
                        <div class="security-risks">
                            <h5>Risks of disabling MFA:</h5>
                            <ul>
                                <li><i class="fas fa-times-circle"></i> Reduced protection against password breaches</li>
                                <li><i class="fas fa-times-circle"></i> Increased vulnerability to phishing attacks</li>
                                <li><i class="fas fa-times-circle"></i> Lower security score for your account</li>
                                <li><i class="fas fa-times-circle"></i> Easier for unauthorized access</li>
                            </ul>
                        </div>
                        
                        <div class="confirmation-text">
                            <p><strong>Are you sure you want to disable Multi-Factor Authentication?</strong></p>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" id="cancel-mfa-disable">
                    <i class="fas fa-times"></i> Cancel
                </button>
                <button type="button" class="btn btn-danger" id="confirm-mfa-disable">
                    <i class="fas fa-unlock"></i> Disable MFA
                </button>
            </div>
        </div>
    </div>

    <!-- Common Dashboard JavaScript -->
    <script src="/assets/js/dashboard-common.js"></script>
    <script src="/assets/js/security-settings.js"></script>
</body>
</html>

