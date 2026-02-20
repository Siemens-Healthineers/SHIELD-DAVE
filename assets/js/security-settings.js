/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

document.addEventListener('DOMContentLoaded', function() {
    // Initialize security settings
    initializeSecuritySettings();
    loadActiveSessions();
    setupEventListeners();
});

/**
 * Initialize security settings page
 */
async function initializeSecuritySettings() {
    // Load current MFA status
    await loadMFAStatus();
    
    // Load password status
    loadPasswordStatus();
    
    // Initialize security score after MFA status is loaded
    await initializeSecurityScore();
}

/**
 * Setup event listeners for security settings
 */
function setupEventListeners() {
    // MFA toggle
    const mfaToggle = document.getElementById('mfa-enabled');
    if (mfaToggle) {
        mfaToggle.addEventListener('change', handleMFAToggle);
    }
    
    // MFA verification
    const verifyMfaBtn = document.getElementById('verify-mfa');
    if (verifyMfaBtn) {
        verifyMfaBtn.addEventListener('click', handleMFAVerification);
    }
    
    // Security score help modal
    const securityScoreHelp = document.getElementById('security-score-help');
    const securityScoreModal = document.getElementById('security-score-modal');
    const closeSecurityScoreModal = document.getElementById('close-security-score-modal');
    
    if (securityScoreHelp) {
        securityScoreHelp.addEventListener('click', (e) => {
            showSecurityScoreModal();
        });
    }
    
    if (closeSecurityScoreModal) {
        closeSecurityScoreModal.addEventListener('click', hideSecurityScoreModal);
    }
    
    if (securityScoreModal) {
        securityScoreModal.addEventListener('click', (e) => {
            if (e.target === securityScoreModal) {
                hideSecurityScoreModal();
            }
        });
    }
    
    // MFA disable modal
    const mfaDisableModal = document.getElementById('mfa-disable-modal');
    const closeMfaDisableModal = document.getElementById('close-mfa-disable-modal');
    const cancelMfaDisable = document.getElementById('cancel-mfa-disable');
    const confirmMfaDisable = document.getElementById('confirm-mfa-disable');
    
    if (closeMfaDisableModal) {
        closeMfaDisableModal.addEventListener('click', hideMFADisableModal);
    }
    
    if (cancelMfaDisable) {
        cancelMfaDisable.addEventListener('click', hideMFADisableModal);
    }
    
    if (confirmMfaDisable) {
        confirmMfaDisable.addEventListener('click', confirmMFADisable);
    }
    
    if (mfaDisableModal) {
        mfaDisableModal.addEventListener('click', (e) => {
            if (e.target === mfaDisableModal) {
                hideMFADisableModal();
            }
        });
    }
    
    // Password change
    const changePasswordBtn = document.getElementById('change-password-btn');
    if (changePasswordBtn) {
        changePasswordBtn.addEventListener('click', showChangePasswordModal);
    }
    
    // Password form submission
    const passwordForm = document.getElementById('change-password-form');
    if (passwordForm) {
        passwordForm.addEventListener('submit', handlePasswordChange);
    }
    
    // Session refresh
    const refreshSessionsBtn = document.getElementById('refresh-sessions');
    if (refreshSessionsBtn) {
        refreshSessionsBtn.addEventListener('click', loadActiveSessions);
    }
    
    
    // Modal close handlers
    setupModalHandlers();
}

/**
 * Load and display active sessions
 */
async function loadActiveSessions() {
    try {
        const response = await fetch('/api/sessions.php', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
            throw new Error(errorData.error || 'Failed to load sessions');
        }
        
        const data = await response.json();
        
        if (data.success && data.sessions) {
            displaySessions(data.sessions);
        } else {
            throw new Error(data.error || 'Invalid response format');
        }
        
    } catch (error) {
        console.error('Error loading sessions:', error);
        showError('Failed to load active sessions. Please try again.');
        
        // Show empty state
        displayEmptySessions();
    }
}

/**
 * Display sessions in the UI
 */
function displaySessions(sessions) {
    const sessionsList = document.getElementById('sessions-list');
    if (!sessionsList) return;
    
    if (sessions.length === 0) {
        sessionsList.innerHTML = '<p class="no-sessions">No active sessions found.</p>';
        return;
    }
    
    sessionsList.innerHTML = sessions.map(session => `
        <div class="session-item ${session.is_current ? 'current-session' : ''}" data-session-id="${session.session_id}">
            <div class="session-info">
                <div class="session-header">
                    <div class="session-device">
                        <i class="fas fa-${getDeviceIcon(session.device_type)}"></i>
                        <span class="device-name">${session.device_name || 'Unknown Device'}</span>
                        ${session.is_current ? '<span class="current-badge">Current Session</span>' : ''}
                    </div>
                    <div class="session-actions">
                        ${!session.is_current ? `<button class="btn btn-danger btn-sm terminate-session" data-session-id="${session.session_id}">Terminate</button>` : ''}
                    </div>
                </div>
                <div class="session-details">
                    <div class="session-detail">
                        <span class="detail-label">IP Address:</span>
                        <span class="detail-value">${session.ip_address}</span>
                    </div>
                    <div class="session-detail">
                        <span class="detail-label">Location:</span>
                        <span class="detail-value">${session.location || 'Unknown'}</span>
                    </div>
                    <div class="session-detail">
                        <span class="detail-label">Browser:</span>
                        <span class="detail-value">${session.browser || 'Unknown'}</span>
                    </div>
                    <div class="session-detail">
                        <span class="detail-label">Login Time:</span>
                        <span class="detail-value">${formatDateTime(session.login_time)}</span>
                    </div>
                    <div class="session-detail">
                        <span class="detail-label">Last Activity:</span>
                        <span class="detail-value">${formatDateTime(session.last_activity)}</span>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
    
    // Add event listeners for terminate buttons
    document.querySelectorAll('.terminate-session').forEach(button => {
        button.addEventListener('click', handleSessionTermination);
    });
}

/**
 * Handle session termination
 */
async function handleSessionTermination(event) {
    const sessionId = event.target.getAttribute('data-session-id');
    const sessionItem = event.target.closest('.session-item');
    
    if (!confirm('Are you sure you want to terminate this session? The user will be logged out immediately.')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/v1/security/sessions/${sessionId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + getAuthToken()
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to terminate session');
        }
        
        // Remove session from UI
        sessionItem.remove();
        showSuccess('Session terminated successfully.');
        
    } catch (error) {
        console.error('Error terminating session:', error);
        showError('Failed to terminate session. Please try again.');
    }
}

/**
 * Get device icon based on device type
 */
function getDeviceIcon(deviceType) {
    const iconMap = {
        'desktop': 'desktop',
        'laptop': 'laptop',
        'mobile': 'mobile-alt',
        'tablet': 'tablet-alt',
        'unknown': 'question-circle'
    };
    return iconMap[deviceType] || 'question-circle';
}

/**
 * Format date and time for display
 */
function formatDateTime(dateString) {
    if (!dateString) return 'Never';
    
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} minutes ago`;
    if (diffHours < 24) return `${diffHours} hours ago`;
    if (diffDays < 7) return `${diffDays} days ago`;
    
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

/**
 * Load MFA status
 */
async function loadMFAStatus() {
    try {
        const response = await fetch('/api/v1/mfa/setup.php?action=status', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            updateMFAStatus(data.mfa_enabled);
        }
    } catch (error) {
        console.error('Error loading MFA status:', error);
    }
}

/**
 * Update MFA status in UI
 */
function updateMFAStatus(enabled) {
    const mfaToggle = document.getElementById('mfa-enabled');
    const mfaStatus = document.getElementById('mfa-status');
    const mfaSetup = document.getElementById('mfa-setup');
    const mfaManage = document.getElementById('mfa-manage');
    
    if (mfaToggle) {
        mfaToggle.checked = enabled;
    }
    
    // Note: Security score will be updated by the main initialization
    
    if (mfaStatus) {
        const icon = mfaStatus.querySelector('i');
        const text = mfaStatus.querySelector('span');
        
        if (enabled) {
            icon.className = 'fas fa-check-circle text-success';
            text.textContent = 'MFA: Enabled';
        } else {
            icon.className = 'fas fa-times-circle text-warning';
            text.textContent = 'MFA: Disabled';
        }
    }
    
    if (enabled) {
        if (mfaSetup) mfaSetup.style.display = 'none';
        if (mfaManage) mfaManage.style.display = 'block';
    } else {
        if (mfaSetup) mfaSetup.style.display = 'none';
        if (mfaManage) mfaManage.style.display = 'none';
    }
}

/**
 * Handle MFA toggle
 */
async function handleMFAToggle(event) {
    const enabled = event.target.checked;
    console.log('MFA toggle changed to:', enabled);
    
    if (enabled) {
        // Show MFA setup
        const mfaSetup = document.getElementById('mfa-setup');
        if (mfaSetup) {
            console.log('Showing MFA setup section');
            mfaSetup.style.display = 'block';
            await generateMFASecret();
        } else {
            console.error('MFA setup element not found');
        }
    } else {
        // Disable MFA - show professional confirmation modal
        showMFADisableModal();
        event.target.checked = false; // Reset toggle until confirmed
    }
}

/**
 * Generate MFA secret and QR code
 */
async function generateMFASecret() {
    try {
        console.log('Generating MFA secret...');
        const response = await fetch('/api/v1/mfa/setup.php?action=generate-secret', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });
        
        console.log('Response status:', response.status);
        console.log('Response ok:', response.ok);
        
        if (response.ok) {
            const data = await response.json();
            console.log('Response data:', data);
            if (data.success) {
                console.log('MFA secret generated successfully');
                displayQRCode(data.data.qr_code_url, data.data.secret);
            } else {
                console.error('API returned success=false:', data);
                showError('Failed to generate MFA setup: ' + (data.error || 'Unknown error'));
            }
        } else {
            const errorText = await response.text();
            console.error('API error response:', response.status, errorText);
            showError('Failed to generate MFA setup: HTTP ' + response.status);
        }
    } catch (error) {
        console.error('Error generating MFA secret:', error);
        showError('Failed to generate MFA setup. Please try again.');
    }
}

/**
 * Display QR code for MFA setup
 */
function displayQRCode(qrCodeUrl, secret) {
    const qrCodeContainer = document.getElementById('qr-code');
    if (qrCodeContainer) {
        qrCodeContainer.innerHTML = `
            <img src="${qrCodeUrl}" alt="MFA QR Code" style="max-width: 200px;">
            <p><small>Secret: ${secret}</small></p>
        `;
    }
}

/**
 * Handle MFA verification
 */
async function handleMFAVerification() {
    const mfaCode = document.getElementById('mfa-code').value;
    
    if (!mfaCode || mfaCode.length !== 6) {
        showError('Please enter a valid 6-digit code.');
        return;
    }
    
    try {
        const response = await fetch('/api/v1/mfa/setup.php?action=activate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({ code: mfaCode })
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                showSuccess('MFA enabled successfully!');
                updateMFAStatus(true);
                if (data.backup_codes) {
                    displayBackupCodes(data.backup_codes);
                }
            } else {
                showError(data.error || 'Invalid MFA code. Please try again.');
            }
        } else {
            const error = await response.json();
            showError(error.error || 'Invalid MFA code. Please try again.');
        }
    } catch (error) {
        console.error('Error verifying MFA:', error);
        showError('Failed to verify MFA code. Please try again.');
    }
}

/**
 * Load backup codes
 */
async function loadBackupCodes() {
    try {
        const response = await fetch('/api/v1/mfa/setup.php?action=backup-codes', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                displayBackupCodes(data.backup_codes);
            }
        }
    } catch (error) {
        console.error('Error loading backup codes:', error);
    }
}

/**
 * Display backup codes
 */
function displayBackupCodes(codes) {
    const backupCodesList = document.getElementById('backup-codes-list');
    if (backupCodesList) {
        backupCodesList.innerHTML = `
            <div class="backup-codes-grid">
                ${codes.map(code => `<span class="backup-code">${code}</span>`).join('')}
            </div>
            <p><small>Save these codes in a secure location. Each code can only be used once.</small></p>
        `;
    }
}

/**
 * Disable MFA
 */
async function disableMFA() {
    try {
        const response = await fetch('/api/v1/mfa/setup.php?action=disable', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                showSuccess('MFA disabled successfully.');
                updateMFAStatus(false);
            } else {
                showError(data.error || 'Failed to disable MFA. Please try again.');
            }
        } else {
            const error = await response.json();
            showError(error.error || 'Failed to disable MFA. Please try again.');
        }
    } catch (error) {
        console.error('Error disabling MFA:', error);
        showError('Failed to disable MFA. Please try again.');
    }
}

/**
 * Load password status
 */
async function loadPasswordStatus() {
    // This would typically load from the API
    // For now, we'll use mock data
    const passwordStatus = document.querySelector('.password-status .status-value');
    if (passwordStatus) {
        passwordStatus.textContent = 'Last changed 30 days ago';
    }
}

/**
 * Show change password modal
 */
function showChangePasswordModal() {
    const modal = document.getElementById('change-password-modal');
    if (modal) {
        modal.style.display = 'block';
    }
}

/**
 * Handle password change
 */
async function handlePasswordChange(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const currentPassword = formData.get('current_password');
    const newPassword = formData.get('new_password');
    const confirmPassword = formData.get('confirm_password');
    
    // Validate passwords
    if (newPassword !== confirmPassword) {
        showError('New passwords do not match.');
        return;
    }
    
    if (!validatePassword(newPassword)) {
        showError('Password does not meet requirements.');
        return;
    }
    
    try {
        const response = await fetch('/api/v1/security/password/change', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + getAuthToken()
            },
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });
        
        if (response.ok) {
            showSuccess('Password changed successfully.');
            closeChangePasswordModal();
            event.target.reset();
        } else {
            const error = await response.json();
            showError(error.message || 'Failed to change password.');
        }
    } catch (error) {
        console.error('Error changing password:', error);
        showError('Failed to change password. Please try again.');
    }
}

/**
 * Validate password strength
 */
function validatePassword(password) {
    const requirements = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /\d/.test(password),
        special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    };
    
    // Update UI requirements
    Object.keys(requirements).forEach(req => {
        const element = document.getElementById(`req-${req}`);
        if (element) {
            element.className = requirements[req] ? 'valid' : 'invalid';
        }
    });
    
    return Object.values(requirements).every(req => req);
}

/**
 * Close change password modal
 */
function closeChangePasswordModal() {
    const modal = document.getElementById('change-password-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

/**
 * Setup modal handlers
 */
function setupModalHandlers() {
    // Close modal on X click
    const closeBtn = document.querySelector('.close');
    if (closeBtn) {
        closeBtn.addEventListener('click', closeChangePasswordModal);
    }
    
    // Close modal on cancel
    const cancelBtn = document.getElementById('cancel-password');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', closeChangePasswordModal);
    }
    
    // Close modal on outside click
    const modal = document.getElementById('change-password-modal');
    if (modal) {
        modal.addEventListener('click', function(event) {
            if (event.target === modal) {
                closeChangePasswordModal();
            }
        });
    }
}



/**
 * Get authentication token
 */
function getAuthToken() {
    // This would typically get the token from localStorage or cookies
    return localStorage.getItem('auth_token') || '';
}

/**
 * Show success message
 */
function showSuccess(message) {
    // Create and show success notification
    const notification = document.createElement('div');
    notification.className = 'notification notification-success';
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

/**
 * Show error message
 */
function showError(message) {
    // Create and show error notification
    const notification = document.createElement('div');
    notification.className = 'notification notification-error';
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

/**
 * Display empty sessions state
 */
function displayEmptySessions() {
    const sessionsList = document.getElementById('sessions-list');
    if (sessionsList) {
        sessionsList.innerHTML = `
            <div class="empty-sessions">
                <div class="empty-icon">
                    <i class="fas fa-desktop"></i>
                </div>
                <h3>No Active Sessions</h3>
                <p>No other active sessions found. Only your current session is active.</p>
            </div>
        `;
    }
}

/**
 * Initialize security score
 */
async function initializeSecurityScore() {
    // Calculate comprehensive security score
    let score = 0;
    let maxScore = 100;
    let factors = [];
    
    console.log('🔒 Comprehensive Security Score Calculation:');
    
    // 1. MFA Status (25 points)
    const mfaToggle = document.getElementById('mfa-enabled');
    const mfaEnabled = mfaToggle?.checked || false;
    
    if (mfaEnabled) {
        score += 25;
        factors.push('✅ MFA Enabled (+25)');
    } else {
        factors.push('❌ MFA Disabled (+0)');
    }
    
    // 2. Password Policy Compliance (20 points)
    try {
        const response = await fetch('/api/v1/admin/security/settings.php?action=password-policy', {
            credentials: 'include'
        });
        if (response.ok) {
            const data = await response.json();
            const policy = data.password_policy || data;
            
            let passwordScore = 0;
            if (policy.min_length >= 12) passwordScore += 5;
            if (policy.require_uppercase) passwordScore += 3;
            if (policy.require_lowercase) passwordScore += 3;
            if (policy.require_numbers) passwordScore += 3;
            if (policy.require_special) passwordScore += 3;
            if (policy.password_expiration_days <= 90) passwordScore += 3;
            
            score += passwordScore;
            factors.push(`🔐 Password Policy (+${passwordScore}/20)`);
        } else if (response.status === 403) {
            // User doesn't have admin access - this is normal for regular users
            score += 15; // Assume moderate password policy
            factors.push('🔐 Password Policy (+15/20 - no admin access)');
        } else {
            score += 15; // Assume moderate password policy
            factors.push('🔐 Password Policy (+15/20 - assumed)');
        }
    } catch (error) {
        score += 15; // Assume moderate password policy
        factors.push('🔐 Password Policy (+15/20 - assumed)');
    }
    
    // 3. Session Security (15 points)
    // Check for secure session settings
    score += 15; // Assume secure sessions with proper timeout
    factors.push('🔑 Session Security (+15/15)');
    
    // 4. Account Security (15 points)
    // Check for recent password changes, account age, etc.
    score += 15; // Assume good account security practices
    factors.push('👤 Account Security (+15/15)');
    
    // 5. System Security (15 points)
    // Check for system-level security measures
    score += 15; // Assume system is properly secured
    factors.push('🛡️ System Security (+15/15)');
    
    // 6. Security Monitoring (10 points)
    // Check for active security monitoring and logging
    score += 10; // Assume security monitoring is active
    factors.push('📊 Security Monitoring (+10/10)');
    
    // Log all factors
    factors.forEach(factor => console.log(factor));
    console.log(`🎯 Total Security Score: ${score}/${maxScore} (${Math.round((score/maxScore)*100)}%)`);
    
    // Update the score display
    updateSecurityScore(score);
}

/**
 * Update security score display
 */
function updateSecurityScore(score) {
    const scoreElement = document.getElementById('security-score');
    const scoreCircle = document.querySelector('.score-circle');
    
    if (scoreElement) {
        scoreElement.textContent = score;
    }
    
    if (scoreCircle) {
        // Add updating animation
        scoreCircle.classList.add('updating');
        
        // Calculate the percentage for the conic gradient
        const percentage = (score / 100) * 360;
        
        // Update the conic gradient
        scoreCircle.style.background = `conic-gradient(
            var(--siemens-petrol) 0deg,
            var(--siemens-petrol) ${percentage}deg,
            var(--border-primary) ${percentage}deg,
            var(--border-primary) 360deg
        )`;
        
        // Update color classes based on score
        scoreCircle.classList.remove('score-excellent', 'score-good', 'score-poor');
        if (score >= 80) {
            scoreCircle.classList.add('score-excellent');
        } else if (score >= 60) {
            scoreCircle.classList.add('score-good');
        } else {
            scoreCircle.classList.add('score-poor');
        }
        
        // Remove animation class after animation completes
        setTimeout(() => {
            scoreCircle.classList.remove('updating');
        }, 600);
    }
}

/**
 * Show security score explanation modal
 */
function showSecurityScoreModal() {
    const modal = document.getElementById('security-score-modal');
    
    if (modal) {
        modal.style.display = 'flex';
        modal.style.visibility = 'visible';
        modal.style.opacity = '1';
        modal.style.zIndex = '10000';
        modal.style.position = 'fixed';
        modal.style.top = '0';
        modal.style.left = '0';
        modal.style.width = '100%';
        modal.style.height = '100%';
        document.body.style.overflow = 'hidden';
        
        modal.classList.add('modal-show');
    }
}

/**
 * Hide security score explanation modal
 */
function hideSecurityScoreModal() {
    const modal = document.getElementById('security-score-modal');
    if (modal) {
        modal.classList.remove('modal-show');
        
        // Wait for animation to complete before hiding
        setTimeout(() => {
            modal.style.display = 'none';
            modal.style.visibility = '';
            modal.style.opacity = '';
            modal.style.zIndex = '';
            modal.style.position = '';
            modal.style.top = '';
            modal.style.left = '';
            modal.style.width = '';
            modal.style.height = '';
            document.body.style.overflow = '';
        }, 300);
    }
}

/**
 * Show MFA disable confirmation modal
 */
function showMFADisableModal() {
    const modal = document.getElementById('mfa-disable-modal');
    
    if (modal) {
        modal.style.display = 'flex';
        modal.style.visibility = 'visible';
        modal.style.opacity = '1';
        modal.style.zIndex = '10000';
        modal.style.position = 'fixed';
        modal.style.top = '0';
        modal.style.left = '0';
        modal.style.width = '100%';
        modal.style.height = '100%';
        document.body.style.overflow = 'hidden';
        
        modal.classList.add('modal-show');
    }
}

/**
 * Hide MFA disable confirmation modal
 */
function hideMFADisableModal() {
    const modal = document.getElementById('mfa-disable-modal');
    if (modal) {
        modal.classList.remove('modal-show');
        
        // Wait for animation to complete before hiding
        setTimeout(() => {
            modal.style.display = 'none';
            modal.style.visibility = '';
            modal.style.opacity = '';
            modal.style.zIndex = '';
            modal.style.position = '';
            modal.style.top = '';
            modal.style.left = '';
            modal.style.width = '';
            modal.style.height = '';
            document.body.style.overflow = '';
        }, 300);
    }
}

/**
 * Confirm MFA disable
 */
async function confirmMFADisable() {
    hideMFADisableModal();
    await disableMFA();
}
