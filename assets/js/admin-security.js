/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
class SecurityManager {
    constructor() {
        this.currentTab = 'password-policy';
        this.apiBase = '/api/v1/admin/security';
        this.isLoading = false;
        this.notifications = [];
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadSecurityMetrics();
        this.initializeTabs();
        this.setupFormValidation();
        this.setupRealTimeUpdates();
        this.initializeTooltips();
        this.setupKeyboardNavigation();
        this.loadLockdownStatus(); // Load lockdown status on page load
    }

    setupEventListeners() {
        // Tab navigation
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                const tabId = button.dataset.tab;
                this.switchTab(tabId);
            });
        });

        // Form submissions
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleFormSubmit(form);
            });
        });

        // Range sliders
        document.querySelectorAll('input[type="range"]').forEach(slider => {
            slider.addEventListener('input', (e) => {
                this.updateRangeValue(e.target);
            });
        });

        // Emergency actions
        document.querySelectorAll('[data-action]').forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                console.log('Emergency action button clicked:', button.dataset.action, button);
                this.handleEmergencyAction(button);
            });
        });

        // Filter controls
        document.querySelectorAll('.filter-controls input, .filter-controls select').forEach(input => {
            input.addEventListener('change', () => {
                this.applyFilters();
            });
        });

        // Data table sorting
        document.querySelectorAll('.data-table th[data-sort]').forEach(header => {
            header.addEventListener('click', () => {
                this.sortTable(header);
            });
        });

        // Auto-refresh for real-time data
        setInterval(() => {
            this.refreshRealTimeData();
        }, 30000); // Refresh every 30 seconds
    }

    initializeTabs() {
        // Show first tab by default
        this.switchTab('password-policy');
        
        // Add smooth transitions
        document.querySelectorAll('.tab-content').forEach(content => {
            content.style.transition = 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)';
        });
    }

    switchTab(tabId) {
        if (this.isLoading) return;

        // Update tab buttons
        document.querySelectorAll('.tab-button').forEach(button => {
            button.classList.remove('active');
            if (button.dataset.tab === tabId) {
                button.classList.add('active');
            }
        });

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
            if (content.id === tabId) {
                content.classList.add('active');
                this.loadTabContent(tabId);
            }
        });

        this.currentTab = tabId;
        this.animateTabSwitch();
    }

    animateTabSwitch() {
        const activeContent = document.querySelector('.tab-content.active');
        if (activeContent) {
            activeContent.style.opacity = '0';
            activeContent.style.transform = 'translateY(20px)';
            
            setTimeout(() => {
                activeContent.style.opacity = '1';
                activeContent.style.transform = 'translateY(0)';
            }, 50);
        }
    }

    async loadTabContent(tabId) {
        this.showLoading(tabId);
        
        try {
            switch (tabId) {
                case 'password-policy':
                    await this.loadPasswordPolicy();
                    break;
                case 'authentication':
                    await this.loadAuthenticationSettings();
                    break;
                case 'audit-log':
                    await this.loadAuditLog();
                    break;
                case 'incidents':
                    await this.loadIncidents();
                    await this.loadLockdownStatus();
                    break;
            }
        } catch (error) {
            this.showNotification('Error loading content: ' + error.message, 'error');
        } finally {
            this.hideLoading(tabId);
        }
    }

    showLoading(tabId) {
        const content = document.getElementById(tabId);
        if (content) {
            content.classList.add('loading');
        }
    }

    hideLoading(tabId) {
        const content = document.getElementById(tabId);
        if (content) {
            content.classList.remove('loading');
        }
    }

    async loadSecurityMetrics() {
        try {
            const response = await fetch(`${this.apiBase}/metrics.php`, {
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.updateMetricsDisplay(data.metrics);
            }
        } catch (error) {
            console.error('Error loading security metrics:', error);
            if (error.message.includes('403')) {
                this.showNotification('Access denied. Admin privileges required.', 'error');
            } else {
                this.showNotification('Failed to load security metrics', 'error');
            }
        }
    }

    updateMetricsDisplay(metrics) {
        const metricsContainer = document.getElementById('security-metrics');
        if (!metricsContainer) return;

        const metricsHtml = `
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="metric-content">
                    <h3>Failed Logins (24h)</h3>
                    <div class="metric-value">${metrics.failed_logins_24h || 0}</div>
                    <div class="metric-detail">Security incidents</div>
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <div class="metric-content">
                    <h3>Active Incidents</h3>
                    <div class="metric-value">${metrics.active_incidents || 0}</div>
                    <div class="metric-detail">Requiring attention</div>
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fas fa-ban"></i>
                </div>
                <div class="metric-content">
                    <h3>Blocked IPs</h3>
                    <div class="metric-value">${(metrics.blocked_ips_permanent || 0) + (metrics.blocked_ips_temporary || 0)}</div>
                    <div class="metric-detail">IP addresses blocked</div>
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-icon">
                    <i class="fas fa-clock"></i>
                </div>
                <div class="metric-content">
                    <h3>Recent Activity</h3>
                    <div class="metric-value">${metrics.unique_ips_last_hour || 0}</div>
                    <div class="metric-detail">Unique IPs (1h)</div>
                </div>
            </div>
        `;

        metricsContainer.innerHTML = metricsHtml;
        this.animateMetrics();
    }

    animateMetrics() {
        const metricCards = document.querySelectorAll('.metric-card');
        metricCards.forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';
            
            setTimeout(() => {
                card.style.transition = 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 100);
        });
    }

    async loadPasswordPolicy() {
        try {
            const response = await fetch(`${this.apiBase}/settings.php`, {
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.populatePasswordPolicyForm(data.data);
            }
        } catch (error) {
            console.error('Error loading password policy:', error);
            if (error.message.includes('403')) {
                this.showNotification('Access denied. Admin privileges required.', 'error');
            } else {
                this.showNotification('Failed to load password policy settings', 'error');
            }
        }
    }

    populatePasswordPolicyForm(settings) {
        // Populate form fields with current settings
        Object.keys(settings).forEach(key => {
            const input = document.querySelector(`[name="${key}"]`);
            if (input) {
                if (input.type === 'checkbox') {
                    input.checked = settings[key] === '1' || settings[key] === true;
                } else if (input.type === 'range') {
                    input.value = settings[key];
                    this.updateRangeValue(input);
                } else {
                    input.value = settings[key];
                }
            }
        });
    }

    async loadAuthenticationSettings() {
        try {
            const response = await fetch(`${this.apiBase}/settings.php`, {
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.populatePasswordPolicyForm(data.data);
            }
        } catch (error) {
            console.error('Error loading authentication settings:', error);
            this.showNotification('Failed to load authentication settings', 'error');
        }
    }


    async loadAuditLog() {
        try {
            const response = await fetch(`${this.apiBase}/audit-log.php`, {
                credentials: 'include'
            });
            const data = await response.json();
            
            if (data.success) {
                this.populateAuditLogTable(data.data || []);
            }
        } catch (error) {
            console.error('Error loading audit log:', error);
        }
    }

    populateAuditLogTable(logs) {
        const tbody = document.querySelector('#audit-log-table tbody');
        if (!tbody) return;

        tbody.innerHTML = logs.map(log => `
            <tr>
                <td>${new Date(log.created_at).toLocaleString()}</td>
                <td><span class="event-type">${log.event_type}</span></td>
                <td>${log.username || 'System'}</td>
                <td>
                    <span class="location-info">
                        ${log.country_flag || ''} ${log.location || 'Unknown Location'}
                    </span>
                </td>
                <td>
                    <span class="ip-address" title="${log.location || 'Unknown Location'}">
                        ${log.ip_address || 'N/A'}
                    </span>
                </td>
                <td>${log.description}</td>
            </tr>
        `).join('');
    }





    async loadIncidents() {
        try {
            const response = await fetch(`${this.apiBase}/incidents.php`, {
                credentials: 'include'
            });
            const data = await response.json();
            
            if (data.success) {
                this.populateIncidentsList(data.data || []);
            }
        } catch (error) {
            console.error('Error loading incidents:', error);
        }
    }

    populateIncidentsList(incidents) {
        const container = document.querySelector('.incidents-list');
        if (!container) return;

        container.innerHTML = incidents.map(incident => `
            <div class="incident-item">
                <div class="incident-header">
                    <span class="incident-type">${incident.incident_type}</span>
                    <span class="incident-severity severity-${incident.severity}">${incident.severity}</span>
                    <span class="incident-status status-${incident.status}">${incident.status}</span>
                </div>
                <div class="incident-description">${incident.description}</div>
                <div class="incident-time">Created: ${new Date(incident.created_at).toLocaleString()}</div>
            </div>
        `).join('');
    }

    updateRangeValue(slider) {
        // Update the value display in the slider labels
        const valueDisplay = slider.parentNode.querySelector('.slider-labels span:nth-child(2)');
        if (valueDisplay) {
            valueDisplay.textContent = slider.value;
        }
        
        // Also update any legacy range-value elements
        const legacyValueDisplay = slider.parentNode.querySelector('.range-value');
        if (legacyValueDisplay) {
            legacyValueDisplay.textContent = slider.value;
        }
    }

    setupFormValidation() {
        // Password strength validation
        const passwordInputs = document.querySelectorAll('input[type="password"]');
        passwordInputs.forEach(input => {
            input.addEventListener('input', (e) => {
                this.validatePasswordStrength(e.target);
            });
        });

        // Form validation on submit
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', (e) => {
                if (!this.validateForm(form)) {
                    e.preventDefault();
                }
            });
        });
    }

    validatePasswordStrength(input) {
        const password = input.value;
        const strength = this.calculatePasswordStrength(password);
        
        // Update strength indicator if it exists
        const indicator = input.parentNode.querySelector('.password-strength');
        if (indicator) {
            indicator.className = `password-strength strength-${strength.level}`;
            indicator.textContent = strength.text;
        }
    }

    calculatePasswordStrength(password) {
        let score = 0;
        let feedback = [];

        if (password.length >= 8) score += 1;
        else feedback.push('At least 8 characters');

        if (/[a-z]/.test(password)) score += 1;
        else feedback.push('Lowercase letters');

        if (/[A-Z]/.test(password)) score += 1;
        else feedback.push('Uppercase letters');

        if (/[0-9]/.test(password)) score += 1;
        else feedback.push('Numbers');

        if (/[^A-Za-z0-9]/.test(password)) score += 1;
        else feedback.push('Special characters');

        if (score <= 2) return { level: 'weak', text: 'Weak password' };
        if (score <= 3) return { level: 'fair', text: 'Fair password' };
        if (score <= 4) return { level: 'good', text: 'Good password' };
        return { level: 'strong', text: 'Strong password' };
    }

    validateForm(form) {
        let isValid = true;
        const requiredFields = form.querySelectorAll('[required]');
        
        requiredFields.forEach(field => {
            if (!field.value.trim()) {
                this.highlightField(field, 'error');
                isValid = false;
            } else {
                this.highlightField(field, 'success');
            }
        });

        return isValid;
    }

    highlightField(field, type) {
        field.classList.remove('error', 'success');
        field.classList.add(type);
        
        setTimeout(() => {
            field.classList.remove('error', 'success');
        }, 3000);
    }

    async handleFormSubmit(form) {
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());
        
        // Ensure all checkbox fields are included (unchecked checkboxes are not sent by default)
        const checkboxes = form.querySelectorAll('input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            if (!data.hasOwnProperty(checkbox.name)) {
                data[checkbox.name] = false;
            } else {
                data[checkbox.name] = true; // Convert 'on' to true
            }
        });
        
        this.showLoading(form.closest('.tab-content').id);
        
        // Determine the correct API endpoint based on form ID
        let endpoint = `${this.apiBase}/settings.php`;
        if (form.id === 'password-policy-form') {
            endpoint = `${this.apiBase}/settings.php?action=password-policy`;
        }
        
        try {
            console.log('Making request to:', endpoint);
            console.log('Sending data:', data);
            
            const response = await fetch(endpoint, {
                credentials: 'include',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            });
            
            console.log('Response status:', response.status);
            console.log('Response headers:', response.headers);
            
            // Check if response is ok
            if (!response.ok) {
                const errorText = await response.text();
                console.log('Error response text:', errorText);
                this.showNotification('Error saving settings: HTTP ' + response.status + ' - ' + errorText, 'error');
                return;
            }
            
            // Try to parse as JSON
            const responseText = await response.text();
            console.log('Raw response text:', responseText);
            
            let result;
            try {
                result = JSON.parse(responseText);
                console.log('Parsed JSON response:', result);
            } catch (parseError) {
                console.error('JSON parse error:', parseError);
                console.log('Response was not JSON:', responseText);
                this.showNotification('Error saving settings: Server returned non-JSON response: ' + response.status + ' ' + response.statusText, 'error');
                return;
            }
            
            if (result.success) {
                this.showNotification('Settings saved successfully', 'success');
                this.animateFormSuccess(form);
            } else {
                console.log('Error details:', result);
                const errorMessage = result.message || result.error || 'Unknown error occurred';
                this.showNotification('Error saving settings: ' + errorMessage, 'error');
            }
        } catch (error) {
            console.error('Network or other error:', error);
            this.showNotification('Error saving settings: ' + error.message, 'error');
        } finally {
            this.hideLoading(form.closest('.tab-content').id);
        }
    }

    animateFormSuccess(form) {
        form.style.transform = 'scale(1.02)';
        form.style.boxShadow = '0 8px 32px rgba(0, 153, 153, 0.3)';
        
        setTimeout(() => {
            form.style.transform = 'scale(1)';
            form.style.boxShadow = '';
        }, 500);
    }

    async handleEmergencyAction(button) {
        const action = button.dataset.action;
        console.log('handleEmergencyAction called with action:', action);
        
        if (!action) {
            console.error('No action found on button:', button);
            return;
        }
        
        const confirmed = await this.showConfirmation(
            `Are you sure you want to ${action}? This action cannot be undone.`,
            'Emergency Action Required'
        );
        
        if (confirmed) {
            console.log('User confirmed action:', action);
            this.executeEmergencyAction(action, button);
        } else {
            console.log('User cancelled action:', action);
        }
    }

    async executeEmergencyAction(action, button) {
        console.log('executeEmergencyAction called with action:', action);
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        button.disabled = true;
        
        try {
            // Map action names to API endpoints and required data
            const actionConfig = this.getActionConfig(action);
            console.log('Action config:', actionConfig);
            
            // Handle input requirements
            let finalData = { ...actionConfig.data };
            if (actionConfig.requiresInput) {
                const userInput = await this.showInputModal(
                    actionConfig.inputTitle,
                    actionConfig.inputMessage,
                    actionConfig.inputPlaceholder,
                    actionConfig.inputType
                );
                
                if (userInput === null) {
                    // User cancelled
                    button.innerHTML = originalText;
                    button.disabled = false;
                    return;
                }
                
                // Set the input value based on the action
                if (action === 'terminate-sessions') {
                    finalData.target_user = userInput || null;
                } else if (action === 'suspend-user') {
                    finalData.username = userInput;
                } else if (action === 'block-ip') {
                    finalData.ip = userInput;
                }
            }
            
            const endpoint = actionConfig.endpoint.replace('/', '');
            console.log('Making API call to:', `${this.apiBase}/incidents.php?action=${endpoint}`);
            console.log('Sending data:', finalData);
            
            const response = await fetch(`${this.apiBase}/incidents.php?action=${endpoint}`, {
                credentials: 'include',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(finalData)
            });
            
            console.log('Emergency action response status:', response.status);
            console.log('Emergency action response headers:', response.headers);
            
            const responseText = await response.text();
            console.log('Emergency action response text:', responseText);
            
            let result;
            try {
                result = JSON.parse(responseText);
            } catch (parseError) {
                console.error('JSON parse error:', parseError);
                console.error('Response was not JSON:', responseText);
                throw new Error(`Server returned non-JSON response: ${response.status} ${response.statusText}`);
            }
            
            if (result.success) {
                this.showNotification(result.message || `Emergency action executed: ${action}`, 'success');
            } else {
                this.showNotification(`Error executing action: ${result.error || result.message}`, 'error');
            }
        } catch (error) {
            this.showNotification(`Error executing action: ${error.message}`, 'error');
        } finally {
            button.innerHTML = originalText;
            button.disabled = false;
        }
    }

    getActionConfig(action) {
        switch (action) {
            case 'block-ip':
                return {
                    endpoint: '/block-ip',
                    data: {
                        ip: null, // Will be set by the modal
                        duration: 60, // 60 minutes
                        reason: 'Emergency block by admin'
                    },
                    requiresInput: true,
                    inputType: 'text',
                    inputTitle: 'Block IP Address',
                    inputMessage: 'Enter IP address to block:',
                    inputPlaceholder: '192.168.1.100'
                };
            case 'suspend-user':
                return {
                    endpoint: '/suspend-user',
                    data: {
                        username: null, // Will be set by the modal
                        reason: 'Emergency suspension by admin'
                    },
                    requiresInput: true,
                    inputType: 'text',
                    inputTitle: 'Suspend User',
                    inputMessage: 'Enter username to suspend:',
                    inputPlaceholder: 'username'
                };
            case 'terminate-sessions':
                return {
                    endpoint: '/terminate-sessions',
                    data: {
                        target_user: null, // Will be set by the modal
                        reason: 'Emergency session termination by admin'
                    },
                    requiresInput: true,
                    inputType: 'username',
                    inputTitle: 'Terminate User Sessions',
                    inputMessage: 'Enter username to terminate sessions (leave empty for all users):',
                    inputPlaceholder: 'Username (optional)'
                };
            case 'system-lockdown':
                return {
                    endpoint: '/lockdown',
                    data: {
                        reason: 'Emergency system lockdown by admin'
                    }
                };
            case 'clear-lockdown':
                return {
                    endpoint: '/clear-lockdown',
                    data: {
                        reason: 'Lockdown cleared by admin'
                    }
                };
            default:
                throw new Error(`Unknown action: ${action}`);
        }
    }

    async loadLockdownStatus() {
        try {
            const response = await fetch(`${this.apiBase}/incidents.php/lockdown-status`, {
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            this.displayLockdownStatus(data.data);
        } catch (error) {
            console.error('Error loading lockdown status:', error);
        }
    }

    displayLockdownStatus(lockdownStatus) {
        // Update banner (always visible)
        const banner = document.querySelector('#lockdown-status-banner');
        if (banner) {
            if (lockdownStatus.locked) {
                const expiresAt = lockdownStatus.expires_at ? new Date(lockdownStatus.expires_at) : null;
                const timeRemaining = expiresAt ? this.getTimeRemaining(expiresAt) : null;
                
                banner.innerHTML = `
                    <div class="lockdown-banner-alert">
                        <div class="lockdown-banner-content">
                            <div class="lockdown-banner-left">
                                <i class="fas fa-lock"></i>
                                <div class="lockdown-banner-text">
                                    <strong>SYSTEM LOCKDOWN ACTIVE</strong>
                                    <span>${lockdownStatus.reason || 'Emergency lockdown'} - ${timeRemaining ? `Expires in ${timeRemaining}` : 'No expiry set'}</span>
                                </div>
                            </div>
                            <div class="lockdown-banner-right">
                                <button class="btn btn-success btn-sm" id="clear-lockdown-banner-btn" data-action="clear-lockdown">
                                    <i class="fas fa-unlock"></i> Clear Lockdown
                                </button>
                            </div>
                        </div>
                    </div>
                `;
                banner.style.display = 'block';
                
                // Add event listener for clear lockdown button
                document.getElementById('clear-lockdown-banner-btn')?.addEventListener('click', () => {
                    this.executeEmergencyAction('clear-lockdown', document.getElementById('clear-lockdown-banner-btn'));
                });
            } else {
                banner.style.display = 'none';
            }
        }

        // Update navigation indicator (if exists)
        const navIndicator = document.querySelector('#lockdown-nav-indicator');
        if (navIndicator) {
            if (lockdownStatus.locked) {
                navIndicator.style.display = 'flex';
            } else {
                navIndicator.style.display = 'none';
            }
        }

        // Update incidents tab status (if visible)
        const container = document.querySelector('#lockdown-status');
        if (container) {
            if (lockdownStatus.locked) {
                const expiresAt = lockdownStatus.expires_at ? new Date(lockdownStatus.expires_at) : null;
                const timeRemaining = expiresAt ? this.getTimeRemaining(expiresAt) : null;
                
                container.innerHTML = `
                    <div class="lockdown-alert">
                        <div class="lockdown-header">
                            <i class="fas fa-lock"></i>
                            <h3>System Lockdown Active</h3>
                            <button class="btn btn-success btn-sm" id="clear-lockdown-btn" data-action="clear-lockdown">
                                <i class="fas fa-unlock"></i> Clear Lockdown
                            </button>
                        </div>
                        <div class="lockdown-details">
                            <p><strong>Reason:</strong> ${lockdownStatus.reason || 'Emergency lockdown'}</p>
                            <p><strong>Initiated:</strong> ${new Date(lockdownStatus.initiated_at).toLocaleString()}</p>
                            ${expiresAt ? `<p><strong>Expires:</strong> ${expiresAt.toLocaleString()}</p>` : ''}
                            ${timeRemaining ? `<p><strong>Time Remaining:</strong> <span class="time-remaining">${timeRemaining}</span></p>` : ''}
                        </div>
                    </div>
                `;
                
                // Add event listener for clear lockdown button
                document.getElementById('clear-lockdown-btn')?.addEventListener('click', () => {
                    this.executeEmergencyAction('clear-lockdown', document.getElementById('clear-lockdown-btn'));
                });
            } else {
                container.innerHTML = `
                    <div class="lockdown-status-normal">
                        <i class="fas fa-check-circle"></i>
                        <span>System is operating normally</span>
                    </div>
                `;
            }
        }
    }

    getTimeRemaining(expiresAt) {
        const now = new Date();
        const diff = expiresAt - now;
        
        if (diff <= 0) return 'Expired';
        
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        
        if (hours > 0) {
            return `${hours}h ${minutes}m`;
        } else {
            return `${minutes}m`;
        }
    }

    async blockIp(ipAddress) {
        const confirmed = await this.showConfirmation(
            `Block IP address ${ipAddress}? This will prevent all access from this IP.`,
            'Block IP Address'
        );
        
        if (confirmed) {
            try {
                const response = await fetch(`${this.apiBase}/failed-logins.php`, {
                    credentials: 'include',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ 
                        action: 'block_ip',
                        ip_address: ipAddress 
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    this.showNotification(`IP address ${ipAddress} blocked successfully`, 'success');
                    this.loadFailedLogins(); // Refresh the list
                } else {
                    this.showNotification(`Error blocking IP: ${result.message}`, 'error');
                }
            } catch (error) {
                this.showNotification(`Error blocking IP: ${error.message}`, 'error');
            }
        }
    }

    applyFilters() {
        const filters = {
            dateFrom: document.querySelector('#date-from')?.value,
            dateTo: document.querySelector('#date-to')?.value,
            username: document.querySelector('#username-filter')?.value,
            eventType: document.querySelector('#event-type-filter')?.value
        };
        
        // Apply filters to current tab
        switch (this.currentTab) {
            case 'audit-log':
                this.loadAuditLog(filters);
                break;
        }
    }

    sortTable(header) {
        const table = header.closest('table');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const column = header.dataset.sort;
        const isAscending = header.classList.contains('sort-asc');
        
        // Remove sort classes from all headers
        table.querySelectorAll('th').forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
        });
        
        // Add sort class to current header
        header.classList.add(isAscending ? 'sort-desc' : 'sort-asc');
        
        // Sort rows
        rows.sort((a, b) => {
            const aValue = a.querySelector(`td:nth-child(${header.cellIndex + 1})`).textContent;
            const bValue = b.querySelector(`td:nth-child(${header.cellIndex + 1})`).textContent;
            
            if (isAscending) {
                return aValue.localeCompare(bValue);
            } else {
                return bValue.localeCompare(aValue);
            }
        });
        
        // Re-append sorted rows
        rows.forEach(row => tbody.appendChild(row));
    }

    setupRealTimeUpdates() {
        // Update metrics every 30 seconds
        setInterval(() => {
            this.loadSecurityMetrics();
        }, 30000);
        
        // Update current tab data every 60 seconds
        setInterval(() => {
            this.loadTabContent(this.currentTab);
        }, 60000);
    }

    async refreshRealTimeData() {
        if (this.currentTab === 'audit-log') {
            await this.loadTabContent(this.currentTab);
        }
    }

    initializeTooltips() {
        // Add tooltips to buttons and form elements (excluding help icons)
        document.querySelectorAll('[data-tooltip]:not(.help-icon)').forEach(element => {
            element.addEventListener('mouseenter', (e) => {
                this.showTooltip(e.target, e.target.dataset.tooltip);
            });
            
            element.addEventListener('mouseleave', () => {
                this.hideTooltip();
            });
        });
        
        // Handle help icon modal
        const helpIcon = document.getElementById('lockdown-help-icon');
        const helpModal = document.getElementById('help-modal');
        const helpModalClose = document.getElementById('help-modal-close');
        const helpModalOk = document.getElementById('help-modal-ok');
        
        if (helpIcon && helpModal) {
            helpIcon.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.showHelpModal();
            });
        }
        
        if (helpModalClose) {
            helpModalClose.addEventListener('click', () => {
                this.hideHelpModal();
            });
        }
        
        if (helpModalOk) {
            helpModalOk.addEventListener('click', () => {
                this.hideHelpModal();
            });
        }
        
        // Close modal when clicking outside
        if (helpModal) {
            helpModal.addEventListener('click', (e) => {
                if (e.target === helpModal) {
                    this.hideHelpModal();
                }
            });
        }
        
        // Handle test password modal
        const testPasswordBtn = document.getElementById('test-password');
        const testPasswordModal = document.getElementById('test-password-modal');
        const testPasswordModalClose = document.getElementById('test-password-modal-close');
        const testPasswordModalCloseBtn = document.getElementById('test-password-modal-close-btn');
        const testPasswordSubmitBtn = document.getElementById('test-password-btn');
        
        if (testPasswordBtn && testPasswordModal) {
            testPasswordBtn.addEventListener('click', () => {
                this.showTestPasswordModal();
            });
        }
        
        if (testPasswordModalClose) {
            testPasswordModalClose.addEventListener('click', () => {
                this.hideTestPasswordModal();
            });
        }
        
        if (testPasswordModalCloseBtn) {
            testPasswordModalCloseBtn.addEventListener('click', () => {
                this.hideTestPasswordModal();
            });
        }
        
        if (testPasswordSubmitBtn) {
            testPasswordSubmitBtn.addEventListener('click', () => {
                this.testPassword();
            });
        }
        
        // Close test password modal when clicking outside
        if (testPasswordModal) {
            testPasswordModal.addEventListener('click', (e) => {
                if (e.target === testPasswordModal) {
                    this.hideTestPasswordModal();
                }
            });
        }
        
        // Close modal with ESC key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideHelpModal();
                this.hideTestPasswordModal();
            }
        });
    }

    showTooltip(element, text) {
        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip';
        tooltip.textContent = text;
        tooltip.style.cssText = `
            position: absolute;
            background: var(--siemens-petrol);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-size: 0.875rem;
            z-index: 1000;
            pointer-events: none;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        `;
        
        document.body.appendChild(tooltip);
        
        const rect = element.getBoundingClientRect();
        tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
        tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + 'px';
    }

    hideTooltip() {
        const tooltip = document.querySelector('.tooltip');
        if (tooltip) {
            tooltip.remove();
        }
    }

    showHelpModal() {
        const modal = document.getElementById('help-modal');
        if (modal) {
            modal.classList.add('show');
            document.body.style.overflow = 'hidden'; // Prevent background scrolling
        }
    }

    hideHelpModal() {
        const modal = document.getElementById('help-modal');
        if (modal) {
            modal.classList.remove('show');
            document.body.style.overflow = ''; // Restore scrolling
        }
    }

    showTestPasswordModal() {
        const modal = document.getElementById('test-password-modal');
        if (modal) {
            modal.classList.add('show');
            document.body.style.overflow = 'hidden'; // Prevent background scrolling
            // Clear previous results
            const resultsDiv = document.getElementById('password-test-results');
            if (resultsDiv) {
                resultsDiv.style.display = 'none';
                resultsDiv.innerHTML = '';
            }
            // Focus on input
            const input = document.getElementById('test-password-input');
            if (input) {
                input.value = '';
                input.focus();
            }
        }
    }

    hideTestPasswordModal() {
        const modal = document.getElementById('test-password-modal');
        if (modal) {
            modal.classList.remove('show');
            document.body.style.overflow = ''; // Restore scrolling
        }
    }

    async testPassword() {
        const password = document.getElementById('test-password-input').value;
        const resultsDiv = document.getElementById('password-test-results');
        
        if (!password) {
            this.showNotification('Please enter a password to test', 'error');
            return;
        }

        try {
            // Get current password policy settings
            console.log('Fetching password policy settings...');
            const response = await fetch(`${this.apiBase}/settings.php`, {
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            console.log('API Response:', data);
            
            if (!data.success) {
                throw new Error(data.error || 'Failed to load password policy');
            }
            
            const allSettings = data.data;
            console.log('All settings:', allSettings);
            console.log('Settings keys:', Object.keys(allSettings));
            
            // Extract password policy settings from the nested structure
            let settings = {};
            if (allSettings && allSettings.password_policy) {
                console.log('Password policy settings found:', allSettings.password_policy);
                // Convert array of settings to object
                settings = {};
                allSettings.password_policy.forEach(setting => {
                    settings[setting.setting_key] = setting.setting_value;
                });
                console.log('Converted password policy settings:', settings);
            }
            
            // If no password policy settings found, use default policy for testing
            if (!settings || Object.keys(settings).length === 0) {
                console.log('No password policy settings found, using default policy');
                settings = {
                    password_min_length: '8',
                    password_require_uppercase: '1',
                    password_require_lowercase: '1',
                    password_require_numbers: '1',
                    password_require_special: '1'
                };
            }
            
            console.log('Final settings for validation:', settings);
            console.log('Checking each requirement:');
            console.log('- password_require_uppercase:', settings.password_require_uppercase, typeof settings.password_require_uppercase);
            console.log('- password_require_lowercase:', settings.password_require_lowercase, typeof settings.password_require_lowercase);
            console.log('- password_require_numbers:', settings.password_require_numbers, typeof settings.password_require_numbers);
            console.log('- password_require_special:', settings.password_require_special, typeof settings.password_require_special);
            
            const results = this.validatePasswordAgainstPolicy(password, settings);
            console.log('Validation results:', results);
            
            // Display results
            resultsDiv.style.display = 'block';
            resultsDiv.innerHTML = this.generatePasswordTestResults(results, password);
            
        } catch (error) {
            console.error('Error testing password:', error);
            this.showNotification('Failed to test password: ' + error.message, 'error');
        }
    }

    validatePasswordAgainstPolicy(password, settings) {
        console.log('Validating password against policy:', { password, settings });
        
        const results = {
            valid: true,
            errors: [],
            warnings: [],
            score: 0,
            checks: {}
        };

        // Check minimum length
        const minLength = parseInt(settings.password_min_length || 8);
        console.log('Checking minimum length:', minLength, 'Password length:', password.length);
        if (password.length < minLength) {
            results.valid = false;
            results.errors.push(`Password must be at least ${minLength} characters long`);
        } else {
            results.score += 20;
        }
        results.checks.length = password.length >= minLength;

        // Check uppercase requirement
        console.log('Checking uppercase requirement:', settings.password_require_uppercase, 'Type:', typeof settings.password_require_uppercase);
        if (settings.password_require_uppercase === '1' || settings.password_require_uppercase === true) {
            console.log('Uppercase requirement is enabled, testing password for uppercase letters');
            if (!/[A-Z]/.test(password)) {
                console.log('Password does not contain uppercase letters, adding error');
                results.valid = false;
                results.errors.push('Password must contain at least one uppercase letter');
            } else {
                console.log('Password contains uppercase letters, adding score');
                results.score += 15;
            }
            results.checks.uppercase = /[A-Z]/.test(password);
        } else {
            console.log('Uppercase requirement is disabled');
        }

        // Check lowercase requirement
        console.log('Checking lowercase requirement:', settings.password_require_lowercase, 'Type:', typeof settings.password_require_lowercase);
        if (settings.password_require_lowercase === '1' || settings.password_require_lowercase === true) {
            console.log('Lowercase requirement is enabled, testing password for lowercase letters');
            if (!/[a-z]/.test(password)) {
                console.log('Password does not contain lowercase letters, adding error');
                results.valid = false;
                results.errors.push('Password must contain at least one lowercase letter');
            } else {
                console.log('Password contains lowercase letters, adding score');
                results.score += 15;
            }
            results.checks.lowercase = /[a-z]/.test(password);
        } else {
            console.log('Lowercase requirement is disabled');
        }

        // Check number requirement
        console.log('Checking number requirement:', settings.password_require_numbers, 'Type:', typeof settings.password_require_numbers);
        if (settings.password_require_numbers === '1' || settings.password_require_numbers === true) {
            console.log('Number requirement is enabled, testing password for numbers');
            if (!/\d/.test(password)) {
                console.log('Password does not contain numbers, adding error');
                results.valid = false;
                results.errors.push('Password must contain at least one number');
            } else {
                console.log('Password contains numbers, adding score');
                results.score += 15;
            }
            results.checks.numbers = /\d/.test(password);
        } else {
            console.log('Number requirement is disabled');
        }

        // Check special character requirement
        console.log('Checking special character requirement:', settings.password_require_special, 'Type:', typeof settings.password_require_special);
        if (settings.password_require_special === '1' || settings.password_require_special === true) {
            console.log('Special character requirement is enabled, testing password for special characters');
            if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
                console.log('Password does not contain special characters, adding error');
                results.valid = false;
                results.errors.push('Password must contain at least one special character');
            } else {
                console.log('Password contains special characters, adding score');
                results.score += 15;
            }
            results.checks.special = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
        } else {
            console.log('Special character requirement is disabled');
        }

        // Additional strength checks
        if (password.length >= 12) {
            results.score += 10;
        }
        if (password.length >= 16) {
            results.score += 10;
        }

        // Check for common patterns
        if (/(.)\1{2,}/.test(password)) {
            results.warnings.push('Password contains repeated characters');
        }

        if (/123|abc|qwe|asd|zxc/i.test(password)) {
            results.warnings.push('Password contains common sequences');
        }

        return results;
    }

    generatePasswordTestResults(results, password) {
        const strength = results.score >= 80 ? 'Strong' : results.score >= 60 ? 'Medium' : results.score >= 40 ? 'Weak' : 'Very Weak';
        const strengthColor = results.score >= 80 ? '#10b981' : results.score >= 60 ? '#f59e0b' : results.score >= 40 ? '#f97316' : '#ef4444';
        
        let html = `
            <div style="margin-bottom: 1rem;">
                <h4 style="margin: 0 0 0.5rem 0; color: var(--text-primary);">Password Test Results</h4>
                <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                    <span style="font-weight: 600;">Strength:</span>
                    <span style="color: ${strengthColor}; font-weight: 600;">${strength}</span>
                    <span style="color: var(--text-muted);">(${results.score}/100)</span>
                </div>
                <div style="width: 100%; height: 8px; background: var(--border-primary); border-radius: 4px; overflow: hidden;">
                    <div style="width: ${results.score}%; height: 100%; background: ${strengthColor}; transition: width 0.3s ease;"></div>
                </div>
            </div>
        `;

        if (results.valid) {
            html += `<div style="color: #10b981; margin-bottom: 1rem;"><i class="fas fa-check-circle"></i> Password meets all policy requirements</div>`;
        } else {
            html += `<div style="color: #ef4444; margin-bottom: 1rem;"><i class="fas fa-times-circle"></i> Password does not meet policy requirements</div>`;
        }

        if (results.errors.length > 0) {
            html += `<div style="margin-bottom: 1rem;"><h5 style="color: #ef4444; margin: 0 0 0.5rem 0;">Errors:</h5><ul style="margin: 0; padding-left: 1.5rem; color: #ef4444;">`;
            results.errors.forEach(error => {
                html += `<li>${error}</li>`;
            });
            html += `</ul></div>`;
        }

        if (results.warnings.length > 0) {
            html += `<div style="margin-bottom: 1rem;"><h5 style="color: #f59e0b; margin: 0 0 0.5rem 0;">Warnings:</h5><ul style="margin: 0; padding-left: 1.5rem; color: #f59e0b;">`;
            results.warnings.forEach(warning => {
                html += `<li>${warning}</li>`;
            });
            html += `</ul></div>`;
        }

        html += `<div><h5 style="color: var(--text-primary); margin: 0 0 0.5rem 0;">Requirements Check:</h5>`;
        html += `<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-size: 0.9rem;">`;
        
        Object.entries(results.checks).forEach(([check, passed]) => {
            const icon = passed ? 'fa-check' : 'fa-times';
            const color = passed ? '#10b981' : '#ef4444';
            const label = check.charAt(0).toUpperCase() + check.slice(1);
            html += `<div style="display: flex; align-items: center; gap: 0.5rem; color: ${color};">
                <i class="fas ${icon}"></i> ${label}
            </div>`;
        });
        
        html += `</div></div>`;

        return html;
    }

    showInputModal(title, message, placeholder, inputType = 'text') {
        return new Promise((resolve) => {
            // Create modal overlay
            const overlay = document.createElement('div');
            overlay.className = 'input-modal-overlay';
            overlay.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.7);
                z-index: 10001;
                display: flex;
                align-items: center;
                justify-content: center;
                animation: modalFadeIn 0.3s ease;
            `;

            // Create modal content
            const modal = document.createElement('div');
            modal.className = 'input-modal-content';
            modal.style.cssText = `
                background: var(--bg-card, #1a1a1a);
                border-radius: 0.75rem;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                max-width: 500px;
                width: 90%;
                animation: modalSlideIn 0.3s ease;
            `;

            modal.innerHTML = `
                <div style="padding: 1.5rem; border-bottom: 1px solid var(--border-primary, #333); background: linear-gradient(135deg, var(--siemens-petrol, #009999) 0%, var(--siemens-petrol-dark, #007777) 100%); color: white; border-radius: 0.75rem 0.75rem 0 0;">
                    <h3 style="margin: 0; font-size: 1.25rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem;">
                        <i class="fas fa-exclamation-triangle"></i> ${title}
                    </h3>
                </div>
                <div style="padding: 1.5rem; color: var(--text-primary, #f8fafc);">
                    <p style="margin-bottom: 1rem; line-height: 1.6;">${message}</p>
                    <div style="margin-bottom: 1.5rem;">
                        <input type="${inputType}" id="input-modal-field" placeholder="${placeholder}" 
                               style="width: 100%; padding: 0.75rem 1rem; border: 1px solid var(--border-primary, #333); border-radius: 0.5rem; background: var(--bg-secondary, #333); color: var(--text-primary, #f8fafc); font-size: 1rem; outline: none; transition: border-color 0.3s ease;"
                               onfocus="this.style.borderColor='var(--siemens-petrol, #009999)'"
                               onblur="this.style.borderColor='var(--border-primary, #333)'">
                    </div>
                </div>
                <div style="padding: 1rem 1.5rem; border-top: 1px solid var(--border-primary, #333); background: var(--bg-secondary, #333); border-radius: 0 0 0.75rem 0.75rem; text-align: right; display: flex; gap: 0.75rem; justify-content: flex-end;">
                    <button id="input-modal-cancel" style="padding: 0.5rem 1rem; background: var(--bg-tertiary, #555); color: var(--text-primary, #f8fafc); border: 1px solid var(--border-primary, #333); border-radius: 0.5rem; cursor: pointer; transition: all 0.3s ease; font-weight: 500;">
                        Cancel
                    </button>
                    <button id="input-modal-confirm" style="padding: 0.5rem 1rem; background: var(--siemens-petrol, #009999); color: white; border: 1px solid var(--siemens-petrol, #009999); border-radius: 0.5rem; cursor: pointer; transition: all 0.3s ease; font-weight: 500;">
                        Confirm
                    </button>
                </div>
            `;

            overlay.appendChild(modal);
            document.body.appendChild(overlay);
            document.body.style.overflow = 'hidden';

            // Focus on input field
            const inputField = modal.querySelector('#input-modal-field');
            inputField.focus();

            // Handle Enter key
            inputField.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    document.getElementById('input-modal-confirm').click();
                }
            });

            // Handle Escape key
            overlay.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    e.preventDefault();
                    document.getElementById('input-modal-cancel').click();
                }
            });

            // Handle button clicks
            document.getElementById('input-modal-cancel').addEventListener('click', () => {
                document.body.removeChild(overlay);
                document.body.style.overflow = '';
                resolve(null);
            });

            document.getElementById('input-modal-confirm').addEventListener('click', () => {
                const value = inputField.value.trim();
                document.body.removeChild(overlay);
                document.body.style.overflow = '';
                resolve(value);
            });

            // Handle overlay click
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay) {
                    document.getElementById('input-modal-cancel').click();
                }
            });
        });
    }

    setupKeyboardNavigation() {
        // Tab navigation with keyboard
        document.addEventListener('keydown', (e) => {
            if (e.altKey && e.key >= '1' && e.key <= '6') {
                const tabIndex = parseInt(e.key) - 1;
                const tabs = document.querySelectorAll('.tab-button');
                if (tabs[tabIndex]) {
                    tabs[tabIndex].click();
                }
            }
        });
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                ${message}
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => notification.remove(), 300);
        }, 5000);
    }

    async showConfirmation(message, title = 'Confirm Action') {
        return new Promise((resolve) => {
            const modal = document.createElement('div');
            modal.className = 'confirmation-modal';
            modal.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 1000;
            `;
            
            modal.innerHTML = `
                <div style="
                    background: var(--bg-card);
                    padding: 2rem;
                    border-radius: 1rem;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                    max-width: 400px;
                    text-align: center;
                ">
                    <h3 style="margin-bottom: 1rem; color: var(--text-primary);">${title}</h3>
                    <p style="margin-bottom: 2rem; color: var(--text-secondary);">${message}</p>
                    <div style="display: flex; gap: 1rem; justify-content: center;">
                        <button class="btn btn-secondary" onclick="this.closest('.confirmation-modal').remove(); window.securityManagerConfirmation = false;">
                            Cancel
                        </button>
                        <button class="btn btn-danger" onclick="this.closest('.confirmation-modal').remove(); window.securityManagerConfirmation = true;">
                            Confirm
                        </button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
            
            // Handle button clicks
            modal.querySelectorAll('button').forEach(button => {
                button.addEventListener('click', () => {
                    resolve(window.securityManagerConfirmation);
                    delete window.securityManagerConfirmation;
                });
            });
        });
    }
}

// Initialize Security Manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.securityManager = new SecurityManager();
});

// Export for global access
window.SecurityManager = SecurityManager;