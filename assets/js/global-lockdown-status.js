/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

class GlobalLockdownStatus {
    constructor() {
        this.apiBase = '/api/v1/admin/security';
        this.updateInterval = 30000; // 30 seconds
        this.updateTimer = null;
        this.errorCount = 0;
        this.maxErrors = 3; // Stop after 3 consecutive errors
        this.init();
    }

    async init() {
        await this.loadLockdownStatus();
        this.startPeriodicUpdates();
    }

    async loadLockdownStatus() {
        try {
            // Use dynamic base URL detection to prevent CORS issues
            const protocol = window.location.protocol;
            const host = window.location.host;
            const baseUrl = `${protocol}//${host}`;
            const response = await fetch(`${baseUrl}${this.apiBase}/incidents.php?action=lockdown-status`, {
                credentials: 'include'
            });
            
            if (!response.ok) {
                // If 403 Forbidden, user doesn't have admin access - this is normal for regular users
                if (response.status === 403) {
                    console.log('User does not have admin access to lockdown status - this is normal for regular users');
                    return;
                }
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            this.displayLockdownStatus(data.data);
            this.errorCount = 0; // Reset error count on success
        } catch (error) {
            // Only log errors that aren't permission-related
            if (!error.message.includes('403')) {
                this.errorCount++;
                console.error('Error loading lockdown status:', error);
                
                // Stop polling after too many errors
                if (this.errorCount >= this.maxErrors) {
                    console.warn('Too many lockdown status errors. Stopping automatic polling.');
                    this.stopPeriodicUpdates();
                }
            }
        }
    }

    displayLockdownStatus(lockdownStatus) {
        // Update navigation indicator
        const navIndicator = document.querySelector('#lockdown-nav-indicator');
        if (navIndicator) {
            if (lockdownStatus.locked) {
                navIndicator.style.display = 'flex';
            } else {
                navIndicator.style.display = 'none';
            }
        }

        // Update banner (if exists)
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
                    this.clearLockdown();
                });
            } else {
                banner.style.display = 'none';
            }
        }

        // Update incidents tab status (if exists)
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
                    this.clearLockdown();
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

    async clearLockdown() {
        const confirmed = confirm('Are you sure you want to clear the system lockdown?');
        if (!confirmed) return;

        try {
            const response = await fetch(`${this.apiBase}/incidents.php?action=clear-lockdown`, {
                credentials: 'include',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({})
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const result = await response.json();
            
            if (result.success) {
                this.showNotification('System lockdown cleared successfully', 'success');
                await this.loadLockdownStatus(); // Refresh status
            } else {
                this.showNotification(`Error clearing lockdown: ${result.error || result.message}`, 'error');
            }
        } catch (error) {
            console.error('Error clearing lockdown:', error);
            this.showNotification('Error clearing lockdown: ' + error.message, 'error');
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

    startPeriodicUpdates() {
        // Only start if not already running and error count is below threshold
        if (!this.updateTimer && this.errorCount < this.maxErrors) {
            this.updateTimer = setInterval(() => {
                this.loadLockdownStatus();
            }, this.updateInterval);
        }
    }

    stopPeriodicUpdates() {
        if (this.updateTimer) {
            clearInterval(this.updateTimer);
            this.updateTimer = null;
        }
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        
        // Style the notification
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 0.5rem;
            color: white;
            font-weight: 600;
            z-index: 10000;
            animation: slideInRight 0.3s ease;
            max-width: 400px;
        `;
        
        // Set background color based on type
        switch (type) {
            case 'success':
                notification.style.backgroundColor = '#10b981';
                break;
            case 'error':
                notification.style.backgroundColor = '#ef4444';
                break;
            case 'warning':
                notification.style.backgroundColor = '#f59e0b';
                break;
            default:
                notification.style.backgroundColor = '#009999';
        }
        
        // Add to page
        document.body.appendChild(notification);
        
        // Remove after 5 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 5000);
    }
}

// Initialize global lockdown status when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.globalLockdownStatus = new GlobalLockdownStatus();
});

// Stop polling when page is hidden or user navigates away
document.addEventListener('visibilitychange', () => {
    if (window.globalLockdownStatus) {
        if (document.hidden) {
            window.globalLockdownStatus.stopPeriodicUpdates();
        } else if (window.globalLockdownStatus.errorCount < window.globalLockdownStatus.maxErrors) {
            window.globalLockdownStatus.startPeriodicUpdates();
            window.globalLockdownStatus.loadLockdownStatus();
        }
    }
});

// Stop polling before page unload
window.addEventListener('beforeunload', () => {
    if (window.globalLockdownStatus) {
        window.globalLockdownStatus.stopPeriodicUpdates();
    }
});

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);
