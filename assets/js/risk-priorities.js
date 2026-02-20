/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

/**
 * Generate priority tier badge HTML
 * @param {number} tier - Priority tier (1, 2, or 3)
 * @returns {string} HTML for priority badge
 */
function generatePriorityBadge(tier) {
    return `<span class="priority-badge priority-badge-tier-${tier}">
        <svg class="priority-badge-icon" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
        </svg>
        ${tier}
    </span>`;
}

/**
 * Generate KEV badge HTML
 * @returns {string} HTML for KEV badge
 */
function generateKEVBadge() {
    return `<span class="kev-badge">
        <svg class="kev-badge-icon" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2.001A11.954 11.954 0 0110 1.944zM11 14a1 1 0 11-2 0 1 1 0 012 0zm0-7a1 1 0 10-2 0v3a1 1 0 102 0V7z" clip-rule="evenodd" />
        </svg>
        KEV
    </span>`;
}

/**
 * Generate overdue badge HTML
 * @param {number} daysOverdue - Number of days overdue
 * @returns {string} HTML for overdue badge
 */
function generateOverdueBadge(daysOverdue) {
    if (daysOverdue <= 0) return '';
    
    return `<span class="overdue-badge">
        <svg class="overdue-badge-icon" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd" />
        </svg>
        ${daysOverdue}d OVERDUE
    </span>`;
}

/**
 * Generate vendor status badge HTML
 * @param {string} status - Vendor status
 * @returns {string} HTML for vendor status badge
 */
function generateVendorStatusBadge(status) {
    if (!status) return '<span class="vendor-status-badge vendor-status-not-contacted">Not Contacted</span>';
    
    const statusClasses = {
        'Not Contacted': 'not-contacted',
        'Contacted': 'contacted',
        'Patch Available': 'patch-available',
        'Patch Pending': 'patch-pending',
        'No Patch Available': 'no-patch',
        'End of Life': 'eol'
    };
    
    const cssClass = statusClasses[status] || 'not-contacted';
    return `<span class="vendor-status-badge vendor-status-${cssClass}">${status}</span>`;
}

/**
 * Generate risk score indicator HTML
 * @param {number} score - Risk score
 * @returns {string} HTML for risk score indicator
 */
function generateRiskScoreIndicator(score) {
    let level = 'low';
    if (score >= 1000) level = 'critical';
    else if (score >= 150) level = 'high';
    else if (score >= 75) level = 'medium';
    
    return `<span class="risk-score risk-score-${level}">${score}</span>`;
}

/**
 * Generate criticality badge HTML
 * @param {string} criticality - Asset criticality
 * @returns {string} HTML for criticality badge
 */
function generateCriticalityBadge(criticality) {
    if (!criticality) return '';
    
    const classes = {
        'Clinical-High': 'clinical-high',
        'Business-Medium': 'business-medium',
        'Non-Essential': 'non-essential'
    };
    
    const cssClass = classes[criticality] || 'non-essential';
    return `<span class="criticality-badge criticality-${cssClass}">${criticality}</span>`;
}

/**
 * Generate location criticality indicator HTML
 * @param {number} criticality - Location criticality (1-10)
 * @returns {string} HTML for location criticality indicator
 */
function generateLocationCriticality(criticality) {
    if (!criticality) return '';
    
    const dots = [];
    for (let i = 1; i <= 10; i++) {
        const isActive = i <= criticality;
        const isHigh = i <= criticality && criticality >= 8;
        const activeClass = isActive ? (isHigh ? 'active active-high' : 'active') : '';
        dots.push(`<span class="location-criticality-dot ${activeClass}"></span>`);
    }
    
    return `<div class="location-criticality">
        <span class="location-criticality-dots">${dots.join('')}</span>
        <span>${criticality}/10</span>
    </div>`;
}

/**
 * Generate status pill HTML
 * @param {string} status - Remediation status
 * @returns {string} HTML for status pill
 */
function generateStatusPill(status) {
    const classes = {
        'Open': 'open',
        'In Progress': 'in-progress',
        'Resolved': 'resolved',
        'Mitigated': 'mitigated'
    };
    
    const cssClass = classes[status] || 'open';
    return `<span class="status-pill status-${cssClass}">${status}</span>`;
}

/**
 * Load priorities and populate table
 * @param {object} filters - Filter parameters
 */
async function loadPriorities(filters = {}) {
    try {
        const params = new URLSearchParams(filters);
        const response = await fetch(`/api/v1/risk-priorities?${params.toString()}`);
        const result = await response.json();
        
        if (result.success) {
            populatePrioritiesTable(result.data);
            updatePagination(result.total, result.limit, result.offset);
        } else {
            showError('Failed to load priorities: ' + result.error);
        }
    } catch (error) {
        showError('Error loading priorities: ' + error.message);
    }
}

/**
 * Load priority statistics
 */
async function loadPriorityStats() {
    try {
        const response = await fetch('/api/v1/risk-priorities/stats');
        const result = await response.json();
        
        if (result.success) {
            updateTierCards(result.data.tiers);
            updateVendorStats(result.data.vendor_stats);
            updateDepartmentStats(result.data.department_stats);
            updateKEVStats(result.data.kev_stats);
            updateTopRisks(result.data.top_risks);
        } else {
            showError('Failed to load statistics: ' + result.error);
        }
    } catch (error) {
        showError('Error loading statistics: ' + error.message);
    }
}

/**
 * Update priority details
 * @param {string} linkId - Link ID
 * @param {object} data - Update data
 */
async function updatePriority(linkId, data) {
    try {
        const response = await fetch(`/api/v1/risk-priorities/${linkId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (result.success) {
            showSuccess('Priority updated successfully');
            return true;
        } else {
            showError('Failed to update priority: ' + result.error);
            return false;
        }
    } catch (error) {
        showError('Error updating priority: ' + error.message);
        return false;
    }
}

/**
 * Update vendor tracking
 * @param {string} linkId - Link ID
 * @param {object} vendorData - Vendor tracking data
 */
async function updateVendorTracking(linkId, vendorData) {
    try {
        const response = await fetch(`/api/v1/risk-priorities/${linkId}/vendor`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(vendorData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            showSuccess('Vendor tracking updated successfully');
            return true;
        } else {
            showError('Failed to update vendor tracking: ' + result.error);
            return false;
        }
    } catch (error) {
        showError('Error updating vendor tracking: ' + error.message);
        return false;
    }
}

/**
 * Add compensating control
 * @param {string} linkId - Link ID
 * @param {object} controlData - Control data
 */
async function addCompensatingControl(linkId, controlData) {
    try {
        const response = await fetch(`/api/v1/risk-priorities/${linkId}/controls`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(controlData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            showSuccess('Compensating control added successfully');
            return result.control_id;
        } else {
            showError('Failed to add control: ' + result.error);
            return null;
        }
    } catch (error) {
        showError('Error adding control: ' + error.message);
        return null;
    }
}

/**
 * Load compensating controls
 * @param {string} linkId - Link ID
 */
async function loadCompensatingControls(linkId) {
    try {
        const response = await fetch(`/api/v1/risk-priorities/${linkId}/controls`);
        const result = await response.json();
        
        if (result.success) {
            return result.data;
        } else {
            showError('Failed to load controls: ' + result.error);
            return [];
        }
    } catch (error) {
        showError('Error loading controls: ' + error.message);
        return [];
    }
}

/**
 * Refresh risk priority view
 */
async function refreshRiskPriorities() {
    try {
        const response = await fetch('/api/v1/risk-priorities/refresh', {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (result.success) {
            showSuccess('Risk priorities refreshed successfully');
            return true;
        } else {
            showError('Failed to refresh: ' + result.error);
            return false;
        }
    } catch (error) {
        showError('Error refreshing priorities: ' + error.message);
        return false;
    }
}

/**
 * Show success message
 * @param {string} message - Success message
 */
function showSuccess(message) {
    // Implementation depends on your notification system
    console.log('SUCCESS:', message);
    alert(message); // Replace with better notification
}

/**
 * Show error message
 * @param {string} message - Error message
 */
function showError(message) {
    // Implementation depends on your notification system
    console.error('ERROR:', message);
    alert(message); // Replace with better notification
}

/**
 * Populate priorities table (placeholder - implement based on your table structure)
 */
function populatePrioritiesTable(data) {
    // To be implemented based on specific table structure
    console.log('Populating table with', data.length, 'items');
}

/**
 * Update pagination (placeholder)
 */
function updatePagination(total, limit, offset) {
    // To be implemented based on your pagination structure
    console.log('Pagination:', {total, limit, offset});
}

/**
 * Update tier cards (placeholder)
 */
function updateTierCards(tiers) {
    // To be implemented
    console.log('Updating tier cards:', tiers);
}

/**
 * Update vendor stats (placeholder)
 */
function updateVendorStats(stats) {
    // To be implemented
    console.log('Updating vendor stats:', stats);
}

/**
 * Update department stats (placeholder)
 */
function updateDepartmentStats(stats) {
    // To be implemented
    console.log('Updating department stats:', stats);
}

/**
 * Update KEV stats (placeholder)
 */
function updateKEVStats(stats) {
    // To be implemented
    console.log('Updating KEV stats:', stats);
}

/**
 * Update top risks (placeholder)
 */
function updateTopRisks(risks) {
    // To be implemented
    console.log('Updating top risks:', risks);
}

