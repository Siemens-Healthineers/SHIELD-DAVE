/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

/**
 * EPSS Utility Functions
 * Provides functions for EPSS score display, formatting, and visualization
 */

// EPSS risk level thresholds
const EPSS_THRESHOLDS = {
    HIGH: 0.7,    // 70% and above
    MEDIUM: 0.3,  // 30% to 69%
    LOW: 0.0      // Below 30%
};

/**
 * Get EPSS risk level based on score
 * @param {number} score - EPSS score (0.0 to 1.0)
 * @returns {string} Risk level: 'high', 'medium', 'low', or 'unknown'
 */
function getEPSSRiskLevel(score) {
    if (score === null || score === undefined || isNaN(score)) {
        return 'unknown';
    }
    
    if (score >= EPSS_THRESHOLDS.HIGH) {
        return 'high';
    } else if (score >= EPSS_THRESHOLDS.MEDIUM) {
        return 'medium';
    } else {
        return 'low';
    }
}

/**
 * Format EPSS score as percentage
 * @param {number} score - EPSS score (0.0 to 1.0)
 * @param {number} decimals - Number of decimal places (default: 1)
 * @returns {string} Formatted percentage string
 */
function formatEPSSScore(score, decimals = 1) {
    if (score === null || score === undefined || isNaN(score)) {
        return 'N/A';
    }
    
    return (score * 100).toFixed(decimals) + '%';
}

/**
 * Format EPSS percentile as percentage
 * @param {number} percentile - EPSS percentile (0.0 to 1.0)
 * @param {number} decimals - Number of decimal places (default: 1)
 * @returns {string} Formatted percentile string
 */
function formatEPSSPercentile(percentile, decimals = 1) {
    if (percentile === null || percentile === undefined || isNaN(percentile)) {
        return 'N/A';
    }
    
    return (percentile * 100).toFixed(decimals) + '%';
}

/**
 * Generate EPSS badge HTML
 * @param {number} score - EPSS score (0.0 to 1.0)
 * @param {number} percentile - EPSS percentile (0.0 to 1.0)
 * @param {boolean} showPercentile - Whether to show percentile in tooltip
 * @returns {string} HTML for EPSS badge
 */
function generateEPSSBadge(score, percentile = null, showPercentile = true) {
    const riskLevel = getEPSSRiskLevel(score);
    const formattedScore = formatEPSSScore(score);
    
    let tooltipText = `EPSS Score: ${formattedScore}`;
    if (showPercentile && percentile !== null && percentile !== undefined) {
        const formattedPercentile = formatEPSSPercentile(percentile);
        tooltipText += `\\nPercentile: ${formattedPercentile}`;
    }
    
    const badgeClass = `epss-badge epss-badge-${riskLevel}`;
    
    return `<span class="${badgeClass}" title="${tooltipText}">
        <svg class="epss-badge-icon" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd" />
        </svg>
        ${formattedScore}
    </span>`;
}

/**
 * Generate EPSS score display with progress bar
 * @param {number} score - EPSS score (0.0 to 1.0)
 * @param {number} percentile - EPSS percentile (0.0 to 1.0)
 * @returns {string} HTML for EPSS score display
 */
function generateEPSSScoreDisplay(score, percentile = null) {
    const riskLevel = getEPSSRiskLevel(score);
    const formattedScore = formatEPSSScore(score);
    const formattedPercentile = percentile ? formatEPSSPercentile(percentile) : null;
    
    return `
        <div class="epss-score-display">
            <div class="epss-score-value ${riskLevel}">${formattedScore}</div>
            <div class="epss-score-label">Exploitation Probability</div>
            ${formattedPercentile ? `<div class="epss-percentile">${formattedPercentile} percentile</div>` : ''}
            <div class="epss-progress">
                <div class="epss-progress-bar ${riskLevel}" style="width: ${(score * 100)}%"></div>
            </div>
        </div>
    `;
}

/**
 * Generate EPSS info tooltip
 * @param {string} text - Tooltip text content
 * @returns {string} HTML for info tooltip
 */
function generateEPSSInfoTooltip(text) {
    return `
        <span class="epss-info-tooltip">
            <i class="fas fa-info-circle tooltip-icon"></i>
            <span class="tooltip-content">${text}</span>
        </span>
    `;
}

/**
 * Generate EPSS legend
 * @returns {string} HTML for EPSS legend
 */
function generateEPSSLegend() {
    return `
        <div class="epss-legend">
            <div class="epss-legend-item">
                <div class="epss-legend-color high"></div>
                <span>High Risk (≥70%)</span>
            </div>
            <div class="epss-legend-item">
                <div class="epss-legend-color medium"></div>
                <span>Medium Risk (30-69%)</span>
            </div>
            <div class="epss-legend-item">
                <div class="epss-legend-color low"></div>
                <span>Low Risk (<30%)</span>
            </div>
        </div>
    `;
}

/**
 * Create EPSS trend chart using Chart.js
 * @param {string} canvasId - Canvas element ID
 * @param {Array} trendData - Array of {date, score, percentile} objects
 * @param {Object} options - Chart options
 * @returns {Chart} Chart.js instance
 */
function createEPSSTrendChart(canvasId, trendData, options = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) {
        console.error(`Canvas element with ID '${canvasId}' not found`);
        return null;
    }
    
    const defaultOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: {
                    color: '#cbd5e1'
                }
            },
            tooltip: {
                backgroundColor: '#1a1a1a',
                titleColor: '#ffffff',
                bodyColor: '#cbd5e1',
                borderColor: '#333333',
                borderWidth: 1
            }
        },
        scales: {
            x: {
                ticks: {
                    color: '#94a3b8'
                },
                grid: {
                    color: '#333333'
                }
            },
            y: {
                beginAtZero: true,
                max: 1,
                ticks: {
                    color: '#94a3b8',
                    callback: function(value) {
                        return (value * 100).toFixed(0) + '%';
                    }
                },
                grid: {
                    color: '#333333'
                }
            }
        }
    };
    
    const chartOptions = { ...defaultOptions, ...options };
    
    const chartData = {
        labels: trendData.map(item => {
            const date = new Date(item.date);
            return date.toLocaleDateString();
        }),
        datasets: [{
            label: 'EPSS Score',
            data: trendData.map(item => item.score),
            borderColor: '#009999',
            backgroundColor: 'rgba(0, 153, 153, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
        }]
    };
    
    return new Chart(ctx, {
        type: 'line',
        data: chartData,
        options: chartOptions
    });
}

/**
 * Create EPSS mini sparkline chart
 * @param {string} canvasId - Canvas element ID
 * @param {Array} trendData - Array of score values
 * @returns {Chart} Chart.js instance
 */
function createEPSSMiniChart(canvasId, trendData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) {
        console.error(`Canvas element with ID '${canvasId}' not found`);
        return null;
    }
    
    const riskLevel = getEPSSRiskLevel(trendData[trendData.length - 1]);
    const colors = {
        high: '#ef4444',
        medium: '#f59e0b',
        low: '#009999'
    };
    
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: trendData.map((_, index) => index),
            datasets: [{
                data: trendData,
                borderColor: colors[riskLevel],
                backgroundColor: colors[riskLevel] + '20',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: true,
                    backgroundColor: '#1a1a1a',
                    titleColor: '#ffffff',
                    bodyColor: '#cbd5e1',
                    borderColor: '#333333',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            return 'EPSS: ' + formatEPSSScore(context.parsed.y);
                        }
                    }
                }
            },
            scales: {
                x: {
                    display: false
                },
                y: {
                    display: false,
                    beginAtZero: true,
                    max: 1
                }
            },
            interaction: {
                intersect: false
            }
        }
    });
}

/**
 * Load EPSS trend data for a CVE
 * @param {string} cveId - CVE identifier
 * @param {number} days - Number of days to fetch (default: 30)
 * @returns {Promise<Array>} Promise resolving to trend data
 */
async function loadEPSSTrendData(cveId, days = 30) {
    try {
        const response = await fetch(`/api/v1/epss/trends/${cveId}?days=${days}`);
        const result = await response.json();
        
        if (result.success) {
            return result.data.trend;
        } else {
            console.error('Failed to load EPSS trend data:', result.error);
            return [];
        }
    } catch (error) {
        console.error('Error loading EPSS trend data:', error);
        return [];
    }
}

/**
 * Load EPSS statistics
 * @returns {Promise<Object>} Promise resolving to EPSS statistics
 */
async function loadEPSSStatistics() {
    try {
        const response = await fetch('/api/v1/epss/');
        const result = await response.json();
        
        if (result.success) {
            return result.data;
        } else {
            console.error('Failed to load EPSS statistics:', result.error);
            return null;
        }
    } catch (error) {
        console.error('Error loading EPSS statistics:', error);
        return null;
    }
}

/**
 * Get EPSS risk level description
 * @param {string} riskLevel - Risk level ('high', 'medium', 'low', 'unknown')
 * @returns {string} Human-readable description
 */
function getEPSSRiskDescription(riskLevel) {
    const descriptions = {
        high: 'High exploitation probability - immediate attention recommended',
        medium: 'Medium exploitation probability - monitor closely',
        low: 'Low exploitation probability - standard priority',
        unknown: 'EPSS score not available'
    };
    
    return descriptions[riskLevel] || descriptions.unknown;
}

/**
 * Format EPSS date for display
 * @param {string} dateString - ISO date string
 * @returns {string} Formatted date string
 */
function formatEPSSDate(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
}

/**
 * Check if EPSS data is recent (within last 24 hours)
 * @param {string} lastUpdated - Last updated timestamp
 * @returns {boolean} True if data is recent
 */
function isEPSSDataRecent(lastUpdated) {
    if (!lastUpdated) return false;
    
    const lastUpdate = new Date(lastUpdated);
    const now = new Date();
    const hoursDiff = (now - lastUpdate) / (1000 * 60 * 60);
    
    return hoursDiff <= 24;
}

/**
 * Generate EPSS status indicator
 * @param {string} lastUpdated - Last updated timestamp
 * @returns {string} HTML for status indicator
 */
function generateEPSSStatusIndicator(lastUpdated) {
    const isRecent = isEPSSDataRecent(lastUpdated);
    const statusClass = isRecent ? 'status-recent' : 'status-stale';
    const statusText = isRecent ? 'Recent' : 'Stale';
    const statusIcon = isRecent ? 'fa-check-circle' : 'fa-exclamation-triangle';
    
    return `
        <span class="epss-status-indicator ${statusClass}" title="EPSS data ${statusText.toLowerCase()}">
            <i class="fas ${statusIcon}"></i>
            ${statusText}
        </span>
    `;
}

// Export functions for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        getEPSSRiskLevel,
        formatEPSSScore,
        formatEPSSPercentile,
        generateEPSSBadge,
        generateEPSSScoreDisplay,
        generateEPSSInfoTooltip,
        generateEPSSLegend,
        createEPSSTrendChart,
        createEPSSMiniChart,
        loadEPSSTrendData,
        loadEPSSStatistics,
        getEPSSRiskDescription,
        formatEPSSDate,
        isEPSSDataRecent,
        generateEPSSStatusIndicator
    };
}
