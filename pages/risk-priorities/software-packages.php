<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/cache.php';

// Initialize authentication
$auth = new Auth();
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

// Get database connection
$db = DatabaseConfig::getInstance();

// Get comprehensive summary statistics with caching
$cache_key = 'software_package_metrics_' . date('Y-m-d-H-i', floor(time() / 300) * 300);
$stats = Cache::get($cache_key);

if (!$stats) {
    // Use direct table queries like other dashboards - count UNIQUE CVEs, not instances
    $sql = "WITH package_metrics AS (
        SELECT 
            COUNT(DISTINCT sp.package_id) as total_packages,
            COUNT(DISTINCT CASE WHEN sprs.kev_count > 0 THEN sp.package_id END) as kev_packages,
            COUNT(DISTINCT CASE WHEN sprs.tier1_assets_count > 0 THEN sp.package_id END) as tier1_packages,
            COUNT(DISTINCT CASE WHEN sprs.tier2_assets_count > 0 THEN sp.package_id END) as tier2_packages,
            COUNT(DISTINCT CASE WHEN sprs.tier3_assets_count > 0 THEN sp.package_id END) as tier3_packages,
            SUM(sprs.affected_assets_count) as total_affected_assets,
            ROUND(AVG(sprs.aggregate_risk_score), 2) as avg_risk_score
        FROM software_packages sp
        LEFT JOIN software_package_risk_scores sprs ON sp.package_id = sprs.package_id
        WHERE sprs.total_vulnerabilities > 0
    ),
    vulnerability_metrics AS (
        -- Count UNIQUE CVEs like vulnerabilities dashboard does
        SELECT 
            COUNT(DISTINCT v.cve_id) as total_vulnerabilities,
            COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN v.cve_id END) as critical_vulns,
            COUNT(DISTINCT CASE WHEN v.severity = 'High' THEN v.cve_id END) as high_vulns,
            COUNT(DISTINCT CASE WHEN v.severity = 'Medium' THEN v.cve_id END) as medium_vulns,
            COUNT(DISTINCT CASE WHEN v.severity = 'Low' THEN v.cve_id END) as low_vulns,
            COUNT(DISTINCT CASE WHEN v.is_kev = true THEN v.cve_id END) as kev_vulns
        FROM vulnerabilities v
        JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
        WHERE dvl.remediation_status = 'Open'
    )
    SELECT 
        COALESCE(pm.total_packages, 0) as total_packages,
        COALESCE(pm.kev_packages, 0) as kev_packages,
        COALESCE(pm.tier1_packages, 0) as tier1_packages,
        COALESCE(pm.tier2_packages, 0) as tier2_packages,
        COALESCE(pm.tier3_packages, 0) as tier3_packages,
        COALESCE(vm.total_vulnerabilities, 0) as total_vulnerabilities,
        COALESCE(vm.critical_vulns, 0) as critical_vulns,
        COALESCE(vm.high_vulns, 0) as high_vulns,
        COALESCE(vm.medium_vulns, 0) as medium_vulns,
        COALESCE(vm.low_vulns, 0) as low_vulns,
        COALESCE(pm.total_affected_assets, 0) as total_affected_assets,
        COALESCE(pm.avg_risk_score, 0) as avg_risk_score
    FROM package_metrics pm, vulnerability_metrics vm";
    
    $stmt = $db->query($sql);
    $stats = $stmt->fetch();
    
    // Cache the results for 5 minutes
    Cache::set($cache_key, $stats, 300);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Software Package Risk Management - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/priority-badges.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .view-toggle {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 2rem;
            background: var(--bg-card, #1a1a1a);
            padding: 0.5rem;
            border-radius: 0.5rem;
            border: 1px solid var(--border-primary, #333333);
            width: fit-content;
        }
        
        .toggle-btn {
            padding: 0.75rem 1.5rem;
            background: transparent;
            color: var(--text-secondary, #cbd5e1);
            border: none;
            border-radius: 0.375rem;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s;
        }
        
        .toggle-btn:hover {
            background: var(--bg-hover, #222222);
            color: var(--text-primary, #ffffff);
        }
        
        .toggle-btn.active {
            background: var(--siemens-petrol, #009999);
            color: white;
        }
        
        .package-card {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            transition: all 0.2s;
        }
        
        .package-card:hover {
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.2);
        }
        
        .package-card.has-kev {
            border-left: 4px solid #ef4444;
        }
        
        .package-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 1rem;
        }
        
        .package-title {
            flex: 1;
        }
        
        .package-name {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.25rem;
        }
        
        .package-vendor {
            color: var(--text-muted, #94a3b8);
            font-size: 0.875rem;
        }
        
        .package-risk-score {
            background: var(--bg-secondary, #0f0f0f);
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            text-align: center;
        }
        
        .risk-score-label {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
            margin-bottom: 0.25rem;
        }
        
        .risk-score-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--siemens-orange, #ff6b35);
        }
        
        .package-body {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .vuln-summary {
            background: var(--bg-secondary, #0f0f0f);
            padding: 1rem;
            border-radius: 0.5rem;
        }
        
        .vuln-summary-title {
            font-size: 0.875rem;
            color: var(--text-secondary, #cbd5e1);
            margin-bottom: 0.75rem;
        }
        
        .vuln-counts {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .vuln-count {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .vuln-count-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .badge-critical { background: #dc2626; color: white; }
        .badge-high { background: #ea580c; color: white; }
        .badge-medium { background: #f59e0b; color: white; }
        .badge-low { background: #10b981; color: white; }
        
        .asset-breakdown {
            background: var(--bg-secondary, #0f0f0f);
            padding: 1rem;
            border-radius: 0.5rem;
        }
        
        .asset-breakdown-title {
            font-size: 0.875rem;
            color: var(--text-secondary, #cbd5e1);
            margin-bottom: 0.75rem;
        }
        
        .tier-breakdown {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        
        .tier-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem;
            background: var(--bg-card, #1a1a1a);
            border-radius: 0.375rem;
        }
        
        .tier-label {
            font-size: 0.875rem;
            color: var(--text-primary, #ffffff);
            font-weight: 500;
        }
        
        .tier-count {
            font-weight: 700;
            font-size: 1rem;
        }
        
        .tier-1-count { color: #ef4444; }
        .tier-2-count { color: #f59e0b; }
        .tier-3-count { color: #10b981; }
        
        .recommendation-box {
            background: linear-gradient(135deg, rgba(0, 153, 153, 0.1), rgba(0, 153, 153, 0.05));
            border: 1px solid var(--siemens-petrol, #009999);
            border-radius: 0.5rem;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        
        .recommendation-title {
            font-size: 0.875rem;
            color: var(--siemens-petrol, #009999);
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .recommendation-text {
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
        }
        
        .package-actions {
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
        }
        
        .btn-sm {
            padding: 0.5rem 1rem;
            font-size: 0.875rem;
        }
        
        .kev-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            background: #ef4444;
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
            margin-left: 0.5rem;
        }
        
        .filter-bar {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }
        
        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 0.375rem;
        }
        
        .filter-label {
            font-size: 0.75rem;
            color: var(--text-secondary, #cbd5e1);
            font-weight: 500;
        }
        
        .filter-select, .filter-input {
            padding: 0.5rem 0.75rem;
            background: var(--bg-card, #1a1a1a);
            color: var(--text-primary, #ffffff);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.375rem;
            font-size: 0.875rem;
        }
        
        .empty-state {
            text-align: center;
            padding: 4rem 2rem;
            background: var(--bg-card, #1a1a1a);
            border-radius: 0.75rem;
            border: 1px dashed var(--border-primary, #333333);
        }
        
        .empty-state-icon {
            font-size: 3rem;
            color: var(--text-muted, #94a3b8);
            margin-bottom: 1rem;
        }
        
        .pagination {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 2rem;
            padding: 1rem;
            background: var(--bg-card, #1a1a1a);
            border-radius: 0.5rem;
        }
        
        /* Chart fill colors for metrics */
        .chart-fill.tier1 { background: #dc2626; }
        .chart-fill.tier2 { background: #f59e0b; }
        .chart-fill.kev-critical { background: #ef4444; }
        .chart-fill.critical { background: #dc2626; }
        .chart-fill.high { background: #ea580c; }
        
        /* Metric detail colors */
        .metric-detail .tier1 { color: #dc2626; }
        .metric-detail .tier2 { color: #f59e0b; }
        .metric-detail .kev-critical { color: #ef4444; }
        .metric-detail .critical { color: #dc2626; }
        .metric-detail .high { color: #ea580c; }
    </style>
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

    <main class="main-content">
        <div class="container" style="max-width: 1400px; margin: 0 auto; padding: 2rem;">
            
            <!-- Page Header -->
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-box"></i> Risk Priority Management</h1>
                    <p>Prioritized vulnerability remediation by software package</p>
                </div>
                <div class="page-actions">
                    <div class="view-toggle">
                        <button class="toggle-btn active" data-view="package" onclick="switchView('package')">
                            <i class="fas fa-boxes"></i> Package View (Recommended)
                        </button>
                        <button class="toggle-btn" data-view="cve" onclick="switchView('cve')">
                            <i class="fas fa-list"></i> CVE View (Detail)
                        </button>
                    </div>
                </div>
            </div>

            <!-- Summary Statistics -->
            <section class="metrics-section">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-icon warning">
                            <i class="fas fa-box"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Vulnerable Packages</h3>
                            <div class="metric-value"><?php echo number_format($stats['total_packages']); ?></div>
                            <div class="metric-detail">
                                <span class="tier1"><?php echo number_format($stats['tier1_packages']); ?> Tier 1</span>
                                <span class="tier2"><?php echo number_format($stats['tier2_packages']); ?> Tier 2</span>
                            </div>
                            <div class="metric-chart">
                                <div class="mini-chart">
                                    <div class="chart-bar">
                                        <div class="chart-fill tier1" style="width: <?php echo $stats['total_packages'] > 0 ? ($stats['tier1_packages'] / $stats['total_packages']) * 100 : 0; ?>%"></div>
                                        <div class="chart-fill tier2" style="width: <?php echo $stats['total_packages'] > 0 ? ($stats['tier2_packages'] / $stats['total_packages']) * 100 : 0; ?>%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="metric-card critical">
                        <div class="metric-icon critical">
                            <i class="fas fa-fire"></i>
                        </div>
                        <div class="metric-content">
                            <h3>KEV Packages</h3>
                            <div class="metric-value"><?php echo number_format($stats['kev_packages']); ?></div>
                            <div class="metric-detail">
                                <span class="kev-critical"><?php echo number_format($stats['kev_packages']); ?> Known Exploited</span>
                            </div>
                            <div class="metric-chart">
                                <div class="mini-chart">
                                    <div class="chart-bar">
                                        <div class="chart-fill kev-critical" style="width: <?php echo $stats['total_packages'] > 0 ? ($stats['kev_packages'] / $stats['total_packages']) * 100 : 0; ?>%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon info">
                            <i class="fas fa-exclamation-circle"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Packages Affecting Tier 1 Assets</h3>
                            <div class="metric-value"><?php echo number_format($stats['tier1_packages']); ?></div>
                            <div class="metric-detail">
                                <span class="critical"><?php echo number_format($stats['tier1_packages']); ?> High-Criticality Assets</span>
                            </div>
                            <div class="metric-chart">
                                <div class="mini-chart">
                                    <div class="chart-bar">
                                        <div class="chart-fill critical" style="width: <?php echo $stats['total_packages'] > 0 ? ($stats['tier1_packages'] / $stats['total_packages']) * 100 : 0; ?>%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-bug"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Total CVEs</h3>
                            <div class="metric-value"><?php echo number_format($stats['total_vulnerabilities']); ?></div>
                            <div class="metric-detail">
                                <span class="critical"><?php echo number_format($stats['critical_vulns']); ?> Critical</span>
                                <span class="high"><?php echo number_format($stats['high_vulns']); ?> High</span>
                            </div>
                            <div class="metric-chart">
                                <div class="mini-chart">
                                    <div class="chart-bar">
                                        <div class="chart-fill critical" style="width: <?php echo $stats['total_vulnerabilities'] > 0 ? ($stats['critical_vulns'] / $stats['total_vulnerabilities']) * 100 : 0; ?>%"></div>
                                        <div class="chart-fill high" style="width: <?php echo $stats['total_vulnerabilities'] > 0 ? ($stats['high_vulns'] / $stats['total_vulnerabilities']) * 100 : 0; ?>%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Filters -->
            <div class="filter-bar">
                <div class="filter-group">
                    <label class="filter-label">Tier</label>
                    <select id="filter-tier" class="filter-select" onchange="loadPackages()">
                        <option value="">All Tiers</option>
                        <option value="1">Tier 1 Only</option>
                        <option value="2">Tier 2 Only</option>
                        <option value="3">Tier 3 Only</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label class="filter-label">Severity</label>
                    <select id="filter-severity" class="filter-select" onchange="loadPackages()">
                        <option value="">All Severities</option>
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label class="filter-label">KEV Status</label>
                    <select id="filter-kev" class="filter-select" onchange="loadPackages()">
                        <option value="">All Packages</option>
                        <option value="true">KEV Only</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label class="filter-label">Search</label>
                    <input type="text" id="filter-search" class="filter-input" placeholder="Search packages..." onkeyup="debounceSearch()">
                </div>
                <div class="filter-group" style="justify-content: flex-end;">
                    <label class="filter-label">&nbsp;</label>
                    <button class="btn btn-secondary btn-sm" onclick="clearFilters()">
                        <i class="fas fa-times"></i> Clear
                    </button>
                </div>
            </div>

            <!-- Package List -->
            <div id="packages-container">
                <div style="text-align: center; padding: 2rem;">
                    <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                    <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading packages...</p>
                </div>
            </div>

            <!-- Pagination -->
            <div class="pagination" id="pagination-container" style="display: none;">
                <div id="pagination-info"></div>
                <div id="pagination-controls"></div>
            </div>

        </div>
    </main>

    <script>
        let currentPage = 1;
        let currentLimit = 10;
        let searchTimeout;

        // Load packages on page load
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize view buttons for package view
            updateViewButtons('package');
            
            // Check saved view preference
            const savedView = localStorage.getItem('risk_priority_view');
            if (savedView === 'cve') {
                switchView('cve');
            } else {
                loadPackages();
            }
        });
        
        // Update view button states
        function updateViewButtons(activeView) {
            const buttons = document.querySelectorAll('.toggle-btn');
            buttons.forEach(button => {
                button.classList.remove('active');
                if (button.dataset.view === activeView) {
                    button.classList.add('active');
                }
            });
        }

        // Switch between package and CVE views
        function switchView(view) {
            localStorage.setItem('risk_priority_view', view);
            
            if (view === 'cve') {
                window.location.href = '/pages/risk-priorities/dashboard.php';
            } else if (view === 'package') {
                // Already on package view, just update the UI
                updateViewButtons(view);
            }
        }

        // Load packages from API
        async function loadPackages(page = 1) {
            currentPage = page;
            
            const tier = document.getElementById('filter-tier').value;
            const severity = document.getElementById('filter-severity').value;
            const kev = document.getElementById('filter-kev').value;
            const search = document.getElementById('filter-search').value;
            
            const params = new URLSearchParams({
                page: page,
                limit: currentLimit
            });
            
            if (tier) params.append('tier', tier);
            if (severity) params.append('severity', severity);
            if (kev) params.append('kev_only', kev);
            if (search) params.append('search', search);
            
            try {
                const response = await fetch(`/api/v1/software-packages/risk-priorities.php?${params}`);
                
                if (!response.ok) {
                    const errorText = await response.text();
                    console.error('HTTP Error:', response.status, errorText);
                    throw new Error(`HTTP ${response.status}: ${errorText.substring(0, 200)}`);
                }
                
                const result = await response.json();
                console.log('API Response:', result);
                
                if (result.success) {
                    renderPackages(result.data);
                    renderPagination(result.pagination);
                } else {
                    const errorMsg = typeof result.error === 'string' ? result.error : JSON.stringify(result.error);
                    showError(errorMsg || 'Failed to load packages');
                }
            } catch (error) {
                console.error('Fetch error:', error);
                showError('Error loading packages: ' + error.message);
            }
        }

        // Render package cards
        function renderPackages(packages) {
            const container = document.getElementById('packages-container');
            
            if (packages.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon"><i class="fas fa-box-open"></i></div>
                        <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">No Vulnerable Packages Found</h3>
                        <p style="color: var(--text-secondary, #cbd5e1);">Try adjusting your filters or check back later.</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = packages.map(pkg => `
                <div class="package-card ${pkg.kev_count > 0 ? 'has-kev' : ''}">
                    <div class="package-header">
                        <div class="package-title">
                            <div class="package-name">
                                ${escapeHtml(pkg.package_name)} v${escapeHtml(pkg.version)}
                                ${pkg.kev_count > 0 ? '<span class="kev-badge"><i class="fas fa-exclamation-triangle"></i> KEV</span>' : ''}
                            </div>
                            <div class="package-vendor">${escapeHtml(pkg.vendor || 'Unknown Vendor')}</div>
                        </div>
                        <div class="package-risk-score">
                            <div class="risk-score-label">Risk Score</div>
                            <div class="risk-score-value">${pkg.aggregate_risk_score}</div>
                        </div>
                    </div>
                    
                    ${pkg.tier1_assets_count > 0 ? `
                    <div class="recommendation-box">
                        <div class="recommendation-title"><i class="fas fa-lightbulb"></i> Priority Recommendation</div>
                        <div class="recommendation-text">
                            Update ${pkg.tier1_assets_count} Tier 1 asset${pkg.tier1_assets_count > 1 ? 's' : ''} first: 
                            ${pkg.top_priority_hostname || 'Critical assets'} in ${pkg.top_priority_location || 'high-risk location'}
                        </div>
                    </div>
                    ` : ''}
                    
                    <div class="package-body">
                        <div class="vuln-summary">
                            <div class="vuln-summary-title">
                                <i class="fas fa-bug"></i> ${pkg.total_vulnerabilities} Vulnerabilit${pkg.total_vulnerabilities === 1 ? 'y' : 'ies'}
                            </div>
                            <div class="vuln-counts">
                                ${pkg.critical_severity_count > 0 ? `<div class="vuln-count"><span class="vuln-count-badge badge-critical">Critical</span> ${pkg.critical_severity_count}</div>` : ''}
                                ${pkg.high_severity_count > 0 ? `<div class="vuln-count"><span class="vuln-count-badge badge-high">High</span> ${pkg.high_severity_count}</div>` : ''}
                                ${pkg.medium_severity_count > 0 ? `<div class="vuln-count"><span class="vuln-count-badge badge-medium">Medium</span> ${pkg.medium_severity_count}</div>` : ''}
                                ${pkg.low_severity_count > 0 ? `<div class="vuln-count"><span class="vuln-count-badge badge-low">Low</span> ${pkg.low_severity_count}</div>` : ''}
                            </div>
                        </div>
                        
                        <div class="asset-breakdown">
                            <div class="asset-breakdown-title">
                                <i class="fas fa-server"></i> ${pkg.affected_assets_count} Affected Asset${pkg.affected_assets_count === 1 ? '' : 's'}
                            </div>
                            <div class="tier-breakdown">
                                ${pkg.tier1_assets_count > 0 ? `
                                <div class="tier-item">
                                    <span class="tier-label">Tier 1 (Critical)</span>
                                    <span class="tier-count tier-1-count">${pkg.tier1_assets_count}</span>
                                </div>
                                ` : ''}
                                ${pkg.tier2_assets_count > 0 ? `
                                <div class="tier-item">
                                    <span class="tier-label">Tier 2 (High)</span>
                                    <span class="tier-count tier-2-count">${pkg.tier2_assets_count}</span>
                                </div>
                                ` : ''}
                                ${pkg.tier3_assets_count > 0 ? `
                                <div class="tier-item">
                                    <span class="tier-label">Tier 3 (Standard)</span>
                                    <span class="tier-count tier-3-count">${pkg.tier3_assets_count}</span>
                                </div>
                                ` : ''}
                            </div>
                        </div>
                    </div>
                    
                    ${pkg.latest_safe_version ? `
                    <div style="background: var(--bg-secondary, #0f0f0f); padding: 0.75rem; border-radius: 0.5rem; margin-bottom: 1rem;">
                        <span style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">
                            <i class="fas fa-shield-alt"></i> Safe Version: <strong style="color: var(--siemens-petrol, #009999);">${escapeHtml(pkg.latest_safe_version)}</strong>
                        </span>
                    </div>
                    ` : ''}
                    
                    <div class="package-actions">
                        <button class="btn btn-primary btn-sm" onclick="viewPackageDetails('${pkg.package_id}')">
                            <i class="fas fa-eye"></i> View Details
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="viewAffectedAssets('${pkg.package_id}')">
                            <i class="fas fa-server"></i> View Assets
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="createPatch('${pkg.package_id}')">
                            <i class="fas fa-plus"></i> Create Patch
                        </button>
                        ${pkg.available_patch_count > 0 ? `
                        <button class="btn btn-accent btn-sm" onclick="applyPatch('${pkg.package_id}')">
                            <i class="fas fa-download"></i> Apply Patch (${pkg.available_patch_count})
                        </button>
                        ` : ''}
                    </div>
                </div>
            `).join('');
        }

        // Render pagination
        function renderPagination(pagination) {
            const container = document.getElementById('pagination-container');
            const info = document.getElementById('pagination-info');
            const controls = document.getElementById('pagination-controls');
            
            if (pagination.total === 0) {
                container.style.display = 'none';
                return;
            }
            
            container.style.display = 'flex';
            
            const start = (pagination.page - 1) * pagination.limit + 1;
            const end = Math.min(pagination.page * pagination.limit, pagination.total);
            
            info.textContent = `Showing ${start}-${end} of ${pagination.total} packages`;
            
            let controlsHTML = '';
            
            if (pagination.page > 1) {
                controlsHTML += `<button class="btn btn-secondary btn-sm" onclick="loadPackages(${pagination.page - 1})"><i class="fas fa-chevron-left"></i> Previous</button>`;
            }
            
            if (pagination.page < pagination.pages) {
                controlsHTML += `<button class="btn btn-secondary btn-sm" onclick="loadPackages(${pagination.page + 1})">Next <i class="fas fa-chevron-right"></i></button>`;
            }
            
            controls.innerHTML = controlsHTML;
        }

        // Debounce search input
        function debounceSearch() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                loadPackages(1);
            }, 500);
        }

        // Clear all filters
        function clearFilters() {
            document.getElementById('filter-tier').value = '';
            document.getElementById('filter-severity').value = '';
            document.getElementById('filter-kev').value = '';
            document.getElementById('filter-search').value = '';
            loadPackages(1);
        }

        // Action functions
        function viewPackageDetails(packageId) {
            window.location.href = `/pages/risk-priorities/package-detail.php?id=${packageId}`;
        }

        function viewAffectedAssets(packageId) {
            window.location.href = `/pages/risk-priorities/package-detail.php?id=${packageId}#assets`;
        }

        function createPatch(packageId) {
            window.location.href = `/pages/admin/patches.php?action=create&package_id=${packageId}`;
        }

        function applyPatch(packageId) {
            window.location.href = `/pages/admin/patches.php?action=apply&package_id=${packageId}`;
        }

        // Utility functions
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function showError(message) {
            const container = document.getElementById('packages-container');
            container.innerHTML = `
                <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                    <i class="fas fa-exclamation-circle"></i> ${escapeHtml(message)}
                </div>
            `;
        }
    </script>

</body>
</html>

