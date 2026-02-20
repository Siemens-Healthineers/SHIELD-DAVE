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

// Initialize authentication
$auth = new Auth();
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

// Get package ID from query string
$packageId = $_GET['id'] ?? '';

if (empty($packageId)) {
    header('Location: /pages/risk-priorities/software-packages.php');
    exit;
}

// Get database connection
$db = DatabaseConfig::getInstance();

// Get package details
$sql = "SELECT * FROM software_package_risk_priority_view WHERE package_id = ?";
$package = $db->query($sql, [$packageId])->fetch();

if (!$package) {
    header('Location: /pages/risk-priorities/software-packages.php?error=package_not_found');
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo dave_htmlspecialchars($package['package_name']); ?> - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/priority-badges.css">
    <link rel="stylesheet" href="/assets/css/schedule.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .detail-header {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        .detail-header.has-kev {
            border-left: 4px solid #ef4444;
        }
        
        .package-title-row {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 1.5rem;
        }
        
        .package-info {
            flex: 1;
        }
        
        .package-name-large {
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.5rem;
        }
        
        .package-vendor-large {
            color: var(--text-secondary, #cbd5e1);
            font-size: 1.125rem;
            margin-bottom: 0.5rem;
        }
        
        .package-version-badge {
            background: var(--bg-secondary, #0f0f0f);
            color: var(--siemens-petrol, #009999);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-size: 0.875rem;
            font-weight: 600;
            display: inline-block;
        }
        
        .risk-score-large {
            background: var(--bg-secondary, #0f0f0f);
            padding: 1.5rem;
            border-radius: 0.75rem;
            text-align: center;
            min-width: 150px;
        }
        
        .risk-score-large-label {
            font-size: 0.875rem;
            color: var(--text-muted, #94a3b8);
            margin-bottom: 0.5rem;
        }
        
        .risk-score-large-value {
            font-size: 3rem;
            font-weight: 700;
            color: var(--siemens-orange, #ff6b35);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .stat-card {
            background: var(--bg-secondary, #0f0f0f);
            padding: 1rem;
            border-radius: 0.5rem;
            text-align: center;
        }
        
        .stat-label {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
            margin-bottom: 0.5rem;
        }
        
        .stat-value {
            font-size: 1.5rem;
            font-weight: 700;
        }
        
        .tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 2rem;
            border-bottom: 2px solid var(--border-primary, #333333);
        }
        
        .tab {
            padding: 1rem 1.5rem;
            background: transparent;
            color: var(--text-secondary, #cbd5e1);
            border: none;
            border-bottom: 3px solid transparent;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s;
        }
        
        .tab:hover {
            color: var(--text-primary, #ffffff);
            background: var(--bg-hover, #222222);
        }
        
        .tab.active {
            color: var(--siemens-petrol, #009999);
            border-bottom-color: var(--siemens-petrol, #009999);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .section-card {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .section-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .data-table th {
            background: var(--bg-secondary, #0f0f0f);
            color: var(--text-secondary, #cbd5e1);
            font-weight: 600;
            text-align: left;
            padding: 0.75rem;
            font-size: 0.875rem;
        }
        
        .data-table td {
            padding: 0.75rem;
            border-bottom: 1px solid var(--border-primary, #333333);
            color: var(--text-primary, #ffffff);
        }
        
        .data-table tr:hover {
            background: var(--bg-hover, #222222);
        }
        
        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical { background: #dc2626; color: white; }
        .severity-high { background: #ea580c; color: white; }
        .severity-medium { background: #f59e0b; color: white; }
        .severity-low { background: #10b981; color: white; }
        
        .tier-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .tier-1 { background: #dc2626; color: white; }
        .tier-2 { background: #f59e0b; color: white; }
        .tier-3 { background: #10b981; color: white; }
        
        .action-bar {
            display: flex;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
        }
        
        .kev-indicator {
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            background: #ef4444;
            color: white;
            padding: 0.375rem 0.75rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .empty-message {
            text-align: center;
            padding: 3rem;
            color: var(--text-muted, #94a3b8);
        }
        
        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 9999;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0, 0, 0, 0.8);
        }
        
        .modal-content {
            background-color: var(--bg-card, #1a1a1a);
            margin: 2% auto;
            padding: 0;
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            width: 90%;
            max-width: 900px;
            max-height: 90vh;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-primary, #333333);
            background: var(--bg-secondary, #0f0f0f);
        }
        
        .modal-header h2 {
            margin: 0;
            font-size: 1.5rem;
            color: var(--text-primary, #ffffff);
        }
        
        .modal-close {
            background: transparent;
            border: none;
            color: var(--text-secondary, #cbd5e1);
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0.5rem;
            line-height: 1;
            transition: color 0.2s;
        }
        
        .modal-close:hover {
            color: var(--siemens-orange, #ff6b35);
        }
        
        .modal-body {
            padding: 1.5rem;
            overflow-y: auto;
            flex: 1;
        }
        
        .vulnerability-details {
            color: var(--text-primary, #ffffff);
        }
        
        .detail-section {
            margin-bottom: 2rem;
        }
        
        .detail-section h3 {
            color: var(--siemens-petrol, #009999);
            margin-bottom: 1rem;
            font-size: 1.125rem;
        }
        
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }
        
        .detail-item {
            background: var(--bg-secondary, #0f0f0f);
            padding: 1rem;
            border-radius: 0.5rem;
        }
        
        .detail-item label {
            display: block;
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            font-weight: 600;
        }
        
        .detail-item p {
            margin: 0;
            color: var(--text-primary, #ffffff);
            line-height: 1.6;
        }
        
        .impact-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
        }
        
        .impact-stat {
            background: var(--bg-secondary, #0f0f0f);
            padding: 1.5rem;
            border-radius: 0.5rem;
            text-align: center;
        }
        
        .stat-number {
            display: block;
            font-size: 2rem;
            font-weight: 700;
            color: var(--siemens-petrol, #009999);
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            display: block;
            font-size: 0.875rem;
            color: var(--text-muted, #94a3b8);
        }
        
        .affected-devices {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .device-item {
            background: var(--bg-secondary, #0f0f0f);
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            display: grid;
            grid-template-columns: 2fr 1fr auto;
            gap: 1rem;
            align-items: start;
        }
        
        .device-info strong {
            color: var(--text-primary, #ffffff);
            display: block;
            margin-bottom: 0.5rem;
        }
        
        .device-details {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            font-size: 0.75rem;
        }
        
        .device-details span {
            background: var(--bg-tertiary, #222222);
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            color: var(--text-secondary, #cbd5e1);
        }
        
        .component-info {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        .component-name {
            font-weight: 600;
            color: var(--text-primary, #ffffff);
        }
        
        .component-version,
        .component-vendor {
            font-size: 0.875rem;
            color: var(--text-secondary, #cbd5e1);
        }
        
        .device-status {
            display: flex;
            align-items: center;
        }
        
        .status-badge {
            padding: 0.375rem 0.75rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status-badge.open {
            background: #ef4444;
            color: white;
        }
        
        .status-badge.in-progress {
            background: #f59e0b;
            color: white;
        }
        
        .status-badge.resolved {
            background: #10b981;
            color: white;
        }
    </style>
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

    <main class="main-content">
        <div class="container" style="max-width: 1400px; margin: 0 auto; padding: 2rem;">
            
            <!-- Breadcrumb -->
            <div style="margin-bottom: 1.5rem;">
                <a href="/pages/risk-priorities/software-packages.php" style="color: var(--siemens-petrol, #009999); text-decoration: none;">
                    <i class="fas fa-arrow-left"></i> Back to Packages
                </a>
            </div>

            <!-- Package Header -->
            <div class="detail-header <?php echo $package['kev_count'] > 0 ? 'has-kev' : ''; ?>">
                <div class="package-title-row">
                    <div class="package-info">
                        <div class="package-name-large">
                            <?php echo dave_htmlspecialchars($package['package_name']); ?>
                            <?php if ($package['kev_count'] > 0): ?>
                                <span class="kev-indicator">
                                    <i class="fas fa-exclamation-triangle"></i> KEV
                                </span>
                            <?php endif; ?>
                        </div>
                        <div class="package-vendor-large">
                            <?php echo dave_htmlspecialchars($package['vendor'] ?? 'Unknown Vendor'); ?>
                        </div>
                        <span class="package-version-badge">
                            <i class="fas fa-code-branch"></i> Version <?php echo dave_htmlspecialchars($package['version']); ?>
                        </span>
                        <?php if ($package['latest_safe_version']): ?>
                            <span class="package-version-badge" style="background: var(--siemens-petrol, #009999); color: white; margin-left: 0.5rem;">
                                <i class="fas fa-shield-alt"></i> Safe Version: <?php echo dave_htmlspecialchars($package['latest_safe_version']); ?>
                            </span>
                        <?php endif; ?>
                    </div>
                    <div class="risk-score-large">
                        <div class="risk-score-large-label">Risk Score</div>
                        <div class="risk-score-large-value"><?php echo number_format($package['aggregate_risk_score']); ?></div>
                    </div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">Total CVEs</div>
                        <div class="stat-value" style="color: var(--siemens-orange, #ff6b35);">
                            <?php echo number_format($package['total_vulnerabilities']); ?>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">KEV Vulnerabilities</div>
                        <div class="stat-value" style="color: #ef4444;">
                            <?php echo number_format($package['kev_count']); ?>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Critical Severity</div>
                        <div class="stat-value" style="color: #dc2626;">
                            <?php echo number_format($package['critical_severity_count']); ?>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Affected Assets</div>
                        <div class="stat-value" style="color: var(--siemens-petrol, #009999);">
                            <?php echo number_format($package['affected_assets_count']); ?>
                        </div>
                    </div>
                </div>
                
                <div class="action-bar">
                    <button class="btn btn-primary" onclick="createPatch()">
                        <i class="fas fa-plus"></i> Create Patch
                    </button>
                    <button class="btn btn-secondary" onclick="exportReport()">
                        <i class="fas fa-download"></i> Export Report
                    </button>
                    <button class="btn btn-secondary" onclick="assignOwner()">
                        <i class="fas fa-user"></i> Assign Owner
                    </button>
                </div>
            </div>

            <!-- Tabs -->
            <div class="tabs">
                <button class="tab active" data-tab="vulnerabilities" onclick="switchTab('vulnerabilities')">
                    <i class="fas fa-bug"></i> Vulnerabilities (<?php echo $package['total_vulnerabilities']; ?>)
                </button>
                <button class="tab" data-tab="assets" onclick="switchTab('assets')">
                    <i class="fas fa-server"></i> Affected Assets (<?php echo $package['affected_assets_count']; ?>)
                </button>
                <button class="tab" data-tab="patches" onclick="switchTab('patches')">
                    <i class="fas fa-band-aid"></i> Patches & Remediation
                </button>
            </div>

            <!-- Vulnerabilities Tab -->
            <div id="tab-vulnerabilities" class="tab-content active">
                <div class="section-card">
                    <div class="section-title">
                        <i class="fas fa-bug"></i> Associated Vulnerabilities
                    </div>
                    <div id="vulnerabilities-list">
                        <div style="text-align: center; padding: 2rem;">
                            <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                            <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading vulnerabilities...</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Assets Tab -->
            <div id="tab-assets" class="tab-content">
                <div class="section-card">
                    <div class="section-title">
                        <i class="fas fa-server"></i> Affected Assets by Tier
                    </div>
                    <div id="assets-list">
                        <div style="text-align: center; padding: 2rem;">
                            <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                            <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading assets...</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Patches Tab -->
            <div id="tab-patches" class="tab-content">
                <div class="section-card">
                    <div class="section-title">
                        <i class="fas fa-band-aid"></i> Available Patches
                    </div>
                    <div id="patches-list">
                        <div style="text-align: center; padding: 2rem;">
                            <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                            <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading patches...</p>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </main>

    <!-- CVE Details Modal -->
    <div id="vulnerabilityModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">Vulnerability Details</h2>
                <button type="button" class="modal-close" onclick="closeVulnerabilityModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body" id="modalBody">
                <!-- Content will be populated by JavaScript -->
            </div>
        </div>
    </div>

    <script src="/assets/js/components/assign-owner-modal.js"></script>
    <script>
        const packageId = '<?php echo addslashes($packageId); ?>';
        
        document.addEventListener('DOMContentLoaded', function() {
            loadVulnerabilities();
            
            // Check for hash anchor
            const hash = window.location.hash.substring(1);
            if (hash === 'assets' || hash === 'patches') {
                switchTab(hash);
            }
        });

        // Switch tabs
        function switchTab(tabName) {
            // Update tab buttons
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
                if (tab.dataset.tab === tabName) {
                    tab.classList.add('active');
                }
            });
            
            // Update tab content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(`tab-${tabName}`).classList.add('active');
            
            // Load data if not already loaded
            if (tabName === 'vulnerabilities' && !document.getElementById('vulnerabilities-list').dataset.loaded) {
                loadVulnerabilities();
            } else if (tabName === 'assets' && !document.getElementById('assets-list').dataset.loaded) {
                loadAssets();
            } else if (tabName === 'patches' && !document.getElementById('patches-list').dataset.loaded) {
                loadPatches();
            }
        }

        // Load vulnerabilities
        async function loadVulnerabilities() {
            try {
                const response = await fetch(`/api/v1/software-packages/risk-priorities.php/${packageId}/vulnerabilities`);
                const result = await response.json();
                
                const container = document.getElementById('vulnerabilities-list');
                container.dataset.loaded = 'true';
                
                if (result.success && result.data.length > 0) {
                    const totalCount = result.total || result.data.length;
                    container.innerHTML = `
                        <div style="margin-bottom: 1rem; color: var(--text-secondary, #cbd5e1);">
                            Showing ${result.data.length} of ${totalCount} vulnerabilities
                        </div>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>CVE ID</th>
                                    <th>Severity</th>
                                    <th>CVSS Score</th>
                                    <th>KEV</th>
                                    <th>Description</th>
                                    <th>Published</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${result.data.map(vuln => {
                                    // Determine which CVSS score to display (v4 > v3 > v2)
                                    let cvssDisplay = 'N/A';
                                    if (vuln.cvss_v4_score && parseFloat(vuln.cvss_v4_score) > 0) {
                                        cvssDisplay = `${vuln.cvss_v4_score} <span style="font-size: 0.75rem; color: var(--text-muted);">(v4.0)</span>`;
                                    } else if (vuln.cvss_v3_score && parseFloat(vuln.cvss_v3_score) > 0) {
                                        cvssDisplay = `${vuln.cvss_v3_score} <span style="font-size: 0.75rem; color: var(--text-muted);">(v3.x)</span>`;
                                    } else if (vuln.cvss_v2_score && parseFloat(vuln.cvss_v2_score) > 0) {
                                        cvssDisplay = `${vuln.cvss_v2_score} <span style="font-size: 0.75rem; color: var(--text-muted);">(v2.0)</span>`;
                                    }
                                    
                                    return `
                                    <tr>
                                        <td><strong>${vuln.cve_id}</strong></td>
                                        <td><span class="severity-badge severity-${vuln.severity.toLowerCase()}">${vuln.severity}</span></td>
                                        <td><strong>${cvssDisplay}</strong></td>
                                        <td>${vuln.kev ? '<span class="kev-indicator"><i class="fas fa-exclamation-triangle"></i></span>' : '-'}</td>
                                        <td>${escapeHtml(vuln.description || 'No description available').substring(0, 100)}...</td>
                                        <td>${formatDate(vuln.published_date)}</td>
                                        <td>
                                            <button class="btn btn-secondary btn-sm" onclick="viewVulnerability('${vuln.cve_id}')">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                        </td>
                                    </tr>
                                `}).join('')}
                            </tbody>
                        </table>
                    `;
                } else {
                    container.innerHTML = '<div class="empty-message">No vulnerabilities found</div>';
                }
            } catch (error) {
                document.getElementById('vulnerabilities-list').innerHTML = `
                    <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                        <i class="fas fa-exclamation-circle"></i> Error loading vulnerabilities: ${escapeHtml(error.message)}
                    </div>
                `;
            }
        }

        // Load affected assets
        async function loadAssets() {
            try {
                const url = `/api/v1/software-packages/risk-priorities.php/${packageId}/affected-assets`;
                const response = await fetch(url);
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const result = await response.json();
                
                const container = document.getElementById('assets-list');
                container.dataset.loaded = 'true';
                
                if (result.success && result.data && result.data.length > 0) {
                    // Group by tier
                    const tiers = {1: [], 2: [], 3: []};
                    result.data.forEach(asset => {
                        if (tiers[asset.tier]) {
                            tiers[asset.tier].push(asset);
                        }
                    });
                    
                    let html = '';
                    for (const tier in tiers) {
                        if (tiers[tier].length > 0) {
                            html += `
                                <div style="margin-bottom: 2rem;">
                                    <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 1rem;">
                                        <span class="tier-badge tier-${tier}">Tier ${tier}</span>
                                        ${tiers[tier].length} Asset${tiers[tier].length > 1 ? 's' : ''}
                                    </h3>
                                    <table class="data-table">
                                        <thead>
                                            <tr>
                                                <th>Asset Name</th>
                                                <th>Device Type</th>
                                                <th>Location</th>
                                                <th>Department</th>
                                                <th>Status</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${tiers[tier].map(asset => `
                                                <tr>
                                                    <td><strong>${escapeHtml(asset.hostname || asset.device_name || asset.ip_address)}</strong></td>
                                                    <td>${escapeHtml(asset.device_type || 'Unknown')}</td>
                                                    <td>${escapeHtml(asset.location || 'Unknown')}</td>
                                                    <td>${escapeHtml(asset.department || 'Unknown')}</td>
                                                    <td>${asset.is_active === 'Active' || asset.is_active === true ? '<span style="color: #10b981;">Active</span>' : '<span style="color: #ef4444;">Inactive</span>'}</td>
                                                    <td>
                                                        <button class="btn btn-secondary btn-sm" onclick="viewAsset('${asset.asset_id}')">
                                                            <i class="fas fa-eye"></i> View
                                                        </button>
                                                    </td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            `;
                        }
                    }
                    container.innerHTML = html;
                } else {
                    let message = '<div class="empty-message">No affected assets found</div>';
                    if (result.success && result.data && result.data.length === 0) {
                        message += '<p style="color: var(--text-muted); font-size: 0.875rem; margin-top: 1rem;">The API returned an empty array.</p>';
                    } else if (!result.success) {
                        message = `<div style="background: #f59e0b; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                            <i class="fas fa-exclamation-triangle"></i> API Error: ${escapeHtml(result.error || 'Unknown error')}
                        </div>`;
                    }
                    container.innerHTML = message;
                }
            } catch (error) {
                console.error('Error in loadAssets:', error);
                console.error('Error stack:', error.stack);
                document.getElementById('assets-list').innerHTML = `
                    <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                        <i class="fas fa-exclamation-circle"></i> Error loading assets: ${escapeHtml(error.message)}
                        <p style="font-size: 0.875rem; margin-top: 0.5rem;">Check browser console for details.</p>
                    </div>
                `;
            }
        }

        // Load patches
        async function loadPatches() {
            try {
                const response = await fetch(`/api/v1/patches/index.php?package_id=${packageId}`);
                const result = await response.json();
                
                const container = document.getElementById('patches-list');
                container.dataset.loaded = 'true';
                
                if (result.success && result.data.length > 0) {
                    container.innerHTML = `
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Patch Name</th>
                                    <th>Type</th>
                                    <th>Target Version</th>
                                    <th>CVEs Resolved</th>
                                    <th>Release Date</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${result.data.map(patch => `
                                    <tr>
                                        <td><strong>${escapeHtml(patch.patch_name)}</strong></td>
                                        <td>${escapeHtml(patch.patch_type)}</td>
                                        <td>${escapeHtml(patch.target_version || 'N/A')}</td>
                                        <td>${patch.cve_count || 0} CVEs</td>
                                        <td>${formatDate(patch.release_date)}</td>
                                        <td>
                                            <button class="btn btn-primary btn-sm" onclick="applyPatch('${patch.patch_id}')">
                                                <i class="fas fa-download"></i> Apply
                                            </button>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    `;
                } else {
                    container.innerHTML = `
                        <div class="empty-message">
                            <p>No patches available for this package.</p>
                            <button class="btn btn-primary" onclick="createPatch()" style="margin-top: 1rem;">
                                <i class="fas fa-plus"></i> Create New Patch
                            </button>
                        </div>
                    `;
                }
            } catch (error) {
                document.getElementById('patches-list').innerHTML = `
                    <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                        <i class="fas fa-exclamation-circle"></i> Error loading patches: ${escapeHtml(error.message)}
                    </div>
                `;
            }
        }

        // Action functions
        function createPatch() {
            window.location.href = `/pages/admin/patches.php?action=create&package_id=${packageId}`;
        }

        function applyPatch(patchId) {
            window.location.href = `/pages/admin/patches.php?action=apply&patch_id=${patchId}`;
        }

        function exportReport() {
            window.location.href = `/api/v1/software-packages/risk-priorities.php/${packageId}/export`;
        }

        function assignOwner() {
            // Get affected devices for this package
            fetch(`/api/v1/software-packages/risk-priorities.php/${packageId}/affected-assets`)
                .then(response => response.json())
                .then(result => {
                    if (result.success && result.data.length > 0) {
                        // Show assign owner modal with affected devices
                        window.assignOwnerModal.showForPackage(packageId, result.data);
                    } else {
                        alert('No affected devices found for this package.');
                    }
                })
                .catch(error => {
                    console.error('Error loading affected devices:', error);
                    alert('Error loading affected devices. Please try again.');
                });
        }

        function viewVulnerability(cveId) {
            // Fetch vulnerability details and show in modal
            fetch(`/pages/vulnerabilities/list.php?ajax=get_vulnerability_details&cve_id=${encodeURIComponent(cveId)}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        displayVulnerabilityModal(data.vulnerability, data.affected_devices);
                    } else {
                        alert('Error loading vulnerability details: ' + (data.error || 'Unknown error'));
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error loading vulnerability details');
                });
        }

        function displayVulnerabilityModal(vulnerability, affectedDevices) {
            document.getElementById('modalTitle').textContent = vulnerability.cve_id;
            
            const modalBody = document.getElementById('modalBody');
            modalBody.innerHTML = `
                <div class="vulnerability-details">
                    <div class="detail-section">
                        <h3>Overview</h3>
                        <div class="detail-grid">
                            <div class="detail-item">
                                <label>Description:</label>
                                <p>${escapeHtml(vulnerability.description || 'No description available')}</p>
                            </div>
                            <div class="detail-item">
                                <label>Severity:</label>
                                <span class="severity-badge ${vulnerability.severity?.toLowerCase() || 'unknown'}">
                                    ${vulnerability.severity || 'Unknown'}
                                </span>
                            </div>
                            <div class="detail-item">
                                <label>CVSS Scores:</label>
                                <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                                    ${vulnerability.cvss_v4_score ? 
                                        `<div><span class="cvss-score ${getCvssClass(vulnerability.cvss_v4_score)}">${vulnerability.cvss_v4_score}</span> <span style="font-size: 0.75rem; color: var(--text-muted);">(v4.0)</span></div>` : 
                                        ''
                                    }
                                    ${vulnerability.cvss_v3_score ? 
                                        `<div><span class="cvss-score ${getCvssClass(vulnerability.cvss_v3_score)}">${vulnerability.cvss_v3_score}</span> <span style="font-size: 0.75rem; color: var(--text-muted);">(v3.x)</span></div>` : 
                                        ''
                                    }
                                    ${vulnerability.cvss_v2_score ? 
                                        `<div><span class="cvss-score ${getCvssClass(vulnerability.cvss_v2_score)}">${vulnerability.cvss_v2_score}</span> <span style="font-size: 0.75rem; color: var(--text-muted);">(v2.0)</span></div>` : 
                                        ''
                                    }
                                    ${!vulnerability.cvss_v4_score && !vulnerability.cvss_v3_score && !vulnerability.cvss_v2_score ? 
                                        '<span class="text-muted">N/A</span>' : 
                                        ''
                                    }
                                </div>
                            </div>
                            <div class="detail-item">
                                <label>Published:</label>
                                <span>${vulnerability.published_date ? new Date(vulnerability.published_date).toLocaleDateString() : 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <label>Last Modified:</label>
                                <span>${vulnerability.last_modified_date ? new Date(vulnerability.last_modified_date).toLocaleDateString() : 'N/A'}</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="detail-section">
                        <h3>Impact Summary</h3>
                        <div class="impact-stats">
                            <div class="impact-stat">
                                <span class="stat-number">${vulnerability.total_affected || 0}</span>
                                <span class="stat-label">Total Affected</span>
                            </div>
                            <div class="impact-stat">
                                <span class="stat-number">${vulnerability.open_count || 0}</span>
                                <span class="stat-label">Open</span>
                            </div>
                            <div class="impact-stat">
                                <span class="stat-number">${vulnerability.in_progress_count || 0}</span>
                                <span class="stat-label">In Progress</span>
                            </div>
                            <div class="impact-stat">
                                <span class="stat-number">${vulnerability.resolved_count || 0}</span>
                                <span class="stat-label">Resolved</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="detail-section">
                        <h3>Affected Devices</h3>
                        ${affectedDevices && affectedDevices.length > 0 ? `
                            <div class="affected-devices">
                                ${affectedDevices.map(device => `
                                    <div class="device-item">
                                        <div class="device-info">
                                            <strong>${device.device_name || 'Unknown Device'}</strong>
                                            <div class="device-details">
                                                ${device.hostname ? `<span class="device-hostname">Hostname: ${device.hostname}</span>` : ''}
                                                ${device.fda_device_name ? `<span class="device-fda-name">FDA Name: ${device.fda_device_name}</span>` : ''}
                                                ${device.brand_name ? `<span class="device-brand">Brand: ${device.brand_name}</span>` : ''}
                                                ${device.model_number ? `<span class="device-model">Model: ${device.model_number}</span>` : ''}
                                                ${device.manufacturer_name ? `<span class="device-manufacturer">Manufacturer: ${device.manufacturer_name}</span>` : ''}
                                                ${device.asset_tag ? `<span class="device-tag">Tag: ${device.asset_tag}</span>` : ''}
                                                ${device.ip_address ? `<span class="device-ip">IP: ${device.ip_address}</span>` : ''}
                                                ${device.asset_type ? `<span class="device-type">Type: ${device.asset_type}</span>` : ''}
                                            </div>
                                        </div>
                                        <div class="component-info">
                                            <span class="component-name">${device.component_name || 'N/A'}</span>
                                            ${device.component_version ? `<span class="component-version">v${device.component_version}</span>` : ''}
                                            ${device.component_vendor ? `<span class="component-vendor">${device.component_vendor}</span>` : ''}
                                        </div>
                                        <div class="device-status">
                                            <span class="status-badge ${device.remediation_status?.toLowerCase().replace(' ', '-') || 'open'}">
                                                ${device.remediation_status || 'Open'}
                                            </span>
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        ` : '<p class="text-muted">No affected devices found</p>'}
                    </div>
                </div>
            `;
            
            // Show the modal
            document.getElementById('vulnerabilityModal').style.display = 'block';
        }

        function closeVulnerabilityModal() {
            document.getElementById('vulnerabilityModal').style.display = 'none';
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('vulnerabilityModal');
            if (event.target === modal) {
                closeVulnerabilityModal();
            }
        };

        function getCvssClass(score) {
            if (score >= 9.0) return 'critical';
            if (score >= 7.0) return 'high';
            if (score >= 4.0) return 'medium';
            return 'low';
        }

        function viewAsset(assetId) {
            window.location.href = `/pages/assets/view.php?id=${assetId}`;
        }

        // Utility functions
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function formatDate(dateString) {
            if (!dateString) return 'N/A';
            const date = new Date(dateString);
            return date.toLocaleDateString('en-US', {year: 'numeric', month: 'short', day: 'numeric'});
        }
    </script>

</body>
</html>

