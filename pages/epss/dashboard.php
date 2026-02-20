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

// Require authentication
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['ajax']) {
        case 'get_epss_overview':
            // Get comprehensive EPSS overview statistics
            $sql = "SELECT 
                COUNT(*) as total_vulnerabilities,
                COUNT(CASE WHEN epss_score IS NOT NULL THEN 1 END) as vulnerabilities_with_epss,
                COUNT(CASE WHEN epss_score >= 0.7 THEN 1 END) as high_epss_count,
                COUNT(CASE WHEN epss_score >= 0.3 AND epss_score < 0.7 THEN 1 END) as medium_epss_count,
                COUNT(CASE WHEN epss_score < 0.3 THEN 1 END) as low_epss_count,
                ROUND(AVG(epss_score), 4) as avg_epss_score,
                ROUND(AVG(epss_percentile), 4) as avg_epss_percentile,
                MAX(epss_last_updated) as last_epss_update,
                MIN(epss_score) as min_epss_score,
                MAX(epss_score) as max_epss_score
            FROM vulnerabilities 
            WHERE epss_score IS NOT NULL";
            
            $stmt = $db->query($sql);
            $overall_stats = $stmt->fetch();
            
            echo json_encode(['success' => true, 'data' => $overall_stats]);
            exit;
            
        case 'get_epss_trends':
            $days = intval($_GET['days'] ?? 30);
            $days = min(365, max(1, $days));
            
            try {
                // Check if epss_score_history table exists, if not use vulnerabilities table
                $checkTable = $db->query("SELECT to_regclass('epss_score_history')");
                $tableExists = $checkTable->fetchColumn();
                
                if ($tableExists) {
                    $sql = "SELECT 
                        recorded_date,
                        COUNT(*) as vulnerabilities_count,
                        ROUND(AVG(epss_score), 4) as avg_epss_score,
                        COUNT(CASE WHEN epss_score >= 0.7 THEN 1 END) as high_epss_count,
                        COUNT(CASE WHEN epss_score >= 0.3 AND epss_score < 0.7 THEN 1 END) as medium_epss_count,
                        COUNT(CASE WHEN epss_score < 0.3 THEN 1 END) as low_epss_count
                    FROM epss_score_history 
                    WHERE recorded_date >= CURRENT_DATE - INTERVAL '" . $days . " days'
                    GROUP BY recorded_date
                    ORDER BY recorded_date DESC";
                } else {
                    // Fallback to vulnerabilities table with date grouping
                    $sql = "SELECT 
                        DATE(epss_last_updated) as recorded_date,
                        COUNT(*) as vulnerabilities_count,
                        ROUND(AVG(epss_score), 4) as avg_epss_score,
                        COUNT(CASE WHEN epss_score >= 0.7 THEN 1 END) as high_epss_count,
                        COUNT(CASE WHEN epss_score >= 0.3 AND epss_score < 0.7 THEN 1 END) as medium_epss_count,
                        COUNT(CASE WHEN epss_score < 0.3 THEN 1 END) as low_epss_count
                    FROM vulnerabilities 
                    WHERE epss_score IS NOT NULL 
                    AND epss_last_updated >= CURRENT_DATE - INTERVAL '" . $days . " days'
                    GROUP BY DATE(epss_last_updated)
                    ORDER BY DATE(epss_last_updated) DESC";
                }
                
                $stmt = $db->query($sql);
                $trends = $stmt->fetchAll();
                
                echo json_encode(['success' => true, 'data' => $trends]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => 'Failed to load trends: ' . $e->getMessage()]);
            }
            exit;
            
        case 'get_high_risk_epss':
            $limit = intval($_GET['limit'] ?? 20);
            $threshold = floatval($_GET['threshold'] ?? 0.7);
            
            $sql = "SELECT 
                v.cve_id,
                v.description,
                v.severity,
                v.epss_score,
                v.epss_percentile,
                v.epss_date,
                v.is_kev,
                COUNT(dvl.device_id) as affected_assets,
                COUNT(CASE WHEN dvl.remediation_status = 'Open' THEN 1 END) as open_count
            FROM vulnerabilities v
            LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
            WHERE v.epss_score >= ?
            GROUP BY v.cve_id, v.description, v.severity, v.epss_score, v.epss_percentile, v.epss_date, v.is_kev
            ORDER BY v.epss_score DESC, v.epss_percentile DESC
            LIMIT ?";
            
            $stmt = $db->prepare($sql);
            $stmt->execute([$threshold, $limit]);
            $high_risk = $stmt->fetchAll();
            
            echo json_encode(['success' => true, 'data' => $high_risk]);
            exit;
            
        case 'get_epss_by_severity':
            $sql = "SELECT 
                v.severity,
                COUNT(*) as count,
                ROUND(AVG(v.epss_score), 4) as avg_epss_score,
                ROUND(AVG(v.epss_percentile), 4) as avg_epss_percentile,
                COUNT(CASE WHEN v.epss_score >= 0.7 THEN 1 END) as high_epss_count,
                COUNT(CASE WHEN v.epss_score >= 0.3 AND v.epss_score < 0.7 THEN 1 END) as medium_epss_count,
                COUNT(CASE WHEN v.epss_score < 0.3 THEN 1 END) as low_epss_count
            FROM vulnerabilities v
            WHERE v.epss_score IS NOT NULL
            GROUP BY v.severity
            ORDER BY 
                CASE v.severity 
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END";
            
            $stmt = $db->query($sql);
            $severity_stats = $stmt->fetchAll();
            
            echo json_encode(['success' => true, 'data' => $severity_stats]);
            exit;
    }
}

// Get initial EPSS data for page load
$sql = "SELECT 
    COUNT(*) as total_vulnerabilities,
    COUNT(CASE WHEN epss_score IS NOT NULL THEN 1 END) as vulnerabilities_with_epss,
    COUNT(CASE WHEN epss_score >= 0.7 THEN 1 END) as high_epss_count,
    COUNT(CASE WHEN epss_score >= 0.3 AND epss_score < 0.7 THEN 1 END) as medium_epss_count,
    COUNT(CASE WHEN epss_score < 0.3 THEN 1 END) as low_epss_count,
    ROUND(AVG(epss_score), 4) as avg_epss_score,
    ROUND(AVG(epss_percentile), 4) as avg_epss_percentile,
    MAX(epss_last_updated) as last_epss_update
FROM vulnerabilities 
WHERE epss_score IS NOT NULL";

$stmt = $db->query($sql);
$epss_stats = $stmt->fetch();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EPSS Dashboard - </title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/priority-badges.css">
    <link rel="stylesheet" href="/assets/css/epss-badges.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        /* Siemens Healthineers Brand Color Variables */
        :root {
            --siemens-petrol: #009999;
            --siemens-petrol-dark: #007777;
            --siemens-petrol-light: #00bbbb;
            --siemens-orange: #ff6b35;
            --siemens-orange-dark: #e55a2b;
            --siemens-orange-light: #ff8c5a;
        }
        
        /* Siemens Healthineers Typography */
        body, .epss-header, .metric-card, .chart-container {
            font-family: 'Siemens Sans', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        /* EPSS Dashboard Specific Styles */
        .epss-header {
            margin-bottom: 2rem;
        }
        
        .epss-header h1 {
            font-size: 2rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.5rem;
        }
        
        .epss-header .subtitle {
            color: var(--text-secondary, #cbd5e1);
            font-size: 1rem;
        }
        
        .epss-metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .epss-metric-card {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            transition: all 0.2s ease;
        }
        
        .epss-metric-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.4);
        }
        
        .epss-metric-card.high-risk {
            border-left: 4px solid #ef4444;
            background: linear-gradient(135deg, var(--bg-card, #1a1a1a) 0%, #1a0a0a 100%);
        }
        
        .epss-metric-card.medium-risk {
            border-left: 4px solid #f59e0b;
            background: linear-gradient(135deg, var(--bg-card, #1a1a1a) 0%, #1a1205 100%);
        }
        
        .epss-metric-card.low-risk {
            border-left: 4px solid var(--siemens-petrol, #009999);
            background: linear-gradient(135deg, var(--bg-card, #1a1a1a) 0%, #0a1515 100%);
        }
        
        .epss-metric-card.overview {
            border-left: 4px solid #6b7280;
            background: linear-gradient(135deg, var(--bg-card, #1a1a1a) 0%, #0f0f0f 100%);
        }
        
        .metric-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
        }
        
        .metric-title {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-secondary, #cbd5e1);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .metric-icon {
            width: 2rem;
            height: 2rem;
            border-radius: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1rem;
        }
        
        .metric-icon.high-risk {
            background: #ef4444;
        }
        
        .metric-icon.medium-risk {
            background: #f59e0b;
        }
        
        .metric-icon.low-risk {
            background: var(--siemens-petrol, #009999);
        }
        
        .metric-icon.overview {
            background: #6b7280;
        }
        
        .metric-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.5rem;
        }
        
        .metric-description {
            font-size: 0.875rem;
            color: var(--text-muted, #94a3b8);
            margin-bottom: 1rem;
        }
        
        .metric-details {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 0.75rem;
        }
        
        .metric-detail {
            display: flex;
            flex-direction: column;
        }
        
        .metric-detail-label {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.25rem;
        }
        
        .metric-detail-value {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
        }
        
        .charts-section {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .chart-container {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        
        .chart-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.5rem;
        }
        
        .chart-title {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
        }
        
        .chart-controls {
            display: flex;
            gap: 0.5rem;
        }
        
        .chart-controls select {
            background: var(--bg-secondary, #0f0f0f);
            border: 1px solid var(--border-primary, #333333);
            color: var(--text-primary, #ffffff);
            padding: 0.5rem 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .chart-controls select:hover {
            border-color: var(--siemens-petrol, #009999);
        }
        
        .chart-controls select:focus {
            outline: none;
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 0 0 2px rgba(0, 153, 153, 0.1);
        }
        
        .high-risk-section {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        
        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.5rem;
        }
        
        .section-title {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
        }
        
        .vulnerability-list {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }
        
        .vulnerability-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1.5rem;
            background: var(--bg-secondary, #0f0f0f);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            transition: all 0.2s ease;
            margin-bottom: 0.75rem;
        }
        
        .vulnerability-item:hover {
            background: var(--bg-hover, #333333);
            transform: translateY(-1px);
        }
        
        .vuln-info {
            flex: 1;
        }
        
        .vuln-cve {
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.25rem;
            font-family: 'Courier New', monospace;
        }
        
        .vuln-description {
            font-size: 0.875rem;
            color: var(--text-secondary, #cbd5e1);
            margin-bottom: 0.25rem;
        }
        
        .vuln-meta {
            display: flex;
            gap: 1rem;
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
        }
        
        .vuln-scores {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 0.5rem;
        }
        
        .epss-score {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--siemens-petrol-light, #00bbbb);
        }
        
        .epss-percentile {
            font-size: 0.875rem;
            color: var(--text-secondary, #cbd5e1);
        }
        
        .severity-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-badge.critical {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid #ef4444;
        }
        
        .severity-badge.high {
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
            border: 1px solid #f59e0b;
        }
        
        .severity-badge.medium {
            background: rgba(0, 153, 153, 0.2);
            color: var(--siemens-petrol, #009999);
            border: 1px solid var(--siemens-petrol, #009999);
        }
        
        .severity-badge.low {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
            border: 1px solid #10b981;
        }
        
        .kev-badge {
            background: #7c3aed;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.625rem;
            font-weight: 700;
            text-transform: uppercase;
        }
        
        .loading-state {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
            color: var(--text-secondary, #cbd5e1);
        }
        
        .loading-state i {
            margin-right: 0.5rem;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        .empty-state {
            text-align: center;
            padding: 2rem;
            color: var(--text-muted, #94a3b8);
        }
        
        .empty-state i {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        /* Responsive Design */
        @media (max-width: 1200px) {
            .charts-section {
                grid-template-columns: 1fr;
            }
        }
        
        @media (max-width: 768px) {
            .epss-metrics-grid {
                grid-template-columns: 1fr;
            }
            
            .vulnerability-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.75rem;
            }
            
            .vuln-scores {
                align-items: flex-start;
            }
        }
    </style>
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>
    
    <main class="main-content">
        <div class="container">
            <!-- Page Header -->
            <div class="epss-header">
                <h1>EPSS Dashboard</h1>
                <p class="subtitle">Exploit Prediction Scoring System - Comprehensive Risk Analytics</p>
            </div>
            
            <!-- EPSS Metrics Overview -->
            <div class="epss-metrics-grid">
                <!-- Total Vulnerabilities with EPSS -->
                <div class="epss-metric-card overview">
                    <div class="metric-header">
                        <span class="metric-title">Total EPSS Data</span>
                        <div class="metric-icon overview">
                            <i class="fas fa-database"></i>
                        </div>
                    </div>
                    <div class="metric-value" id="total-epss-count"><?= $epss_stats['vulnerabilities_with_epss'] ?? 0 ?></div>
                    <div class="metric-description">Vulnerabilities with EPSS scores</div>
                    <div class="metric-details">
                        <div class="metric-detail">
                            <span class="metric-detail-label">Last Updated</span>
                            <span class="metric-detail-value" id="last-update"><?= $epss_stats['last_epss_update'] ? date('M j, Y', strtotime($epss_stats['last_epss_update'])) : 'N/A' ?></span>
                        </div>
                        <div class="metric-detail">
                            <span class="metric-detail-label">Avg Score</span>
                            <span class="metric-detail-value" id="avg-score"><?= $epss_stats['avg_epss_score'] ? number_format($epss_stats['avg_epss_score'] * 100, 1) . '%' : 'N/A' ?></span>
                        </div>
                    </div>
                </div>
                
                <!-- High Risk EPSS -->
                <div class="epss-metric-card high-risk">
                    <div class="metric-header">
                        <span class="metric-title">High Risk (≥70%)</span>
                        <div class="metric-icon high-risk">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                    </div>
                    <div class="metric-value" id="high-risk-count"><?= $epss_stats['high_epss_count'] ?? 0 ?></div>
                    <div class="metric-description">Vulnerabilities with EPSS ≥70%</div>
                    <div class="metric-details">
                        <div class="metric-detail">
                            <span class="metric-detail-label">Percentage</span>
                            <span class="metric-detail-value" id="high-risk-percentage">
                                <?= $epss_stats['vulnerabilities_with_epss'] > 0 ? 
                                    number_format(($epss_stats['high_epss_count'] / $epss_stats['vulnerabilities_with_epss']) * 100, 1) . '%' : '0%' ?>
                            </span>
                        </div>
                        <div class="metric-detail">
                            <span class="metric-detail-label">Priority</span>
                            <span class="metric-detail-value">Critical</span>
                        </div>
                    </div>
                </div>
                
                <!-- Medium Risk EPSS -->
                <div class="epss-metric-card medium-risk">
                    <div class="metric-header">
                        <span class="metric-title">Medium Risk (30-70%)</span>
                        <div class="metric-icon medium-risk">
                            <i class="fas fa-exclamation-circle"></i>
                        </div>
                    </div>
                    <div class="metric-value" id="medium-risk-count"><?= $epss_stats['medium_epss_count'] ?? 0 ?></div>
                    <div class="metric-description">Vulnerabilities with EPSS 30-70%</div>
                    <div class="metric-details">
                        <div class="metric-detail">
                            <span class="metric-detail-label">Percentage</span>
                            <span class="metric-detail-value" id="medium-risk-percentage">
                                <?= $epss_stats['vulnerabilities_with_epss'] > 0 ? 
                                    number_format(($epss_stats['medium_epss_count'] / $epss_stats['vulnerabilities_with_epss']) * 100, 1) . '%' : '0%' ?>
                            </span>
                        </div>
                        <div class="metric-detail">
                            <span class="metric-detail-label">Priority</span>
                            <span class="metric-detail-value">High</span>
                        </div>
                    </div>
                </div>
                
                <!-- Low Risk EPSS -->
                <div class="epss-metric-card low-risk">
                    <div class="metric-header">
                        <span class="metric-title">Low Risk (<30%)</span>
                        <div class="metric-icon low-risk">
                            <i class="fas fa-check-circle"></i>
                        </div>
                    </div>
                    <div class="metric-value" id="low-risk-count"><?= $epss_stats['low_epss_count'] ?? 0 ?></div>
                    <div class="metric-description">Vulnerabilities with EPSS <30%</div>
                    <div class="metric-details">
                        <div class="metric-detail">
                            <span class="metric-detail-label">Percentage</span>
                            <span class="metric-detail-value" id="low-risk-percentage">
                                <?= $epss_stats['vulnerabilities_with_epss'] > 0 ? 
                                    number_format(($epss_stats['low_epss_count'] / $epss_stats['vulnerabilities_with_epss']) * 100, 1) . '%' : '0%' ?>
                            </span>
                        </div>
                        <div class="metric-detail">
                            <span class="metric-detail-label">Priority</span>
                            <span class="metric-detail-value">Medium</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Charts Section -->
            <div class="charts-section">
                <!-- EPSS Trends Chart -->
                <div class="chart-container">
                    <div class="chart-header">
                        <h3 class="chart-title">EPSS Trends</h3>
                        <div class="chart-controls">
                            <select id="trend-period">
                                <option value="7">Last 7 days</option>
                                <option value="30" selected>Last 30 days</option>
                                <option value="90">Last 90 days</option>
                                <option value="365">Last year</option>
                            </select>
                        </div>
                    </div>
                    <div style="height: 300px; position: relative;">
                        <canvas id="trendsChart"></canvas>
                    </div>
                </div>
                
                <!-- EPSS Distribution Chart -->
                <div class="chart-container">
                    <div class="chart-header">
                        <h3 class="chart-title">Risk Distribution</h3>
                    </div>
                    <div style="height: 300px; position: relative;">
                        <canvas id="distributionChart"></canvas>
                    </div>
                </div>
            </div>
            
            <!-- High-Risk EPSS Vulnerabilities -->
            <div class="high-risk-section">
                <div class="section-header">
                    <h3 class="section-title">High-Risk EPSS Vulnerabilities</h3>
                    <div class="chart-controls">
                        <select id="risk-threshold">
                            <option value="0.7">≥70% EPSS</option>
                            <option value="0.5">≥50% EPSS</option>
                            <option value="0.3">≥30% EPSS</option>
                        </select>
                        <select id="risk-limit">
                            <option value="10">Top 10</option>
                            <option value="20" selected>Top 20</option>
                            <option value="50">Top 50</option>
                        </select>
                    </div>
                </div>
                <div id="high-risk-list">
                    <div class="loading-state">
                        <i class="fas fa-spinner"></i>
                        Loading high-risk vulnerabilities...
                    </div>
                </div>
            </div>
        </div>
    </main>
    
    <script>
        let trendsChart = null;
        let distributionChart = null;
        
        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {
            loadTrends();
            loadDistribution();
            loadHighRiskVulnerabilities();
            
            // Add event listeners for dropdowns
            const trendPeriodSelect = document.getElementById('trend-period');
            if (trendPeriodSelect) {
                trendPeriodSelect.addEventListener('change', function() {
                    loadTrends();
                });
            }
            
            const riskThresholdSelect = document.getElementById('risk-threshold');
            const riskLimitSelect = document.getElementById('risk-limit');
            
            if (riskThresholdSelect) {
                riskThresholdSelect.addEventListener('change', function() {
                    loadHighRiskVulnerabilities();
                });
            }
            
            if (riskLimitSelect) {
                riskLimitSelect.addEventListener('change', function() {
                    loadHighRiskVulnerabilities();
                });
            }
        });
        
        // Load EPSS trends
        async function loadTrends() {
            try {
                const days = document.getElementById('trend-period').value;
                
                const response = await fetch(`?ajax=get_epss_trends&days=${days}`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const text = await response.text();
                
                let result;
                try {
                    result = JSON.parse(text);
                } catch (parseError) {
                    console.error('JSON parse error:', parseError);
                    console.error('Response text:', text);
                    throw new Error('Invalid JSON response');
                }
                
                if (result.success) {
                    createTrendsChart(result.data);
                } else {
                    console.error('Failed to load trends:', result.error);
                    // Show error in chart area
                    const chartContainer = document.getElementById('trendsChart').parentElement;
                    chartContainer.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><p>Failed to load trends data</p></div>';
                }
            } catch (error) {
                console.error('Error loading trends:', error);
                // Show error in chart area
                const chartContainer = document.getElementById('trendsChart').parentElement;
                chartContainer.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><p>Error loading trends: ' + error.message + '</p></div>';
            }
        }
        
        // Create trends chart
        function createTrendsChart(data) {
            const ctx = document.getElementById('trendsChart').getContext('2d');
            
            if (trendsChart) {
                trendsChart.destroy();
            }
            
            const labels = data.map(item => new Date(item.recorded_date).toLocaleDateString()).reverse();
            const highRiskData = data.map(item => item.high_epss_count).reverse();
            const mediumRiskData = data.map(item => item.medium_epss_count).reverse();
            const lowRiskData = data.map(item => item.low_epss_count).reverse();
            
            trendsChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'High Risk (≥70%)',
                            data: highRiskData,
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            tension: 0.4
                        },
                        {
                            label: 'Medium Risk (30-70%)',
                            data: mediumRiskData,
                            borderColor: '#f59e0b',
                            backgroundColor: 'rgba(245, 158, 11, 0.1)',
                            tension: 0.4
                        },
                        {
                            label: 'Low Risk (<30%)',
                            data: lowRiskData,
                            borderColor: '#009999',
                            backgroundColor: 'rgba(0, 153, 153, 0.1)',
                            tension: 0.4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#cbd5e1'
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: '#94a3b8'
                            },
                            grid: {
                                color: '#374151'
                            }
                        },
                        y: {
                            ticks: {
                                color: '#94a3b8'
                            },
                            grid: {
                                color: '#374151'
                            }
                        }
                    }
                }
            });
        }
        
        // Load EPSS distribution
        async function loadDistribution() {
            try {
                const response = await fetch('?ajax=get_epss_by_severity');
                const result = await response.json();
                
                if (result.success) {
                    createDistributionChart(result.data);
                } else {
                    console.error('Failed to load distribution:', result.error);
                }
            } catch (error) {
                console.error('Error loading distribution:', error);
            }
        }
        
        // Create distribution chart
        function createDistributionChart(data) {
            const ctx = document.getElementById('distributionChart').getContext('2d');
            
            if (distributionChart) {
                distributionChart.destroy();
            }
            
            const labels = data.map(item => item.severity);
            const highRiskData = data.map(item => item.high_epss_count);
            const mediumRiskData = data.map(item => item.medium_epss_count);
            const lowRiskData = data.map(item => item.low_epss_count);
            
            distributionChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'High Risk',
                            data: highRiskData,
                            backgroundColor: '#ef4444'
                        },
                        {
                            label: 'Medium Risk',
                            data: mediumRiskData,
                            backgroundColor: '#f59e0b'
                        },
                        {
                            label: 'Low Risk',
                            data: lowRiskData,
                            backgroundColor: '#009999'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#cbd5e1'
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: '#94a3b8'
                            },
                            grid: {
                                color: '#374151'
                            }
                        },
                        y: {
                            ticks: {
                                color: '#94a3b8'
                            },
                            grid: {
                                color: '#374151'
                            }
                        }
                    }
                }
            });
        }
        
        // Load high-risk vulnerabilities
        async function loadHighRiskVulnerabilities() {
            try {
                const threshold = document.getElementById('risk-threshold').value;
                const limit = document.getElementById('risk-limit').value;
                
                
                const response = await fetch(`?ajax=get_high_risk_epss&threshold=${threshold}&limit=${limit}`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const text = await response.text();
                
                let result;
                try {
                    result = JSON.parse(text);
                } catch (parseError) {
                    console.error('JSON parse error:', parseError);
                    throw new Error('Invalid JSON response');
                }
                
                if (result.success) {
                    displayHighRiskVulnerabilities(result.data);
                } else {
                    console.error('Failed to load high-risk vulnerabilities:', result.error);
                    document.getElementById('high-risk-list').innerHTML = 
                        '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><p>Failed to load vulnerabilities: ' + result.error + '</p></div>';
                }
            } catch (error) {
                console.error('Error loading high-risk vulnerabilities:', error);
                document.getElementById('high-risk-list').innerHTML = 
                    '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><p>Error loading vulnerabilities: ' + error.message + '</p></div>';
            }
        }
        
        // Display high-risk vulnerabilities
        function displayHighRiskVulnerabilities(vulnerabilities) {
            const container = document.getElementById('high-risk-list');
            
            if (vulnerabilities.length === 0) {
                container.innerHTML = '<div class="empty-state"><i class="fas fa-shield-alt"></i><p>No high-risk vulnerabilities found</p></div>';
                return;
            }
            
            container.innerHTML = vulnerabilities.map(vuln => `
                <div class="vulnerability-item">
                    <div class="vuln-info">
                        <div class="vuln-cve">${vuln.cve_id}</div>
                        <div class="vuln-description">${vuln.description || 'No description available'}</div>
                        <div class="vuln-meta">
                            <span>${vuln.affected_assets} affected assets</span>
                            <span>${vuln.open_count} open</span>
                            ${vuln.is_kev ? '<span class="kev-badge">KEV</span>' : ''}
                        </div>
                    </div>
                    <div class="vuln-scores">
                        <div class="epss-score">${(vuln.epss_score * 100).toFixed(1)}%</div>
                        <div class="epss-percentile">${(vuln.epss_percentile * 100).toFixed(1)}% percentile</div>
                        <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                    </div>
                </div>
            `).join('');
        }
    </script>
</body>
</html>
