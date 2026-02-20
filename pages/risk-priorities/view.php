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

$linkId = $_GET['id'] ?? null;

if (!$linkId) {
    header('Location: /pages/risk-priorities/dashboard.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Handle GET AJAX requests for modal
if (isset($_GET['ajax']) && $_GET['ajax'] === 'get_priority_details') {
    header('Content-Type: application/json');
    
    try {
        // Check if this is an action_id (from vulnerabilities view) or link_id (from device vulnerabilities)
        $id = $_GET['id'];
        
        // First try to get from device_vulnerabilities_link (most common case)
        $sql = "SELECT 
                    dvl.link_id,
                    dvl.device_id,
                    dvl.component_id,
                    dvl.cve_id,
                    dvl.remediation_status,
                    dvl.remediation_notes,
                    dvl.assigned_to,
                    dvl.due_date,
                    dvl.vendor_name,
                    dvl.vendor_contact,
                    dvl.vendor_ticket_id,
                    dvl.vendor_status,
                    dvl.patch_expected_date,
                    dvl.patch_applied_date,
                    dvl.risk_score as calculated_risk_score,
                    dvl.priority_tier,
                    dvl.compensating_controls,
                    dvl.created_at,
                    dvl.updated_at,
                    v.epss_score,
                    v.epss_percentile,
                    v.epss_date,
                    v.epss_last_updated,
                    v.severity,
                    CASE 
                        WHEN a.hostname IS NOT NULL AND a.hostname != '' THEN a.hostname
                        WHEN a.asset_tag IS NOT NULL AND a.asset_tag != '' THEN a.asset_tag
                        WHEN md.brand_name IS NOT NULL THEN md.brand_name || ' ' || COALESCE(md.model_number, '') || ' (' || COALESCE(md.manufacturer_name, '') || ')'
                        WHEN a.asset_type IS NOT NULL THEN a.asset_type || ' ' || COALESCE(a.manufacturer, '') || ' ' || COALESCE(a.model, '')
                        ELSE 'Unidentified Device'
                    END as device_name,
                    COALESCE(a.hostname, 'N/A') as hostname,
                    COALESCE(a.ip_address::text, 'N/A') as ip_address,
                    COALESCE(a.criticality, 'High') as asset_criticality,
                    COALESCE(l.location_name, 'Location Not Mapped') as location_name,
                    COALESCE(l.criticality, 5) as location_criticality,
                    dvl.remediation_status as status,
                    '' as action_description
                FROM device_vulnerabilities_link dvl
                LEFT JOIN medical_devices md ON dvl.device_id = md.device_id
                LEFT JOIN assets a ON md.asset_id = a.asset_id
                LEFT JOIN locations l ON a.location_id = l.location_id
                LEFT JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
                WHERE dvl.link_id = ?";
        
        $stmt = $db->prepare($sql);
        $stmt->execute([$id]);
        $priority = $stmt->fetch();
        
        // If not found in device_vulnerabilities_link, try remediation_actions (for vulnerabilities view mode)
        if (!$priority) {
            $sql = "SELECT ra.*, ars.urgency_score, ars.efficiency_score, 
                           v.epss_score, v.epss_percentile, v.epss_date, v.epss_last_updated,
                           CASE 
                               WHEN a.hostname IS NOT NULL AND a.hostname != '' THEN a.hostname
                               WHEN a.asset_tag IS NOT NULL AND a.asset_tag != '' THEN a.asset_tag
                               WHEN md.brand_name IS NOT NULL THEN md.brand_name || ' ' || COALESCE(md.model_number, '') || ' (' || COALESCE(md.manufacturer_name, '') || ')'
                               WHEN a.asset_type IS NOT NULL THEN a.asset_type || ' ' || COALESCE(a.manufacturer, '') || ' ' || COALESCE(a.model, '')
                               ELSE 'Unidentified Device'
                           END as device_name,
                           COALESCE(a.hostname, 'N/A') as hostname,
                           COALESCE(a.ip_address::text, 'N/A') as ip_address,
                           COALESCE(a.criticality, 'High') as asset_criticality,
                           COALESCE(l.location_name, 'Location Not Mapped') as location_name,
                           COALESCE(l.criticality, 5) as location_criticality,
                           COALESCE(v.severity, 'High') as severity,
                           ars.urgency_score as calculated_risk_score,
                           ra.action_id as link_id,
                           ra.assigned_to,
                           ra.due_date,
                           ra.created_at,
                           ra.status,
                           ra.action_description,
                           ra.cve_id,
                           CASE 
                               WHEN ars.urgency_score >= 1000 THEN 1
                               WHEN ars.urgency_score >= 180 THEN 2
                               WHEN ars.urgency_score >= 160 THEN 3
                               ELSE 4
                           END as priority_tier
                    FROM remediation_actions ra
                    LEFT JOIN action_risk_scores ars ON ra.action_id = ars.action_id
                    LEFT JOIN vulnerabilities v ON ra.cve_id = v.cve_id
                    LEFT JOIN action_device_links adl ON ra.action_id = adl.action_id
                    LEFT JOIN medical_devices md ON adl.device_id = md.device_id
                    LEFT JOIN assets a ON md.asset_id = a.asset_id
                    LEFT JOIN locations l ON a.location_id = l.location_id
                    WHERE ra.action_id = ?";
            
            $stmt = $db->prepare($sql);
            $stmt->execute([$id]);
            $priority = $stmt->fetch();
        }
        
        if (!$priority) {
            echo json_encode(['success' => false, 'error' => 'Priority not found']);
            exit;
        }
        
        echo json_encode(['success' => true, 'data' => $priority]);
        exit;
        
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => 'Database error: ' . $e->getMessage()]);
        exit;
    }
}

// Handle AJAX requests
if (isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    try {
        switch ($_POST['action']) {
            case 'update_remediation':
                $sql = "UPDATE device_vulnerabilities_link SET
                        remediation_status = ?,
                        remediation_notes = ?,
                        assigned_to = ?,
                        due_date = ?,
                        updated_at = CURRENT_TIMESTAMP
                        WHERE link_id = ?";
                
                $stmt = $db->prepare($sql);
                $stmt->execute([
                    $_POST['remediation_status'],
                    $_POST['remediation_notes'],
                    $_POST['assigned_to'] ?: null,
                    $_POST['due_date'] ?: null,
                    $linkId
                ]);
                
                echo json_encode(['success' => true, 'message' => 'Remediation details updated']);
                exit;
                
            case 'update_vendor':
                $sql = "UPDATE device_vulnerabilities_link SET
                        vendor_name = ?,
                        vendor_contact = ?,
                        vendor_ticket_id = ?,
                        vendor_status = ?,
                        patch_expected_date = ?,
                        patch_applied_date = ?,
                        updated_at = CURRENT_TIMESTAMP
                        WHERE link_id = ?";
                
                $stmt = $db->prepare($sql);
                $stmt->execute([
                    $_POST['vendor_name'],
                    $_POST['vendor_contact'],
                    $_POST['vendor_ticket_id'],
                    $_POST['vendor_status'],
                    $_POST['patch_expected_date'] ?: null,
                    $_POST['patch_applied_date'] ?: null,
                    $linkId
                ]);
                
                echo json_encode(['success' => true, 'message' => 'Vendor tracking updated']);
                exit;
                
            case 'add_control':
                $sql = "INSERT INTO compensating_controls_checklist 
                        (link_id, control_type, control_description, is_implemented, implemented_date, verified_by, notes)
                        VALUES (?, ?, ?, ?, ?, ?, ?)";
                
                $stmt = $db->prepare($sql);
                $stmt->execute([
                    $linkId,
                    $_POST['control_type'],
                    $_POST['control_description'],
                    $_POST['is_implemented'] === 'true',
                    $_POST['implemented_date'] ?: null,
                    $_POST['verified_by'] ?: null,
                    $_POST['notes']
                ]);
                
                echo json_encode(['success' => true, 'message' => 'Compensating control added']);
                exit;
                
            case 'delete_control':
                $sql = "DELETE FROM compensating_controls_checklist WHERE control_id = ?";
                $stmt = $db->prepare($sql);
                $stmt->execute([$_POST['control_id']]);
                
                echo json_encode(['success' => true, 'message' => 'Compensating control deleted']);
                exit;
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        exit;
    }
}

// Get priority details with EPSS data
$sql = "SELECT rpv.*, v.epss_score, v.epss_percentile, v.epss_date, v.epss_last_updated
        FROM risk_priority_view rpv
        LEFT JOIN vulnerabilities v ON rpv.cve_id = v.cve_id
        WHERE rpv.link_id = ?";
$stmt = $db->prepare($sql);
$stmt->execute([$linkId]);
$priority = $stmt->fetch();

if (!$priority) {
    header('Location: /pages/risk-priorities/dashboard.php');
    exit;
}

// Get additional details
$sql = "SELECT 
    remediation_notes,
    compensating_controls,
    vendor_name,
    vendor_contact,
    vendor_ticket_id,
    patch_applied_date
FROM device_vulnerabilities_link
WHERE link_id = ?";
$stmt = $db->prepare($sql);
$stmt->execute([$linkId]);
$details = $stmt->fetch();

// Get compensating controls
$sql = "SELECT 
    c.*,
    u.username as verified_by_name
FROM compensating_controls_checklist c
LEFT JOIN users u ON c.verified_by = u.user_id
WHERE c.link_id = ?
ORDER BY c.created_at DESC";
$stmt = $db->prepare($sql);
$stmt->execute([$linkId]);
$controls = $stmt->fetchAll();

// Get users for assignment
$sql = "SELECT user_id, username, email FROM users WHERE is_active = TRUE ORDER BY username";
$stmt = $db->query($sql);
$users = $stmt->fetchAll();

// Get full vulnerability details
$sql = "SELECT * FROM vulnerabilities WHERE cve_id = ?";
$stmt = $db->prepare($sql);
$stmt->execute([$priority['cve_id']]);
$vulnerability = $stmt->fetch();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Risk Priority Details - <?= dave_htmlspecialchars($priority['cve_id']) ?> - </title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/priority-badges.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Dark Theme Risk Priority View Styles */
        .priority-detail-container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .priority-header {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        
        .priority-title {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 1rem;
        }
        
        .priority-title h1 {
            font-size: 1.875rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.5rem;
        }
        
        .priority-title p {
            font-size: 0.875rem;
            color: var(--text-secondary, #cbd5e1);
            margin-top: 0.5rem;
            line-height: 1.5;
        }
        
        /* Back button styling */
        .btn-secondary {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.625rem 1.25rem;
            background: var(--bg-secondary, #0f0f0f);
            color: var(--text-primary, #ffffff);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            font-size: 0.875rem;
            font-weight: 500;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.2s ease;
            white-space: nowrap;
        }
        
        .btn-secondary:hover {
            background: var(--bg-hover, #222222);
            border-color: var(--siemens-petrol, #009999);
            transform: translateY(-1px);
        }
        
        .priority-meta {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .tab-content-container {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        
        .tabs {
            display: flex;
            border-bottom: 2px solid var(--border-primary, #333333);
            background: var(--bg-secondary, #0f0f0f);
        }
        
        .tab {
            padding: 1rem 2rem;
            font-weight: 500;
            color: var(--text-muted, #94a3b8);
            cursor: pointer;
            border-bottom: 2px solid transparent;
            margin-bottom: -2px;
            transition: all 0.2s;
        }
        
        .tab:hover {
            color: var(--siemens-petrol, #009999);
        }
        
        .tab.active {
            color: var(--siemens-petrol, #009999);
            border-bottom-color: var(--siemens-petrol, #009999);
        }
        
        .tab-content {
            display: none;
            padding: 2rem;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .form-section {
            margin-bottom: 2rem;
        }
        
        .form-section h3 {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            margin-bottom: 1rem;
        }
        
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }
        
        .form-group {
            display: flex;
            flex-direction: column;
        }
        
        .form-group label {
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-secondary, #cbd5e1);
            margin-bottom: 0.375rem;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            padding: 0.625rem 0.875rem;
            border: 1px solid var(--border-primary, #333333);
            background: var(--bg-secondary, #0f0f0f);
            color: var(--text-primary, #ffffff);
            border-radius: 0.375rem;
            font-size: 0.875rem;
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.2);
        }
        
        .form-group textarea {
            min-height: 100px;
            resize: vertical;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .info-item {
            display: flex;
            flex-direction: column;
        }
        
        .info-label {
            font-size: 0.75rem;
            font-weight: 500;
            color: var(--text-muted, #94a3b8);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.375rem;
        }
        
        .info-value {
            font-size: 1rem;
            color: var(--text-primary, #ffffff);
        }
        
        .controls-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        .control-item {
            background: var(--bg-secondary, #0f0f0f);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            padding: 1.5rem;
        }
        
        .control-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 1rem;
        }
        
        .control-type {
            font-weight: 600;
            color: var(--text-primary, #ffffff);
        }
        
        .control-status {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .control-description {
            color: var(--text-secondary, #cbd5e1);
            margin-bottom: 0.75rem;
        }
        
        .control-meta {
            display: flex;
            gap: 1.5rem;
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
        }
        
        .risk-breakdown {
            background: var(--bg-secondary, #0f0f0f);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .risk-breakdown h4 {
            font-size: 1rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            margin-bottom: 1rem;
        }
        
        .risk-component {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 0;
            border-bottom: 1px solid var(--border-primary, #333333);
        }
        
        .risk-component:last-child {
            border-bottom: none;
        }
        
        .risk-component-label {
            color: var(--text-secondary, #cbd5e1);
        }
        
        .risk-component-value {
            font-weight: 600;
            color: var(--text-primary, #ffffff);
        }
    </style>
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>
    
    <main class="main-content">
        <div class="priority-detail-container">
            <!-- Header -->
            <div class="priority-header">
                <div class="priority-title">
                    <div>
                        <h1><?= dave_htmlspecialchars($priority['cve_id']) ?></h1>
                        <p><?= dave_htmlspecialchars($vulnerability['description'] ?? 'No description available') ?></p>
                    </div>
                    <div>
                        <a href="/pages/risk-priorities/dashboard.php" class="btn btn-secondary">
                            <svg width="16" height="16" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd" />
                            </svg>
                            Back to List
                        </a>
                    </div>
                </div>
                <div class="priority-meta">
                    <span class="priority-badge priority-badge-tier-<?= $priority['priority_tier'] ?>">
                        TIER <?= $priority['priority_tier'] ?>
                    </span>
                    <?php if ($priority['is_kev']): ?>
                    <span class="kev-badge">KEV</span>
                    <?php endif; ?>
                    <span class="badge badge-<?= strtolower($priority['severity']) ?>">
                        <?= dave_htmlspecialchars($priority['severity']) ?>
                    </span>
                    <span class="risk-score risk-score-<?= $priority['calculated_risk_score'] >= 1000 ? 'critical' : ($priority['calculated_risk_score'] >= 150 ? 'high' : ($priority['calculated_risk_score'] >= 75 ? 'medium' : 'low')) ?>">
                        Risk Score: <?= $priority['calculated_risk_score'] ?>
                    </span>
                    <?php if ($priority['days_overdue'] > 0): ?>
                    <span class="overdue-badge">
                        <?= $priority['days_overdue'] ?> DAYS OVERDUE
                    </span>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Tabs -->
            <div class="tab-content-container">
                <div class="tabs">
                    <div class="tab active" onclick="switchTab('overview')">Overview</div>
                    <div class="tab" onclick="switchTab('vendor')">Vendor Tracking</div>
                    <div class="tab" onclick="switchTab('controls')">Compensating Controls</div>
                    <div class="tab" onclick="switchTab('assignment')">Assignment & Timeline</div>
                </div>
                
                <!-- Overview Tab -->
                <div id="tab-overview" class="tab-content active">
                    <div class="form-section">
                        <h3>Vulnerability Details</h3>
                        <div class="info-grid">
                            <div class="info-item">
                                <span class="info-label">CVE ID</span>
                                <span class="info-value"><?= dave_htmlspecialchars($priority['cve_id']) ?></span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Severity</span>
                                <span class="info-value"><?= dave_htmlspecialchars($priority['severity']) ?></span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">CVSS v3 Score</span>
                                <span class="info-value"><?= $priority['cvss_v3_score'] ?? 'N/A' ?></span>
                            </div>
                            <?php if ($priority['is_kev']): ?>
                            <div class="info-item">
                                <span class="info-label">KEV Due Date</span>
                                <span class="info-value"><?= $priority['kev_due_date'] ?? 'Not Set' ?></span>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                    
                    <div class="form-section">
                        <h3>Device Information</h3>
                        <div class="info-grid">
                            <div class="info-item">
                                <span class="info-label">Device Name</span>
                                <span class="info-value"><?= dave_htmlspecialchars($priority['device_name'] ?? 'Unknown') ?></span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Hostname</span>
                                <span class="info-value"><?= dave_htmlspecialchars($priority['hostname'] ?? 'N/A') ?></span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">IP Address</span>
                                <span class="info-value"><?= dave_htmlspecialchars($priority['ip_address'] ?? 'N/A') ?></span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Asset Criticality</span>
                                <span class="info-value"><?= dave_htmlspecialchars($priority['asset_criticality'] ?? 'N/A') ?></span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Department</span>
                                <span class="info-value"><?= dave_htmlspecialchars($priority['department'] ?? 'N/A') ?></span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Location</span>
                                <span class="info-value"><?= dave_htmlspecialchars($priority['location_name'] ?? 'N/A') ?></span>
                            </div>
                            <?php if ($priority['location_criticality']): ?>
                            <div class="info-item">
                                <span class="info-label">Location Criticality</span>
                                <span class="info-value"><?= $priority['location_criticality'] ?>/10</span>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                    
                    <div class="form-section">
                        <h3>Risk Score Breakdown</h3>
                        <div class="risk-breakdown">
                            <h4>How this priority tier was calculated:</h4>
                            <div class="risk-component">
                                <span class="risk-component-label">Base Priority</span>
                                <span class="risk-component-value">Tier <?= $priority['priority_tier'] ?></span>
                            </div>
                            <?php if ($priority['is_kev']): ?>
                            <div class="risk-component">
                                <span class="risk-component-label">KEV Status</span>
                                <span class="risk-component-value">+1000 points</span>
                            </div>
                            <?php endif; ?>
                            <div class="risk-component">
                                <span class="risk-component-label">Asset Criticality (<?= $priority['asset_criticality'] ?>)</span>
                                <span class="risk-component-value">
                                    <?php
                                    $assetScore = 0;
                                    if ($priority['asset_criticality'] === 'Clinical-High') $assetScore = 100;
                                    elseif ($priority['asset_criticality'] === 'Business-Medium') $assetScore = 50;
                                    elseif ($priority['asset_criticality'] === 'Non-Essential') $assetScore = 10;
                                    echo "+$assetScore points";
                                    ?>
                                </span>
                            </div>
                            <?php if ($priority['location_criticality']): ?>
                            <div class="risk-component">
                                <span class="risk-component-label">Location Criticality (<?= $priority['location_criticality'] ?>/10)</span>
                                <span class="risk-component-value">+<?= $priority['location_criticality'] * 5 ?> points</span>
                            </div>
                            <?php endif; ?>
                            <div class="risk-component">
                                <span class="risk-component-label">Vulnerability Severity (<?= $priority['severity'] ?>)</span>
                                <span class="risk-component-value">
                                    <?php
                                    $sevScore = 0;
                                    if ($priority['severity'] === 'Critical') $sevScore = 40;
                                    elseif ($priority['severity'] === 'High') $sevScore = 28;
                                    elseif ($priority['severity'] === 'Medium') $sevScore = 16;
                                    elseif ($priority['severity'] === 'Low') $sevScore = 4;
                                    echo "+$sevScore points";
                                    ?>
                                </span>
                            </div>
                            <?php if ($priority['epss_score'] && $priority['epss_score'] >= 0.7): ?>
                            <div class="risk-component" style="background: rgba(255, 107, 53, 0.1); border-left: 3px solid #ff6b35; padding-left: 0.75rem;">
                                <span class="risk-component-label" style="color: #ff6b35; font-weight: 600;">EPSS Score (<?= number_format($priority['epss_score'] * 100, 1) ?>% ≥ 70%)</span>
                                <span class="risk-component-value" style="color: #ff6b35; font-weight: 600;">+20 points</span>
                            </div>
                            <?php endif; ?>
                            <div class="risk-component" style="border-top: 2px solid #009999; margin-top: 0.75rem; padding-top: 0.75rem;">
                                <span class="risk-component-label"><strong>Total Risk Score</strong></span>
                                <span class="risk-component-value" style="font-size: 1.25rem; color: #009999;">
                                    <?= $priority['calculated_risk_score'] ?> points
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Vendor Tracking Tab -->
                <div id="tab-vendor" class="tab-content">
                    <form id="vendor-form" onsubmit="saveVendor(event)">
                        <div class="form-section">
                            <h3>Vendor Information</h3>
                            <div class="form-grid">
                                <div class="form-group">
                                    <label>Vendor Name</label>
                                    <input type="text" name="vendor_name" value="<?= dave_htmlspecialchars($details['vendor_name'] ?? '') ?>">
                                </div>
                                <div class="form-group">
                                    <label>Vendor Contact</label>
                                    <input type="text" name="vendor_contact" value="<?= dave_htmlspecialchars($details['vendor_contact'] ?? '') ?>">
                                </div>
                                <div class="form-group">
                                    <label>Vendor Ticket ID</label>
                                    <input type="text" name="vendor_ticket_id" value="<?= dave_htmlspecialchars($details['vendor_ticket_id'] ?? '') ?>">
                                </div>
                                <div class="form-group">
                                    <label>Vendor Status</label>
                                    <select name="vendor_status">
                                        <option value="">Select Status</option>
                                        <option value="Not Contacted" <?= ($priority['vendor_status'] ?? '') === 'Not Contacted' ? 'selected' : '' ?>>Not Contacted</option>
                                        <option value="Contacted" <?= ($priority['vendor_status'] ?? '') === 'Contacted' ? 'selected' : '' ?>>Contacted</option>
                                        <option value="Patch Available" <?= ($priority['vendor_status'] ?? '') === 'Patch Available' ? 'selected' : '' ?>>Patch Available</option>
                                        <option value="Patch Pending" <?= ($priority['vendor_status'] ?? '') === 'Patch Pending' ? 'selected' : '' ?>>Patch Pending</option>
                                        <option value="No Patch Available" <?= ($priority['vendor_status'] ?? '') === 'No Patch Available' ? 'selected' : '' ?>>No Patch Available</option>
                                        <option value="End of Life" <?= ($priority['vendor_status'] ?? '') === 'End of Life' ? 'selected' : '' ?>>End of Life</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Patch Expected Date</label>
                                    <input type="date" name="patch_expected_date" value="<?= dave_htmlspecialchars($priority['patch_expected_date'] ?? '') ?>">
                                </div>
                                <div class="form-group">
                                    <label>Patch Applied Date</label>
                                    <input type="date" name="patch_applied_date" value="<?= dave_htmlspecialchars($details['patch_applied_date'] ?? '') ?>">
                                </div>
                            </div>
                        </div>
                        <div class="form-actions">
                            <button type="submit" class="btn btn-primary">Save Vendor Information</button>
                        </div>
                    </form>
                </div>
                
                <!-- Compensating Controls Tab -->
                <div id="tab-controls" class="tab-content">
                    <div class="form-section">
                        <h3>Add Compensating Control</h3>
                        <form id="control-form" onsubmit="addControl(event)">
                            <div class="form-grid">
                                <div class="form-group">
                                    <label>Control Type</label>
                                    <select name="control_type" required>
                                        <option value="">Select Type</option>
                                        <option value="Network Isolation">Network Isolation</option>
                                        <option value="Access Control">Access Control</option>
                                        <option value="Monitoring">Monitoring</option>
                                        <option value="Physical Security">Physical Security</option>
                                        <option value="Procedural Control">Procedural Control</option>
                                        <option value="Other">Other</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Implemented?</label>
                                    <select name="is_implemented">
                                        <option value="false">Not Implemented</option>
                                        <option value="true">Implemented</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Implemented Date</label>
                                    <input type="date" name="implemented_date">
                                </div>
                                <div class="form-group">
                                    <label>Verified By</label>
                                    <select name="verified_by">
                                        <option value="">Not Verified</option>
                                        <?php foreach ($users as $u): ?>
                                        <option value="<?= $u['user_id'] ?>"><?= dave_htmlspecialchars($u['username']) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                            </div>
                            <div class="form-group" style="margin-top: 1rem;">
                                <label>Control Description</label>
                                <textarea name="control_description" required placeholder="Describe the compensating control in detail..."></textarea>
                            </div>
                            <div class="form-group" style="margin-top: 1rem;">
                                <label>Notes</label>
                                <textarea name="notes" placeholder="Additional notes..."></textarea>
                            </div>
                            <div class="form-actions" style="margin-top: 1rem;">
                                <button type="submit" class="btn btn-primary">Add Control</button>
                            </div>
                        </form>
                    </div>
                    
                    <div class="form-section">
                        <h3>Existing Compensating Controls</h3>
                        <div class="controls-list" id="controls-list">
                            <?php if (empty($controls)): ?>
                            <p style="color: #6b7280;">No compensating controls have been added yet.</p>
                            <?php else: ?>
                            <?php foreach ($controls as $control): ?>
                            <div class="control-item">
                                <div class="control-header">
                                    <span class="control-type"><?= dave_htmlspecialchars($control['control_type']) ?></span>
                                    <div class="control-status">
                                        <?php if ($control['is_implemented']): ?>
                                        <span class="badge badge-success">Implemented</span>
                                        <?php else: ?>
                                        <span class="badge badge-warning">Not Implemented</span>
                                        <?php endif; ?>
                                        <button class="btn-icon" onclick="deleteControl('<?= $control['control_id'] ?>')" title="Delete">
                                            <svg width="16" height="16" fill="currentColor" viewBox="0 0 20 20">
                                                <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
                                            </svg>
                                        </button>
                                    </div>
                                </div>
                                <div class="control-description">
                                    <?= dave_htmlspecialchars($control['control_description']) ?>
                                </div>
                                <?php if ($control['notes']): ?>
                                <div class="control-description" style="font-style: italic;">
                                    <strong>Notes:</strong> <?= dave_htmlspecialchars($control['notes']) ?>
                                </div>
                                <?php endif; ?>
                                <div class="control-meta">
                                    <?php if ($control['implemented_date']): ?>
                                    <span>Implemented: <?= $control['implemented_date'] ?></span>
                                    <?php endif; ?>
                                    <?php if ($control['verified_by_name']): ?>
                                    <span>Verified by: <?= dave_htmlspecialchars($control['verified_by_name']) ?></span>
                                    <?php endif; ?>
                                    <span>Added: <?= date('Y-m-d', strtotime($control['created_at'])) ?></span>
                                </div>
                            </div>
                            <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
                
                <!-- Assignment & Timeline Tab -->
                <div id="tab-assignment" class="tab-content">
                    <form id="assignment-form" onsubmit="saveAssignment(event)">
                        <div class="form-section">
                            <h3>Assignment & Status</h3>
                            <div class="form-grid">
                                <div class="form-group">
                                    <label>Assigned To</label>
                                    <select name="assigned_to">
                                        <option value="">Unassigned</option>
                                        <?php foreach ($users as $u): ?>
                                        <option value="<?= $u['user_id'] ?>" <?= ($priority['assigned_to'] ?? '') === $u['user_id'] ? 'selected' : '' ?>>
                                            <?= dave_htmlspecialchars($u['username']) ?>
                                        </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Remediation Status</label>
                                    <select name="remediation_status">
                                        <option value="Open" <?= ($priority['remediation_status'] ?? '') === 'Open' ? 'selected' : '' ?>>Open</option>
                                        <option value="In Progress" <?= ($priority['remediation_status'] ?? '') === 'In Progress' ? 'selected' : '' ?>>In Progress</option>
                                        <option value="Resolved" <?= ($priority['remediation_status'] ?? '') === 'Resolved' ? 'selected' : '' ?>>Resolved</option>
                                        <option value="Mitigated" <?= ($priority['remediation_status'] ?? '') === 'Mitigated' ? 'selected' : '' ?>>Mitigated</option>
                                        <option value="False Positive" <?= ($priority['remediation_status'] ?? '') === 'False Positive' ? 'selected' : '' ?>>False Positive</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Due Date</label>
                                    <input type="date" name="due_date" value="<?= dave_htmlspecialchars($priority['due_date'] ?? '') ?>">
                                </div>
                            </div>
                        </div>
                        
                        <div class="form-section">
                            <h3>Remediation Notes</h3>
                            <div class="form-group">
                                <textarea name="remediation_notes" rows="6" placeholder="Document remediation steps, progress updates, and other notes..."><?= dave_htmlspecialchars($details['remediation_notes'] ?? '') ?></textarea>
                            </div>
                        </div>
                        
                        <div class="form-actions">
                            <button type="submit" class="btn btn-primary">Save Assignment & Status</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </main>
    
    <script>
        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            // Show selected tab
            event.target.classList.add('active');
            document.getElementById('tab-' + tabName).classList.add('active');
        }
        
        async function saveVendor(event) {
            event.preventDefault();
            
            const formData = new FormData(event.target);
            formData.append('action', 'update_vendor');
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    alert('Vendor information updated successfully');
                    location.reload();
                } else {
                    alert('Error: ' + result.error);
                }
            } catch (error) {
                alert('Error saving vendor information: ' + error.message);
            }
        }
        
        async function addControl(event) {
            event.preventDefault();
            
            const formData = new FormData(event.target);
            formData.append('action', 'add_control');
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    alert('Compensating control added successfully');
                    location.reload();
                } else {
                    alert('Error: ' + result.error);
                }
            } catch (error) {
                alert('Error adding control: ' + error.message);
            }
        }
        
        async function deleteControl(controlId) {
            if (!confirm('Are you sure you want to delete this control?')) {
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'delete_control');
            formData.append('control_id', controlId);
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    alert('Control deleted successfully');
                    location.reload();
                } else {
                    alert('Error: ' + result.error);
                }
            } catch (error) {
                alert('Error deleting control: ' + error.message);
            }
        }
        
        async function saveAssignment(event) {
            event.preventDefault();
            
            const formData = new FormData(event.target);
            formData.append('action', 'update_remediation');
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    alert('Assignment and status updated successfully');
                    location.reload();
                } else {
                    alert('Error: ' + result.error);
                }
            } catch (error) {
                alert('Error saving assignment: ' + error.message);
            }
        }
    </script>
</body>
</html>

