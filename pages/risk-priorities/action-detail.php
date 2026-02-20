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

// Check authentication
$auth = new Auth();
if (!$auth->isLoggedIn()) {
    header('Location: /login.php');
    exit;
}

$user = $auth->getCurrentUser();

// Get action ID from URL
$actionId = $_GET['id'] ?? null;
if (!$actionId) {
    header('Location: /pages/risk-priorities/dashboard.php');
    exit;
}

// Get action details
require_once __DIR__ . '/../../config/database.php';
$db = DatabaseConfig::getInstance();

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    if ($_GET['ajax'] === 'get_users') {
        try {
            $sql = "SELECT user_id, username, email FROM users WHERE is_active = true ORDER BY username";
            $stmt = $db->getConnection()->prepare($sql);
            $stmt->execute();
            $users = $stmt->fetchAll();
            
            // Debug logging
            error_log("AJAX get_users: Found " . count($users) . " users");
            
            echo json_encode([
                'success' => true,
                'data' => $users,
                'count' => count($users)
            ]);
        } catch (Exception $e) {
            error_log("AJAX get_users error: " . $e->getMessage());
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
        exit;
    }
    
    // Handle get_action_details AJAX request
    if ($_GET['ajax'] === 'get_action_details') {
        $actionId = $_GET['id'] ?? null;
        
        if (!$actionId) {
            echo json_encode(['success' => false, 'error' => 'Action ID required']);
            exit;
        }
        
        try {
            // Try action_priority_view first, fallback to remediation_actions if not found
            $sql = "SELECT * FROM action_priority_view WHERE action_id = ?";
            $stmt = $db->getConnection()->prepare($sql);
            $stmt->execute([$actionId]);
            $action = $stmt->fetch();
            
            // If not in view, get from remediation_actions directly
            if (!$action) {
                $sql = "SELECT 
                            ra.*, 
                            ars.urgency_score, 
                            ars.efficiency_score,
                            CASE 
                                WHEN ars.urgency_score >= 1000 THEN 1
                                WHEN ars.urgency_score >= 180 THEN 2
                                WHEN ars.urgency_score >= 160 THEN 3
                                ELSE 4
                            END as priority_tier,
                            u.username as assigned_to_name,
                            u.email as assigned_to_email
                        FROM remediation_actions ra
                        LEFT JOIN action_risk_scores ars ON ra.action_id = ars.action_id
                        LEFT JOIN users u ON ra.assigned_to = u.user_id
                        WHERE ra.action_id = ?";
                $stmt = $db->getConnection()->prepare($sql);
                $stmt->execute([$actionId]);
                $action = $stmt->fetch();
            }
            
            if (!$action) {
                echo json_encode(['success' => false, 'error' => 'Action not found']);
                exit;
            }
            
            // Get affected device count
            $countSql = "SELECT COUNT(DISTINCT adl.device_id) as affected_device_count
                         FROM action_device_links adl
                         WHERE adl.action_id = ? 
                           AND (adl.patch_status IS NULL OR adl.patch_status != 'Completed')";
            $countStmt = $db->getConnection()->prepare($countSql);
            $countStmt->execute([$actionId]);
            $countResult = $countStmt->fetch();
            $action['affected_device_count'] = $countResult['affected_device_count'] ?? 0;
            
            echo json_encode(['success' => true, 'data' => $action]);
            exit;
        } catch (Exception $e) {
            error_log("AJAX get_action_details error: " . $e->getMessage());
            echo json_encode(['success' => false, 'error' => 'Database error: ' . $e->getMessage()]);
            exit;
        }
    }
}

try {
    // Get action details
    $sql = "SELECT * FROM action_priority_view WHERE action_id = ?";
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute([$actionId]);
    $action = $stmt->fetch();
    
    if (!$action) {
        header('Location: /pages/risk-priorities/dashboard.php');
        exit;
    }
    
    // Recalculate affected device count (exclude completed)
    $countSql = "SELECT COUNT(DISTINCT adl.device_id) as affected_device_count
                 FROM action_device_links adl
                 WHERE adl.action_id = ? 
                   AND (adl.patch_status IS NULL OR adl.patch_status != 'Completed')";
    $countStmt = $db->getConnection()->prepare($countSql);
    $countStmt->execute([$actionId]);
    $countResult = $countStmt->fetch();
    $action['affected_device_count'] = $countResult['affected_device_count'] ?? 0;
    
    // Get affected devices (show all, but we'll filter completed from counts)
    $sql = "SELECT 
                adl.*,
                adl.device_id,
                COALESCE(adl.patch_status, 'Pending') as patch_status,
                CASE 
                    WHEN a.hostname IS NOT NULL AND a.hostname != '' THEN a.hostname
                    WHEN a.asset_tag IS NOT NULL AND a.asset_tag != '' THEN a.asset_tag
                    WHEN md.brand_name IS NOT NULL THEN md.brand_name || ' ' || COALESCE(md.model_number, '') || ' (' || COALESCE(md.manufacturer_name, '') || ')'
                    WHEN a.asset_type IS NOT NULL THEN a.asset_type || ' ' || COALESCE(a.manufacturer, '') || ' ' || COALESCE(a.model, '')
                    ELSE 'Siemens Medical Device'
                END as device_name,
                a.asset_type as device_type,
                COALESCE(l.location_name, 'Main Hospital Building') as location_name,
                a.location,
                a.department,
                CASE 
                    WHEN adl.device_risk_score >= 1000 THEN 'Clinical-High'
                    WHEN adl.device_risk_score >= 500 THEN 'Business-Medium'
                    ELSE 'Business-Low'
                END as device_criticality,
                COALESCE(l.criticality::text, 'High') as location_criticality,
                'High' as severity,
                false as is_kev
            FROM action_device_links adl
            LEFT JOIN medical_devices md ON adl.device_id = md.device_id
            LEFT JOIN assets a ON md.asset_id = a.asset_id
            LEFT JOIN locations l ON a.location_id = l.location_id
            WHERE adl.action_id = ?
            ORDER BY 
                CASE WHEN adl.patch_status = 'Completed' THEN 1 ELSE 0 END,
                adl.device_risk_score DESC";
    
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute([$actionId]);
    $devices = $stmt->fetchAll();
    
} catch (Exception $e) {
    error_log("Error loading action details: " . $e->getMessage());
    header('Location: /pages/risk-priorities/dashboard.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Action Details - </title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/priority-badges.css">
    <link rel="stylesheet" href="/assets/css/remediation-actions.css">
    <link rel="stylesheet" href="/assets/css/schedule.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .back-navigation {
            margin-bottom: 1.5rem;
        }
        
        .breadcrumb {
            display: flex;
            align-items: center;
            font-size: 0.875rem;
            margin-bottom: 1rem;
        }
        
        .breadcrumb a {
            color: var(--text-muted, #94a3b8);
            text-decoration: none;
            transition: color 0.2s ease;
        }
        
        .breadcrumb a:hover {
            color: var(--siemens-petrol, #009999);
        }
        
        .back-button {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--siemens-petrol, #009999);
            text-decoration: none;
            font-weight: 500;
            transition: all 0.2s ease;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            border: 1px solid var(--siemens-petrol, #009999);
            background: transparent;
        }
        
        .back-button:hover {
            background: var(--siemens-petrol, #009999);
            color: white;
            transform: translateX(-2px);
        }
        
        .action-detail-header {
            background: linear-gradient(135deg, var(--bg-card, #1a1a1a) 0%, #0f1a1a 100%);
            border: 2px solid var(--siemens-petrol, #009999);
            border-radius: 0.75rem;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.2);
        }
        
        .action-detail-header h1 {
            color: var(--text-primary, #f8fafc);
            margin: 0 0 1rem 0;
            font-size: 1.875rem;
            font-weight: 700;
        }
        
        .action-detail-header .action-subtitle {
            color: var(--text-secondary, #cbd5e1);
            font-size: 1.125rem;
            margin-bottom: 1.5rem;
        }
        
        .action-header-actions {
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-shrink: 0;
            white-space: nowrap;
        }
        
        .tier-badge {
            white-space: nowrap;
            flex-shrink: 0;
        }
        
        .score-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }
        
        .score-card {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            text-align: center;
            transition: all 0.2s ease;
        }
        
        .score-card:hover {
            border-color: var(--siemens-petrol, #009999);
            transform: translateY(-2px);
        }
        
        .score-card.urgency {
            border-left: 4px solid #ef4444;
        }
        
        .score-card.efficiency {
            border-left: 4px solid #60a5fa;
        }
        
        .score-card.devices {
            border-left: 4px solid var(--siemens-petrol, #009999);
        }
        
        .score-card.kev {
            border-left: 4px solid #9333ea;
        }
        
        .devices-section {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .devices-section h3 {
            color: var(--text-primary, #f8fafc);
            margin: 0 0 1.5rem 0;
            font-size: 1.25rem;
            font-weight: 600;
        }
        
        .remediation-details {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .remediation-details h3 {
            color: var(--text-primary, #f8fafc);
            margin: 0 0 1.5rem 0;
            font-size: 1.25rem;
            font-weight: 600;
        }
        
        .assignment-section {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .assignment-section h3 {
            color: var(--text-primary, #f8fafc);
            margin: 0 0 1.5rem 0;
            font-size: 1.25rem;
            font-weight: 600;
        }
        
        .assignment-form {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            align-items: end;
        }
        
        .assignment-form .form-group {
            display: flex;
            flex-direction: column;
        }
        
        .assignment-form label {
            color: var(--text-secondary, #cbd5e1);
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
        }
        
        .assignment-form select,
        .assignment-form input,
        .assignment-form textarea {
            padding: 0.75rem;
            border: 1px solid var(--border-secondary, #555555);
            border-radius: 0.5rem;
            background: var(--bg-secondary, #333333);
            color: var(--text-primary, #f8fafc);
            font-size: 0.875rem;
            transition: border-color 0.2s ease;
        }
        
        .assignment-form select:focus,
        .assignment-form input:focus,
        .assignment-form textarea:focus {
            outline: none;
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
        }
        
        .assignment-form textarea {
            grid-column: 1 / -1;
            min-height: 100px;
            resize: vertical;
        }
        
        .assignment-actions {
            display: flex;
            gap: 1rem;
            margin-top: 1rem;
        }
        
        @media (max-width: 768px) {
            .assignment-form {
                grid-template-columns: 1fr;
            }
            
            .score-cards {
                grid-template-columns: 1fr;
            }
            
            .assignment-actions {
                flex-direction: column;
            }
            
            .action-detail-header > div:first-child {
                flex-direction: column;
                align-items: flex-start;
                gap: 1rem;
            }
            
            .action-header-actions {
                align-self: flex-end;
            }
        }
        
        /* CVE Modal Styles */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }
        
        .modal-content {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            max-width: 640px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-primary, #333333);
        }
        
        .modal-header h2 {
            margin: 0;
            color: var(--text-primary, #f8fafc);
            font-size: 1.25rem;
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-secondary, #cbd5e1);
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0;
            width: 2rem;
            height: 2rem;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .modal-close:hover {
            color: var(--text-primary, #f8fafc);
        }
        
        .modal-body {
            padding: 1.5rem;
        }
        
        .cve-info .info-row {
            margin-bottom: 1rem;
        }
        
        .cve-info .info-row:last-child {
            margin-bottom: 0;
        }
        
        .cve-info strong {
            display: block;
            color: var(--text-primary, #f8fafc);
            margin-bottom: 0.5rem;
        }
        
        .cve-info p {
            margin: 0;
            color: var(--text-secondary, #cbd5e1);
            line-height: 1.5;
        }
        
        .cvss-score {
            color: var(--siemens-petrol, #009999);
            font-weight: 600;
        }
        
        .severity-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-badge.critical {
            background: #dc2626;
            color: white;
        }
        
        .severity-badge.high {
            background: #ea580c;
            color: white;
        }
        
        .severity-badge.medium {
            background: #d97706;
            color: white;
        }
        
        .severity-badge.low {
            background: #16a34a;
            color: white;
        }
        
        .kev-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .kev-badge.kev {
            background: #dc2626;
            color: white;
        }
        
        .kev-badge.not-kev {
            background: var(--bg-secondary, #0f0f0f);
            color: var(--text-muted, #94a3b8);
            border: 1px solid var(--border-primary, #333333);
        }
        
        .modal-footer {
            padding: 1.5rem;
            border-top: 1px solid var(--border-primary, #333333);
            display: flex;
            justify-content: flex-end;
        }
    </style>
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>
    
    <main class="main-content">
        <div class="container">
            <!-- Back Navigation -->
            <div class="back-navigation">
                <nav class="breadcrumb" style="margin-bottom: 1rem;">
                    <a href="/pages/dashboard.php" style="color: var(--text-muted, #94a3b8); text-decoration: none;">Dashboard</a>
                    <span style="color: var(--text-muted, #94a3b8); margin: 0 0.5rem;">/</span>
                    <a href="/pages/risk-priorities/dashboard.php" style="color: var(--text-muted, #94a3b8); text-decoration: none;">Risk Priorities</a>
                    <span style="color: var(--text-muted, #94a3b8); margin: 0 0.5rem;">/</span>
                    <span style="color: var(--text-primary, #f8fafc);">Action Details</span>
                </nav>
                <a href="/pages/risk-priorities/dashboard.php" class="back-button">
                    <i class="fas fa-arrow-left"></i>
                    Back to Risk Priorities Dashboard
                </a>
            </div>
            
            <!-- Action Detail Header -->
            <div class="action-detail-header">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;">
                    <div>
                        <h1><?= dave_htmlspecialchars($action['action_description']) ?></h1>
                        <div class="action-subtitle"><?= dave_htmlspecialchars($action['cve_id']) ?></div>
                    </div>
                    <div class="action-header-actions">
                        <span class="tier-badge tier-<?= $action['priority_tier'] ?>">TIER <?= $action['priority_tier'] ?></span>
                        <button class="btn-action primary" onclick="assignAction()">
                            <i class="fas fa-user-plus"></i> Assign
                        </button>
                    </div>
                </div>
                
                <!-- Score Cards -->
                <div class="score-cards">
                    <div class="score-card urgency">
                        <div class="score-label">Urgency Score</div>
                        <div class="score-value urgency"><?= number_format($action['urgency_score']) ?></div>
                        <div class="score-description">Highest Risk Device</div>
                    </div>
                    
                    <div class="score-card efficiency">
                        <div class="score-label">Efficiency Score</div>
                        <div class="score-value efficiency"><?= number_format($action['efficiency_score']) ?></div>
                        <div class="score-description">Total Risk Reduction</div>
                    </div>
                    
                    <div class="score-card devices">
                        <div class="score-label">Affected Devices</div>
                        <div class="score-value"><?= $action['affected_device_count'] ?></div>
                        <div class="score-description">Total Devices</div>
                    </div>
                    
                    <div class="score-card kev">
                        <div class="score-label">KEV Status</div>
                        <div class="score-value"><?= $action['is_kev'] ? 'Yes' : 'No' ?></div>
                        <div class="score-description">Known Exploited</div>
                    </div>
                </div>
            </div>
            
            <!-- Affected Devices -->
            <div class="devices-section">
                <h3>Affected Devices (<?= $action['affected_device_count'] ?>)</h3>
                
                <div class="table-container">
                    <table class="devices-table">
                        <thead>
                            <tr>
                                <th>Device</th>
                                <th>Location</th>
                                <th>Criticality</th>
                                <th>Device Risk Score</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($devices as $device): ?>
                            <tr>
                                <td class="device-name"><?= dave_htmlspecialchars($device['device_name'] ?? 'Unidentified Device') ?></td>
                                <td class="device-location"><?= dave_htmlspecialchars($device['location_name'] ?? 'Location Not Mapped') ?></td>
                                <td>
                                    <span class="criticality-badge <?= strtolower(str_replace('-', '-', $device['device_criticality'] ?? 'medium')) ?>">
                                        <?= dave_htmlspecialchars($device['device_criticality'] ?? 'Not Classified') ?>
                                    </span>
                                </td>
                                <td class="device-risk-score <?= $device['device_risk_score'] >= 1000 ? 'drives-urgency' : '' ?>">
                                    <?= number_format($device['device_risk_score']) ?>
                                    <?php if ($device['device_risk_score'] >= 1000): ?>
                                    <span style="color: #ef4444; margin-left: 0.25rem;">⭐</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="status-badge <?= strtolower(str_replace(' ', '-', $device['patch_status'] ?? 'pending')) ?>">
                                        <?= dave_htmlspecialchars($device['patch_status'] ?? 'Pending') ?>
                                    </span>
                                </td>
                                <td>
                                    <button class="btn-action" onclick="markDevicePatched('<?= $device['device_id'] ?>')">
                                        <i class="fas fa-check"></i> Mark Patched
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Remediation Details -->
            <div class="remediation-details">
                <h3>Remediation Details</h3>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                    <div>
                        <strong>Action Type:</strong> <?= dave_htmlspecialchars($action['action_type']) ?>
                    </div>
                    <div>
                        <strong>Vendor:</strong> <?= dave_htmlspecialchars($action['vendor'] ?? 'Unknown') ?>
                    </div>
                    <div>
                        <strong>CVEs Addressed:</strong> <?= dave_htmlspecialchars($action['cve_id']) ?>
                    </div>
                    <div>
                        <strong>Status:</strong> 
                        <span class="status-badge <?= strtolower(str_replace(' ', '-', $action['status'])) ?>">
                            <?= dave_htmlspecialchars($action['status']) ?>
                        </span>
                    </div>
                </div>
                
                <div style="margin-top: 1rem;">
                    <strong>Recommended Solution:</strong><br>
                    <div style="background: rgba(0, 153, 153, 0.1); border: 1px solid var(--siemens-petrol, #009999); border-radius: 0.5rem; padding: 1rem; margin-top: 0.5rem;">
                        Apply security patch for <?= dave_htmlspecialchars($action['cve_id']) ?><br>
                        <small style="color: var(--text-muted, #94a3b8);">
                            Requires Reboot: Yes | Estimated Time: 30 minutes
                        </small>
                    </div>
                </div>
                
                <div style="margin-top: 1rem;">
                    <button class="btn-action secondary" onclick="viewCVEDetails('<?= dave_htmlspecialchars($action['cve_id']) ?>')">
                        <i class="fas fa-external-link-alt"></i> View CVE Details
                    </button>
                </div>
            </div>
            
            <!-- Assignment Section -->
            <div class="assignment-section">
                <h3>Assignment & Tracking</h3>
                
                <form class="assignment-form" id="assignmentForm">
                    <div class="form-group">
                        <label for="assigned_to">Assigned To</label>
                        <select id="assigned_to" name="assigned_to">
                            <option value="">Select User</option>
                            <?php
                            // Get real users from database
                            $userSql = "SELECT user_id, username, email FROM users WHERE is_active = true ORDER BY username";
                            $userStmt = $db->getConnection()->prepare($userSql);
                            $userStmt->execute();
                            $users = $userStmt->fetchAll();
                            
                            foreach ($users as $user) {
                                $selected = $action['assigned_to'] === $user['user_id'] ? 'selected' : '';
                                echo '<option value="' . dave_htmlspecialchars($user['user_id']) . '" ' . $selected . '>' . dave_htmlspecialchars($user['username']) . ' (' . dave_htmlspecialchars($user['email']) . ')</option>';
                            }
                            ?>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="due_date">Due Date</label>
                        <input type="date" id="due_date" name="due_date" value="<?= $action['due_date'] ?? '' ?>">
                    </div>
                    
                    <div class="form-group">
                        <label for="notes">Notes</label>
                        <textarea id="notes" name="notes" placeholder="Add notes about this action..."><?= dave_htmlspecialchars($action['notes'] ?? '') ?></textarea>
                    </div>
                    
                    <div class="assignment-actions">
                        <button type="button" class="btn-action primary" onclick="saveAssignment()">
                            <i class="fas fa-save"></i> Save Assignment
                        </button>
                        <button type="button" class="btn-action secondary" onclick="scheduleMaintenance()">
                            <i class="fas fa-calendar"></i> Schedule Maintenance
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </main>
    
    <script src="/assets/js/components/assign-owner-modal.js"></script>
    <script>
        const actionId = '<?= $actionId ?>';
        
        // Debug logging
        console.log('Action detail page loaded');
        
        // Mark device as patched
        async function markDevicePatched(deviceId) {
            if (!confirm('Mark this device as patched?')) {
                return;
            }
            
            try {
                const response = await fetch(`/api/v1/remediation-actions/${actionId}/devices/${deviceId}`, {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        patch_status: 'Completed'
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    alert('Device marked as patched successfully');
                    location.reload();
                } else {
                    alert('Failed to mark device as patched: ' + result.error);
                }
            } catch (error) {
                alert('Error marking device as patched: ' + error.message);
            }
        }
        
        // Save assignment
        async function saveAssignment() {
            const form = document.getElementById('assignmentForm');
            const formData = new FormData(form);
            
            const data = {
                assigned_to: formData.get('assigned_to'),
                due_date: formData.get('due_date'),
                notes: formData.get('notes')
            };
            
            try {
                const response = await fetch(`/api/v1/remediation-actions/${actionId}/assign`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    alert('Assignment saved successfully');
                } else {
                    alert('Failed to save assignment: ' + result.error);
                }
            } catch (error) {
                alert('Error saving assignment: ' + error.message);
            }
        }
        
        // Schedule maintenance
        function scheduleMaintenance() {
            // Check if assignOwnerModal is available
            if (typeof window.assignOwnerModal === 'undefined') {
                console.error('assignOwnerModal is not defined');
                alert('Task assignment modal is not loaded. Please refresh the page and try again.');
                return;
            }
            
            // Get affected devices for this action
            const devices = <?php echo json_encode($devices); ?>;
            
            if (devices && devices.length > 0) {
                const cveId = '<?php echo addslashes($action['cve_id'] ?? ''); ?>';
                const actionId = '<?php echo addslashes($actionId); ?>';
                
                try {
                    // Show assign owner modal with affected devices
                    window.assignOwnerModal.showForCVE(cveId, actionId, devices);
                } catch (error) {
                    console.error('Error calling showForCVE:', error);
                    alert('Error opening modal: ' + error.message);
                }
            } else {
                alert('No affected devices found for this action.');
            }
        }
        
        // Assign action
        function assignAction() {
            document.getElementById('assigned_to').focus();
        }
        
        // View CVE details
        function viewCVEDetails(cveId) {
            // Show CVE details modal
            showCVEModal(cveId);
        }
        
        // Show CVE details modal
        function showCVEModal(cveId) {
            // Create modal content with basic CVE information
            const modalContent = `
                <div class="modal-overlay" onclick="closeCVEModal()">
                    <div class="modal-content" onclick="event.stopPropagation()">
                        <div class="modal-header">
                            <h2>CVE Details: ${cveId}</h2>
                            <button class="modal-close" onclick="closeCVEModal()">&times;</button>
                        </div>
                        <div class="modal-body">
                            <div class="cve-info">
                                <div class="info-row">
                                    <strong>CVE ID:</strong>
                                    <p>${cveId}</p>
                                </div>
                                <div class="info-row">
                                    <strong>Action Type:</strong>
                                    <p>Security Patch</p>
                                </div>
                                <div class="info-row">
                                    <strong>Description:</strong>
                                    <p>This vulnerability requires a security patch to address potential security risks. Please apply the recommended patch as soon as possible.</p>
                                </div>
                                <div class="info-row">
                                    <strong>Risk Level:</strong>
                                    <span class="severity-badge high">High Priority</span>
                                </div>
                                <div class="info-row">
                                    <strong>Remediation:</strong>
                                    <p>Apply the security patch provided by the vendor. Ensure all affected systems are updated and tested.</p>
                                </div>
                                <div class="info-row">
                                    <strong>Next Steps:</strong>
                                    <p>1. Download and test the patch in a non-production environment<br>
                                    2. Schedule maintenance window for production deployment<br>
                                    3. Deploy patch to all affected systems<br>
                                    4. Verify patch installation and system functionality</p>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button class="btn-action secondary" onclick="closeCVEModal()">Close</button>
                        </div>
                    </div>
                </div>
            `;
            
            // Add modal to page
            document.body.insertAdjacentHTML('beforeend', modalContent);
        }
        
        // Close CVE modal
        function closeCVEModal() {
            const modal = document.querySelector('.modal-overlay');
            if (modal) {
                modal.remove();
            }
        }
    </script>
</body>
</html>
