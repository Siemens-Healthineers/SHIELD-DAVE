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

// Check if user has admin privileges for patch management
$isAdmin = (strtolower($user['role']) === 'admin' || strtolower($user['role']) === 'security_admin');

// Get action and parameters
$action = $_GET['action'] ?? 'list';
$packageId = $_GET['package_id'] ?? '';
$patchId = $_GET['patch_id'] ?? '';

// Get affected devices for patch scheduling
$affectedDevices = [];
$patch = null; // Initialize patch variable
if ($action === 'schedule' && $patchId) {
    try {
        // Get patch details
        $sql = "SELECT * FROM patches WHERE patch_id = ?";
        $stmt = $db->getConnection()->prepare($sql);
        $stmt->execute([$patchId]);
        $patch = $stmt->fetch();
        
        if ($patch && $patch['cve_list']) {
            $cveList = json_decode($patch['cve_list'], true);
            
            if ($cveList && count($cveList) > 0) {
                // Get devices affected by the CVEs in this patch
                $placeholders = str_repeat('?,', count($cveList) - 1) . '?';
                $sql = "SELECT 
                            dvl.*,
                            dvl.device_id,
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
                                WHEN dvl.risk_score >= 1000 THEN 'Clinical-High'
                                WHEN dvl.risk_score >= 500 THEN 'Business-Medium'
                                ELSE 'Business-Low'
                            END as device_criticality,
                            COALESCE(l.criticality::text, 'High') as location_criticality,
                            p.patch_name,
                            p.target_version as patch_version,
                            dvl.cve_id
                        FROM device_vulnerabilities_link dvl
                        LEFT JOIN medical_devices md ON dvl.device_id = md.device_id
                        LEFT JOIN assets a ON md.asset_id = a.asset_id
                        LEFT JOIN locations l ON a.location_id = l.location_id
                        LEFT JOIN patches p ON p.patch_id = ?
                        WHERE dvl.cve_id IN ($placeholders)
                        ORDER BY dvl.risk_score DESC";
                
                $stmt = $db->getConnection()->prepare($sql);
                $stmt->execute(array_merge([$patchId], $cveList));
                $rawDevices = $stmt->fetchAll();
                
                // Deduplicate devices by device_id, keeping the one with highest risk score
                $deviceMap = [];
                foreach ($rawDevices as $device) {
                    $deviceId = $device['device_id'];
                    if (!isset($deviceMap[$deviceId]) || $device['risk_score'] > $deviceMap[$deviceId]['risk_score']) {
                        $deviceMap[$deviceId] = $device;
                    }
                }
                $affectedDevices = array_values($deviceMap);
            }
        }
    } catch (Exception $e) {
        error_log("Error loading affected devices for patch scheduling: " . $e->getMessage());
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Patch Management - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="/assets/js/components/assign-owner-modal.js"></script>
    <style>
        .patch-card {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            transition: all 0.2s;
        }
        
        .patch-card:hover {
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.2);
        }
        
        .patch-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 1rem;
        }
        
        .patch-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.25rem;
        }
        
        .patch-type {
            font-size: 0.875rem;
            color: var(--text-secondary, #cbd5e1);
        }
        
        .patch-meta {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .meta-item {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        .meta-label {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
        }
        
        .meta-value {
            font-size: 1rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
        }
        
        .form-section {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-label {
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.5rem;
        }
        
        .form-input, .form-textarea, .form-select {
            width: 100%;
            padding: 0.75rem;
            background: var(--bg-secondary, #0f0f0f);
            color: var(--text-primary, #ffffff);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            font-size: 0.875rem;
        }
        
        .form-input:focus, .form-textarea:focus, .form-select:focus {
            outline: none;
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
        }
        
        .form-textarea {
            min-height: 100px;
            resize: vertical;
        }
        
        .form-help {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
            margin-top: 0.25rem;
        }
        
        .asset-selector {
            background: var(--bg-secondary, #0f0f0f);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            padding: 1rem;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .asset-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem;
            border-bottom: 1px solid var(--border-primary, #333333);
        }
        
        .asset-item:last-child {
            border-bottom: none;
        }
        
        .asset-item:hover {
            background: var(--bg-hover, #222222);
        }
        
        .asset-item.selected-item {
            background: rgba(0, 153, 153, 0.1);
            border-left: 3px solid var(--siemens-petrol, #009999);
        }
        
        .asset-checkbox {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }
        
        .asset-info {
            flex: 1;
        }
        
        .asset-name {
            font-weight: 600;
            color: var(--text-primary, #ffffff);
        }
        
        .asset-details {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
        }
        
        .selected-count {
            background: var(--siemens-petrol, #009999);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-weight: 600;
            display: inline-block;
            margin-bottom: 1rem;
        }
        
        .wizard-steps {
            display: flex;
            justify-content: space-between;
            margin-bottom: 2rem;
            position: relative;
        }
        
        .wizard-step {
            flex: 1;
            text-align: center;
            position: relative;
        }
        
        .step-number {
            width: 40px;
            height: 40px;
            background: var(--bg-secondary, #0f0f0f);
            border: 2px solid var(--border-primary, #333333);
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            color: var(--text-secondary, #cbd5e1);
            margin-bottom: 0.5rem;
        }
        
        .wizard-step.active .step-number {
            background: var(--siemens-petrol, #009999);
            border-color: var(--siemens-petrol, #009999);
            color: white;
        }
        
        .wizard-step.completed .step-number {
            background: #10b981;
            border-color: #10b981;
            color: white;
        }
        
        .step-label {
            font-size: 0.875rem;
            color: var(--text-secondary, #cbd5e1);
        }
        
        .wizard-step.active .step-label {
            color: var(--text-primary, #ffffff);
            font-weight: 600;
        }
        
        .application-result {
            background: var(--bg-secondary, #0f0f0f);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        
        .result-success {
            border-left: 4px solid #10b981;
        }
        
        .result-error {
            border-left: 4px solid #ef4444;
        }
        
        /* Notification System */
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            padding: 1rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
            z-index: 10000;
            max-width: 400px;
            transform: translateX(100%);
            transition: transform 0.3s ease;
        }

        .notification.show {
            transform: translateX(0);
        }

        .notification-content {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .notification-content i {
            font-size: 1.25rem;
        }

        .notification-success {
            border-left: 4px solid var(--success-green, #10b981);
        }

        .notification-success .notification-content i {
            color: var(--success-green, #10b981);
        }

        .notification-error {
            border-left: 4px solid var(--error-red, #ef4444);
        }

        .notification-error .notification-content i {
            color: var(--error-red, #ef4444);
        }

        .notification-info {
            border-left: 4px solid var(--siemens-petrol, #009999);
        }

        .notification-info .notification-content i {
            color: var(--siemens-petrol, #009999);
        }

        .notification-content span {
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

    <main class="main-content">
        <div class="container" style="max-width: 1400px; margin: 0 auto; padding: 2rem;">
            
            <!-- Page Header -->
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
                <div>
                    <h1 style="font-size: 1.875rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">
                        <i class="fas fa-band-aid"></i> Patch Management
                    </h1>
                    <p style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">
                        Create and apply patches to remediate vulnerabilities across assets
                    </p>
                </div>
                <?php if ($isAdmin && $action === 'list'): ?>
                <button class="btn btn-primary" onclick="window.location.href='?action=create'">
                    <i class="fas fa-plus"></i> Create New Patch
                </button>
                <?php endif; ?>
            </div>

            <?php if ($action === 'list'): ?>
                <!-- Patch List View -->
                <div id="patches-container">
                    <?php if (isset($_GET['fallback']) && $_GET['fallback'] == '1'): ?>
                        <?php
                        // Server-side fallback when API is not accessible
                        try {
                            $db = DatabaseConfig::getInstance();
                            $sql = "SELECT 
                                        p.*,
                                        sp.name as package_name,
                                        sp.vendor as package_vendor,
                                        u.username as created_by_name,
                                        (SELECT COUNT(*) FROM patch_applications WHERE patch_id = p.patch_id) as application_count,
                                        CASE 
                                            WHEN p.cve_list IS NULL THEN 0
                                            ELSE jsonb_array_length(p.cve_list)
                                        END as cve_count
                                    FROM patches p
                                    LEFT JOIN software_packages sp ON p.package_id = sp.package_id
                                    LEFT JOIN users u ON p.created_by = u.user_id
                                    WHERE p.is_active = TRUE
                                    ORDER BY p.created_at DESC";
                            
                            $stmt = $db->prepare($sql);
                            $stmt->execute();
                            $patches = $stmt->fetchAll();
                            
                            if (count($patches) > 0) {
                                foreach ($patches as $patch) {
                                    $cveList = json_decode($patch['cve_list'] ?? '[]', true);
                                    $cveCount = count($cveList);
                                    
                                    echo '<div class="patch-card">';
                                    echo '<div class="patch-header">';
                                    echo '<div>';
                                    echo '<div class="patch-title">' . dave_htmlspecialchars($patch['patch_name']) . '</div>';
                                    echo '<div class="patch-type"><i class="fas fa-tag"></i> ' . dave_htmlspecialchars($patch['patch_type']) . '</div>';
                                    echo '</div>';
                                    echo '<div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">';
                                    echo '<button class="btn btn-primary btn-sm" onclick="applyPatch(\'' . $patch['patch_id'] . '\')">';
                                    echo '<i class="fas fa-download"></i> Apply';
                                    echo '</button>';
                                    echo '<button class="btn btn-secondary btn-sm" onclick="editPatch(\'' . $patch['patch_id'] . '\')">';
                                    echo '<i class="fas fa-edit"></i> Edit';
                                    echo '</button>';
                                    echo '<button class="btn btn-info btn-sm" onclick="viewPatchHistory(\'' . $patch['patch_id'] . '\')">';
                                    echo '<i class="fas fa-history"></i> History';
                                    echo '</button>';
                                    echo '<button class="btn btn-warning btn-sm" onclick="schedulePatch(\'' . $patch['patch_id'] . '\')">';
                                    echo '<i class="fas fa-calendar-plus"></i> Schedule';
                                    echo '</button>';
                                    echo '<button class="btn btn-danger btn-sm" onclick="deletePatch(\'' . $patch['patch_id'] . '\')">';
                                    echo '<i class="fas fa-trash"></i> Delete';
                                    echo '</button>';
                                    echo '</div>';
                                    echo '</div>';
                                    echo '<div class="patch-meta">';
                                    echo '<div class="meta-item">';
                                    echo '<div class="meta-label">Target Version</div>';
                                    echo '<div class="meta-value">' . dave_htmlspecialchars($patch['target_version'] ?? 'N/A') . '</div>';
                                    echo '</div>';
                                    echo '<div class="meta-item">';
                                    echo '<div class="meta-label">CVEs</div>';
                                    echo '<div class="meta-value">' . $cveCount . ' associated</div>';
                                    echo '</div>';
                                    echo '<div class="meta-item">';
                                    echo '<div class="meta-label">History</div>';
                                    echo '<div class="meta-value">' . $patch['application_count'] . ' applied</div>';
                                    echo '</div>';
                                    echo '<div class="meta-item">';
                                    echo '<div class="meta-label">Created</div>';
                                    echo '<div class="meta-value">' . date('M j, Y', strtotime($patch['created_at'])) . '</div>';
                                    echo '</div>';
                                    echo '</div>';
                                    echo '<div class="patch-description">';
                                    echo '<p>' . dave_htmlspecialchars($patch['description'] ?? 'No description available') . '</p>';
                                    echo '</div>';
                                    echo '</div>';
                                }
                            } else {
                                echo '<div style="text-align: center; padding: 3rem;">';
                                echo '<i class="fas fa-inbox" style="font-size: 3rem; color: var(--text-muted, #94a3b8); margin-bottom: 1rem;"></i>';
                                echo '<h3 style="color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">No Patches Found</h3>';
                                echo '<p style="color: var(--text-secondary, #cbd5e1);">No patches have been created yet.</p>';
                                echo '<a href="?action=create" class="btn btn-primary" style="margin-top: 1rem;">';
                                echo '<i class="fas fa-plus"></i> Create First Patch';
                                echo '</a>';
                                echo '</div>';
                            }
                        } catch (Exception $e) {
                            echo '<div style="background: #ef4444; color: white; padding: 2rem; border-radius: 0.5rem; text-align: center;">';
                            echo '<i class="fas fa-exclamation-triangle" style="font-size: 2rem; margin-bottom: 1rem;"></i>';
                            echo '<h3 style="margin: 0 0 1rem 0;">Database Error</h3>';
                            echo '<p style="margin: 0;">Unable to load patches from database.</p>';
                            echo '</div>';
                        }
                        ?>
                    <?php else: ?>
                        <div style="text-align: center; padding: 2rem;">
                            <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                            <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading patches...</p>
                        </div>
                    <?php endif; ?>
                </div>

            <?php elseif ($action === 'create'): ?>
                <?php if (!$isAdmin): ?>
                    <!-- Access Denied for Create -->
                    <div class="form-section">
                        <div style="text-align: center; padding: 3rem;">
                            <i class="fas fa-lock" style="font-size: 3rem; color: var(--text-muted, #94a3b8); margin-bottom: 1rem;"></i>
                            <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">Admin Access Required</h3>
                            <p style="color: var(--text-secondary, #cbd5e1);">Only administrators can create patches.</p>
                            <button class="btn btn-secondary" onclick="window.location.href='?action=list'" style="margin-top: 1rem;">
                                <i class="fas fa-arrow-left"></i> Back to Patches
                            </button>
                        </div>
                    </div>
                <?php else: ?>
                <!-- Create Patch Wizard -->
                <div class="wizard-steps">
                    <div class="wizard-step active" data-step="1">
                        <div class="step-number">1</div>
                        <div class="step-label">Patch Info</div>
                    </div>
                    <div class="wizard-step" data-step="2">
                        <div class="step-number">2</div>
                        <div class="step-label">CVE Selection</div>
                    </div>
                    <div class="wizard-step" data-step="3">
                        <div class="step-number">3</div>
                        <div class="step-label">Review</div>
                    </div>
                </div>

                <form id="create-patch-form">
                    <!-- Step 1: Basic Info -->
                    <div class="wizard-content" data-step="1">
                        <div class="form-section">
                            <h2 style="font-size: 1.25rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1.5rem;">
                                Patch Information
                            </h2>
                            
                            <div class="form-group">
                                <label class="form-label">Patch Name <span style="color: #ef4444;">*</span></label>
                                <input type="text" name="patch_name" class="form-input" required placeholder="e.g., 2025Q1 Ultrasound Security Update">
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Patch Type <span style="color: #ef4444;">*</span></label>
                                <select name="patch_type" class="form-select" required>
                                    <option value="">Select Type...</option>
                                    <option value="Software Update">Software Update</option>
                                    <option value="Firmware">Firmware Update</option>
                                    <option value="Configuration">Configuration Change</option>
                                    <option value="Security Patch">Security Patch</option>
                                    <option value="Hotfix">Hotfix</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Description <span style="color: #ef4444;">*</span></label>
                                <textarea name="description" class="form-textarea" required placeholder="Describe what this patch does and any special considerations..."></textarea>
                            </div>
                            
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                <div class="form-group">
                                    <label class="form-label">Target Version</label>
                                    <input type="text" name="target_version" class="form-input" placeholder="e.g., 2024.004.20220">
                                    <div class="form-help">The version this patch updates to</div>
                                </div>
                                
                                <div class="form-group">
                                    <label class="form-label">Release Date</label>
                                    <input type="date" name="release_date" class="form-input" value="<?php echo date('Y-m-d'); ?>">
                                </div>
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Target Device Type (Optional)</label>
                                <input type="text" name="target_device_type" class="form-input" placeholder="e.g., Ultrasound System">
                                <div class="form-help">Leave blank for generic software patches</div>
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Vendor</label>
                                <input type="text" name="vendor" class="form-input" placeholder="e.g., Siemens Healthineers">
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">KB Article</label>
                                <input type="text" name="kb_article" class="form-input" placeholder="e.g., KB123456">
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Download URL</label>
                                <input type="url" name="download_url" class="form-input" placeholder="https://vendor.com/patch-download">
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Install Instructions</label>
                                <textarea name="install_instructions" class="form-textarea" placeholder="Step-by-step installation instructions..."></textarea>
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Prerequisites</label>
                                <textarea name="prerequisites" class="form-textarea" placeholder="System requirements, dependencies, etc..."></textarea>
                            </div>
                            
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                <div class="form-group">
                                    <label class="form-label">Estimated Install Time (minutes)</label>
                                    <input type="number" name="estimated_install_time" class="form-input" placeholder="30" min="1">
                                </div>
                                
                                <div class="form-group">
                                    <label style="display: flex; align-items: center; gap: 0.5rem; color: var(--text-primary, #ffffff);">
                                        <input type="checkbox" name="requires_reboot"> Requires Reboot
                                    </label>
                                </div>
                            </div>
                            
                            <input type="hidden" name="package_id" value="<?php echo dave_htmlspecialchars($packageId); ?>">
                        </div>
                        
                        <div style="display: flex; justify-content: flex-end; gap: 0.75rem;">
                            <button type="button" class="btn btn-secondary" onclick="window.location.href='?action=list'">
                                Cancel
                            </button>
                            <button type="button" class="btn btn-primary" onclick="nextStep()">
                                Next: Select CVEs <i class="fas fa-arrow-right"></i>
                            </button>
                        </div>
                    </div>
                    
                    <!-- Step 2: CVE Selection -->
                    <div class="wizard-content" data-step="2" style="display: none;">
                        <div class="form-section">
                            <h2 style="font-size: 1.25rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1.5rem;">
                                Select CVEs to Resolve
                            </h2>
                            
                            <div id="cve-selector">
                                <div style="text-align: center; padding: 2rem;">
                                    <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                                    <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading CVEs...</p>
                                </div>
                            </div>
                        </div>
                        
                        <div style="display: flex; justify-content: space-between; gap: 0.75rem;">
                            <button type="button" class="btn btn-secondary" onclick="previousStep()">
                                <i class="fas fa-arrow-left"></i> Previous
                            </button>
                            <button type="button" class="btn btn-primary" onclick="nextStep()">
                                Next: Review <i class="fas fa-arrow-right"></i>
                            </button>
                        </div>
                    </div>
                    
                    <!-- Step 3: Review -->
                    <div class="wizard-content" data-step="3" style="display: none;">
                        <div class="form-section">
                            <h2 style="font-size: 1.25rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1.5rem;">
                                Review Patch Details
                            </h2>
                            
                            <div id="patch-review">
                                <!-- Review content will be populated here -->
                            </div>
                        </div>
                        
                        <div style="display: flex; justify-content: space-between; gap: 0.75rem;">
                            <button type="button" class="btn btn-secondary" onclick="previousStep()">
                                <i class="fas fa-arrow-left"></i> Previous
                            </button>
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-check"></i> Create Patch
                            </button>
                        </div>
                    </div>
                </form>
                <?php endif; ?>

            <?php elseif ($action === 'apply'): ?>
                <?php if (!$isAdmin): ?>
                    <!-- Access Denied for Apply -->
                    <div class="form-section">
                        <div style="text-align: center; padding: 3rem;">
                            <i class="fas fa-lock" style="font-size: 3rem; color: var(--text-muted, #94a3b8); margin-bottom: 1rem;"></i>
                            <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">Admin Access Required</h3>
                            <p style="color: var(--text-secondary, #cbd5e1);">Only administrators can apply patches.</p>
                            <button class="btn btn-secondary" onclick="window.location.href='?action=list'" style="margin-top: 1rem;">
                                <i class="fas fa-arrow-left"></i> Back to Patches
                            </button>
                        </div>
                    </div>
                <?php else: ?>
                <!-- Apply Patch Interface -->
                <div class="form-section">
                    <h2 style="font-size: 1.25rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1.5rem;">
                        Apply Patch to Assets
                    </h2>
                    
                    <div id="patch-info" style="margin-bottom: 2rem;">
                        <div style="text-align: center; padding: 2rem;">
                            <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                            <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading patch details...</p>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Select Assets to Apply Patch</label>
                        <div id="asset-selector">
                            <div style="text-align: center; padding: 2rem;">
                                <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                                <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading affected assets...</p>
                            </div>
                        </div>
                    </div>
                    
                    <div id="selected-assets-info"></div>
                    
                    <div class="form-group">
                        <label class="form-label">Application Notes</label>
                        <textarea id="application-notes" class="form-textarea" placeholder="Add any notes about this patch application..."></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Verification Method</label>
                        <select id="verification-method" class="form-select">
                            <option value="Pending">Pending Verification</option>
                            <option value="Manual">Manual Verification</option>
                            <option value="SBOM Upload">SBOM Upload</option>
                            <option value="Automatic">Automatic</option>
                        </select>
                    </div>
                    
                    <div style="display: flex; justify-content: space-between; gap: 0.75rem; margin-top: 2rem;">
                        <button class="btn btn-secondary" onclick="window.location.href='?action=list'">
                            Cancel
                        </button>
                        <button class="btn btn-primary" onclick="applyPatchToAssets()">
                            <i class="fas fa-download"></i> Apply Patch to Selected Assets
                        </button>
                    </div>
                </div>
                
                <div id="application-results"></div>
                <?php endif; ?>

            <?php elseif ($action === 'edit'): ?>
                <?php if (!$isAdmin): ?>
                    <!-- Access Denied for Edit -->
                    <div class="form-section">
                        <div style="text-align: center; padding: 3rem;">
                            <i class="fas fa-lock" style="font-size: 3rem; color: var(--text-muted, #94a3b8); margin-bottom: 1rem;"></i>
                            <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">Admin Access Required</h3>
                            <p style="color: var(--text-secondary, #cbd5e1);">Only administrators can edit patches.</p>
                            <button class="btn btn-secondary" onclick="window.location.href='?action=list'" style="margin-top: 1rem;">
                                <i class="fas fa-arrow-left"></i> Back to Patches
                            </button>
                        </div>
                    </div>
                <?php else: ?>
                <!-- Edit Patch Interface -->
                <div class="form-section">
                    <h2 style="font-size: 1.25rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1.5rem;">
                        Edit Patch
                    </h2>
                    
                    <div id="patch-edit-form">
                        <div style="text-align: center; padding: 2rem;">
                            <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                            <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading patch details...</p>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                
            <?php elseif ($action === 'history'): ?>
                <!-- Patch History View -->
                <div class="form-section">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                        <h2 style="font-size: 1.25rem; font-weight: 600; color: var(--text-primary, #ffffff); margin: 0;">
                            Patch History
                        </h2>
                        <a href="?action=list" class="btn btn-secondary">
                            <i class="fas fa-arrow-left"></i> Back to Patches
                        </a>
                    </div>
                    <div id="patch-history-content">
                        <div style="text-align: center; padding: 2rem;">
                            <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                            <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading history...</p>
                        </div>
                    </div>
                </div>

            <?php elseif ($action === 'schedule'): ?>
                <!-- Patch Scheduling View -->
                <div class="form-section">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                        <h2 style="font-size: 1.25rem; font-weight: 600; color: var(--text-primary, #ffffff); margin: 0;">
                            Schedule Patch Application
                        </h2>
                        <a href="?action=list" class="btn btn-secondary">
                            <i class="fas fa-arrow-left"></i> Back to Patches
                        </a>
                    </div>
                    
                    <?php if (empty($patchId)): ?>
                        <div style="text-align: center; padding: 2rem;">
                            <i class="fas fa-exclamation-triangle" style="font-size: 2rem; color: #f59e0b; margin-bottom: 1rem;"></i>
                            <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">No Patch Selected</h3>
                            <p style="color: var(--text-secondary, #cbd5e1);">Please select a patch to schedule.</p>
                        </div>
                    <?php elseif (empty($patch)): ?>
                        <div style="text-align: center; padding: 2rem;">
                            <i class="fas fa-exclamation-circle" style="font-size: 2rem; color: #ef4444; margin-bottom: 1rem;"></i>
                            <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">Patch Not Found</h3>
                            <p style="color: var(--text-secondary, #cbd5e1);">The selected patch could not be found.</p>
                        </div>
                    <?php else: ?>
                        <!-- Patch Information -->
                        <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333); border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1.5rem;">
                            <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 1rem;"><?php echo dave_htmlspecialchars($patch['patch_name']); ?></h3>
                            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                                <div>
                                    <div style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; margin-bottom: 0.25rem;">Patch Type</div>
                                    <div style="color: var(--text-primary, #ffffff);"><?php echo dave_htmlspecialchars($patch['patch_type']); ?></div>
                                </div>
                                <div>
                                    <div style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; margin-bottom: 0.25rem;">CVEs Resolved</div>
                                    <div style="color: var(--text-primary, #ffffff);"><?php echo count(json_decode($patch['cve_list'] ?? '[]', true)); ?></div>
                                </div>
                                <div>
                                    <div style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; margin-bottom: 0.25rem;">Release Date</div>
                                    <div style="color: var(--text-primary, #ffffff);"><?php echo dave_htmlspecialchars($patch['release_date']); ?></div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Affected Devices -->
                        <?php if (empty($affectedDevices)): ?>
                            <div style="text-align: center; padding: 2rem;">
                                <i class="fas fa-info-circle" style="font-size: 2rem; color: var(--siemens-petrol, #009999); margin-bottom: 1rem;"></i>
                                <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">No Affected Devices</h3>
                                <p style="color: var(--text-secondary, #cbd5e1);">No devices are currently affected by the CVEs in this patch.</p>
                            </div>
                        <?php else: ?>
                            <div id="patch-scheduling-content">
                                <div style="text-align: center; padding: 2rem;">
                                    <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                                    <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Preparing scheduling modal...</p>
                                </div>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>

            <?php endif; ?>

        </div>
    </main>

    <script>
        let currentStep = 1;
        let selectedCVEs = [];
        let selectedAssets = [];
        const patchId = '<?php echo addslashes($patchId); ?>';
        const packageId = '<?php echo addslashes($packageId); ?>';
        const action = '<?php echo addslashes($action); ?>';
        
        // Notification System
        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <div class="notification-content">
                    <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                    <span>${message}</span>
                </div>
            `;
            document.body.appendChild(notification);
            setTimeout(() => notification.classList.add('show'), 100);
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize assign owner modal
            if (typeof window.assignOwnerModal === 'undefined') {
                window.assignOwnerModal = new AssignOwnerModal();
                window.assignOwnerModal.init();
            }
            
            if (action === 'list') {
                // Try to load patches with fallback
                loadPatchesWithFallback();
            } else if (action === 'create') {
                setupCreateForm();
            } else if (action === 'apply') {
                loadPatchForApplication();
            } else if (action === 'edit') {
                loadPatchForEdit();
            } else if (action === 'history') {
                loadPatchHistory();
            } else if (action === 'schedule') {
                loadPatchScheduling();
            }
        });
        
        // Load patches with fallback mechanism
        async function loadPatchesWithFallback() {
            const container = document.getElementById('patches-container');
            
            // Show loading state
            container.innerHTML = `
                <div style="text-align: center; padding: 3rem;">
                    <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                    <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading patches...</p>
                </div>
            `;
            
            try {
                await loadPatches();
            } catch (error) {
                console.error('Primary loadPatches failed:', error);
                // Try fallback method
                try {
                    await loadPatchesFallback();
                } catch (fallbackError) {
                    console.error('Fallback also failed:', fallbackError);
                    showPatchesError(container, 'Unable to load patches. Please try refreshing the page.');
                }
            }
        }
        
        // Fallback method using direct PHP include
        async function loadPatchesFallback() {
            const container = document.getElementById('patches-container');
            
            try {
                const response = await fetch('?action=list&fallback=1');
                if (response.ok) {
                    const html = await response.text();
                    // Extract just the patches content
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(html, 'text/html');
                    const patchesContent = doc.querySelector('#patches-container');
                    if (patchesContent) {
                        container.innerHTML = patchesContent.innerHTML;
                    } else {
                        throw new Error('No patches content found in fallback response');
                    }
                } else {
                    throw new Error(`Fallback request failed: ${response.status}`);
                }
            } catch (error) {
                throw new Error(`Fallback method failed: ${error.message}`);
            }
        }
        
        function showPatchesError(container, message) {
            container.innerHTML = `
                <div style="background: #ef4444; color: white; padding: 2rem; border-radius: 0.5rem; text-align: center; margin: 1rem 0;">
                    <i class="fas fa-exclamation-triangle" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                    <h3 style="margin: 0 0 1rem 0;">System Error</h3>
                    <p style="margin: 0 0 1rem 0;">${escapeHtml(message)}</p>
                    <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
                        <button onclick="window.location.reload()" class="btn btn-primary">
                            <i class="fas fa-refresh"></i> Reload Page
                        </button>
                        <a href="?action=create" class="btn btn-secondary">
                            <i class="fas fa-plus"></i> Create Patch
                        </a>
                    </div>
                </div>
            `;
        }

        // Load all patches
        async function loadPatches() {
            const container = document.getElementById('patches-container');
            
            // Show loading state
            container.innerHTML = `
                <div style="text-align: center; padding: 3rem;">
                    <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                    <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading patches...</p>
                </div>
            `;
            
            try {
                // Add timeout to prevent hanging
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
                
                const response = await fetch('/api/v1/patches/index.php', {
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const result = await response.json();
                
                if (result.success && result.data.length > 0) {
                    container.innerHTML = result.data.map(patch => `
                        <div class="patch-card">
                            <div class="patch-header">
                                <div>
                                    <div class="patch-title">${escapeHtml(patch.patch_name)}</div>
                                    <div class="patch-type"><i class="fas fa-tag"></i> ${escapeHtml(patch.patch_type)}</div>
                                </div>
                        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                            <button class="btn btn-primary btn-sm" onclick="applyPatch('${patch.patch_id}')">
                                <i class="fas fa-download"></i> Apply
                            </button>
                            <button class="btn btn-secondary btn-sm" onclick="editPatch('${patch.patch_id}')">
                                <i class="fas fa-edit"></i> Edit
                            </button>
                            <button class="btn btn-info btn-sm" onclick="viewPatchHistory('${patch.patch_id}')">
                                <i class="fas fa-history"></i> History
                            </button>
                            <button class="btn btn-warning btn-sm" onclick="schedulePatch('${patch.patch_id}')">
                                <i class="fas fa-calendar-plus"></i> Schedule
                            </button>
                            <button class="btn btn-danger btn-sm" onclick="deletePatch('${patch.patch_id}')">
                                <i class="fas fa-trash"></i> Delete
                            </button>
                        </div>
                            </div>
                            
                            <div class="patch-meta">
                                <div class="meta-item">
                                    <div class="meta-label">Target Version</div>
                                    <div class="meta-value">${escapeHtml(patch.target_version || 'N/A')}</div>
                                </div>
                                <div class="meta-item">
                                    <div class="meta-label">CVEs Resolved</div>
                                    <div class="meta-value">${patch.cve_count || 0}</div>
                                </div>
                                <div class="meta-item">
                                    <div class="meta-label">History</div>
                                    <div class="meta-value">${patch.application_count || 0}</div>
                                </div>
                                <div class="meta-item">
                                    <div class="meta-label">Release Date</div>
                                    <div class="meta-value">${formatDate(patch.release_date)}</div>
                                </div>
                            </div>
                            
                            <div style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; margin-top: 0.5rem;">
                                ${escapeHtml(patch.description || '').substring(0, 150)}${patch.description && patch.description.length > 150 ? '...' : ''}
                            </div>
                        </div>
                    `).join('');
                } else {
                    container.innerHTML = `
                        <div style="text-align: center; padding: 3rem; background: var(--bg-card, #1a1a1a); border-radius: 0.75rem; border: 1px dashed var(--border-primary, #333333);">
                            <i class="fas fa-box-open" style="font-size: 3rem; color: var(--text-muted, #94a3b8); margin-bottom: 1rem;"></i>
                            <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">No Patches Available</h3>
                            <p style="color: var(--text-secondary, #cbd5e1); margin-bottom: 1.5rem;">Create your first patch to start managing vulnerability remediation.</p>
                            <button class="btn btn-primary" onclick="window.location.href='?action=create'">
                                <i class="fas fa-plus"></i> Create First Patch
                            </button>
                        </div>
                    `;
                }
            } catch (error) {
                console.error('Error loading patches:', error);
                
                let errorMessage = 'Unknown error occurred';
                if (error.name === 'AbortError') {
                    errorMessage = 'Request timed out. The server may be slow or unresponsive.';
                } else if (error.message.includes('Failed to fetch')) {
                    errorMessage = 'Unable to connect to the server. Please check your network connection.';
                } else if (error.message.includes('HTTP')) {
                    errorMessage = `Server error: ${error.message}`;
                } else {
                    errorMessage = error.message;
                }
                
                container.innerHTML = `
                    <div style="background: #ef4444; color: white; padding: 2rem; border-radius: 0.5rem; text-align: center; margin: 1rem 0;">
                        <i class="fas fa-exclamation-triangle" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                        <h3 style="margin: 0 0 1rem 0;">Error Loading Patches</h3>
                        <p style="margin: 0 0 1rem 0;">${escapeHtml(errorMessage)}</p>
                        <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
                            <button onclick="loadPatches()" class="btn btn-primary">
                                <i class="fas fa-refresh"></i> Retry
                            </button>
                            <a href="?action=create" class="btn btn-secondary">
                                <i class="fas fa-plus"></i> Create Patch
                            </a>
                        </div>
                    </div>
                `;
            }
        }

        // Setup create form
        function setupCreateForm() {
            document.getElementById('create-patch-form').addEventListener('submit', handleCreatePatch);
        }

        // Wizard navigation
        function nextStep() {
            if (currentStep === 1) {
                // Validate step 1
                const form = document.getElementById('create-patch-form');
                const patchName = form.patch_name.value;
                const patchType = form.patch_type.value;
                const description = form.description.value;
                
                if (!patchName || !patchType || !description) {
                    showNotification('Please fill in all required fields', 'error');
                    return;
                }
                
                currentStep = 2;
                updateWizardDisplay();
                loadCVEsForSelection();
            } else if (currentStep === 2) {
                if (selectedCVEs.length === 0) {
                    showNotification('No CVEs selected. Please select at least one CVE to continue.', 'error');
                        return;
                }
                currentStep = 3;
                updateWizardDisplay();
                showReview();
            }
        }

        function previousStep() {
            if (currentStep > 1) {
                currentStep--;
                updateWizardDisplay();
            }
        }

        function updateWizardDisplay() {
            // Update step indicators
            document.querySelectorAll('.wizard-step').forEach((step, index) => {
                const stepNum = index + 1;
                step.classList.remove('active', 'completed');
                if (stepNum < currentStep) {
                    step.classList.add('completed');
                } else if (stepNum === currentStep) {
                    step.classList.add('active');
                }
            });
            
            // Update content visibility
            document.querySelectorAll('.wizard-content').forEach(content => {
                content.style.display = 'none';
            });
            document.querySelector(`.wizard-content[data-step="${currentStep}"]`).style.display = 'block';
        }

        // Load CVEs for selection
        async function loadCVEsForSelection() {
            try {
                let allCVEs = [];
                
                if (packageId) {
                    // Load CVEs for specific package
                    const response = await fetch(`/api/v1/software-packages/risk-priorities.php/${packageId}/vulnerabilities`, {
                        method: 'GET',
                        credentials: 'same-origin',
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    });
                    const result = await response.json();
                    
                    if (result.success && result.data) {
                        allCVEs = result.data;
                    }
                } else {
                    // Load all vulnerabilities in batches (API limits to 100 per request)
                    let page = 1;
                    let hasMore = true;
                    
                    while (hasMore && page <= 100) {
                        const response = await fetch(`/api/v1/vulnerabilities/index.php?page=${page}&limit=100`, {
                            method: 'GET',
                            credentials: 'same-origin',
                            headers: {
                                'Content-Type': 'application/json'
                            }
                        });
                        const result = await response.json();
                        
                        
                        if (result.success && result.data && result.data.length > 0) {
                            allCVEs.push(...result.data);
                            hasMore = result.data.length === 100;
                            page++;
                        } else {
                            if (result.error) {
                                console.error(`Error on page ${page}:`, result.error);
                            }
                            hasMore = false;
                        }
                    }
                    
                }
                
                if (allCVEs.length > 0) {
                    renderCVESelector(allCVEs);
                } else {
                    document.getElementById('cve-selector').innerHTML = `
                        <div class="empty-message">
                            <p>No vulnerabilities found</p>
                            <p style="font-size: 0.875rem; color: var(--text-muted);">The system has no CVEs available</p>
                        </div>
                    `;
                }
            } catch (error) {
                console.error('Error loading CVEs for selection:', error);
                const errorMessage = error?.message || error?.error?.message || error?.toString() || 'Unknown error occurred';
                document.getElementById('cve-selector').innerHTML = `
                    <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                        <i class="fas fa-exclamation-circle"></i> Error loading CVEs: ${escapeHtml(errorMessage)}
                        <br><br>
                        <small>Check browser console for details</small>
                    </div>
                `;
            }
        }

        function renderCVESelector(cves) {
            // Store all CVEs for searching
            window.allCVEs = cves;
            window.filteredCVEs = cves;
            
            document.getElementById('cve-selector').innerHTML = `
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                    <!-- Available CVEs Panel -->
                    <div>
                        <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 1rem; font-size: 1rem;">
                            Available CVEs (${cves.length})
                        </h3>
                        
                        <!-- Search and Filters -->
                        <div style="margin-bottom: 1rem;">
                            <input type="text" id="cve-search" class="form-input" placeholder="Search CVE ID, severity..." 
                                   onkeyup="filterCVEs()" style="margin-bottom: 0.5rem;">
                            <div style="display: flex; gap: 0.5rem;">
                                <select id="severity-filter" class="form-select" onchange="filterCVEs()" style="flex: 1;">
                                    <option value="">All Severities</option>
                                    <option value="Critical">Critical</option>
                                    <option value="High">High</option>
                                    <option value="Medium">Medium</option>
                                    <option value="Low">Low</option>
                                </select>
                                <label style="display: flex; align-items: center; gap: 0.5rem; color: var(--text-primary, #ffffff);">
                                    <input type="checkbox" id="kev-filter" onchange="filterCVEs()"> KEV Only
                                </label>
                            </div>
                        </div>
                        
                        <!-- Available CVE List -->
                        <div id="available-cves" class="asset-selector" style="height: 400px; overflow-y: auto;">
                            <!-- Will be populated by renderAvailableCVEs -->
                        </div>
                        
                        <div style="margin-top: 0.5rem; font-size: 0.875rem; color: var(--text-muted, #94a3b8);">
                            Showing <span id="filtered-count">${cves.length}</span> of ${cves.length} CVEs
                        </div>
                    </div>
                    
                    <!-- Selected CVEs Panel -->
                    <div>
                        <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 1rem; font-size: 1rem;">
                            Selected CVEs (<span id="cve-count">0</span>)
                        </h3>
                        
                        <div style="margin-bottom: 1rem;">
                            <button type="button" class="btn btn-secondary btn-sm" onclick="clearSelectedCVEs()">
                                <i class="fas fa-times"></i> Clear All
                            </button>
                        </div>
                        
                        <!-- Selected CVE List -->
                        <div id="selected-cves" class="asset-selector" style="height: 400px; overflow-y: auto; background: var(--bg-tertiary, #222222);">
                            <div style="text-align: center; padding: 2rem; color: var(--text-muted, #94a3b8);">
                                <i class="fas fa-hand-pointer" style="font-size: 2rem; margin-bottom: 0.5rem;"></i>
                                <p>Click CVEs on the left to add them here</p>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            renderAvailableCVEs();
        }
        
        function filterCVEs() {
            const searchTerm = document.getElementById('cve-search').value.toLowerCase();
            const severityFilter = document.getElementById('severity-filter').value;
            const kevOnly = document.getElementById('kev-filter').checked;
            
            window.filteredCVEs = window.allCVEs.filter(cve => {
                // Search filter
                if (searchTerm && !cve.cve_id.toLowerCase().includes(searchTerm) && 
                    !cve.severity.toLowerCase().includes(searchTerm)) {
                    return false;
                }
                
                // Severity filter
                if (severityFilter && cve.severity !== severityFilter) {
                    return false;
                }
                
                // KEV filter
                if (kevOnly && !cve.is_kev && !cve.kev) {
                    return false;
                }
                
                return true;
            });
            
            document.getElementById('filtered-count').textContent = window.filteredCVEs.length;
            renderAvailableCVEs();
        }
        
        function renderAvailableCVEs() {
            const container = document.getElementById('available-cves');
            
            // Ensure filteredCVEs is defined and is an array
            if (!window.filteredCVEs || !Array.isArray(window.filteredCVEs)) {
                console.error('Error: window.filteredCVEs is undefined or not an array');
                container.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-muted, #94a3b8);">No CVEs available. Please reload the page.</div>';
                return;
            }
            
            if (window.filteredCVEs.length === 0) {
                container.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-muted, #94a3b8);">No CVEs match your filters</div>';
                return;
            }
            
            container.innerHTML = window.filteredCVEs.map(cve => {
                const isSelected = selectedCVEs.includes(cve.cve_id);
                return `
                    <div class="asset-item ${isSelected ? 'selected-item' : ''}" onclick="toggleCVESelection('${cve.cve_id}')" style="cursor: pointer;">
                        <div style="display: flex; align-items: center; gap: 0.5rem; width: 100%;">
                            <i class="fas ${isSelected ? 'fa-check-circle' : 'fa-plus-circle'}" style="color: ${isSelected ? 'var(--siemens-petrol, #009999)' : 'var(--text-muted, #94a3b8)'};"></i>
                            <div class="asset-info" style="flex: 1;">
                                <div class="asset-name">${cve.cve_id}</div>
                                <div class="asset-details">
                                    <span class="severity-badge severity-${cve.severity.toLowerCase()}">${cve.severity}</span>
                                    CVSS: ${cve.cvss_score || cve.cvss_v3_score || 'N/A'}
                                    ${cve.is_kev || cve.kev ? '<span class="kev-indicator" style="margin-left: 0.5rem;"><i class="fas fa-exclamation-triangle"></i></span>' : ''}
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }
        
        function renderSelectedCVEs() {
            const container = document.getElementById('selected-cves');
            
            if (selectedCVEs.length === 0) {
                container.innerHTML = `
                    <div style="text-align: center; padding: 2rem; color: var(--text-muted, #94a3b8);">
                        <i class="fas fa-hand-pointer" style="font-size: 2rem; margin-bottom: 0.5rem;"></i>
                        <p>Click CVEs on the left to add them here</p>
                    </div>
                `;
                return;
            }
            
            const selectedCVEObjects = window.allCVEs.filter(cve => selectedCVEs.includes(cve.cve_id));
            
            container.innerHTML = selectedCVEObjects.map(cve => `
                <div class="asset-item" style="background: var(--bg-secondary, #0f0f0f);">
                    <div style="display: flex; align-items: center; gap: 0.5rem; width: 100%;">
                        <button type="button" onclick="removeCVE('${cve.cve_id}')" 
                                style="background: none; border: none; color: #ef4444; cursor: pointer; padding: 0;">
                            <i class="fas fa-times-circle"></i>
                        </button>
                        <div class="asset-info" style="flex: 1;">
                            <div class="asset-name">${cve.cve_id}</div>
                            <div class="asset-details">
                                <span class="severity-badge severity-${cve.severity.toLowerCase()}">${cve.severity}</span>
                                CVSS: ${cve.cvss_score || cve.cvss_v3_score || 'N/A'}
                                ${cve.is_kev || cve.kev ? '<span class="kev-indicator" style="margin-left: 0.5rem;"><i class="fas fa-exclamation-triangle"></i></span>' : ''}
                            </div>
                        </div>
                    </div>
                </div>
            `).join('');
        }
        
        function toggleCVESelection(cveId) {
            const index = selectedCVEs.indexOf(cveId);
            if (index > -1) {
                selectedCVEs.splice(index, 1);
            } else {
                selectedCVEs.push(cveId);
            }
            
            document.getElementById('cve-count').textContent = selectedCVEs.length;
            renderAvailableCVEs();
            renderSelectedCVEs();
        }
        
        function removeCVE(cveId) {
            const index = selectedCVEs.indexOf(cveId);
            if (index > -1) {
                selectedCVEs.splice(index, 1);
            }
            
            document.getElementById('cve-count').textContent = selectedCVEs.length;
            renderAvailableCVEs();
            renderSelectedCVEs();
        }
        
        function clearSelectedCVEs() {
            selectedCVEs = [];
            document.getElementById('cve-count').textContent = 0;
            renderAvailableCVEs();
            renderSelectedCVEs();
        }


        // Show review
        function showReview() {
            const form = document.getElementById('create-patch-form');
            const review = document.getElementById('patch-review');
            
            review.innerHTML = `
                <div style="display: grid; gap: 1rem;">
                    <div>
                        <strong style="color: var(--text-primary, #ffffff);">Patch Name:</strong>
                        <p style="color: var(--text-secondary, #cbd5e1);">${escapeHtml(form.patch_name.value)}</p>
                    </div>
                    <div>
                        <strong style="color: var(--text-primary, #ffffff);">Patch Type:</strong>
                        <p style="color: var(--text-secondary, #cbd5e1);">${escapeHtml(form.patch_type.value)}</p>
                    </div>
                    <div>
                        <strong style="color: var(--text-primary, #ffffff);">Description:</strong>
                        <p style="color: var(--text-secondary, #cbd5e1);">${escapeHtml(form.description.value)}</p>
                    </div>
                    ${form.target_version.value ? `
                    <div>
                        <strong style="color: var(--text-primary, #ffffff);">Target Version:</strong>
                        <p style="color: var(--text-secondary, #cbd5e1);">${escapeHtml(form.target_version.value)}</p>
                    </div>
                    ` : ''}
                    ${form.vendor.value ? `
                    <div>
                        <strong style="color: var(--text-primary, #ffffff);">Vendor:</strong>
                        <p style="color: var(--text-secondary, #cbd5e1);">${escapeHtml(form.vendor.value)}</p>
                    </div>
                    ` : ''}
                    ${form.kb_article.value ? `
                    <div>
                        <strong style="color: var(--text-primary, #ffffff);">KB Article:</strong>
                        <p style="color: var(--text-secondary, #cbd5e1);">${escapeHtml(form.kb_article.value)}</p>
                    </div>
                    ` : ''}
                    ${form.download_url.value ? `
                    <div>
                        <strong style="color: var(--text-primary, #ffffff);">Download URL:</strong>
                        <p style="color: var(--text-secondary, #cbd5e1);">${escapeHtml(form.download_url.value)}</p>
                    </div>
                    ` : ''}
                    ${form.estimated_install_time.value ? `
                    <div>
                        <strong style="color: var(--text-primary, #ffffff);">Estimated Install Time:</strong>
                        <p style="color: var(--text-secondary, #cbd5e1);">${escapeHtml(form.estimated_install_time.value)} minutes</p>
                    </div>
                    ` : ''}
                    ${form.requires_reboot.checked ? `
                    <div>
                        <strong style="color: var(--text-primary, #ffffff);">Requires Reboot:</strong>
                        <p style="color: var(--text-secondary, #cbd5e1);">Yes</p>
                    </div>
                    ` : ''}
                    <div>
                        <strong style="color: var(--text-primary, #ffffff);">CVEs to Resolve:</strong>
                        <p style="color: var(--text-secondary, #cbd5e1);">${selectedCVEs.length} CVE${selectedCVEs.length !== 1 ? 's' : ''}</p>
                    </div>
                </div>
            `;
        }

        // Handle create patch submission
        async function handleCreatePatch(e) {
            e.preventDefault();
            
            const form = e.target;
            const formData = new FormData(form);
            
            const patchData = {
                patch_name: formData.get('patch_name'),
                patch_type: formData.get('patch_type'),
                description: formData.get('description'),
                target_version: formData.get('target_version'),
                target_device_type: formData.get('target_device_type'),
                release_date: formData.get('release_date'),
                vendor: formData.get('vendor'),
                kb_article: formData.get('kb_article'),
                download_url: formData.get('download_url'),
                install_instructions: formData.get('install_instructions'),
                prerequisites: formData.get('prerequisites'),
                estimated_install_time: formData.get('estimated_install_time') && !isNaN(parseInt(formData.get('estimated_install_time'))) ? parseInt(formData.get('estimated_install_time')) : null,
                requires_reboot: formData.get('requires_reboot') === 'on',
                package_id: formData.get('package_id'),
                cve_list: selectedCVEs
            };
            
            try {
                const response = await fetch('/api/v1/patches/index.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(patchData)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification('Patch created successfully!', 'success');
                    window.location.href = '?action=list';
                } else {
                    showNotification('Error creating patch: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                showNotification('Error creating patch: ' + error.message, 'error');
            }
        }

        // Load patch for application
        async function loadPatchForApplication() {
            if (!patchId && !packageId) {
                document.getElementById('patch-info').innerHTML = '<div class="empty-message">No patch or package specified</div>';
                return;
            }
            
            try {
                // Load patch details
                const patchResponse = await fetch(`/api/v1/patches/index.php/${patchId}`);
                const patchResult = await patchResponse.json();
                
                if (patchResult.success) {
                    renderPatchInfo(patchResult.data);
                    await loadAffectedAssets(patchResult.data);
                } else {
                    document.getElementById('patch-info').innerHTML = `
                        <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                            <i class="fas fa-exclamation-circle"></i> Error loading patch: ${escapeHtml(patchResult.error || 'Unknown error')}
                        </div>
                    `;
                }
            } catch (error) {
                document.getElementById('patch-info').innerHTML = `
                    <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                        <i class="fas fa-exclamation-circle"></i> Error loading patch: ${escapeHtml(error.message)}
                    </div>
                `;
            }
        }
        
        // Render patch information
        function renderPatchInfo(patch) {
            const patchInfo = document.getElementById('patch-info');
            patchInfo.innerHTML = `
                <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                        <div>
                            <h3 style="color: var(--text-primary, #ffffff); margin: 0 0 0.5rem 0;">${escapeHtml(patch.patch_name)}</h3>
                            <p style="color: var(--text-secondary, #cbd5e1); margin: 0; font-size: 0.875rem;">${escapeHtml(patch.patch_type)} - Version ${escapeHtml(patch.target_version || 'N/A')}</p>
                        </div>
                        <div style="text-align: right;">
                            <div style="color: var(--text-muted, #94a3b8); font-size: 0.75rem;">Created</div>
                            <div style="color: var(--text-primary, #ffffff);">${formatDate(patch.created_at)}</div>
                        </div>
                    </div>
                    
                    <div style="background: var(--bg-secondary, #0f0f0f); border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem;">
                        <div style="color: var(--text-muted, #94a3b8); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.5rem;">Description</div>
                        <div style="color: var(--text-primary, #ffffff);">${escapeHtml(patch.description || 'No description available')}</div>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
                        <div>
                            <div style="color: var(--text-muted, #94a3b8); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.25rem;">Vendor</div>
                            <div style="color: var(--text-primary, #ffffff);">${escapeHtml(patch.vendor || 'N/A')}</div>
                        </div>
                        <div>
                            <div style="color: var(--text-muted, #94a3b8); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.25rem;">Install Time</div>
                            <div style="color: var(--text-primary, #ffffff);">${patch.estimated_install_time ? patch.estimated_install_time + ' minutes' : 'N/A'}</div>
                        </div>
                        <div>
                            <div style="color: var(--text-muted, #94a3b8); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.25rem;">Reboot Required</div>
                            <div style="color: var(--text-primary, #ffffff);">${patch.requires_reboot ? 'Yes' : 'No'}</div>
                        </div>
                        <div>
                            <div style="color: var(--text-muted, #94a3b8); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.25rem;">CVEs</div>
                            <div style="color: var(--text-primary, #ffffff);">${patch.cve_list ? JSON.parse(patch.cve_list).length : 0} associated</div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        // Load affected assets
        async function loadAffectedAssets(patch) {
            try {
                // Get CVEs from patch
                const cveList = patch.cve_list ? JSON.parse(patch.cve_list) : [];
                
                if (cveList.length === 0) {
                    document.getElementById('asset-selector').innerHTML = `
                        <div style="text-align: center; padding: 3rem;">
                            <i class="fas fa-info-circle" style="font-size: 3rem; color: var(--text-muted, #94a3b8); margin-bottom: 1rem;"></i>
                            <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">No CVEs Associated</h3>
                            <p style="color: var(--text-secondary, #cbd5e1);">This patch has no associated CVEs, so no specific assets are affected.</p>
                        </div>
                    `;
                    return;
                }
                
                // Load assets filtered by CVEs
                const cveFilter = cveList.join(',');
                const response = await fetch(`/api/v1/assets/index.php?cve_filter=${encodeURIComponent(cveFilter)}&limit=1000`);
                const result = await response.json();
                
                if (result.success) {
                    renderAssetSelector(result.data, cveList);
                } else {
                    document.getElementById('asset-selector').innerHTML = `
                        <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                            <i class="fas fa-exclamation-circle"></i> Error loading assets: ${escapeHtml(result.error || 'Unknown error')}
                        </div>
                    `;
                }
            } catch (error) {
                document.getElementById('asset-selector').innerHTML = `
                    <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                        <i class="fas fa-exclamation-circle"></i> Error loading assets: ${escapeHtml(error.message)}
                    </div>
                `;
            }
        }
        
        // Render asset selector
        function renderAssetSelector(assets, cveList) {
            if (assets.length === 0) {
                document.getElementById('asset-selector').innerHTML = `
                    <div style="text-align: center; padding: 3rem;">
                        <i class="fas fa-inbox" style="font-size: 3rem; color: var(--text-muted, #94a3b8); margin-bottom: 1rem;"></i>
                        <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">No Affected Assets</h3>
                        <p style="color: var(--text-secondary, #cbd5e1);">No assets are currently affected by the CVEs in this patch.</p>
                    </div>
                `;
                return;
            }
            
            const assetSelector = document.getElementById('asset-selector');
            assetSelector.innerHTML = `
                <div style="margin-bottom: 1rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <span style="color: var(--text-primary, #ffffff); font-weight: 600;">Select Assets (${assets.length} available)</span>
                        <div style="display: flex; gap: 0.5rem;">
                            <button onclick="selectAllAssets()" class="btn btn-secondary btn-sm">
                                <i class="fas fa-check-square"></i> Select All
                            </button>
                            <button onclick="deselectAllAssets()" class="btn btn-secondary btn-sm">
                                <i class="fas fa-square"></i> Deselect All
                            </button>
                        </div>
                    </div>
                    <div style="background: var(--bg-secondary, #0f0f0f); border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem; border-left: 4px solid var(--success-green, #10b981);">
                        <div style="color: var(--text-primary, #ffffff); font-weight: 600; margin-bottom: 0.5rem;">
                            <i class="fas fa-filter" style="color: var(--success-green, #10b981);"></i> CVE-Filtered Results
                        </div>
                        <div style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">
                            Showing only assets affected by the patch's CVEs.
                            <br>Filtering by: ${cveList.length > 0 ? cveList.join(', ') : 'No CVEs'}
                        </div>
                    </div>
                    <div style="max-height: 400px; overflow-y: auto; border: 1px solid var(--border-primary, #333333); border-radius: 0.5rem;">
                        ${assets.map(asset => `
                            <div class="asset-item" data-asset-id="${asset.asset_id}" style="padding: 1rem; border-bottom: 1px solid var(--border-primary, #333333); cursor: pointer; transition: background-color 0.2s;" onclick="toggleAssetSelection('${asset.asset_id}')">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <div style="flex: 1;">
                                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                                            <input type="checkbox" id="asset-${asset.asset_id}" style="margin: 0;">
                                            <label for="asset-${asset.asset_id}" style="color: var(--text-primary, #ffffff); font-weight: 600; margin: 0; cursor: pointer;">${escapeHtml(getAssetDisplayName(asset))}</label>
                                        </div>
                                        <div style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; margin-left: 1.5rem;">
                                            <div>IP: ${escapeHtml(asset.ip_address || 'N/A')} | Type: ${escapeHtml(asset.asset_type || 'N/A')}</div>
                                            <div>Manufacturer: ${escapeHtml(asset.manufacturer_name || asset.manufacturer || 'N/A')} | Status: ${escapeHtml(asset.status || 'N/A')}</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
            
            // Add event listeners for checkboxes
            assets.forEach(asset => {
                const checkbox = document.getElementById(`asset-${asset.asset_id}`);
                if (checkbox) {
                    checkbox.addEventListener('change', function() {
                        toggleAssetSelection(asset.asset_id);
                    });
                }
            });
        }
        
        // Toggle asset selection
        function toggleAssetSelection(assetId) {
            const index = selectedAssets.indexOf(assetId);
            if (index > -1) {
                selectedAssets.splice(index, 1);
            } else {
                selectedAssets.push(assetId);
            }
            
            // Update visual state
            const assetItem = document.querySelector(`[data-asset-id="${assetId}"]`);
            const checkbox = document.getElementById(`asset-${assetId}`);
            
            if (selectedAssets.includes(assetId)) {
                assetItem.style.background = 'var(--siemens-petrol, #009999)';
                if (checkbox) checkbox.checked = true;
            } else {
                assetItem.style.background = '';
                if (checkbox) checkbox.checked = false;
            }
            
            updateSelectedAssetsInfo();
        }
        
        // Select all assets
        function selectAllAssets() {
            const assetItems = document.querySelectorAll('.asset-item');
            assetItems.forEach(item => {
                const assetId = item.dataset.assetId;
                if (!selectedAssets.includes(assetId)) {
                    selectedAssets.push(assetId);
                    item.style.background = 'var(--siemens-petrol, #009999)';
                    const checkbox = document.getElementById(`asset-${assetId}`);
                    if (checkbox) checkbox.checked = true;
                }
            });
            updateSelectedAssetsInfo();
        }
        
        // Deselect all assets
        function deselectAllAssets() {
            selectedAssets = [];
            const assetItems = document.querySelectorAll('.asset-item');
            assetItems.forEach(item => {
                item.style.background = '';
                const assetId = item.dataset.assetId;
                const checkbox = document.getElementById(`asset-${assetId}`);
                if (checkbox) checkbox.checked = false;
            });
            updateSelectedAssetsInfo();
        }
        
        // Update selected assets info
        function updateSelectedAssetsInfo() {
            const infoDiv = document.getElementById('selected-assets-info');
            if (selectedAssets.length === 0) {
                infoDiv.innerHTML = '';
                return;
            }
            
            infoDiv.innerHTML = `
                <div style="background: var(--bg-secondary, #0f0f0f); border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem;">
                    <div style="color: var(--text-primary, #ffffff); font-weight: 600; margin-bottom: 0.5rem;">
                        <i class="fas fa-check-circle" style="color: var(--success-green, #10b981);"></i> 
                        ${selectedAssets.length} Asset${selectedAssets.length === 1 ? '' : 's'} Selected
                    </div>
                    <div style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">
                        Ready to apply patch to selected assets
                    </div>
                </div>
            `;
        }

        // Apply patch to assets
        async function applyPatchToAssets() {
            if (selectedAssets.length === 0) {
                showNotification('Please select at least one asset', 'error');
                return;
            }
            
            const notes = document.getElementById('application-notes').value;
            const verificationMethod = document.getElementById('verification-method').value;
            
            const applicationData = {
                patch_id: patchId,
                asset_ids: selectedAssets,
                notes: notes,
                verification_method: verificationMethod
            };
            
            try {
                const response = await fetch('/api/v1/patches/bulk-apply.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(applicationData)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showApplicationResults(result.data);
                } else {
                    showNotification('Error applying patch: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                showNotification('Error applying patch: ' + error.message, 'error');
            }
        }

        function showApplicationResults(results) {
            const container = document.getElementById('application-results');
            container.innerHTML = `
                <div class="form-section">
                    <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 1rem;">Application Results</h3>
                    ${results.map(result => `
                        <div class="application-result ${result.success ? 'result-success' : 'result-error'}">
                            <div style="font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 0.25rem;">
                                ${result.success ? '<i class="fas fa-check-circle"></i>' : '<i class="fas fa-times-circle"></i>'}
                                ${escapeHtml(result.asset_name)}
                            </div>
                            <div style="font-size: 0.875rem; color: var(--text-secondary, #cbd5e1);">
                                ${escapeHtml(result.message)}
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        // Load patch for editing
        async function loadPatchForEdit() {
            if (!patchId) {
                document.getElementById('patch-edit-form').innerHTML = '<div class="empty-message">No patch specified</div>';
                return;
            }
            
            try {
                const response = await fetch(`/api/v1/patches/index.php/${patchId}`);
                const result = await response.json();
                
                if (result.success) {
                    renderEditForm(result.data);
                } else {
                    document.getElementById('patch-edit-form').innerHTML = `
                        <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                            <i class="fas fa-exclamation-circle"></i> Error loading patch: ${escapeHtml(result.error || 'Unknown error')}
                        </div>
                    `;
                }
            } catch (error) {
                document.getElementById('patch-edit-form').innerHTML = `
                    <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                        <i class="fas fa-exclamation-circle"></i> Error loading patch: ${escapeHtml(error.message)}
                    </div>
                `;
            }
        }
        
        // Load patch history
        async function loadPatchHistory() {
            const patchId = new URLSearchParams(window.location.search).get('patch_id');
            if (!patchId) {
                document.getElementById('patch-history-content').innerHTML = `
                    <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                        Patch ID is required for viewing history.
                    </div>
                `;
                return;
            }
            
            try {
                const response = await fetch(`/api/v1/patches/index.php/${patchId}/applications`);
                const result = await response.json();
                
                if (result.success) {
                    renderPatchHistory(result.data);
                } else {
                    document.getElementById('patch-history-content').innerHTML = `
                        <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                            Error loading history: ${escapeHtml(result.error || 'Unknown error')}
                        </div>
                    `;
                }
            } catch (error) {
                document.getElementById('patch-history-content').innerHTML = `
                    <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                        Error loading history: ${escapeHtml(error.message)}
                    </div>
                `;
            }
        }
        
        // Render patch history
        function renderPatchHistory(applications) {
            if (!applications || applications.length === 0) {
                document.getElementById('patch-history-content').innerHTML = `
                    <div style="text-align: center; padding: 3rem;">
                        <i class="fas fa-inbox" style="font-size: 3rem; color: var(--text-muted, #94a3b8); margin-bottom: 1rem;"></i>
                        <h3 style="color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">No History Found</h3>
                        <p style="color: var(--text-secondary, #cbd5e1);">This patch has not been applied to any assets yet.</p>
                    </div>
                `;
                return;
            }
            
            const applicationsHtml = applications.map(app => `
                <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 1rem;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">
                        <div>
                            <h4 style="color: var(--text-primary, #ffffff); margin: 0 0 0.5rem 0;">${escapeHtml(getAssetDisplayName(app))}</h4>
                        </div>
                        <div style="display: flex; gap: 0.5rem;">
                            <span style="background: ${getStatusColor(app.status)}; color: white; padding: 0.25rem 0.75rem; border-radius: 1rem; font-size: 0.75rem; font-weight: 600;">
                                ${escapeHtml(app.status || 'Unknown')}
                            </span>
                        </div>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1rem;">
                        <div>
                            <div style="color: var(--text-muted, #94a3b8); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.25rem;">Applied Date</div>
                            <div style="color: var(--text-primary, #ffffff);">${formatDate(app.applied_date)}</div>
                        </div>
                        <div>
                            <div style="color: var(--text-muted, #94a3b8); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.25rem;">Applied By</div>
                            <div style="color: var(--text-primary, #ffffff);">${escapeHtml(app.applied_by || 'System')}</div>
                        </div>
                        <div>
                            <div style="color: var(--text-muted, #94a3b8); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.25rem;">Installation Time</div>
                            <div style="color: var(--text-primary, #ffffff);">${app.install_time ? app.install_time + ' minutes' : 'N/A'}</div>
                        </div>
                    </div>
                    
                    ${app.notes ? `
                        <div style="background: var(--bg-secondary, #0f0f0f); border-radius: 0.5rem; padding: 1rem; margin-top: 1rem;">
                            <div style="color: var(--text-muted, #94a3b8); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.5rem;">Notes</div>
                            <div style="color: var(--text-primary, #ffffff);">${escapeHtml(app.notes)}</div>
                        </div>
                    ` : ''}
                </div>
            `).join('');
            
            document.getElementById('patch-history-content').innerHTML = applicationsHtml;
        }
        
        function getStatusColor(status) {
            switch (status?.toLowerCase()) {
                case 'success': return '#10b981';
                case 'failed': return '#ef4444';
                case 'pending': return '#f59e0b';
                case 'in_progress': return '#3b82f6';
                default: return '#6b7280';
            }
        }
        
        function formatDate(dateString) {
            if (!dateString) return 'N/A';
            try {
                return new Date(dateString).toLocaleString();
            } catch (e) {
                return dateString;
            }
        }
        
        // Get asset display name with proper fallback logic
        function getAssetDisplayName(asset) {
            // Check each field and return the first non-empty, non-null value
            if (asset.hostname && asset.hostname.trim() !== '') {
                return asset.hostname;
            }
            if (asset.brand_name && asset.brand_name.trim() !== '') {
                return asset.brand_name;
            }
            if (asset.device_name && asset.device_name.trim() !== '') {
                return asset.device_name;
            }
            return 'Unknown';
        }
        
        // Render edit form
        function renderEditForm(patch) {
            const form = document.getElementById('patch-edit-form');
            
            form.innerHTML = `
                <form id="edit-patch-form">
                    <div class="form-group">
                        <label class="form-label">Patch Name <span style="color: #ef4444;">*</span></label>
                        <input type="text" name="patch_name" class="form-input" required value="${escapeHtml(patch.patch_name)}">
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Patch Type <span style="color: #ef4444;">*</span></label>
                        <select name="patch_type" class="form-select" required>
                            <option value="Software Update" ${patch.patch_type === 'Software Update' ? 'selected' : ''}>Software Update</option>
                            <option value="Firmware" ${patch.patch_type === 'Firmware' ? 'selected' : ''}>Firmware Update</option>
                            <option value="Configuration" ${patch.patch_type === 'Configuration' ? 'selected' : ''}>Configuration Change</option>
                            <option value="Security Patch" ${patch.patch_type === 'Security Patch' ? 'selected' : ''}>Security Patch</option>
                            <option value="Hotfix" ${patch.patch_type === 'Hotfix' ? 'selected' : ''}>Hotfix</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Description <span style="color: #ef4444;">*</span></label>
                        <textarea name="description" class="form-textarea" required>${escapeHtml(patch.description || '')}</textarea>
                    </div>
                    
                    <!-- CVE Management Section -->
                    <div class="form-group">
                        <label class="form-label">Associated CVEs</label>
                        <div id="cve-management-section">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                                <span style="color: var(--text-primary, #ffffff);">Current CVEs: <span id="current-cve-count">${patch.cve_list ? JSON.parse(patch.cve_list).length : 0}</span></span>
                                <button type="button" class="btn btn-secondary btn-sm" onclick="openCVEManager()">
                                    <i class="fas fa-edit"></i> Manage CVEs
                                </button>
                            </div>
                            <div id="current-cve-list" data-cve-list="${escapeHtml(patch.cve_list || '[]')}" style="background: var(--bg-secondary, #0f0f0f); border: 1px solid var(--border-primary, #333333); border-radius: 0.5rem; padding: 1rem; min-height: 100px;">
                                ${renderCurrentCVEs(patch.cve_list)}
                            </div>
                        </div>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                        <div class="form-group">
                            <label class="form-label">Target Version</label>
                            <input type="text" name="target_version" class="form-input" value="${escapeHtml(patch.target_version || '')}">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Release Date</label>
                            <input type="date" name="release_date" class="form-input" value="${patch.release_date || ''}">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Target Device Type</label>
                        <input type="text" name="target_device_type" class="form-input" value="${escapeHtml(patch.target_device_type || '')}">
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Vendor</label>
                        <input type="text" name="vendor" class="form-input" value="${escapeHtml(patch.vendor || '')}">
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">KB Article</label>
                        <input type="text" name="kb_article" class="form-input" value="${escapeHtml(patch.kb_article || '')}">
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Download URL</label>
                        <input type="url" name="download_url" class="form-input" value="${escapeHtml(patch.download_url || '')}">
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Install Instructions</label>
                        <textarea name="install_instructions" class="form-textarea">${escapeHtml(patch.install_instructions || '')}</textarea>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Prerequisites</label>
                        <textarea name="prerequisites" class="form-textarea">${escapeHtml(patch.prerequisites || '')}</textarea>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                        <div class="form-group">
                            <label class="form-label">Estimated Install Time (minutes)</label>
                            <input type="number" name="estimated_install_time" class="form-input" value="${patch.estimated_install_time || ''}">
                        </div>
                        
                        <div class="form-group">
                            <label style="display: flex; align-items: center; gap: 0.5rem; color: var(--text-primary, #ffffff);">
                                <input type="checkbox" name="requires_reboot" ${patch.requires_reboot ? 'checked' : ''}> Requires Reboot
                            </label>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label style="display: flex; align-items: center; gap: 0.5rem; color: var(--text-primary, #ffffff);">
                            <input type="checkbox" name="is_active" ${patch.is_active ? 'checked' : ''}> Active Patch
                        </label>
                    </div>
                    
                    <div style="display: flex; justify-content: space-between; gap: 0.75rem; margin-top: 2rem;">
                        <button type="button" class="btn btn-secondary" onclick="window.location.href='?action=list'">
                            Cancel
                        </button>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Update Patch
                        </button>
                    </div>
                </form>
            `;
            
            // Add form submission handler
            document.getElementById('edit-patch-form').addEventListener('submit', handleUpdatePatch);
        }
        
        // Handle patch update
        async function handleUpdatePatch(e) {
            e.preventDefault();
            
            const form = e.target;
            const formData = new FormData(form);
            
            const patchData = {
                patch_name: formData.get('patch_name'),
                patch_type: formData.get('patch_type'),
                description: formData.get('description'),
                target_version: formData.get('target_version'),
                target_device_type: formData.get('target_device_type'),
                vendor: formData.get('vendor'),
                kb_article: formData.get('kb_article'),
                download_url: formData.get('download_url'),
                install_instructions: formData.get('install_instructions'),
                prerequisites: formData.get('prerequisites'),
                estimated_install_time: formData.get('estimated_install_time') && !isNaN(parseInt(formData.get('estimated_install_time'))) ? parseInt(formData.get('estimated_install_time')) : null,
                requires_reboot: formData.get('requires_reboot') === 'on',
                is_active: formData.get('is_active') === 'on',
                release_date: formData.get('release_date')
            };
            
            try {
                const response = await fetch(`/api/v1/patches/index.php/${patchId}`, {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(patchData)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification('Patch updated successfully!', 'success');
                    window.location.href = '?action=list';
                } else {
                    showNotification('Error updating patch: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                showNotification('Error updating patch: ' + error.message, 'error');
            }
        }

        // CVE Management Functions
        function renderCurrentCVEs(cveListJson) {
            if (!cveListJson) {
                return '<div style="text-align: center; color: var(--text-muted, #94a3b8); padding: 2rem;">No CVEs associated with this patch</div>';
            }
            
            try {
                const cveList = JSON.parse(cveListJson);
                if (!cveList || cveList.length === 0) {
                    return '<div style="text-align: center; color: var(--text-muted, #94a3b8); padding: 2rem;">No CVEs associated with this patch</div>';
                }
                
                return cveList.map(cve => `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; border-bottom: 1px solid var(--border-primary, #333333);">
                        <span style="color: var(--text-primary, #ffffff); font-weight: 600;">${escapeHtml(cve)}</span>
                        <button type="button" onclick="removeCVEFromPatch('${escapeHtml(cve)}')" style="background: #ef4444; color: white; border: none; border-radius: 0.25rem; padding: 0.25rem 0.5rem; cursor: pointer;">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                `).join('');
            } catch (e) {
                return '<div style="text-align: center; color: #ef4444; padding: 2rem;">Error loading CVEs</div>';
            }
        }
        
        function openCVEManager() {
            // Initialize selected CVEs from current patch
            const currentCVEList = getCurrentPatchCVEs();
            selectedCVEs = [...currentCVEList];
            
            // Create modal for CVE management
            const modal = document.createElement('div');
            modal.style.cssText = `
                position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
                background: rgba(0,0,0,0.8); z-index: 1000; display: flex; 
                align-items: center; justify-content: center;
            `;
            
            modal.innerHTML = `
                <div style="background: var(--bg-card, #1a1a1a); border-radius: 0.75rem; padding: 2rem; max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                        <h3 style="color: var(--text-primary, #ffffff); margin: 0;">Manage Patch CVEs</h3>
                        <button onclick="this.closest('.modal').remove()" style="background: none; border: none; color: var(--text-muted, #94a3b8); font-size: 1.5rem; cursor: pointer;">&times;</button>
                    </div>
                    <div id="cve-manager-content">
                        <div style="text-align: center; padding: 2rem;">
                            <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                            <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading CVEs...</p>
                        </div>
                    </div>
                </div>
            `;
            modal.className = 'modal';
            document.body.appendChild(modal);
            
            // Load CVEs for management
            loadCVEsForManagement();
        }
        
        async function loadCVEsForManagement() {
            try {
                const response = await fetch('/api/v1/vulnerabilities/index.php?limit=1000', {
                    method: 'GET',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                const result = await response.json();
                
                if (result.success && result.data && Array.isArray(result.data)) {
                    renderCVEManager(result.data);
                } else {
                    const errorMsg = result.error || 'CVEs data is not available';
                    document.getElementById('cve-manager-content').innerHTML = `
                        <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                            Error loading CVEs: ${escapeHtml(errorMsg)}
                        </div>
                    `;
                }
            } catch (error) {
                console.error('Error loading CVEs for management:', error);
                const errorMessage = error?.message || error?.error?.message || error?.toString() || 'Unknown error occurred';
                document.getElementById('cve-manager-content').innerHTML = `
                    <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                        <i class="fas fa-exclamation-circle"></i> Error loading CVEs: ${escapeHtml(errorMessage)}
                        <br><br>
                        <small>Check browser console for details</small>
                    </div>
                `;
            }
        }
        
        function renderCVEManager(allCVEs) {
            document.getElementById('cve-manager-content').innerHTML = `
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
                    <div>
                        <h4 style="color: var(--text-primary, #ffffff); margin-bottom: 1rem;">Available CVEs</h4>
                        <div style="margin-bottom: 1rem;">
                            <input type="text" id="cve-search" placeholder="Search CVE ID..." style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.25rem;">
                        </div>
                        <div id="available-cves" style="max-height: 300px; overflow-y: auto; border: 1px solid var(--border-primary, #333333); border-radius: 0.5rem;">
                            ${renderAvailableCVEs(allCVEs || [], selectedCVEs || [])}
                        </div>
                    </div>
                    <div>
                        <h4 style="color: var(--text-primary, #ffffff); margin-bottom: 1rem;">Selected CVEs</h4>
                        <div id="selected-cves" style="max-height: 300px; overflow-y: auto; border: 1px solid var(--border-primary, #333333); border-radius: 0.5rem; background: var(--bg-secondary, #0f0f0f);">
                            ${renderSelectedCVEs(selectedCVEs)}
                        </div>
                    </div>
                </div>
                <div style="display: flex; justify-content: space-between; gap: 1rem;">
                    <button onclick="this.closest('.modal').remove()" class="btn btn-secondary">Cancel</button>
                    <button onclick="saveCVESelection()" class="btn btn-primary">Save Changes</button>
                </div>
            `;
            
            // Add search functionality
            document.getElementById('cve-search').addEventListener('input', function() {
                const searchTerm = this.value.toLowerCase();
                const cveItems = document.querySelectorAll('#available-cves .cve-item');
                cveItems.forEach(item => {
                    const cveId = item.dataset.cveId.toLowerCase();
                    item.style.display = cveId.includes(searchTerm) ? 'block' : 'none';
                });
            });
        }
        
        function renderAvailableCVEs(allCVEs, selectedCVEs) {
            // Ensure allCVEs is an array
            if (!allCVEs || !Array.isArray(allCVEs)) {
                console.error('Error loading CVEs for selection: allCVEs is undefined or not an array', allCVEs);
                return '<div style="text-align: center; padding: 2rem; color: var(--text-muted, #94a3b8);">No CVEs available. Please try again.</div>';
            }
            
            if (allCVEs.length === 0) {
                return '<div style="text-align: center; padding: 2rem; color: var(--text-muted, #94a3b8);">No CVEs found</div>';
            }
            
            return allCVEs.map(cve => {
                const isSelected = selectedCVEs.includes(cve.cve_id);
                return `
                    <div class="cve-item" data-cve-id="${escapeHtml(cve.cve_id)}" onclick="toggleCVESelection('${escapeHtml(cve.cve_id)}')" style="padding: 0.75rem; border-bottom: 1px solid var(--border-primary, #333333); cursor: pointer; ${isSelected ? 'background: var(--siemens-petrol, #009999);' : ''}">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div style="color: var(--text-primary, #ffffff); font-weight: 600;">${escapeHtml(cve.cve_id)}</div>
                                <div style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">${escapeHtml(cve.severity || 'Unknown')} - CVSS: ${cve.cvss_score || 'N/A'}</div>
                            </div>
                            <i class="fas ${isSelected ? 'fa-check-circle' : 'fa-plus-circle'}" style="color: ${isSelected ? 'white' : 'var(--text-muted, #94a3b8)'};"></i>
                        </div>
                    </div>
                `;
            }).join('');
        }
        
        function renderSelectedCVEs(selectedCVEs) {
            if (selectedCVEs.length === 0) {
                return '<div style="text-align: center; color: var(--text-muted, #94a3b8); padding: 2rem;">No CVEs selected</div>';
            }
            
            return selectedCVEs.map(cve => `
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem; border-bottom: 1px solid var(--border-primary, #333333);">
                    <span style="color: var(--text-primary, #ffffff);">${escapeHtml(cve)}</span>
                    <button onclick="removeCVESelection('${escapeHtml(cve)}')" style="background: #ef4444; color: white; border: none; border-radius: 0.25rem; padding: 0.25rem 0.5rem; cursor: pointer;">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `).join('');
        }
        
        function getCurrentPatchCVEs() {
            const cveListElement = document.getElementById('current-cve-list');
            if (!cveListElement) return [];
            
            const cveData = cveListElement.dataset.cveList;
            if (!cveData) return [];
            try {
                return JSON.parse(cveData);
            } catch (e) {
                return [];
            }
        }
        
        function toggleCVESelection(cveId) {
            const index = selectedCVEs.indexOf(cveId);
            if (index > -1) {
                // Remove from selection
                selectedCVEs.splice(index, 1);
            } else {
                // Add to selection
                selectedCVEs.push(cveId);
            }
            
            // Update the UI
            updateCVESelectionUI();
        }
        
        function removeCVESelection(cveId) {
            const index = selectedCVEs.indexOf(cveId);
            if (index > -1) {
                selectedCVEs.splice(index, 1);
                updateCVESelectionUI();
            }
        }
        
        function updateCVESelectionUI() {
            // Update available CVEs display
            const availableCves = document.getElementById('available-cves');
            if (availableCves) {
                const cveItems = availableCves.querySelectorAll('.cve-item');
                cveItems.forEach(item => {
                    const cveId = item.dataset.cveId;
                    const isSelected = selectedCVEs.includes(cveId);
                    
                    // Update visual state
                    item.style.background = isSelected ? 'var(--siemens-petrol, #009999)' : '';
                    const icon = item.querySelector('i');
                    if (icon) {
                        icon.className = isSelected ? 'fas fa-check-circle' : 'fas fa-plus-circle';
                        icon.style.color = isSelected ? 'white' : 'var(--text-muted, #94a3b8)';
                    }
                });
            }
            
            // Update selected CVEs display
            const selectedCves = document.getElementById('selected-cves');
            if (selectedCves) {
                selectedCves.innerHTML = renderSelectedCVEs(selectedCVEs);
            }
        }
        
        async function saveCVESelection() {
            const patchId = new URLSearchParams(window.location.search).get('patch_id');
            if (!patchId) {
                showNotification('Patch ID not found', 'error');
                return;
            }
            
            try {
                // Update the patch with new CVE list
                const response = await fetch(`/api/v1/patches/index.php/${patchId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        cve_list: selectedCVEs
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    // Update the current CVE list in the edit form
                    updateCurrentCVEList(selectedCVEs);
                    document.querySelector('.modal').remove();
                } else {
                    showNotification('Error saving CVE selection: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                showNotification('Error saving CVE selection: ' + error.message, 'error');
            }
        }
        
        function updateCurrentCVEList(cveList) {
            // Update the CVE count
            const countElement = document.getElementById('current-cve-count');
            if (countElement) {
                countElement.textContent = cveList.length;
            }
            
            // Update the CVE list display
            const cveListElement = document.getElementById('current-cve-list');
            if (cveListElement) {
                cveListElement.innerHTML = renderCurrentCVEs(JSON.stringify(cveList));
                cveListElement.dataset.cveList = JSON.stringify(cveList);
            }
        }
        
        async function removeCVEFromPatch(cveId) {
            showCVERemovalConfirmationModal(cveId);
        }

        function showCVERemovalConfirmationModal(cveId) {
            const modal = document.createElement('div');
            modal.className = 'modal';
            modal.id = 'cve-removal-confirmation-modal';
            modal.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10001;
            `;
            
            modal.innerHTML = `
                <div style="
                    background: var(--bg-card, #1a1a1a);
                    border: 1px solid var(--border-primary, #333333);
                    border-radius: 0.75rem;
                    max-width: 400px;
                    width: 90%;
                    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
                ">
                    <div style="
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 1.5rem;
                        border-bottom: 1px solid var(--border-primary, #333333);
                        background: var(--bg-secondary, #0f0f0f);
                    ">
                        <h2 style="margin: 0; color: var(--text-primary, #ffffff);">Remove CVE</h2>
                        <button onclick="document.getElementById('cve-removal-confirmation-modal').remove()" style="
                            background: transparent;
                            border: none;
                            color: var(--text-secondary, #cbd5e1);
                            font-size: 1.5rem;
                            cursor: pointer;
                            padding: 0.5rem;
                        ">×</button>
                    </div>
                    <div style="padding: 1.5rem;">
                        <div style="margin-bottom: 1.5rem;">
                            <div style="
                                display: flex;
                                align-items: center;
                                gap: 1rem;
                                margin-bottom: 1rem;
                            ">
                                <i class="fas fa-trash" style="
                                    font-size: 2rem;
                                    color: var(--error-red, #ef4444);
                                "></i>
                                <div>
                                    <h3 style="margin: 0; color: var(--text-primary, #ffffff);">Remove CVE</h3>
                                    <p style="margin: 0.5rem 0 0 0; color: var(--text-secondary, #cbd5e1);">
                                        Remove ${cveId} from this patch?
                                    </p>
                                </div>
                            </div>
                        </div>
                        <div style="display: flex; gap: 0.75rem; justify-content: flex-end;">
                            <button onclick="document.getElementById('cve-removal-confirmation-modal').remove()" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--bg-secondary, #0f0f0f);
                                color: var(--text-secondary, #cbd5e1);
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Cancel</button>
                            <button onclick="confirmRemoveCVE('${cveId}')" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--error-red, #ef4444);
                                color: white;
                                border: none;
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Remove CVE</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
        }

        async function confirmRemoveCVE(cveId) {
                const patchId = new URLSearchParams(window.location.search).get('patch_id');
                if (!patchId) {
                showNotification('Patch ID not found', 'error');
                    return;
                }
                
                try {
                    // Get current CVE list
                    const currentCVEs = getCurrentPatchCVEs();
                    const updatedCVEs = currentCVEs.filter(cve => cve !== cveId);
                    
                    // Update the patch with new CVE list
                    const response = await fetch(`/api/v1/patches/index.php/${patchId}`, {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            cve_list: updatedCVEs
                        })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        showNotification('CVE removed successfully', 'success');
                        // Close the CVE removal confirmation modal
                        const cveModal = document.getElementById('cve-removal-confirmation-modal');
                        if (cveModal) {
                            cveModal.remove();
                        }
                        // Update the current CVE list in the edit form
                        updateCurrentCVEList(updatedCVEs);
                    } else {
                        showNotification('Error removing CVE: ' + (result.error || 'Unknown error'), 'error');
                    }
                } catch (error) {
                    showNotification('Error removing CVE: ' + error.message, 'error');
                }
        }
        
        // History Management Functions
        function viewPatchHistory(patchId) {
            window.location.href = `?action=history&patch_id=${patchId}`;
        }
        
        // Schedule Management Functions
        function schedulePatch(patchId) {
            // Redirect to schedule page with patch ID
            window.location.href = `?action=schedule&patch_id=${patchId}`;
        }
        
        // Load patch scheduling interface
        function loadPatchScheduling() {
            const patchId = new URLSearchParams(window.location.search).get('patch_id');
            if (!patchId) {
                console.error('No patch ID provided');
                return;
            }
            
            // Get affected devices from server-side data
            const devices = <?php echo json_encode($affectedDevices); ?>;
            
            if (devices.length === 0) {
                console.log('No affected devices found for this patch');
                return;
            }
            
            // Check if assignOwnerModal is available
            if (typeof window.assignOwnerModal === 'undefined') {
                console.error('assignOwnerModal is not defined');
                showNotification('Task assignment modal is not loaded. Please refresh the page and try again.', 'error');
                return;
            }
            
            // Wait a bit for the modal to be fully initialized
            setTimeout(() => {
                if (typeof window.assignOwnerModal === 'undefined') {
                    console.error('assignOwnerModal still not defined after timeout');
                    showNotification('Task assignment modal is not loaded. Please refresh the page and try again.', 'error');
                    return;
                }
                
                // Add patch information to each device for display in the modal
                const patchInfo = {
                    patch_name: devices[0]?.patch_name || 'Unknown Patch',
                    patch_version: devices[0]?.patch_version || ''
                };
                
                // Enhance device data with patch information
                const enhancedDevices = devices.map(device => ({
                    ...device,
                    package_name: patchInfo.patch_version ? 
                        `${patchInfo.patch_name} v${patchInfo.patch_version}` : 
                        patchInfo.patch_name,
                    cve_id: device.cve_id || 'Unknown CVE'
                }));
                
                // Show assign owner modal for patch scheduling
                try {
                    console.log('About to show modal for patch:', patchId);
                    console.log('Enhanced devices:', enhancedDevices);
                    console.log('assignOwnerModal exists:', typeof window.assignOwnerModal);
                    
                    window.assignOwnerModal.showForPatch(patchId, enhancedDevices);
                    console.log('Modal showForPatch completed');
                    // Modal will handle the scheduling process
                } catch (error) {
                    console.error('Error opening scheduling modal:', error);
                    showNotification('Error opening scheduling modal: ' + error.message, 'error');
                }
            }, 100); // Wait 100ms for modal initialization
        }
        
        
        
        // Patch Deletion Functions
        function deletePatch(patchId) {
            showPatchDeletionConfirmationModal(patchId);
        }

        function showPatchDeletionConfirmationModal(patchId) {
            const modal = document.createElement('div');
            modal.className = 'modal';
            modal.id = 'patch-deletion-confirmation-modal';
            modal.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10001;
            `;
            
            modal.innerHTML = `
                <div style="
                    background: var(--bg-card, #1a1a1a);
                    border: 1px solid var(--border-primary, #333333);
                    border-radius: 0.75rem;
                    max-width: 500px;
                    width: 90%;
                    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
                ">
                    <div style="
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 1.5rem;
                        border-bottom: 1px solid var(--border-primary, #333333);
                        background: var(--bg-secondary, #0f0f0f);
                    ">
                        <h2 style="margin: 0; color: var(--text-primary, #ffffff);">Delete Patch</h2>
                        <button onclick="document.getElementById('patch-deletion-confirmation-modal').remove()" style="
                            background: transparent;
                            border: none;
                            color: var(--text-secondary, #cbd5e1);
                            font-size: 1.5rem;
                            cursor: pointer;
                            padding: 0.5rem;
                        ">×</button>
                    </div>
                    <div style="padding: 1.5rem;">
                        <div style="margin-bottom: 1.5rem;">
                            <div style="
                                display: flex;
                                align-items: center;
                                gap: 1rem;
                                margin-bottom: 1rem;
                            ">
                                <i class="fas fa-exclamation-triangle" style="
                                    font-size: 2rem;
                                    color: var(--error-red, #ef4444);
                                "></i>
                                <div>
                                    <h3 style="margin: 0; color: var(--text-primary, #ffffff);">Confirm Patch Deletion</h3>
                                    <p style="margin: 0.5rem 0 0 0; color: var(--text-secondary, #cbd5e1);">
                                        Are you sure you want to delete this patch? This action cannot be undone.
                                    </p>
                                    <p style="margin: 0.5rem 0 0 0; color: var(--text-muted, #94a3b8); font-size: 0.875rem;">
                                        This will also delete all associated patch history.
                                    </p>
                                </div>
                            </div>
                        </div>
                        <div style="display: flex; gap: 0.75rem; justify-content: flex-end;">
                            <button onclick="document.getElementById('patch-deletion-confirmation-modal').remove()" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--bg-secondary, #0f0f0f);
                                color: var(--text-secondary, #cbd5e1);
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Cancel</button>
                            <button onclick="confirmDeletePatch('${patchId}')" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--error-red, #ef4444);
                                color: white;
                                border: none;
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Delete Patch</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
        }

        async function confirmDeletePatch(patchId) {
            // Close the deletion confirmation modal
            const deletionModal = document.getElementById('patch-deletion-confirmation-modal');
            if (deletionModal) {
                deletionModal.remove();
            }
            // Perform the actual deletion
            await performPatchDeletion(patchId);
        }
        
        async function performPatchDeletion(patchId) {
            try {
                const response = await fetch(`/api/v1/patches/index.php/${patchId}`, {
                    method: 'DELETE',
                    headers: {'Content-Type': 'application/json'}
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification('Patch deleted successfully!', 'success');
                    window.location.href = '?action=list';
                } else {
                    showNotification('Error deleting patch: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                showNotification('Error deleting patch: ' + error.message, 'error');
            }
        }

        // Utility functions
        function applyPatch(pid) {
            window.location.href = `?action=apply&patch_id=${pid}`;
        }
        
        function editPatch(pid) {
            window.location.href = `?action=edit&patch_id=${pid}`;
        }

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

