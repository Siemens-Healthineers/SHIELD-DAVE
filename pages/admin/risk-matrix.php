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
if (!$user || $user['role'] !== 'Admin') {
    header('Location: /pages/dashboard.php');
    exit;
}

// Get database connection
$db = DatabaseConfig::getInstance();

// Ensure we're not in a transaction and can see all committed data
// This is critical for seeing the latest saved configuration
try {
    // If we're in a transaction, rollback to ensure fresh read
    if ($db->inTransaction()) {
        $db->rollback();
        error_log("Risk Matrix Page: Rolled back open transaction to ensure fresh read");
    }
} catch (Exception $e) {
    // Ignore - connection might not support inTransaction check
    error_log("Risk Matrix Page: Could not check transaction status: " . $e->getMessage());
}

// Get current configuration - ensure fresh query with explicit READ COMMITTED
$sql = "SELECT * FROM risk_matrix_config WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1";
$stmt = $db->prepare($sql);
$stmt->execute();
$currentConfig = $stmt->fetch();

// Log what we're reading for debugging
if ($currentConfig) {
    error_log("Risk Matrix Page: Loaded config - ID: " . $currentConfig['config_id'] . ", kev_weight: " . $currentConfig['kev_weight'] . ", created_at: " . $currentConfig['created_at']);
} else {
    error_log("Risk Matrix Page: WARNING - No active configuration found!");
}


// Get sample vulnerabilities for preview
$sql = "SELECT 
    v.cve_id,
    v.severity,
    v.is_kev,
    a.criticality as asset_criticality,
    l.criticality as location_criticality,
    dvl.risk_score as current_risk_score,
    dvl.priority_tier as current_priority_tier
FROM device_vulnerabilities_link dvl
JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
JOIN medical_devices md ON dvl.device_id = md.device_id
JOIN assets a ON md.asset_id = a.asset_id
LEFT JOIN locations l ON a.location_id = l.location_id
ORDER BY dvl.risk_score DESC
LIMIT 20";
$sampleVulnerabilities = $db->query($sql)->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Risk Matrix Configuration - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

    <!-- Main Content -->
    <main class="main-content">
        <div class="container" style="max-width: 1400px; margin: 0 auto; padding: 2rem;">
            
            <!-- Page Header -->
            <div style="margin-bottom: 2rem;">
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <div>
                        <h1 style="font-size: 1.875rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">
                            <i class="fas fa-sliders-h"></i> Risk Matrix Configuration
                        </h1>
                        <p style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">
                            Configure how risk scores are calculated based on asset criticality, location, and vulnerability severity
                        </p>
                    </div>
                    <a href="/pages/admin/index.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i> Back to Admin
                    </a>
                </div>
            </div>

            <!-- Alert Messages -->
            <div id="alertContainer"></div>

            <!-- Two Column Layout -->
            <div style="display: grid; grid-template-columns: 1fr 400px; gap: 1.5rem; align-items: start;">
                
                <!-- Left Column - Configuration Form -->
                <div style="display: flex; flex-direction: column; gap: 1.5rem;">
                    
                    <!-- Current Configuration Info -->
                    <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem;">
                        <h3 style="font-size: 1.125rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1rem;">
                            <i class="fas fa-info-circle"></i> Current Configuration
                        </h3>
                        <?php if ($currentConfig): ?>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem;">
                            <div>
                                <span style="color: var(--text-muted, #94a3b8); font-size: 0.75rem;">Last Updated</span>
                                <p style="color: var(--text-primary, #ffffff); font-weight: 500; margin-top: 0.25rem;">
                                    <?php echo date('M d, Y H:i', strtotime($currentConfig['updated_at'])); ?>
                                </p>
                            </div>
                        </div>
                        <?php else: ?>
                        <p style="color: var(--text-muted, #94a3b8);">No configuration found. Create your first configuration below.</p>
                        <?php endif; ?>
                    </div>

                    <!-- KEV Weight Configuration -->
                    <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem;">
                        <h3 style="font-size: 1.125rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1rem;">
                            <i class="fas fa-exclamation-circle" style="color: #ef4444;"></i> KEV (Known Exploited Vulnerability) Weight
                        </h3>
                        <p style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; margin-bottom: 1rem;">
                            KEV vulnerabilities are actively exploited in the wild and should be prioritized immediately.
                        </p>
                        <div style="display: flex; gap: 1rem; align-items: end;">
                            <div style="flex: 1;">
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    Points Added for KEV Status
                                </label>
                                <input type="number" id="kev_weight" value="<?php echo $currentConfig['kev_weight'] ?? 1000; ?>" min="0" max="10000" step="100"
                                       style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;"
                                       onchange="updatePreview()">
                            </div>
                            <div style="background: var(--bg-secondary, #0f0f0f); padding: 1rem; border-radius: 0.375rem; min-width: 120px; text-align: center;">
                                <span style="color: var(--text-muted, #94a3b8); font-size: 0.75rem;">Current Value</span>
                                <p style="color: var(--siemens-orange, #ff6b35); font-size: 1.5rem; font-weight: 700; margin-top: 0.25rem;">
                                    +<span id="kev_display"><?php echo $currentConfig['kev_weight'] ?? 1000; ?></span>
                                </p>
                            </div>
                        </div>
                    </div>

                    <!-- Asset Criticality Scores -->
                    <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem;">
                        <h3 style="font-size: 1.125rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1rem;">
                            <i class="fas fa-hospital"></i> Asset Criticality Scores
                        </h3>
                        <p style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; margin-bottom: 1rem;">
                            Points added based on the asset's criticality level to patient care and operations.
                        </p>
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem;">
                            <div>
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    <span style="display: inline-block; padding: 0.25rem 0.5rem; background: #ef4444; color: white; border-radius: 0.25rem; font-size: 0.75rem; margin-bottom: 0.25rem;">Clinical-High</span>
                                    <br>Points
                                </label>
                                <input type="number" id="clinical_high_score" value="<?php echo $currentConfig['clinical_high_score'] ?? 100; ?>" min="0" max="1000" step="10"
                                       style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;"
                                       onchange="updatePreview()">
                            </div>
                            <div>
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    <span style="display: inline-block; padding: 0.25rem 0.5rem; background: #f59e0b; color: white; border-radius: 0.25rem; font-size: 0.75rem; margin-bottom: 0.25rem;">Business-Medium</span>
                                    <br>Points
                                </label>
                                <input type="number" id="business_medium_score" value="<?php echo $currentConfig['business_medium_score'] ?? 50; ?>" min="0" max="1000" step="10"
                                       style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;"
                                       onchange="updatePreview()">
                            </div>
                            <div>
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    <span style="display: inline-block; padding: 0.25rem 0.5rem; background: #10b981; color: white; border-radius: 0.25rem; font-size: 0.75rem; margin-bottom: 0.25rem;">Non-Essential</span>
                                    <br>Points
                                </label>
                                <input type="number" id="non_essential_score" value="<?php echo $currentConfig['non_essential_score'] ?? 10; ?>" min="0" max="1000" step="5"
                                       style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;"
                                       onchange="updatePreview()">
                            </div>
                        </div>
                    </div>

                    <!-- Location Criticality Multiplier -->
                    <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem;">
                        <h3 style="font-size: 1.125rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1rem;">
                            <i class="fas fa-map-marker-alt"></i> Location Criticality Multiplier
                        </h3>
                        <p style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; margin-bottom: 1rem;">
                            Location criticality (1-10) is multiplied by this value. Higher values increase location impact on risk score.
                        </p>
                        <div style="display: flex; gap: 1rem; align-items: end;">
                            <div style="flex: 1;">
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    Multiplier Value
                                </label>
                                <input type="number" id="location_weight_multiplier" value="<?php echo $currentConfig['location_weight_multiplier'] ?? 5; ?>" min="0" max="20" step="0.5"
                                       style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;"
                                       onchange="updatePreview()">
                            </div>
                            <div style="background: var(--bg-secondary, #0f0f0f); padding: 1rem; border-radius: 0.375rem; flex: 1;">
                                <span style="color: var(--text-muted, #94a3b8); font-size: 0.75rem;">Example: Location 10</span>
                                <p style="color: var(--siemens-petrol, #009999); font-size: 1.25rem; font-weight: 700; margin-top: 0.25rem;">
                                    = <span id="location_example">50</span> points
                                </p>
                            </div>
                        </div>
                    </div>

                    <!-- Vulnerability Severity Scores -->
                    <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem;">
                        <h3 style="font-size: 1.125rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1rem;">
                            <i class="fas fa-bug"></i> Vulnerability Severity Scores
                        </h3>
                        <p style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; margin-bottom: 1rem;">
                            Points added based on the CVSS severity rating of the vulnerability.
                        </p>
                        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem;">
                            <div>
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    <span style="display: inline-block; padding: 0.25rem 0.5rem; background: #dc2626; color: white; border-radius: 0.25rem; font-size: 0.75rem; margin-bottom: 0.25rem;">Critical</span>
                                    <br>Points
                                </label>
                                <input type="number" id="critical_severity_score" value="<?php echo $currentConfig['critical_severity_score'] ?? 40; ?>" min="0" max="100" step="5"
                                       style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;"
                                       onchange="updatePreview()">
                            </div>
                            <div>
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    <span style="display: inline-block; padding: 0.25rem 0.5rem; background: #ea580c; color: white; border-radius: 0.25rem; font-size: 0.75rem; margin-bottom: 0.25rem;">High</span>
                                    <br>Points
                                </label>
                                <input type="number" id="high_severity_score" value="<?php echo $currentConfig['high_severity_score'] ?? 28; ?>" min="0" max="100" step="2"
                                       style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;"
                                       onchange="updatePreview()">
                            </div>
                            <div>
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    <span style="display: inline-block; padding: 0.25rem 0.5rem; background: #f59e0b; color: white; border-radius: 0.25rem; font-size: 0.75rem; margin-bottom: 0.25rem;">Medium</span>
                                    <br>Points
                                </label>
                                <input type="number" id="medium_severity_score" value="<?php echo $currentConfig['medium_severity_score'] ?? 16; ?>" min="0" max="100" step="2"
                                       style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;"
                                       onchange="updatePreview()">
                            </div>
                            <div>
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    <span style="display: inline-block; padding: 0.25rem 0.5rem; background: #10b981; color: white; border-radius: 0.25rem; font-size: 0.75rem; margin-bottom: 0.25rem;">Low</span>
                                    <br>Points
                                </label>
                                <input type="number" id="low_severity_score" value="<?php echo $currentConfig['low_severity_score'] ?? 4; ?>" min="0" max="100" step="1"
                                       style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;"
                                       onchange="updatePreview()">
                            </div>
                        </div>
                    </div>

                    <!-- EPSS Configuration -->
                    <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem;">
                        <h3 style="font-size: 1.125rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1rem;">
                            <i class="fas fa-chart-line" style="color: var(--siemens-petrol, #009999);"></i> EPSS (Exploit Prediction Scoring System) Configuration
                        </h3>
                        <p style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; margin-bottom: 1rem;">
                            EPSS provides probability scores (0-1) for vulnerability exploitation likelihood. Configure how EPSS influences risk scoring.
                        </p>
                        
                        <!-- EPSS Enable/Disable -->
                        <div style="margin-bottom: 1.5rem;">
                            <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                                <input type="checkbox" id="epss_weight_enabled" <?php echo ($currentConfig['epss_weight_enabled'] ?? true) ? 'checked' : ''; ?> 
                                       style="width: 1rem; height: 1rem; accent-color: var(--siemens-petrol, #009999);"
                                       onchange="updatePreview()">
                                <span style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem; font-weight: 500;">
                                    Enable EPSS in risk score calculation
                                </span>
                            </label>
                            <small style="color: var(--text-muted, #94a3b8); font-size: 0.75rem; display: block; margin-top: 0.25rem; margin-left: 1.5rem;">
                                When enabled, vulnerabilities with high EPSS scores will receive additional risk points
                            </small>
                        </div>

                        <!-- EPSS Configuration Fields -->
                        <div id="epss-config-fields" style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem;">
                            <div>
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    High EPSS Threshold
                                </label>
                                <input type="number" id="epss_high_threshold" value="<?php echo $currentConfig['epss_high_threshold'] ?? 0.7; ?>" min="0" max="1" step="0.05"
                                       style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;"
                                       onchange="updatePreview()">
                                <small style="color: var(--text-muted, #94a3b8); font-size: 0.75rem; display: block; margin-top: 0.25rem;">
                                    EPSS scores ≥ this value are considered high risk (0.0-1.0)
                                </small>
                            </div>
                            <div>
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    EPSS Weight Points
                                </label>
                                <input type="number" id="epss_weight_score" value="<?php echo $currentConfig['epss_weight_score'] ?? 20; ?>" min="0" max="100" step="5"
                                       style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;"
                                       onchange="updatePreview()">
                                <small style="color: var(--text-muted, #94a3b8); font-size: 0.75rem; display: block; margin-top: 0.25rem;">
                                    Points added for high EPSS vulnerabilities
                                </small>
                            </div>
                        </div>

                        <!-- EPSS Example -->
                        <div style="background: var(--bg-secondary, #0f0f0f); padding: 1rem; border-radius: 0.375rem; margin-top: 1rem;">
                            <span style="color: var(--text-muted, #94a3b8); font-size: 0.75rem;">EPSS Example:</span>
                            <p style="color: var(--siemens-petrol, #009999); font-size: 0.875rem; margin-top: 0.25rem;">
                                Vulnerability with EPSS score <span id="epss_example_score">0.75</span> 
                                → <span id="epss_example_result">+20</span> points (if ≥ <span id="epss_example_threshold">0.70</span>)
                            </p>
                        </div>
                    </div>

                    <!-- Configuration Name -->
                    <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem;">
                        <h3 style="font-size: 1.125rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1rem;">
                            <i class="fas fa-tag"></i> Configuration Details
                        </h3>
                        <div>
                        </div>
                    </div>

                    <!-- Action Buttons -->
                    <div style="display: flex; gap: 1rem; justify-content: flex-end;">
                        <button type="button" class="btn btn-secondary" onclick="resetToDefaults()">
                            <i class="fas fa-undo"></i> Reset to Current
                        </button>
                        <button type="button" class="btn btn-primary" id="saveRiskMatrixBtn" onclick="saveConfiguration()">
                            <i class="fas fa-save"></i> Save Configuration
                        </button>
                    </div>

                </div>

                <!-- Right Column - Preview & History -->
                <div style="display: flex; flex-direction: column; gap: 1.5rem; position: sticky; top: 20px;">
                    
                    <!-- Impact Preview -->
                    <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem;">
                        <h3 style="font-size: 1rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1rem;">
                            <i class="fas fa-eye"></i> Impact Preview
                        </h3>
                        <div id="impactPreview" style="font-size: 0.875rem;">
                            <p style="color: var(--text-muted, #94a3b8);">Adjust values to see impact preview</p>
                        </div>
                    </div>

                    <!-- Example Calculation -->
                    <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--siemens-petrol, #009999); border-radius: 0.75rem; padding: 1.5rem;">
                        <h3 style="font-size: 1rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1rem;">
                            <i class="fas fa-calculator"></i> Example Calculation
                        </h3>
                        <div style="font-size: 0.875rem; color: var(--text-secondary, #cbd5e1); line-height: 1.8;">
                            <div style="margin-bottom: 0.5rem;">
                                <strong style="color: var(--text-primary, #ffffff);">Scenario:</strong> Critical KEV on Clinical-High asset in high-criticality location
                            </div>
                            <div style="padding: 0.75rem; background: var(--bg-secondary, #0f0f0f); border-radius: 0.375rem; margin-top: 1rem;">
                                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                                    <span>KEV Status:</span>
                                    <span style="color: var(--siemens-orange, #ff6b35); font-weight: 600;">+<span id="preview_kev">1000</span></span>
                                </div>
                                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                                    <span>Asset (Clinical-High):</span>
                                    <span style="color: var(--siemens-orange, #ff6b35); font-weight: 600;">+<span id="preview_clinical">100</span></span>
                                </div>
                                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                                    <span>Location (9/10):</span>
                                    <span style="color: var(--siemens-orange, #ff6b35); font-weight: 600;">+<span id="preview_location">45</span></span>
                                </div>
                                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                                    <span>Severity (Critical):</span>
                                    <span style="color: var(--siemens-orange, #ff6b35); font-weight: 600;">+<span id="preview_severity">40</span></span>
                                </div>
                                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border-primary, #333333);">
                                    <span>EPSS Score (≥70%):</span>
                                    <span style="color: var(--siemens-orange, #ff6b35); font-weight: 600;">+<span id="preview_epss">20</span></span>
                                </div>
                                <div style="display: flex; justify-content: space-between; font-size: 1rem; margin-top: 0.5rem;">
                                    <strong style="color: var(--text-primary, #ffffff);">Total Risk Score:</strong>
                                    <strong style="color: var(--siemens-petrol, #009999); font-size: 1.25rem;"><span id="preview_total">1185</span></strong>
                                </div>
                            </div>
                        </div>
                    </div>


                </div>
            </div>

        </div>
    </main>

    <script>
        // Sample vulnerabilities data for preview
        const sampleVulnerabilities = <?php echo json_encode($sampleVulnerabilities); ?>;

        // Update preview calculations
        function updatePreview() {
            const kevWeight = parseInt(document.getElementById('kev_weight').value) || 0;
            const clinicalHigh = parseInt(document.getElementById('clinical_high_score').value) || 0;
            const businessMedium = parseInt(document.getElementById('business_medium_score').value) || 0;
            const nonEssential = parseInt(document.getElementById('non_essential_score').value) || 0;
            const locationMultiplier = parseFloat(document.getElementById('location_weight_multiplier').value) || 0;
            const criticalSeverity = parseInt(document.getElementById('critical_severity_score').value) || 0;
            const highSeverity = parseInt(document.getElementById('high_severity_score').value) || 0;
            const mediumSeverity = parseInt(document.getElementById('medium_severity_score').value) || 0;
            const lowSeverity = parseInt(document.getElementById('low_severity_score').value) || 0;
            
            // EPSS configuration
            const epssEnabled = document.getElementById('epss_weight_enabled').checked;
            const epssThreshold = parseFloat(document.getElementById('epss_high_threshold').value) || 0.7;
            const epssWeight = parseInt(document.getElementById('epss_weight_score').value) || 20;

            // Update display values
            document.getElementById('kev_display').textContent = kevWeight;
            document.getElementById('location_example').textContent = Math.round(10 * locationMultiplier);
            
            // Update EPSS example
            document.getElementById('epss_example_score').textContent = '0.75';
            document.getElementById('epss_example_threshold').textContent = epssThreshold.toFixed(2);
            document.getElementById('epss_example_result').textContent = epssEnabled ? '+' + epssWeight : '+0';

            // Update example calculation
            document.getElementById('preview_kev').textContent = kevWeight;
            document.getElementById('preview_clinical').textContent = clinicalHigh;
            document.getElementById('preview_location').textContent = Math.round(9 * locationMultiplier);
            document.getElementById('preview_severity').textContent = criticalSeverity;
            
            // Add EPSS to preview (assuming high EPSS score for example)
            const epssExample = epssEnabled ? epssWeight : 0;
            document.getElementById('preview_epss').textContent = epssExample;
            const totalExample = kevWeight + clinicalHigh + Math.round(9 * locationMultiplier) + criticalSeverity + epssExample;
            document.getElementById('preview_total').textContent = totalExample;

            // Calculate impact on sample vulnerabilities
            if (sampleVulnerabilities.length > 0) {
                let changedCount = 0;
                let avgChange = 0;

                sampleVulnerabilities.forEach(vuln => {
                    const oldScore = vuln.current_risk_score;
                    
                    let newScore = 0;
                    
                    // KEV
                    if (vuln.is_kev) {
                        newScore += kevWeight;
                    }
                    
                    // Asset criticality
                    if (vuln.asset_criticality === 'Clinical-High') {
                        newScore += clinicalHigh;
                    } else if (vuln.asset_criticality === 'Business-Medium') {
                        newScore += businessMedium;
                    } else if (vuln.asset_criticality === 'Non-Essential') {
                        newScore += nonEssential;
                    }
                    
                    // Location
                    if (vuln.location_criticality) {
                        newScore += Math.round(vuln.location_criticality * locationMultiplier);
                    }
                    
                    // Severity
                    if (vuln.severity === 'Critical') {
                        newScore += criticalSeverity;
                    } else if (vuln.severity === 'High') {
                        newScore += highSeverity;
                    } else if (vuln.severity === 'Medium') {
                        newScore += mediumSeverity;
                    } else if (vuln.severity === 'Low') {
                        newScore += lowSeverity;
                    }
                    
                    // EPSS (assuming high EPSS for demonstration - in real implementation, this would check actual EPSS score)
                    if (epssEnabled && vuln.severity === 'Critical') {
                        // For demo purposes, assume critical vulnerabilities have high EPSS
                        newScore += epssWeight;
                    }
                    
                    if (newScore !== oldScore) {
                        changedCount++;
                        avgChange += (newScore - oldScore);
                    }
                });

                if (changedCount > 0) {
                    avgChange = Math.round(avgChange / changedCount);
                    const direction = avgChange > 0 ? 'increase' : 'decrease';
                    const color = avgChange > 0 ? '#ef4444' : '#10b981';
                    
                    document.getElementById('impactPreview').innerHTML = `
                        <div style="padding: 1rem; background: var(--bg-secondary, #0f0f0f); border-radius: 0.375rem; margin-bottom: 1rem;">
                            <div style="font-size: 0.75rem; color: var(--text-muted, #94a3b8); margin-bottom: 0.5rem;">Estimated Impact on Top 20 Vulnerabilities:</div>
                            <div style="font-size: 1.5rem; font-weight: 700; color: ${color}; margin-bottom: 0.5rem;">
                                ${avgChange > 0 ? '+' : ''}${avgChange}
                            </div>
                            <div style="font-size: 0.875rem; color: var(--text-secondary, #cbd5e1);">
                                Average ${direction} per vulnerability
                            </div>
                        </div>
                        <div style="font-size: 0.75rem; color: var(--text-muted, #94a3b8);">
                            ${changedCount} of ${sampleVulnerabilities.length} vulnerabilities would have different scores
                        </div>
                    `;
                } else {
                    document.getElementById('impactPreview').innerHTML = `
                        <p style="color: var(--text-secondary, #cbd5e1);">No changes detected in sample vulnerabilities</p>
                    `;
                }
            }
        }

        // Reset to current configuration
        function resetToDefaults() {
            <?php if ($currentConfig): ?>
            document.getElementById('kev_weight').value = <?php echo $currentConfig['kev_weight']; ?>;
            document.getElementById('clinical_high_score').value = <?php echo $currentConfig['clinical_high_score']; ?>;
            document.getElementById('business_medium_score').value = <?php echo $currentConfig['business_medium_score']; ?>;
            document.getElementById('non_essential_score').value = <?php echo $currentConfig['non_essential_score']; ?>;
            document.getElementById('location_weight_multiplier').value = <?php echo $currentConfig['location_weight_multiplier']; ?>;
            document.getElementById('critical_severity_score').value = <?php echo $currentConfig['critical_severity_score']; ?>;
            document.getElementById('high_severity_score').value = <?php echo $currentConfig['high_severity_score']; ?>;
            document.getElementById('medium_severity_score').value = <?php echo $currentConfig['medium_severity_score']; ?>;
            document.getElementById('low_severity_score').value = <?php echo $currentConfig['low_severity_score']; ?>;
            document.getElementById('epss_weight_enabled').checked = <?php echo ($currentConfig['epss_weight_enabled'] ?? true) ? 'true' : 'false'; ?>;
            document.getElementById('epss_high_threshold').value = <?php echo $currentConfig['epss_high_threshold'] ?? 0.7; ?>;
            document.getElementById('epss_weight_score').value = <?php echo $currentConfig['epss_weight_score'] ?? 20; ?>;
            updatePreview();
            <?php endif; ?>
        }

        // Save configuration
        async function saveConfiguration() {
            try {
                console.log('[Risk Matrix] Save configuration called');
                
                // Prevent double-clicks
                const saveButton = document.querySelector('button[onclick="saveConfiguration()"]');
                if (saveButton && saveButton.disabled) {
                    console.log('[Risk Matrix] Save button already disabled, returning');
                    return;
                }
                if (saveButton) {
                    saveButton.disabled = true;
                    saveButton.textContent = 'Saving...';
                    console.log('[Risk Matrix] Save button disabled');
                }
                
                // Get all input values
                const kevWeightEl = document.getElementById('kev_weight');
                const clinicalHighEl = document.getElementById('clinical_high_score');
                const businessMediumEl = document.getElementById('business_medium_score');
                const nonEssentialEl = document.getElementById('non_essential_score');
                const locationMultiplierEl = document.getElementById('location_weight_multiplier');
                const criticalSeverityEl = document.getElementById('critical_severity_score');
                const highSeverityEl = document.getElementById('high_severity_score');
                const mediumSeverityEl = document.getElementById('medium_severity_score');
                const lowSeverityEl = document.getElementById('low_severity_score');
                const epssEnabledEl = document.getElementById('epss_weight_enabled');
                const epssThresholdEl = document.getElementById('epss_high_threshold');
                const epssWeightEl = document.getElementById('epss_weight_score');
                
                // Validate elements exist
                const requiredElements = [
                    {name: 'kev_weight', el: kevWeightEl},
                    {name: 'clinical_high_score', el: clinicalHighEl},
                    {name: 'business_medium_score', el: businessMediumEl},
                    {name: 'non_essential_score', el: nonEssentialEl},
                    {name: 'location_weight_multiplier', el: locationMultiplierEl},
                    {name: 'critical_severity_score', el: criticalSeverityEl},
                    {name: 'high_severity_score', el: highSeverityEl},
                    {name: 'medium_severity_score', el: mediumSeverityEl},
                    {name: 'low_severity_score', el: lowSeverityEl},
                    {name: 'epss_weight_enabled', el: epssEnabledEl},
                    {name: 'epss_high_threshold', el: epssThresholdEl},
                    {name: 'epss_weight_score', el: epssWeightEl}
                ];
                
                const missing = requiredElements.filter(item => !item.el);
                if (missing.length > 0) {
                    throw new Error('Missing required form elements: ' + missing.map(m => m.name).join(', '));
                }

                const config = {
                    kev_weight: parseInt(kevWeightEl.value) || 0,
                    clinical_high_score: parseInt(clinicalHighEl.value) || 0,
                    business_medium_score: parseInt(businessMediumEl.value) || 0,
                    non_essential_score: parseInt(nonEssentialEl.value) || 0,
                    location_weight_multiplier: parseFloat(locationMultiplierEl.value) || 0,
                    critical_severity_score: parseInt(criticalSeverityEl.value) || 0,
                    high_severity_score: parseInt(highSeverityEl.value) || 0,
                    medium_severity_score: parseInt(mediumSeverityEl.value) || 0,
                    low_severity_score: parseInt(lowSeverityEl.value) || 0,
                    epss_weight_enabled: epssEnabledEl.checked,
                    epss_high_threshold: parseFloat(epssThresholdEl.value) || 0.7,
                    epss_weight_score: parseInt(epssWeightEl.value) || 0
                };

                console.log('[Risk Matrix] Sending config:', JSON.stringify(config, null, 2));
                
                const response = await fetch('/api/v1/admin/risk-matrix/index.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    credentials: 'include',
                    body: JSON.stringify(config)
                });

                console.log('[Risk Matrix] Response status:', response.status);
                console.log('[Risk Matrix] Response headers:', [...response.headers.entries()]);
                
                // Check if response is OK before parsing JSON
                if (!response.ok) {
                    const errorText = await response.text();
                    console.error('[Risk Matrix] HTTP Error Response:', errorText);
                    throw new Error(`HTTP ${response.status}: ${errorText}`);
                }
                
                const result = await response.json();
                console.log('[Risk Matrix] Response result:', JSON.stringify(result, null, 2));

                if (result.success) {
                    showAlert('Risk matrix configuration saved successfully! All risk scores have been recalculated.', 'success');
                    setTimeout(() => {
                        // Force reload without cache
                        window.location.href = window.location.pathname + '?t=' + Date.now();
                    }, 1500);
                } else {
                    const errorMsg = result.error || 'Failed to save configuration';
                    console.error('[Risk Matrix] API Error:', errorMsg);
                    showAlert('Error: ' + errorMsg, 'error');
                    if (saveButton) {
                        saveButton.disabled = false;
                        saveButton.innerHTML = '<i class="fas fa-save"></i> Save Configuration';
                    }
                }
            } catch (error) {
                console.error('[Risk Matrix] Exception in saveConfiguration:', error);
                console.error('[Risk Matrix] Stack trace:', error.stack);
                showAlert('Error saving configuration: ' + error.message, 'error');
                const saveButton = document.querySelector('button[onclick="saveConfiguration()"]');
                if (saveButton) {
                    saveButton.disabled = false;
                    saveButton.innerHTML = '<i class="fas fa-save"></i> Save Configuration';
                }
            }
        }

        // Show alert
        function showAlert(message, type) {
            const alertContainer = document.getElementById('alertContainer');
            const alert = document.createElement('div');
            alert.style.cssText = `
                padding: 1rem 1.5rem;
                background: ${type === 'success' ? '#10b981' : '#ef4444'};
                color: white;
                border-radius: 0.5rem;
                margin-bottom: 1rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            `;
            alert.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
                <span>${message}</span>
            `;
            alertContainer.appendChild(alert);

            setTimeout(() => {
                alert.remove();
            }, 5000);
        }

        // Initialize preview on page load
        updatePreview();

        // Update preview when inputs change
        document.querySelectorAll('input[type="number"]').forEach(input => {
            input.addEventListener('input', updatePreview);
        });

        // EPSS checkbox event listener
        const epssCheckbox = document.getElementById('epss_weight_enabled');
        if (epssCheckbox) {
            epssCheckbox.addEventListener('change', function() {
                const epssFields = document.getElementById('epss-config-fields');
                if (epssFields) {
                    if (this.checked) {
                        epssFields.style.display = 'grid';
                    } else {
                        epssFields.style.display = 'none';
                    }
                }
                updatePreview();
            });
        }

        // Initialize EPSS fields visibility on page load
        window.addEventListener('DOMContentLoaded', function() {
            console.log('[Risk Matrix] DOMContentLoaded fired');
            const epssEnabled = document.getElementById('epss_weight_enabled');
            const epssFields = document.getElementById('epss-config-fields');
            if (epssEnabled && epssFields) {
                epssFields.style.display = epssEnabled.checked ? 'grid' : 'none';
            }
            
            // Verify save button exists
            const saveBtn = document.querySelector('button[onclick="saveConfiguration()"]');
            if (saveBtn) {
                console.log('[Risk Matrix] Save button found:', saveBtn);
            } else {
                console.error('[Risk Matrix] Save button NOT found!');
            }
        });
        
        // Also run initialization if DOM is already loaded
        if (document.readyState === 'loading') {
            // DOM is still loading, wait for DOMContentLoaded
        } else {
            // DOM is already loaded
            console.log('[Risk Matrix] DOM already loaded, initializing immediately');
            const epssEnabled = document.getElementById('epss_weight_enabled');
            const epssFields = document.getElementById('epss-config-fields');
            if (epssEnabled && epssFields) {
                epssFields.style.display = epssEnabled.checked ? 'grid' : 'none';
            }
            
            const saveBtn = document.querySelector('button[onclick="saveConfiguration()"]');
            if (saveBtn) {
                console.log('[Risk Matrix] Save button found (early init):', saveBtn);
            } else {
                console.error('[Risk Matrix] Save button NOT found (early init)!');
            }
        }

    </script>

</body>
</html>

