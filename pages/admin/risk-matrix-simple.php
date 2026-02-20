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

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_config') {
    try {
        $db->beginTransaction();
        
        // Update the current active configuration
        $sql = "UPDATE risk_matrix_config SET 
            kev_weight = ?,
            clinical_high_score = ?,
            business_medium_score = ?,
            non_essential_score = ?,
            location_weight_multiplier = ?,
            critical_severity_score = ?,
            high_severity_score = ?,
            medium_severity_score = ?,
            low_severity_score = ?,
            epss_weight_enabled = ?,
            epss_high_threshold = ?,
            epss_weight_score = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE is_active = TRUE";
        
        $stmt = $db->prepare($sql);
        $stmt->execute([
            intval($_POST['kev_weight']),
            intval($_POST['clinical_high_score']),
            intval($_POST['business_medium_score']),
            intval($_POST['non_essential_score']),
            floatval($_POST['location_weight_multiplier']),
            intval($_POST['critical_severity_score']),
            intval($_POST['high_severity_score']),
            intval($_POST['medium_severity_score']),
            intval($_POST['low_severity_score']),
            isset($_POST['epss_weight_enabled']) ? 1 : 0,
            floatval($_POST['epss_high_threshold']),
            intval($_POST['epss_weight_score'])
        ]);
        
        // Refresh materialized view
        try {
            $db->query("SELECT refresh_risk_priorities()");
        } catch (Exception $e) {
            // Continue if refresh fails
        }
        
        $db->commit();
        
        // Redirect to prevent resubmission
        header('Location: ' . $_SERVER['PHP_SELF'] . '?success=1');
        exit;
        
    } catch (Exception $e) {
        $db->rollBack();
        $error = "Error updating configuration: " . $e->getMessage();
    }
}

// Get current configuration
$sql = "SELECT * FROM risk_matrix_config WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1";
$currentConfig = $db->query($sql)->fetch();

// If no active configuration exists, create a default one
if (!$currentConfig) {
    try {
        $sql = "INSERT INTO risk_matrix_config (
            config_name, is_active, kev_weight, clinical_high_score, 
            business_medium_score, non_essential_score, location_weight_multiplier,
            critical_severity_score, high_severity_score, medium_severity_score,
            low_severity_score, epss_weight_enabled, epss_high_threshold, epss_weight_score,
            created_by
        ) VALUES (?, TRUE, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        $stmt = $db->prepare($sql);
        $stmt->execute([
            'Risk Matrix Configuration',
            1000, 100, 50, 10, 5.0,
            40, 28, 16, 4,
            1, 0.7, 20,
            $user['user_id']
        ]);
        
        // Reload the configuration
        $sql = "SELECT * FROM risk_matrix_config WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1";
        $currentConfig = $db->query($sql)->fetch();
        
    } catch (Exception $e) {
        $error = "Error creating default configuration: " . $e->getMessage();
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Risk Matrix Configuration - </title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .header {
            text-align: center;
            margin-bottom: 3rem;
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 0.5rem;
        }
        
        .header p {
            color: #94a3b8;
            font-size: 1.1rem;
        }
        
        .config-form {
            background: #1a1a1a;
            border: 1px solid #333333;
            border-radius: 1rem;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .form-group {
            display: flex;
            flex-direction: column;
        }
        
        .form-group label {
            color: #ffffff;
            font-weight: 600;
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
        }
        
        .form-group input,
        .form-group select {
            background: #0f0f0f;
            border: 1px solid #333333;
            border-radius: 0.5rem;
            padding: 0.75rem;
            color: #ffffff;
            font-size: 1rem;
        }
        
        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: #009999;
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-top: 1rem;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: 1.2rem;
            height: 1.2rem;
            accent-color: #009999;
        }
        
        .checkbox-group label {
            color: #cbd5e1;
            font-size: 0.9rem;
            cursor: pointer;
        }
        
        .submit-button {
            background: #009999;
            color: white;
            border: none;
            padding: 1rem 2rem;
            border-radius: 0.5rem;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
            width: 100%;
            max-width: 300px;
            margin: 0 auto;
            display: block;
        }
        
        .submit-button:hover {
            background: #007777;
        }
        
        .submit-button:disabled {
            background: #666666;
            cursor: not-allowed;
        }
        
        .alert {
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1.5rem;
            font-weight: 500;
        }
        
        .alert-success {
            background: #065f46;
            color: #10b981;
            border: 1px solid #10b981;
        }
        
        .alert-error {
            background: #7f1d1d;
            color: #f87171;
            border: 1px solid #f87171;
        }
        
        .current-config {
            background: #0f0f0f;
            border: 1px solid #333333;
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .current-config h3 {
            color: #ffffff;
            font-size: 1.2rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .config-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        
        .config-item {
            background: #1a1a1a;
            padding: 1rem;
            border-radius: 0.5rem;
            border: 1px solid #333333;
        }
        
        .config-item-label {
            color: #94a3b8;
            font-size: 0.8rem;
            font-weight: 500;
            margin-bottom: 0.25rem;
        }
        
        .config-item-value {
            color: #ffffff;
            font-size: 1.1rem;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-cogs"></i> Risk Matrix Configuration</h1>
            <p>Configure how risk scores are calculated for your organization</p>
        </div>

        <?php if (isset($_GET['success']) && $_GET['success'] == '1'): ?>
        <div class="alert alert-success">
            <i class="fas fa-check-circle"></i> Risk matrix configuration updated successfully!
        </div>
        <?php endif; ?>

        <?php if (isset($error)): ?>
        <div class="alert alert-error">
            <i class="fas fa-exclamation-circle"></i> <?php echo dave_htmlspecialchars($error); ?>
        </div>
        <?php endif; ?>

        <?php if ($currentConfig): ?>
        <div class="current-config">
            <h3><i class="fas fa-info-circle"></i> Current Configuration</h3>
            <div class="config-info">
                <div class="config-item">
                    <div class="config-item-label">Last Updated</div>
                    <div class="config-item-value"><?php echo date('M d, Y H:i', strtotime($currentConfig['updated_at'] ?: $currentConfig['created_at'])); ?></div>
                </div>
                <div class="config-item">
                    <div class="config-item-label">Status</div>
                    <div class="config-item-value" style="color: #10b981;">Active</div>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <div class="config-form">
            <form method="POST" action="">
                <input type="hidden" name="action" value="update_config">
                
                <div class="form-grid">
                    <div class="form-group">
                        <label for="kev_weight">KEV Weight</label>
                        <input type="number" id="kev_weight" name="kev_weight" 
                               value="<?php echo dave_htmlspecialchars($currentConfig['kev_weight'] ?? 1000); ?>" 
                               min="0" max="10000" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="clinical_high_score">Clinical High Score</label>
                        <input type="number" id="clinical_high_score" name="clinical_high_score" 
                               value="<?php echo dave_htmlspecialchars($currentConfig['clinical_high_score'] ?? 100); ?>" 
                               min="0" max="1000" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="business_medium_score">Business Medium Score</label>
                        <input type="number" id="business_medium_score" name="business_medium_score" 
                               value="<?php echo dave_htmlspecialchars($currentConfig['business_medium_score'] ?? 50); ?>" 
                               min="0" max="1000" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="non_essential_score">Non-Essential Score</label>
                        <input type="number" id="non_essential_score" name="non_essential_score" 
                               value="<?php echo dave_htmlspecialchars($currentConfig['non_essential_score'] ?? 10); ?>" 
                               min="0" max="1000" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="location_weight_multiplier">Location Weight Multiplier</label>
                        <input type="number" id="location_weight_multiplier" name="location_weight_multiplier" 
                               value="<?php echo dave_htmlspecialchars($currentConfig['location_weight_multiplier'] ?? 5.0); ?>" 
                               step="0.1" min="0" max="100" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="critical_severity_score">Critical Severity Score</label>
                        <input type="number" id="critical_severity_score" name="critical_severity_score" 
                               value="<?php echo dave_htmlspecialchars($currentConfig['critical_severity_score'] ?? 40); ?>" 
                               min="0" max="1000" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="high_severity_score">High Severity Score</label>
                        <input type="number" id="high_severity_score" name="high_severity_score" 
                               value="<?php echo dave_htmlspecialchars($currentConfig['high_severity_score'] ?? 28); ?>" 
                               min="0" max="1000" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="medium_severity_score">Medium Severity Score</label>
                        <input type="number" id="medium_severity_score" name="medium_severity_score" 
                               value="<?php echo dave_htmlspecialchars($currentConfig['medium_severity_score'] ?? 16); ?>" 
                               min="0" max="1000" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="low_severity_score">Low Severity Score</label>
                        <input type="number" id="low_severity_score" name="low_severity_score" 
                               value="<?php echo dave_htmlspecialchars($currentConfig['low_severity_score'] ?? 4); ?>" 
                               min="0" max="1000" required>
                    </div>
                </div>
                
                <div class="checkbox-group">
                    <input type="checkbox" id="epss_weight_enabled" name="epss_weight_enabled" 
                           <?php echo ($currentConfig['epss_weight_enabled'] ?? true) ? 'checked' : ''; ?>>
                    <label for="epss_weight_enabled">Enable EPSS in risk score calculation</label>
                </div>
                
                <div class="form-grid" style="margin-top: 1.5rem;">
                    <div class="form-group">
                        <label for="epss_high_threshold">EPSS High Threshold</label>
                        <input type="number" id="epss_high_threshold" name="epss_high_threshold" 
                               value="<?php echo dave_htmlspecialchars($currentConfig['epss_high_threshold'] ?? 0.7); ?>" 
                               step="0.01" min="0" max="1" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="epss_weight_score">EPSS Weight Score</label>
                        <input type="number" id="epss_weight_score" name="epss_weight_score" 
                               value="<?php echo dave_htmlspecialchars($currentConfig['epss_weight_score'] ?? 20); ?>" 
                               min="0" max="1000" required>
                    </div>
                </div>
                
                <button type="submit" class="submit-button">
                    <i class="fas fa-save"></i> Update Configuration
                </button>
            </form>
        </div>
    </div>

    <script>
        // Simple form validation
        document.querySelector('form').addEventListener('submit', function(e) {
            const button = document.querySelector('.submit-button');
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';
        });
        
        // EPSS fields visibility
        const epssCheckbox = document.getElementById('epss_weight_enabled');
        const epssFields = document.querySelectorAll('#epss_high_threshold, #epss_weight_score');
        
        function toggleEpssFields() {
            epssFields.forEach(field => {
                field.closest('.form-group').style.display = epssCheckbox.checked ? 'block' : 'none';
            });
        }
        
        epssCheckbox.addEventListener('change', toggleEpssFields);
        toggleEpssFields(); // Initial state
    </script>
</body>
</html>
