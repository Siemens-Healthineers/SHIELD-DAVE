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

// Check permissions
if (!$auth->hasPermission('recalls.manage')) {
    header('HTTP/1.1 403 Forbidden');
    echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
    exit;
}

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    try {
        // Handle manual device matching
        if (isset($_POST['action']) && $_POST['action'] === 'match_devices') {
            require_once __DIR__ . '/../../scripts/match_recalls_to_devices.php';
            
            $matcher = new RecallDeviceMatcher();
            $result = $matcher->matchRecallsToDevices();
            
            if ($result['success']) {
                // Log the matching action
                $auth->logUserAction('recall_device_matching', 'device_recalls_link', null, [
                    'matches_created' => $result['matched'],
                    'recalls_processed' => $result['total_recalls']
                ]);
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Device matching completed successfully',
                    'data' => $result
                ]);
            } else {
                echo json_encode([
                    'success' => false,
                    'message' => 'Device matching failed: ' . $result['error']
                ]);
            }
            exit;
        }
        
        $daysBack = intval($_POST['days_back'] ?? 30);
        $limit = intval($_POST['limit'] ?? 100);
        
        // Validate parameters
        if ($daysBack < 1 || $daysBack > 365) {
            throw new Exception('Days back must be between 1 and 365');
        }
        
        if ($limit < 1 || $limit > 1000) {
            throw new Exception('Limit must be between 1 and 1000');
        }
        
        // Include the import script
        require_once __DIR__ . '/../../scripts/import_recalls.php';
        require_once __DIR__ . '/../../scripts/match_recalls_to_devices.php';
        
        // Create importer instance
        $importer = new RecallImporter();
        
        // Run import
        $result = $importer->importRecalls($daysBack, $limit);
        
        // If import was successful, run device matching
        if ($result['success'] && ($result['imported'] > 0 || $result['updated'] > 0)) {
            $matcher = new RecallDeviceMatcher();
            $matchResult = $matcher->matchRecallsToDevices();
            
            if ($matchResult['success']) {
                $result['device_matches'] = $matchResult['matched'];
            }
        }
        
        if ($result['success']) {
            // Log the import action
            $auth->logUserAction('recall_import', 'recalls', null, [
                'days_back' => $daysBack,
                'limit' => $limit,
                'imported' => $result['imported'],
                'updated' => $result['updated'],
                'errors' => $result['errors']
            ]);
            
            echo json_encode([
                'success' => true,
                'message' => 'Recall import completed successfully',
                'data' => $result
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Recall import failed: ' . $result['error']
            ]);
        }
        
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Error: ' . $e->getMessage()
        ]);
    }
    exit;
}

$db = DatabaseConfig::getInstance();

// Get current recall statistics
$sql = "SELECT 
    COUNT(*) as total_recalls,
    COUNT(CASE WHEN recall_status = 'Active' THEN 1 END) as active_recalls,
    COUNT(CASE WHEN recall_date > CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as recent_recalls
    FROM recalls";
$stmt = $db->query($sql);
$stats = $stmt->fetch();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Import Recalls - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-download"></i> Import Recalls</h1>
                    <p>Import recall data from FDA API</p>
                </div>
                <div class="page-actions">
                    <a href="/pages/recalls/dashboard.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Back to Dashboard
                    </a>
                </div>
            </div>

            <!-- Current Statistics -->
            <section class="metrics-section">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value"><?php echo number_format($stats['total_recalls']); ?></div>
                            <div class="metric-label">Total Recalls</div>
                        </div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-clock"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value"><?php echo number_format($stats['active_recalls']); ?></div>
                            <div class="metric-label">Active Recalls</div>
                        </div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-calendar-day"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value"><?php echo number_format($stats['recent_recalls']); ?></div>
                            <div class="metric-label">Recent (30 days)</div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Import Form -->
            <section class="content-section">
                <div class="section-header">
                    <h3><i class="fas fa-download"></i> Import Recalls from FDA</h3>
                </div>
                
                <div class="import-form">
                    <form id="importForm">
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="daysBack">Days Back</label>
                                <select id="daysBack" name="days_back" required>
                                    <option value="7">Last 7 days</option>
                                    <option value="30" selected>Last 30 days</option>
                                    <option value="90">Last 90 days</option>
                                    <option value="180">Last 180 days</option>
                                    <option value="365">Last year</option>
                                </select>
                                <small>How far back to search for recalls</small>
                            </div>
                            
                            <div class="form-group">
                                <label for="limit">Limit</label>
                                <select id="limit" name="limit" required>
                                    <option value="50">50 recalls</option>
                                    <option value="100" selected>100 recalls</option>
                                    <option value="250">250 recalls</option>
                                    <option value="500">500 recalls</option>
                                    <option value="1000">1000 recalls</option>
                                </select>
                                <small>Maximum number of recalls to import</small>
                            </div>
                        </div>
                        
                        <div class="form-actions">
                            <button type="submit" class="btn btn-primary" id="importBtn">
                                <i class="fas fa-download"></i>
                                Import Recalls
                            </button>
                            <button type="button" class="btn btn-outline" onclick="checkFDAStatus()">
                                <i class="fas fa-check-circle"></i>
                                Check FDA API Status
                            </button>
                            <button type="button" class="btn btn-accent" onclick="runDeviceMatching()">
                                <i class="fas fa-link"></i>
                                Match Devices to Recalls
                            </button>
                        </div>
                    </form>
                </div>
            </section>

            <!-- Import Results -->
            <section class="content-section" id="resultsSection" style="display: none;">
                <div class="section-header">
                    <h3><i class="fas fa-chart-bar"></i> Import Results</h3>
                </div>
                <div id="importResults"></div>
            </section>
        </main>
    </div>

    <script>
        // Import form handling
        document.getElementById('importForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const importBtn = document.getElementById('importBtn');
            const originalText = importBtn.innerHTML;
            
            // Show loading state
            importBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Importing...';
            importBtn.disabled = true;
            
            try {
                const formData = new FormData(this);
                
                const response = await fetch('/pages/recalls/import.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showSuccess(result.message, result.data);
                    // Refresh page after successful import
                    setTimeout(() => {
                        window.location.reload();
                    }, 3000);
                } else {
                    showError(result.message);
                }
                
            } catch (error) {
                showError('Import failed: ' + error.message);
            } finally {
                // Reset button
                importBtn.innerHTML = originalText;
                importBtn.disabled = false;
            }
        });
        
        // Check FDA API status
        async function checkFDAStatus() {
            try {
                const response = await fetch('https://api.fda.gov/device/enforcement.json?limit=1');
                if (response.ok) {
                    showSuccess('FDA API is accessible and responding');
                } else {
                    showError('FDA API returned status: ' + response.status);
                }
            } catch (error) {
                showError('FDA API is not accessible: ' + error.message);
            }
        }
        
        // Run device matching
        async function runDeviceMatching() {
            const btn = event.target;
            const originalText = btn.innerHTML;
            
            // Show loading state
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Matching...';
            btn.disabled = true;
            
            try {
                const formData = new FormData();
                formData.append('action', 'match_devices');
                
                const response = await fetch('/pages/recalls/import.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showSuccess(result.message, result.data);
                } else {
                    showError(result.message);
                }
                
            } catch (error) {
                showError('Device matching failed: ' + error.message);
            } finally {
                // Reset button
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        }
        
        // Show success message
        function showSuccess(message, data = null) {
            const resultsSection = document.getElementById('resultsSection');
            const resultsDiv = document.getElementById('importResults');
            
            let html = `
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    ${message}
                </div>
            `;
            
            if (data) {
                html += `
                    <div class="results-details">
                        <h4>Import Details:</h4>
                        <ul>
                            <li><strong>Imported:</strong> ${data.imported} new recalls</li>
                            <li><strong>Updated:</strong> ${data.updated} existing recalls</li>
                            <li><strong>Errors:</strong> ${data.errors}</li>
                            <li><strong>Total Processed:</strong> ${data.total_processed}</li>
                            ${data.device_matches !== undefined ? `<li><strong>Device Matches:</strong> ${data.device_matches} devices linked to recalls</li>` : ''}
                        </ul>
                    </div>
                `;
            }
            
            resultsDiv.innerHTML = html;
            resultsSection.style.display = 'block';
        }
        
        // Show error message
        function showError(message) {
            const resultsSection = document.getElementById('resultsSection');
            const resultsDiv = document.getElementById('importResults');
            
            resultsDiv.innerHTML = `
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i>
                    ${message}
                </div>
            `;
            
            resultsSection.style.display = 'block';
        }
        
        // Profile dropdown functionality
        function toggleProfileDropdown() {
            const dropdown = document.getElementById('profileDropdown');
            dropdown.classList.toggle('show');
        }
        
        // Close dropdown when clicking outside
        window.addEventListener('click', function(event) {
            const dropdown = document.getElementById('profileDropdown');
            const profileBtn = document.querySelector('.profile-btn');
            
            if (!profileBtn.contains(event.target)) {
                dropdown.classList.remove('show');
            }
        });
    </script>
</body>
</html>
