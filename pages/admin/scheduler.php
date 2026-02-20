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

// Require authentication and admin permission
$auth->requireAuth();
$auth->requirePermission('admin.manage');

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();
$error = '';
$success = '';

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['ajax']) {
            
            
        case 'run_task':
            $task = $_POST['task'] ?? '';
            
            if (empty($task)) {
                echo json_encode(['success' => false, 'message' => 'Task name required']);
                exit;
            }
            
            // Route to appropriate script based on task
            switch ($task) {
                case 'health_check':
                    $command = "cd /var/www/html && php scripts/health-check.php";
                    break;
                case 'data_consistency_check':
                    $command = "cd /var/www/html && php scripts/validate-data-consistency.php";
                    break;
                case 'process_sbom_queue':
                    $command = "cd /var/www/html && php services/process-sbom-queue.php";
                    break;
                case 'analyze_assets_oui':
                    // Run in background and redirect output to log file
                    $logFile = '/var/www/html/logs/oui_analysis_' . date('Y-m-d_H-i-s') . '.log';
                    $command = "cd /var/www/html && nohup php scripts/analyze-assets-oui.php > " . escapeshellarg($logFile) . " 2>&1 &";
                    shell_exec($command);
                    // Return immediately - task is running in background
                    echo json_encode([
                        'success' => true, 
                        'message' => "OUI analysis task started in background.\n\nLog file: " . basename($logFile) . "\n\nYou can check the logs directory for progress updates.",
                        'background' => true,
                        'log_file' => basename($logFile)
                    ]);
                    exit;
                case 'recalculate_risk_scores':
                    $command = "cd /var/www/html && php scripts/recalculate-risk-scores.php";
                    break;
                case 'match_kev_vulnerabilities':
                    $command = "cd /var/www/html && php scripts/match-kev-vulnerabilities.php";
                    break;
                default:
                    echo json_encode(['success' => false, 'message' => 'Unknown task: ' . $task]);
                    exit;
            }
            
            $output = shell_exec($command . ' 2>&1');
            
            // Parse output for success/error indicators
            $success = true;
            $message = $output;
            
            // Check for fatal errors
            if (strpos($output, 'ERROR') !== false || strpos($output, 'Fatal error') !== false || strpos($output, 'fatal') !== false) {
                $success = false;
            }
            
            // For OUI analysis, try to extract statistics
            if ($task === 'analyze_assets_oui') {
                $processed = 0;
                $updated = 0;
                $skipped = 0;
                $errors = 0;
                
                if (preg_match('/Total processed: (\d+)/', $output, $matches)) {
                    $processed = intval($matches[1]);
                }
                if (preg_match('/Manufacturers found and updated: (\d+)/', $output, $matches)) {
                    $updated = intval($matches[1]);
                }
                if (preg_match('/No manufacturer found: (\d+)/', $output, $matches)) {
                    $skipped = intval($matches[1]);
                }
                if (preg_match('/Errors: (\d+)/', $output, $matches)) {
                    $errors = intval($matches[1]);
                }
                
                // Success if: updated some assets, OR processed with no errors, OR no assets needed processing (all have manufacturers)
                if ($updated > 0 || ($processed > 0 && $errors === 0) || ($processed === 0 && stripos($output, 'No assets need manufacturer lookup') !== false)) {
                    $success = true;
                    if ($processed === 0) {
                        $message = "OUI Analysis completed successfully.\n\nAll assets already have manufacturer information. No lookups needed.";
                    } else {
                        $message = "OUI Analysis completed successfully. Processed: {$processed}, Updated: {$updated}, Not Found: {$skipped}, Errors: {$errors}\n\n" . $output;
                    }
                } else {
                    $success = false;
                    $message = $output;
                }
            }
            
            // For risk score recalculation, try to extract statistics
            if ($task === 'recalculate_risk_scores') {
                $processed = 0;
                $updated = 0;
                $skipped = 0;
                $errors = 0;
                $remaining = 0;
                
                if (preg_match('/Total processed: (\d+)/', $output, $matches)) {
                    $processed = intval($matches[1]);
                }
                if (preg_match('/Risk scores updated: (\d+)/', $output, $matches)) {
                    $updated = intval($matches[1]);
                }
                if (preg_match('/Skipped.*?: (\d+)/', $output, $matches)) {
                    $skipped = intval($matches[1]);
                }
                if (preg_match('/Errors: (\d+)/', $output, $matches)) {
                    $errors = intval($matches[1]);
                }
                if (preg_match('/Remaining NULL risk scores: (\d+)/', $output, $matches)) {
                    $remaining = intval($matches[1]);
                }
                
                // Success if: updated some scores, OR processed with no errors
                if ($updated > 0 || ($processed > 0 && $errors === 0) || ($processed === 0 && stripos($output, 'No links need risk score recalculation') !== false)) {
                    $success = true;
                    if ($processed === 0) {
                        $message = "Risk score recalculation completed successfully.\n\nAll device-vulnerability links already have risk scores. No recalculation needed.";
                    } else {
                        $message = "Risk score recalculation completed successfully.\n\nProcessed: {$processed}\nUpdated: {$updated}\nSkipped: {$skipped}\nErrors: {$errors}\nRemaining NULL scores: {$remaining}\n\n" . $output;
                    }
                } else {
                    $success = false;
                    $message = $output;
                }
            }
            
            // For KEV matching, try to extract statistics
            if ($task === 'match_kev_vulnerabilities') {
                $matched = 0;
                $actionsUpdated = 0;
                $urgencyRecalculated = 0;
                $linksRecalculated = 0;
                
                if (preg_match('/Vulnerabilities matched: (\d+)/', $output, $matches)) {
                    $matched = intval($matches[1]);
                }
                if (preg_match('/Actions updated: (\d+)/', $output, $matches)) {
                    $actionsUpdated = intval($matches[1]);
                }
                if (preg_match('/Urgency scores recalculated: (\d+)/', $output, $matches)) {
                    $urgencyRecalculated = intval($matches[1]);
                }
                if (preg_match('/Recalculated risk scores for (\d+) device-vulnerability links/', $output, $matches)) {
                    $linksRecalculated = intval($matches[1]);
                }
                
                // Success if output contains success message
                if (stripos($output, 'KEV MATCHING COMPLETED SUCCESSFULLY') !== false) {
                    $success = true;
                    if ($matched === 0) {
                        $message = "KEV matching completed successfully.\n\nAll vulnerabilities are already matched with KEV catalog. Risk scores and action counts have been updated.\n\n";
                    } else {
                        $message = "KEV matching completed successfully.\n\n";
                    }
                    $message .= "Summary:\n";
                    $message .= "  Vulnerabilities matched: {$matched}\n";
                    $message .= "  Device risk scores recalculated: {$linksRecalculated}\n";
                    $message .= "  Actions updated: {$actionsUpdated}\n";
                    $message .= "  Urgency scores recalculated: {$urgencyRecalculated}\n";
                    $message .= "  Materialized views refreshed: 2\n";
                } else {
                    $success = false;
                    $message = $output;
                }
            }
            
            echo json_encode(['success' => $success, 'message' => $message]);
            exit;
            
        case 'recalculate_remediation_actions':
            $command = "cd /var/www/html && php services/vulnerability-monitor.php";
            $output = shell_exec($command . ' 2>&1');
            
            // Parse the output to extract results
            $created = 0;
            $errors = 0;
            $total = 0;
            
            if (preg_match('/Created: (\d+) remediation actions/', $output, $matches)) {
                $created = intval($matches[1]);
            }
            if (preg_match('/Errors: (\d+)/', $output, $matches)) {
                $errors = intval($matches[1]);
            }
            if (preg_match('/Total processed: (\d+)/', $output, $matches)) {
                $total = intval($matches[1]);
            }
            
            // Refresh the action_priority_view materialized view to ensure it includes new/updated actions
            try {
                $db = DatabaseConfig::getInstance();
                $db->getConnection()->exec("REFRESH MATERIALIZED VIEW action_priority_view");
            } catch (Exception $e) {
                error_log("Failed to refresh action_priority_view after recalculation: " . $e->getMessage());
                // Don't fail the entire operation if refresh fails
            }
            
            if ($created > 0 || $errors == 0) {
                echo json_encode([
                    'success' => true, 
                    'message' => "Successfully created $created remediation actions for $total vulnerabilities",
                    'created' => $created,
                    'errors' => $errors,
                    'total' => $total
                ]);
            } else {
                echo json_encode([
                    'success' => false, 
                    'message' => "Failed to create remediation actions. Errors: $errors",
                    'created' => $created,
                    'errors' => $errors,
                    'total' => $total
                ]);
            }
            exit;
    }
}



// Available manual tasks
$manualTasks = [
    'recalculate_remediation_actions' => 'Recalculate Remediation Actions',
    'match_kev_vulnerabilities' => 'Match KEV Vulnerabilities',
    'health_check' => 'System Health Check',
    'data_consistency_check' => 'Data Consistency Check',
    'process_sbom_queue' => 'Process SBOM Queue',
    'analyze_assets_oui' => 'Analyze Assets OUI',
    'recalculate_risk_scores' => 'Recalculate Risk Scores'
];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manual Tasks - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-tasks"></i> Manual Tasks</h1>
                    <p>Run system maintenance and monitoring tasks manually</p>
                </div>
            </div>

            <?php if ($error): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i>
                    <?php echo dave_htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <?php echo dave_htmlspecialchars($success); ?>
                </div>
            <?php endif; ?>



            <!-- Manual Tasks -->
            <section class="manual-tasks-section">
                <div class="section-header">
                    <h3><i class="fas fa-play"></i> Manual Tasks</h3>
                    <p>Run specific tasks manually for testing or immediate execution</p>
                </div>
                
                <div class="manual-tasks-grid">
                    <?php foreach ($manualTasks as $taskKey => $taskName): ?>
                        <div class="manual-task-item">
                            <div class="task-info">
                                <div class="task-name"><?php echo dave_htmlspecialchars($taskName); ?></div>
                                <div class="task-description">
                                    <?php
                                    switch ($taskKey) {
                                        case 'monitor_recalls':
                                            echo 'Check for new FDA recalls and match against organizational devices';
                                            break;
                                        case 'scan_vulnerabilities':
                                            echo 'Scan all devices for known vulnerabilities';
                                            break;
                                        case 'check_new_vulnerabilities':
                                            echo 'Check NVD database for new vulnerabilities';
                                            break;
                                        case 'cleanup_data':
                                            echo 'Clean up old data, logs, and temporary files';
                                            break;
                                        case 'recalculate_remediation_actions':
                                            echo 'Create remediation actions for vulnerabilities that don\'t have them, calculate urgency and efficiency scores, and recalculate device risk scores';
                                            break;
                                        case 'match_kev_vulnerabilities':
                                            echo 'Match existing vulnerabilities with CISA KEV catalog, update is_kev flags, and recalculate risk scores for all affected actions and devices';
                                            break;
                                        case 'health_check':
                                            echo 'Perform system health checks and diagnostics';
                                            break;
                                        case 'data_consistency_check':
                                            echo 'Validate data integrity across the system, including vulnerability counts, tier calculations, device counts, and risk score calculations';
                                            break;
                                        case 'process_sbom_queue':
                                            echo 'Process any SBOMs that failed during upload, retry stuck evaluations, and clean up the SBOM processing queue';
                                            break;
                                        case 'analyze_assets_oui':
                                            echo 'Look up manufacturers for assets with MAC addresses but no manufacturer information using OUI database';
                                            break;
                                        case 'recalculate_risk_scores':
                                            echo 'Recalculate risk scores for device-vulnerability links that have NULL risk scores';
                                            break;
                                        default:
                                            echo 'Run this task manually';
                                    }
                                    ?>
                                </div>
                            </div>
                            <div class="task-actions">
                                <button type="button" class="btn btn-primary" onclick="runManualTask('<?php echo $taskKey; ?>')">
                                    <i class="fas fa-play"></i>
                                    Run Now
                                </button>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </section>

        </main>
    </div>

    <script>
        // Manual Tasks Management JavaScript
        document.addEventListener('DOMContentLoaded', function() {
            setupEventListeners();
        });
        
        function setupEventListeners() {
            // No event listeners needed for manual tasks only
        }
        
        
        
        function runManualTask(taskKey) {
            // Show appropriate modal for each task
            switch(taskKey) {
                case 'recalculate_remediation_actions':
                    showRecalculateModal();
                    break;
                case 'match_kev_vulnerabilities':
                    showTaskModal('match_kev_vulnerabilities', 'Match KEV Vulnerabilities', 'This will match existing vulnerabilities with the CISA KEV catalog, update is_kev flags, recalculate device risk scores, update action urgency scores, and refresh materialized views.');
                    break;
                case 'health_check':
                    showTaskModal('health_check', 'System Health Check', 'This will perform a comprehensive system health check including database connectivity, disk space, memory usage, service status, and data integrity validation.');
                    break;
                case 'data_consistency_check':
                    showTaskModal('data_consistency_check', 'Data Consistency Check', 'This will validate data integrity across the system, including vulnerability counts, tier calculations, device counts, and risk score calculations.');
                    break;
                case 'process_sbom_queue':
                    showTaskModal('process_sbom_queue', 'Process SBOM Queue', 'This will process any SBOMs that failed during upload, retry stuck evaluations, and clean up the SBOM processing queue.');
                    break;
                case 'analyze_assets_oui':
                    showTaskModal('analyze_assets_oui', 'Analyze Assets OUI', 'This will look up manufacturers for all assets that have MAC addresses but no manufacturer information. The lookup uses the OUI (Organizationally Unique Identifier) database to identify manufacturers from MAC addresses.');
                    break;
                case 'recalculate_risk_scores':
                    showTaskModal('recalculate_risk_scores', 'Recalculate Risk Scores', 'This will recalculate risk scores for all device-vulnerability links that currently have NULL risk scores. The calculation uses the configured risk matrix and considers factors like KEV status, asset criticality, location criticality, vulnerability severity, and EPSS scores.');
                    break;
                default:
                    showTaskModal(taskKey, 'Manual Task', 'This will execute the selected manual task.');
                    break;
            }
        }
        
        
        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
                ${message}
            `;
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 3000);
        }

        // Generic Task Modal Functions
        let currentTaskKey = null;

        function showTaskModal(taskKey, title, description) {
            currentTaskKey = taskKey;
            document.getElementById('taskModalTitle').innerHTML = `<i class="fas fa-tasks"></i> ${title}`;
            document.getElementById('taskModalDescription').textContent = description;
            
            // Reset modal state
            document.getElementById('taskProgress').style.display = 'none';
            document.getElementById('taskResult').style.display = 'none';
            document.getElementById('taskExecuteBtn').style.display = 'inline-block';
            document.getElementById('taskCancelBtn').textContent = 'Cancel';
            
            document.getElementById('taskModal').style.display = 'block';
        }

        function closeTaskModal() {
            document.getElementById('taskModal').style.display = 'none';
            currentTaskKey = null;
        }

        function executeTask() {
            if (!currentTaskKey) return;
            
            // Show progress section
            document.getElementById('taskProgress').style.display = 'block';
            document.getElementById('taskExecuteBtn').style.display = 'none';
            document.getElementById('taskCancelBtn').textContent = 'Close';
            
            // Start progress animation
            updateTaskProgress(0, 'Initializing task...');
            
            const formData = new FormData();
            formData.append('task', currentTaskKey);
            
            fetch('?ajax=run_task', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                // Handle background tasks differently
                if (data.background) {
                    updateTaskProgress(100, 'Task started in background!');
                    setTimeout(() => {
                        document.getElementById('taskProgress').style.display = 'none';
                        document.getElementById('taskResult').style.display = 'block';
                        
                        const resultContent = document.getElementById('taskResultContent');
                        const logFileLink = data.log_file ? `<br><br><strong>Log file:</strong> <code>${data.log_file}</code><br><small>Check the logs directory for progress updates.</small>` : '';
                        resultContent.innerHTML = `
                            <div class="result-success">
                                <i class="fas fa-clock"></i>
                                <h4>Task Started in Background</h4>
                                <p>${data.message.replace(/\n/g, '<br>')}${logFileLink}</p>
                            </div>
                        `;
                    }, 500);
                } else {
                    updateTaskProgress(100, 'Task completed!');
                    
                    // Show results
                    setTimeout(() => {
                        document.getElementById('taskProgress').style.display = 'none';
                        document.getElementById('taskResult').style.display = 'block';
                        
                        const resultContent = document.getElementById('taskResultContent');
                        if (data.success) {
                            resultContent.innerHTML = `
                                <div class="result-success">
                                    <i class="fas fa-check-circle"></i>
                                    <h4>Task Completed Successfully</h4>
                                    <p>${data.message.replace(/\n/g, '<br>')}</p>
                                </div>
                            `;
                        } else {
                            resultContent.innerHTML = `
                                <div class="result-error">
                                    <i class="fas fa-exclamation-circle"></i>
                                    <h4>Task Failed</h4>
                                    <p>${data.message.replace(/\n/g, '<br>')}</p>
                                </div>
                            `;
                        }
                    }, 1000);
                }
            })
            .catch(error => {
                updateTaskProgress(100, 'Task failed!');
                setTimeout(() => {
                    document.getElementById('taskProgress').style.display = 'none';
                    document.getElementById('taskResult').style.display = 'block';
                    
                    const resultContent = document.getElementById('taskResultContent');
                    resultContent.innerHTML = `
                        <div class="result-error">
                            <i class="fas fa-exclamation-circle"></i>
                            <h4>Task Failed</h4>
                            <p>Error running task: ${error.message}</p>
                        </div>
                    `;
                }, 1000);
            });
        }

        function updateTaskProgress(percent, text) {
            document.getElementById('taskProgressFill').style.width = percent + '%';
            document.getElementById('taskProgressText').textContent = text;
        }

        // Recalculate Modal Functions (existing)
        function showRecalculateModal() {
            document.getElementById('recalculateModal').style.display = 'block';
        }

        function closeRecalculateModal() {
            document.getElementById('recalculateModal').style.display = 'none';
        }

        function executeRecalculate() {
            // Show progress section
            document.getElementById('recalculateProgress').style.display = 'block';
            document.getElementById('executeBtn').style.display = 'none';
            document.getElementById('cancelBtn').textContent = 'Close';
            
            // Start progress animation
            updateProgress(0, 'Initializing recalculation...');
            
            const formData = new FormData();
            formData.append('task', 'recalculate_remediation_actions');
            
            fetch('?ajax=recalculate_remediation_actions', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                updateProgress(100, 'Recalculation completed!');
                
                // Show results
                setTimeout(() => {
                    document.getElementById('recalculateProgress').style.display = 'none';
                    document.getElementById('recalculateResult').style.display = 'block';
                    
                    const resultContent = document.getElementById('resultContent');
                    if (data.success) {
                        resultContent.innerHTML = `
                            <div class="result-success">
                                <i class="fas fa-check-circle"></i>
                                <h4>Recalculation Completed Successfully</h4>
                                <p>Created: ${data.created} remediation actions</p>
                                <p>Errors: ${data.errors}</p>
                                <p>Total processed: ${data.total} vulnerabilities</p>
                            </div>
                        `;
                    } else {
                        resultContent.innerHTML = `
                            <div class="result-error">
                                <i class="fas fa-exclamation-circle"></i>
                                <h4>Recalculation Failed</h4>
                                <p>${data.message}</p>
                            </div>
                        `;
                    }
                }, 1000);
            })
            .catch(error => {
                updateProgress(100, 'Recalculation failed!');
                setTimeout(() => {
                    document.getElementById('recalculateProgress').style.display = 'none';
                    document.getElementById('recalculateResult').style.display = 'block';
                    
                    const resultContent = document.getElementById('resultContent');
                    resultContent.innerHTML = `
                        <div class="result-error">
                            <i class="fas fa-exclamation-circle"></i>
                            <h4>Recalculation Failed</h4>
                            <p>Error running recalculation: ${error.message}</p>
                        </div>
                    `;
                }, 1000);
            });
        }

        function updateProgress(percent, text) {
            document.getElementById('progressFill').style.width = percent + '%';
            document.getElementById('progressText').textContent = text;
        }

        function displayResult(success, message) {
            const resultContent = document.getElementById('resultContent');
            if (success) {
                resultContent.innerHTML = `
                    <div class="result-success">
                        <i class="fas fa-check-circle"></i>
                        <h4>Success</h4>
                        <p>${message}</p>
                    </div>
                `;
            } else {
                resultContent.innerHTML = `
                    <div class="result-error">
                        <i class="fas fa-exclamation-circle"></i>
                        <h4>Error</h4>
                        <p>${message}</p>
                    </div>
                `;
            }
        }
    </script>
    <!-- Profile Dropdown Script -->
    <script src="/assets/js/dashboard-common.js"></script>
    <script>
        // Pass user data to the profile dropdown
        window.userData = {
            name: '<?php echo dave_htmlspecialchars($user['username']); ?>',
            role: '<?php echo dave_htmlspecialchars($user['role']); ?>',
            email: '<?php echo dave_htmlspecialchars($user['email'] ?? 'user@example.com'); ?>'
        };
    </script>

    <!-- Recalculate Remediation Actions Modal -->
    <div id="recalculateModal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-calculator"></i> Recalculate Remediation Actions</h3>
                <span class="close" onclick="closeRecalculateModal()">&times;</span>
            </div>
            <div class="modal-body">
                <div class="warning-box">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Warning:</strong> This operation will recalculate remediation actions and risk scores for all vulnerabilities. This may take several minutes to complete.
                </div>
                <div class="info-box">
                    <i class="fas fa-info-circle"></i>
                    <strong>What this does:</strong>
                    <ul>
                        <li>Creates remediation actions for vulnerabilities that don't have them</li>
                        <li>Calculates urgency and efficiency scores for all actions</li>
                        <li>Recalculates device risk scores for all device-vulnerability links</li>
                        <li>Updates tier calculations based on new scores</li>
                    </ul>
                </div>
                <div class="progress-section" id="recalculateProgress" style="display: none;">
                    <div class="progress-bar">
                        <div class="progress-fill" id="progressFill"></div>
                    </div>
                    <div class="progress-text" id="progressText">Initializing...</div>
                </div>
                <div class="result-section" id="recalculateResult" style="display: none;">
                    <div class="result-content" id="resultContent"></div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeRecalculateModal()" id="cancelBtn">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="executeRecalculate()" id="executeBtn">
                    <i class="fas fa-play"></i> Start Recalculation
                </button>
            </div>
        </div>
    </div>

    <!-- Generic Task Modal -->
    <div id="taskModal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="taskModalTitle"><i class="fas fa-tasks"></i> Manual Task</h3>
                <span class="close" onclick="closeTaskModal()">&times;</span>
            </div>
            <div class="modal-body">
                <div class="warning-box">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Warning:</strong> This operation may take several minutes to complete.
                </div>
                <div class="info-box">
                    <i class="fas fa-info-circle"></i>
                    <strong>What this does:</strong>
                    <p id="taskModalDescription">Task description will appear here.</p>
                </div>
                <div class="progress-section" id="taskProgress" style="display: none;">
                    <div class="progress-bar">
                        <div class="progress-fill" id="taskProgressFill"></div>
                    </div>
                    <div class="progress-text" id="taskProgressText">Initializing...</div>
                </div>
                <div class="result-section" id="taskResult" style="display: none;">
                    <div class="result-content" id="taskResultContent"></div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeTaskModal()" id="taskCancelBtn">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="executeTask()" id="taskExecuteBtn">
                    <i class="fas fa-play"></i> Start Task
                </button>
            </div>
        </div>
    </div>

    <style>
        :root {
            /* Siemens Healthineers Brand Colors */
            --siemens-petrol: #009999;
            --siemens-petrol-dark: #007777;
            --siemens-petrol-light: #00bbbb;
            --siemens-orange: #ff6b35;
            --siemens-orange-dark: #e55a2b;
            --siemens-orange-light: #ff8c5a;
        }

        .modal {
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background: var(--bg-card) !important;
            border: 1px solid var(--border-card) !important;
            border-radius: 8px !important;
            box-shadow: var(--shadow-xl) !important;
            max-width: 600px !important;
            width: 90% !important;
            max-height: 80vh !important;
            overflow-y: auto !important;
        }

        .modal-header {
            padding: 20px !important;
            border-bottom: 1px solid var(--border-secondary) !important;
            background: var(--bg-tertiary) !important;
            display: flex !important;
            justify-content: space-between !important;
            align-items: center !important;
        }

        .modal .modal-header h3 {
            margin: 0 !important;
            color: var(--text-primary) !important;
            font-family: 'Siemens Sans', sans-serif !important;
            font-weight: 600 !important;
            display: flex !important;
            align-items: center !important;
            gap: 10px !important;
        }

        .modal .close {
            font-size: 24px !important;
            font-weight: bold !important;
            cursor: pointer !important;
            color: var(--text-primary) !important;
            transition: color 0.2s ease !important;
        }

        .modal .close:hover {
            color: var(--siemens-petrol) !important;
        }

        .modal-body {
            padding: 20px !important;
            background: var(--bg-card) !important;
            color: var(--text-primary) !important;
        }

        .modal .warning-box {
            background: rgba(255, 107, 53, 0.1) !important;
            border: 1px solid var(--siemens-orange) !important;
            border-radius: 6px !important;
            padding: 15px !important;
            margin-bottom: 20px !important;
            display: flex !important;
            align-items: flex-start !important;
            gap: 10px !important;
            color: var(--text-primary) !important;
        }

        .modal .warning-box i {
            color: var(--siemens-orange) !important;
            margin-top: 2px !important;
        }

        .modal .info-box {
            background: rgba(0, 153, 153, 0.1) !important;
            border: 1px solid var(--siemens-petrol) !important;
            border-radius: 6px !important;
            padding: 15px !important;
            margin-bottom: 20px !important;
            color: var(--text-primary) !important;
        }

        .modal .info-box i {
            color: var(--siemens-petrol) !important;
            margin-right: 8px !important;
        }

        .info-box ul {
            margin: 10px 0 0 20px;
            padding: 0;
        }

        .info-box li {
            margin: 5px 0;
            color: #1e40af;
        }

        .progress-section {
            margin: 20px 0;
        }

        .progress-bar {
            width: 100%;
            height: 20px;
            background: #e5e7eb;
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 10px;
        }

        .modal .progress-fill {
            height: 100% !important;
            background: linear-gradient(90deg, var(--siemens-petrol), var(--siemens-petrol-dark)) !important;
            width: 0% !important;
            transition: width 0.3s ease !important;
        }

        .modal .progress-text {
            text-align: center !important;
            color: var(--text-secondary) !important;
            font-size: 14px !important;
        }

        /* Data Consistency Report Styles */
        .data-consistency-report {
            font-family: 'Siemens Sans', sans-serif;
            color: var(--text-primary);
            background: var(--bg-card);
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }

        .report-header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid var(--siemens-petrol);
        }

        .report-header h2 {
            color: var(--siemens-petrol);
            margin: 0 0 10px 0;
            font-size: 24px;
            font-weight: 600;
        }

        .report-header .timestamp {
            color: var(--text-secondary);
            font-size: 14px;
            margin: 0;
        }

        .stats-summary {
            margin-bottom: 30px;
        }

        .stats-summary h3 {
            color: var(--text-primary);
            margin-bottom: 20px;
            font-size: 18px;
            font-weight: 600;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-secondary);
            border-radius: 8px;
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 15px;
            transition: transform 0.2s ease;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.1);
        }

        .stat-icon {
            font-size: 24px;
            color: var(--siemens-petrol);
            width: 40px;
            text-align: center;
        }

        .stat-content {
            flex: 1;
        }

        .stat-value {
            font-size: 24px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 14px;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .validation-result {
            display: flex;
            align-items: center;
            gap: 20px;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .validation-result.success {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid #10b981;
        }

        .validation-result.warning {
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid #f59e0b;
        }

        .result-icon {
            font-size: 32px;
        }

        .validation-result.success .result-icon {
            color: #10b981;
        }

        .validation-result.warning .result-icon {
            color: #f59e0b;
        }

        .result-content h3 {
            margin: 0 0 10px 0;
            font-size: 18px;
            font-weight: 600;
        }

        .result-content p {
            margin: 0;
            color: var(--text-secondary);
        }

        .issues-list {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        .issue-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-secondary);
            border-radius: 8px;
            overflow: hidden;
        }

        .issue-card.severity-high {
            border-left: 4px solid #ef4444;
        }

        .issue-card.severity-medium {
            border-left: 4px solid #f59e0b;
        }

        .issue-card.severity-low {
            border-left: 4px solid #10b981;
        }

        .issue-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-secondary);
        }

        .issue-number {
            font-weight: 600;
            color: var(--siemens-petrol);
            font-size: 16px;
        }

        .issue-severity {
            font-weight: 600;
            font-size: 14px;
        }

        .issue-card.severity-high .issue-severity {
            color: #ef4444;
        }

        .issue-card.severity-medium .issue-severity {
            color: #f59e0b;
        }

        .issue-card.severity-low .issue-severity {
            color: #10b981;
        }

        .issue-content {
            padding: 20px;
        }

        .issue-content h4 {
            margin: 0 0 10px 0;
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .issue-message {
            margin: 0 0 15px 0;
            color: var(--text-secondary);
            line-height: 1.5;
        }

        .issue-recommendation {
            background: rgba(0, 153, 153, 0.1);
            border: 1px solid var(--siemens-petrol);
            border-radius: 6px;
            padding: 12px;
            font-size: 14px;
            color: var(--text-primary);
        }

        .issue-recommendation strong {
            color: var(--siemens-petrol);
        }

        /* Health Check Report Styles */
        .health-check-report {
            font-family: 'Siemens Sans', sans-serif;
            color: var(--text-primary);
            background: var(--bg-card);
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }

        .health-check-report .report-header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid var(--siemens-petrol);
        }

        .health-check-report .report-header h2 {
            color: var(--siemens-petrol);
            margin: 0 0 10px 0;
            font-size: 24px;
            font-weight: 600;
        }

        .health-check-report .report-header .timestamp {
            color: var(--text-secondary);
            font-size: 14px;
            margin: 0;
        }

        .status-summary {
            margin-bottom: 30px;
        }

        .status-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .status-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-secondary);
            border-radius: 8px;
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 15px;
            transition: transform 0.2s ease;
        }

        .status-card:hover {
            transform: translateY(-2px);
        }

        .status-card.success {
            border-left: 4px solid #10b981;
        }

        .status-card.warning {
            border-left: 4px solid #f59e0b;
        }

        .status-card.error {
            border-left: 4px solid #ef4444;
        }

        .status-icon {
            font-size: 24px;
            width: 40px;
            text-align: center;
        }

        .status-card.success .status-icon {
            color: #10b981;
        }

        .status-card.warning .status-icon {
            color: #f59e0b;
        }

        .status-card.error .status-icon {
            color: #ef4444;
        }

        .status-content {
            flex: 1;
        }

        .status-value {
            font-size: 24px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 5px;
        }

        .status-label {
            font-size: 14px;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .overall-status {
            display: flex;
            align-items: center;
            gap: 20px;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }

        .overall-status.success {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid #10b981;
        }

        .overall-status.warning {
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid #f59e0b;
        }

        .overall-status.error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid #ef4444;
        }

        .overall-status .status-icon {
            font-size: 32px;
        }

        .overall-status.success .status-icon {
            color: #10b981;
        }

        .overall-status.warning .status-icon {
            color: #f59e0b;
        }

        .overall-status.error .status-icon {
            color: #ef4444;
        }

        .overall-status .status-content h3 {
            margin: 0 0 10px 0;
            font-size: 18px;
            font-weight: 600;
        }

        .overall-status .status-content p {
            margin: 0;
            color: var(--text-secondary);
        }

        .results-section {
            margin-bottom: 25px;
        }

        .results-section h3 {
            margin: 0 0 15px 0;
            font-size: 16px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .results-section.success h3 {
            color: #10b981;
        }

        .results-section.warning h3 {
            color: #f59e0b;
        }

        .results-section.error h3 {
            color: #ef4444;
        }

        .items-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px 15px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-secondary);
            border-radius: 6px;
            font-size: 14px;
        }

        .success-item {
            border-left: 4px solid #10b981;
        }

        .warning-item {
            border-left: 4px solid #f59e0b;
        }

        .error-item {
            border-left: 4px solid #ef4444;
        }

        .item i {
            font-size: 14px;
            width: 16px;
            text-align: center;
        }

        .success-item i {
            color: #10b981;
        }

        .warning-item i {
            color: #f59e0b;
        }

        .error-item i {
            color: #ef4444;
        }

        .item span {
            color: var(--text-primary);
        }

        /* SBOM Queue Report Styles */
        .sbom-queue-report {
            font-family: 'Siemens Sans', sans-serif;
            color: var(--text-primary);
            background: var(--bg-card);
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }

        .sbom-queue-report .report-header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid var(--siemens-petrol);
        }

        .sbom-queue-report .report-header h2 {
            color: var(--siemens-petrol);
            margin: 0 0 10px 0;
            font-size: 24px;
            font-weight: 600;
        }

        .sbom-queue-report .report-header .timestamp {
            color: var(--text-secondary);
            font-size: 14px;
            margin: 0;
        }

        .processing-summary {
            margin-bottom: 30px;
        }

        .processing-summary h3 {
            color: var(--text-primary);
            margin-bottom: 20px;
            font-size: 18px;
            font-weight: 600;
        }

        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .summary-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-secondary);
            border-radius: 8px;
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 15px;
            transition: transform 0.2s ease;
        }

        .summary-card:hover {
            transform: translateY(-2px);
        }

        .summary-card.total {
            border-left: 4px solid var(--siemens-petrol);
        }

        .summary-card.success {
            border-left: 4px solid #10b981;
        }

        .summary-card.error {
            border-left: 4px solid #ef4444;
        }

        .card-icon {
            font-size: 24px;
            color: var(--siemens-petrol);
            width: 40px;
            text-align: center;
        }

        .summary-card.success .card-icon {
            color: #10b981;
        }

        .summary-card.error .card-icon {
            color: #ef4444;
        }

        .card-content {
            flex: 1;
        }

        .card-value {
            font-size: 24px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 5px;
        }

        .card-label {
            font-size: 14px;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .sbom-queue-report .overall-status {
            display: flex;
            align-items: center;
            gap: 20px;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }

        .sbom-queue-report .overall-status.success {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid #10b981;
        }

        .sbom-queue-report .overall-status.warning {
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid #f59e0b;
        }

        .sbom-queue-report .overall-status .status-icon {
            font-size: 32px;
        }

        .sbom-queue-report .overall-status.success .status-icon {
            color: #10b981;
        }

        .sbom-queue-report .overall-status.warning .status-icon {
            color: #f59e0b;
        }

        .sbom-queue-report .overall-status .status-content h3 {
            margin: 0 0 10px 0;
            font-size: 18px;
            font-weight: 600;
        }

        .sbom-queue-report .overall-status .status-content p {
            margin: 0;
            color: var(--text-secondary);
        }

        .processing-details {
            margin-bottom: 25px;
        }

        .processing-details h3 {
            margin: 0 0 15px 0;
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .details-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .detail-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px 15px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-secondary);
            border-radius: 6px;
            font-size: 14px;
        }

        .detail-item.success {
            border-left: 4px solid #10b981;
        }

        .detail-item.error {
            border-left: 4px solid #ef4444;
        }

        .detail-item i {
            font-size: 14px;
            width: 16px;
            text-align: center;
        }

        .detail-item.success i {
            color: #10b981;
        }

        .detail-item.error i {
            color: #ef4444;
        }

        .detail-item span {
            color: var(--text-primary);
        }

        .result-section {
            margin: 20px 0;
        }

        .result-content {
            padding: 15px;
            border-radius: 6px;
            font-size: 14px;
        }

        .modal .result-success {
            background: rgba(0, 153, 153, 0.1) !important;
            border: 1px solid var(--siemens-petrol) !important;
            color: var(--text-primary) !important;
            border-radius: 6px !important;
            padding: 15px !important;
            margin: 10px 0 !important;
        }

        .modal .result-error {
            background: rgba(255, 107, 53, 0.1) !important;
            border: 1px solid var(--siemens-orange) !important;
            color: var(--text-primary) !important;
            border-radius: 6px !important;
            padding: 15px !important;
            margin: 10px 0 !important;
        }

        .modal-footer {
            padding: 20px !important;
            border-top: 1px solid var(--border-secondary) !important;
            background: var(--bg-tertiary) !important;
            display: flex !important;
            justify-content: flex-end !important;
            gap: 10px !important;
        }

        .btn {
            padding: 8px 16px;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            font-family: 'Siemens Sans', sans-serif;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
        }

        .modal .btn-primary {
            background: var(--siemens-petrol) !important;
            color: white !important;
            border: 1px solid var(--siemens-petrol) !important;
        }

        .modal .btn-primary:hover {
            background: var(--siemens-petrol-dark) !important;
            transform: translateY(-1px) !important;
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.3) !important;
        }

        .modal .btn-secondary {
            background: #6b7280 !important;
            color: white !important;
            border: 1px solid #6b7280 !important;
        }

        .modal .btn-secondary:hover {
            background: #4b5563 !important;
            transform: translateY(-1px) !important;
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
    </style>
</body>
</html>
