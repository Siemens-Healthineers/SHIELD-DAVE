<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
/**
 * Recall Dashboard for Device Assessment and Vulnerability Exposure ()
 * FDA recall monitoring and management interface
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
        case 'get_recall_stats':
            $sql = "SELECT 
                COUNT(DISTINCT r.recall_id) as total_recalls,
                COUNT(DISTINCT CASE WHEN r.recall_status = 'Active' THEN r.recall_id END) as active_recalls,
                COUNT(DISTINCT drl.device_id) as affected_devices,
                COUNT(DISTINCT CASE WHEN drl.remediation_status = 'Open' THEN drl.device_id END) as open_remediations,
                COUNT(DISTINCT CASE WHEN r.recall_date > CURRENT_DATE - INTERVAL '30 days' THEN r.recall_id END) as recent_recalls
                FROM recalls r
                LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
                    AND (drl.remediation_status IS NULL OR drl.remediation_status <> 'Resolved')";
            
            $stmt = $db->query($sql);
            $stats = $stmt->fetch();
            
            echo json_encode($stats);
            exit;
            
        case 'get_recall_list':
            $page = intval($_GET['page'] ?? 1);
            $limit = intval($_GET['limit'] ?? 25);
            $offset = ($page - 1) * $limit;
            $status = $_GET['status'] ?? '';
            $classification = $_GET['classification'] ?? '';
            
            // Build filters
            $filters = [];
            $params = [];
            
            if (!empty($status)) {
                $filters[] = "r.recall_status = ?";
                $params[] = $status;
            }
            
            if (!empty($classification)) {
                $filters[] = "r.recall_classification = ?";
                $params[] = $classification;
            }
            
            $whereClause = !empty($filters) ? 'WHERE ' . implode(' AND ', $filters) : '';
            
            // Get recalls
            $sql = "SELECT 
                r.recall_id,
                r.fda_recall_number,
                r.recall_date,
                r.product_description,
                r.reason_for_recall,
                r.manufacturer_name,
                r.recall_classification,
                r.recall_status,
                COUNT(DISTINCT drl.device_id) as affected_devices,
                COUNT(DISTINCT CASE WHEN drl.remediation_status = 'Open' THEN drl.device_id END) as open_remediations
                FROM recalls r
                LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
                    AND (drl.remediation_status IS NULL OR drl.remediation_status <> 'Resolved')
                $whereClause
                GROUP BY r.recall_id, r.fda_recall_number, r.recall_date, r.product_description, 
                         r.reason_for_recall, r.manufacturer_name, r.recall_classification, r.recall_status
                ORDER BY r.recall_date DESC
                LIMIT ? OFFSET ?";
            
            $params[] = $limit;
            $params[] = $offset;
            $stmt = $db->query($sql, $params);
            $recalls = $stmt->fetchAll();
            
            // Get total count
            $countSql = "SELECT COUNT(DISTINCT r.recall_id) 
                        FROM recalls r
                        LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
                        $whereClause";
            $countStmt = $db->query($countSql, array_slice($params, 0, -2));
            $total = $countStmt->fetch()['count'];
            
            echo json_encode([
                'recalls' => $recalls,
                'total' => $total,
                'page' => $page,
                'limit' => $limit,
                'pages' => ceil($total / $limit)
            ]);
            exit;
            
        case 'get_device_recalls':
            $deviceId = $_GET['device_id'] ?? '';
            
            if (empty($deviceId)) {
                echo json_encode(['error' => 'Device ID required']);
                exit;
            }
            
            $sql = "SELECT 
                r.recall_id,
                r.fda_recall_number,
                r.recall_date,
                r.product_description,
                r.reason_for_recall,
                r.recall_classification,
                drl.remediation_status,
                drl.remediation_notes,
                drl.created_at as linked_at
                FROM device_recalls_link drl
                JOIN recalls r ON drl.recall_id = r.recall_id
                WHERE drl.device_id = ?
                ORDER BY r.recall_date DESC";
            
            $stmt = $db->query($sql, [$deviceId]);
            $recalls = $stmt->fetchAll();
            
            echo json_encode(['recalls' => $recalls]);
            exit;
            
        case 'check_new_recalls':
            // Suppress PHP notices and warnings for clean JSON output
            $old_error_reporting = error_reporting(E_ERROR | E_PARSE);
            
            // Log the request for debugging
            error_log('AJAX check_new_recalls request received from user: ' . ($user['username'] ?? 'unknown'));
            
            if (!$auth->hasPermission('recalls.manage')) {
                error_log('Permission denied for user: ' . ($user['username'] ?? 'unknown'));
                error_reporting($old_error_reporting);
                echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                exit;
            }
            
            try {
                // Use our PHP-based recall import system instead of Python
                require_once __DIR__ . '/../../scripts/import_recalls.php';
                require_once __DIR__ . '/../../scripts/match_recalls_to_devices.php';
                
                // Import recent recalls (last 7 days)
                $importer = new RecallImporter();
                $importResult = $importer->importRecalls(7, 50);
                
                $newRecalls = 0;
                $matchedDevices = 0;
                
                if ($importResult['success']) {
                    $newRecalls = $importResult['imported'];
                    
                    // If we imported new recalls, run device matching
                    if ($newRecalls > 0) {
                        $matcher = new RecallDeviceMatcher();
                        $matchResult = $matcher->matchRecallsToDevices();
                        
                        if ($matchResult['success']) {
                            $matchedDevices = $matchResult['matched'];
                        }
                    }
                }
                
                // Log the action
                $auth->logUserAction($user['user_id'], 'recall_check', 'recalls', null, [
                    'new_recalls' => $newRecalls,
                    'matched_devices' => $matchedDevices
                ]);
                
                echo json_encode([
                    'success' => true,
                    'results' => [
                        'new_recalls' => $newRecalls,
                        'matched_devices' => $matchedDevices,
                        'alerts_created' => 0 // TODO: Implement alert system
                    ]
                ]);
                
            } catch (Exception $e) {
                error_log('Recall check error: ' . $e->getMessage());
                error_log('Stack trace: ' . $e->getTraceAsString());
                error_reporting($old_error_reporting);
                echo json_encode(['success' => false, 'message' => 'Recall check failed: ' . $e->getMessage()]);
            }
            
            // Restore error reporting
            error_reporting($old_error_reporting);
            exit;
            
        case 'update_remediation':
            if (!$auth->hasPermission('recalls.manage')) {
                echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                exit;
            }
            
            $linkId = $_POST['link_id'] ?? '';
            $status = $_POST['status'] ?? '';
            $notes = $_POST['notes'] ?? '';
            
            if (empty($linkId) || empty($status)) {
                echo json_encode(['success' => false, 'message' => 'Missing required parameters']);
                exit;
            }
            
            $sql = "UPDATE device_recalls_link 
                    SET remediation_status = ?, remediation_notes = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE link_id = ?";
            
            $stmt = $db->prepare($sql);
            $result = $stmt->execute([$status, $notes, $linkId]);
            
            if ($result) {
                echo json_encode(['success' => true, 'message' => 'Remediation status updated']);
            } else {
                echo json_encode(['success' => false, 'message' => 'Failed to update status']);
            }
            exit;
    }
}

// Get recall statistics
$stats = [
    'total_recalls' => 0,
    'active_recalls' => 0,
    'affected_devices' => 0,
    'open_remediations' => 0,
    'recent_recalls' => 0
];

$sql = "SELECT 
    COUNT(DISTINCT r.recall_id) FILTER (WHERE drl.device_id IS NOT NULL) as total_recalls,
    COUNT(DISTINCT r.recall_id) FILTER (WHERE r.recall_status = 'Active' AND drl.device_id IS NOT NULL) as active_recalls,
    COUNT(DISTINCT drl.device_id) as affected_devices,
    COUNT(DISTINCT CASE WHEN drl.remediation_status = 'Open' THEN drl.device_id END) as open_remediations,
    COUNT(DISTINCT r.recall_id) FILTER (WHERE drl.device_id IS NOT NULL AND r.recall_date > CURRENT_DATE - INTERVAL '30 days') as recent_recalls
    FROM recalls r
    LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
        AND (drl.remediation_status IS NULL OR drl.remediation_status <> 'Resolved')";
$stmt = $db->query($sql);
$stats = array_merge($stats, $stmt->fetch());

// Get recent recalls
$sql = "SELECT 
    r.recall_id,
    r.fda_recall_number,
    r.recall_date,
    r.product_description,
    r.reason_for_recall,
    r.manufacturer_name,
    r.recall_classification,
    COUNT(DISTINCT drl.device_id) as affected_devices
    FROM recalls r
    LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
    GROUP BY r.recall_id, r.fda_recall_number, r.recall_date, r.product_description, 
             r.reason_for_recall, r.manufacturer_name, r.recall_classification
    ORDER BY r.recall_date DESC
    LIMIT 10";
$stmt = $db->query($sql);
$recentRecalls = $stmt->fetchAll();

// Get devices with most recalls
$sql = "SELECT 
    md.device_id,
    a.hostname,
    a.ip_address,
    a.asset_tag,
    a.asset_type,
    a.manufacturer,
    a.model,
    md.brand_name,
    md.model_number,
    md.manufacturer_name,
    -- Build device name with fallback hierarchy (prioritize medical device info)
    CASE 
        WHEN md.brand_name IS NOT NULL AND md.brand_name != '' THEN 
            md.brand_name || 
            CASE WHEN md.model_number IS NOT NULL AND md.model_number != '' THEN ' ' || md.model_number ELSE '' END ||
            CASE WHEN md.manufacturer_name IS NOT NULL AND md.manufacturer_name != '' THEN ' (' || md.manufacturer_name || ')' ELSE '' END
        WHEN md.device_description IS NOT NULL AND md.device_description != '' THEN md.device_description
        WHEN a.hostname IS NOT NULL AND a.hostname != '' THEN a.hostname
        WHEN a.asset_tag IS NOT NULL AND a.asset_tag != '' THEN a.asset_tag
        WHEN a.asset_type IS NOT NULL THEN a.asset_type || ' ' || COALESCE(a.manufacturer, '') || ' ' || COALESCE(a.model, '')
        ELSE 'Unidentified Device'
    END as device_name,
    COUNT(drl.recall_id) as recall_count,
    COUNT(CASE WHEN drl.remediation_status = 'Open' THEN 1 END) as open_recalls
    FROM medical_devices md
    JOIN assets a ON md.asset_id = a.asset_id
    LEFT JOIN device_recalls_link drl ON md.device_id = drl.device_id
    LEFT JOIN recalls r ON drl.recall_id = r.recall_id
    GROUP BY md.device_id, a.hostname, a.ip_address, a.asset_tag, a.asset_type, a.manufacturer, a.model, 
             md.brand_name, md.model_number, md.manufacturer_name, md.device_description
    HAVING COUNT(drl.recall_id) > 0
    ORDER BY recall_count DESC
    LIMIT 10";
$stmt = $db->query($sql);
$devicesWithRecalls = $stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recall Dashboard - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="/assets/css/recalls.css">
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
                    <h1><i class="fas fa-exclamation-triangle"></i> Recall Dashboard</h1>
                    <p>Monitor FDA recalls and manage device remediation</p>
                </div>
                <div class="page-actions">
                    <?php if ($auth->hasPermission('recalls.manage')): ?>
                    <button type="button" id="checkRecalls" class="btn btn-primary">
                        <i class="fas fa-sync"></i>
                        Check New Recalls
                    </button>
                    <?php endif; ?>
                    <a href="/pages/recalls/list.php" class="btn btn-secondary">
                        <i class="fas fa-list"></i>
                        View All Recalls
                    </a>
                    <a href="/pages/recalls/remediation.php" class="btn btn-secondary">
                        <i class="fas fa-tools"></i>
                        Manage Remediation
                    </a>
                </div>
            </div>

            <!-- Recall Statistics -->
            <section class="metrics-section">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Total Recalls</h3>
                            <div class="metric-value"><?php echo number_format($stats['total_recalls']); ?></div>
                            <div class="metric-detail">
                                <span class="active"><?php echo number_format($stats['active_recalls']); ?> active</span>
                            </div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon warning">
                            <i class="fas fa-server"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Affected Devices</h3>
                            <div class="metric-value"><?php echo number_format($stats['affected_devices']); ?></div>
                            <div class="metric-detail">
                                <span class="open"><?php echo number_format($stats['open_remediations']); ?> open</span>
                            </div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon info">
                            <i class="fas fa-clock"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Recent Recalls</h3>
                            <div class="metric-value"><?php echo number_format($stats['recent_recalls']); ?></div>
                            <div class="metric-detail">Last 30 days</div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon success">
                            <i class="fas fa-check-circle"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Remediation Rate</h3>
                            <div class="metric-value">
                                <?php 
                                $total = $stats['affected_devices'];
                                $open = $stats['open_remediations'];
                                $rate = $total > 0 ? round((($total - $open) / $total) * 100) : 100;
                                echo $rate . '%';
                                ?>
                            </div>
                            <div class="metric-detail">Devices remediated</div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Dashboard Grid -->
            <section class="dashboard-grid">
                <!-- Recent Recalls -->
                <div class="dashboard-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-exclamation-triangle"></i> Recent Recalls</h3>
                        <a href="/pages/recalls/list.php" class="widget-action">View All</a>
                    </div>
                    <div class="widget-content">
                        <?php if (empty($recentRecalls)): ?>
                            <div class="empty-state">
                                <i class="fas fa-shield-alt"></i>
                                <p>No recalls found</p>
                            </div>
                        <?php else: ?>
                            <div class="recall-list">
                                <?php foreach ($recentRecalls as $recall): ?>
                                    <div class="recall-item">
                                        <div class="recall-info">
                                            <div class="recall-number"><?php echo dave_htmlspecialchars($recall['fda_recall_number']); ?></div>
                                            <div class="recall-description"><?php echo dave_htmlspecialchars(substr($recall['product_description'], 0, 100)); ?>...</div>
                                            <div class="recall-meta">
                                                <?php echo dave_htmlspecialchars($recall['manufacturer_name']); ?> • 
                                                <?php echo date('M j, Y', strtotime($recall['recall_date'])); ?> • 
                                                <?php echo $recall['affected_devices']; ?> devices
                                            </div>
                                        </div>
                                        <div class="recall-classification">
                                            <span class="classification-badge <?php echo strtolower($recall['recall_classification']); ?>">
                                                <?php echo $recall['recall_classification']; ?>
                                            </span>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Devices with Most Recalls -->
                <div class="dashboard-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-server"></i> Most Affected Devices</h3>
                        <a href="/pages/assets/manage.php" class="widget-action">View Assets</a>
                    </div>
                    <div class="widget-content">
                        <?php if (empty($devicesWithRecalls)): ?>
                            <div class="empty-state">
                                <i class="fas fa-check-circle"></i>
                                <p>No devices affected by recalls</p>
                            </div>
                        <?php else: ?>
                            <div class="device-list">
                                <?php foreach ($devicesWithRecalls as $device): ?>
                                    <div class="device-item">
                                        <div class="device-info">
                                            <div class="device-name"><?php echo dave_htmlspecialchars($device['device_name'] ?? 'Unidentified Device'); ?></div>
                                            <div class="device-details">
                                                <?php if (!empty($device['brand_name'])): ?>
                                                    <?php echo dave_htmlspecialchars($device['brand_name']); ?>
                                                    <?php if (!empty($device['model_number'])): ?>
                                                        • <?php echo dave_htmlspecialchars($device['model_number']); ?>
                                                    <?php endif; ?>
                                                <?php elseif (!empty($device['hostname'])): ?>
                                                    <?php echo dave_htmlspecialchars($device['hostname']); ?>
                                                    <?php if (!empty($device['ip_address'])): ?>
                                                        • <?php echo dave_htmlspecialchars($device['ip_address']); ?>
                                                    <?php endif; ?>
                                                <?php else: ?>
                                                    Device ID: <?php echo dave_htmlspecialchars($device['device_id'] ?? 'N/A'); ?>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                        <div class="device-recalls">
                                            <div class="recall-count"><?php echo $device['recall_count']; ?> total</div>
                                            <div class="recall-breakdown">
                                                <span class="open"><?php echo $device['open_recalls']; ?> Open</span>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Recall Classification Chart -->
                <div class="dashboard-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-chart-pie"></i> Recall Classifications</h3>
                    </div>
                    <div class="widget-content">
                        <div class="classification-chart">
                            <?php
                            $sql = "SELECT recall_classification, COUNT(*) as count 
                                    FROM recalls 
                                    WHERE recall_status = 'Active'
                                    GROUP BY recall_classification";
                            $stmt = $db->query($sql);
                            $classifications = $stmt->fetchAll();
                            
                            $total = array_sum(array_column($classifications, 'count'));
                            ?>
                            
                            <?php foreach ($classifications as $class): ?>
                                <div class="classification-item">
                                    <div class="classification-label"><?php echo $class['recall_classification']; ?></div>
                                    <div class="classification-bar">
                                        <div class="classification-fill <?php echo strtolower($class['recall_classification']); ?>" 
                                             style="width: <?php echo ($class['count'] / max($total, 1)) * 100; ?>%"></div>
                                    </div>
                                    <div class="classification-value"><?php echo $class['count']; ?></div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>

                <!-- Recall Trends -->
                <div class="dashboard-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-chart-line"></i> Recall Trends</h3>
                    </div>
                    <div class="widget-content">
                        <div class="trends-placeholder">
                            <i class="fas fa-chart-line"></i>
                            <p>Recall trends over time</p>
                            <small>Chart visualization coming soon</small>
                        </div>
                    </div>
                </div>
            </section>
        </main>
    </div>

    <script>
        // Recall Dashboard JavaScript
        document.addEventListener('DOMContentLoaded', function() {
            setupEventListeners();
        });

        function setupEventListeners() {
            // Check recalls button
            const checkBtn = document.getElementById('checkRecalls');
            if (checkBtn) {
                checkBtn.addEventListener('click', checkNewRecalls);
            }
        }

        function checkNewRecalls() {
            const btn = document.getElementById('checkRecalls');
            const originalText = btn.innerHTML;
            
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking...';
            btn.disabled = true;
            
            fetch(window.location.pathname + '?ajax=check_new_recalls', {
                method: 'GET',
                credentials: 'same-origin'
            })
            .then(response => {
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                return response.text().then(text => {
                    try {
                        return JSON.parse(text);
                    } catch (e) {
                        console.error('JSON parse error:', e);
                        console.error('Response text:', text);
                        throw new Error('Invalid JSON response: ' + text.substring(0, 100));
                    }
                });
            })
            .then(data => {
                if (data.success) {
                    showNotification(`Found ${data.results.new_recalls} new recalls, ${data.results.matched_devices} devices affected`, 'success');
                    // Refresh the page to show updated data
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showNotification(data.message || 'Recall check failed', 'error');
                }
            })
            .catch(error => {
                console.error('Error checking recalls:', error);
                showNotification('Error checking recalls: ' + error.message, 'error');
            })
            .finally(() => {
                btn.innerHTML = originalText;
                btn.disabled = false;
            });
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
    </script>
    <!-- Common Dashboard JavaScript -->
    <script src="/assets/js/dashboard-common.js"></script>
</body>
</html>
