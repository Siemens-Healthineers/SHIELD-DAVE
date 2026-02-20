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
$auth->requirePermission('vulnerabilities.view');

$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Get queue statistics
$statsSql = "SELECT 
    COUNT(*) FILTER (WHERE status = 'Queued') as queued_count,
    COUNT(*) FILTER (WHERE status = 'Processing') as processing_count,
    COUNT(*) FILTER (WHERE status = 'Completed') as completed_count,
    COUNT(*) FILTER (WHERE status = 'Failed') as failed_count,
    AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) FILTER (WHERE status = 'Completed') as avg_duration,
    COUNT(*) FILTER (WHERE status = 'Completed' AND completed_at > NOW() - INTERVAL '24 hours') as completed_today
FROM sbom_evaluation_queue";
$statsStmt = $db->query($statsSql);
$stats = $statsStmt->fetch(PDO::FETCH_ASSOC);

// Get queue items
$queueSql = "SELECT 
    q.queue_id,
    q.sbom_id,
    q.device_id,
    q.priority,
    q.status,
    q.queued_at,
    q.started_at,
    q.completed_at,
    q.vulnerabilities_found,
    q.vulnerabilities_stored,
    q.components_evaluated,
    q.error_message,
    q.retry_count,
    a.hostname,
    md.brand_name,
    md.model_number,
    s.file_name,
    EXTRACT(EPOCH FROM (COALESCE(q.completed_at, CURRENT_TIMESTAMP) - q.started_at)) as duration_seconds
FROM sbom_evaluation_queue q
JOIN medical_devices md ON q.device_id = md.device_id
JOIN assets a ON md.asset_id = a.asset_id
JOIN sboms s ON q.sbom_id = s.sbom_id
ORDER BY 
    CASE q.status
        WHEN 'Processing' THEN 1
        WHEN 'Queued' THEN 2
        WHEN 'Failed' THEN 3
        WHEN 'Completed' THEN 4
    END,
    q.priority ASC,
    q.queued_at DESC
LIMIT 100";
$queueStmt = $db->query($queueSql);
$queueItems = $queueStmt->fetchAll(PDO::FETCH_ASSOC);

// Get recent evaluation logs
$logsSql = "SELECT 
    l.log_id,
    l.evaluation_started_at,
    l.evaluation_completed_at,
    l.evaluation_duration_seconds,
    l.components_evaluated,
    l.vulnerabilities_found,
    l.vulnerabilities_stored,
    l.nvd_api_calls_made,
    l.nvd_api_failures,
    l.status,
    l.error_message,
    a.hostname,
    md.brand_name,
    md.model_number,
    s.file_name
FROM sbom_evaluation_logs l
JOIN medical_devices md ON l.device_id = md.device_id
JOIN assets a ON md.asset_id = a.asset_id
JOIN sboms s ON l.sbom_id = s.sbom_id
ORDER BY l.evaluation_started_at DESC
LIMIT 50";
$logsStmt = $db->query($logsSql);
$logs = $logsStmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SBOM Evaluation Queue - </title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="/assets/css/style.css">
    <style>
        .queue-container {
            max-width: 1400px;
            margin: 2rem auto;
            padding: 0 2rem;
        }

        .queue-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }

        .queue-title {
            font-size: 2rem;
            color: var(--text-primary);
            font-weight: 600;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            padding: 1.5rem;
        }

        .stat-card .stat-icon {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }

        .stat-card .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            margin: 0.5rem 0;
        }

        .stat-card .stat-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
        }

        .stat-card.queued { color: #3b82f6; }
        .stat-card.processing { color: #f59e0b; }
        .stat-card.completed { color: #10b981; }
        .stat-card.failed { color: #ef4444; }

        .section-card {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }

        .section-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--text-primary);
        }

        .queue-table {
            width: 100%;
            border-collapse: collapse;
        }

        .queue-table th {
            background: var(--bg-secondary);
            color: var(--text-secondary);
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            border-bottom: 2px solid var(--border-primary);
        }

        .queue-table td {
            padding: 0.75rem;
            border-bottom: 1px solid var(--border-primary);
            color: var(--text-primary);
        }

        .queue-table tr:hover {
            background: var(--bg-hover);
        }

        .status-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            display: inline-block;
        }

        .status-badge.queued { background: #3b82f620; color: #3b82f6; }
        .status-badge.processing { background: #f59e0b20; color: #f59e0b; }
        .status-badge.completed { background: #10b98120; color: #10b981; }
        .status-badge.failed { background: #ef444420; color: #ef4444; }

        .priority-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.7rem;
            font-weight: 600;
            background: var(--bg-secondary);
            color: var(--text-secondary);
        }

        .refresh-btn {
            background: var(--siemens-petrol);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }

        .refresh-btn:hover {
            background: var(--siemens-petrol-dark);
            transform: translateY(-1px);
        }

        .empty-state {
            text-align: center;
            padding: 3rem;
            color: var(--text-secondary);
        }

        .empty-state i {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        .device-info {
            display: flex;
            flex-direction: column;
        }

        .device-name {
            font-weight: 600;
            color: var(--text-primary);
        }

        .device-model {
            font-size: 0.85rem;
            color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <?php include __DIR__ . '/../components/header.php'; ?>

    <div class="queue-container">
        <div class="queue-header">
            <h1 class="queue-title">
                <i class="fas fa-tasks"></i> SBOM Evaluation Queue
            </h1>
            <button class="refresh-btn" onclick="location.reload()">
                <i class="fas fa-sync-alt"></i> Refresh
            </button>
        </div>

        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card queued">
                <div class="stat-icon"><i class="fas fa-clock"></i></div>
                <div class="stat-value"><?php echo $stats['queued_count'] ?? 0; ?></div>
                <div class="stat-label">Queued</div>
            </div>
            
            <div class="stat-card processing">
                <div class="stat-icon"><i class="fas fa-spinner"></i></div>
                <div class="stat-value"><?php echo $stats['processing_count'] ?? 0; ?></div>
                <div class="stat-label">Processing</div>
            </div>
            
            <div class="stat-card completed">
                <div class="stat-icon"><i class="fas fa-check-circle"></i></div>
                <div class="stat-value"><?php echo $stats['completed_count'] ?? 0; ?></div>
                <div class="stat-label">Completed</div>
            </div>
            
            <div class="stat-card failed">
                <div class="stat-icon"><i class="fas fa-exclamation-triangle"></i></div>
                <div class="stat-value"><?php echo $stats['failed_count'] ?? 0; ?></div>
                <div class="stat-label">Failed</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon"><i class="fas fa-clock"></i></div>
                <div class="stat-value"><?php echo $stats['avg_duration'] ? round($stats['avg_duration']) . 's' : 'N/A'; ?></div>
                <div class="stat-label">Avg Duration</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon"><i class="fas fa-calendar-day"></i></div>
                <div class="stat-value"><?php echo $stats['completed_today'] ?? 0; ?></div>
                <div class="stat-label">Today</div>
            </div>
        </div>

        <!-- Queue Items -->
        <div class="section-card">
            <h2 class="section-title">
                <i class="fas fa-list"></i> Evaluation Queue
            </h2>
            
            <?php if (empty($queueItems)): ?>
                <div class="empty-state">
                    <i class="fas fa-inbox"></i>
                    <p>No items in queue</p>
                </div>
            <?php else: ?>
                <div style="overflow-x: auto;">
                    <table class="queue-table">
                        <thead>
                            <tr>
                                <th>Device</th>
                                <th>SBOM File</th>
                                <th>Priority</th>
                                <th>Status</th>
                                <th>Queued</th>
                                <th>Duration</th>
                                <th>Components</th>
                                <th>Vulnerabilities</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($queueItems as $item): ?>
                                <tr>
                                    <td>
                                        <div class="device-info">
                                            <span class="device-name"><?php echo dave_htmlspecialchars($item['hostname']); ?></span>
                                            <span class="device-model"><?php echo dave_htmlspecialchars($item['brand_name'] . ' ' . $item['model_number']); ?></span>
                                        </div>
                                    </td>
                                    <td><?php echo dave_htmlspecialchars($item['file_name']); ?></td>
                                    <td>
                                        <span class="priority-badge">P<?php echo $item['priority']; ?></span>
                                    </td>
                                    <td>
                                        <span class="status-badge <?php echo strtolower($item['status']); ?>">
                                            <?php echo $item['status']; ?>
                                        </span>
                                    </td>
                                    <td><?php echo date('M j, Y H:i', strtotime($item['queued_at'])); ?></td>
                                    <td>
                                        <?php 
                                        if ($item['status'] == 'Completed' && $item['duration_seconds']) {
                                            echo round($item['duration_seconds']) . 's';
                                        } elseif ($item['status'] == 'Processing' && $item['started_at']) {
                                            $elapsed = time() - strtotime($item['started_at']);
                                            echo round($elapsed) . 's';
                                        } else {
                                            echo '-';
                                        }
                                        ?>
                                    </td>
                                    <td><?php echo $item['components_evaluated'] ?: '-'; ?></td>
                                    <td>
                                        <?php if ($item['vulnerabilities_found']): ?>
                                            <span style="color: var(--siemens-orange);">
                                                <i class="fas fa-shield-alt"></i> <?php echo $item['vulnerabilities_found']; ?>
                                            </span>
                                        <?php else: ?>
                                            -
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($item['error_message']): ?>
                                            <i class="fas fa-exclamation-circle" style="color: var(--error-red);" 
                                               title="<?php echo dave_htmlspecialchars($item['error_message']); ?>"></i>
                                        <?php endif; ?>
                                        <?php if ($item['retry_count'] > 0): ?>
                                            <span style="color: var(--text-secondary); font-size: 0.8rem;">
                                                (Retry: <?php echo $item['retry_count']; ?>)
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>

        <!-- Recent Evaluation Logs -->
        <div class="section-card">
            <h2 class="section-title">
                <i class="fas fa-history"></i> Recent Evaluations
            </h2>
            
            <?php if (empty($logs)): ?>
                <div class="empty-state">
                    <i class="fas fa-clipboard-list"></i>
                    <p>No evaluation logs yet</p>
                </div>
            <?php else: ?>
                <div style="overflow-x: auto;">
                    <table class="queue-table">
                        <thead>
                            <tr>
                                <th>Device</th>
                                <th>SBOM File</th>
                                <th>Started</th>
                                <th>Duration</th>
                                <th>Components</th>
                                <th>Vulnerabilities</th>
                                <th>API Calls</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($logs as $log): ?>
                                <tr>
                                    <td>
                                        <div class="device-info">
                                            <span class="device-name"><?php echo dave_htmlspecialchars($log['hostname']); ?></span>
                                            <span class="device-model"><?php echo dave_htmlspecialchars($log['brand_name'] . ' ' . $log['model_number']); ?></span>
                                        </div>
                                    </td>
                                    <td><?php echo dave_htmlspecialchars($log['file_name']); ?></td>
                                    <td><?php echo date('M j, Y H:i', strtotime($log['evaluation_started_at'])); ?></td>
                                    <td><?php echo $log['evaluation_duration_seconds'] . 's'; ?></td>
                                    <td><?php echo $log['components_evaluated']; ?></td>
                                    <td>
                                        <span style="color: var(--siemens-orange);">
                                            <?php echo $log['vulnerabilities_found']; ?> found / <?php echo $log['vulnerabilities_stored']; ?> stored
                                        </span>
                                    </td>
                                    <td>
                                        <?php echo $log['nvd_api_calls_made']; ?>
                                        <?php if ($log['nvd_api_failures'] > 0): ?>
                                            <span style="color: var(--error-red);">
                                                (<?php echo $log['nvd_api_failures']; ?> failed)
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <span class="status-badge <?php echo strtolower($log['status']); ?>">
                                            <?php echo $log['status']; ?>
                                        </span>
                                        <?php if ($log['error_message']): ?>
                                            <i class="fas fa-info-circle" style="color: var(--text-secondary); cursor: help;" 
                                               title="<?php echo dave_htmlspecialchars($log['error_message']); ?>"></i>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>

