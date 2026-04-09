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
require_once __DIR__ . '/../../services/shell_command_utilities.php';

// Require admin authentication
$auth->requireAuth();
if (!$auth->hasPermission('admin.access')) {
    header('Location: /pages/auth/login.php');
    exit;
}

// Get current user
$user = $auth->getCurrentUser();

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    if ($_GET['ajax'] === 'check_jobs') {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input || !isset($input['jobs'])) {
            echo json_encode(['success' => false, 'error' => 'No jobs provided']);
            exit;
        }
        
        $results = [];
        
        foreach ($input['jobs'] as $job) {
            if (!isset($job['pid']) || !isset($job['log_file'])) {
                $results[] = [
                    'job_id' => $job['job_id'] ?? null,
                    'status' => 'error',
                    'error' => 'Invalid job data'
                ];
                continue;
            }
            
            // Check if process is still running
            $isRunning = ShellCommandUtilities::isProcessRunning($job['pid']);
            
            if ($isRunning) {
                $results[] = [
                    'job_id' => $job['job_id'],
                    'type' => $job['type'] ?? 'unknown',
                    'pid' => $job['pid'],
                    'status' => 'running'
                ];
            } else {
                // Process completed, get results from log file
                $output = ShellCommandUtilities::getCommandOutput($job['log_file']);
                
                if ($output) {
                    $success = (strpos($output, 'completed successfully') !== false ||
                               strpos($output, 'Backup completed') !== false ||
                               strpos($output, 'Restore completed') !== false);
                    
                    $results[] = [
                        'job_id' => $job['job_id'],
                        'type' => $job['type'] ?? 'unknown',
                        'status' => $success ? 'completed' : 'failed',
                        'data' => [
                            'output' => $output
                        ],
                        'error' => $success ? null : 'Operation completed with errors'
                    ];
                } else {
                    $results[] = [
                        'job_id' => $job['job_id'],
                        'type' => $job['type'] ?? 'unknown',
                        'status' => 'failed',
                        'error' => 'No output from command'
                    ];
                }
            }
        }
        
        echo json_encode([
            'success' => true,
            'results' => $results
        ]);
        exit;
    }
}

// Handle backup actions
$action = $_GET['action'] ?? 'list';
$message = '';
$message_type = '';

// Handle messages from redirects
if (isset($_GET['message']) && isset($_GET['msg'])) {
    $message = urldecode($_GET['msg']);
    $message_type = $_GET['message'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    
    switch ($action) {
        case 'create_backup':
            $backup_type = $_POST['backup_type'] ?? 'full';
            $description = $_POST['description'] ?? '';
            
            // Execute backup script (non-blocking)
            $script_path = _ROOT . '/scripts/backup.sh';
            $logFile = _ROOT . '/logs/backup_' . date('Ymd_His') . '.log';
            $result = ShellCommandUtilities::executeShellCommand(
                "$script_path --type $backup_type",
                [
                    'blocking' => false,
                    'log_file' => $logFile
                ]
            );
            
            if (!$result['success']) {
                header('Location: /pages/admin/backup.php?message=error&msg=' . urlencode('Failed to start backup: ' . ($result['error'] ?? 'Unknown error')));
                exit;
            }
            
            // Store job info and description in temp file for later retrieval
            $jobData = [
                'job_id' => uniqid('backup_'),
                'pid' => $result['pid'],
                'log_file' => $result['log_file'],
                'status' => 'running',
                'type' => 'backup',
                'backup_type' => $backup_type,
                'description' => $description,
                'started_at' => time()
            ];
            $jobFile = '/tmp/backup_job_' . $jobData['job_id'] . '.json';
            file_put_contents($jobFile, json_encode($jobData));
            
            // Redirect to a polling page or return JSON if AJAX
            header('Location: /pages/admin/backup.php?message=info&msg=' . urlencode('Backup started in background. Job ID: ' . $jobData['job_id']));
            exit;
            break;
            
        case 'restore_backup':
            $backup_file = $_POST['backup_file'] ?? '';
            if (empty($backup_file)) {
                header('Location: /pages/admin/backup.php?message=error&msg=' . urlencode('Please select a backup file to restore.'));
                exit;
            } else {
                // Execute restore script (non-blocking)
                $script_path = _ROOT . '/scripts/restore.sh';
                $logFile = _ROOT . '/logs/restore_' . date('Ymd_His') . '.log';
                
                // Determine restore type based on backup file name
                $restoreType = '--full'; // Default to full restore
                if (strpos($backup_file, 'dave_db_') !== false) {
                    $restoreType = '--database';
                } elseif (strpos($backup_file, 'dave_config_') !== false) {
                    $restoreType = '--config';
                } elseif (strpos($backup_file, 'dave_uploads_') !== false) {
                    $restoreType = '--uploads';
                }
                
                $result = ShellCommandUtilities::executeShellCommand(
                    "$script_path --file '$backup_file' $restoreType",
                    [
                        'blocking' => false,
                        'log_file' => $logFile
                    ]
                );
                
                if (!$result['success']) {
                    header('Location: /pages/admin/backup.php?message=error&msg=' . urlencode('Failed to start restore: ' . ($result['error'] ?? 'Unknown error')));
                    exit;
                }
                
                // Store job info
                $jobData = [
                    'job_id' => uniqid('restore_'),
                    'pid' => $result['pid'],
                    'log_file' => $result['log_file'],
                    'status' => 'running',
                    'type' => 'restore',
                    'backup_file' => $backup_file,
                    'started_at' => time()
                ];
                $jobFile = '/tmp/restore_job_' . $jobData['job_id'] . '.json';
                file_put_contents($jobFile, json_encode($jobData));
                
                header('Location: /pages/admin/backup.php?message=info&msg=' . urlencode('Restore started in background. Job ID: ' . $jobData['job_id']));
                exit;
            }
            break;
            
        case 'delete_backup':
            $backup_file = $_POST['backup_file'] ?? '';
            if (empty($backup_file)) {
                header('Location: /pages/admin/backup.php?message=error&msg=' . urlencode('No backup file specified.'));
                exit;
            } elseif (!file_exists($backup_file)) {
                header('Location: /pages/admin/backup.php?message=error&msg=' . urlencode('Backup file not found: ' . basename($backup_file)));
                exit;
            } elseif (!is_writable($backup_file)) {
                header('Location: /pages/admin/backup.php?message=error&msg=' . urlencode('Permission denied: Cannot delete backup file.'));
                exit;
            } else {
                if (unlink($backup_file)) {
                    // Also delete associated metadata file if it exists
                    $backup_dir = '/var/backups/dave';
                    $metadata_files = glob($backup_dir . '/backup_metadata_*.json');
                    foreach ($metadata_files as $metadata_file) {
                        $metadata_content = file_get_contents($metadata_file);
                        $metadata = json_decode($metadata_content, true);
                        if ($metadata && isset($metadata['backup_file']) && $metadata['backup_file'] === basename($backup_file)) {
                            unlink($metadata_file);
                            break;
                        }
                    }
                    
                    header('Location: /pages/admin/backup.php?message=success&msg=' . urlencode('Backup deleted successfully: ' . basename($backup_file)));
                    exit;
                } else {
                    header('Location: /pages/admin/backup.php?message=error&msg=' . urlencode('Failed to delete backup file: ' . basename($backup_file)));
                    exit;
                }
            }
            break;
            
        case 'download_backup':
            $backup_file = $_POST['backup_file'] ?? '';
            if (empty($backup_file)) {
                header('Location: /pages/admin/backup.php?message=error&msg=' . urlencode('No backup file specified.'));
                exit;
            }
            
            $backup_path = '/var/backups/dave/' . $backup_file;
            if (!file_exists($backup_path)) {
                header('Location: /pages/admin/backup.php?message=error&msg=' . urlencode('Backup file not found: ' . $backup_file));
                exit;
            }
            
            // Set headers for file download
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . $backup_file . '"');
            header('Content-Length: ' . filesize($backup_path));
            header('Cache-Control: no-cache, must-revalidate');
            header('Pragma: no-cache');
            
            // Output the file
            readfile($backup_path);
            exit;
            break;
    }
}

// Get backup directory
$backup_dir = '/var/backups/dave';
$backups = [];

if (is_dir($backup_dir)) {
    $files = scandir($backup_dir);
    foreach ($files as $file) {
        if ($file !== '.' && $file !== '..' && strpos($file, 'dave_') === 0) {
            $file_path = $backup_dir . '/' . $file;
            
            // Look for description in metadata files
            $description = '';
            $metadata_files = glob($backup_dir . '/backup_metadata_*.json');
            foreach ($metadata_files as $metadata_file) {
                $metadata_content = file_get_contents($metadata_file);
                $metadata = json_decode($metadata_content, true);
                if ($metadata && isset($metadata['backup_file']) && $metadata['backup_file'] === $file) {
                    $description = $metadata['description'] ?? '';
                    break;
                }
            }
            
            $backups[] = [
                'name' => $file,
                'path' => $file_path,
                'size' => filesize($file_path),
                'date' => filemtime($file_path),
                'type' => getBackupType($file),
                'description' => $description
            ];
        }
    }
    
    // Sort by date (newest first)
    usort($backups, function($a, $b) {
        return $b['date'] - $a['date'];
    });
}

function getBackupType($filename) {
    if (strpos($filename, 'dave_db_') === 0) return 'Database';
    if (strpos($filename, 'dave_files_') === 0) return 'Files';
    if (strpos($filename, 'dave_config_') === 0) return 'Configuration';
    if (strpos($filename, 'dave_uploads_') === 0) return 'Uploads';
    if (strpos($filename, 'dave_full_') === 0) return 'Full System';
    return 'Unknown';
}

function formatBytes($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, 2) . ' ' . $units[$pow];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup & Recovery - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .backup-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        
        .stat-card {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            padding: 1rem;
            text-align: center;
        }
        
        .stat-number {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--siemens-petrol, #009999);
            margin-bottom: 0.25rem;
        }
        
        .stat-label {
            color: var(--text-secondary, #cbd5e1);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .backup-table {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            overflow: hidden;
        }
        
        .table-header {
            background: var(--bg-secondary, #0f0f0f);
            padding: 1rem;
            border-bottom: 1px solid var(--border-primary, #333333);
        }
        
        .table-header h3 {
            margin: 0;
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .table-content {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-primary, #333333);
        }
        
        th {
            background: var(--bg-secondary, #0f0f0f);
            color: var(--text-primary, #ffffff);
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        td {
            color: var(--text-secondary, #cbd5e1);
            font-size: 0.875rem;
        }
        
        .backup-type {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .backup-type i {
            color: var(--siemens-petrol, #009999);
            width: 14px;
        }
        
        .backup-description {
            color: var(--text-muted, #94a3b8);
            font-size: 0.8rem;
            line-height: 1.4;
            max-width: 300px;
        }
        
        .backup-size {
            font-weight: 500;
            color: var(--text-primary, #ffffff);
        }
        
        .backup-date {
            color: var(--text-muted, #94a3b8);
        }
        
        .backup-actions {
            display: flex;
            gap: 0.25rem;
        }
        
        .btn-sm {
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
            border-radius: 0.25rem;
        }
        
        .btn-sm.btn-danger {
            background: #ef4444;
            color: white;
            border: 1px solid #ef4444;
        }
        
        .btn-sm.btn-danger:hover {
            background: #dc2626;
            border-color: #dc2626;
        }
        
        .btn-sm.btn-danger i {
            color: white;
        }
        
        /* Styled Alert System */
        .alert-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.6);
            z-index: 2000;
            display: none;
            align-items: center;
            justify-content: center;
        }
        
        .alert-dialog {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            padding: 0;
            max-width: 400px;
            width: 90%;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
        }
        
        .alert-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-primary, #333333);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .alert-icon {
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            font-size: 0.875rem;
        }
        
        .alert-icon.warning {
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
        }
        
        .alert-icon.danger {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
        }
        
        .alert-icon.info {
            background: rgba(0, 153, 153, 0.2);
            color: var(--siemens-petrol, #009999);
        }
        
        .alert-title {
            color: var(--text-primary, #ffffff);
            font-weight: 600;
            font-size: 1rem;
            margin: 0;
        }
        
        .alert-body {
            padding: 1.5rem;
            color: var(--text-secondary, #cbd5e1);
            line-height: 1.5;
        }
        
        .alert-footer {
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--border-primary, #333333);
            display: flex;
            justify-content: flex-end;
            gap: 0.75rem;
        }
        
        .alert-btn {
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            border: none;
        }
        
        .alert-btn-secondary {
            background: var(--bg-secondary, #0f0f0f);
            color: var(--text-primary, #ffffff);
            border: 1px solid var(--border-primary, #333333);
        }
        
        .alert-btn-secondary:hover {
            background: var(--bg-hover, #333333);
        }
        
        .alert-btn-danger {
            background: #ef4444;
            color: white;
        }
        
        .alert-btn-danger:hover {
            background: #dc2626;
        }
        
        .alert-btn-primary {
            background: var(--siemens-petrol, #009999);
            color: white;
        }
        
        .alert-btn-primary:hover {
            background: var(--siemens-petrol-dark, #007777);
        }
        
        .empty-state {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary, #cbd5e1);
        }
        
        .empty-state i {
            font-size: 2rem;
            color: var(--text-muted, #94a3b8);
            margin-bottom: 0.5rem;
        }
        
        .empty-state h3 {
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.5rem;
            font-size: 1rem;
        }
        
        .empty-state p {
            margin-bottom: 1rem;
            font-size: 0.875rem;
        }
        
        .quick-actions {
            display: flex;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }
        
        .action-btn {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.375rem;
            padding: 0.5rem 1rem;
            color: var(--text-primary, #ffffff);
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            font-weight: 500;
            text-decoration: none;
        }
        
        .action-btn:hover {
            border-color: var(--siemens-petrol, #009999);
            background: var(--bg-hover, #333333);
        }
        
        .action-btn i {
            color: var(--siemens-petrol, #009999);
            width: 14px;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
        }
        
        .modal-content {
            background: var(--bg-card, #1a1a1a);
            margin: 10% auto;
            padding: 0;
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            width: 90%;
            max-width: 450px;
        }
        
        .modal-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-primary, #333333);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .modal-header h3 {
            color: var(--text-primary, #ffffff);
            margin: 0;
            font-size: 1rem;
            font-weight: 600;
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-secondary, #cbd5e1);
            font-size: 1.25rem;
            cursor: pointer;
            padding: 0;
            width: 24px;
            height: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .modal-body {
            padding: 1.5rem;
        }
        
        .modal-footer {
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--border-primary, #333333);
            display: flex;
            justify-content: flex-end;
            gap: 0.5rem;
        }
        
        
        /* Loading States */
        .btn.loading {
            opacity: 0.7;
            pointer-events: none;
        }
        
        .btn.loading::after {
            content: '';
            display: inline-block;
            width: 12px;
            height: 12px;
            border: 2px solid transparent;
            border-top: 2px solid currentColor;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-left: 0.5rem;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        
        /* Page Header Container */
        .page-header-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            width: 100%;
        }

        /* Main Content Container */
        .main-content-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 2rem;
            width: 100%;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .page-header-container {
                flex-direction: column;
                align-items: stretch;
                gap: 1rem;
                padding: 0 1rem;
            }
            
            .main-content-container {
                padding: 0 1rem;
            }
            
            .page-actions {
                justify-content: center;
            }
            
            .backup-stats {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .quick-actions {
                flex-direction: column;
            }
            
            .action-btn {
                justify-content: center;
            }
            
            .table-content {
                font-size: 0.75rem;
            }
            
            th, td {
                padding: 0.5rem 0.75rem;
            }
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Page Header -->
        <div class="page-header">
            <div class="page-header-container">
                <div class="page-title">
                    <h1><i class="fas fa-download"></i> Backup & Recovery</h1>
                    <p>System backup and recovery management</p>
                </div>
                <div class="page-actions">
                    <a href="/pages/admin/index.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Back to Admin
                    </a>
                </div>
            </div>
        </div>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="main-content-container">
            <?php if ($message): ?>
                <div class="alert alert-<?php echo $message_type; ?>">
                    <i class="fas fa-<?php echo $message_type === 'success' ? 'check-circle' : 'exclamation-circle'; ?>"></i>
                    <?php echo dave_htmlspecialchars($message); ?>
                </div>
            <?php endif; ?>

            <!-- Backup Statistics -->
            <div class="backup-stats">
                <div class="stat-card">
                    <div class="stat-number"><?php echo count($backups); ?></div>
                    <div class="stat-label">Total Backups</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo formatBytes(array_sum(array_column($backups, 'size'))); ?></div>
                    <div class="stat-label">Total Size</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo count(array_filter($backups, function($b) { return $b['type'] === 'Database'; })); ?></div>
                    <div class="stat-label">Database</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo count(array_filter($backups, function($b) { return $b['type'] === 'Full System'; })); ?></div>
                    <div class="stat-label">Full System</div>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="quick-actions">
                <button class="action-btn" onclick="showCreateBackupModal()">
                    <i class="fas fa-plus"></i>
                    Create Backup
                </button>
                <button class="action-btn" onclick="showRestoreModal()">
                    <i class="fas fa-undo"></i>
                    Restore System
                </button>
                <button class="action-btn" onclick="refreshBackups()">
                    <i class="fas fa-sync-alt"></i>
                    Refresh List
                </button>
            </div>

            <!-- Backup Table -->
            <div class="backup-table">
                <div class="table-header">
                    <h3><i class="fas fa-archive"></i> Available Backups</h3>
                </div>
                
                <?php if (empty($backups)): ?>
                    <div class="empty-state">
                        <i class="fas fa-archive"></i>
                        <h3>No Backups Found</h3>
                        <p>Create your first backup to get started.</p>
                        <button class="btn btn-primary" onclick="showCreateBackupModal()">
                            <i class="fas fa-plus"></i> Create Backup
                        </button>
                    </div>
                <?php else: ?>
                    <div class="table-content">
                        <table>
                            <thead>
                                <tr>
                                    <th>Type</th>
                                    <th>Name</th>
                                    <th>Description</th>
                                    <th>Size</th>
                                    <th>Date</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($backups as $backup): ?>
                                    <tr>
                                        <td>
                                            <div class="backup-type">
                                                <i class="fas fa-<?php echo getBackupIcon($backup['type']); ?>"></i>
                                                <?php echo dave_htmlspecialchars($backup['type']); ?>
                                            </div>
                                        </td>
                                        <td><?php echo dave_htmlspecialchars($backup['name']); ?></td>
                                        <td class="backup-description">
                                            <?php 
                                            if (!empty($backup['description'])) {
                                                echo dave_htmlspecialchars($backup['description']);
                                            } else {
                                                echo getBackupDescription($backup['type']);
                                            }
                                            ?>
                                        </td>
                                        <td class="backup-size"><?php echo formatBytes($backup['size']); ?></td>
                                        <td class="backup-date"><?php echo date('M j, Y g:i A', $backup['date']); ?></td>
                                        <td>
                                            <div class="backup-actions">
                                                <button class="btn btn-sm btn-primary" onclick="restoreBackup('<?php echo dave_htmlspecialchars($backup['name']); ?>')">
                                                    <i class="fas fa-undo"></i>
                                                </button>
                                                <button class="btn btn-sm btn-secondary" onclick="downloadBackup('<?php echo dave_htmlspecialchars($backup['name']); ?>')">
                                                    <i class="fas fa-download"></i>
                                                </button>
                                                <button class="btn btn-sm btn-danger" onclick="deleteBackup('<?php echo dave_htmlspecialchars($backup['name']); ?>')">
                                                    <i class="fas fa-trash"></i>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
            </div>
        </main>
    </div>

    <!-- Create Backup Modal -->
    <div id="createBackupModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-plus"></i> Create New Backup</h3>
                <button class="modal-close" onclick="closeModal('createBackupModal')">&times;</button>
            </div>
            <form method="POST" action="">
                <input type="hidden" name="action" value="create_backup">
                <div class="modal-body">
                    <div class="form-group">
                        <label for="backup_type">Backup Type</label>
                        <select name="backup_type" id="backup_type" required>
                            <option value="full">Full System Backup</option>
                            <option value="database">Database Only</option>
                            <option value="config">Configuration Only</option>
                            <option value="uploads">Uploads Only</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="description">Description (Optional)</label>
                        <textarea name="description" id="description" rows="3" placeholder="Enter a description for this backup..."></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('createBackupModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-plus"></i> Create Backup
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Restore Backup Modal -->
    <div id="restoreModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-undo"></i> Restore System</h3>
                <button class="modal-close" onclick="closeModal('restoreModal')">&times;</button>
            </div>
            <form method="POST" action="">
                <input type="hidden" name="action" value="restore_backup">
                <div class="modal-body">
                    <div class="form-group">
                        <label for="backup_file">Select Backup to Restore</label>
                        <select name="backup_file" id="backup_file" required>
                            <option value="">Select a backup...</option>
                            <?php foreach ($backups as $backup): ?>
                                <option value="<?php echo dave_htmlspecialchars($backup['path']); ?>">
                                    <?php echo dave_htmlspecialchars($backup['name']); ?> 
                                    (<?php echo date('M j, Y g:i A', $backup['date']); ?>)
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle"></i>
                        <strong>Warning:</strong> This will restore the system to the selected backup state. 
                        All current data will be replaced. This action cannot be undone.
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('restoreModal')">Cancel</button>
                    <button type="button" class="btn btn-danger" onclick="confirmRestore()">
                        <i class="fas fa-undo"></i> Restore System
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Styled Alert System -->
    <div id="alertOverlay" class="alert-overlay">
        <div class="alert-dialog">
            <div class="alert-header">
                <div class="alert-icon" id="alertIcon">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <h3 class="alert-title" id="alertTitle">Confirm Action</h3>
            </div>
            <div class="alert-body" id="alertBody">
                Are you sure you want to proceed?
            </div>
            <div class="alert-footer">
                <button class="alert-btn alert-btn-secondary" id="alertCancel">Cancel</button>
                <button class="alert-btn alert-btn-danger" id="alertConfirm">Confirm</button>
            </div>
        </div>
    </div>

    <script>
        // Modal functions
        function showCreateBackupModal() {
            document.getElementById('createBackupModal').style.display = 'block';
        }

        function showRestoreModal() {
            document.getElementById('restoreModal').style.display = 'block';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        function refreshBackups() {
            location.reload();
        }

        function downloadBackup(backupName) {
            // Create a form to submit the download request
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/pages/admin/backup.php';
            
            const actionInput = document.createElement('input');
            actionInput.type = 'hidden';
            actionInput.name = 'action';
            actionInput.value = 'download_backup';
            form.appendChild(actionInput);
            
            const fileInput = document.createElement('input');
            fileInput.type = 'hidden';
            fileInput.name = 'backup_file';
            fileInput.value = backupName;
            form.appendChild(fileInput);
            
            document.body.appendChild(form);
            form.submit();
            document.body.removeChild(form);
        }

        function deleteBackup(backupName) {
            showStyledAlert(
                'danger',
                'Delete Backup',
                `Are you sure you want to delete "${backupName}"? This action cannot be undone.`,
                'Delete',
                () => {
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.innerHTML = `
                        <input type="hidden" name="action" value="delete_backup">
                        <input type="hidden" name="backup_file" value="/var/backups/dave/${backupName}">
                    `;
                    document.body.appendChild(form);
                    form.submit();
                }
            );
        }

        function restoreBackup(backupName) {
            showStyledAlert(
                'warning',
                'Restore Backup',
                `Are you sure you want to restore "${backupName}"? This will replace all current data and cannot be undone.`,
                'Restore',
                () => {
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.innerHTML = `
                        <input type="hidden" name="action" value="restore_backup">
                        <input type="hidden" name="backup_file" value="/var/backups/dave/${backupName}">
                    `;
                    document.body.appendChild(form);
                    form.submit();
                }
            );
        }

        function viewBackupLogs() {
            window.open('/pages/admin/logs.php?filter=backup', '_blank');
        }

        function confirmRestore() {
            const backupFile = document.getElementById('backup_file').value;
            if (!backupFile) {
                showStyledAlert(
                    'warning',
                    'No Backup Selected',
                    'Please select a backup file to restore.',
                    'OK'
                );
                return;
            }
            
            const backupName = backupFile.split('/').pop();
            showStyledAlert(
                'warning',
                'Restore System',
                `Are you sure you want to restore "${backupName}"? This will replace all current data and cannot be undone.`,
                'Restore',
                () => {
                    document.querySelector('#restoreModal form').submit();
                }
            );
        }

        // Styled Alert System
        function showStyledAlert(type, title, message, confirmText = 'OK', onConfirm = null) {
            const overlay = document.getElementById('alertOverlay');
            const icon = document.getElementById('alertIcon');
            const titleEl = document.getElementById('alertTitle');
            const body = document.getElementById('alertBody');
            const cancelBtn = document.getElementById('alertCancel');
            const confirmBtn = document.getElementById('alertConfirm');
            
            // Set icon and colors based on type
            let iconClass, iconBg, confirmBtnClass;
            switch(type) {
                case 'warning':
                    iconClass = 'fas fa-exclamation-triangle';
                    iconBg = 'warning';
                    confirmBtnClass = 'alert-btn-danger';
                    break;
                case 'danger':
                    iconClass = 'fas fa-trash';
                    iconBg = 'danger';
                    confirmBtnClass = 'alert-btn-danger';
                    break;
                case 'info':
                    iconClass = 'fas fa-info-circle';
                    iconBg = 'info';
                    confirmBtnClass = 'alert-btn-primary';
                    break;
                default:
                    iconClass = 'fas fa-question-circle';
                    iconBg = 'info';
                    confirmBtnClass = 'alert-btn-primary';
            }
            
            // Update elements
            icon.className = `alert-icon ${iconBg}`;
            icon.innerHTML = `<i class="${iconClass}"></i>`;
            titleEl.textContent = title;
            body.textContent = message;
            confirmBtn.textContent = confirmText;
            confirmBtn.className = `alert-btn ${confirmBtnClass}`;
            
            // Show/hide cancel button based on whether there's a callback
            if (onConfirm) {
                cancelBtn.style.display = 'block';
                confirmBtn.onclick = () => {
                    overlay.style.display = 'none';
                    onConfirm();
                };
            } else {
                cancelBtn.style.display = 'none';
                confirmBtn.onclick = () => {
                    overlay.style.display = 'none';
                };
            }
            
            // Cancel button
            cancelBtn.onclick = () => {
                overlay.style.display = 'none';
            };
            
            // Show overlay
            overlay.style.display = 'flex';
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        }

        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {
            // Add loading states to buttons
            document.querySelectorAll('.btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    if (this.type !== 'submit') {
                        this.classList.add('loading');
                        setTimeout(() => {
                            this.classList.remove('loading');
                        }, 1000);
                    }
                });
            });
            
            // Clear form data after successful operations to prevent browser warnings
            if (window.history.replaceState) {
                // Replace the current history entry to prevent back button issues
                window.history.replaceState({}, document.title, window.location.pathname);
            }
            
            // Clear any form data that might cause browser warnings
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', function() {
                    // Clear form after successful submission
                    setTimeout(() => {
                        form.reset();
                    }, 100);
                });
            });
        });
    </script>
    
    <!-- Common Dashboard JavaScript -->
    <script src="/assets/js/dashboard-common.js"></script>
</body>
</html>

<?php
function getBackupIcon($type) {
    switch ($type) {
        case 'Database': return 'database';
        case 'Files': return 'folder';
        case 'Configuration': return 'cog';
        case 'Uploads': return 'upload';
        case 'Full System': return 'server';
        default: return 'archive';
    }
}

function getBackupDescription($type) {
    switch ($type) {
        case 'Database': return 'PostgreSQL database dump with all tables, data, and schema';
        case 'Files': return 'Application files and code (version controlled)';
        case 'Configuration': return 'Application settings, database config, and environment files';
        case 'Uploads': return 'User-uploaded files, reports, SBOMs, and scan results';
        case 'Full System': return 'Complete system backup including database, config, and uploads (application files excluded - version controlled)';
        default: return 'System backup archive';
    }
}
?>
