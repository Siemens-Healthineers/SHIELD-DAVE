<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Initialize unified authentication
$unifiedAuth = new UnifiedAuth();

// Authenticate user (supports both session and API key)
if (!$unifiedAuth->authenticate()) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'UNAUTHORIZED',
            'message' => 'Authentication required'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

// Get authenticated user
$user = $unifiedAuth->getCurrentUser();
// Check if user has permission to access this resource
$unifiedAuth->requirePermission('system', 'read');

// Check admin permissions
if (!$auth->hasPermission('admin.access')) {
    http_response_code(403);
    echo json_encode(['error' => 'Admin access required']);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

// Route requests
switch ($method) {
    case 'GET':
        handleGetRequest($action);
        break;
    case 'POST':
        handlePostRequest($action);
        break;
    case 'DELETE':
        handleDeleteRequest($action);
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleGetRequest($action) {
    switch ($action) {
        case 'list':
            listBackups();
            break;
        case 'status':
            getBackupStatus();
            break;
        default:
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action']);
            break;
    }
}

function handlePostRequest($action) {
    switch ($action) {
        case 'create':
            createBackup();
            break;
        case 'restore':
            restoreBackup();
            break;
        default:
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action']);
            break;
    }
}

function handleDeleteRequest($action) {
    switch ($action) {
        case 'delete':
            deleteBackup();
            break;
        default:
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action']);
            break;
    }
}

function listBackups() {
    $backup_dir = '/var/backups/dave';
    $backups = [];
    
    if (is_dir($backup_dir)) {
        $files = scandir($backup_dir);
        foreach ($files as $file) {
            if ($file !== '.' && $file !== '..' && strpos($file, 'dave_') === 0) {
                $file_path = $backup_dir . '/' . $file;
                $backups[] = [
                    'name' => $file,
                    'path' => $file_path,
                    'size' => filesize($file_path),
                    'date' => filemtime($file_path),
                    'type' => getBackupType($file)
                ];
            }
        }
        
        // Sort by date (newest first)
        usort($backups, function($a, $b) {
            return $b['date'] - $a['date'];
        });
    }
    
    echo json_encode([
        'success' => true,
        'data' => $backups,
        'timestamp' => date('c')
    ]);
}

function getBackupStatus() {
    $backup_dir = '/var/backups/dave';
    
    // Check for running backup/restore processes
    $backup_logs = glob('/tmp/dave_backup_*.log');
    $restore_logs = glob('/tmp/dave_restore_*.log');
    
    $running_backups = [];
    $running_restores = [];
    
    // Check backup processes
    foreach ($backup_logs as $log_file) {
        // Extract PID from potential process names
        $log_time = filemtime($log_file);
        // If log was updated in last 5 minutes, might still be running
        if (time() - $log_time < 300) {
            $running_backups[] = [
                'log_file' => basename($log_file),
                'last_updated' => $log_time,
                'log_size' => filesize($log_file)
            ];
        }
    }
    
    // Check restore processes
    foreach ($restore_logs as $log_file) {
        $log_time = filemtime($log_file);
        if (time() - $log_time < 300) {
            $running_restores[] = [
                'log_file' => basename($log_file),
                'last_updated' => $log_time,
                'log_size' => filesize($log_file)
            ];
        }
    }
    
    // Get last backup info for each type
    $last_backups = [];
    if (is_dir($backup_dir)) {
        $types = ['database' => 'dave_db_*.sql.gz', 'full' => 'dave_full_*.tar.gz', 
                  'config' => 'dave_config_*.tar.gz', 'uploads' => 'dave_uploads_*.tar.gz'];
        
        foreach ($types as $type => $pattern) {
            $files = glob($backup_dir . '/' . $pattern);
            if (!empty($files)) {
                $latest = null;
                $latest_time = 0;
                foreach ($files as $file) {
                    $mtime = filemtime($file);
                    if ($mtime > $latest_time) {
                        $latest_time = $mtime;
                        $latest = $file;
                    }
                }
                
                if ($latest) {
                    $last_backups[$type] = [
                        'file' => basename($latest),
                        'path' => $latest,
                        'date' => $latest_time,
                        'size' => filesize($latest),
                        'size_mb' => round(filesize($latest) / 1024 / 1024, 2)
                    ];
                }
            }
        }
    }
    
    echo json_encode([
        'success' => true,
        'data' => [
            'running_backups' => $running_backups,
            'running_restores' => $running_restores,
            'last_backups' => $last_backups,
            'backup_directory' => $backup_dir,
            'directory_exists' => is_dir($backup_dir),
            'directory_writable' => is_writable($backup_dir)
        ],
        'timestamp' => date('c')
    ]);
}

function createBackup() {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON input']);
        return;
    }
    
    $backup_type = $input['type'] ?? 'full';
    $description = $input['description'] ?? '';
    
    // Validate backup type (matching new script options)
    $valid_types = ['full', 'database', 'config', 'uploads'];
    if (!in_array($backup_type, $valid_types)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid backup type. Valid types: full, database, config, uploads']);
        return;
    }
    
    // Build command based on backup type
    $script_path = '/var/www/html/scripts/backup.sh';
    $command_options = '';
    
    switch ($backup_type) {
        case 'database':
            $command_options = '--database-only';
            break;
        case 'config':
            $command_options = '--config-only';
            break;
        case 'uploads':
            $command_options = '--uploads-only';
            break;
        case 'full':
        default:
            $command_options = '--type full';
            break;
    }
    
    // Ensure script is executable
    if (!is_executable($script_path)) {
        @chmod($script_path, 0755);
    }
    
    // Execute backup script with proper error handling
    $log_file = '/tmp/dave_backup_' . date('Ymd_His') . '.log';
    $command = "nohup $script_path $command_options > $log_file 2>&1 & echo \$!";
    
    // Run in background and capture PID
    $pid = trim(shell_exec($command));
    
    if (empty($pid) || !is_numeric($pid)) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Failed to start backup process. Check script permissions and logs.',
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Backup initiated successfully',
        'pid' => $pid,
        'type' => $backup_type,
        'log_file' => $log_file,
        'timestamp' => date('c')
    ]);
}

function restoreBackup() {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON input']);
        return;
    }
    
    $backup_file = $input['file'] ?? '';
    $restore_type = $input['type'] ?? 'full'; // full, database, config, uploads
    
    if (empty($backup_file)) {
        http_response_code(400);
        echo json_encode(['error' => 'Backup file required']);
        return;
    }
    
    // Validate restore type
    $valid_types = ['full', 'database', 'config', 'uploads'];
    if (!in_array($restore_type, $valid_types)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid restore type. Valid types: full, database, config, uploads']);
        return;
    }
    
    // Check if file exists (support both absolute and relative paths)
    $backup_dir = '/var/backups/dave';
    if (!file_exists($backup_file) && file_exists($backup_dir . '/' . $backup_file)) {
        $backup_file = $backup_dir . '/' . $backup_file;
    }
    
    if (!file_exists($backup_file)) {
        http_response_code(404);
        echo json_encode(['error' => 'Backup file not found: ' . $backup_file]);
        return;
    }
    
    // Ensure script is executable
    $script_path = '/var/www/html/scripts/restore.sh';
    if (!is_executable($script_path)) {
        @chmod($script_path, 0755);
    }
    
    // Build restore type option
    $restore_option = '';
    switch ($restore_type) {
        case 'database':
            $restore_option = '--database';
            break;
        case 'config':
            $restore_option = '--config';
            break;
        case 'uploads':
            $restore_option = '--uploads';
            break;
        case 'full':
        default:
            $restore_option = '--full';
            break;
    }
    
    // Execute restore script with proper error handling
    $log_file = '/tmp/dave_restore_' . date('Ymd_His') . '.log';
    $command = "nohup $script_path --file " . escapeshellarg($backup_file) . " $restore_option > $log_file 2>&1 & echo \$!";
    
    // Run in background and capture PID
    $pid = trim(shell_exec($command));
    
    if (empty($pid) || !is_numeric($pid)) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Failed to start restore process. Check script permissions and logs.',
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Restore initiated successfully',
        'pid' => $pid,
        'type' => $restore_type,
        'file' => basename($backup_file),
        'log_file' => $log_file,
        'timestamp' => date('c')
    ]);
}

function deleteBackup() {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON input']);
        return;
    }
    
    $backup_file = $input['file'] ?? '';
    
    if (empty($backup_file)) {
        http_response_code(400);
        echo json_encode(['error' => 'Backup file required']);
        return;
    }
    
    if (!file_exists($backup_file)) {
        http_response_code(404);
        echo json_encode(['error' => 'Backup file not found']);
        return;
    }
    
    if (unlink($backup_file)) {
        echo json_encode([
            'success' => true,
            'message' => 'Backup deleted successfully',
            'timestamp' => date('c')
        ]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to delete backup file']);
    }
}

function getBackupType($filename) {
    if (strpos($filename, 'dave_db_') === 0) return 'Database';
    if (strpos($filename, 'dave_files_') === 0) return 'Files';
    if (strpos($filename, 'dave_config_') === 0) return 'Configuration';
    if (strpos($filename, 'dave_uploads_') === 0) return 'Uploads';
    if (strpos($filename, 'dave_full_') === 0) return 'Full System';
    return 'Unknown';
}
?>




















