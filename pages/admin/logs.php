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
require_once __DIR__ . '/../../includes/cache.php';

// Initialize authentication
$auth = new Auth();

// Require authentication and admin permission
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

// Check if user has admin role
if ($user['role'] !== 'Admin') {
    header('Location: /pages/dashboard.php');
    exit;
}

// Get log files and statistics
$log_dir = _LOGS;
$log_files = [];
$log_stats = [];

if (is_dir($log_dir)) {
    $files = glob($log_dir . '/*.log');
    foreach ($files as $file) {
        $filename = basename($file);
        $size = filesize($file);
        $modified = filemtime($file);
        $log_files[] = [
            'name' => $filename,
            'path' => $file,
            'size' => $size,
            'size_formatted' => formatBytes($size),
            'modified' => $modified,
            'modified_formatted' => date('Y-m-d H:i:s', $modified)
        ];
    }
    
    // Sort by modification time (newest first)
    usort($log_files, function($a, $b) {
        return $b['modified'] - $a['modified'];
    });
}

// Get current log file content if requested
$current_log = '';
$selected_file = $_GET['file'] ?? '';
$log_level_filter = $_GET['level'] ?? '';
$search_term = $_GET['search'] ?? '';

if ($selected_file && in_array($selected_file, array_column($log_files, 'name'))) {
    $log_path = $log_dir . '/' . $selected_file;
    if (file_exists($log_path)) {
        $lines = file($log_path, FILE_IGNORE_NEW_LINES);
        
        // Apply filters
        if ($log_level_filter) {
            $lines = array_filter($lines, function($line) use ($log_level_filter) {
                return strpos($line, "[$log_level_filter]") !== false;
            });
        }
        
        if ($search_term) {
            $lines = array_filter($lines, function($line) use ($search_term) {
                return stripos($line, $search_term) !== false;
            });
        }
        
        // Limit to last 1000 lines for performance
        $lines = array_slice($lines, -1000);
        $current_log = implode("\n", $lines);
    }
}

// Helper function to format bytes
function formatBytes($bytes, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    
    for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
        $bytes /= 1024;
    }
    
    return round($bytes, $precision) . ' ' . $units[$i];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Logs - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

    <!-- Main Content -->
    <main class="main-content">
        <div class="container" style="max-width: 1400px; margin: 0 auto; padding: 2rem;">
            <!-- Page Header -->
            <div style="margin-bottom: 2rem;">
                <h1 style="font-size: 1.875rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 0.5rem;">
                    <i class="fas fa-file-alt"></i> System Logs
                </h1>
                <p style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">
                    View and manage system log files
                </p>
            </div>

            <!-- Two Column Layout -->
            <div style="display: grid; grid-template-columns: 350px 1fr; gap: 1.5rem; align-items: start;">
                
                <!-- Left Column - Log Files List -->
                <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem; position: sticky; top: 20px;">
                    <h3 style="font-size: 1.125rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 1rem;">
                        <i class="fas fa-list"></i> Log Files
                    </h3>
                    <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                        <?php foreach ($log_files as $file): ?>
                        <button onclick="selectLogFile('<?php echo dave_htmlspecialchars($file['name']); ?>')" 
                                style="background: <?php echo $selected_file === $file['name'] ? 'var(--siemens-petrol, #009999)' : 'var(--bg-secondary, #0f0f0f)'; ?>; 
                                       border: 1px solid <?php echo $selected_file === $file['name'] ? 'var(--siemens-petrol, #009999)' : 'var(--border-primary, #333333)'; ?>; 
                                       border-radius: 0.5rem; padding: 1rem; text-align: left; cursor: pointer; transition: all 0.2s; color: var(--text-primary, #ffffff);"
                                onmouseover="if ('<?php echo $selected_file === $file['name'] ? 'true' : 'false'; ?>' === 'false') this.style.background='var(--bg-hover, #222222)'"
                                onmouseout="if ('<?php echo $selected_file === $file['name'] ? 'true' : 'false'; ?>' === 'false') this.style.background='var(--bg-secondary, #0f0f0f)'">
                            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.5rem;">
                                <span style="font-weight: 600; font-size: 0.875rem;">
                                    <i class="fas fa-file-alt"></i> <?php echo dave_htmlspecialchars(str_replace('.log', '', $file['name'])); ?>
                                </span>
                                <span style="font-size: 0.75rem; color: var(--text-muted, #94a3b8); font-weight: 500;">
                                    <?php echo $file['size_formatted']; ?>
                                </span>
                            </div>
                            <div style="font-size: 0.7rem; color: var(--text-muted, #94a3b8);">
                                <i class="fas fa-clock"></i> <?php echo date('M d, H:i', $file['modified']); ?>
                            </div>
                        </button>
                        <?php endforeach; ?>
                    </div>
                </div>

                <!-- Right Column - Log Content -->
                <div style="display: flex; flex-direction: column; gap: 1.5rem;">
                    
                    <?php if ($selected_file): ?>
                    
                    <!-- Filters and Actions -->
                    <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 1.5rem;">
                        <form method="GET" style="display: flex; gap: 1rem; align-items: end; flex-wrap: wrap;">
                            <input type="hidden" name="file" value="<?php echo dave_htmlspecialchars($selected_file); ?>">
                            
                            <div style="flex: 1; min-width: 200px;">
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    Log Level
                                </label>
                                <select name="level" style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;">
                                    <option value="">All Levels</option>
                                    <option value="DEBUG" <?php echo $log_level_filter === 'DEBUG' ? 'selected' : ''; ?>>DEBUG</option>
                                    <option value="INFO" <?php echo $log_level_filter === 'INFO' ? 'selected' : ''; ?>>INFO</option>
                                    <option value="WARNING" <?php echo $log_level_filter === 'WARNING' ? 'selected' : ''; ?>>WARNING</option>
                                    <option value="ERROR" <?php echo $log_level_filter === 'ERROR' ? 'selected' : ''; ?>>ERROR</option>
                                </select>
                            </div>
                            
                            <div style="flex: 2; min-width: 250px;">
                                <label style="display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-secondary, #cbd5e1); margin-bottom: 0.375rem;">
                                    Search
                                </label>
                                <input type="text" name="search" value="<?php echo dave_htmlspecialchars($search_term); ?>" placeholder="Search logs..." 
                                       style="width: 100%; padding: 0.5rem; background: var(--bg-secondary, #0f0f0f); color: var(--text-primary, #ffffff); border: 1px solid var(--border-primary, #333333); border-radius: 0.375rem;">
                            </div>
                            
                            <button type="submit" class="btn btn-primary" style="padding: 0.5rem 1rem;">
                                <i class="fas fa-search"></i> Filter
                            </button>
                            
                            <button type="button" class="btn btn-secondary" onclick="refreshLogs()" style="padding: 0.5rem 1rem;">
                                <i class="fas fa-sync"></i> Refresh
                            </button>
                            
                            <button type="button" class="btn btn-secondary" onclick="downloadLog()" style="padding: 0.5rem 1rem;">
                                <i class="fas fa-download"></i> Download
                            </button>
                        </form>
                    </div>

                    <!-- Log Content Display -->
                    <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; overflow: hidden;">
                        <div style="padding: 1rem 1.5rem; border-bottom: 1px solid var(--border-primary, #333333); display: flex; justify-content: space-between; align-items: center;">
                            <h3 style="font-size: 1rem; font-weight: 600; color: var(--text-primary, #ffffff); margin: 0;">
                                <i class="fas fa-file-text"></i> <?php echo dave_htmlspecialchars($selected_file); ?>
                            </h3>
                            <span style="font-size: 0.75rem; color: var(--text-muted, #94a3b8);">
                                Last 1000 lines
                            </span>
                        </div>
                        <div style="padding: 1.5rem; max-height: 600px; overflow-y: auto; font-family: 'Courier New', monospace; font-size: 0.75rem; line-height: 1.5;">
                            <pre style="margin: 0; color: var(--text-primary, #ffffff); white-space: pre-wrap; word-break: break-all;"><?php echo dave_htmlspecialchars($current_log); ?></pre>
                        </div>
                    </div>
                    
                    <?php else: ?>
                    
                    <!-- No Log Selected -->
                    <div style="background: var(--bg-card, #1a1a1a); border: 1px solid var(--border-primary, #333333); border-radius: 0.75rem; padding: 4rem; text-align: center;">
                        <i class="fas fa-file-alt" style="font-size: 3rem; color: var(--text-muted, #94a3b8); margin-bottom: 1rem;"></i>
                        <h3 style="color: var(--text-primary, #ffffff); font-size: 1.25rem; margin-bottom: 0.5rem;">No Log File Selected</h3>
                        <p style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">Select a log file from the list to view its contents</p>
                    </div>
                    
                    <?php endif; ?>
                    
                </div>
            </div>
        </div>
    </main>

    <script>
        function selectLogFile(filename) {
            window.location.href = '?file=' + encodeURIComponent(filename);
        }

        function refreshLogs() {
            window.location.reload();
        }

        function downloadLog() {
            const selectedFile = '<?php echo dave_htmlspecialchars($selected_file); ?>';
            if (selectedFile) {
                window.location.href = '/api/v1/system/download-log.php?file=' + encodeURIComponent(selectedFile);
            } else {
                alert('Please select a log file first.');
            }
        }

        function clearLog() {
            const selectedFile = '<?php echo dave_htmlspecialchars($selected_file); ?>';
            if (selectedFile) {
                if (confirm('Are you sure you want to clear this log file? This action cannot be undone.')) {
                    fetch('/api/v1/system/clear-log.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: JSON.stringify({ file: selectedFile })
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert('Log file cleared successfully!');
                            location.reload();
                        } else {
                            alert('Error clearing log: ' + data.message);
                        }
                    })
                    .catch(error => {
                        alert('Error clearing log: ' + error.message);
                    });
                }
            } else {
                alert('Please select a log file first.');
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
</body>
</html>
