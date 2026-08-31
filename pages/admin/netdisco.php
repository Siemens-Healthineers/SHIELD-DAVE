<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

define('DAVE_ACCESS', true);
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/cache.php';
require_once __DIR__ . '/../../services/shell_command_utilities.php';

function getNetdiscoLogPayload($logFile, $offset = 0, $maxBytes = 65536) {
    $payload = [
        'success' => true,
        'content' => '',
        'offset' => 0,
        'reset' => false,
        'file_exists' => false,
        'log_file' => $logFile,
        'message' => 'Waiting for NetDisco to write log output...'
    ];

    if (empty($logFile)) {
        $payload['success'] = false;
        $payload['message'] = 'Log file is not configured.';
        return $payload;
    }

    clearstatcache(true, $logFile);

    if (!is_file($logFile) || !is_readable($logFile)) {
        return $payload;
    }

    $fileSize = filesize($logFile);
    if ($fileSize === false) {
        $payload['success'] = false;
        $payload['message'] = 'Unable to determine log file size.';
        return $payload;
    }

    $payload['file_exists'] = true;
    $payload['message'] = 'Streaming log output';

    $offset = max(0, (int)$offset);
    $maxBytes = max(1024, (int)$maxBytes);

    if ($offset > $fileSize) {
        $offset = max(0, $fileSize - $maxBytes);
        $payload['reset'] = true;
    }

    if ($offset === 0 && $fileSize > $maxBytes) {
        $offset = $fileSize - $maxBytes;
        $payload['reset'] = true;
    }

    $length = min($maxBytes, max(0, $fileSize - $offset));
    if ($length > 0) {
        $content = file_get_contents($logFile, false, null, $offset, $length);
        if ($content === false) {
            $payload['success'] = false;
            $payload['message'] = 'Unable to read log file.';
            return $payload;
        }

        $payload['content'] = $content;
        $payload['offset'] = $offset + strlen($content);
        return $payload;
    }

    $payload['offset'] = $offset;
    return $payload;
}

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

$log_file = '';
if (is_dir(_LOGS)) {
    $log_file = _LOGS . DIRECTORY_SEPARATOR . 'netdisco_background_job.log';
}

if (isset($_GET['log_view']) && $_GET['log_view'] === '1') {
    header('Content-Type: application/json');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo json_encode(getNetdiscoLogPayload($log_file, $_GET['offset'] ?? 0));
    exit;
}

   
try {
    // Call Python service in background (non-blocking)
    $command = "cd " . _ROOT . " && python3 python/services/ingest_netdisco.py";
    $result = ShellCommandUtilities::executeShellCommand($command, [
        'blocking' => false,
        'log_file' => $log_file
    ]);
    if (!$result['success']) {
        error_log('NetDisco ingestion failed to start: ' . ($result['error'] ?? 'Unknown error'));
    }
} catch (Exception $e) {
    error_log('NetDisco ingestion failed to start: ' . $e->getMessage());
}
    
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cynerio Sync - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <main class="main-content">
        <div class="container" style="max-width: 1400px; margin: 0 auto; padding: 2rem;">
            <!-- Page Header -->
            <div style="margin-bottom: 2rem;">
                <h1 style="font-size: 1.875rem; font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 0.5rem; display:flex;">
                    <div class="admin-card-icon">
                        <i class="fa-solid fa-n"></i>
                    </div>
                    <div class="admin-card-content">
                        <h3>NetDisco Integration</h3>
                        <p>Manage NetDisco integration settings</p>
                    </div>
                </h1>
            </div>
            <section class="center-content">
                <p>NetDisco data synchronization initiated. Please check system logs for details.</p>
                <br>
                <br>
                <a href="/pages/admin/index.php" class="admin-card">
                    <div class="admin-card-icon">
                        <i class="fas fa-cog"></i>
                    </div>
                    <div class="admin-card-content">
                        <h3>Admin Panel</h3>
                        <p>Go back to Admin Panel</p>
                    </div>
                </a>

                <div class="netdisco-log-viewer">
                    <div class="netdisco-log-header">
                        <div>
                            <h2>Live Log Output</h2>
                            <p>New log entries will appear here as the NetDisco job runs.</p>
                        </div>
                        <button type="button" id="netdisco-log-refresh" class="netdisco-log-refresh">Refresh Now</button>
                    </div>
                    <div class="netdisco-log-meta">
                        <span>Source: <?php echo dave_htmlspecialchars($log_file ?: 'No log file configured'); ?></span>
                        <span id="netdisco-log-status">Connecting...</span>
                    </div>
                    <pre id="netdisco-log-output" class="netdisco-log-output">Waiting for log output...</pre>
                </div>
            </section>
        </div>
    </main>

    <!-- Profile Dropdown Script -->
    <script src="/assets/js/dashboard-common.js"></script>
    <script>
        // Pass user data to the profile dropdown
        window.userData = {
            name: '<?php echo dave_htmlspecialchars($user['username']); ?>',
            role: '<?php echo dave_htmlspecialchars($user['role']); ?>',
            email: '<?php echo dave_htmlspecialchars($user['email'] ?? 'user@example.com'); ?>'
        };

        (function() {
            const output = document.getElementById('netdisco-log-output');
            const status = document.getElementById('netdisco-log-status');
            const refreshButton = document.getElementById('netdisco-log-refresh');
            const pollIntervalMs = 1500;
            let offset = 0;
            let timerId = null;

            function buildLogUrl() {
                const url = new URL(window.location.href);
                url.search = '';
                url.searchParams.set('log_view', '1');
                url.searchParams.set('offset', String(offset));
                return url.toString();
            }

            function shouldStickToBottom() {
                return output.scrollHeight - output.scrollTop - output.clientHeight < 32;
            }

            function appendContent(content, reset) {
                const keepAtBottom = shouldStickToBottom();

                if (reset) {
                    output.textContent = content || 'Waiting for log output...';
                } else if (content) {
                    if (output.textContent === 'Waiting for log output...') {
                        output.textContent = content;
                    } else {
                        output.textContent += content;
                    }
                }

                if (keepAtBottom || reset) {
                    output.scrollTop = output.scrollHeight;
                }
            }

            async function fetchLogs() {
                status.textContent = 'Updating...';

                try {
                    const response = await fetch(buildLogUrl(), {
                        headers: {
                            'Accept': 'application/json'
                        },
                        cache: 'no-store'
                    });

                    if (!response.ok) {
                        throw new Error('Request failed with status ' + response.status);
                    }

                    const data = await response.json();
                    appendContent(data.content || '', Boolean(data.reset));
                    offset = Number(data.offset || 0);

                    if (!data.file_exists && offset === 0) {
                        output.textContent = data.message || 'Waiting for log output...';
                    }

                    if (data.reset) {
                        status.textContent = 'Showing latest log output';
                    } else {
                        status.textContent = data.file_exists ? 'Live' : 'Waiting for log file';
                    }
                } catch (error) {
                    status.textContent = 'Update failed';
                    output.textContent += '\n[log viewer] ' + error.message;
                    output.scrollTop = output.scrollHeight;
                } finally {
                    timerId = window.setTimeout(fetchLogs, pollIntervalMs);
                }
            }

            refreshButton.addEventListener('click', function() {
                if (timerId !== null) {
                    window.clearTimeout(timerId);
                }
                fetchLogs();
            });

            fetchLogs();
        })();
    </script>
    <style>
        .center-content {
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            min-height: 50vh;
            gap: 1rem;
        }

        .netdisco-log-viewer {
            width: min(100%, 960px);
            margin-top: 1rem;
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }

        .netdisco-log-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
            margin-bottom: 0.75rem;
        }

        .netdisco-log-header h2 {
            margin: 0;
            font-size: 1.125rem;
            color: var(--text-primary, #ffffff);
        }

        .netdisco-log-header p {
            margin: 0.35rem 0 0;
            color: var(--text-secondary, #cbd5e1);
            font-size: 0.875rem;
        }

        .netdisco-log-refresh {
            border: 1px solid var(--border-primary, #333333);
            background: var(--bg-secondary, #0f0f0f);
            color: var(--text-primary, #ffffff);
            border-radius: 0.5rem;
            padding: 0.625rem 0.9rem;
            cursor: pointer;
            white-space: nowrap;
        }

        .netdisco-log-refresh:hover {
            background: var(--bg-hover, #222222);
        }

        .netdisco-log-meta {
            display: flex;
            justify-content: space-between;
            gap: 1rem;
            flex-wrap: wrap;
            margin-bottom: 0.75rem;
            color: var(--text-muted, #94a3b8);
            font-size: 0.8rem;
        }

        .netdisco-log-output {
            margin: 0;
            min-height: 280px;
            max-height: 480px;
            overflow: auto;
            padding: 1rem;
            border-radius: 0.5rem;
            border: 1px solid var(--border-primary, #333333);
            background: #0b1220;
            color: #d7e3f4;
            font-family: Consolas, Monaco, 'Courier New', monospace;
            font-size: 0.85rem;
            line-height: 1.5;
            text-align: left;
            white-space: pre-wrap;
            word-break: break-word;
        }

        @media (max-width: 640px) {
            .netdisco-log-header {
                flex-direction: column;
            }

            .netdisco-log-refresh {
                width: 100%;
            }
        }
    </style>
</body>
</html>
