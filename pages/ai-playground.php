<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../services/shell_command_utilities.php';

// Require authentication
$auth->requireAuth();

$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

// Check if Azure OpenAI is configured via .env
$api_key_configured = (
    !empty(getenv('AZURE_OPENAI_API_KEY'))    &&
    !empty(getenv('AZURE_OPENAI_ENDPOINT'))   &&
    !empty(getenv('AZURE_OPENAI_DEPLOYMENT'))
);

// ── Job directory ─────────────────────────────────────────────────────────────
define('AI_JOBS_DIR', __DIR__ . '/../temp/ai_jobs');
if (!is_dir(AI_JOBS_DIR)) {
    mkdir(AI_JOBS_DIR, 0750, true);
}

// ── Helper: sanitise job_id from user input ────────────────────────────────────
function sanitiseJobId(string $raw): string {
    return preg_replace('/[^a-f0-9]/', '', strtolower($raw));
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AJAX STATUS ENDPOINT  ?action=status&job_id=<hex>
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if ($_SERVER['REQUEST_METHOD'] === 'GET' &&
    isset($_GET['action']) && $_GET['action'] === 'status' &&
    isset($_GET['job_id'])) {

    header('Content-Type: application/json');
    $jobId   = sanitiseJobId($_GET['job_id']);
    $jobFile = AI_JOBS_DIR . '/' . $jobId . '.json';

    if (empty($jobId) || !file_exists($jobFile)) {
        echo json_encode(['status' => 'not_found']);
        exit;
    }

    $job = json_decode(file_get_contents($jobFile), true);
    echo json_encode([
        'status'       => $job['status']       ?? 'unknown',
        'result'       => $job['result']        ?? null,
        'error'        => $job['error']         ?? null,
        'query'        => $job['query']         ?? '',
        'completed_at' => $job['completed_at']  ?? null,
    ]);
    exit;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// FORM POST — create job, spawn background worker, redirect to polling view
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['query'])) {
    $rawQuery = trim($_POST['query']);

    if (empty($rawQuery)) {
        header('Location: /pages/ai-playground.php?err=empty');
        exit;
    }

    // Create job file
    $jobId   = bin2hex(random_bytes(16));
    $jobFile = AI_JOBS_DIR . '/' . $jobId . '.json';
    file_put_contents($jobFile, json_encode([
        'job_id'     => $jobId,
        'status'     => 'pending',
        'query'      => $rawQuery,
        'user_id'    => $user['user_id']   ?? 'unknown',
        'username'   => $user['username']  ?? 'Unknown',
        'created_at' => date('c'),
    ], JSON_PRETTY_PRINT));

    // Spawn background worker (non-blocking)
    $workerScript = escapeshellarg(__DIR__ . '/../services/ai-query-worker.php');
    $jobIdArg     = escapeshellarg($jobId);
    $logFile      = AI_JOBS_DIR . '/' . $jobId . '.log';

    ShellCommandUtilities::executeShellCommand(
        'php ' . $workerScript . ' ' . $jobIdArg,
        [
            'blocking'   => false,
            'log_file'   => $logFile,
            'return_pid' => false,
        ]
    );

    // Redirect to polling view immediately — no waiting
    header('Location: /pages/ai-playground.php?job_id=' . $jobId);
    exit;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// NORMAL GET — show form (or polling view if ?job_id present)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
$activeJobId = '';
if (!empty($_GET['job_id'])) {
    $activeJobId = sanitiseJobId($_GET['job_id']);
    // Validate the file actually exists (reject garbage IDs)
    if (!file_exists(AI_JOBS_DIR . '/' . $activeJobId . '.json')) {
        $activeJobId = '';
    }
}
$formError = (!empty($_GET['err']) && $_GET['err'] === 'empty') ? 'Please enter a question.' : '';

// ─── Helper functions (defined before output) ────────────────────────────────

function buildTablePHP(array $rows): string {
    if (count($rows) < 2) return implode("\n", $rows);

    $html = '<table class="ai-result-table">';

    $headers = array_values(array_filter(explode('|', $rows[0]), fn($c) => trim($c) !== ''));
    $html .= '<thead><tr>';
    foreach ($headers as $h) {
        $html .= '<th>' . trim($h) . '</th>';
    }
    $html .= '</tr></thead><tbody>';

    for ($i = 2; $i < count($rows); $i++) {
        $cells = array_values(array_filter(explode('|', $rows[$i]), fn($c) => trim($c) !== ''));
        if (!$cells) continue;
        $html .= '<tr>';
        foreach ($cells as $cell) {
            $html .= '<td>' . trim($cell) . '</td>';
        }
        $html .= '</tr>';
    }

    return $html . '</tbody></table>';
}

function convertMarkdownTablePHP(string $text): string {
    $lines     = explode("\n", $text);
    $result    = [];
    $inTable   = false;
    $tableRows = [];

    foreach ($lines as $line) {
        if (strpos($line, '|') !== false) {
            if (!$inTable) { $inTable = true; $tableRows = []; }
            $tableRows[] = $line;
        } else {
            if ($inTable) { $result[] = buildTablePHP($tableRows); $inTable = false; $tableRows = []; }
            $result[] = $line;
        }
    }
    if ($inTable && $tableRows) {
        $result[] = buildTablePHP($tableRows);
    }
    return implode("\n", $result);
}

function formatAIResponse(string $response): string {
    $out = htmlspecialchars($response, ENT_QUOTES, 'UTF-8');
    // Bold
    $out = preg_replace('/\*\*(.*?)\*\*/s', '<strong>$1</strong>', $out);
    // Tables
    if (strpos($out, '|') !== false) {
        $out = convertMarkdownTablePHP($out);
    }
    // Line breaks
    $out = nl2br($out);
    // Bullet points
    $out = preg_replace('/^- (.+)$/m', '<li>$1</li>', $out);
    $out = preg_replace('/(<li>.*?<\/li>\s*)+/s', '<ul>$&</ul>', $out);
    return $out;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Security Analytics - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .ai-config-warning {
            background: #fffbeb;
            border: 1px solid #f59e0b;
            color: #92400e;
            padding: 1rem 1.25rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
        }
        .ai-config-warning code { background: rgba(0,0,0,.07); padding: 1px 4px; border-radius: 4px; }

        .ai-layout {
            display: grid;
            grid-template-columns: 260px 1fr;
            gap: 1.5rem;
            align-items: start;
        }
        @media (max-width: 900px) { .ai-layout { grid-template-columns: 1fr; } }

        .ai-sidebar {
            background: var(--card-bg, #1e293b);
            border-radius: 10px;
            padding: 1.25rem;
            position: sticky;
            top: 1.5rem;
        }
        .ai-sidebar h3 { margin: 0 0 0.75rem; font-size: 1rem; color: var(--text-primary, #fff); }

        .ai-suggestions { list-style: none; padding: 0; margin: 0; }
        .ai-suggestions li {
            padding: 0.6rem 0.75rem;
            margin-bottom: 0.4rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.875rem;
            color: var(--text-secondary, #cbd5e1);
            background: var(--bg-secondary, #0f172a);
            transition: background 0.15s, color 0.15s, transform 0.15s;
        }
        .ai-suggestions li:hover {
            background: var(--siemens-petrol, #009999);
            color: #fff;
            transform: translateX(4px);
        }

        .ai-query-area {
            background: var(--card-bg, #1e293b);
            border-radius: 10px;
            padding: 1.5rem;
        }
        .ai-query-area label {
            display: block;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: var(--text-primary, #fff);
        }
        .ai-textarea-wrap { position: relative; }
        #queryInput {
            width: 100%;
            box-sizing: border-box;
            padding: 0.875rem 1rem 3.5rem;
            border: 2px solid var(--border-color, #334155);
            border-radius: 8px;
            background: var(--bg-secondary, #0f172a);
            color: var(--text-primary, #fff);
            font-size: 1rem;
            min-height: 100px;
            resize: vertical;
            font-family: inherit;
        }
        #queryInput:focus { outline: none; border-color: var(--siemens-petrol, #009999); }
        #queryInput:disabled { opacity: 0.5; cursor: not-allowed; }

        .ai-submit-btn {
            position: absolute;
            right: 0.75rem;
            bottom: 0.75rem;
            background: var(--siemens-petrol, #009999);
            color: #fff;
            border: none;
            padding: 0.6rem 1.25rem;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.95rem;
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            transition: background 0.2s;
        }
        .ai-submit-btn:hover:not(:disabled) { background: #00797a; }
        .ai-submit-btn:disabled { opacity: 0.5; cursor: not-allowed; }

        .ai-result-card {
            margin-top: 1.5rem;
            background: var(--bg-secondary, #0f172a);
            border: 1px solid var(--border-color, #334155);
            border-radius: 8px;
            padding: 1.25rem;
        }
        .ai-result-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 0.75rem;
            margin-bottom: 0.75rem;
            border-bottom: 1px solid var(--border-color, #334155);
            gap: 1rem;
        }
        .ai-result-question { font-weight: 600; color: var(--text-primary, #fff); }
        .ai-result-time     { font-size: 0.8rem; color: var(--text-secondary, #94a3b8); white-space: nowrap; }
        .ai-result-body     { color: var(--text-primary, #e2e8f0); line-height: 1.7; }
        .ai-result-body ul  { padding-left: 1.5rem; }
        .ai-result-body li  { margin-bottom: 0.25rem; }

        .ai-result-table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            font-size: 0.9rem;
        }
        .ai-result-table th,
        .ai-result-table td {
            padding: 0.6rem 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color, #334155);
        }
        .ai-result-table th { background: var(--card-bg, #1e293b); font-weight: 600; color: var(--text-primary, #fff); }
        .ai-result-table tr:last-child td { border-bottom: none; }

        .ai-error {
            margin-top: 1rem;
            padding: 0.875rem;
            background: #fef2f2;
            border: 1px solid #fca5a5;
            border-radius: 6px;
            color: #991b1b;
        }
        .ai-info-box {
            margin-top: 1.25rem;
            border-left: 4px solid var(--siemens-petrol, #009999);
            background: var(--bg-secondary, #0f172a);
            padding: 1rem;
            border-radius: 0 6px 6px 0;
            color: var(--text-secondary, #cbd5e1);
        }
        .ai-info-box h4 { margin: 0 0 0.4rem; color: var(--text-primary, #fff); }
        .ai-info-box p  { margin: 0; }

        /* ── Async loading state ── */
        .ai-loading {
            margin-top: 1.5rem;
            background: var(--bg-secondary, #0f172a);
            border: 1px solid var(--border-color, #334155);
            border-radius: 8px;
            padding: 2rem;
            text-align: center;
            color: var(--text-secondary, #94a3b8);
        }
        .ai-spinner {
            display: inline-block;
            width: 2.5rem;
            height: 2.5rem;
            border: 3px solid var(--border-color, #334155);
            border-top-color: var(--siemens-petrol, #009999);
            border-radius: 50%;
            animation: ai-spin 0.8s linear infinite;
            margin-bottom: 1rem;
        }
        @keyframes ai-spin { to { transform: rotate(360deg); } }
        .ai-loading p { margin: 0.25rem 0; }
        .ai-loading .ai-steps { margin-top: 1rem; font-size: 0.85rem; list-style: none; padding: 0; }
        .ai-loading .ai-steps li { padding: 0.2rem 0; opacity: 0.5; transition: opacity 0.3s; }
        .ai-loading .ai-steps li.active { opacity: 1; color: var(--siemens-petrol, #009999); font-weight: 600; }
        .ai-loading .ai-steps li.done   { opacity: 0.7; }
    </style>
</head>
<body>
<div class="dashboard-container">
    <?php include __DIR__ . '/../assets/templates/dashboard-header.php'; ?>

    <main class="dashboard-main">
        <div class="page-header">
            <div class="page-title">
                <h1><i class="fas fa-brain"></i> AI Security Analytics</h1>
                <p>Ask natural language questions about your DAVE security data</p>
            </div>
            <div class="page-actions">
                <a href="/pages/dashboard.php" class="btn btn-secondary">
                    <i class="fas fa-arrow-left"></i> Back to Dashboard
                </a>
            </div>
        </div>

        <?php if (!$api_key_configured): ?>
        <div class="ai-config-warning">
            <i class="fas fa-exclamation-triangle" style="margin-top:2px;flex-shrink:0;"></i>
            <div>
                <strong>Azure OpenAI not configured.</strong>
                Please add the following to your <code>.env</code> file and restart the web server:<br>
                <code>AZURE_OPENAI_API_KEY</code> &nbsp;·&nbsp;
                <code>AZURE_OPENAI_ENDPOINT</code> &nbsp;·&nbsp;
                <code>AZURE_OPENAI_DEPLOYMENT</code>
            </div>
        </div>
        <?php endif; ?>

        <div class="ai-layout">

            <!-- Sidebar: example queries -->
            <aside class="ai-sidebar">
                <h3><i class="fas fa-lightbulb"></i> Example Queries</h3>
                <ul class="ai-suggestions">
                    <li data-query="Show me the top 10 critical vulnerabilities">Critical vulnerabilities</li>
                    <li data-query="What are the top 5 most recently added assets?">Most recent assets</li>
                    <li data-query="Show existing remediations for Log4j patch">Remediations available</li>
                    <li data-query="List assets that are mapped to FDA devices">FDA device mapped assets</li>
                    <li data-query="List all vulnerabilities with EPSS score above 0.7">High EPSS vulnerabilities</li>
                </ul>
            </aside>

            <!-- Query form and results -->
            <div class="ai-query-area">
                <form method="POST" action="">
                    <label for="queryInput">
                        <i class="fas fa-comment-dots"></i> Ask a Question
                        <span style="font-weight:400;font-size:0.85rem;color:var(--text-secondary,#94a3b8);"> — Ctrl+Enter to submit</span>
                    </label>
                    <div class="ai-textarea-wrap">
                        <textarea
                            id="queryInput"
                            name="query"
                            placeholder="e.g., Show me all critical vulnerabilities affecting medical devices in the ICU..."
                            <?php echo !$api_key_configured ? 'disabled' : ''; ?>
                        ></textarea>
                        <button type="submit" class="ai-submit-btn" <?php echo !$api_key_configured ? 'disabled' : ''; ?>>
                            <i class="fas fa-paper-plane"></i> Ask AI
                        </button>
                    </div>
                </form>

                <?php if ($formError): ?>
                <div class="ai-error">
                    <strong><i class="fas fa-exclamation-circle"></i></strong>
                    <?php echo htmlspecialchars($formError, ENT_QUOTES, 'UTF-8'); ?>
                </div>
                <?php endif; ?>

                <?php if ($activeJobId): ?>
                <!-- ── Async loading / result area ── -->
                <div id="aiResultArea">
                    <div class="ai-loading" id="aiLoading">
                        <div class="ai-spinner"></div>
                        <p><strong>Processing your query…</strong></p>
                        <p id="aiLoadingStep" style="font-size:0.875rem;">Starting up…</p>
                        <ul class="ai-steps">
                            <li id="step1"><i class="fas fa-code"></i> Generating SQL query</li>
                            <li id="step2"><i class="fas fa-database"></i> Querying database</li>
                            <li id="step3"><i class="fas fa-brain"></i> Interpreting results</li>
                        </ul>
                    </div>
                    <div id="aiResult" style="display:none;"></div>
                    <div id="aiError"  style="display:none;" class="ai-error"></div>
                </div>
                <?php else: ?>
                <div class="ai-info-box">
                    <h4><i class="fas fa-info-circle"></i> How to Use</h4>
                    <p>Type a security question in plain English and click <strong>Ask AI</strong>. Use the example queries on the left to get started quickly.</p>
                </div>
                <?php endif; ?>

            </div><!-- .ai-query-area -->
        </div><!-- .ai-layout -->
    </main>
</div><!-- .dashboard-container -->

<script>
// ── Sidebar suggestion clicks ─────────────────────────────────────────────────
document.querySelectorAll('.ai-suggestions li').forEach(function(item) {
    item.addEventListener('click', function() {
        document.getElementById('queryInput').value = this.getAttribute('data-query');
        document.getElementById('queryInput').focus();
    });
});

// ── Ctrl+Enter submit ─────────────────────────────────────────────────────────
document.getElementById('queryInput').addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.key === 'Enter') {
        this.closest('form').submit();
    }
});

<?php if ($activeJobId): ?>
// ── Background job polling ────────────────────────────────────────────────────
(function() {
    var jobId      = <?php echo json_encode($activeJobId); ?>;
    var pollUrl    = '/pages/ai-playground.php?action=status&job_id=' + encodeURIComponent(jobId);
    var interval   = 1500;   // ms between polls
    var maxPolls   = 120;    // give up after ~3 minutes
    var polls      = 0;
    var steps      = [document.getElementById('step1'),
                      document.getElementById('step2'),
                      document.getElementById('step3')];
    var stepIndex  = 0;

    // Animate the step indicators while waiting
    var stepTimer = setInterval(function() {
        steps.forEach(function(s) { s.className = 'done'; });
        if (stepIndex < steps.length) {
            steps[stepIndex].className = 'active';
            stepIndex++;
        }
    }, 4000);

    function formatResponse(text) {
        // Bold
        text = text.replace(/\*\*(.*?)\*\*/gs, '<strong>$1</strong>');
        // Simple markdown table to HTML
        if (text.indexOf('|') !== -1) {
            text = text.replace(/(?:^|\n)((?:\|[^\n]+\|\n?)+)/g, function(match, table) {
                var rows = table.trim().split('\n');
                var html = '<table class="ai-result-table">';
                rows.forEach(function(row, i) {
                    if (/^[\s|:-]+$/.test(row)) return; // skip separator
                    var cells = row.split('|').filter(function(c) { return c.trim() !== ''; });
                    var tag   = (i === 0) ? 'th' : 'td';
                    if (i === 0) html += '<thead><tr>';
                    else if (i === 2) html += '<tbody><tr>';
                    else html += '<tr>';
                    cells.forEach(function(c) { html += '<' + tag + '>' + c.trim() + '</' + tag + '>'; });
                    html += '</tr>';
                    if (i === 0) html += '</thead>';
                });
                return html + '</tbody></table>';
            });
        }
        // Escape unprocessed HTML and render newlines
        return text.replace(/\n/g, '<br>');
    }

    function showResult(data) {
        clearInterval(stepTimer);
        document.getElementById('aiLoading').style.display = 'none';
        if (data.error) {
            var err = document.getElementById('aiError');
            err.innerHTML = '<strong><i class="fas fa-exclamation-circle"></i> Error:</strong> '
                            + data.error.replace(/</g,'&lt;');
            err.style.display = 'block';
        } else {
            var ts  = data.completed_at ? new Date(data.completed_at).toLocaleString() : '';
            var div = document.getElementById('aiResult');
            div.innerHTML =
                '<div class="ai-result-card">'
                + '  <div class="ai-result-meta">'
                + '    <span class="ai-result-question"><i class="fas fa-question-circle"></i> '
                +        (data.query || '').replace(/</g,'&lt;')
                + '    </span>'
                + '    <span class="ai-result-time">' + ts + '</span>'
                + '  </div>'
                + '  <div class="ai-result-body">' + formatResponse(data.result || '') + '</div>'
                + '</div>';
            div.style.display = 'block';
            div.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    function poll() {
        if (++polls > maxPolls) {
            clearInterval(stepTimer);
            document.getElementById('aiLoading').style.display = 'none';
            var err = document.getElementById('aiError');
            err.innerHTML = '<strong>Timed out</strong> — the query took too long. Please try again.';
            err.style.display = 'block';
            return;
        }
        fetch(pollUrl)
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.status === 'complete' || data.status === 'error') {
                    showResult(data);
                } else {
                    setTimeout(poll, interval);
                }
            })
            .catch(function() { setTimeout(poll, interval); });
    }

    // Start polling after a short delay to let the worker spin up
    setTimeout(poll, 800);
})();
<?php endif; ?>
</script>
</body>
</html>
