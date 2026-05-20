<?php
/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
 *
 * AI Query Background Worker
 *
 * Usage (spawned by ShellCommandUtilities, never called via HTTP):
 *   php services/ai-query-worker.php <job_id>
 *
 * Reads temp/ai_jobs/<job_id>.json, runs the two-step Text-to-SQL flow,
 * and writes the result back to the same file.
 */

// Guard: this is a CLI-only script
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit('CLI only');
}

// Validate argument
if (empty($argv[1]) || !preg_match('/^[a-f0-9]{32}$/', $argv[1])) {
    fwrite(STDERR, "[ai-query-worker] ERROR: invalid or missing job_id argument\n");
    exit(1);
}

$jobId = $argv[1];

// Bootstrap – loads .env, defines _ROOT, etc.
define('DAVE_ACCESS', true);
$root = dirname(__DIR__);
require_once $root . '/config/config.php';
require_once $root . '/includes/ai-query-engine.php';

// ── Locate job file ────────────────────────────────────────────────────────────
$jobsDir = $root . '/temp/ai_jobs';
$jobFile = $jobsDir . '/' . $jobId . '.json';

if (!file_exists($jobFile)) {
    fwrite(STDERR, "[ai-query-worker] ERROR: job file not found: {$jobFile}\n");
    exit(1);
}

// ── Load job ───────────────────────────────────────────────────────────────────
$job = json_decode(file_get_contents($jobFile), true);

if (!$job || empty($job['query'])) {
    fwrite(STDERR, "[ai-query-worker] ERROR: job file is empty or malformed\n");
    exit(1);
}

// ── Mark as processing ─────────────────────────────────────────────────────────
$job['status']       = 'processing';
$job['started_at']   = date('c');
file_put_contents($jobFile, json_encode($job, JSON_PRETTY_PRINT));

echo "[" . date('Y-m-d H:i:s') . "] Starting AI query for job {$jobId}\n";
echo "[" . date('Y-m-d H:i:s') . "] Query: " . substr($job['query'], 0, 100) . "\n";

// ── Run the AI query ───────────────────────────────────────────────────────────
try {
    $engine = new AIQueryEngine();

    if (!$engine->isConfigured()) {
        throw new RuntimeException(
            'Azure OpenAI is not configured. ' .
            'Set AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT in .env.'
        );
    }

    $result = $engine->processQuery(
        $job['query'],
        $job['user_id']  ?? 'unknown',
        $job['username'] ?? 'Unknown'
    );

    echo "[" . date('Y-m-d H:i:s') . "] Query complete. Response length: " . strlen($result) . " chars\n";

    // ── Write success ──────────────────────────────────────────────────────────
    $job['status']       = 'complete';
    $job['result']       = $result;
    $job['error']        = null;
    $job['completed_at'] = date('c');
    file_put_contents($jobFile, json_encode($job, JSON_PRETTY_PRINT));
    exit(0);

} catch (Throwable $e) {
    $msg = $e->getMessage();
    fwrite(STDERR, "[ai-query-worker] ERROR: {$msg}\n");
    echo "[" . date('Y-m-d H:i:s') . "] ERROR: {$msg}\n";

    // ── Write failure ──────────────────────────────────────────────────────────
    $job['status']       = 'error';
    $job['result']       = null;
    $job['error']        = $msg;
    $job['completed_at'] = date('c');
    file_put_contents($jobFile, json_encode($job, JSON_PRETTY_PRINT));
    exit(1);
}
