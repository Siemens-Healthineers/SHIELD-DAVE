<?php
/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
 *
 * Export Query AJAX endpoint
 * POST  ?action=preview   â€“ run query, return first N rows as JSON
 * POST  ?action=export    â€“ stream file download (csv / json / excel)
 *
 * Expected POST fields:
 *   asset_conditions_json        â€“ required  (condition tree for assets)
 *   vuln_conditions_json         â€“ optional
 *   patch_conditions_json        â€“ optional
 *   remediation_conditions_json  â€“ optional
 *   export_format                â€“ csv | json | excel
 *   limit / offset               â€“ for preview pagination
 */

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../services/export-query-executor.php';

header('Content-Type: application/json');

// Auth â”””””””””””””””””””””””””””””””””””””””””””””””””””””””””””””””””””””€
$auth->requireAuth();
$user = $auth->getCurrentUser();
if (!$user) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthenticated']);
    exit;
}
// Delegate to shared executor ─────────────────────────────────────────────────
$action = $_GET['action'] ?? 'preview';

$params = ExportQueryExecutor::resolveParams($_POST);
if ($params['error'] !== null) {
    echo json_encode(['error' => $params['error']]);
    exit;
}

// Action: preview ─────────────────────────────────────────────────────────────
if ($action === 'preview') {
    $result = ExportQueryExecutor::runPreview($params);
    if (!$result['success']) {
        echo json_encode(['error' => $result['error']]);
        exit;
    }
    echo json_encode($result);
    exit;
}

// Action: export ──────────────────────────────────────────────────────────────
if ($action === 'export') {
    $result = ExportQueryExecutor::runExport($params);
    if (!$result['success']) {
        echo json_encode(['error' => $result['error']]);
        exit;
    }

    $format   = $result['format'];
    $columns  = $result['columns'];
    $rows     = $result['rows'];
    $filename = $result['filename'];

    if ($format === 'csv')   { ExportQueryExecutor::streamCsv($columns, $rows, $filename); }
    if ($format === 'json')  { ExportQueryExecutor::streamJson($rows, $filename); }
    if ($format === 'excel') { ExportQueryExecutor::streamExcel($columns, $rows, $filename); }

    echo json_encode(['error' => "Unknown export format: {$format}"]);
    exit;
}

echo json_encode(['error' => "Unknown action: {$action}"]);