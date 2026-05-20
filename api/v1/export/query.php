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
require_once __DIR__ . '/../../../services/export-query-executor.php';

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key');

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
            'message' => '00 Authentication required'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

// Get authenticated user
$user = $unifiedAuth->getCurrentUser();
// Check if user has permission to access this resource
$unifiedAuth->requirePermission('reports', 'read');

$db = DatabaseConfig::getInstance();

// Get request method
$method = $_SERVER['REQUEST_METHOD'];

// Parse input: JSON body takes priority over query-string / form data
$jsonBody = [];
$rawBody  = file_get_contents('php://input');
if (!empty($rawBody)) {
    $decoded = json_decode($rawBody, true);
    if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
        $jsonBody = $decoded;
    }
}

// Merge sources: JSON body > POST fields > GET params (lower priority)
$input = array_merge($_GET, $_POST, $jsonBody);

try {
    switch ($method) {
        case 'GET':
        case 'POST':
            handleQueryRequest($input);
            break;
        default:
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            break;
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}

/**
 * Handle query / download requests.
 *
 * Input keys (any combination of JSON body, POST fields, or GET params):
 *   action        – "query" (default) | "download"
 *   primary_mode  – "vulnerability" (default) | "patch"
 *   export_format – "csv" (default) | "json" | "excel"
 *   limit         – integer, max 500 (preview only)
 *   offset        – integer >= 0
 *   filters       – object with up to four optional entity arrays:
 *                   {
 *                     "vulnerabilities": [{"fieldname", "operator", "value"}, ...],
 *                     "assets":          [{"fieldname", "operator", "value"}, ...],
 *                     "patches":         [{"fieldname", "operator", "value"}, ...],
 *                     "remediations":    [{"fieldname", "operator", "value"}, ...]
 *                   }
 *                   Field names are validated against per-entity whitelists.
 *                   Operators must be one of:
 *                     = != < > <= >= LIKE NOT LIKE STARTS ENDS IS NULL NOT NULL
 *                   All conditions within an entity are AND-ed together.
 *
 * Responses:
 *   action=query    → 200 JSON  {success, columns, rows, total, returned,
 *                                offset, limit, sql_preview, mode}
 *   action=download → file attachment (csv / json / excel)
 */
function handleQueryRequest(array $input): void
{
    $action = strtolower(trim($input['action'] ?? 'query'));

    $params = ExportQueryExecutor::resolveFilters($input);
    if ($params['error'] !== null) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => $params['error']]);
        return;
    }

    if ($action === 'query') {
        $result = ExportQueryExecutor::runPreview($params);
        if (!$result['success']) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => $result['error']]);
            return;
        }
        echo json_encode($result);
        return;
    }

    if ($action === 'download') {
        $result = ExportQueryExecutor::runExport($params);
        if (!$result['success']) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => $result['error']]);
            return;
        }

        $format   = $result['format'];
        $columns  = $result['columns'];
        $rows     = $result['rows'];
        $filename = $result['filename'];

        if ($format === 'csv')   { ExportQueryExecutor::streamCsv($columns, $rows, $filename); }
        if ($format === 'json')  { ExportQueryExecutor::streamJson($rows, $filename); }
        if ($format === 'excel') { ExportQueryExecutor::streamExcel($columns, $rows, $filename); }

        http_response_code(400);
        echo json_encode(['success' => false, 'error' => "Unknown export format: {$format}"]);
        return;
    }

    http_response_code(400);
    echo json_encode(['success' => false, 'error' => "Unknown action \"{$action}\". Use \"query\" or \"download\"."]);
}
