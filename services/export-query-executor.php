<?php
/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
 *
 * ExportQueryExecutor
 * Shared execution layer for the export query builder.
 * Used by both the UI endpoint (pages/export/query.php) and the HTTP API
 * (api/v1/reports/query.php) so both paths stay in sync.
 *
 * Public API
 * ----------
 * ExportQueryExecutor::decodeTree(string $raw) : ?array
 *     Decode a JSON condition-tree string. Returns null when empty/invalid.
 *
 * ExportQueryExecutor::resolveParams(array $input) : array
 *     Validate and normalise query parameters from an associative array.
 *     Returns ['mode', 'primaryTree', 'counterpartTree', 'assetTree',
 *              'remTree', 'limit', 'offset', 'format', 'error'].
 *     'error' is null on success, a string on failure.
 *
 * ExportQueryExecutor::runPreview(array $params) : array
 *     Execute the query and return a preview result array.
 *
 * ExportQueryExecutor::runExport(array $params) : array
 *     Execute the full (unlimited) query and return rows + metadata.
 *     Returns ['columns', 'rows', 'mode', 'format', 'error'].
 *
 * ExportQueryExecutor::streamCsv(array $columns, array $rows, string $filename) : void
 *     Send CSV headers and stream CSV content. Exits when done.
 *
 * ExportQueryExecutor::streamJson(array $rows, string $filename) : void
 *     Send JSON attachment headers and stream JSON content. Exits when done.
 *
 * ExportQueryExecutor::streamExcel(array $columns, array $rows, string $filename) : void
 *     Send XLS (SpreadsheetML) headers and stream content. Exits when done.
 */

if (!class_exists('ExportQueryBuilder')) {
    require_once __DIR__ . '/export-query-builder.php';
}

class ExportQueryExecutor
{
    // Maximum rows returned in a preview response.
    public const PREVIEW_LIMIT_MAX = 500;

    // Maximum rows returned in a full export.
    public const EXPORT_LIMIT_MAX  = 100000;

    // ─────────────────────────────────────────────────────────────────────
    // decodeTree
    // ─────────────────────────────────────────────────────────────────────
    /**
     * Decode a JSON condition-tree string.
     *
     * @param  string $raw  Raw JSON string (may be empty).
     * @return array|null   Decoded tree, or null when absent / invalid.
     */
    public static function decodeTree(string $raw): ?array
    {
        $raw = trim($raw);
        if ($raw === '') return null;
        $decoded = json_decode($raw, true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) return null;
        return $decoded;
    }

    // ─────────────────────────────────────────────────────────────────────
    // resolveParams
    // ─────────────────────────────────────────────────────────────────────
    /**
     * Validate and normalise query parameters.
     *
     * Accepts an associative array with the following keys (all optional
     * except primary_mode has a default):
     *   primary_mode            string   'vulnerability' | 'patch'  (default: 'vulnerability')
     *   primary_conditions_json string   JSON condition tree
     *   counterpart_conditions_json string
     *   asset_conditions_json   string
     *   remediation_conditions_json string
     *   limit                   int      max rows (preview)
     *   offset                  int      row offset (preview)
     *   export_format           string   'csv' | 'json' | 'excel'   (default: 'csv')
     *
     * @param  array $input
     * @return array{mode:string, primaryTree:array|null, counterpartTree:array|null,
     *               assetTree:array|null, remTree:array|null,
     *               limit:int, offset:int, format:string, error:string|null}
     */
    public static function resolveParams(array $input): array
    {
        $mode = strtolower(trim($input['primary_mode'] ?? 'vulnerability'));
        if (!in_array($mode, ['vulnerability', 'patch'], true)) {
            return self::errorResult("Invalid primary_mode \"{$mode}\". Must be 'vulnerability' or 'patch'.");
        }

        // Decode primary tree; report JSON parse errors explicitly.
        $primaryRaw  = trim($input['primary_conditions_json'] ?? '');
        $primaryTree = null;
        if ($primaryRaw !== '') {
            $primaryTree = json_decode($primaryRaw, true);
            if (json_last_error() !== JSON_ERROR_NONE || !is_array($primaryTree)) {
                return self::errorResult('primary_conditions_json is not valid JSON.');
            }
        }

        $counterpartTree = self::decodeTree($input['counterpart_conditions_json'] ?? '');
        $assetTree       = self::decodeTree($input['asset_conditions_json']       ?? '');
        $remTree         = self::decodeTree($input['remediation_conditions_json'] ?? '');

        $limit  = min((int)($input['limit']  ?? 200), self::PREVIEW_LIMIT_MAX);
        $offset = max((int)($input['offset'] ?? 0),   0);

        $format = strtolower(trim($input['export_format'] ?? 'csv'));
        if (!in_array($format, ['csv', 'json', 'excel'], true)) {
            return self::errorResult("Invalid export_format \"{$format}\". Must be 'csv', 'json', or 'excel'.");
        }

        return [
            'mode'            => $mode,
            'primaryTree'     => $primaryTree,
            'counterpartTree' => $counterpartTree,
            'assetTree'       => $assetTree,
            'remTree'         => $remTree,
            'limit'           => $limit,
            'offset'          => $offset,
            'format'          => $format,
            'error'           => null,
        ];
    }

    // ─────────────────────────────────────────────────────────────────────
    // runPreview
    // ─────────────────────────────────────────────────────────────────────
    /**
     * Build and execute the query for a preview (paginated, limited rows).
     *
     * @param  array $params  Output of resolveParams().
     * @return array{success:bool, columns:array, rows:array, total:int,
     *               returned:int, offset:int, limit:int, sql_preview:string,
     *               mode:string, error:string|null}
     */
    public static function runPreview(array $params): array
    {
        try {
            $built = ExportQueryBuilder::buildModeCentric(
                $params['mode'],
                $params['primaryTree'],
                $params['counterpartTree'],
                $params['assetTree'],
                $params['remTree'],
                $params['limit'],
                $params['offset']
            );
        } catch (InvalidArgumentException $e) {
            return ['success' => false, 'error' => 'Query builder error: ' . $e->getMessage()];
        } catch (Throwable $e) {
            error_log('ExportQueryExecutor::runPreview builder exception: ' . $e->getMessage());
            return ['success' => false, 'error' => 'Unexpected error building query.'];
        }

        if ($built['error']) {
            return ['success' => false, 'error' => $built['error']];
        }

        try {
            $db        = DatabaseConfig::getInstance();
            $stmt      = $db->query($built['sql'],       $built['params']);
            $rows      = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $cntStmt   = $db->query($built['count_sql'], $built['params']);
            $total     = (int)$cntStmt->fetchColumn();
        } catch (Throwable $e) {
            error_log('ExportQueryExecutor::runPreview execution failed: ' . $e->getMessage());
            return ['success' => false, 'error' => 'Query execution failed: ' . $e->getMessage()];
        }

        return [
            'success'     => true,
            'columns'     => $built['columns'],
            'rows'        => $rows,
            'total'       => $total,
            'returned'    => count($rows),
            'offset'      => $params['offset'],
            'limit'       => $params['limit'],
            'sql_preview' => ExportQueryBuilder::humanReadable($built['sql'], $built['params']),
            'mode'        => $params['mode'],
            'error'       => null,
        ];
    }

    // ─────────────────────────────────────────────────────────────────────
    // runExport
    // ─────────────────────────────────────────────────────────────────────
    /**
     * Build and execute the query for a full export (all matching rows).
     *
     * @param  array $params  Output of resolveParams().
     * @return array{success:bool, columns:array, rows:array, mode:string,
     *               format:string, filename:string, error:string|null}
     */
    public static function runExport(array $params): array
    {
        try {
            $built = ExportQueryBuilder::buildModeCentric(
                $params['mode'],
                $params['primaryTree'],
                $params['counterpartTree'],
                $params['assetTree'],
                $params['remTree'],
                self::EXPORT_LIMIT_MAX,
                0
            );
        } catch (InvalidArgumentException $e) {
            return ['success' => false, 'error' => 'Query builder error: ' . $e->getMessage()];
        } catch (Throwable $e) {
            error_log('ExportQueryExecutor::runExport builder exception: ' . $e->getMessage());
            return ['success' => false, 'error' => 'Unexpected error building query.'];
        }

        if ($built['error']) {
            return ['success' => false, 'error' => $built['error']];
        }

        error_log('Export query (full): ' . ExportQueryBuilder::humanReadable($built['sql'], $built['params']));

        try {
            $db   = DatabaseConfig::getInstance();
            $stmt = $db->query($built['sql'], $built['params']);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            error_log('ExportQueryExecutor::runExport execution failed: ' . $e->getMessage());
            return ['success' => false, 'error' => 'Export query failed: ' . $e->getMessage()];
        }

        $timestamp = date('Ymd_His');
        $filename  = "export_{$params['mode']}s_{$timestamp}";

        return [
            'success'  => true,
            'columns'  => $built['columns'],
            'rows'     => $rows,
            'mode'     => $params['mode'],
            'format'   => $params['format'],
            'filename' => $filename,
            'error'    => null,
        ];
    }

    // ─────────────────────────────────────────────────────────────────────
    // streamCsv
    // ─────────────────────────────────────────────────────────────────────
    /**
     * Send CSV file download headers and stream CSV content.
     * Calls exit() when done.
     *
     * @param array  $columns Column header labels.
     * @param array  $rows    Rows as associative arrays.
     * @param string $filename Base filename without extension.
     */
    public static function streamCsv(array $columns, array $rows, string $filename): void
    {
        header('Content-Type: text/csv; charset=UTF-8');
        header("Content-Disposition: attachment; filename=\"{$filename}.csv\"");
        $out = fopen('php://output', 'w');
        fprintf($out, chr(0xEF) . chr(0xBB) . chr(0xBF)); // UTF-8 BOM
        fputcsv($out, $columns);
        foreach ($rows as $row) {
            fputcsv($out, array_values($row));
        }
        fclose($out);
        exit;
    }

    // ─────────────────────────────────────────────────────────────────────
    // streamJson
    // ─────────────────────────────────────────────────────────────────────
    /**
     * Send JSON attachment headers and stream JSON content.
     * Calls exit() when done.
     *
     * @param array  $rows     Rows as associative arrays.
     * @param string $filename Base filename without extension.
     */
    public static function streamJson(array $rows, string $filename): void
    {
        header('Content-Type: application/json');
        header("Content-Disposition: attachment; filename=\"{$filename}.json\"");
        echo json_encode($rows, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit;
    }

    // ─────────────────────────────────────────────────────────────────────
    // streamExcel
    // ─────────────────────────────────────────────────────────────────────
    /**
     * Send SpreadsheetML (XLS) headers and stream content.
     * Calls exit() when done.
     *
     * @param array  $columns Column header labels.
     * @param array  $rows    Rows as associative arrays.
     * @param string $filename Base filename without extension.
     */
    public static function streamExcel(array $columns, array $rows, string $filename): void
    {
        header('Content-Type: application/vnd.ms-excel');
        header("Content-Disposition: attachment; filename=\"{$filename}.xls\"");
        echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
        echo '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
               xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
        <Worksheet ss:Name="Export"><Table>';
        echo '<Row>';
        foreach ($columns as $col) {
            echo '<Cell><Data ss:Type="String">' . htmlspecialchars((string)$col, ENT_XML1) . '</Data></Cell>';
        }
        echo '</Row>';
        foreach ($rows as $row) {
            echo '<Row>';
            foreach (array_values($row) as $val) {
                $type = is_numeric($val) ? 'Number' : 'String';
                echo '<Cell><Data ss:Type="' . $type . '">' . htmlspecialchars((string)$val, ENT_XML1) . '</Data></Cell>';
            }
            echo '</Row>';
        }
        echo '</Table></Worksheet></Workbook>';
        exit;
    }

    // ─────────────────────────────────────────────────────────────────────
    // resolveFilters
    // ─────────────────────────────────────────────────────────────────────
    /**
     * Resolve parameters from the flat "filters" API format.
     *
     * Input keys (JSON body, POST fields, or GET params):
     *   primary_mode   string  'vulnerability' | 'patch'   (default: 'vulnerability')
     *   export_format  string  'csv' | 'json' | 'excel'    (default: 'csv')
     *   limit          int     max rows for preview         (default: 200, max: 500)
     *   offset         int     row offset                   (default: 0)
     *   filters        object  {
     *                    vulnerabilities?: [{fieldname, operator, value}, ...],
     *                    assets?:          [{fieldname, operator, value}, ...],
     *                    patches?:         [{fieldname, operator, value}, ...],
     *                    remediations?:    [{fieldname, operator, value}, ...],
     *                  }
     *
     * Field names are validated against the per-entity whitelist in
     * ExportQueryBuilder::$ALLOWED_FIELDS.
     * Operators are validated against ExportQueryBuilder::$OP_MAP keys:
     *   = != < > <= >= LIKE NOT LIKE STARTS ENDS IS NULL NOT NULL
     * All conditions within an entity array are AND-ed together.
     *
     * @param  array $input
     * @return array  Same shape as resolveParams() output.
     */
    public static function resolveFilters(array $input): array
    {
        $mode = strtolower(trim($input['primary_mode'] ?? 'vulnerability'));
        if (!in_array($mode, ['vulnerability', 'patch'], true)) {
            return self::errorResult("Invalid primary_mode \"{$mode}\". Must be 'vulnerability' or 'patch'.");
        }

        $limit  = min((int)($input['limit']  ?? 200), self::PREVIEW_LIMIT_MAX);
        $offset = max((int)($input['offset'] ?? 0),   0);

        $format = strtolower(trim($input['export_format'] ?? 'csv'));
        if (!in_array($format, ['csv', 'json', 'excel'], true)) {
            return self::errorResult("Invalid export_format \"{$format}\". Must be 'csv', 'json', or 'excel'.");
        }

        // Parse filters – arrives as an array from a JSON body, or a string from form data.
        $filters = $input['filters'] ?? [];
        if (is_string($filters)) {
            $filters = json_decode($filters, true);
            if (json_last_error() !== JSON_ERROR_NONE || !is_array($filters)) {
                return self::errorResult('filters must be a valid JSON object.');
            }
        }
        if (!is_array($filters)) {
            return self::errorResult('filters must be an object.');
        }

        // Map: input key → internal entity name used for whitelist lookup.
        $entityMap = [
            'vulnerabilities' => 'vulnerability',
            'assets'          => 'asset',
            'patches'         => 'patch',
            'remediations'    => 'remediation',
        ];

        $validOperators = array_keys(ExportQueryBuilder::$OP_MAP);
        $trees          = [];

        foreach ($entityMap as $filterKey => $entityName) {
            $conditions = $filters[$filterKey] ?? [];
            if (!is_array($conditions)) {
                return self::errorResult("filters.{$filterKey} must be an array.");
            }
            if (empty($conditions)) {
                $trees[$filterKey] = null;
                continue;
            }

            $allowedFields = ExportQueryBuilder::$ALLOWED_FIELDS[$entityName] ?? [];
            $children      = [];

            foreach ($conditions as $i => $condition) {
                if (!is_array($condition)) {
                    return self::errorResult("filters.{$filterKey}[{$i}] must be an object.");
                }
                if (!array_key_exists('fieldname', $condition)) {
                    return self::errorResult("filters.{$filterKey}[{$i}] is missing 'fieldname'.");
                }
                if (!array_key_exists('operator', $condition)) {
                    return self::errorResult("filters.{$filterKey}[{$i}] is missing 'operator'.");
                }

                $fieldname = (string)$condition['fieldname'];
                $operator  = (string)$condition['operator'];
                $value     = (string)($condition['value'] ?? '');

                if (!in_array($fieldname, $allowedFields, true)) {
                    return self::errorResult(
                        "filters.{$filterKey}[{$i}]: '{$fieldname}' is not a valid field for '{$entityName}'. " .
                        "Allowed fields: " . implode(', ', $allowedFields)
                    );
                }
                if (!in_array($operator, $validOperators, true)) {
                    return self::errorResult(
                        "filters.{$filterKey}[{$i}]: '{$operator}' is not a valid operator. " .
                        "Allowed operators: " . implode(', ', $validOperators)
                    );
                }

                $leaf = ['type' => 'condition', 'field' => $fieldname, 'operator' => $operator];
                if (!in_array($operator, ['IS NULL', 'NOT NULL'], true)) {
                    $leaf['value'] = $value;
                }
                $children[] = $leaf;
            }

            $trees[$filterKey] = ['type' => 'group', 'operator' => 'AND', 'children' => $children];
        }

        // Map entity trees to the positions ExportQueryBuilder::buildModeCentric() expects.
        //   primary_mode=vulnerability → vulnerabilities=primary,  patches=counterpart
        //   primary_mode=patch         → patches=primary,          vulnerabilities=counterpart
        if ($mode === 'vulnerability') {
            $primaryTree     = $trees['vulnerabilities'];
            $counterpartTree = $trees['patches'];
        } else {
            $primaryTree     = $trees['patches'];
            $counterpartTree = $trees['vulnerabilities'];
        }

        return [
            'mode'            => $mode,
            'primaryTree'     => $primaryTree,
            'counterpartTree' => $counterpartTree,
            'assetTree'       => $trees['assets'],
            'remTree'         => $trees['remediations'],
            'limit'           => $limit,
            'offset'          => $offset,
            'format'          => $format,
            'error'           => null,
        ];
    }

    // ─────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────
    private static function errorResult(string $msg): array
    {
        return [
            'mode'            => '',
            'primaryTree'     => null,
            'counterpartTree' => null,
            'assetTree'       => null,
            'remTree'         => null,
            'limit'           => 200,
            'offset'          => 0,
            'format'          => 'csv',
            'error'           => $msg,
        ];
    }
}
