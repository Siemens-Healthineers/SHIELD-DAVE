<?php
/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
 *
 * ExportQueryBuilder
 * Translates frontend condition-tree JSON into parameterised PostgreSQL.
 *
 * buildJoined() – asset-centric joined export:
 *   Always queries assets (alias a).
 *   Optionally INNER JOINs vulnerabilities / patches / remediation_actions
 *   when condition trees for those entities are supplied.
 *
 * Only whitelisted field names per entity are allowed in SQL;
 * all values are bound via PDO placeholders.
 */

class ExportQueryBuilder
{
    // ── Table aliases used in joined queries ───────────────────────────────────
    private static array $ALIAS = [
        'asset'         => 'a',
        'vulnerability' => 'v',
        'patch'         => 'p',
        'remediation'   => 'ra',
    ];

    // ── Whitelisted columns per entity ─────────────────────────────────────────
    // Only these column names may appear un-escaped in the generated SQL.
    public static array $ALLOWED_FIELDS = [
        'asset' => [
            'asset_id','hostname','ip_address','mac_address','source','asset_tag',
            'asset_type','asset_subtype','manufacturer','model','serial_number',
            'location','firmware_version','cpu','memory_ram','storage',
            'power_requirements','primary_communication_protocol',
            'assigned_admin_user','business_unit','department','cost_center',
            'warranty_expiration_date','scheduled_replacement_date','disposal_date',
            'disposal_method','criticality','regulatory_classification','phi_status',
            'data_encryption_transit','data_encryption_rest','authentication_method',
            'patch_level_last_update','last_audit_date','status',
            'first_seen','last_seen','created_at','updated_at','metadata',
        ],
        'vulnerability' => [
            'vulnerability_id','cve_id','description','cvss_v3_score','cvss_v3_vector',
            'cvss_v2_score','cvss_v2_vector','cvss_v4_score','cvss_v4_vector',
            'severity','published_date','last_modified_date','is_kev',
            'kev_date_added','kev_due_date','kev_required_action',
            'priority','epss_score','epss_percentile','epss_date','epss_last_updated',
            'created_at','updated_at',
        ],
        'patch' => [
            'patch_id','patch_name','patch_type','target_device_type','target_version',
            'description','release_date','vendor','kb_article','requires_reboot',
            'is_active','estimated_install_time','estimated_downtime',
            'created_at','updated_at',
        ],
        'remediation' => [
            'action_id','cve_id','action_type','action_description','target_version',
            'patch_reference','vendor','status','due_date','completed_at',
            'notes','created_at','updated_at',
        ],
    ];

    // ── Columns that are stored as a non-text type and need ::text cast for
    //    pattern operators (ILIKE / NOT ILIKE).
    private static array $TEXT_CAST_FIELDS = [
        'asset' => ['ip_address', 'mac_address'],
    ];

    // ── UUID columns — must be cast to text for ALL comparison operators so
    //    PDO string bindings are accepted by PostgreSQL.
    private static array $UUID_CAST_FIELDS = [
        'asset'         => ['asset_id'],
        'vulnerability' => ['vulnerability_id'],
        'patch'         => ['patch_id'],
        'remediation'   => ['action_id'],
    ];

    // ── Operator whitelist ─────────────────────────────────────────────────────
    private static array $OPERATORS = ['=', '!=', '<', '>', '<=', '>=', 'LIKE', 'NOT LIKE', 'IS NULL', 'IS NOT NULL'];

    // Map frontend operator tokens → SQL operator + value transform
    public static array $OP_MAP = [
        '='        => ['sql' => '=',        'wrap' => 'exact'],
        '!='       => ['sql' => '!=',       'wrap' => 'exact'],
        '<'        => ['sql' => '<',        'wrap' => 'exact'],
        '>'        => ['sql' => '>',        'wrap' => 'exact'],
        '<='       => ['sql' => '<=',       'wrap' => 'exact'],
        '>='       => ['sql' => '>=',       'wrap' => 'exact'],
        'LIKE'     => ['sql' => 'ILIKE',    'wrap' => 'both'],   // case-insensitive contains
        'NOT LIKE' => ['sql' => 'NOT ILIKE','wrap' => 'both'],
        'STARTS'   => ['sql' => 'ILIKE',    'wrap' => 'start'],
        'ENDS'     => ['sql' => 'ILIKE',    'wrap' => 'end'],
        'IS NULL'  => ['sql' => 'IS NULL',  'wrap' => 'none'],
        'NOT NULL' => ['sql' => 'IS NOT NULL', 'wrap' => 'none'],
    ];

    // ── Key export columns per joined entity (prefixed in SELECT) ─────────────
    private static array $JOIN_SELECT_COLS = [
        'vulnerability' => [
            'cve_id','severity','cvss_v4_score','cvss_v3_score','epss_score',
            'epss_percentile','is_kev','priority','published_date','last_modified_date',
        ],
        'patch' => [
            'patch_name','patch_type','vendor','release_date',
            'target_version','requires_reboot','kb_article',
        ],
        'remediation' => [
            'action_type','action_description','status','due_date',
            'target_version','patch_reference','vendor',
        ],
    ];

    // ──────────────────────────────────────────────────────────────────────────
    // buildJoined — asset-centric multi-table query
    //
    // $assetTree      required  – condition tree for assets
    // $vulnTree       optional  – condition tree for vulnerabilities (or null/[])
    // $patchTree      optional  – condition tree for patches
    // $remTree        optional  – condition tree for remediation_actions
    //
    // Returns array with keys: sql, count_sql, params, columns, error
    // ──────────────────────────────────────────────────────────────────────────
    public static function buildJoined(
        array  $assetTree,
        ?array $vulnTree  = null,
        ?array $patchTree = null,
        ?array $remTree   = null,
        int    $limit     = 200,
        int    $offset    = 0
    ): array {
        $params   = [];
        $joinSql  = '';
        $whereParts = [];
        $selectCols = [];  // ["alias.col AS label", ...]
        $columnLabels = []; // flat list for the result table header

        // ── Asset SELECT columns ──
        foreach (self::$ALLOWED_FIELDS['asset'] as $col) {
            $selectCols[]   = 'a."' . $col . '"';
            $columnLabels[] = $col;
        }

        // ── Asset WHERE ──
        $assetWhere = self::buildNode($assetTree, 'asset', 'a', $params);
        if ($assetWhere !== '') {
            $whereParts[] = $assetWhere;
        }

        // ── Vulnerability JOIN ──
        if (!empty($vulnTree) && self::treeHasConditions($vulnTree)) {
            $joinSql .= "\n  INNER JOIN device_vulnerabilities_link dvl"
                      . " ON a.asset_id = dvl.asset_id"
                      . "\n  INNER JOIN vulnerabilities v"
                      . " ON dvl.vulnerability_id = v.vulnerability_id";
            foreach (self::$JOIN_SELECT_COLS['vulnerability'] as $col) {
                $selectCols[]   = 'v."' . $col . '" AS "vuln_' . $col . '"';
                $columnLabels[] = 'vuln_' . $col;
            }
            $vulnWhere = self::buildNode($vulnTree, 'vulnerability', 'v', $params);
            if ($vulnWhere !== '') {
                $whereParts[] = $vulnWhere;
            }
        }

        // ── Patch JOIN ──
        if (!empty($patchTree) && self::treeHasConditions($patchTree)) {
            $joinSql .= "\n  INNER JOIN (\n"
                      . "    SELECT patch_id, asset_id FROM patch_applications\n"
                      . "    UNION\n"
                      . "    SELECT st.patch_id, COALESCE(md.asset_id, a_hn.asset_id) AS asset_id\n"
                      . "    FROM scheduled_tasks st\n"
                      . "    LEFT JOIN medical_devices md ON st.device_id = md.device_id\n"
                      . "    LEFT JOIN assets a_hn ON a_hn.hostname = st.original_hostname\n"
                      . "    WHERE st.task_type = 'patch_application'\n"
                      . "      AND st.patch_id IS NOT NULL\n"
                      . "      AND COALESCE(md.asset_id, a_hn.asset_id) IS NOT NULL\n"
                      . "  ) pa ON a.asset_id = pa.asset_id"
                      . "\n  INNER JOIN patches p"
                      . " ON pa.patch_id = p.patch_id";
            foreach (self::$JOIN_SELECT_COLS['patch'] as $col) {
                $selectCols[]   = 'p."' . $col . '" AS "patch_' . $col . '"';
                $columnLabels[] = 'patch_' . $col;
            }
            $patchWhere = self::buildNode($patchTree, 'patch', 'p', $params);
            if ($patchWhere !== '') {
                $whereParts[] = $patchWhere;
            }
        }

        // ── Remediation JOIN ──
        if (!empty($remTree) && self::treeHasConditions($remTree)) {
            $joinSql .= "\n  INNER JOIN remediation_assets_link ral"
                      . " ON a.asset_id = ral.asset_id"
                      . "\n  INNER JOIN remediation_actions ra"
                      . " ON ral.remediation_id = ra.action_id";
            foreach (self::$JOIN_SELECT_COLS['remediation'] as $col) {
                $selectCols[]   = 'ra."' . $col . '" AS "rem_' . $col . '"';
                $columnLabels[] = 'rem_' . $col;
            }
            $remWhere = self::buildNode($remTree, 'remediation', 'ra', $params);
            if ($remWhere !== '') {
                $whereParts[] = $remWhere;
            }
        }

        $selectList = implode(",\n       ", $selectCols);
        $whereClause = !empty($whereParts)
            ? "\nWHERE  " . implode("\n  AND ", $whereParts)
            : '';

        $sql = "SELECT {$selectList}"
             . "\nFROM   assets a"
             . $joinSql
             . $whereClause
             . "\nORDER  BY a.asset_id"
             . "\nLIMIT  " . (int)$limit
             . " OFFSET " . (int)$offset;

        $countSql = "SELECT COUNT(*)"
                  . "\nFROM   assets a"
                  . $joinSql
                  . $whereClause;

        return [
            'sql'       => $sql,
            'count_sql' => $countSql,
            'params'    => $params,
            'columns'   => $columnLabels,
            'error'     => null,
        ];
    }

    // ──────────────────────────────────────────────────────────────────────────
    // buildModeCentric — vulnerability-centric or patch-centric query
    //
    // $mode              'vulnerability' | 'patch'  — primary driving table
    // $primaryTree       optional – conditions on the primary entity
    // $counterpartTree   optional – conditions on the OPPOSITE entity
    //                    (patch when mode=vulnerability, vuln when mode=patch)
    //                    Adds an INNER JOIN to the counterpart table.
    // $assetTree         optional – filter assets (always INNER JOINed via link table)
    // $remTree           optional – LEFT JOIN remediation_actions when supplied
    //
    // Column naming:
    //   Primary entity columns     → no prefix  (e.g. cve_id, patch_name)
    //   Counterpart entity columns → counterpart_* prefix
    //   Asset columns              → asset_*     (e.g. asset_hostname)
    //   Remediation columns        → rem_*       (e.g. rem_action_type)
    // ──────────────────────────────────────────────────────────────────────────
    public static function buildModeCentric(
        string $mode,
        ?array $primaryTree     = null,
        ?array $counterpartTree = null,
        ?array $assetTree       = null,
        ?array $remTree         = null,
        int    $limit           = 200,
        int    $offset          = 0
    ): array {
        if (!in_array($mode, ['vulnerability', 'patch'], true)) {
            return ['sql' => '', 'count_sql' => '', 'params' => [], 'columns' => [], 'error' => "Invalid mode \"{$mode}\"."];
        }

        // ── Primary SELECT columns (no prefix – main payload) ──
        $primaryCols = $mode === 'vulnerability'
            ? ['vulnerability_id','cve_id','description','severity',
               'cvss_v4_score','cvss_v4_vector','cvss_v3_score','cvss_v3_vector',
               'cvss_v2_score','cvss_v2_vector',
               'priority','is_kev','epss_score','epss_percentile',
               'epss_date','epss_last_updated',
               'published_date','last_modified_date',
               'kev_date_added','kev_due_date','kev_required_action',
               'created_at','updated_at']
            : ['patch_id','patch_name','patch_type','vendor','release_date',
               'requires_reboot','is_active','description',
               'target_version','kb_article','estimated_install_time'];

        // ── Asset SELECT columns (prefixed asset_) ──
        $assetCols = [
            'asset_id','hostname','ip_address','asset_type','manufacturer',
            'model','location','department','business_unit','criticality','status',
        ];

        // ── Remediation SELECT columns (prefixed rem_) ──
        $remCols = [
            'action_id','action_type','action_description',
            'status','cve_id','due_date','completed_at',
        ];

        $alias      = self::$ALIAS[$mode]; // 'v' or 'p'
        $params     = [];
        $whereParts = [];
        $selectCols = [];
        $colLabels  = [];

        // Counterpart entity config (opposite of $mode)
        $counterpart      = ($mode === 'vulnerability') ? 'patch' : 'vulnerability';
        $counterpartAlias = self::$ALIAS[$counterpart]; // 'p' or 'v'
        $includeCounterpart = !empty($counterpartTree);

        // Primary columns
        foreach ($primaryCols as $col) {
            if (!in_array($col, self::$ALLOWED_FIELDS[$mode] ?? [], true)) continue;
            $selectCols[] = $alias . '."' . $col . '"';
            $colLabels[]  = $col;
        }

        // Asset columns
        foreach ($assetCols as $col) {
            if (!in_array($col, self::$ALLOWED_FIELDS['asset'] ?? [], true)) continue;
            $selectCols[] = 'a."' . $col . '" AS "asset_' . $col . '"';
            $colLabels[]  = 'asset_' . $col;
        }

        // Counterpart columns (prefixed counterpart_)
        if ($includeCounterpart) {
            foreach (self::$JOIN_SELECT_COLS[$counterpart] as $col) {
                $selectCols[] = $counterpartAlias . '."' . $col . '" AS "counterpart_' . $col . '"';
                $colLabels[]  = 'counterpart_' . $col;
            }
        }

        $includeRem = ($remTree !== null);

        // Remediation columns
        if ($includeRem) {
            foreach ($remCols as $col) {
                if (!in_array($col, self::$ALLOWED_FIELDS['remediation'] ?? [], true)) continue;
                $selectCols[] = 'ra."' . $col . '" AS "rem_' . $col . '"';
                $colLabels[]  = 'rem_' . $col;
            }
        }

        // ── WHERE clauses ──
        if (!empty($primaryTree)) {
            $clause = self::buildNode($primaryTree, $mode, $alias, $params);
            if ($clause !== '') $whereParts[] = $clause;
        }
        if (!empty($assetTree)) {
            $clause = self::buildNode($assetTree, 'asset', 'a', $params);
            if ($clause !== '') $whereParts[] = $clause;
        }
        if ($includeCounterpart && !empty($counterpartTree)) {
            $clause = self::buildNode($counterpartTree, $counterpart, $counterpartAlias, $params);
            if ($clause !== '') $whereParts[] = $clause;
        }
        if ($includeRem && !empty($remTree)) {
            $clause = self::buildNode($remTree, 'remediation', 'ra', $params);
            if ($clause !== '') $whereParts[] = $clause;
        }

        // ── FROM + JOINs ──
        if ($mode === 'vulnerability') {
            $fromJoin = "vulnerabilities v\n"
                . "  INNER JOIN device_vulnerabilities_link dvl"
                . " ON v.vulnerability_id = dvl.vulnerability_id\n"
                . "  INNER JOIN assets a ON dvl.asset_id = a.asset_id";
            $orderBy  = 'v.severity, v.cve_id';
        } else {
            $fromJoin = "patches p\n"
                . "  INNER JOIN (\n"
                . "    SELECT patch_id, asset_id FROM patch_applications\n"
                . "    UNION\n"
                . "    SELECT st.patch_id, COALESCE(md.asset_id, a_hn.asset_id) AS asset_id\n"
                . "    FROM scheduled_tasks st\n"
                . "    LEFT JOIN medical_devices md ON st.device_id = md.device_id\n"
                . "    LEFT JOIN assets a_hn ON a_hn.hostname = st.original_hostname\n"
                . "    WHERE st.task_type = 'patch_application'\n"
                . "      AND st.patch_id IS NOT NULL\n"
                . "      AND COALESCE(md.asset_id, a_hn.asset_id) IS NOT NULL\n"
                . "  ) pa ON p.patch_id = pa.patch_id\n"
                . "  INNER JOIN assets a ON pa.asset_id = a.asset_id";
            $orderBy  = 'p.release_date DESC, p.patch_name';
        }

        // Counterpart JOIN (opposite entity, via assets as bridge)
        if ($includeCounterpart) {
            if ($counterpart === 'patch') {
                $fromJoin .= "\n  INNER JOIN (\n"
                           . "    SELECT patch_id, asset_id FROM patch_applications\n"
                           . "    UNION\n"
                           . "    SELECT st.patch_id, COALESCE(md.asset_id, a_hn.asset_id) AS asset_id\n"
                           . "    FROM scheduled_tasks st\n"
                           . "    LEFT JOIN medical_devices md ON st.device_id = md.device_id\n"
                           . "    LEFT JOIN assets a_hn ON a_hn.hostname = st.original_hostname\n"
                           . "    WHERE st.task_type = 'patch_application'\n"
                           . "      AND st.patch_id IS NOT NULL\n"
                           . "      AND COALESCE(md.asset_id, a_hn.asset_id) IS NOT NULL\n"
                           . "  ) cpa ON a.asset_id = cpa.asset_id"
                           . "\n  INNER JOIN patches p ON cpa.patch_id = p.patch_id";
            } else {
                $fromJoin .= "\n  INNER JOIN device_vulnerabilities_link cdvl ON a.asset_id = cdvl.asset_id"
                           . "\n  INNER JOIN vulnerabilities v ON cdvl.vulnerability_id = v.vulnerability_id";
            }
        }

        if ($includeRem) {
            $fromJoin .= "\n  LEFT JOIN remediation_assets_link ral ON a.asset_id = ral.asset_id"
                       . "\n  LEFT JOIN remediation_actions ra ON ral.remediation_id = ra.action_id";
        }

        $selectList  = implode(",\n       ", $selectCols);
        $whereClause = !empty($whereParts)
            ? "\nWHERE  " . implode("\n  AND ", $whereParts)
            : '';

        $sql = "SELECT {$selectList}"
             . "\nFROM   {$fromJoin}"
             . $whereClause
             . "\nORDER  BY {$orderBy}"
             . "\nLIMIT  " . (int)$limit
             . " OFFSET " . (int)$offset;

        $countSql = "SELECT COUNT(*)"
                  . "\nFROM   {$fromJoin}"
                  . $whereClause;

        return [
            'sql'       => $sql,
            'count_sql' => $countSql,
            'params'    => $params,
            'columns'   => $colLabels,
            'error'     => null,
        ];
    }

    // ── Check if a tree has at least one condition node ────────────────────────
    private static function treeHasConditions(array $node): bool
    {
        if ($node['type'] === 'condition') {
            return !empty($node['field']);
        }
        if ($node['type'] === 'group') {
            foreach ($node['children'] as $child) {
                if (self::treeHasConditions($child)) return true;
            }
        }
        return false;
    }

    // ── Recurse through tree node ──────────────────────────────────────────────
    // $alias: table alias to prefix column references (e.g. 'a', 'v', 'p', 'ra')
    private static function buildNode(array $node, string $entity, string $alias, array &$params): string
    {
        if ($node['type'] === 'condition') {
            return self::buildCondition($node, $entity, $alias, $params);
        }

        if ($node['type'] === 'group') {
            $parts = [];
            foreach ($node['children'] as $child) {
                $fragment = self::buildNode($child, $entity, $alias, $params);
                if ($fragment !== '') {
                    $parts[] = $fragment;
                }
            }
            if (empty($parts)) return '';
            $op = strtoupper($node['operator'] ?? 'AND') === 'OR' ? 'OR' : 'AND';
            return count($parts) === 1 ? $parts[0] : '(' . implode(" {$op} ", $parts) . ')';
        }

        return '';
    }

    // ── Build a single condition clause with table alias ───────────────────────
    private static function buildCondition(array $cond, string $entity, string $alias, array &$params): string
    {
        $field    = $cond['field']    ?? '';
        $operator = $cond['operator'] ?? '=';
        $value    = $cond['value']    ?? '';

        if (empty($field) || !in_array($field, self::$ALLOWED_FIELDS[$entity] ?? [], true)) {
            throw new InvalidArgumentException("Field \"{$field}\" is not allowed for entity \"{$entity}\".");
        }
        if (!isset(self::$OP_MAP[$operator])) {
            throw new InvalidArgumentException("Operator \"{$operator}\" is not permitted.");
        }

        $opDef   = self::$OP_MAP[$operator];
        $sqlOp   = $opDef['sql'];
        $wrap    = $opDef['wrap'];
        $colExpr = $alias . '."' . $field . '"';

        // Cast inet/macaddr columns to text for pattern operators.
        $needsTextCast = in_array($field, self::$TEXT_CAST_FIELDS[$entity] ?? [], true);
        if ($needsTextCast && in_array($wrap, ['both', 'start', 'end'], true)) {
            $colExpr = 'CAST(' . $colExpr . ' AS TEXT)';
        }

        // Cast UUID columns to text for all operators — PDO always binds
        // parameters as strings and PostgreSQL won't implicitly coerce them.
        $isUuid = in_array($field, self::$UUID_CAST_FIELDS[$entity] ?? [], true);
        if ($isUuid && $wrap !== 'none') {
            $colExpr = 'CAST(' . $colExpr . ' AS TEXT)';
        }

        if ($wrap === 'none') {
            return "{$colExpr} {$sqlOp}";
        }

        $placeholder = ':p' . count($params);

        switch ($wrap) {
            case 'both':  $bindValue = '%' . self::escapeLike($value) . '%'; break;
            case 'start': $bindValue = self::escapeLike($value) . '%';       break;
            case 'end':   $bindValue = '%' . self::escapeLike($value);       break;
            default:      $bindValue = $value;                                break;
        }

        $params[$placeholder] = $bindValue;
        return "{$colExpr} {$sqlOp} {$placeholder}";
    }

    // ── Escape LIKE wildcards ──────────────────────────────────────────────────
    private static function escapeLike(string $value): string
    {
        return str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $value);
    }

    // ── Human-readable SQL preview (values inlined — NOT for execution) ────────
    public static function humanReadable(string $sql, array $params): string
    {
        // Sort by key length desc to avoid partial replacement (:p1 replacing :p10)
        uksort($params, fn($a, $b) => strlen($b) - strlen($a));
        $display = $sql;
        foreach ($params as $k => $v) {
            $quoted  = is_numeric($v) ? $v : "'" . addslashes((string)$v) . "'";
            $display = str_replace($k, $quoted, $display);
        }
        return $display;
    }
}
