<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

/**
 * AI Query Engine for Natural Language Security Analytics
 *
 * Flow:
 *   1. User submits a natural-language question.
 *   2. First LLM call  → generate a safe PostgreSQL SELECT query.
 *   3. Execute the SQL → return up to MAX_ROWS rows from the database.
 *   4. Second LLM call → interpret the result set as a human-readable answer.
 */
class AIQueryEngine {

    private $apiKey;
    private $endpoint;
    private $deployment;
    private $apiVersion;
    private $maxTokens = 2000;

    /** Maximum rows returned to the LLM to avoid token overflow */
    private const MAX_ROWS = 100;
    
    public function __construct() {
        $this->loadConfiguration();
    }
    
    /**
     * Load Azure OpenAI configuration from .env file
     * Required env vars:
     *   AZURE_OPENAI_API_KEY      - Your Azure OpenAI API key
     *   AZURE_OPENAI_ENDPOINT     - e.g. https://my-resource.openai.azure.com
     *   AZURE_OPENAI_DEPLOYMENT   - Your deployment name, e.g. gpt-4o
     *   AZURE_OPENAI_API_VERSION  - e.g. 2024-12-01-preview
     */
    private function loadConfiguration() {
        $this->apiKey     = getenv('AZURE_OPENAI_API_KEY')     ?: ($_ENV['AZURE_OPENAI_API_KEY']     ?? '');
        $this->endpoint   = rtrim(getenv('AZURE_OPENAI_ENDPOINT')   ?: ($_ENV['AZURE_OPENAI_ENDPOINT']   ?? ''), '/');
        $this->deployment = getenv('AZURE_OPENAI_DEPLOYMENT')  ?: ($_ENV['AZURE_OPENAI_DEPLOYMENT']  ?? '');
        $this->apiVersion = getenv('AZURE_OPENAI_API_VERSION') ?: ($_ENV['AZURE_OPENAI_API_VERSION'] ?? '2024-12-01-preview');
    }
    
    /**
     * Check if Azure OpenAI is configured
     */
    public function isConfigured() {
        return !empty($this->apiKey) && !empty($this->endpoint) && !empty($this->deployment);
    }
    
    /**
     * Process natural language query – two-step Text-to-SQL flow:
     *   1. Ask AI to produce a SQL SELECT query from the question.
     *   2. Execute the SQL against the DAVE database.
     *   3. Ask AI to interpret the result set in plain English.
     */
    public function processQuery($query, $userId, $username) {
        $schema = $this->getDatabaseSchema();

        // ── Step 1: generate SQL ──────────────────────────────────────────────
        $sqlSystemPrompt = $this->buildSQLGenerationPrompt($schema);
        $rawSQL = $this->callOpenAI($sqlSystemPrompt, $query);
        $sql    = $this->extractSQL($rawSQL);

        error_log(sprintf('[AI SQL] User: %s | SQL: %s', $username, $sql));

        // ── Validate: only SELECT allowed ─────────────────────────────────────
        $this->validateSQL($sql);

        // ── Step 2: execute SQL ───────────────────────────────────────────────
        $rows     = $this->executeSQLQuery($sql);
        $rowCount = count($rows);

        // ── Step 3: interpret results ─────────────────────────────────────────
        $interpretPrompt = $this->buildInterpretationPrompt($query, $sql, $rows, $rowCount);
        $answer = $this->callOpenAI($interpretPrompt['system'], $interpretPrompt['user']);

        return $answer;
    }

    // ─── SQL Generation ───────────────────────────────────────────────────────

    /**
     * Schema description sent to the AI so it can write accurate SQL.
     */
    private function getDatabaseSchema(): string {
        return <<<'SCHEMA'
PostgreSQL database: DAVE (Device Assessment and Vulnerability Exposure)
All tables are in the "public" schema.

KEY TABLES AND COLUMNS (use EXACT column names as listed)
──────────────────────────────────────────────────────────

vulnerabilities
  vulnerability_id uuid (PK), cve_id varchar(20), description text,
  severity varchar(20)            -- values: 'Critical','High','Medium','Low','Info','Unknown'
  cvss_v3_score numeric(3,1), cvss_v2_score numeric(3,1), cvss_v4_score numeric(3,1),
  epss_score numeric(5,4), epss_percentile numeric(5,4), epss_date date,
  is_kev boolean,                 -- TRUE = actively exploited (CISA KEV)
  priority varchar(20)            -- values: 'Critical-KEV','High','Medium','Low','Normal'
  published_date date, last_modified_date date,
  created_at timestamp, updated_at timestamp

assets
  asset_id uuid (PK), hostname varchar(255), ip_address inet, mac_address macaddr,
  asset_type varchar(50), asset_subtype varchar(50),
  manufacturer varchar(100), model varchar(100), serial_number varchar(100),
  firmware_version varchar(50),
  criticality varchar(20),        -- e.g. 'Critical','High','Medium','Low'
  location varchar(255), department varchar(100), business_unit varchar(100),
  first_seen timestamp, last_seen timestamp, created_at timestamp, updated_at timestamp

medical_devices
  device_id uuid (PK), asset_id uuid (FK → assets),
  brand_name varchar(100), model_number varchar(100),
  manufacturer_name varchar(100), -- NOTE: manufacturer_name NOT manufacturer
  device_description text,
  fda_class varchar(10),          -- 'I', 'II', 'III'
  fda_class_name varchar(200), medical_specialty varchar(100),
  udi varchar(100), catalog_number varchar(100),
  created_at timestamp, updated_at timestamp

device_vulnerabilities_link       -- links medical_devices ↔ vulnerabilities
  link_id uuid (PK),
  device_id uuid (FK → medical_devices),
  vulnerability_id uuid (FK → vulnerabilities),
  cve_id varchar(20),             -- denormalised for quick filtering
  asset_id uuid (FK → assets),
  remediation_status varchar(20)  -- values: 'Open','In Progress','Resolved','Mitigated','False Positive'
  discovered_at timestamp,        -- NOTE: discovered_at NOT detection_date
  due_date date, assigned_to uuid,
  risk_score integer, priority_tier integer (1=highest),
  created_at timestamp, updated_at timestamp
  -- ⚠ NO remediation_id column — to reach remediations join via vulnerability_id

remediation_actions
  action_id uuid (PK), cve_id varchar(20),
  action_type varchar(50)         -- values: 'Patch','Upgrade','Configuration','Disable','Mitigation'
  action_description text,        -- NOTE: action_description NOT description
  target_version varchar(100), patch_reference varchar(255), vendor varchar(255),
  status varchar(20)              -- values: 'Pending','In Progress','Completed','Cancelled'
  assigned_to uuid (FK → users), due_date date,
  created_at timestamp, updated_at timestamp, completed_at timestamp

cisa_kev_catalog
  kev_id uuid (PK), cve_id varchar(20), vendor_project varchar(100),
  product varchar(100), vulnerability_name varchar(255),
  date_added date, due_date date, short_description text, required_action text,
  created_at timestamp, updated_at timestamp

recalls
  recall_id uuid (PK),
  fda_recall_number varchar(50),  -- NOTE: fda_recall_number NOT recall_number
  recall_date date, product_description text, reason_for_recall text,
  manufacturer_name varchar(100), -- NOTE: manufacturer_name NOT manufacturer
  recall_classification varchar(20), -- NOTE: recall_classification NOT recall_class
  recall_status varchar(20)       -- values: 'Active','Resolved','Closed'
  created_at timestamp, updated_at timestamp

device_recalls_link
  link_id uuid (PK), device_id uuid (FK → medical_devices), recall_id uuid (FK → recalls),
  remediation_status varchar, due_date date

locations
  location_id uuid (PK), location_name varchar(200),
  location_type varchar(50),      -- values: 'Building','Floor','Department','Ward','Lab','Room','Other'
  criticality integer,            -- 1=highest risk, 10=lowest (integer NOT string)
  location_code varchar(50), is_active boolean, parent_location_id uuid,
  created_at timestamp, updated_at timestamp

patches
  patch_id uuid (PK), patch_name varchar(255),  -- NOTE: patch_name NOT patch_title
  patch_type varchar(50), cve_list jsonb,
  release_date date, vendor varchar(255),
  kb_article varchar(100), download_url text,   -- NOTE: download_url NOT patch_url
  created_at timestamp, updated_at timestamp

patch_applications
  application_id uuid (PK), patch_id uuid (FK → patches), asset_id uuid (FK → assets),
  applied_date date, applied_by uuid,
  status varchar                  -- 'Applied','Pending','Failed'

remediations
  remediation_id uuid (PK),
  vulnerability_id uuid (FK → vulnerabilities),
  user_id uuid (FK → users),
  upstream_api varchar(255),      -- source system that provided the remediation info
  description text,               -- brief description of the remediation
  narrative text,                 -- detailed explanation / remediation steps
  created_at timestamp, updated_at timestamp

remediation_assets_link           -- links remediations ↔ assets (many-to-many)
  link_id uuid (PK),
  remediation_id uuid (FK → remediations),
  asset_id uuid (FK → assets),
  created_at timestamp

remediation_patches_link          -- links remediations ↔ patches (many-to-many)
  link_id uuid (PK),
  remediation_id uuid (FK → remediations),
  patch_id uuid (FK → patches),
  is_latest boolean,              -- TRUE = this is the latest patch version for this remediation
  created_at timestamp, updated_at timestamp

risks
  risk_id varchar (PK), asset_id uuid (FK → assets),
  risk_score numeric(10,2), risk_score_level varchar(50),
  cvss numeric(10,2), epss numeric(10,5),
  type varchar(100), description text, status_display_name varchar(100),
  tags_exploited_in_the_wild boolean, tags_easy_to_weaponize boolean,
  created_at timestamp

scheduled_tasks
  task_id uuid (PK), action_id uuid (FK → remediation_actions),
  task_type varchar(50), cve_id varchar(20),
  assigned_to uuid (FK → users), scheduled_date date, status varchar(50),
  created_at timestamp, updated_at timestamp

users
  user_id uuid (PK), username varchar(50), email varchar(100),
  role varchar(20)                -- 'admin','analyst','viewer'
  is_active boolean, created_at timestamp

USEFUL VIEWS (safe to SELECT from)
────────────────────────────────────
recall_summary     -- pre-joined device+asset+recall: hostname, ip_address, department,
                   -- criticality, fda_recall_number, recall_date, reason_for_recall,
                   -- recall_classification, remediation_status, due_date
location_hierarchy -- recursive tree with hierarchy_path column

COMMON JOIN PATTERNS
─────────────────────
Device + Vulnerability:
  FROM medical_devices md
  JOIN device_vulnerabilities_link dvl ON md.device_id = dvl.device_id
  JOIN vulnerabilities v ON dvl.vulnerability_id = v.vulnerability_id

Device + Asset:
  JOIN assets a ON md.asset_id = a.asset_id

Remediation + Vulnerability + Patches:
  FROM remediations r
  JOIN vulnerabilities v ON r.vulnerability_id = v.vulnerability_id
  LEFT JOIN remediation_patches_link rpl ON r.remediation_id = rpl.remediation_id
  LEFT JOIN patches p ON rpl.patch_id = p.patch_id

Remediation + Affected Assets:
  FROM remediations r
  JOIN remediation_assets_link ral ON r.remediation_id = ral.remediation_id
  JOIN assets a ON ral.asset_id = a.asset_id

Device + Vulnerability + Remediation (correct path — via vulnerability_id):
  FROM medical_devices md
  JOIN device_vulnerabilities_link dvl ON md.device_id = dvl.device_id
  JOIN vulnerabilities v ON dvl.vulnerability_id = v.vulnerability_id
  LEFT JOIN remediations r ON v.vulnerability_id = r.vulnerability_id
  -- ⚠ Never use dvl.remediation_id — that column does not exist

NOTES
──────
- KEV check: v.is_kev = true
- Severity filter: v.severity = 'Critical'  (mixed-case, not UPPER)
- assets does NOT have a location_id FK; use assets.location (text) or assets.department instead
- Always include LIMIT 100 unless the query is purely an aggregate (COUNT/SUM/AVG).
SCHEMA;
    }

    /**
     * System prompt instructing the model to output ONLY a SQL SELECT query.
     */
    private function buildSQLGenerationPrompt(string $schema): string {
        return "You are a PostgreSQL expert working on the DAVE medical-device cybersecurity platform.

Given the schema below, convert the user's natural-language question into a single, safe PostgreSQL SELECT query.

RULES (strictly enforced):
1. Output ONLY the SQL query — no explanation, no markdown fences, no commentary.
2. Use only SELECT statements. No INSERT, UPDATE, DELETE, DROP, TRUNCATE, ALTER, GRANT, EXECUTE, COPY, etc.
3. Always include LIMIT " . self::MAX_ROWS . " unless the query is a simple COUNT(*).
4. Never reference tables not listed in the schema.
5. Use table aliases to keep the query readable.
6. Use ILIKE for case-insensitive string matching.
7. Cast dates with ::date when comparing to plain date strings.
8. If the question cannot be answered with a SELECT query, output: SELECT 'UNSUPPORTED' AS reason;

SCHEMA:
{$schema}";
    }

    /**
     * Strip markdown fences (```sql … ```) that the model sometimes adds.
     */
    private function extractSQL(string $raw): string {
        $sql = trim($raw);
        // Remove ```sql ... ``` or ``` ... ```
        $sql = preg_replace('/^```[a-z]*\s*/i', '', $sql);
        $sql = preg_replace('/\s*```\s*$/', '', $sql);
        return trim($sql);
    }

    /**
     * Reject anything that is not a SELECT.
     *
     * To avoid false positives on column names like "updated_date" or string
     * literals like status = 'In Progress/Update', we:
     *   1. Strip all single-quoted string literals before scanning.
     *   2. Match forbidden keywords only at word boundaries (\b).
     */
    private function validateSQL(string $sql): void {
        // Must start with SELECT or a CTE (WITH … SELECT)
        if (!preg_match('/^\s*(WITH\s+|SELECT\s)/i', $sql)) {
            throw new Exception('The AI produced a non-SELECT query. Please rephrase your question.');
        }

        // Remove single-quoted string literals so their contents don't trip the check.
        // Handles escaped quotes ('it''s fine') by consuming pairs of single-quotes.
        $stripped = preg_replace("/'(?:[^']|'')*'/", "''", $sql);
        $upper    = strtoupper($stripped);

        $forbidden = [
            'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TRUNCATE',
            'ALTER',  'GRANT',  'REVOKE', 'EXECUTE', 'CALL',
            'COPY',   'PG_SLEEP', 'PG_CANCEL_BACKEND',
        ];

        foreach ($forbidden as $kw) {
            // \b ensures we match the keyword, not a substring (e.g. "updated" != "UPDATE")
            if (preg_match('/\b' . $kw . '\b/', $upper)) {
                throw new Exception("Query contains a forbidden keyword ({$kw}). Only SELECT queries are allowed.");
            }
        }
    }

    // ─── SQL Execution ────────────────────────────────────────────────────────

    /**
     * Execute the validated SELECT and return rows as an array.
     */
    private function executeSQLQuery(string $sql): array {
        require_once __DIR__ . '/../config/database.php';
        $db  = DatabaseConfig::getInstance()->getConnection();
        $stmt = $db->prepare($sql);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // ─── Result Interpretation ────────────────────────────────────────────────

    /**
     * Build the second-pass prompt so the AI explains the result set.
     */
    private function buildInterpretationPrompt(string $question, string $sql, array $rows, int $rowCount): array {
        $resultJSON = '';

        if ($rowCount === 0) {
            $resultJSON = 'No rows returned.';
        } elseif ($rowCount === 1 && isset($rows[0]['reason']) && $rows[0]['reason'] === 'UNSUPPORTED') {
            throw new Exception('We are unable to process your request. Try rephrasing your question.');
        } else {
            // Truncate to MAX_ROWS (already enforced by LIMIT, but double-check)
            $sample = array_slice($rows, 0, self::MAX_ROWS);
            $resultJSON = json_encode($sample, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        }

        $system = "You are an expert medical-device cybersecurity analyst for the DAVE platform.
You have just run a SQL query against the live database to answer the user's question.
Interpret the results clearly and concisely.

Guidelines:
- Summarise what the data shows directly answering the user's question.
- Use **bold**, bullet lists, and markdown tables where they improve readability.
- Highlight patient-safety risks (KEV vulnerabilities, life-critical devices, overdue remediations).
- If no rows were returned, explain what that means in context.
- Do NOT repeat the SQL query unless the user asks for it.
- Keep responses factual — only state what the data shows.

Row count: {$rowCount}" . ($rowCount >= self::MAX_ROWS ? " (limited to " . self::MAX_ROWS . ")" : "");

        $user = "**User question:** {$question}\n\n**SQL executed:**\n```sql\n{$sql}\n```\n\n**Result ({$rowCount} rows):**\n```json\n{$resultJSON}\n```";

        return ['system' => $system, 'user' => $user];
    }
    
    /**
     * Call Azure OpenAI API
     * Endpoint format:
     *   https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version={version}
     */
    private function callOpenAI($systemPrompt, $userQuery) {
        $url = sprintf(
            '%s/openai/deployments/%s/chat/completions?api-version=%s',
            $this->endpoint,
            $this->deployment,
            $this->apiVersion
        );
        
        // Azure OpenAI does not take a 'model' field - the deployment name in the URL defines it
        $data = [
            'messages' => [
                [
                    'role' => 'system',
                    'content' => $systemPrompt
                ],
                [
                    'role' => 'user',
                    'content' => $userQuery
                ]
            ],
            'max_tokens' => $this->maxTokens,
            'temperature' => 0.7
        ];
        
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'api-key: ' . $this->apiKey   // Azure uses api-key header, not Authorization: Bearer
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 60);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            throw new Exception('Azure OpenAI cURL error: ' . $error);
        }
        
        if ($httpCode !== 200) {
            $errorData = json_decode($response, true);
            $errorMessage = $errorData['error']['message'] ?? $response;
            throw new Exception("Azure OpenAI returned HTTP {$httpCode}: " . $errorMessage);
        }
        
        $result = json_decode($response, true);
        
        if (!isset($result['choices'][0]['message']['content'])) {
            throw new Exception('Unexpected response from Azure OpenAI: ' . $response);
        }
        
        return $result['choices'][0]['message']['content'];
    }
    
}
