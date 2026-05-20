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
            'message' => 'Authentication required'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

// Get authenticated user
$user = $unifiedAuth->getCurrentUser();

$db = DatabaseConfig::getInstance();
$method = $_SERVER['REQUEST_METHOD'];
$path = $_GET['path'] ?? '';

// Normalize: strip 'index.php' injected by the central router so that
// /api/v1/assets/index.php and /api/v1/assets both list assets, and
// /api/v1/assets/index.php/{uuid} and /api/v1/assets/{uuid} both fetch one asset.
if (preg_match('#^index\.php(/(.*))?$#', $path, $m)) {
    $path = $m[2] ?? '';
}

// Route requests
switch ($method) {
    case 'GET':
        handleGetRequest($path);
        break;
    case 'POST':
        handlePostRequest($path);
        break;
    case 'PUT':
        handlePutRequest($path);
        break;
    case 'DELETE':
        handleDeleteRequest($path);
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleGetRequest($path) {
    global $db, $user;
    
    try {
        if (empty($path)) {
            // List all assets
            listAssets();
        } else {
            // Get specific asset
            getAsset($path);
        }
    } catch (Exception $e) {
        error_log("Assets API handleGetRequest error: " . $e->getMessage() . " | Trace: " . $e->getTraceAsString());
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function listAssets() {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to read assets
    $unifiedAuth->requirePermission('assets', 'read');

    // Get query parameters
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = min(100, max(1, intval($_GET['limit'] ?? 25)));
    $search = $_GET['search'] ?? '';
    $department = $_GET['department'] ?? '';
    $asset_type = $_GET['asset_type'] ?? '';
    $status = $_GET['status'] ?? '';
    $cve_filter = $_GET['cve_filter'] ?? '';
    $k_number = $_GET['k_number'] ?? '';
    
    $offset = ($page - 1) * $limit;
    
    // Build query
    $where_conditions = ["a.status = 'Active'"];
    $params = [];
    
    if (!empty($search)) {
        $where_conditions[] = "(a.hostname ILIKE :search OR a.ip_address::text ILIKE :search OR a.manufacturer ILIKE :search)";
        $params[':search'] = "%$search%";
    }
    
    if (!empty($department)) {
        $where_conditions[] = "a.department = :department";
        $params[':department'] = $department;
    }
    
    if (!empty($asset_type)) {
        $where_conditions[] = "a.asset_type = :asset_type";
        $params[':asset_type'] = $asset_type;
    }
    
    if (!empty($status)) {
        $where_conditions[] = "a.status = :status";
        $params[':status'] = $status;
    }
    
    // CVE filtering - find assets that have specific CVEs
    if (!empty($cve_filter)) {
        $cve_list = explode(',', $cve_filter);
        $cve_list = array_map('trim', $cve_list);
        $cve_list = array_filter($cve_list); // Remove empty values
        
        if (!empty($cve_list)) {
            // Create four sets of named placeholders — PDO named params cannot be reused in the
            // same query, so we need distinct param names for each IN() clause occurrence.
            // Suffix _da / _db = direct-asset-path (dvl.cve_id / v.cve_id)
            // Suffix _mc / _md = medical-device-path (dvl.cve_id / v.cve_id)
            $ph_da = []; $ph_db = []; $ph_mc = []; $ph_md = [];
            foreach ($cve_list as $index => $cve_id) {
                $ph_da[] = ":cve_da{$index}"; $params[":cve_da{$index}"] = $cve_id;
                $ph_db[] = ":cve_db{$index}"; $params[":cve_db{$index}"] = $cve_id;
                $ph_mc[] = ":cve_mc{$index}"; $params[":cve_mc{$index}"] = $cve_id;
                $ph_md[] = ":cve_md{$index}"; $params[":cve_md{$index}"] = $cve_id;
            }
            $ps_da = implode(',', $ph_da);
            $ps_db = implode(',', $ph_db);
            $ps_mc = implode(',', $ph_mc);
            $ps_md = implode(',', $ph_md);

            // Add CVE filtering to WHERE clause.
            // Two asset-linkage paths exist in device_vulnerabilities_link:
            //   1. dvl.asset_id  → assets.asset_id  (direct link; covers all non-medical-device assets)
            //   2. dvl.device_id → medical_devices.device_id → assets.asset_id  (FDA-mapped medical devices)
            // Two CVE-matching paths exist:
            //   a. dvl.cve_id                — legacy string match (older records)
            //   b. dvl.vulnerability_id → vulnerabilities.cve_id  (UUID-based; newer records)
            $where_conditions[] = "a.asset_id IN (
                SELECT DISTINCT dvl_d.asset_id
                FROM device_vulnerabilities_link dvl_d
                LEFT JOIN vulnerabilities v_d ON dvl_d.vulnerability_id = v_d.vulnerability_id
                WHERE (dvl_d.cve_id IN ($ps_da) OR v_d.cve_id IN ($ps_db))
                  AND dvl_d.asset_id IS NOT NULL
                UNION
                SELECT DISTINCT a2.asset_id
                FROM assets a2
                INNER JOIN medical_devices md2 ON a2.asset_id = md2.asset_id
                INNER JOIN device_vulnerabilities_link dvl_m ON md2.device_id = dvl_m.device_id
                LEFT JOIN vulnerabilities v_m ON dvl_m.vulnerability_id = v_m.vulnerability_id
                WHERE (dvl_m.cve_id IN ($ps_mc) OR v_m.cve_id IN ($ps_md))
            )";
        }
    }
    
    // K-number filtering - find assets mapped to a specific FDA 510(k) number
    if (!empty($k_number)) {
        $where_conditions[] = "a.asset_id IN (
            SELECT a2.asset_id
            FROM assets a2
            INNER JOIN medical_devices md2 ON a2.asset_id = md2.asset_id
            WHERE UPPER(md2.k_number) = UPPER(:k_number)
        )";
        $params[':k_number'] = $k_number;
    }
    
    $where_clause = implode(' AND ', $where_conditions);
    
    // Get total count
    $count_sql = "SELECT COUNT(*) as total FROM assets a WHERE $where_clause";
    $count_stmt = $db->prepare($count_sql);
    $count_stmt->execute($params);
    $total = $count_stmt->fetch()['total'];
    
    // Get assets
    $sql = "SELECT 
        a.asset_id,
        a.hostname,
        a.ip_address,
        a.asset_type,
        a.manufacturer,
        a.model,
        a.serial_number,
        a.department,
        a.location,
        a.criticality,
        a.status,
        a.last_seen,
        a.created_at,
        a.updated_at,
        a.metadata,
        CASE WHEN md.device_id IS NOT NULL THEN 'Mapped' ELSE 'Unmapped' END as mapping_status,
        md.brand_name,
        md.device_name,
        md.manufacturer_name
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        WHERE $where_clause
        ORDER BY a.last_seen DESC
        LIMIT :limit OFFSET :offset";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    
    $stmt->execute();
    $assets = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $assets,
        'pagination' => [
            'page' => $page,
            'limit' => $limit,
            'total' => $total,
            'pages' => ceil($total / $limit)
        ],
        'timestamp' => date('c')
    ]);
}

function getAsset($asset_id) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to read assets
    $unifiedAuth->requirePermission('assets', 'read');
    
    $sql = "SELECT 
        a.asset_id,
        a.hostname,
        a.ip_address,
        a.mac_address,
        a.asset_type,
        a.asset_subtype,
        a.manufacturer,
        a.model,
        a.serial_number,
        a.location,
        a.firmware_version,
        a.cpu,
        a.memory_ram,
        a.storage,
        a.power_requirements,
        a.primary_communication_protocol,
        a.assigned_admin_user,
        a.business_unit,
        a.department,
        a.cost_center,
        a.warranty_expiration_date,
        a.scheduled_replacement_date,
        a.disposal_date,
        a.disposal_method,
        a.criticality,
        a.regulatory_classification,
        a.phi_status,
        a.data_encryption_transit,
        a.data_encryption_rest,
        a.authentication_method,
        a.patch_level_last_update,
        a.last_audit_date,
        a.source,
        a.status,
        a.first_seen,
        a.last_seen,
        a.created_at,
        a.updated_at,
        a.metadata,
        CASE WHEN md.device_id IS NOT NULL THEN 'Mapped' ELSE 'Unmapped' END as mapping_status,
        md.device_id,
        md.device_identifier,
        md.brand_name,
        md.model_number,
        md.manufacturer_name,
        md.device_description,
        md.gmdn_term,
        md.is_implantable,
        md.fda_class,
        md.udi,
        md.mapping_confidence,
        md.mapping_method,
        md.mapped_at,
        -- 510k specific fields
        md.k_number,
        md.decision_code,
        md.decision_date,
        md.decision_description,
        md.clearance_type,
        md.date_received,
        md.statement_or_summary,
        md.applicant,
        md.contact,
        md.address_1,
        md.address_2,
        md.city,
        md.state,
        md.zip_code,
        md.postal_code,
        md.country_code,
        md.advisory_committee,
        md.advisory_committee_description,
        md.review_advisory_committee,
        md.expedited_review_flag,
        md.third_party_flag,
        md.device_class,
        md.medical_specialty_description,
        md.registration_numbers,
        md.fei_numbers,
        md.device_name,
        md.product_code,
        md.regulation_number
        FROM assets a
        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
        WHERE a.asset_id = :asset_id";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':asset_id', $asset_id);
    $stmt->execute();
    $asset = $stmt->fetch();
    
    if (!$asset) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'ASSET_NOT_FOUND',
                'message' => 'Asset not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'data' => $asset,
        'timestamp' => date('c')
    ]);
}

function handlePostRequest($path) {
    global $db, $user;
    
    try {
        // Create new asset
        createAsset();
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function createAsset() {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to write assets
    $unifiedAuth->requirePermission('assets', 'write');
    
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_JSON',
                'message' => 'Invalid JSON input'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Validate required fields
    $required_fields = ['hostname', 'ip_address', 'asset_type'];
    foreach ($required_fields as $field) {
        if (empty($input[$field])) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_FIELD',
                    'message' => "Field '$field' is required"
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
    }
    
    // Build INSERT query - include asset_id if provided, otherwise let database generate it
    $hasAssetId = !empty($input['asset_id']);
    
    if ($hasAssetId) {
        $sql = "INSERT INTO assets (
            asset_id, hostname, ip_address, mac_address, asset_type, manufacturer, model, 
            serial_number, department, location, criticality, status, 
            firmware_version, first_seen, last_seen, created_at, updated_at, source, metadata
        ) VALUES (
            :asset_id, :hostname, :ip_address, :mac_address, :asset_type, :manufacturer, :model,
            :serial_number, :department, :location, :criticality, :status,
            :firmware_version, :first_seen, :last_seen, :created_at, :updated_at, :source, :metadata
        ) RETURNING asset_id";
    } else {
        $sql = "INSERT INTO assets (
            hostname, ip_address, mac_address, asset_type, manufacturer, model, 
            serial_number, department, location, criticality, status, 
            firmware_version, first_seen, last_seen, created_at, updated_at, source, metadata
        ) VALUES (
            :hostname, :ip_address, :mac_address, :asset_type, :manufacturer, :model,
            :serial_number, :department, :location, :criticality, :status,
            :firmware_version, :first_seen, :last_seen, :created_at, :updated_at, :source, :metadata
        ) RETURNING asset_id";
    }
    
    $stmt = $db->prepare($sql);
    
    // Bind asset_id if provided
    if ($hasAssetId) {
        $stmt->bindValue(':asset_id', $input['asset_id']);
    }
    
    // Bind all other values
    $stmt->bindValue(':hostname', $input['hostname']);
    $stmt->bindValue(':ip_address', $input['ip_address']);
    $stmt->bindValue(':mac_address', $input['mac_address'] ?? null);
    $stmt->bindValue(':asset_type', $input['asset_type']);
    $stmt->bindValue(':manufacturer', $input['manufacturer'] ?? null);
    $stmt->bindValue(':model', $input['model'] ?? null);
    $stmt->bindValue(':serial_number', $input['serial_number'] ?? null);
    $stmt->bindValue(':department', $input['department'] ?? null);
    $stmt->bindValue(':location', $input['location'] ?? null);
    $stmt->bindValue(':criticality', $input['criticality'] ?? 'Business-Medium');
    $stmt->bindValue(':status', $input['status'] ?? 'Active');
    $stmt->bindValue(':firmware_version', $input['firmware_version'] ?? null);
    $stmt->bindValue(':first_seen', $input['first_seen'] ?? date('Y-m-d H:i:s'));
    $stmt->bindValue(':last_seen', $input['last_seen'] ?? date('Y-m-d H:i:s'));
    $stmt->bindValue(':created_at', date('Y-m-d H:i:s'));
    $stmt->bindValue(':updated_at', date('Y-m-d H:i:s'));
    $stmt->bindValue(':source', $input['source'] ?? 'Manual Entry');
    $stmt->bindValue(':metadata', $input['metadata'] ?? null);

    $stmt->execute();
    $asset_id = $stmt->fetch()['asset_id'];
    
    echo json_encode([
        'success' => true,
        'data' => [
            'asset_id' => $asset_id,
            'message' => 'Asset created successfully'
        ],
        'timestamp' => date('c')
    ]);
}

function handlePutRequest($path) {
    global $db, $user;
    
    try {
        if (empty($path)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_ASSET_ID',
                    'message' => 'Asset ID is required'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        updateAsset($path);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function updateAsset($asset_id) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to write assets
    $unifiedAuth->requirePermission('assets', 'write');
    
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_JSON',
                'message' => 'Invalid JSON input'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Build update query
    $update_fields = [];
    $params = [':asset_id' => $asset_id];
    
    $allowed_fields = [
        'hostname', 'ip_address', 'mac_address', 'asset_type', 'asset_subtype',
        'manufacturer', 'model', 'serial_number', 'location', 'firmware_version',
        'cpu', 'memory_ram', 'storage', 'power_requirements', 'primary_communication_protocol',
        'assigned_admin_user', 'business_unit', 'department', 'cost_center',
        'warranty_expiration_date', 'scheduled_replacement_date', 'disposal_date', 'disposal_method',
        'criticality', 'regulatory_classification', 'phi_status', 'data_encryption_transit',
        'data_encryption_rest', 'authentication_method', 'patch_level_last_update',
        'last_audit_date', 'status', 'metadata'
    ];
    
    foreach ($allowed_fields as $field) {
        if (isset($input[$field])) {
            $update_fields[] = "$field = :$field";
            $params[":$field"] = $input[$field];
        }
    }
    
    if (empty($update_fields)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'NO_FIELDS_TO_UPDATE',
                'message' => 'No valid fields to update'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    $update_fields[] = "updated_at = :updated_at";
    $params[':updated_at'] = date('Y-m-d H:i:s');
    
    $sql = "UPDATE assets SET " . implode(', ', $update_fields) . " WHERE asset_id = :asset_id";
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    
    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'ASSET_NOT_FOUND',
                'message' => 'Asset not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'data' => [
            'asset_id' => $asset_id,
            'message' => 'Asset updated successfully'
        ],
        'timestamp' => date('c')
    ]);
}

function handleDeleteRequest($path) {
    global $db, $user;
    
    try {
        if (empty($path)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_ASSET_ID',
                    'message' => 'Asset ID is required'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        deleteAsset($path);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function deleteAsset($asset_id) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to delete assets
    $unifiedAuth->requirePermission('assets', 'delete');
    
    // Soft delete - set status to 'Disposed' (valid values: Active, Inactive, Retired, Disposed)
    $sql = "UPDATE assets SET status = 'Disposed', updated_at = :updated_at WHERE asset_id = :asset_id";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':asset_id', $asset_id);
    $stmt->bindValue(':updated_at', date('Y-m-d H:i:s'));
    $stmt->execute();
    
    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'ASSET_NOT_FOUND',
                'message' => 'Asset not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'data' => [
            'asset_id' => $asset_id,
            'message' => 'Asset deleted successfully'
        ],
        'timestamp' => date('c')
    ]);
}
?>
