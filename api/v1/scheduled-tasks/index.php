<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}

// Start output buffering to prevent PHP warnings/notices from corrupting JSON
ob_start();

require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

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

// Check if user has permission for task management
$unifiedAuth->requirePermission('tasks', 'read');

$db = DatabaseConfig::getInstance();
$method = $_SERVER['REQUEST_METHOD'];
$path = $_GET['path'] ?? '';

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
            // List all scheduled tasks
            listScheduledTasks();
        } elseif ($path === 'downtime-calendar') {
            // Get downtime calendar data
            getDowntimeCalendar();
        } else {
            // Get specific task
            getScheduledTask($path);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function listScheduledTasks() {
    global $db, $user;
    
    // Get query parameters
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = min(100, max(1, intval($_GET['limit'] ?? 25)));
    $offset = ($page - 1) * $limit;
    
    // Build filter conditions
    $where_conditions = [];
    $params = [];
    
    // User filter
    if (!empty($_GET['assigned_to'])) {
        $where_conditions[] = "assigned_to = :assigned_to";
        $params[':assigned_to'] = $_GET['assigned_to'];
    }
    
    // Date range filter
    if (!empty($_GET['start_date'])) {
        $where_conditions[] = "scheduled_date >= :start_date";
        $params[':start_date'] = $_GET['start_date'];
    }
    if (!empty($_GET['end_date'])) {
        $where_conditions[] = "scheduled_date <= :end_date";
        $params[':end_date'] = $_GET['end_date'];
    }
    
    // Status filter
    if (!empty($_GET['status'])) {
        $where_conditions[] = "status = :status";
        $params[':status'] = $_GET['status'];
    }
    
    // Location filter
    if (!empty($_GET['location'])) {
        $where_conditions[] = "location = :location";
        $params[':location'] = $_GET['location'];
    }
    
    // Department filter
    if (!empty($_GET['department'])) {
        $where_conditions[] = "department = :department";
        $params[':department'] = $_GET['department'];
    }
    
    // Tier filter (based on device criticality)
    if (!empty($_GET['tier'])) {
        $tier = intval($_GET['tier']);
        if ($tier == 1) {
            $where_conditions[] = "device_criticality = 'Clinical-High'";
        } elseif ($tier == 2) {
            $where_conditions[] = "device_criticality = 'Business-Medium'";
        } elseif ($tier == 3) {
            $where_conditions[] = "device_criticality = 'Non-Essential'";
        }
    }
    
    // Package name filter
    if (!empty($_GET['package_name'])) {
        $where_conditions[] = "package_name ILIKE :package_name";
        $params[':package_name'] = "%" . $_GET['package_name'] . "%";
    }
    
    // Severity filter
    if (!empty($_GET['severity'])) {
        $where_conditions[] = "cve_severity = :severity";
        $params[':severity'] = $_GET['severity'];
    }
    
    // Task type filter
    if (!empty($_GET['task_type'])) {
        $where_conditions[] = "task_type = :task_type";
        $params[':task_type'] = $_GET['task_type'];
    }
    
    $where_clause = empty($where_conditions) ? '1=1' : implode(' AND ', $where_conditions);
    
    // Get total count
    $count_sql = "SELECT COUNT(*) as total FROM scheduled_tasks_view WHERE $where_clause";
    $count_stmt = $db->prepare($count_sql);
    foreach ($params as $key => $value) {
        $count_stmt->bindValue($key, $value);
    }
    $count_stmt->execute();
    $total = $count_stmt->fetch()['total'];
    
    // Get tasks
    $sql = "SELECT * FROM scheduled_tasks_view 
            WHERE $where_clause 
            ORDER BY priority_score ASC, scheduled_date ASC 
            LIMIT :limit OFFSET :offset";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    
    $stmt->execute();
    $tasks = $stmt->fetchAll();
    // Fallback device_name using original_device_name if available
    if (!empty($tasks)) {
        $fallbackStmt = $db->prepare("SELECT task_id, original_device_name FROM scheduled_tasks WHERE task_id = :task_id");
        foreach ($tasks as &$t) {
            if (isset($t['device_name']) && $t['device_name'] === 'Unknown Device') {
                $fallbackStmt->bindValue(':task_id', $t['task_id']);
                $fallbackStmt->execute();
                $orig = $fallbackStmt->fetch();
                if (!empty($orig['original_device_name'])) {
                    $t['device_name'] = $orig['original_device_name'];
                }
            }
        }
        unset($t);
    }
    
    echo json_encode([
        'success' => true,
        'data' => $tasks,
        'pagination' => [
            'page' => $page,
            'limit' => $limit,
            'total' => $total,
            'pages' => ceil($total / $limit)
        ],
        'timestamp' => date('c')
    ]);
}

function getScheduledTask($task_id) {
    global $db, $user;
    
    $sql = "SELECT * FROM scheduled_tasks_view WHERE task_id = :task_id";
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':task_id', $task_id);
    $stmt->execute();
    $task = $stmt->fetch();
    // Fallback device_name using original_device_name if available
    if ($task && isset($task['device_name']) && $task['device_name'] === 'Unknown Device') {
        $fb = $db->prepare("SELECT original_device_name FROM scheduled_tasks WHERE task_id = :task_id");
        $fb->bindValue(':task_id', $task_id);
        $fb->execute();
        $orig = $fb->fetch();
        if (!empty($orig['original_device_name'])) {
            $task['device_name'] = $orig['original_device_name'];
        }
    }
    
    if (!$task) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'TASK_NOT_FOUND',
                'message' => 'Scheduled task not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'data' => $task,
        'timestamp' => date('c')
    ]);
}

function getDowntimeCalendar() {
    global $db, $user;
    
    $start_date = $_GET['start_date'] ?? date('Y-m-01'); // Default to first day of current month
    $end_date = $_GET['end_date'] ?? date('Y-m-t'); // Default to last day of current month
    
    $sql = "SELECT * FROM downtime_calendar_view 
            WHERE calendar_date >= :start_date AND calendar_date <= :end_date
            ORDER BY calendar_date";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':start_date', $start_date);
    $stmt->bindValue(':end_date', $end_date);
    $stmt->execute();
    $calendar_data = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $calendar_data,
        'date_range' => [
            'start_date' => $start_date,
            'end_date' => $end_date
        ],
        'timestamp' => date('c')
    ]);
}

function handlePostRequest($path) {
    global $db, $user;
    
    try {
        // Check permission for creating tasks
        $unifiedAuth = new UnifiedAuth();
        $unifiedAuth->requirePermission('tasks', 'create');
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (empty($input)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_INPUT',
                    'message' => 'Invalid JSON input'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        // Validate required fields
        $required_fields = ['task_type', 'device_id', 'assigned_to', 'scheduled_date', 'estimated_downtime'];
        foreach ($required_fields as $field) {
            if (empty($input[$field])) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'error' => [
                        'code' => 'MISSING_FIELD',
                        'message' => "Required field '$field' is missing"
                    ],
                    'timestamp' => date('c')
                ]);
                return;
            }
        }
        
        // Validate task_type
        $valid_task_types = ['package_remediation', 'cve_remediation', 'patch_application'];
        if (!in_array($input['task_type'], $valid_task_types)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_TASK_TYPE',
                    'message' => 'Invalid task_type. Must be one of: ' . implode(', ', $valid_task_types)
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        // Validate device exists
        $device_sql = "SELECT device_id FROM medical_devices WHERE device_id = :device_id";
        $device_stmt = $db->prepare($device_sql);
        $device_stmt->bindValue(':device_id', $input['device_id']);
        $device_stmt->execute();
        if (!$device_stmt->fetch()) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'DEVICE_NOT_FOUND',
                    'message' => 'Device not found'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        // Validate assigned user exists
        $user_sql = "SELECT user_id FROM users WHERE user_id = :user_id AND is_active = true";
        $user_stmt = $db->prepare($user_sql);
        $user_stmt->bindValue(':user_id', $input['assigned_to']);
        $user_stmt->execute();
        if (!$user_stmt->fetch()) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'USER_NOT_FOUND',
                    'message' => 'Assigned user not found or inactive'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        // Insert task
        $sql = "INSERT INTO scheduled_tasks (
                    task_type, package_id, cve_id, action_id, patch_id, device_id, 
                    assigned_to, assigned_by, scheduled_date, implementation_date,
                    estimated_downtime, status, task_description, notes
                ) VALUES (
                    :task_type, :package_id, :cve_id, :action_id, :patch_id, :device_id,
                    :assigned_to, :assigned_by, :scheduled_date, :implementation_date,
                    :estimated_downtime, :status, :task_description, :notes
                ) RETURNING task_id";
        
        $stmt = $db->prepare($sql);
        $stmt->bindValue(':task_type', $input['task_type']);
        $stmt->bindValue(':package_id', $input['package_id'] ?? null);
        $stmt->bindValue(':cve_id', $input['cve_id'] ?? null);
        $stmt->bindValue(':action_id', $input['action_id'] ?? null);
        $stmt->bindValue(':patch_id', $input['patch_id'] ?? null);
        $stmt->bindValue(':device_id', $input['device_id']);
        $stmt->bindValue(':assigned_to', $input['assigned_to']);
        $stmt->bindValue(':assigned_by', $user['user_id']);
        $stmt->bindValue(':scheduled_date', $input['scheduled_date']);
        $stmt->bindValue(':implementation_date', $input['implementation_date'] ?? null);
        $stmt->bindValue(':estimated_downtime', intval($input['estimated_downtime']));
        $stmt->bindValue(':status', $input['status'] ?? 'Scheduled');
        $stmt->bindValue(':task_description', $input['task_description'] ?? null);
        $stmt->bindValue(':notes', $input['notes'] ?? null);
        
        $stmt->execute();
        $task_id = $stmt->fetch()['task_id'];
        
        // Enrich original information fields from source entities
        try {
            // Device original info
            $devInfoSql = "SELECT md.device_id, md.brand_name, md.model_number, md.device_identifier, md.k_number, md.udi,
                                   a.hostname, a.ip_address, a.asset_tag, a.location as original_location, a.department as original_department
                            FROM medical_devices md
                            LEFT JOIN assets a ON md.asset_id = a.asset_id
                            WHERE md.device_id = :device_id";
            $devStmt = $db->prepare($devInfoSql);
            $devStmt->bindValue(':device_id', $input['device_id']);
            $devStmt->execute();
            $dev = $devStmt->fetch();

            if ($dev) {
                $origDeviceName = null;
                if (!empty($dev['hostname'])) {
                    $origDeviceName = $dev['hostname'];
                } elseif (!empty($dev['asset_tag'])) {
                    $origDeviceName = $dev['asset_tag'];
                } elseif (!empty($dev['brand_name'])) {
                    $origDeviceName = $dev['brand_name'] . (!empty($dev['model_number']) ? ' ' . $dev['model_number'] : '');
                }

                $updSql = "UPDATE scheduled_tasks SET 
                            original_device_name = COALESCE(:original_device_name, original_device_name),
                            original_brand_name = COALESCE(:brand_name, original_brand_name),
                            original_model_number = COALESCE(:model_number, original_model_number),
                            original_device_identifier = COALESCE(:device_identifier, original_device_identifier),
                            original_k_number = COALESCE(:k_number, original_k_number),
                            original_udi = COALESCE(:udi, original_udi),
                            original_hostname = COALESCE(:hostname, original_hostname),
                            original_ip_address = COALESCE(:ip_address, original_ip_address),
                            original_location = COALESCE(:original_location, original_location),
                            original_department = COALESCE(:original_department, original_department)
                           WHERE task_id = :task_id";
                $upd = $db->prepare($updSql);
                $upd->bindValue(':original_device_name', $origDeviceName);
                $upd->bindValue(':brand_name', $dev['brand_name']);
                $upd->bindValue(':model_number', $dev['model_number']);
                $upd->bindValue(':device_identifier', $dev['device_identifier']);
                $upd->bindValue(':k_number', $dev['k_number']);
                $upd->bindValue(':udi', $dev['udi']);
                $upd->bindValue(':hostname', $dev['hostname']);
                $upd->bindValue(':ip_address', $dev['ip_address']);
                $upd->bindValue(':original_location', $dev['original_location']);
                $upd->bindValue(':original_department', $dev['original_department']);
                $upd->bindValue(':task_id', $task_id);
                $upd->execute();
            }

            // Patch original info including CVE list
            if (!empty($input['patch_id'])) {
                $patchSql = "SELECT patch_name, patch_type, vendor, target_version, description, release_date, requires_reboot, cve_list
                             FROM patches WHERE patch_id = :patch_id";
                $patchStmt = $db->prepare($patchSql);
                $patchStmt->bindValue(':patch_id', $input['patch_id']);
                $patchStmt->execute();
                $patch = $patchStmt->fetch();
                if ($patch) {
                    $updPatchSql = "UPDATE scheduled_tasks SET 
                        original_patch_name = COALESCE(:patch_name, original_patch_name),
                        original_patch_type = COALESCE(:patch_type, original_patch_type),
                        original_patch_vendor = COALESCE(:vendor, original_patch_vendor),
                        original_patch_version = COALESCE(:target_version, original_patch_version),
                        original_patch_description = COALESCE(:description, original_patch_description),
                        original_patch_release_date = COALESCE(:release_date, original_patch_release_date),
                        original_patch_requires_reboot = COALESCE(:requires_reboot, original_patch_requires_reboot),
                        notes = COALESCE(notes, '') || :cve_list_note
                        WHERE task_id = :task_id";
                    $updPatch = $db->prepare($updPatchSql);
                    $updPatch->bindValue(':patch_name', $patch['patch_name']);
                    $updPatch->bindValue(':patch_type', $patch['patch_type']);
                    $updPatch->bindValue(':vendor', $patch['vendor']);
                    $updPatch->bindValue(':target_version', $patch['target_version']);
                    $updPatch->bindValue(':description', $patch['description']);
                    $updPatch->bindValue(':release_date', $patch['release_date']);
                    $updPatch->bindValue(':requires_reboot', $patch['requires_reboot']);
                    $cveListNote = '';
                    if (!empty($patch['cve_list'])) {
                        // cve_list could be JSON/array; ensure string
                        $listStr = is_string($patch['cve_list']) ? $patch['cve_list'] : json_encode($patch['cve_list']);
                        $cveListNote = "\nCVE list: " . $listStr;
                    }
                    $updPatch->bindValue(':cve_list_note', $cveListNote);
                    $updPatch->bindValue(':task_id', $task_id);
                    $updPatch->execute();
                }
            }

            // CVE original info
            if (!empty($input['cve_id'])) {
                $cveSql = "SELECT cve_id, description, severity, cvss_v3_score
                           FROM vulnerabilities WHERE cve_id = :cve_id";
                $cveStmt = $db->prepare($cveSql);
                $cveStmt->bindValue(':cve_id', $input['cve_id']);
                $cveStmt->execute();
                $cve = $cveStmt->fetch();
                if ($cve) {
                    $updCveSql = "UPDATE scheduled_tasks SET 
                        original_cve_id = COALESCE(:cve_id, original_cve_id),
                        original_cve_description = COALESCE(:cve_desc, original_cve_description),
                        original_cve_severity = COALESCE(:severity, original_cve_severity),
                        original_cvss_v3_score = COALESCE(:cvss, original_cvss_v3_score)
                        WHERE task_id = :task_id";
                    $updCve = $db->prepare($updCveSql);
                    $updCve->bindValue(':cve_id', $cve['cve_id']);
                    $updCve->bindValue(':cve_desc', $cve['description']);
                    $updCve->bindValue(':severity', $cve['severity']);
                    $updCve->bindValue(':cvss', $cve['cvss_v3_score']);
                    $updCve->bindValue(':task_id', $task_id);
                    $updCve->execute();
                }
            }
        } catch (Exception $enrichEx) {
            // Non-fatal enrichment error; continue returning the task
        }

        // Get the created task with full details
        $task_sql = "SELECT * FROM scheduled_tasks_view WHERE task_id = :task_id";
        $task_stmt = $db->prepare($task_sql);
        $task_stmt->bindValue(':task_id', $task_id);
        $task_stmt->execute();
        $created_task = $task_stmt->fetch();
        
        echo json_encode([
            'success' => true,
            'data' => $created_task,
            'message' => 'Scheduled task created successfully',
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function handlePutRequest($path) {
    global $db, $user;
    
    try {
        // Check permission for updating tasks
        $unifiedAuth = new UnifiedAuth();
        $unifiedAuth->requirePermission('tasks', 'update');
        
        if (empty($path)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_TASK_ID',
                    'message' => 'Task ID is required for updates'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (empty($input)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'INVALID_INPUT',
                    'message' => 'Invalid JSON input'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        // Check if task exists
        $check_sql = "SELECT task_id FROM scheduled_tasks WHERE task_id = :task_id";
        $check_stmt = $db->prepare($check_sql);
        $check_stmt->bindValue(':task_id', $path);
        $check_stmt->execute();
        if (!$check_stmt->fetch()) {
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'TASK_NOT_FOUND',
                    'message' => 'Scheduled task not found'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        // Build update query dynamically
        $update_fields = [];
        $params = [':task_id' => $path];
        
        $allowed_fields = [
            'assigned_to', 'scheduled_date', 'implementation_date', 
            'estimated_downtime', 'actual_downtime', 'status', 
            'task_description', 'notes', 'completion_notes',
            'department_notified', 'department_approval_status', 
            'department_approval_contact', 'department_approval_notes'
        ];
        
        foreach ($allowed_fields as $field) {
            if (isset($input[$field])) {
                $update_fields[] = "$field = :$field";
                $params[":$field"] = $input[$field];
            }
        }
        
        // Special handling for approval status changes
        if (isset($input['department_approval_status']) && $input['department_approval_status'] !== 'Pending') {
            $update_fields[] = "department_approval_date = :approval_date";
            $update_fields[] = "department_approval_by = :approval_by";
            $params[":approval_date"] = date('Y-m-d H:i:s');
            $params[":approval_by"] = $user['user_id'];
        }
        
        if (empty($update_fields)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'NO_FIELDS_TO_UPDATE',
                    'message' => 'No valid fields provided for update'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        // Set completed_at and completed_by if status is being changed to Completed
        if (isset($input['status']) && $input['status'] === 'Completed') {
            $update_fields[] = "completed_at = CURRENT_TIMESTAMP";
            $update_fields[] = "completed_by = :completed_by";
            $params[":completed_by"] = $user['user_id'];
        }
        
        $sql = "UPDATE scheduled_tasks SET " . implode(', ', $update_fields) . " WHERE task_id = :task_id";
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        
        // Get updated task
        $task_sql = "SELECT * FROM scheduled_tasks_view WHERE task_id = :task_id";
        $task_stmt = $db->prepare($task_sql);
        $task_stmt->bindValue(':task_id', $path);
        $task_stmt->execute();
        $updated_task = $task_stmt->fetch();
        
        echo json_encode([
            'success' => true,
            'data' => $updated_task,
            'message' => 'Scheduled task updated successfully',
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

function handleDeleteRequest($path) {
    global $db, $user;
    
    try {
        // Check permission for deleting tasks
        $unifiedAuth = new UnifiedAuth();
        $unifiedAuth->requirePermission('tasks', 'delete');
        
        if (empty($path)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'MISSING_TASK_ID',
                    'message' => 'Task ID is required for deletion'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        // Check if task exists
        $check_sql = "SELECT task_id, status FROM scheduled_tasks WHERE task_id = :task_id";
        $check_stmt = $db->prepare($check_sql);
        $check_stmt->bindValue(':task_id', $path);
        $check_stmt->execute();
        $task = $check_stmt->fetch();
        
        if (!$task) {
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'TASK_NOT_FOUND',
                    'message' => 'Scheduled task not found'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        // Check if task can be deleted (only if not completed)
        if ($task['status'] === 'Completed') {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'CANNOT_DELETE_COMPLETED',
                    'message' => 'Cannot delete completed tasks'
                ],
                'timestamp' => date('c')
            ]);
            return;
        }
        
        // Delete task
        $sql = "DELETE FROM scheduled_tasks WHERE task_id = :task_id";
        $stmt = $db->prepare($sql);
        $stmt->bindValue(':task_id', $path);
        $stmt->execute();
        
        echo json_encode([
            'success' => true,
            'message' => 'Scheduled task deleted successfully',
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

