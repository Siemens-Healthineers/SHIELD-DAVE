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
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'METHOD_NOT_ALLOWED',
                'message' => 'Method not allowed'
            ],
            'timestamp' => date('c')
        ]);
        break;
}

function handleGetRequest($path) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to read remediations
    $unifiedAuth->requirePermission('remediations', 'read');
    
    try {
        if (empty($path)) {
            // List all remediations
            listRemediations();
        } else {
            // Get specific remediation
            getRemediation($path);
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

function handlePostRequest($path) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to create remediations
    $unifiedAuth->requirePermission('remediations', 'write');
    
    try {
        if (empty($path)) {
            // Create new remediation
            createRemediation();
        } else {
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'NOT_FOUND',
                    'message' => 'Endpoint not found'
                ],
                'timestamp' => date('c')
            ]);
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

function handlePutRequest($path) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to update remediations
    $unifiedAuth->requirePermission('remediations', 'write');
    
    try {
        if (!empty($path)) {
            // Update existing remediation
            updateRemediation($path);
        } else {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'BAD_REQUEST',
                    'message' => 'Remediation ID required'
                ],
                'timestamp' => date('c')
            ]);
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

function handleDeleteRequest($path) {
    global $db, $user, $unifiedAuth;
    
    // Check if user has permission to delete remediations
    $unifiedAuth->requirePermission('remediations', 'delete');
    
    try {
        if (!empty($path)) {
            // Delete remediation
            deleteRemediation($path);
        } else {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'BAD_REQUEST',
                    'message' => 'Remediation ID required'
                ],
                'timestamp' => date('c')
            ]);
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

/**
 * List all remediations
 */
function listRemediations() {
    global $db;
    
    $limit = isset($_GET['limit']) ? min((int)$_GET['limit'], 1000) : 100;
    $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;
    $search = $_GET['search'] ?? '';
    $vulnerabilityId = $_GET['vulnerability_id'] ?? null;
    $userId = $_GET['user_id'] ?? null;
    
    $sql = "SELECT 
                r.remediation_id,
                r.upstream_api,
                r.description,
                r.narrative,
                r.vulnerability_id,
                r.user_id,
                r.created_at,
                r.updated_at,
                v.cve_id,
                v.description as vulnerability_description,
                v.severity,
                u.username,
                u.email as user_email
            FROM remediations r
            LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.vulnerability_id
            LEFT JOIN users u ON r.user_id = u.user_id
            WHERE 1=1";
    
    $params = [];
    
    if (!empty($search)) {
        $sql .= " AND (r.description ILIKE ? OR r.narrative ILIKE ? OR v.cve_id ILIKE ?)";
        $searchTerm = "%{$search}%";
        $params[] = $searchTerm;
        $params[] = $searchTerm;
        $params[] = $searchTerm;
    }
    
    if (!empty($vulnerabilityId)) {
        $sql .= " AND r.vulnerability_id = ?";
        $params[] = $vulnerabilityId;
    }
    
    if (!empty($userId)) {
        $sql .= " AND r.user_id = ?";
        $params[] = $userId;
    }
    
    $sql .= " ORDER BY r.created_at DESC LIMIT ? OFFSET ?";
    $params[] = $limit;
    $params[] = $offset;
    
    $stmt = $db->query($sql, $params);
    $remediations = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get total count
    $countSql = "SELECT COUNT(*) FROM remediations r 
                 LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.vulnerability_id
                 WHERE 1=1";
    $countParams = [];
    
    if (!empty($search)) {
        $countSql .= " AND (r.description ILIKE ? OR r.narrative ILIKE ? OR v.cve_id ILIKE ?)";
        $searchTerm = "%{$search}%";
        $countParams[] = $searchTerm;
        $countParams[] = $searchTerm;
        $countParams[] = $searchTerm;
    }
    
    if (!empty($vulnerabilityId)) {
        $countSql .= " AND r.vulnerability_id = ?";
        $countParams[] = $vulnerabilityId;
    }
    
    if (!empty($userId)) {
        $countSql .= " AND r.user_id = ?";
        $countParams[] = $userId;
    }
    
    $countStmt = $db->query($countSql, $countParams);
    $total = $countStmt->fetchColumn();
    
    echo json_encode([
        'success' => true,
        'data' => $remediations,
        'pagination' => [
            'total' => (int)$total,
            'limit' => $limit,
            'offset' => $offset,
            'has_more' => ($offset + $limit) < $total
        ],
        'timestamp' => date('c')
    ]);
}

/**
 * Get a specific remediation
 */
function getRemediation($remediationId) {
    global $db;
    
    // Validate UUID format
    if (!isValidUuid($remediationId)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_UUID',
                'message' => 'Invalid remediation ID format. Expected UUID.'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    $stmt = $db->query(
        "SELECT 
            r.remediation_id,
            r.upstream_api,
            r.description,
            r.narrative,
            r.vulnerability_id,
            r.user_id,
            r.created_at,
            r.updated_at,
            v.cve_id,
            v.description as vulnerability_description,
            v.severity,
            v.cvss_v3_score,
            u.username,
            u.email as user_email
        FROM remediations r
        LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.vulnerability_id
        LEFT JOIN users u ON r.user_id = u.user_id
        WHERE r.remediation_id = ?",
        [$remediationId]
    );
    
    $remediation = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$remediation) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'REMEDIATION_NOT_FOUND',
                'message' => 'Remediation not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Get linked assets
    $assetsStmt = $db->query(
        "SELECT 
            a.asset_id,
            a.hostname,
            a.asset_type,
            a.manufacturer,
            a.model
        FROM remediation_assets_link ral
        JOIN assets a ON ral.asset_id = a.asset_id
        WHERE ral.remediation_id = ?
        ORDER BY a.hostname",
        [$remediationId]
    );
    
    $remediation['linked_assets'] = $assetsStmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get linked patches
    $patchesStmt = $db->query(
        "SELECT 
            p.patch_id,
            p.patch_name,
            p.patch_type,
            p.description,
            p.release_date
        FROM remediation_patches_link rpl
        JOIN patches p ON rpl.patch_id = p.patch_id
        WHERE rpl.remediation_id = ?
        ORDER BY p.release_date DESC",
        [$remediationId]
    );
    
    $remediation['linked_patches'] = $patchesStmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo json_encode([
        'success' => true,
        'data' => $remediation,
        'timestamp' => date('c')
    ]);
}

/**
 * Create a new remediation
 * Note: The user_id is automatically set to the authenticated user's ID 
 * (determined by the API key or session authentication)
 */
function createRemediation() {
    global $db, $user;
    
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
    if (empty($input['description'])) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'MISSING_REQUIRED_FIELD',
                'message' => 'Field "description" is required'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Validate vulnerability_id if provided
    if (!empty($input['vulnerability_id']) && !isValidUuid($input['vulnerability_id'])) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_VULNERABILITY_ID',
                'message' => 'Invalid vulnerability ID format. Expected UUID.'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Use the authenticated user's ID
    $userId = $user['user_id'];
    
    try {
        // Begin transaction
        $db->beginTransaction();
        
        // Generate remediation ID
        $remediationId = $db->query("SELECT uuid_generate_v4()")->fetchColumn();
        
        // Insert remediation
        $sql = "INSERT INTO remediations (
            remediation_id,
            upstream_api,
            description,
            narrative,
            vulnerability_id,
            user_id,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING remediation_id";
        
        $params = [
            $remediationId,
            !empty($input['upstream_api']) ? trim($input['upstream_api']) : null,
            trim($input['description']),
            !empty($input['narrative']) ? trim($input['narrative']) : null,
            !empty($input['vulnerability_id']) ? $input['vulnerability_id'] : null,
            $userId
        ];
        
        $stmt = $db->query($sql, $params);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Link assets if provided
        if (!empty($input['asset_ids']) && is_array($input['asset_ids'])) {
            foreach ($input['asset_ids'] as $assetId) {
                if (isValidUuid($assetId)) {
                    $linkId = $db->query("SELECT uuid_generate_v4()")->fetchColumn();
                    $db->query(
                        "INSERT INTO remediation_assets_link (link_id, remediation_id, asset_id) 
                         VALUES (?, ?, ?)",
                        [$linkId, $remediationId, $assetId]
                    );
                }
            }
        }
        
        // Link patches if provided
        if (!empty($input['patch_ids']) && is_array($input['patch_ids'])) {
            foreach ($input['patch_ids'] as $patchId) {
                if (isValidUuid($patchId)) {
                    $linkId = $db->query("SELECT uuid_generate_v4()")->fetchColumn();
                    $db->query(
                        "INSERT INTO remediation_patches_link (link_id, remediation_id, patch_id) 
                         VALUES (?, ?, ?)",
                        [$linkId, $remediationId, $patchId]
                    );
                }
            }
        }
        
        // Commit transaction
        $db->commit();
        
        // Get the created remediation with full details
        $stmt = $db->query(
            "SELECT 
                r.remediation_id,
                r.upstream_api,
                r.description,
                r.narrative,
                r.vulnerability_id,
                r.user_id,
                r.created_at,
                r.updated_at,
                v.cve_id,
                v.description as vulnerability_description,
                v.severity,
                u.username,
                u.email as user_email
            FROM remediations r
            LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.vulnerability_id
            LEFT JOIN users u ON r.user_id = u.user_id
            WHERE r.remediation_id = ?",
            [$result['remediation_id']]
        );
        
        $remediation = $stmt->fetch(PDO::FETCH_ASSOC);
        
        http_response_code(201);
        echo json_encode([
            'success' => true,
            'message' => 'Remediation created successfully',
            'data' => $remediation,
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        // Rollback transaction on error
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'CREATION_FAILED',
                'message' => 'Failed to create remediation: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

/**
 * Update an existing remediation
 * Note: The user_id is automatically updated to the authenticated user's ID
 * (determined by the API key or session authentication)
 */
function updateRemediation($remediationId) {
    global $db, $user;
    
    // Validate UUID format
    if (!isValidUuid($remediationId)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_UUID',
                'message' => 'Invalid remediation ID format. Expected UUID.'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Check if remediation exists
    $checkStmt = $db->query(
        "SELECT remediation_id FROM remediations WHERE remediation_id = ?",
        [$remediationId]
    );
    
    if (!$checkStmt->fetch()) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'REMEDIATION_NOT_FOUND',
                'message' => 'Remediation not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
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
    
    try {
        // Begin transaction
        $db->beginTransaction();
        
        // Build update query dynamically based on provided fields
        $updateFields = [];
        $params = [];
        
        $allowedFields = ['upstream_api', 'description', 'narrative', 'vulnerability_id'];
        
        foreach ($allowedFields as $field) {
            if (isset($input[$field])) {
                // Validate UUIDs
                if ($field === 'vulnerability_id' && 
                    !empty($input[$field]) && 
                    !isValidUuid($input[$field])) {
                    $db->rollBack();
                    http_response_code(400);
                    echo json_encode([
                        'success' => false,
                        'error' => [
                            'code' => 'INVALID_UUID',
                            'message' => "Invalid {$field} format. Expected UUID."
                        ],
                        'timestamp' => date('c')
                    ]);
                    return;
                }
                
                $updateFields[] = "{$field} = ?";
                $params[] = !empty($input[$field]) ? trim($input[$field]) : null;
            }
        }
        
        // Always update user_id to the current authenticated user
        $updateFields[] = "user_id = ?";
        $params[] = $user['user_id'];
        
        // Always update the updated_at timestamp
        $updateFields[] = "updated_at = CURRENT_TIMESTAMP";
        
        if (count($updateFields) === 2) { // Only user_id and updated_at (no actual changes)
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'NO_FIELDS_TO_UPDATE',
                    'message' => 'No valid fields provided for update'
                ],
                'timestamp' => date('c')
            ]);
            $db->rollBack();
            return;
        }
        
        $params[] = $remediationId;
        
        $sql = "UPDATE remediations 
                SET " . implode(', ', $updateFields) . "
                WHERE remediation_id = ?
                RETURNING remediation_id";
        
        $stmt = $db->query($sql, $params);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Update asset links if provided
        if (isset($input['asset_ids']) && is_array($input['asset_ids'])) {
            // Remove existing asset links
            $db->query(
                "DELETE FROM remediation_assets_link WHERE remediation_id = ?",
                [$remediationId]
            );
            
            // Add new asset links
            foreach ($input['asset_ids'] as $assetId) {
                if (isValidUuid($assetId)) {
                    $linkId = $db->query("SELECT uuid_generate_v4()")->fetchColumn();
                    $db->query(
                        "INSERT INTO remediation_assets_link (link_id, remediation_id, asset_id) 
                         VALUES (?, ?, ?)",
                        [$linkId, $remediationId, $assetId]
                    );
                }
            }
        }
        
        // Update patch links if provided
        if (isset($input['patch_ids']) && is_array($input['patch_ids'])) {
            // Remove existing patch links
            $db->query(
                "DELETE FROM remediation_patches_link WHERE remediation_id = ?",
                [$remediationId]
            );
            
            // Add new patch links
            foreach ($input['patch_ids'] as $patchId) {
                if (isValidUuid($patchId)) {
                    $linkId = $db->query("SELECT uuid_generate_v4()")->fetchColumn();
                    $db->query(
                        "INSERT INTO remediation_patches_link (link_id, remediation_id, patch_id) 
                         VALUES (?, ?, ?)",
                        [$linkId, $remediationId, $patchId]
                    );
                }
            }
        }
        
        // Commit transaction
        $db->commit();
        
        // Get the updated remediation with full details
        $stmt = $db->query(
            "SELECT 
                r.remediation_id,
                r.upstream_api,
                r.description,
                r.narrative,
                r.vulnerability_id,
                r.user_id,
                r.created_at,
                r.updated_at,
                v.cve_id,
                v.description as vulnerability_description,
                v.severity,
                u.username,
                u.email as user_email
            FROM remediations r
            LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.vulnerability_id
            LEFT JOIN users u ON r.user_id = u.user_id
            WHERE r.remediation_id = ?",
            [$remediationId]
        );
        
        $remediation = $stmt->fetch(PDO::FETCH_ASSOC);
        
        echo json_encode([
            'success' => true,
            'message' => 'Remediation updated successfully',
            'data' => $remediation,
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        // Rollback transaction on error
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'UPDATE_FAILED',
                'message' => 'Failed to update remediation: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

/**
 * Delete a remediation
 */
function deleteRemediation($remediationId) {
    global $db;
    
    // Validate UUID format
    if (!isValidUuid($remediationId)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_UUID',
                'message' => 'Invalid remediation ID format. Expected UUID.'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Check if remediation exists
    $checkStmt = $db->query(
        "SELECT remediation_id FROM remediations WHERE remediation_id = ?",
        [$remediationId]
    );
    
    if (!$checkStmt->fetch()) {
        http_response_code(404);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'REMEDIATION_NOT_FOUND',
                'message' => 'Remediation not found'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    try {
        // Begin transaction
        $db->beginTransaction();
        
        // Delete linked assets
        $db->query(
            "DELETE FROM remediation_assets_link WHERE remediation_id = ?",
            [$remediationId]
        );
        
        // Delete linked patches
        $db->query(
            "DELETE FROM remediation_patches_link WHERE remediation_id = ?",
            [$remediationId]
        );
        
        // Delete the remediation
        $db->query(
            "DELETE FROM remediations WHERE remediation_id = ?",
            [$remediationId]
        );
        
        // Commit transaction
        $db->commit();
        
        echo json_encode([
            'success' => true,
            'message' => 'Remediation deleted successfully',
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        // Rollback transaction on error
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'DELETION_FAILED',
                'message' => 'Failed to delete remediation: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

/**
 * Validate UUID format
 */
function isValidUuid($uuid) {
    if (empty($uuid)) {
        return false;
    }
    return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uuid);
}
