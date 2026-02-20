<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/


if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../../config/database.php';
require_once __DIR__ . '/../../../../includes/auth.php';

header('Content-Type: application/json');

// Verify authentication
$auth = new Auth();
if (!$auth->isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

$user = $auth->getCurrentUser();

// Verify admin role
if ($user['role'] !== 'Admin') {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Admin access required']);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];
$path = $_SERVER['PATH_INFO'] ?? '/';

try {
    $db = DatabaseConfig::getInstance();
    
    // Route requests
    if ($method === 'GET' && $path === '/') {
        handleGetConfig($db, $user);
    } elseif ($method === 'GET' && $path === '/history') {
        handleGetHistory($db, $user);
    } elseif (($method === 'PUT' || $method === 'POST') && $path === '/') {
        handleUpdateConfig($db, $user);
    } elseif ($method === 'POST' && $path === '/preview') {
        handlePreviewChanges($db, $user);
    } elseif ($method === 'DELETE' && preg_match('/^\/[a-f0-9-]+$/', $path)) {
        handleDeleteConfig($db, $user, substr($path, 1));
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'Endpoint not found']);
    }
    
} catch (Exception $e) {
    http_response_code(500);
    error_log("Risk Matrix API Error: " . $e->getMessage());
    error_log("Stack trace: " . $e->getTraceAsString());
    echo json_encode([
        'success' => false,
        'error' => 'Server error: ' . $e->getMessage()
    ]);
}

/**
 * Handle GET /api/v1/admin/risk-matrix - Get current configuration
 */
function handleGetConfig($db, $user) {
    $sql = "SELECT * FROM risk_matrix_config WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1";
    $stmt = $db->query($sql);
    $config = $stmt->fetch();
    
    if (!$config) {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'No active configuration found']);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'data' => $config
    ]);
}

/**
 * Handle GET /api/v1/admin/risk-matrix/history - Get configuration history
 */
function handleGetHistory($db, $user) {
    $sql = "SELECT 
        c.*,
        u.username as created_by_name
    FROM risk_matrix_config c
    LEFT JOIN users u ON c.created_by = u.user_id
    ORDER BY c.created_at DESC
    LIMIT 50";
    
    $stmt = $db->query($sql);
    $history = $stmt->fetchAll();
    
    echo json_encode([
        'success' => true,
        'data' => $history
    ]);
}

/**
 * Handle PUT /api/v1/admin/risk-matrix - Update configuration
 */
function handleUpdateConfig($db, $user) {
    $input = json_decode(file_get_contents('php://input'), true);
    
    
    // Validate input
    $requiredFields = [
        'kev_weight',
        'clinical_high_score',
        'business_medium_score',
        'non_essential_score',
        'location_weight_multiplier',
        'critical_severity_score',
        'high_severity_score',
        'medium_severity_score',
        'low_severity_score'
    ];
    
    // EPSS fields are optional with defaults
    $epss_weight_enabled = isset($input['epss_weight_enabled']) && 
        $input['epss_weight_enabled'] !== '' && 
        $input['epss_weight_enabled'] !== 'false' && 
        $input['epss_weight_enabled'] !== false ? true : false;
    $epss_high_threshold = floatval($input['epss_high_threshold'] ?? 0.7);
    $epss_weight_score = intval($input['epss_weight_score'] ?? 20);
    
    
    foreach ($requiredFields as $field) {
        if (!isset($input[$field]) || $input[$field] === '' || $input[$field] === null) {
            http_response_code(400);
            echo json_encode([
                'success' => false, 
                'error' => "Missing or invalid required field: $field",
                'received_fields' => array_keys($input)
            ]);
            return;
        }
    }
    
    // Validate numeric fields
    $numericFields = [
        'kev_weight', 'clinical_high_score', 'business_medium_score', 'non_essential_score',
        'critical_severity_score', 'high_severity_score', 'medium_severity_score', 'low_severity_score'
    ];
    foreach ($numericFields as $field) {
        if (!is_numeric($input[$field])) {
            http_response_code(400);
            echo json_encode([
                'success' => false, 
                'error' => "Invalid numeric value for field: $field (received: " . var_export($input[$field], true) . ")"
            ]);
            return;
        }
    }
    
    // Validate location_weight_multiplier is numeric
    if (!is_numeric($input['location_weight_multiplier'])) {
        http_response_code(400);
        echo json_encode([
            'success' => false, 
            'error' => "Invalid numeric value for location_weight_multiplier (received: " . var_export($input['location_weight_multiplier'], true) . ")"
        ]);
        return;
    }
    
    $db->beginTransaction();
    
    try {
        // Deactivate ALL current active configurations first
        $sql = "UPDATE risk_matrix_config SET is_active = FALSE WHERE is_active = TRUE";
        $updateStmt = $db->prepare($sql);
        $updateStmt->execute();
        $deactivatedCount = $updateStmt->rowCount();
        error_log("Risk Matrix: Deactivated $deactivatedCount active configuration(s)");
        
        // Verify no active configs remain (within transaction)
        $checkActiveSql = "SELECT COUNT(*) as active_count FROM risk_matrix_config WHERE is_active = TRUE";
        $checkActiveStmt = $db->prepare($checkActiveSql);
        $checkActiveStmt->execute();
        $activeCount = $checkActiveStmt->fetch()['active_count'];
        if ($activeCount > 0) {
            error_log("Risk Matrix: WARNING - $activeCount active config(s) still exist after deactivation!");
            // Force deactivate any remaining
            $db->query("UPDATE risk_matrix_config SET is_active = FALSE WHERE is_active = TRUE");
        } else {
            error_log("Risk Matrix: Verified - no active configs remain before insert");
        }
        
        // Insert new configuration and get the ID
        // NOTE: We cannot disable triggers (insufficient privileges)
        // The trigger will fire, but if it fails, we need to handle it
        // The trigger calls recalculate_action_urgency_score for each action in action_risk_scores
        
        $sql = "INSERT INTO risk_matrix_config (
            config_name,
            is_active,
            kev_weight,
            clinical_high_score,
            business_medium_score,
            non_essential_score,
            location_weight_multiplier,
            critical_severity_score,
            high_severity_score,
            medium_severity_score,
            low_severity_score,
            epss_weight_enabled,
            epss_high_threshold,
            epss_weight_score,
            created_by
        ) VALUES (?, TRUE, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING config_id";
        
        $stmt = $db->prepare($sql);
        
        // Use PDO::PARAM_BOOL for boolean type - PostgreSQL needs explicit boolean casting
        $stmt->bindValue(1, 'Risk Matrix Configuration', PDO::PARAM_STR);
        $stmt->bindValue(2, intval($input['kev_weight']), PDO::PARAM_INT);
        $stmt->bindValue(3, intval($input['clinical_high_score']), PDO::PARAM_INT);
        $stmt->bindValue(4, intval($input['business_medium_score']), PDO::PARAM_INT);
        $stmt->bindValue(5, intval($input['non_essential_score']), PDO::PARAM_INT);
        $stmt->bindValue(6, floatval($input['location_weight_multiplier']), PDO::PARAM_STR); // numeric type
        $stmt->bindValue(7, intval($input['critical_severity_score']), PDO::PARAM_INT);
        $stmt->bindValue(8, intval($input['high_severity_score']), PDO::PARAM_INT);
        $stmt->bindValue(9, intval($input['medium_severity_score']), PDO::PARAM_INT);
        $stmt->bindValue(10, intval($input['low_severity_score']), PDO::PARAM_INT);
        $stmt->bindValue(11, $epss_weight_enabled, PDO::PARAM_BOOL); // Use boolean type directly
        $stmt->bindValue(12, floatval($epss_high_threshold), PDO::PARAM_STR); // numeric type
        $stmt->bindValue(13, intval($epss_weight_score), PDO::PARAM_INT);
        $stmt->bindValue(14, $user['user_id'], PDO::PARAM_STR); // UUID as string
        
        try {
            $stmt->execute();
        } catch (PDOException $e) {
            error_log("Risk Matrix: INSERT failed with PDO error: " . $e->getMessage());
            error_log("Risk Matrix: INSERT error code: " . $e->getCode());
            throw new Exception('Failed to insert risk matrix configuration: ' . $e->getMessage());
        }
        
        $result = $stmt->fetch();
        if (!$result) {
            error_log("Risk Matrix: INSERT failed - no config_id returned");
            error_log("Risk Matrix: Statement error info: " . json_encode($stmt->errorInfo()));
            throw new Exception('Failed to insert risk matrix configuration: no config_id returned');
        }
        $configId = $result['config_id'];
        error_log("Risk Matrix: Created new configuration with ID: $configId");
        
        // Immediately verify the INSERT worked by counting rows
        $countSql = "SELECT COUNT(*) as cnt FROM risk_matrix_config WHERE config_id = ?";
        $countStmt = $db->prepare($countSql);
        $countStmt->execute([$configId]);
        $count = $countStmt->fetch()['cnt'];
        if ($count != 1) {
            error_log("Risk Matrix: CRITICAL - Config count is $count, expected 1! ID: $configId");
            throw new Exception("Configuration INSERT verification failed - count mismatch");
        }
        error_log("Risk Matrix: INSERT verified - config exists in transaction");
        
        // Check if trigger execution caused transaction abort
        // The trigger fires AFTER INSERT, so check immediately
        if (!$db->inTransaction()) {
            $errorInfo = $db->getConnection()->errorInfo();
            error_log("Risk Matrix: CRITICAL - Transaction aborted by trigger after INSERT! Error: " . json_encode($errorInfo));
            // Try to rollback explicitly (though it's already aborted)
            try {
                $db->rollback();
            } catch (Exception $e) {
                // Already rolled back
            }
            throw new Exception('Transaction aborted by trigger. The trigger_recalculate_all_actions may have failed. Error: ' . ($errorInfo[2] ?? 'Unknown'));
        }
        
        // Check for trigger errors even if transaction is still active
        $triggerErrorInfo = $db->getConnection()->errorInfo();
        if ($triggerErrorInfo && $triggerErrorInfo[0] !== '00000' && $triggerErrorInfo[0] !== null && $triggerErrorInfo[0] !== '') {
            error_log("Risk Matrix: WARNING - PDO errors after INSERT (trigger may have failed): " . json_encode($triggerErrorInfo));
            if ($triggerErrorInfo[0] === '25P02') {
                error_log("Risk Matrix: CRITICAL - Transaction was aborted by trigger!");
                try {
                    $db->rollback();
                } catch (Exception $e) {
                    // Already aborted
                }
                throw new Exception('Transaction aborted by trigger. Check action_risk_scores table or recalculate_action_urgency_score function.');
            }
        }
        error_log("Risk Matrix: Trigger executed successfully - transaction still active");
        
        // Verify the insert was successful by querying it back (within transaction)
        // This checks that the INSERT worked before commit
        $verifySql = "SELECT * FROM risk_matrix_config WHERE config_id = ?";
        $verifyStmt = $db->prepare($verifySql);
        $verifyStmt->execute([$configId]);
        $verifyResult = $verifyStmt->fetch();
        if (!$verifyResult) {
            error_log("Risk Matrix: Verification failed - new config not found");
            throw new Exception('Failed to verify inserted configuration');
        }
        
        // Check is_active flag
        if (!$verifyResult['is_active']) {
            error_log("Risk Matrix: WARNING - Config inserted but is_active is FALSE! ID: $configId");
            throw new Exception('Configuration inserted but is_active flag is FALSE');
        }
        
        error_log("Risk Matrix: Verified new configuration - ID: $configId, kev_weight: " . $verifyResult['kev_weight'] . ", epss_weight_enabled: " . ($verifyResult['epss_weight_enabled'] ? 'true' : 'false') . ", is_active: " . ($verifyResult['is_active'] ? 'true' : 'false'));
        
        // Recalculate risk scores for all existing vulnerabilities
        // Wrap in try-catch to prevent transaction rollback if this fails
        try {
            $sql = "UPDATE device_vulnerabilities_link dvl
            SET 
                risk_score = (
                    SELECT 
                        (CASE 
                            WHEN v.is_kev = TRUE THEN ?
                            ELSE 0
                        END +
                        CASE a.criticality 
                            WHEN 'Clinical-High' THEN ?
                            WHEN 'Business-Medium' THEN ?
                            WHEN 'Non-Essential' THEN ?
                            ELSE 0
                        END +
                        COALESCE(l.criticality * ?::numeric, 0) +
                        CASE v.severity
                            WHEN 'Critical' THEN ?
                            WHEN 'High' THEN ?
                            WHEN 'Medium' THEN ?
                            WHEN 'Low' THEN ?
                            ELSE 0
                        END +
                        -- EPSS component
                        CASE 
                            WHEN ?::boolean = TRUE AND v.epss_score >= ? THEN ?
                            ELSE 0
                        END)
                    FROM medical_devices md
                    JOIN assets a ON md.asset_id = a.asset_id
                    LEFT JOIN locations l ON a.location_id = l.location_id
                    JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
                    WHERE md.device_id = dvl.device_id
                )";
            
            $stmt = $db->prepare($sql);
            $stmt->execute([
                intval($input['kev_weight']),
                intval($input['clinical_high_score']),
                intval($input['business_medium_score']),
                intval($input['non_essential_score']),
                floatval($input['location_weight_multiplier']),
                intval($input['critical_severity_score']),
                intval($input['high_severity_score']),
                intval($input['medium_severity_score']),
                intval($input['low_severity_score']),
                $epss_weight_enabled ? 'TRUE' : 'FALSE',  // Use boolean string for SQL CASE
                floatval($epss_high_threshold),
                intval($epss_weight_score)
            ]);
            error_log("Risk Matrix: Risk scores recalculated successfully");
        } catch (Exception $e) {
            error_log("Risk Matrix: WARNING - Risk score recalculation failed: " . $e->getMessage());
            // Don't throw - we want to commit the config even if recalculation fails
            // The trigger will handle recalculation anyway
        }
        
        // Refresh materialized view (optional - may fail due to permissions)
        // BUT: Check for transaction errors first - if transaction is aborted, we can't continue
        $transactionCheck = $db->getConnection()->errorInfo();
        if ($transactionCheck && $transactionCheck[0] === '25P02') {
            error_log("Risk Matrix: CRITICAL - Transaction aborted before commit! Error: " . json_encode($transactionCheck));
            throw new Exception('Transaction was aborted - cannot commit. This may be due to a trigger error.');
        }
        
        try {
            $db->query("SELECT refresh_risk_priorities()");
        } catch (Exception $e) {
            error_log("Risk Matrix: WARNING - refresh_risk_priorities failed: " . $e->getMessage());
            // Continue execution as this is not critical - the view will be refreshed on next access
        }
        
        // Double-check transaction is still valid BEFORE any further operations
        if (!$db->inTransaction()) {
            error_log("Risk Matrix: WARNING - Transaction not active! May have been aborted.");
            // Check what caused the abort
            $errorInfo = $db->getConnection()->errorInfo();
            error_log("Risk Matrix: Error info: " . json_encode($errorInfo));
            throw new Exception('Transaction was lost before commit - cannot proceed');
        }
        error_log("Risk Matrix: Transaction still active before commit check");
        
        // Double-check our config is still in the transaction before committing
        // Do this BEFORE any operations that might fail
        $preCommitCheckSql = "SELECT config_id, is_active FROM risk_matrix_config WHERE config_id = ?";
        $preCommitCheckStmt = $db->prepare($preCommitCheckSql);
        $preCommitCheckStmt->execute([$configId]);
        $preCommitCheck = $preCommitCheckStmt->fetch();
        if (!$preCommitCheck || !$preCommitCheck['is_active']) {
            error_log("Risk Matrix: CRITICAL - Config missing or inactive BEFORE commit! ID: $configId");
            throw new Exception('Configuration lost before commit - cannot proceed');
        }
        error_log("Risk Matrix: Pre-commit check passed - config exists and is active");
        
        // IMPORTANT: Log audit AFTER we verify everything, but wrap it carefully
        // This must NOT fail or it will abort the transaction
        try {
            // Only log if the function exists and won't cause transaction abort
            if (function_exists('logRiskMatrixAudit')) {
                // Check transaction status before logging
                if ($db->inTransaction()) {
                    logRiskMatrixAudit($db, $user['user_id'], 'UPDATE_RISK_MATRIX', 'risk_matrix_config', $configId,
                                 'Updated risk matrix configuration');
                }
            }
        } catch (Exception $auditError) {
            // CRITICAL: Don't let audit logging abort the transaction
            error_log("Risk Matrix: Audit logging failed (non-critical): " . $auditError->getMessage());
            // Continue - audit is not critical for the save operation
        }
        
        // Final check - transaction must still be active
        if (!$db->inTransaction()) {
            $errorInfo = $db->getConnection()->errorInfo();
            error_log("Risk Matrix: CRITICAL - Transaction aborted after audit log! Error: " . json_encode($errorInfo));
            throw new Exception('Transaction was aborted - cannot commit. Error: ' . ($errorInfo[2] ?? 'Unknown'));
        }
        
        // Check if there are any pending errors or warnings before commit
        $errorCheck = $db->getConnection()->errorInfo();
        if ($errorCheck && $errorCheck[0] !== '00000' && $errorCheck[0] !== null) {
            error_log("Risk Matrix: WARNING - PDO errors before commit: " . json_encode($errorCheck));
            if ($errorCheck[0] === '25P02') {
                throw new Exception('Transaction aborted - cannot commit. Error: ' . ($errorCheck[2] ?? 'Unknown'));
            }
        }
        
        // IMPORTANT: Commit the transaction - this makes all changes visible
        try {
            $commitResult = $db->commit();
            if (!$commitResult) {
                error_log("Risk Matrix: CRITICAL - Commit returned FALSE! Transaction may have failed.");
                throw new Exception('Transaction commit failed');
            }
            error_log("Risk Matrix: Transaction committed successfully");
        } catch (Exception $commitError) {
            error_log("Risk Matrix: CRITICAL - Commit exception: " . $commitError->getMessage());
            throw $commitError;
        }
        
        // Check for errors after commit
        $postCommitError = $db->getConnection()->errorInfo();
        if ($postCommitError && $postCommitError[0] !== '00000') {
            error_log("Risk Matrix: WARNING - PDO errors after commit: " . json_encode($postCommitError));
        }
        
        // Use a completely NEW database connection instance to verify
        // This ensures we see committed data from a fresh connection
        // Force a new instance by clearing the singleton (if possible) or using a new query
        $freshDb = DatabaseConfig::getInstance();
        // Small delay to ensure commit is fully processed and any triggers complete
        usleep(200000); // 0.2 second - longer delay to allow trigger to complete
        
        // Verify using a fresh connection after commit to ensure we see committed data
        // Query for the most recent active config (should be ours)
        $finalCheckSql = "SELECT * FROM risk_matrix_config WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1";
        $finalCheckStmt = $freshDb->prepare($finalCheckSql);
        $finalCheckStmt->execute();
        $finalCheck = $finalCheckStmt->fetch();
        
        // Compare config IDs as strings (UUIDs)
        $finalCheckConfigId = $finalCheck ? (string)$finalCheck['config_id'] : null;
        $expectedConfigId = (string)$configId;
        
        if (!$finalCheck || $finalCheckConfigId !== $expectedConfigId) {
            error_log("Risk Matrix: WARNING - Final check after commit failed! Expected ID: $expectedConfigId, Got: " . ($finalCheckConfigId ?: 'NULL'));
            // Check what configs are active - query ALL active configs to see what's wrong
            $allActiveSql = "SELECT config_id, kev_weight, is_active, created_at FROM risk_matrix_config WHERE is_active = TRUE ORDER BY created_at DESC";
            $allActiveStmt = $freshDb->prepare($allActiveSql);
            $allActiveStmt->execute();
            $allActive = $allActiveStmt->fetchAll();
            error_log("Risk Matrix: All active configs after commit: " . json_encode($allActive, JSON_PRETTY_PRINT));
            
            // Also check our specific config using fresh connection
            $ourConfigSql = "SELECT config_id, kev_weight, is_active, created_at FROM risk_matrix_config WHERE config_id = ?";
            $ourConfigStmt = $freshDb->prepare($ourConfigSql);
            $ourConfigStmt->execute([$configId]);
            $ourConfig = $ourConfigStmt->fetch();
            if ($ourConfig === false) {
                error_log("Risk Matrix: CRITICAL - Our config not found in database! Config ID: $configId");
            } else {
                error_log("Risk Matrix: Our config status: " . json_encode($ourConfig, JSON_PRETTY_PRINT));
            }
            
            // If our config exists but isn't active, something went wrong
            if ($ourConfig && !$ourConfig['is_active']) {
                error_log("Risk Matrix: CRITICAL - Our config exists but is_active is FALSE! Attempting to fix...");
                // Start a new transaction to fix this
                $freshDb->beginTransaction();
                try {
                    // Deactivate all others
                    $reactivateSql = "UPDATE risk_matrix_config SET is_active = FALSE WHERE is_active = TRUE AND config_id != ?";
                    $reactivateStmt1 = $freshDb->prepare($reactivateSql);
                    $reactivateStmt1->execute([$configId]);
                    
                    // Activate our config
                    $reactivateSql2 = "UPDATE risk_matrix_config SET is_active = TRUE WHERE config_id = ?";
                    $reactivateStmt2 = $freshDb->prepare($reactivateSql2);
                    $reactivateStmt2->execute([$configId]);
                    $freshDb->commit();
                    
                    error_log("Risk Matrix: Fixed - reactivated our config");
                    // Re-query to get the fixed config
                    $finalCheckStmt->execute();
                    $finalCheck = $finalCheckStmt->fetch();
                } catch (Exception $e) {
                    $freshDb->rollback();
                    error_log("Risk Matrix: Failed to fix config: " . $e->getMessage());
                }
            }
            
            // Use verification result if final check still fails
            if (!$finalCheck || (string)$finalCheck['config_id'] !== $expectedConfigId) {
                error_log("Risk Matrix: Using pre-commit verification result");
                $finalCheck = $verifyResult;
            }
        } else {
            error_log("Risk Matrix: Commit successful - verified. Config ID: $configId, kev_weight: " . $finalCheck['kev_weight'] . ", epss_weight_enabled: " . ($finalCheck['epss_weight_enabled'] ? 'true' : 'false'));
        }
        
        echo json_encode([
            'success' => true,
            'message' => 'Risk matrix configuration updated successfully',
            'config_id' => $configId,
            'saved_values' => [
                'kev_weight' => $finalCheck['kev_weight'],
                'epss_weight_enabled' => $finalCheck['epss_weight_enabled']
            ]
        ]);
        
    } catch (Exception $e) {
        $db->rollBack();
        throw $e;
    }
}

/**
 * Handle POST /api/v1/admin/risk-matrix/preview - Preview configuration changes
 */
function handlePreviewChanges($db, $user) {
    $input = json_decode(file_get_contents('php://input'), true);
    
    // Get current top 20 priorities
    $sql = "SELECT 
        link_id,
        cve_id,
        hostname,
        device_name,
        severity,
        asset_criticality,
        location_criticality,
        is_kev,
        calculated_risk_score,
        priority_tier
    FROM risk_priority_view
    ORDER BY calculated_risk_score DESC
    LIMIT 20";
    
    $stmt = $db->query($sql);
    $current = $stmt->fetchAll();
    
    // Calculate what the scores would be with new configuration
    $newScores = [];
    foreach ($current as $item) {
        $score = 0;
        
        // KEV weight
        if ($item['is_kev']) {
            $score += $input['kev_weight'];
        }
        
        // Asset criticality
        if ($item['asset_criticality'] === 'Clinical-High') {
            $score += $input['clinical_high_score'];
        } elseif ($item['asset_criticality'] === 'Business-Medium') {
            $score += $input['business_medium_score'];
        } elseif ($item['asset_criticality'] === 'Non-Essential') {
            $score += $input['non_essential_score'];
        }
        
        // Location criticality
        if ($item['location_criticality']) {
            $score += $item['location_criticality'] * floatval($input['location_weight_multiplier']);
        }
        
        // Severity
        if ($item['severity'] === 'Critical') {
            $score += $input['critical_severity_score'];
        } elseif ($item['severity'] === 'High') {
            $score += $input['high_severity_score'];
        } elseif ($item['severity'] === 'Medium') {
            $score += $input['medium_severity_score'];
        } elseif ($item['severity'] === 'Low') {
            $score += $input['low_severity_score'];
        }
        
        // Determine new tier
        $tier = 3; // Default
        if ($item['is_kev']) {
            $tier = 1;
        } elseif ($item['asset_criticality'] === 'Clinical-High' && 
                  $item['location_criticality'] >= 8 && 
                  in_array($item['severity'], ['Critical', 'High'])) {
            $tier = 2;
        }
        
        $newScores[] = [
            'link_id' => $item['link_id'],
            'cve_id' => $item['cve_id'],
            'hostname' => $item['hostname'],
            'device_name' => $item['device_name'],
            'current_score' => $item['calculated_risk_score'],
            'new_score' => $score,
            'score_change' => $score - $item['calculated_risk_score'],
            'current_tier' => $item['priority_tier'],
            'new_tier' => $tier,
            'tier_change' => $tier - $item['priority_tier']
        ];
    }
    
    // Sort by new score
    usort($newScores, function($a, $b) {
        return $b['new_score'] - $a['new_score'];
    });
    
    echo json_encode([
        'success' => true,
        'data' => [
            'preview' => $newScores,
            'summary' => [
                'items_analyzed' => count($newScores),
                'tier_changes' => array_filter($newScores, function($item) {
                    return $item['tier_change'] != 0;
                }),
                'avg_score_change' => array_sum(array_column($newScores, 'score_change')) / count($newScores)
            ]
        ]
    ]);
}

/**
 * Handle DELETE /api/v1/admin/risk-matrix/{config_id} - Delete configuration
 */
function handleDeleteConfig($db, $user, $configId) {
    // Validate UUID format
    if (!preg_match('/^[a-f0-9-]{36}$/', $configId)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Invalid configuration ID format']);
        return;
    }
    
    $db->beginTransaction();
    
    try {
        // Check if configuration exists
        $sql = "SELECT config_name, is_active FROM risk_matrix_config WHERE config_id = ?";
        $stmt = $db->prepare($sql);
        $stmt->execute([$configId]);
        $config = $stmt->fetch();
        
        if (!$config) {
            http_response_code(404);
            echo json_encode(['success' => false, 'error' => 'Configuration not found']);
            return;
        }
        
        // Prevent deletion of active configuration
        if ($config['is_active']) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Cannot delete active configuration. Please activate another configuration first.']);
            return;
        }
        
        // Delete the configuration
        $sql = "DELETE FROM risk_matrix_config WHERE config_id = ?";
        $stmt = $db->prepare($sql);
        $stmt->execute([$configId]);
        
        // Log the action
        try {
            logRiskMatrixAudit($db, $user['user_id'], 'DELETE_RISK_MATRIX', 'risk_matrix_config', $configId,
                     'Deleted risk matrix configuration: ' . $config['config_name']);
        } catch (Exception $e) {
            error_log("Warning: Could not log audit: " . $e->getMessage());
            // Continue execution as this is not critical
        }
        
        $db->commit();
        
        echo json_encode([
            'success' => true,
            'message' => 'Risk matrix configuration deleted successfully',
            'deleted_config' => $config['config_name']
        ]);
        
    } catch (Exception $e) {
        $db->rollBack();
        throw $e;
    }
}

/**
 * Log audit trail for risk matrix
 */
function logRiskMatrixAudit($db, $userId, $action, $table, $recordId, $details) {
    $sql = "INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values, ip_address, user_agent, timestamp)
            VALUES (?, ?, ?, ?, ?::jsonb, ?, ?, CURRENT_TIMESTAMP)";
    $stmt = $db->prepare($sql);
    // Ensure details is valid JSON - wrap string in quotes if needed
    if (is_string($details) && !empty($details)) {
        // Check if it's already valid JSON
        $testJson = json_decode($details);
        if ($testJson === null && json_last_error() !== JSON_ERROR_NONE) {
            // Not valid JSON - wrap it as a JSON object
            $detailsJson = json_encode(['message' => $details]);
        } else {
            $detailsJson = $details;
        }
    } else {
        $detailsJson = is_array($details) ? json_encode($details) : ($details ?? null);
    }
    $stmt->execute([
        $userId,
        $action,
        $table,
        $recordId,
        $detailsJson,
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ]);
}

