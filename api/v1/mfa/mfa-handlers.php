<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

/**
 * Handle GET requests
 */
function handleGetRequest($mfaService, $user, $action) {
    switch ($action) {
        case 'status':
            // Get MFA status
            $isEnabled = $mfaService->isMFAEnabled($user['user_id']);
            $backupCodes = $isEnabled ? $mfaService->getBackupCodes($user['user_id']) : [];
            
            ob_clean();
            echo json_encode([
                'success' => true,
                'mfa_enabled' => $isEnabled,
                'backup_codes_count' => count($backupCodes)
            ]);
            break;
            
        case 'backup-codes':
            // Get backup codes
            $backupCodes = $mfaService->getBackupCodes($user['user_id']);
            
            ob_clean();
            echo json_encode([
                'success' => true,
                'backup_codes' => $backupCodes
            ]);
            break;
            
        default:
            http_response_code(404);
            ob_clean();
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

/**
 * Handle POST requests
 */
function handlePostRequest($mfaService, $user, $action) {
    error_log("MFA handlePostRequest called with action: $action");
    $input = json_decode(file_get_contents('php://input'), true);
    
    switch ($action) {
        case 'generate-secret':
            error_log("MFA generate-secret case called");
            // Generate new MFA secret
            $result = $mfaService->generateSecret($user['user_id']);
            error_log("MFA generateSecret result: " . json_encode($result));
            
            if ($result) {
                ob_clean();
                echo json_encode([
                    'success' => true,
                    'data' => $result
                ]);
            } else {
                http_response_code(400);
                ob_clean();
                echo json_encode(['error' => 'Failed to generate MFA secret']);
            }
            break;
            
        case 'activate':
            // Activate MFA
            $code = $input['code'] ?? '';
            
            if (empty($code)) {
                http_response_code(400);
                ob_clean();
                echo json_encode(['error' => 'Verification code is required']);
                return;
            }
            
            $backupCodes = $mfaService->activateMFA($user['user_id'], $code);
            
            if ($backupCodes !== false) {
                ob_clean();
                echo json_encode([
                    'success' => true,
                    'message' => 'MFA activated successfully',
                    'backup_codes' => $backupCodes
                ]);
            } else {
                http_response_code(400);
                ob_clean();
                echo json_encode(['error' => 'Failed to activate MFA. Invalid verification code.']);
            }
            break;
            
        case 'verify':
            // Verify MFA code
            $code = $input['code'] ?? '';
            
            if (empty($code)) {
                http_response_code(400);
                ob_clean();
                echo json_encode(['error' => 'Verification code is required']);
                return;
            }
            
            // Get user's MFA secret
            $stmt = DatabaseConfig::getInstance()->prepare("SELECT mfa_secret FROM users WHERE user_id = ?");
            $stmt->execute([$user['user_id']]);
            $userData = $stmt->fetch();
            
            if (!$userData || !$userData['mfa_secret']) {
                http_response_code(400);
                ob_clean();
                echo json_encode(['error' => 'MFA not configured for this user']);
                return;
            }
            
            $isValid = $mfaService->verifyCode($userData['mfa_secret'], $code);
            
            ob_clean();
            echo json_encode([
                'success' => true,
                'valid' => $isValid
            ]);
            break;
            
        case 'disable':
            // Disable MFA (simple disable without verification code)
            $result = $mfaService->disableMFASimple($user['user_id']);
            
            if ($result) {
                ob_clean();
                echo json_encode([
                    'success' => true,
                    'message' => 'MFA disabled successfully'
                ]);
            } else {
                http_response_code(400);
                ob_clean();
                echo json_encode(['error' => 'Failed to disable MFA']);
            }
            break;
            
        default:
            http_response_code(404);
            ob_clean();
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

/**
 * Handle PUT requests
 */
function handlePutRequest($mfaService, $user, $action) {
    $input = json_decode(file_get_contents('php://input'), true);
    
    switch ($action) {
        case 'regenerate-backup-codes':
            // Regenerate backup codes
            $code = $input['code'] ?? '';
            
            if (empty($code)) {
                http_response_code(400);
                ob_clean();
                echo json_encode(['error' => 'Verification code is required']);
                return;
            }
            
            // Verify current code
            $stmt = DatabaseConfig::getInstance()->prepare("SELECT mfa_secret FROM users WHERE user_id = ?");
            $stmt->execute([$user['user_id']]);
            $userData = $stmt->fetch();
            
            if (!$userData || !$userData['mfa_secret']) {
                http_response_code(400);
                ob_clean();
                echo json_encode(['error' => 'MFA not configured for this user']);
                return;
            }
            
            $isValid = $mfaService->verifyCode($userData['mfa_secret'], $code);
            
            if (!$isValid) {
                http_response_code(400);
                ob_clean();
                echo json_encode(['error' => 'Invalid verification code']);
                return;
            }
            
            // Generate new backup codes
            $backupCodes = [];
            for ($i = 0; $i < 10; $i++) {
                $backupCodes[] = strtoupper(substr(md5(uniqid(rand(), true)), 0, 8));
            }
            
            // Update backup codes
            $stmt = DatabaseConfig::getInstance()->prepare("
                UPDATE users 
                SET mfa_backup_codes = ?, updated_at = NOW() 
                WHERE user_id = ?
            ");
            $result = $stmt->execute([json_encode($backupCodes), $user['user_id']]);
            
            if ($result) {
                ob_clean();
                echo json_encode([
                    'success' => true,
                    'message' => 'Backup codes regenerated successfully',
                    'backup_codes' => $backupCodes
                ]);
            } else {
                http_response_code(500);
                ob_clean();
                echo json_encode(['error' => 'Failed to regenerate backup codes']);
            }
            break;
            
        default:
            http_response_code(404);
            ob_clean();
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}

/**
 * Handle DELETE requests
 */
function handleDeleteRequest($mfaService, $user, $action) {
    $input = json_decode(file_get_contents('php://input'), true);
    
    switch ($action) {
        case 'disable':
            // Disable MFA
            $code = $input['code'] ?? '';
            
            if (empty($code)) {
                http_response_code(400);
                ob_clean();
                echo json_encode(['error' => 'Verification code is required']);
                return;
            }
            
            $result = $mfaService->disableMFA($user['user_id'], $code);
            
            if ($result) {
                ob_clean();
                echo json_encode([
                    'success' => true,
                    'message' => 'MFA disabled successfully'
                ]);
            } else {
                http_response_code(400);
                ob_clean();
                echo json_encode(['error' => 'Failed to disable MFA. Invalid verification code.']);
            }
            break;
            
        default:
            http_response_code(404);
            ob_clean();
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}
?>
