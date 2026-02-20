<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

require_once __DIR__ . '/version-comparison.php';

/**
 * Apply a patch to one or more assets
 * 
 * @param string $patchId Patch UUID
 * @param array $assetIds Array of asset UUIDs
 * @param string $userId User applying the patch
 * @param string $verificationStatus Initial verification status
 * @param string $verificationMethod Method of verification
 * @param string $notes Optional notes
 * @return array Result with success status and details
 */
function applyPatch($patchId, $assetIds, $userId, $verificationStatus = 'Pending', $verificationMethod = 'Manual', $notes = '') {
    $db = DatabaseConfig::getInstance();
    
    // Get patch details
    $patch = getPatchDetails($patchId);
    if (!$patch) {
        return [
            'success' => false,
            'message' => 'Patch not found'
        ];
    }
    
    $db->beginTransaction();
    
    try {
        $applicationsCreated = 0;
        $vulnerabilitiesClosed = 0;
        
        foreach ($assetIds as $assetId) {
            // Get device_id for this asset
            $sql = "SELECT device_id FROM medical_devices WHERE asset_id = ?";
            $stmt = $db->prepare($sql);
            $stmt->execute([$assetId]);
            $device = $stmt->fetch();
            $deviceId = $device ? $device['device_id'] : null;
            
            // Create patch application record
            $sql = "INSERT INTO patch_applications (
                        patch_id, asset_id, device_id, applied_by,
                        verification_status, verification_method, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    RETURNING application_id";
            
            $stmt = $db->prepare($sql);
            $stmt->execute([
                $patchId,
                $assetId,
                $deviceId,
                $userId,
                $verificationStatus,
                $verificationMethod,
                $notes
            ]);
            
            $application = $stmt->fetch();
            $applicationId = $application['application_id'];
            $applicationsCreated++;
            
            // Create activity log entry for asset timeline
            createPatchActivityLog($db, $assetId, $deviceId, $patch, $userId, $applicationId);
            
            // If verification status is 'Verified', automatically close vulnerabilities
            if ($verificationStatus === 'Verified' && $deviceId) {
                $closed = closePatchVulnerabilities($db, $patchId, $deviceId, $userId, $applicationId);
                $vulnerabilitiesClosed += $closed;
            }
        }
        
        $db->commit();
        
        // Refresh materialized views
        refreshRiskViews($db);
        
        return [
            'success' => true,
            'message' => "Patch applied to $applicationsCreated asset(s). $vulnerabilitiesClosed vulnerabilities closed.",
            'applications_created' => $applicationsCreated,
            'vulnerabilities_closed' => $vulnerabilitiesClosed
        ];
        
    } catch (Exception $e) {
        $db->rollBack();
        error_log("Error applying patch: " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'Error applying patch: ' . $e->getMessage()
        ];
    }
}

/**
 * Close vulnerabilities associated with a patch for a specific device
 * 
 * @param object $db Database connection
 * @param string $patchId Patch UUID
 * @param string $deviceId Device UUID
 * @param string $userId User ID
 * @param string $applicationId Application ID for reference
 * @return int Number of vulnerabilities closed
 */
function closePatchVulnerabilities($db, $patchId, $deviceId, $userId, $applicationId) {
    // Get patch details
    $patch = getPatchDetails($patchId);
    if (!$patch || empty($patch['cve_list'])) {
        return 0;
    }
    
    $cveList = json_decode($patch['cve_list'], true);
    if (!is_array($cveList)) {
        return 0;
    }
    
    $closedCount = 0;
    
    foreach ($cveList as $cveId) {
        $sql = "UPDATE device_vulnerabilities_link 
                SET remediation_status = 'Resolved',
                    remediation_notes = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE device_id = ? 
                AND cve_id = ?
                AND remediation_status IN ('Open', 'In Progress')";
        
        $remediationNote = sprintf(
            "Resolved by patch: %s (Application ID: %s)",
            $patch['patch_name'],
            $applicationId
        );
        
        $stmt = $db->prepare($sql);
        $stmt->execute([$remediationNote, $deviceId, $cveId]);
        
        if ($stmt->rowCount() > 0) {
            $closedCount++;
            
            // Log the action
            logAudit($db, $userId, 'PATCH_CLOSE_VULNERABILITY', 'device_vulnerabilities_link', null, [
                'device_id' => $deviceId,
                'cve_id' => $cveId,
                'patch_id' => $patchId,
                'application_id' => $applicationId
            ]);
        }
    }
    
    return $closedCount;
}

/**
 * Create activity log entry for patch application
 * 
 * @param object $db Database connection
 * @param string $assetId Asset UUID
 * @param string $deviceId Device UUID
 * @param array $patch Patch details
 * @param string $userId User ID
 * @param string $applicationId Application ID
 */
function createPatchActivityLog($db, $assetId, $deviceId, $patch, $userId, $applicationId) {
    $cveList = json_decode($patch['cve_list'], true);
    $cveCount = is_array($cveList) ? count($cveList) : 0;
    
    $activityDetails = [
        'action' => 'patch_applied',
        'patch_id' => $patch['patch_id'],
        'patch_name' => $patch['patch_name'],
        'patch_type' => $patch['patch_type'],
        'application_id' => $applicationId,
        'cve_count' => $cveCount,
        'target_version' => $patch['target_version']
    ];
    
    // Create audit log entry
    $sql = "INSERT INTO audit_logs (
                user_id, action, table_name, record_id, new_values, ip_address, user_agent, timestamp
            ) VALUES (?, 'PATCH_APPLIED', 'assets', ?, ?, ?, ?, CURRENT_TIMESTAMP)";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([
        $userId,
        $assetId,
        json_encode($activityDetails),
        $_SERVER['REMOTE_ADDR'] ?? 'system',
        $_SERVER['HTTP_USER_AGENT'] ?? 'system'
    ]);
}

/**
 * Verify a patch application
 * 
 * @param string $applicationId Application UUID
 * @param string $userId User verifying
 * @param string $verificationStatus Status: 'Verified', 'Failed', 'Rolled Back'
 * @param string $notes Verification notes
 * @return array Result
 */
function verifyPatchApplication($applicationId, $userId, $verificationStatus, $notes = '') {
    $db = DatabaseConfig::getInstance();
    
    $db->beginTransaction();
    
    try {
        // Update patch application
        $sql = "UPDATE patch_applications 
                SET verification_status = ?,
                    verification_date = CURRENT_TIMESTAMP,
                    verified_by = ?,
                    notes = CASE 
                        WHEN notes IS NULL THEN ?
                        ELSE notes || E'\\n\\n' || ?
                    END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE application_id = ?
                RETURNING patch_id, device_id, asset_id";
        
        $stmt = $db->prepare($sql);
        $stmt->execute([$verificationStatus, $userId, $notes, $notes, $applicationId]);
        
        $application = $stmt->fetch();
        if (!$application) {
            throw new Exception('Patch application not found');
        }
        
        // If verified, close vulnerabilities
        $vulnerabilitiesClosed = 0;
        if ($verificationStatus === 'Verified' && $application['device_id']) {
            $vulnerabilitiesClosed = closePatchVulnerabilities(
                $db,
                $application['patch_id'],
                $application['device_id'],
                $userId,
                $applicationId
            );
        }
        
        // Log the verification
        logAudit($db, $userId, 'PATCH_VERIFIED', 'patch_applications', $applicationId, [
            'verification_status' => $verificationStatus,
            'vulnerabilities_closed' => $vulnerabilitiesClosed
        ]);
        
        $db->commit();
        
        // Refresh views
        refreshRiskViews($db);
        
        return [
            'success' => true,
            'message' => "Patch verification updated. $vulnerabilitiesClosed vulnerabilities closed.",
            'vulnerabilities_closed' => $vulnerabilitiesClosed
        ];
        
    } catch (Exception $e) {
        $db->rollBack();
        error_log("Error verifying patch: " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'Error verifying patch: ' . $e->getMessage()
        ];
    }
}

/**
 * Get patch details
 * 
 * @param string $patchId Patch UUID
 * @return array|null Patch details or null
 */
function getPatchDetails($patchId) {
    $db = DatabaseConfig::getInstance();
    
    $sql = "SELECT * FROM patches WHERE patch_id = ?";
    $stmt = $db->prepare($sql);
    $stmt->execute([$patchId]);
    
    return $stmt->fetch();
}

/**
 * Get patch application history for an asset
 * 
 * @param string $assetId Asset UUID
 * @return array Patch applications
 */
function getAssetPatchHistory($assetId) {
    $db = DatabaseConfig::getInstance();
    
    $sql = "SELECT 
                pa.*,
                p.patch_name,
                p.patch_type,
                p.target_version,
                p.cve_list,
                u1.username as applied_by_name,
                u2.username as verified_by_name
            FROM patch_applications pa
            JOIN patches p ON pa.patch_id = p.patch_id
            LEFT JOIN users u1 ON pa.applied_by = u1.user_id
            LEFT JOIN users u2 ON pa.verified_by = u2.user_id
            WHERE pa.asset_id = ?
            ORDER BY pa.applied_at DESC";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([$assetId]);
    
    return $stmt->fetchAll();
}

/**
 * Refresh risk priority materialized views
 * 
 * @param object $db Database connection
 */
function refreshRiskViews($db) {
    try {
        $db->query("SELECT refresh_risk_priorities()");
        $db->query("SELECT refresh_software_package_risk_priority_view()");
    } catch (Exception $e) {
        error_log("Error refreshing risk views: " . $e->getMessage());
    }
}

/**
 * Process SBOM upload and detect software updates
 * 
 * @param string $deviceId Device UUID
 * @param array $newComponents New software components from SBOM
 * @param string $userId User uploading SBOM
 * @return array Result with closed vulnerabilities
 */
function processSBOMUpdate($deviceId, $newComponents, $userId) {
    $db = DatabaseConfig::getInstance();
    
    // Get current components for this device
    $sql = "SELECT sc.component_id, sc.name, sc.version, sc.package_id
            FROM software_components sc
            JOIN sboms s ON sc.sbom_id = s.sbom_id
            WHERE s.device_id = ?
            AND s.sbom_id = (
                SELECT sbom_id FROM sboms 
                WHERE device_id = ? 
                ORDER BY uploaded_at DESC 
                LIMIT 1 OFFSET 1
            )";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([$deviceId, $deviceId]);
    $oldComponents = $stmt->fetchAll(PDO::FETCH_GROUP|PDO::FETCH_ASSOC);
    
    $totalClosed = 0;
    
    // Compare versions and auto-close resolved vulnerabilities
    foreach ($newComponents as $newComp) {
        $name = $newComp['name'];
        
        if (isset($oldComponents[$name])) {
            $oldComp = $oldComponents[$name][0];
            $oldVersion = $oldComp['version'];
            $newVersion = $newComp['version'];
            $packageId = $oldComp['package_id'];
            
            // Check if version changed
            if ($oldVersion !== $newVersion && $packageId) {
                $closed = autoCloseResolvedVulnerabilities(
                    $deviceId,
                    $packageId,
                    $oldVersion,
                    $newVersion,
                    $userId,
                    "Detected by SBOM upload"
                );
                
                $totalClosed += $closed;
            }
        }
    }
    
    return [
        'success' => true,
        'vulnerabilities_closed' => $totalClosed
    ];
}

/**
 * Get patch recommendations for a device
 * 
 * @param string $deviceId Device UUID
 * @return array Recommended patches
 */
function getRecommendedPatches($deviceId) {
    $db = DatabaseConfig::getInstance();
    
    $sql = "SELECT DISTINCT
                p.*,
                COUNT(DISTINCT dvl.cve_id) as applicable_cve_count
            FROM patches p
            JOIN software_packages sp ON p.target_package_id = sp.package_id
            JOIN software_components sc ON sp.package_id = sc.package_id
            JOIN sboms s ON sc.sbom_id = s.sbom_id
            LEFT JOIN device_vulnerabilities_link dvl ON dvl.device_id = s.device_id
                AND dvl.cve_id = ANY(SELECT jsonb_array_elements_text(p.cve_list))
                AND dvl.remediation_status = 'Open'
            WHERE s.device_id = ?
            AND p.is_active = TRUE
            GROUP BY p.patch_id
            ORDER BY applicable_cve_count DESC, p.release_date DESC";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([$deviceId]);
    
    return $stmt->fetchAll();
}

