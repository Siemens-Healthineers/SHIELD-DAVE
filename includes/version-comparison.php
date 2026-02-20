<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

require_once __DIR__ . '/../config/database.php';

/**
 * Compare two semantic version strings
 * 
 * Supports various version formats:
 * - Semantic: 1.2.3, 2.0.0-beta.1
 * - Multi-part: 2023.001.20085, 24.004.20220
 * - Simple: 5.0, 1.2
 * 
 * @param string $version1 First version to compare
 * @param string $version2 Second version to compare
 * @return int Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
 */
function compareVersions($version1, $version2) {
    // Normalize versions - remove 'v' prefix if present
    $v1 = ltrim($version1, 'vV');
    $v2 = ltrim($version2, 'vV');
    
    // Handle exact match
    if ($v1 === $v2) {
        return 0;
    }
    
    // Split by common delimiters (. - _)
    $parts1 = preg_split('/[.\-_]/', $v1);
    $parts2 = preg_split('/[.\-_]/', $v2);
    
    // Compare each part
    $maxParts = max(count($parts1), count($parts2));
    
    for ($i = 0; $i < $maxParts; $i++) {
        $part1 = isset($parts1[$i]) ? $parts1[$i] : '0';
        $part2 = isset($parts2[$i]) ? $parts2[$i] : '0';
        
        // Try numeric comparison first
        if (is_numeric($part1) && is_numeric($part2)) {
            $num1 = intval($part1);
            $num2 = intval($part2);
            
            if ($num1 < $num2) return -1;
            if ($num1 > $num2) return 1;
        } else {
            // Fall back to string comparison for alpha/beta/rc versions
            $cmp = strcmp($part1, $part2);
            if ($cmp !== 0) {
                return $cmp < 0 ? -1 : 1;
            }
        }
    }
    
    return 0;
}

/**
 * Check if a version falls within a vulnerable range
 * 
 * Supports range formats:
 * - "< 1.2.3" - less than
 * - "<= 1.2.3" - less than or equal
 * - ">= 1.0.0, < 2.0.0" - range
 * - "1.2.3" - exact version
 * - "1.2.*" - wildcard
 * 
 * @param string $version Version to check
 * @param string $versionRange Vulnerability range expression
 * @return bool True if version is vulnerable
 */
function isVersionVulnerable($version, $versionRange) {
    // Handle empty inputs
    if (empty($versionRange) || empty($version)) {
        return false;
    }
    
    // Normalize version
    $version = ltrim($version, 'vV');
    
    // Handle wildcard matches (e.g., "1.2.*")
    if (strpos($versionRange, '*') !== false) {
        $pattern = str_replace('.', '\.', $versionRange);
        $pattern = str_replace('*', '.*', $pattern);
        return preg_match('/^' . $pattern . '$/', $version) === 1;
    }
    
    // Handle multiple conditions separated by comma or AND
    if (strpos($versionRange, ',') !== false || stripos($versionRange, ' AND ') !== false) {
        $separator = strpos($versionRange, ',') !== false ? ',' : ' AND ';
        $conditions = array_map('trim', explode($separator, $versionRange));
        
        foreach ($conditions as $condition) {
            if (!isVersionVulnerable($version, $condition)) {
                return false;
            }
        }
        return true;
    }
    
    // Handle OR conditions
    if (stripos($versionRange, ' OR ') !== false) {
        $conditions = array_map('trim', explode(' OR ', $versionRange));
        
        foreach ($conditions as $condition) {
            if (isVersionVulnerable($version, $condition)) {
                return true;
            }
        }
        return false;
    }
    
    // Parse comparison operators
    if (preg_match('/^(<=|>=|<|>|=|!=)\s*(.+)$/', $versionRange, $matches)) {
        $operator = $matches[1];
        $compareVersion = trim($matches[2]);
        
        $cmp = compareVersions($version, $compareVersion);
        
        switch ($operator) {
            case '<':
                return $cmp < 0;
            case '<=':
                return $cmp <= 0;
            case '>':
                return $cmp > 0;
            case '>=':
                return $cmp >= 0;
            case '=':
                return $cmp === 0;
            case '!=':
                return $cmp !== 0;
            default:
                return false;
        }
    }
    
    // If no operator, treat as exact match
    return compareVersions($version, $versionRange) === 0;
}

/**
 * Get all vulnerabilities for a specific software package version
 * 
 * @param string $packageId Package UUID
 * @param string $version Version string
 * @return array Array of vulnerability records
 */
function getVulnerabilitiesForVersion($packageId, $version) {
    try {
        $db = DatabaseConfig::getInstance();
        $stmt = $db->prepare("
            SELECT 
                v.cve_id,
                v.description,
                v.severity,
                v.cvss_v3_score,
                v.cvss_v2_score,
                v.cvss_v4_score,
                v.is_kev,
                v.published_date,
                spv.affects_version_range
            FROM software_package_vulnerabilities spv
            JOIN vulnerabilities v ON v.cve_id = spv.cve_id
            WHERE spv.package_id = :package_id
            ORDER BY 
                CASE v.severity
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END,
                v.is_kev DESC,
                v.published_date DESC
        ");
        
        $stmt->execute(['package_id' => $packageId]);
        $vulnerabilities = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Filter to only vulnerabilities that affect this specific version
        $affectedVulns = [];
        foreach ($vulnerabilities as $vuln) {
            if (isVersionVulnerable($version, $vuln['affects_version_range'])) {
                $affectedVulns[] = $vuln;
            }
        }
        
        return $affectedVulns;
        
    } catch (PDOException $e) {
        error_log("Error getting vulnerabilities for version: " . $e->getMessage());
        return [];
    }
}

/**
 * Get vulnerabilities that would be resolved by updating software
 * 
 * This is the key function for automatic CVE closure
 * 
 * @param string $packageId Package UUID
 * @param string $oldVersion Current version
 * @param string $newVersion Target version
 * @return array Array of CVE IDs that would be resolved
 */
function getVulnerabilitiesResolvedByUpdate($packageId, $oldVersion, $newVersion) {
    try {
        $db = DatabaseConfig::getInstance();
        // Get all vulnerabilities for the package
        $stmt = $db->prepare("
            SELECT 
                spv.cve_id,
                spv.affects_version_range,
                v.description,
                v.severity
            FROM software_package_vulnerabilities spv
            JOIN vulnerabilities v ON v.cve_id = spv.cve_id
            WHERE spv.package_id = :package_id
        ");
        
        $stmt->execute(['package_id' => $packageId]);
        $allVulns = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $resolvedCVEs = [];
        
        foreach ($allVulns as $vuln) {
            $affectsOldVersion = isVersionVulnerable($oldVersion, $vuln['affects_version_range']);
            $affectsNewVersion = isVersionVulnerable($newVersion, $vuln['affects_version_range']);
            
            // If old version is vulnerable but new version is not, it's resolved
            if ($affectsOldVersion && !$affectsNewVersion) {
                $resolvedCVEs[] = [
                    'cve_id' => $vuln['cve_id'],
                    'description' => $vuln['description'],
                    'severity' => $vuln['severity'],
                    'version_range' => $vuln['affects_version_range']
                ];
            }
        }
        
        return $resolvedCVEs;
        
    } catch (PDOException $e) {
        error_log("Error getting resolved vulnerabilities: " . $e->getMessage());
        return [];
    }
}

/**
 * Auto-close vulnerabilities for a device when software is updated
 * 
 * @param string $deviceId Device UUID
 * @param string $packageId Package UUID
 * @param string $oldVersion Previous version
 * @param string $newVersion New version
 * @param string $userId User performing the update
 * @param string $method Update method (e.g., 'SBOM Upload', 'Manual Update', 'Patch Application')
 * @return array Results with closed CVE count and details
 */
function autoCloseResolvedVulnerabilities($deviceId, $packageId, $oldVersion, $newVersion, $userId, $method = 'Software Update') {
    try {
        $db = DatabaseConfig::getInstance();
        // Get vulnerabilities resolved by this update
        $resolvedCVEs = getVulnerabilitiesResolvedByUpdate($packageId, $oldVersion, $newVersion);
        
        if (empty($resolvedCVEs)) {
            return [
                'success' => true,
                'closed_count' => 0,
                'cves' => []
            ];
        }
        
        // Get package name for audit log
        $stmt = $db->prepare("SELECT name FROM software_packages WHERE package_id = :package_id");
        $stmt->execute(['package_id' => $packageId]);
        $packageName = $stmt->fetchColumn();
        
        $closedCount = 0;
        $closedCVEs = [];
        
        $db->beginTransaction();
        
        foreach ($resolvedCVEs as $cve) {
            // Update device_vulnerabilities_link to mark as resolved
            $updateStmt = $db->prepare("
                UPDATE device_vulnerabilities_link
                SET 
                    remediation_status = 'Resolved',
                    remediation_date = CURRENT_TIMESTAMP,
                    remediated_by = :user_id,
                    remediation_notes = :notes
                WHERE device_id = :device_id
                  AND cve_id = :cve_id
                  AND remediation_status IN ('Open', 'In Progress')
            ");
            
            $notes = sprintf(
                "Automatically resolved by %s: %s updated from %s to %s",
                $method,
                $packageName,
                $oldVersion,
                $newVersion
            );
            
            $updateStmt->execute([
                'user_id' => $userId,
                'notes' => $notes,
                'device_id' => $deviceId,
                'cve_id' => $cve['cve_id']
            ]);
            
            if ($updateStmt->rowCount() > 0) {
                $closedCount++;
                $closedCVEs[] = $cve['cve_id'];
                
                // Log the closure in activity log
                $logStmt = $db->prepare("
                    INSERT INTO activity_logs (
                        log_id, user_id, action_type, entity_type, entity_id,
                        details, ip_address, created_at
                    ) VALUES (
                        uuid_generate_v4(), :user_id, 'vulnerability_auto_closed', 'device',
                        :device_id, :details, :ip, CURRENT_TIMESTAMP
                    )
                ");
                
                $logStmt->execute([
                    'user_id' => $userId,
                    'device_id' => $deviceId,
                    'details' => json_encode([
                        'cve_id' => $cve['cve_id'],
                        'package' => $packageName,
                        'old_version' => $oldVersion,
                        'new_version' => $newVersion,
                        'method' => $method,
                        'severity' => $cve['severity']
                    ]),
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'system'
                ]);
            }
        }
        
        $db->commit();
        
        return [
            'success' => true,
            'closed_count' => $closedCount,
            'cves' => $closedCVEs,
            'details' => $resolvedCVEs
        ];
        
    } catch (PDOException $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        error_log("Error auto-closing vulnerabilities: " . $e->getMessage());
        return [
            'success' => false,
            'error' => $e->getMessage(),
            'closed_count' => 0,
            'cves' => []
        ];
    }
}

/**
 * Get safe version recommendation for a vulnerable package
 * 
 * @param string $packageId Package UUID
 * @return string|null Recommended safe version or null if not available
 */
function getSafeVersionForPackage($packageId) {
    try {
        $db = DatabaseConfig::getInstance();
        $stmt = $db->prepare("
            SELECT latest_safe_version 
            FROM software_packages 
            WHERE package_id = :package_id
        ");
        
        $stmt->execute(['package_id' => $packageId]);
        $result = $stmt->fetchColumn();
        
        return $result ?: null;
        
    } catch (PDOException $e) {
        error_log("Error getting safe version: " . $e->getMessage());
        return null;
    }
}

/**
 * Test if a version is safe (not vulnerable to any known CVEs)
 * 
 * @param string $packageId Package UUID
 * @param string $version Version to test
 * @return bool True if version is safe
 */
function isVersionSafe($packageId, $version) {
    $vulnerabilities = getVulnerabilitiesForVersion($packageId, $version);
    return empty($vulnerabilities);
}

/**
 * Get version upgrade recommendations
 * 
 * @param string $packageId Package UUID
 * @param string $currentVersion Current version
 * @return array Upgrade recommendations with vulnerability counts
 */
function getVersionUpgradeRecommendations($packageId, $currentVersion) {
    try {
        $db = DatabaseConfig::getInstance();
        // Get package info
        $stmt = $db->prepare("
            SELECT name, vendor, latest_safe_version
            FROM software_packages
            WHERE package_id = :package_id
        ");
        $stmt->execute(['package_id' => $packageId]);
        $package = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$package) {
            return [];
        }
        
        // Get current vulnerabilities
        $currentVulns = getVulnerabilitiesForVersion($packageId, $currentVersion);
        
        $recommendations = [
            'package_name' => $package['name'],
            'current_version' => $currentVersion,
            'current_vulnerability_count' => count($currentVulns),
            'safe_version' => $package['latest_safe_version'],
            'recommendations' => []
        ];
        
        // If safe version is available, calculate what would be resolved
        if ($package['latest_safe_version']) {
            $resolvedCVEs = getVulnerabilitiesResolvedByUpdate(
                $packageId, 
                $currentVersion, 
                $package['latest_safe_version']
            );
            
            $recommendations['recommendations'][] = [
                'target_version' => $package['latest_safe_version'],
                'vulnerabilities_resolved' => count($resolvedCVEs),
                'is_safe' => isVersionSafe($packageId, $package['latest_safe_version']),
                'resolved_cves' => array_column($resolvedCVEs, 'cve_id')
            ];
        }
        
        return $recommendations;
        
    } catch (PDOException $e) {
        error_log("Error getting upgrade recommendations: " . $e->getMessage());
        return [];
    }
}
