<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';

echo "==========================================================\n";
echo "Software Package Population Script\n";
echo "==========================================================\n\n";

$db = DatabaseConfig::getInstance();

try {
    echo "Step 1: Creating unique software packages from components...\n";
    
    // Create unique packages
    $sql = "INSERT INTO software_packages (name, vendor, cpe_product, first_seen, last_seen)
            SELECT DISTINCT 
                name,
                vendor,
                cpe,
                MIN(created_at) as first_seen,
                MAX(created_at) as last_seen
            FROM software_components
            WHERE name IS NOT NULL
            GROUP BY name, vendor, cpe
            ON CONFLICT (name, vendor) DO UPDATE
            SET last_seen = EXCLUDED.last_seen";
    
    $db->query($sql);
    echo "✓ Software packages created\n\n";
    
    echo "Step 2: Creating package versions...\n";
    
    $sql = "INSERT INTO software_package_versions (package_id, version, first_seen, last_seen)
            SELECT DISTINCT 
                sp.package_id,
                sc.version,
                MIN(sc.created_at) as first_seen,
                MAX(sc.created_at) as last_seen
            FROM software_components sc
            JOIN software_packages sp ON sc.name = sp.name 
                AND COALESCE(sc.vendor, '') = COALESCE(sp.vendor, '')
            WHERE sc.version IS NOT NULL
            GROUP BY sp.package_id, sc.version
            ON CONFLICT (package_id, version) DO UPDATE
            SET last_seen = EXCLUDED.last_seen";
    
    $db->query($sql);
    echo "✓ Package versions created\n\n";
    
    echo "Step 3: Linking components to packages...\n";
    
    $sql = "UPDATE software_components sc
            SET package_id = sp.package_id,
                version_id = spv.version_id
            FROM software_packages sp
            JOIN software_package_versions spv ON sp.package_id = spv.package_id
            WHERE sc.name = sp.name
            AND COALESCE(sc.vendor, '') = COALESCE(sp.vendor, '')
            AND sc.version = spv.version";
    
    $result = $db->query($sql);
    $linkedCount = $result->rowCount();
    echo "✓ Linked $linkedCount components to packages\n\n";
    
    echo "Step 4: Creating software package vulnerabilities...\n";
    
    $sql = "INSERT INTO software_package_vulnerabilities (package_id, version_id, cve_id, discovered_at)
            SELECT DISTINCT
                sc.package_id,
                sc.version_id,
                dvl.cve_id,
                MIN(dvl.discovered_at) as discovered_at
            FROM device_vulnerabilities_link dvl
            JOIN software_components sc ON dvl.component_id = sc.component_id
            WHERE sc.package_id IS NOT NULL
            AND sc.version_id IS NOT NULL
            GROUP BY sc.package_id, sc.version_id, dvl.cve_id
            ON CONFLICT (package_id, version_id, cve_id) DO NOTHING";
    
    $result = $db->query($sql);
    $vulnCount = $result->rowCount();
    echo "✓ Created $vulnCount package-vulnerability mappings\n\n";
    
    echo "Step 5: Calculating package version statistics...\n";
    
    $sql = "UPDATE software_package_versions spv
            SET vulnerability_count = (
                    SELECT COUNT(DISTINCT cve_id)
                    FROM software_package_vulnerabilities
                    WHERE version_id = spv.version_id
                ),
                affected_asset_count = (
                    SELECT COUNT(DISTINCT a.asset_id)
                    FROM software_components sc
                    JOIN sboms s ON sc.sbom_id = s.sbom_id
                    JOIN medical_devices md ON s.device_id = md.device_id
                    JOIN assets a ON md.asset_id = a.asset_id
                    WHERE sc.version_id = spv.version_id
                ),
                highest_severity = (
                    SELECT v.severity
                    FROM software_package_vulnerabilities spvuln
                    JOIN vulnerabilities v ON spvuln.cve_id = v.cve_id
                    WHERE spvuln.version_id = spv.version_id
                    ORDER BY 
                        CASE v.severity
                            WHEN 'Critical' THEN 1
                            WHEN 'High' THEN 2
                            WHEN 'Medium' THEN 3
                            WHEN 'Low' THEN 4
                        END
                    LIMIT 1
                ),
                is_vulnerable = (
                    SELECT COUNT(*) > 0
                    FROM software_package_vulnerabilities
                    WHERE version_id = spv.version_id
                )";
    
    $db->query($sql);
    echo "✓ Package version statistics calculated\n\n";
    
    echo "Step 6: Calculating risk scores...\n";
    
    // Calculate risk scores for each package/version
    $sql = "INSERT INTO software_package_risk_scores (
                package_id, version_id, total_vulnerabilities, kev_count,
                critical_severity_count, high_severity_count, medium_severity_count, low_severity_count,
                affected_assets_count, tier1_assets_count, tier2_assets_count, tier3_assets_count,
                highest_risk_score, aggregate_risk_score, oldest_vulnerability_date
            )
            SELECT 
                spv.package_id,
                spv.version_id,
                COUNT(DISTINCT spvuln.cve_id) as total_vulnerabilities,
                COUNT(DISTINCT CASE WHEN v.is_kev THEN spvuln.cve_id END) as kev_count,
                COUNT(DISTINCT CASE WHEN v.severity = 'Critical' THEN spvuln.cve_id END) as critical_severity_count,
                COUNT(DISTINCT CASE WHEN v.severity = 'High' THEN spvuln.cve_id END) as high_severity_count,
                COUNT(DISTINCT CASE WHEN v.severity = 'Medium' THEN spvuln.cve_id END) as medium_severity_count,
                COUNT(DISTINCT CASE WHEN v.severity = 'Low' THEN spvuln.cve_id END) as low_severity_count,
                COUNT(DISTINCT a.asset_id) as affected_assets_count,
                COUNT(DISTINCT CASE 
                    WHEN a.criticality = 'Clinical-High' AND COALESCE(l.criticality, 0) >= 8 
                    THEN a.asset_id 
                END) as tier1_assets_count,
                COUNT(DISTINCT CASE 
                    WHEN a.criticality = 'Clinical-High' AND COALESCE(l.criticality, 0) BETWEEN 5 AND 7
                    THEN a.asset_id 
                END) as tier2_assets_count,
                COUNT(DISTINCT CASE 
                    WHEN NOT (a.criticality = 'Clinical-High' AND COALESCE(l.criticality, 0) >= 5)
                    THEN a.asset_id 
                END) as tier3_assets_count,
                MAX(dvl.risk_score) as highest_risk_score,
                CAST(AVG(dvl.risk_score) AS INTEGER) as aggregate_risk_score,
                MIN(spvuln.discovered_at) as oldest_vulnerability_date
            FROM software_package_versions spv
            JOIN software_package_vulnerabilities spvuln ON spv.version_id = spvuln.version_id
            JOIN vulnerabilities v ON spvuln.cve_id = v.cve_id
            LEFT JOIN software_components sc ON spv.version_id = sc.version_id
            LEFT JOIN sboms s ON sc.sbom_id = s.sbom_id
            LEFT JOIN medical_devices md ON s.device_id = md.device_id
            LEFT JOIN assets a ON md.asset_id = a.asset_id
            LEFT JOIN locations l ON a.location_id = l.location_id
            LEFT JOIN device_vulnerabilities_link dvl ON md.device_id = dvl.device_id 
                AND spvuln.cve_id = dvl.cve_id
            WHERE dvl.remediation_status = 'Open'
            GROUP BY spv.package_id, spv.version_id
            ON CONFLICT (package_id, version_id) DO UPDATE
            SET total_vulnerabilities = EXCLUDED.total_vulnerabilities,
                kev_count = EXCLUDED.kev_count,
                critical_severity_count = EXCLUDED.critical_severity_count,
                high_severity_count = EXCLUDED.high_severity_count,
                medium_severity_count = EXCLUDED.medium_severity_count,
                low_severity_count = EXCLUDED.low_severity_count,
                affected_assets_count = EXCLUDED.affected_assets_count,
                tier1_assets_count = EXCLUDED.tier1_assets_count,
                tier2_assets_count = EXCLUDED.tier2_assets_count,
                tier3_assets_count = EXCLUDED.tier3_assets_count,
                highest_risk_score = EXCLUDED.highest_risk_score,
                aggregate_risk_score = EXCLUDED.aggregate_risk_score,
                oldest_vulnerability_date = EXCLUDED.oldest_vulnerability_date,
                calculated_at = CURRENT_TIMESTAMP";
    
    $result = $db->query($sql);
    $riskCount = $result->rowCount();
    echo "✓ Calculated risk scores for $riskCount package/version combinations\n\n";
    
    echo "Step 7: Refreshing materialized view...\n";
    
    $db->query("REFRESH MATERIALIZED VIEW software_package_risk_priority_view");
    echo "✓ Materialized view refreshed\n\n";
    
    echo "Step 8: Generating statistics...\n";
    
    // Get statistics
    $sql = "SELECT COUNT(*) as count FROM software_packages";
    $packages = $db->query($sql)->fetch()['count'];
    
    $sql = "SELECT COUNT(*) as count FROM software_package_versions WHERE is_vulnerable = TRUE";
    $vulnerableVersions = $db->query($sql)->fetch()['count'];
    
    $sql = "SELECT COUNT(*) as count FROM software_package_risk_scores WHERE tier1_assets_count > 0";
    $tier1Packages = $db->query($sql)->fetch()['count'];
    
    $sql = "SELECT COUNT(*) as count FROM software_package_risk_scores WHERE kev_count > 0";
    $kevPackages = $db->query($sql)->fetch()['count'];
    
    echo "\n==========================================================\n";
    echo "Population Complete!\n";
    echo "==========================================================\n\n";
    echo "Statistics:\n";
    echo "  • Total unique software packages: $packages\n";
    echo "  • Vulnerable versions: $vulnerableVersions\n";
    echo "  • Packages affecting Tier 1 assets: $tier1Packages\n";
    echo "  • Packages with KEV vulnerabilities: $kevPackages\n";
    echo "\n";
    
} catch (Exception $e) {
    echo "\n✗ Error: " . $e->getMessage() . "\n";
    echo "Stack trace:\n";
    echo $e->getTraceAsString() . "\n";
    exit(1);
}

