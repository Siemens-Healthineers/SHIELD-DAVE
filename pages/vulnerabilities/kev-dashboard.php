<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/auth.php';

// Require authentication
$auth->requireAuth();
$auth->requirePermission('vulnerabilities.view');

$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Get KEV statistics
// Only count vulnerabilities where is_kev = TRUE to match main dashboard logic
$kevStatsSql = "SELECT 
    COUNT(DISTINCT k.kev_id) as total_kev_vulnerabilities,
    COUNT(DISTINCT dvl.device_id) as affected_devices,
    COUNT(DISTINCT dvl.link_id) as total_affected_vulns,
    COUNT(DISTINCT k.kev_id) FILTER (WHERE k.known_ransomware_campaign_use = TRUE) as ransomware_kevs,
    COUNT(DISTINCT k.kev_id) FILTER (WHERE k.due_date < CURRENT_DATE AND dvl.remediation_status != 'Resolved') as overdue_kevs,
    MAX(k.last_synced_at) as last_sync_time
FROM cisa_kev_catalog k
LEFT JOIN vulnerabilities v ON k.cve_id = v.cve_id AND v.is_kev = TRUE
LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id 
    AND dvl.remediation_status != 'Resolved'
    AND NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))";
$statsStmt = $db->query($kevStatsSql);
$kevStats = $statsStmt->fetch(PDO::FETCH_ASSOC);

// Get KEV vulnerabilities by severity
$sevStatsSql = "SELECT 
    v.severity,
    COUNT(DISTINCT dvl.link_id) as count
FROM vulnerabilities v
JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
WHERE v.is_kev = TRUE
GROUP BY v.severity
ORDER BY 
    CASE v.severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
    END";
$sevStmt = $db->query($sevStatsSql);
$severityStats = $sevStmt->fetchAll(PDO::FETCH_ASSOC);

// Get recent KEV additions
// Only count devices where is_kev = TRUE to match main dashboard logic
$recentKevSql = "SELECT 
    k.cve_id,
    k.vulnerability_name,
    k.vendor_project,
    k.product,
    k.date_added,
    k.due_date,
    k.known_ransomware_campaign_use,
    COUNT(DISTINCT dvl.device_id) as affected_devices
FROM cisa_kev_catalog k
LEFT JOIN vulnerabilities v ON k.cve_id = v.cve_id AND v.is_kev = TRUE
LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id 
    AND dvl.remediation_status != 'Resolved'
    AND NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))
GROUP BY k.kev_id, k.cve_id, k.vulnerability_name, k.vendor_project, k.product, k.date_added, k.due_date, k.known_ransomware_campaign_use
ORDER BY k.date_added DESC
LIMIT 10";
$recentStmt = $db->query($recentKevSql);
$recentKevs = $recentStmt->fetchAll(PDO::FETCH_ASSOC);

// Get overdue KEV vulnerabilities
// Only count vulnerabilities where is_kev = TRUE to match main dashboard logic
$overdueSql = "SELECT 
    k.cve_id,
    k.vulnerability_name,
    k.vendor_project,
    k.product,
    k.due_date,
    k.required_action,
    k.known_ransomware_campaign_use,
    COUNT(DISTINCT dvl.device_id) as affected_devices,
    (CURRENT_DATE - k.due_date) as days_overdue
FROM cisa_kev_catalog k
JOIN vulnerabilities v ON k.cve_id = v.cve_id AND v.is_kev = TRUE
JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id 
WHERE k.due_date < CURRENT_DATE 
  AND dvl.remediation_status != 'Resolved'
  AND NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))
GROUP BY k.kev_id, k.cve_id, k.vulnerability_name, k.vendor_project, k.product, k.due_date, k.required_action, k.known_ransomware_campaign_use
ORDER BY days_overdue DESC
LIMIT 10";
$overdueStmt = $db->query($overdueSql);
$overdueKevs = $overdueStmt->fetchAll(PDO::FETCH_ASSOC);

// Get affected devices
// Only count vulnerabilities where is_kev = TRUE and exclude patched devices (matching main dashboard logic)
$devicesSql = "SELECT 
    a.hostname,
    md.brand_name,
    md.model_number,
    l.location_name,
    COUNT(DISTINCT dvl.link_id) as kev_count,
    COUNT(DISTINCT dvl.link_id) FILTER (WHERE k.known_ransomware_campaign_use = TRUE) as ransomware_kev_count
FROM device_vulnerabilities_link dvl
JOIN vulnerabilities v ON dvl.cve_id = v.cve_id
JOIN cisa_kev_catalog k ON v.cve_id = k.cve_id
JOIN medical_devices md ON dvl.device_id = md.device_id
JOIN assets a ON md.asset_id = a.asset_id
LEFT JOIN locations l ON a.location_id = l.location_id
WHERE v.is_kev = TRUE
  AND dvl.remediation_status != 'Resolved'
  AND NOT (v.patched_devices IS NOT NULL AND v.patched_devices @> jsonb_build_array(dvl.device_id::text))
  AND a.status = 'Active'
GROUP BY a.hostname, md.brand_name, md.model_number, l.location_name
ORDER BY kev_count DESC
LIMIT 10";
$devicesStmt = $db->query($devicesSql);
$affectedDevices = $devicesStmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CISA KEV Dashboard - </title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/vulnerabilities.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Siemens Sans', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }

        .kev-container {
            max-width: 1400px;
            margin: 2rem auto;
            padding: 0 2rem;
        }

        .kev-header {
            margin-bottom: 2rem;
        }

        .kev-title {
            font-size: 2rem;
            color: var(--text-primary);
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .kev-title .kev-badge {
            background: var(--error-red);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }

        .kev-subtitle {
            color: var(--text-secondary);
            margin-top: 0.5rem;
            font-size: 1rem;
        }

        .kev-alert {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 0.75rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
        }

        .kev-alert h3 {
            margin: 0 0 0.5rem 0;
            font-size: 1.25rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            padding: 1.5rem;
        }

        .stat-card.critical {
            border-color: var(--error-red);
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, var(--bg-card) 100%);
        }

        .stat-card .stat-icon {
            font-size: 2rem;
            margin-bottom: 0.5rem;
            color: var(--error-red);
        }

        .stat-card .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--error-red);
            margin: 0.5rem 0;
        }

        .stat-card .stat-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
        }

        .section-card {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }

        .section-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .kev-table {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
        }

        .kev-table th {
            background: var(--bg-secondary);
            color: var(--text-secondary);
            padding: 0.75rem 0.5rem;
            text-align: left;
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            border-bottom: 2px solid var(--border-primary);
            white-space: nowrap;
        }

        .kev-table td {
            padding: 0.75rem 0.5rem;
            border-bottom: 1px solid var(--border-primary);
            color: var(--text-primary);
            vertical-align: top;
            word-wrap: break-word;
        }

        .kev-table tr:hover {
            background: var(--bg-hover);
        }

        /* Column widths for overdue table (7 columns) */
        .kev-table.overdue-table th:nth-child(1),
        .kev-table.overdue-table td:nth-child(1) { width: 130px; }
        
        .kev-table.overdue-table th:nth-child(2),
        .kev-table.overdue-table td:nth-child(2) { width: 22%; }
        
        .kev-table.overdue-table th:nth-child(3),
        .kev-table.overdue-table td:nth-child(3) { width: 20%; }
        
        .kev-table.overdue-table th:nth-child(4),
        .kev-table.overdue-table td:nth-child(4) { width: 120px; text-align: center; }
        
        .kev-table.overdue-table th:nth-child(5),
        .kev-table.overdue-table td:nth-child(5) { width: 110px; text-align: center; }
        
        .kev-table.overdue-table th:nth-child(6),
        .kev-table.overdue-table td:nth-child(6) { width: 90px; text-align: center; }
        
        .kev-table.overdue-table th:nth-child(7),
        .kev-table.overdue-table td:nth-child(7) { width: 100px; text-align: center; }

        /* Column widths for recent KEV table (7 columns) */
        .kev-table.recent-table th:nth-child(1),
        .kev-table.recent-table td:nth-child(1) { width: 130px; }
        
        .kev-table.recent-table th:nth-child(2),
        .kev-table.recent-table td:nth-child(2) { width: 24%; }
        
        .kev-table.recent-table th:nth-child(3),
        .kev-table.recent-table td:nth-child(3) { width: 20%; }
        
        .kev-table.recent-table th:nth-child(4),
        .kev-table.recent-table td:nth-child(4) { width: 120px; text-align: center; }
        
        .kev-table.recent-table th:nth-child(5),
        .kev-table.recent-table td:nth-child(5) { width: 120px; text-align: center; }
        
        .kev-table.recent-table th:nth-child(6),
        .kev-table.recent-table td:nth-child(6) { width: 90px; text-align: center; }
        
        .kev-table.recent-table th:nth-child(7),
        .kev-table.recent-table td:nth-child(7) { width: 140px; text-align: center; }

        /* Column widths for devices table (5 columns) */
        .kev-table.devices-table th:nth-child(1),
        .kev-table.devices-table td:nth-child(1) { width: 25%; }
        
        .kev-table.devices-table th:nth-child(2),
        .kev-table.devices-table td:nth-child(2) { width: 25%; }
        
        .kev-table.devices-table th:nth-child(3),
        .kev-table.devices-table td:nth-child(3) { width: 20%; }
        
        .kev-table.devices-table th:nth-child(4),
        .kev-table.devices-table td:nth-child(4) { width: 150px; text-align: center; }
        
        .kev-table.devices-table th:nth-child(5),
        .kev-table.devices-table td:nth-child(5) { width: 150px; text-align: center; }

        .cve-badge {
            background: var(--error-red);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-family: monospace;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .ransomware-badge {
            background: #7c2d12;
            color: #fca5a5;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
        }

        .overdue-badge {
            background: #991b1b;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .sync-info {
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .sync-btn {
            background: var(--siemens-petrol);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }

        .sync-btn:hover {
            background: var(--siemens-petrol-dark);
            transform: translateY(-1px);
        }

        .device-info {
            display: flex;
            flex-direction: column;
        }

        .device-name {
            font-weight: 600;
            color: var(--text-primary);
        }

        .device-model {
            font-size: 0.85rem;
            color: var(--text-secondary);
        }

        .btn-view-kev {
            background: var(--siemens-petrol);
            color: white;
            border: none;
            padding: 0.4rem 0.8rem;
            border-radius: 0.375rem;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
        }

        .btn-view-kev:hover {
            background: var(--siemens-petrol-dark);
            transform: translateY(-1px);
        }

        .kev-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 9999;
            padding: 2rem;
            overflow-y: auto;
        }

        .kev-modal-content {
            background: var(--bg-secondary);
            max-width: 900px;
            margin: 0 auto;
            border-radius: 0.75rem;
            padding: 0;
            position: relative;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }

        .kev-modal-header {
            background: var(--bg-tertiary);
            padding: 1.5rem;
            border-bottom: 2px solid var(--border-primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .kev-modal-header h2 {
            margin: 0;
            color: var(--text-primary);
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .kev-modal-close {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0.5rem;
            transition: all 0.2s;
        }

        .kev-modal-close:hover {
            color: var(--text-primary);
            transform: rotate(90deg);
        }

        .kev-modal-body {
            padding: 2rem;
        }

        .kev-detail-section {
            margin-bottom: 2rem;
        }

        .kev-detail-section h3 {
            color: var(--siemens-petrol);
            font-size: 1.1rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .kev-detail-grid {
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 1rem;
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 0.5rem;
        }

        .kev-detail-label {
            font-weight: 600;
            color: var(--text-secondary);
        }

        .kev-detail-value {
            color: var(--text-primary);
        }
    </style>
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

    <div class="kev-container">
        <div class="kev-header">
            <h1 class="kev-title">
                <i class="fas fa-shield-virus"></i>
                CISA Known Exploited Vulnerabilities
                <span class="kev-badge">Actively Exploited</span>
            </h1>
            <p class="kev-subtitle">
                Vulnerabilities known to be actively exploited in the wild - IMMEDIATE ACTION REQUIRED
            </p>
        </div>

        <?php if ($kevStats['overdue_kevs'] > 0): ?>
        <div class="kev-alert">
            <h3><i class="fas fa-exclamation-triangle"></i> URGENT: Overdue KEV Remediation</h3>
            <p>
                You have <strong><?php echo $kevStats['overdue_kevs']; ?> overdue</strong> CISA KEV vulnerabilities 
                past their remediation due date. These represent critical security risks that require immediate attention.
            </p>
        </div>
        <?php endif; ?>

        <!-- Sync Info -->
        <div class="sync-info">
            <div>
                <i class="fas fa-sync-alt"></i>
                Last KEV Catalog Sync: 
                <strong>
                    <?php 
                    if ($kevStats['last_sync_time']) {
                        echo date('M j, Y H:i', strtotime($kevStats['last_sync_time']));
                    } else {
                        echo 'Never';
                    }
                    ?>
                </strong>
            </div>
            <button class="sync-btn" onclick="syncKEV()">
                <i class="fas fa-sync-alt"></i> Sync Now
            </button>
        </div>

        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-icon"><i class="fas fa-shield-virus"></i></div>
                <div class="stat-value"><?php echo $kevStats['total_kev_vulnerabilities'] ?? 0; ?></div>
                <div class="stat-label">Total KEV Entries</div>
            </div>
            
            <div class="stat-card critical">
                <div class="stat-icon"><i class="fas fa-server"></i></div>
                <div class="stat-value"><?php echo $kevStats['affected_devices'] ?? 0; ?></div>
                <div class="stat-label">Affected Devices</div>
            </div>
            
            <div class="stat-card critical">
                <div class="stat-icon"><i class="fas fa-bug"></i></div>
                <div class="stat-value"><?php echo $kevStats['total_affected_vulns'] ?? 0; ?></div>
                <div class="stat-label">Affected Vulnerabilities</div>
            </div>
            
            <div class="stat-card critical">
                <div class="stat-icon"><i class="fas fa-skull-crossbones"></i></div>
                <div class="stat-value"><?php echo $kevStats['ransomware_kevs'] ?? 0; ?></div>
                <div class="stat-label">Ransomware KEVs</div>
            </div>

            <div class="stat-card critical">
                <div class="stat-icon"><i class="fas fa-clock"></i></div>
                <div class="stat-value"><?php echo $kevStats['overdue_kevs'] ?? 0; ?></div>
                <div class="stat-label">Overdue</div>
            </div>
        </div>

        <!-- Overdue KEVs -->
        <?php if (!empty($overdueKevs)): ?>
        <div class="section-card">
            <h2 class="section-title">
                <i class="fas fa-exclamation-circle"></i> Overdue KEV Remediation
            </h2>
            
            <div style="overflow-x: auto;">
                <table class="kev-table overdue-table">
                    <thead>
                        <tr>
                            <th>CVE</th>
                            <th>Vulnerability</th>
                            <th>Vendor/Product</th>
                            <th>Due Date</th>
                            <th>Days Overdue</th>
                            <th>Affected</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($overdueKevs as $kev): ?>
                            <tr>
                                <td><span class="cve-badge"><?php echo dave_htmlspecialchars($kev['cve_id']); ?></span></td>
                                <td><?php echo dave_htmlspecialchars($kev['vulnerability_name']); ?></td>
                                <td>
                                    <div style="font-weight: 600;"><?php echo dave_htmlspecialchars($kev['vendor_project']); ?></div>
                                    <div style="font-size: 0.85rem; color: var(--text-secondary);"><?php echo dave_htmlspecialchars($kev['product']); ?></div>
                                </td>
                                <td>
                                    <span class="overdue-badge">
                                        <?php echo date('M j, Y', strtotime($kev['due_date'])); ?>
                                    </span>
                                </td>
                                <td>
                                    <strong style="color: var(--error-red);"><?php echo $kev['days_overdue']; ?> days</strong>
                                </td>
                                <td><?php echo $kev['affected_devices']; ?></td>
                                <td>
                                    <button class="btn-view-kev" onclick='viewKevDetails(<?php echo json_encode($kev); ?>)'>
                                        <i class="fas fa-eye"></i> View
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php endif; ?>

        <!-- Recent KEV Additions -->
        <div class="section-card">
            <h2 class="section-title">
                <i class="fas fa-plus-circle"></i> Recently Added to KEV Catalog
            </h2>
            
            <?php if (empty($recentKevs)): ?>
                <p style="text-align: center; color: var(--text-secondary); padding: 2rem;">
                    No KEV entries found. Run KEV catalog sync to populate data.
                </p>
            <?php else: ?>
                <div style="overflow-x: auto;">
                    <table class="kev-table recent-table">
                        <thead>
                            <tr>
                                <th>CVE</th>
                                <th>Vulnerability</th>
                                <th>Vendor/Product</th>
                                <th>Date Added</th>
                                <th>Due Date</th>
                                <th>Affected</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($recentKevs as $kev): ?>
                                <tr>
                                    <td><span class="cve-badge"><?php echo dave_htmlspecialchars($kev['cve_id']); ?></span></td>
                                    <td><?php echo dave_htmlspecialchars($kev['vulnerability_name']); ?></td>
                                    <td>
                                        <div style="font-weight: 600;"><?php echo dave_htmlspecialchars($kev['vendor_project']); ?></div>
                                        <div style="font-size: 0.85rem; color: var(--text-secondary);"><?php echo dave_htmlspecialchars($kev['product']); ?></div>
                                    </td>
                                    <td><?php echo date('M j, Y', strtotime($kev['date_added'])); ?></td>
                                    <td><?php echo date('M j, Y', strtotime($kev['due_date'])); ?></td>
                                    <td>
                                        <?php if ($kev['affected_devices'] > 0): ?>
                                            <strong style="color: var(--error-red);"><?php echo $kev['affected_devices']; ?></strong>
                                        <?php else: ?>
                                            0
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <button class="btn-view-kev" onclick='viewKevDetails(<?php echo json_encode($kev); ?>)'>
                                            <i class="fas fa-eye"></i> View
                                        </button>
                                        <?php if ($kev['known_ransomware_campaign_use']): ?>
                                            <span class="ransomware-badge" style="margin-left: 0.5rem;">
                                                <i class="fas fa-skull-crossbones"></i>
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>

        <!-- Affected Devices -->
        <?php if (!empty($affectedDevices)): ?>
        <div class="section-card">
            <h2 class="section-title">
                <i class="fas fa-server"></i> Most Affected Devices
            </h2>
            
            <div style="overflow-x: auto;">
                <table class="kev-table devices-table">
                    <thead>
                        <tr>
                            <th>Hostname</th>
                            <th>Device Model</th>
                            <th>Location</th>
                            <th>KEV Count</th>
                            <th>Ransomware KEVs</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($affectedDevices as $device): ?>
                            <tr>
                                <td>
                                    <span class="device-name"><?php echo dave_htmlspecialchars($device['hostname'] ?: 'N/A'); ?></span>
                                </td>
                                <td>
                                    <span class="device-model"><?php echo dave_htmlspecialchars($device['brand_name'] . ' ' . $device['model_number']); ?></span>
                                </td>
                                <td>
                                    <span style="color: var(--text-secondary);"><?php echo dave_htmlspecialchars($device['location_name'] ?? 'Not Mapped'); ?></span>
                                </td>
                                <td>
                                    <strong style="color: var(--error-red); font-size: 1.1rem;"><?php echo $device['kev_count']; ?></strong>
                                </td>
                                <td>
                                    <?php if ($device['ransomware_kev_count'] > 0): ?>
                                        <span class="ransomware-badge">
                                            <i class="fas fa-skull-crossbones"></i> <?php echo $device['ransomware_kev_count']; ?>
                                        </span>
                                    <?php else: ?>
                                        <span style="color: var(--text-secondary);">0</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <!-- KEV Details Modal -->
    <div id="kevModal" class="kev-modal">
        <div class="kev-modal-content">
            <div class="kev-modal-header">
                <h2><i class="fas fa-shield-virus"></i> <span id="modalCveId"></span></h2>
                <button class="kev-modal-close" onclick="closeKevModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="kev-modal-body" id="kevModalBody">
                <!-- Content populated by JavaScript -->
            </div>
        </div>
    </div>

    <script>
        function viewKevDetails(kev) {
            document.getElementById('modalCveId').textContent = kev.cve_id;
            
            const daysOverdue = kev.days_overdue || 0;
            const isOverdue = daysOverdue > 0;
            
            const modalBody = document.getElementById('kevModalBody');
            modalBody.innerHTML = `
                <div class="kev-detail-section">
                    <h3><i class="fas fa-info-circle"></i> Vulnerability Information</h3>
                    <div class="kev-detail-grid">
                        <div class="kev-detail-label">CVE ID:</div>
                        <div class="kev-detail-value"><span class="cve-badge">${kev.cve_id}</span></div>
                        
                        <div class="kev-detail-label">Vulnerability Name:</div>
                        <div class="kev-detail-value">${kev.vulnerability_name || 'N/A'}</div>
                        
                        <div class="kev-detail-label">Vendor/Project:</div>
                        <div class="kev-detail-value">${kev.vendor_project || 'N/A'}</div>
                        
                        <div class="kev-detail-label">Product:</div>
                        <div class="kev-detail-value">${kev.product || 'N/A'}</div>
                        
                        <div class="kev-detail-label">Description:</div>
                        <div class="kev-detail-value">${kev.short_description || kev.description || 'No description available'}</div>
                    </div>
                </div>

                <div class="kev-detail-section">
                    <h3><i class="fas fa-clock"></i> Timeline & Deadlines</h3>
                    <div class="kev-detail-grid">
                        <div class="kev-detail-label">Date Added to KEV:</div>
                        <div class="kev-detail-value">${kev.date_added ? new Date(kev.date_added).toLocaleDateString('en-US', {year: 'numeric', month: 'long', day: 'numeric'}) : 'N/A'}</div>
                        
                        <div class="kev-detail-label">Remediation Due Date:</div>
                        <div class="kev-detail-value">
                            <span class="${isOverdue ? 'overdue-badge' : ''}" style="padding: 0.25rem 0.5rem;">
                                ${kev.due_date ? new Date(kev.due_date).toLocaleDateString('en-US', {year: 'numeric', month: 'long', day: 'numeric'}) : 'N/A'}
                            </span>
                        </div>
                        
                        ${isOverdue ? `
                        <div class="kev-detail-label">Days Overdue:</div>
                        <div class="kev-detail-value">
                            <strong style="color: var(--error-red); font-size: 1.2rem;">${daysOverdue} days</strong>
                        </div>
                        ` : ''}
                    </div>
                </div>

                <div class="kev-detail-section">
                    <h3><i class="fas fa-exclamation-triangle"></i> Threat Assessment</h3>
                    <div class="kev-detail-grid">
                        <div class="kev-detail-label">Exploitation Status:</div>
                        <div class="kev-detail-value">
                            <strong style="color: var(--siemens-orange);">Actively Exploited in the Wild</strong>
                        </div>
                        
                        <div class="kev-detail-label">Ransomware Campaign:</div>
                        <div class="kev-detail-value">
                            ${kev.known_ransomware_campaign_use ? 
                                '<span class="ransomware-badge"><i class="fas fa-skull-crossbones"></i> YES - Known Ransomware Use</span>' : 
                                '<span style="color: var(--text-secondary);">No known ransomware campaigns</span>'
                            }
                        </div>
                        
                        <div class="kev-detail-label">Affected Devices:</div>
                        <div class="kev-detail-value">
                            ${kev.affected_devices > 0 ? 
                                `<strong style="color: var(--error-red); font-size: 1.2rem;">${kev.affected_devices} devices</strong>` : 
                                '<span style="color: var(--text-secondary);">No devices currently affected</span>'
                            }
                        </div>
                    </div>
                </div>

                <div class="kev-detail-section">
                    <h3><i class="fas fa-tasks"></i> Required Action</h3>
                    <div style="background: var(--bg-primary); padding: 1rem; border-radius: 0.5rem; border-left: 4px solid var(--siemens-orange);">
                        <p style="color: var(--text-primary); line-height: 1.6; margin: 0;">
                            ${kev.required_action || 'Apply security updates per vendor instructions.'}
                        </p>
                    </div>
                </div>

                ${kev.notes ? `
                <div class="kev-detail-section">
                    <h3><i class="fas fa-sticky-note"></i> Additional Notes</h3>
                    <div style="background: var(--bg-primary); padding: 1rem; border-radius: 0.5rem;">
                        <p style="color: var(--text-primary); line-height: 1.6; margin: 0;">
                            ${kev.notes}
                        </p>
                    </div>
                </div>
                ` : ''}

                <div class="kev-detail-section">
                    <h3><i class="fas fa-external-link-alt"></i> External Resources</h3>
                    <div style="display: flex; gap: 1rem;">
                        <a href="https://nvd.nist.gov/vuln/detail/${kev.cve_id}" target="_blank" 
                           style="color: var(--siemens-petrol); text-decoration: none; padding: 0.5rem 1rem; background: var(--bg-primary); border-radius: 0.375rem; display: inline-flex; align-items: center; gap: 0.5rem;">
                            <i class="fas fa-link"></i> View in NVD
                        </a>
                        <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" 
                           style="color: var(--siemens-petrol); text-decoration: none; padding: 0.5rem 1rem; background: var(--bg-primary); border-radius: 0.375rem; display: inline-flex; align-items: center; gap: 0.5rem;">
                            <i class="fas fa-link"></i> CISA KEV Catalog
                        </a>
                    </div>
                </div>
            `;
            
            document.getElementById('kevModal').style.display = 'block';
        }

        function closeKevModal() {
            document.getElementById('kevModal').style.display = 'none';
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('kevModal');
            if (event.target === modal) {
                closeKevModal();
            }
        }

        function syncKEV() {
            if (!confirm('Sync CISA KEV catalog? This will download the latest catalog and update the database.')) {
                return;
            }
            
            // Show loading
            const syncBtn = document.querySelector('.sync-btn');
            const originalText = syncBtn.innerHTML;
            syncBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Syncing...';
            syncBtn.disabled = true;
            
            // Trigger sync
            fetch('/api/v1/kev/sync.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => {
                // Check if response is JSON
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    throw new Error('Server returned non-JSON response. Status: ' + response.status);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    alert('KEV sync started successfully! KEV matching will run automatically via cron.');
                    location.reload();
                } else {
                    alert('KEV sync failed: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Sync error:', error);
                alert('KEV sync request failed: ' + error.message + '. Please check your permissions and try again.');
            })
            .finally(() => {
                // Restore button
                syncBtn.innerHTML = originalText;
                syncBtn.disabled = false;
            });
        }
    </script>
</body>
</html>

