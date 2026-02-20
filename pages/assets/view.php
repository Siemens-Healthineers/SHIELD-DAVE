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

// Authentication required
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Get asset ID from URL
$assetId = $_GET['id'] ?? '';

if (empty($assetId)) {
    header('Location: /pages/assets/manage.php');
    exit;
}

// Get asset details
try {
    $sql = "SELECT 
        a.*,
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
        l.location_name as assigned_location_name,
        l.location_code as assigned_location_code,
        l.criticality as location_criticality,
        lh.hierarchy_path as location_hierarchy_path
    FROM assets a
    LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
    LEFT JOIN locations l ON a.location_id = l.location_id
    LEFT JOIN location_hierarchy lh ON l.location_id = lh.location_id
    WHERE a.asset_id = ?";
    
    $stmt = $db->query($sql, [$assetId]);
    $asset = $stmt->fetch();
    
    if (!$asset) {
        header('Location: /pages/assets/manage.php?error=Asset not found');
        exit;
    }
    
} catch (Exception $e) {
    error_log("Error fetching asset: " . $e->getMessage());
    header('Location: /pages/assets/manage.php?error=Database error');
    exit;
}

// Get related vulnerability scans
$vulnerabilityScans = [];
try {
    $sql = "SELECT * FROM vulnerability_scans WHERE asset_id = ? ORDER BY scan_date DESC LIMIT 5";
    $stmt = $db->query($sql, [$assetId]);
    $vulnerabilityScans = $stmt->fetchAll();
} catch (Exception $e) {
    error_log("Error fetching vulnerability scans: " . $e->getMessage());
}

// Get patch applications for this asset
$patchApplications = [];
try {
    $sql = "SELECT 
        pa.*,
        p.patch_name,
        p.patch_type,
        p.target_version,
        p.cve_list,
        u.username as applied_by_name
    FROM patch_applications pa
    JOIN patches p ON pa.patch_id = p.patch_id
    LEFT JOIN users u ON pa.applied_by = u.user_id
    WHERE pa.asset_id = ?
    ORDER BY pa.applied_at DESC";
    $stmt = $db->query($sql, [$assetId]);
    $patchApplications = $stmt->fetchAll();
} catch (Exception $e) {
    error_log("Error fetching patch applications: " . $e->getMessage());
}

// Get related SBOMs
$sboms = [];
try {
    $sql = "SELECT s.*, md.device_id 
            FROM sboms s
            JOIN medical_devices md ON s.device_id = md.device_id
            WHERE md.asset_id = ?
            ORDER BY s.uploaded_at DESC LIMIT 5";
    $stmt = $db->query($sql, [$assetId]);
    $sboms = $stmt->fetchAll();
} catch (Exception $e) {
    error_log("Error fetching SBOMs: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Asset Details - <?php echo dave_htmlspecialchars($asset['hostname'] ?: $asset['ip_address']); ?> - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-server"></i> Asset Details</h1>
                    <p><?php echo dave_htmlspecialchars($asset['hostname'] ?: $asset['ip_address']); ?></p>
                </div>
                <div class="page-actions">
                    <a href="/pages/assets/manage.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Back to Assets
                    </a>
                    <?php if ($auth->hasPermission('assets.edit')): ?>
                    <a href="/pages/assets/edit.php?id=<?php echo dave_htmlspecialchars($asset['asset_id']); ?>" class="btn btn-primary">
                        <i class="fas fa-edit"></i>
                        Edit Asset
                    </a>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Asset Information -->
            <div class="asset-details-container">
                <!-- Basic Information -->
                <div class="detail-section">
                    <div class="section-header">
                        <h2><i class="fas fa-info-circle"></i> Basic Information</h2>
                    </div>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <label>Hostname</label>
                            <span><?php echo dave_htmlspecialchars($asset['hostname'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>IP Address</label>
                            <span><?php echo dave_htmlspecialchars($asset['ip_address'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>MAC Address</label>
                            <span><?php echo dave_htmlspecialchars($asset['mac_address'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Asset Type</label>
                            <span class="asset-type-badge"><?php echo dave_htmlspecialchars($asset['asset_type'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Status</label>
                            <span class="status-badge status-<?php echo strtolower($asset['status']); ?>">
                                <?php echo dave_htmlspecialchars($asset['status']); ?>
                            </span>
                        </div>
                        <div class="detail-item">
                            <label>Source</label>
                            <span class="source-badge"><?php echo dave_htmlspecialchars($asset['source']); ?></span>
                        </div>
                    </div>
                </div>

                <!-- Hardware Information -->
                <div class="detail-section">
                    <div class="section-header">
                        <h2><i class="fas fa-microchip"></i> Hardware Information</h2>
                    </div>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <label>Manufacturer</label>
                            <span><?php echo dave_htmlspecialchars($asset['manufacturer'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Model</label>
                            <span><?php echo dave_htmlspecialchars($asset['model'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Serial Number</label>
                            <span><?php echo dave_htmlspecialchars($asset['serial_number'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>CPU</label>
                            <span><?php echo dave_htmlspecialchars($asset['cpu'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Memory</label>
                            <span><?php echo dave_htmlspecialchars($asset['memory_ram'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Storage</label>
                            <span><?php echo dave_htmlspecialchars($asset['storage'] ?: 'N/A'); ?></span>
                        </div>
                    </div>
                </div>

                <!-- Location & Organization -->
                <div class="detail-section">
                    <div class="section-header">
                        <h2><i class="fas fa-map-marker-alt"></i> Location & Organization</h2>
                    </div>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <label>Location</label>
                            <span><?php echo dave_htmlspecialchars($asset['assigned_location_name'] ?: $asset['location'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Department</label>
                            <span><?php echo dave_htmlspecialchars($asset['assigned_location_name'] ?: $asset['department'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Business Unit</label>
                            <span><?php echo dave_htmlspecialchars($asset['business_unit'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Assigned Admin</label>
                            <span><?php echo dave_htmlspecialchars($asset['assigned_admin_user'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Criticality</label>
                            <span class="criticality-badge criticality-<?php echo $asset['location_criticality'] ?: strtolower(str_replace('-', '_', $asset['criticality'])); ?>">
                                <?php echo dave_htmlspecialchars($asset['location_criticality'] ?: $asset['criticality'] ?: 'N/A'); ?>
                            </span>
                        </div>
                        <div class="detail-item">
                            <label>Location Path</label>
                            <span><?php echo dave_htmlspecialchars($asset['location_hierarchy_path'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Assignment Method</label>
                            <span><?php echo dave_htmlspecialchars($asset['location_assignment_method'] ?: 'Manual'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Cost Center</label>
                            <span><?php echo dave_htmlspecialchars($asset['cost_center'] ?: 'N/A'); ?></span>
                        </div>
                    </div>
                </div>

                <!-- Medical Device Information (if mapped) -->
                <?php if ($asset['device_id']): ?>
                <div class="detail-section">
                    <div class="section-header">
                        <h2><i class="fas fa-heartbeat"></i> Medical Device Information</h2>
                        <span class="mapping-confidence">
                            Mapping Confidence: <?php echo number_format($asset['mapping_confidence'] * 100, 1); ?>%
                        </span>
                    </div>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <label>Device Identifier</label>
                            <span><?php echo dave_htmlspecialchars($asset['device_identifier'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Brand Name</label>
                            <span><?php echo dave_htmlspecialchars($asset['brand_name'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Model Number</label>
                            <span><?php echo dave_htmlspecialchars($asset['model_number'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Manufacturer</label>
                            <span><?php echo dave_htmlspecialchars($asset['manufacturer_name'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>GMDN Term</label>
                            <span><?php echo dave_htmlspecialchars($asset['gmdn_term'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>FDA Class</label>
                            <span><?php echo dave_htmlspecialchars($asset['fda_class'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>UDI</label>
                            <span><?php echo dave_htmlspecialchars($asset['udi'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Implantable</label>
                            <span><?php echo $asset['is_implantable'] ? 'Yes' : 'No'; ?></span>
                        </div>
                    </div>
                    <?php if ($asset['device_description']): ?>
                    <div class="detail-item full-width">
                        <label>Device Description</label>
                        <p><?php echo dave_htmlspecialchars($asset['device_description']); ?></p>
                    </div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>

                <!-- Security Information -->
                <div class="detail-section">
                    <div class="section-header">
                        <h2><i class="fas fa-shield-alt"></i> Security Information</h2>
                    </div>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <label>Firmware Version</label>
                            <span><?php echo dave_htmlspecialchars($asset['firmware_version'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Authentication Method</label>
                            <span><?php echo dave_htmlspecialchars($asset['authentication_method'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Data Encryption (Transit)</label>
                            <span><?php echo dave_htmlspecialchars($asset['data_encryption_transit'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>Data Encryption (Rest)</label>
                            <span><?php echo dave_htmlspecialchars($asset['data_encryption_rest'] ?: 'N/A'); ?></span>
                        </div>
                        <div class="detail-item">
                            <label>PHI Status</label>
                            <span class="phi-status <?php echo $asset['phi_status'] === 'true' ? 'phi-yes' : 'phi-no'; ?>">
                                <?php echo $asset['phi_status'] === 'true' ? 'Contains PHI' : 'No PHI'; ?>
                            </span>
                        </div>
                        <div class="detail-item">
                            <label>Last Patch Update</label>
                            <span><?php echo $asset['patch_level_last_update'] ? date('M j, Y', strtotime($asset['patch_level_last_update'])) : 'N/A'; ?></span>
                        </div>
                    </div>
                </div>

                <!-- Timeline -->
                <div class="detail-section">
                    <div class="section-header">
                        <h2><i class="fas fa-clock"></i> Timeline & Patch History</h2>
                    </div>
                    <div class="timeline">
                        <?php if (!empty($patchApplications)): ?>
                            <?php foreach ($patchApplications as $patch): 
                                $cveCount = $patch['cve_list'] ? count(json_decode($patch['cve_list'], true)) : 0;
                                $statusClass = '';
                                $statusIcon = '';
                                switch ($patch['verification_status']) {
                                    case 'Verified':
                                        $statusClass = 'patch-verified';
                                        $statusIcon = 'fa-check-circle';
                                        break;
                                    case 'Failed':
                                        $statusClass = 'patch-failed';
                                        $statusIcon = 'fa-times-circle';
                                        break;
                                    default:
                                        $statusClass = 'patch-pending';
                                        $statusIcon = 'fa-clock';
                                }
                            ?>
                        <div class="timeline-item">
                            <div class="timeline-marker <?php echo $statusClass; ?>"><i class="fas <?php echo $statusIcon; ?>"></i></div>
                            <div class="timeline-content">
                                <h4><i class="fas fa-band-aid"></i> Patch Applied: <?php echo dave_htmlspecialchars($patch['patch_name']); ?></h4>
                                <p style="margin-bottom: 0.5rem;">
                                    <strong>Type:</strong> <?php echo dave_htmlspecialchars($patch['patch_type']); ?>
                                    <?php if ($patch['target_version']): ?>
                                        | <strong>Version:</strong> <?php echo dave_htmlspecialchars($patch['target_version']); ?>
                                    <?php endif; ?>
                                    <br>
                                    <strong>Status:</strong> <span class="badge badge-<?php echo strtolower($patch['verification_status']); ?>"><?php echo $patch['verification_status']; ?></span>
                                    <?php if ($cveCount > 0): ?>
                                        | <strong>CVEs Resolved:</strong> <?php echo $cveCount; ?>
                                    <?php endif; ?>
                                </p>
                                <p style="font-size: 0.875rem; color: var(--text-muted);">
                                    Applied by <?php echo dave_htmlspecialchars($patch['applied_by_name'] ?? 'System'); ?> on 
                                    <?php echo date('M j, Y g:i A', strtotime($patch['applied_at'])); ?>
                                </p>
                                <?php if ($patch['notes']): ?>
                                <p style="font-size: 0.875rem; margin-top: 0.5rem; padding: 0.5rem; background: var(--bg-secondary); border-radius: 0.375rem;">
                                    <i class="fas fa-sticky-note"></i> <?php echo dave_htmlspecialchars($patch['notes']); ?>
                                </p>
                                <?php endif; ?>
                            </div>
                        </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                        
                        <div class="timeline-item">
                            <div class="timeline-marker"></div>
                            <div class="timeline-content">
                                <h4>Asset Created</h4>
                                <p><?php echo date('M j, Y g:i A', strtotime($asset['created_at'])); ?></p>
                            </div>
                        </div>
                        <div class="timeline-item">
                            <div class="timeline-marker"></div>
                            <div class="timeline-content">
                                <h4>First Seen</h4>
                                <p><?php echo date('M j, Y g:i A', strtotime($asset['first_seen'])); ?></p>
                            </div>
                        </div>
                        <div class="timeline-item">
                            <div class="timeline-marker"></div>
                            <div class="timeline-content">
                                <h4>Last Seen</h4>
                                <p><?php echo date('M j, Y g:i A', strtotime($asset['last_seen'])); ?></p>
                            </div>
                        </div>
                        <?php if ($asset['mapped_at']): ?>
                        <div class="timeline-item">
                            <div class="timeline-marker mapped"></div>
                            <div class="timeline-content">
                                <h4>Device Mapped</h4>
                                <p><?php echo date('M j, Y g:i A', strtotime($asset['mapped_at'])); ?></p>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Related Data -->
                <?php if (!empty($vulnerabilityScans)): ?>
                <div class="detail-section">
                    <div class="section-header">
                        <h2><i class="fas fa-bug"></i> Recent Vulnerability Scans</h2>
                    </div>
                    <div class="related-data">
                        <?php foreach ($vulnerabilityScans as $scan): ?>
                        <div class="related-item">
                            <div class="related-item-header">
                                <h4>Scan #<?php echo dave_htmlspecialchars($scan['scan_id']); ?></h4>
                                <span class="scan-status status-<?php echo strtolower($scan['status']); ?>">
                                    <?php echo dave_htmlspecialchars($scan['status']); ?>
                                </span>
                            </div>
                            <p>Date: <?php echo date('M j, Y g:i A', strtotime($scan['scan_date'])); ?></p>
                            <p>Vulnerabilities Found: <?php echo $scan['vulnerabilities_found'] ?? 'N/A'; ?></p>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>

                <?php if (!empty($sboms)): ?>
                <div class="detail-section">
                    <div class="section-header">
                        <h2><i class="fas fa-list"></i> Recent SBOMs</h2>
                    </div>
                    <div class="related-data">
                        <?php foreach ($sboms as $sbom): ?>
                        <div class="related-item">
                            <div class="related-item-header">
                                <h4><?php echo dave_htmlspecialchars($sbom['file_name']); ?></h4>
                                <span class="sbom-status status-<?php echo strtolower($sbom['parsing_status']); ?>">
                                    <?php echo dave_htmlspecialchars($sbom['parsing_status']); ?>
                                </span>
                            </div>
                            <p>Format: <?php echo dave_htmlspecialchars($sbom['format']); ?></p>
                            <p>Uploaded: <?php echo date('M j, Y g:i A', strtotime($sbom['uploaded_at'])); ?></p>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </main>
    </div>

    <style>
        .asset-details-container {
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }

        .detail-section {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            padding: 1.5rem;
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-primary);
        }

        .section-header h2 {
            color: var(--text-primary);
            margin: 0;
            font-size: 1.25rem;
            font-weight: 600;
        }

        .mapping-confidence {
            background: var(--siemens-petrol);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.875rem;
            font-weight: 500;
        }

        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }

        .detail-item {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .detail-item.full-width {
            grid-column: 1 / -1;
        }

        .detail-item label {
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .detail-item span,
        .detail-item p {
            color: var(--text-primary);
            font-size: 1rem;
        }

        .asset-type-badge,
        .source-badge {
            background: var(--bg-secondary);
            color: var(--text-primary);
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.875rem;
            font-weight: 500;
            display: inline-block;
        }

        .status-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.875rem;
            font-weight: 500;
            display: inline-block;
        }

        .status-active { background: var(--success-green); color: white; }
        .status-inactive { background: var(--gray-500); color: white; }
        .status-retired { background: var(--warning-orange); color: white; }
        .status-disposed { background: var(--error-red); color: white; }

        .criticality-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.875rem;
            font-weight: 500;
            display: inline-block;
        }

        .criticality-clinical_high { background: var(--error-red); color: white; }
        .criticality-business_medium { background: var(--warning-orange); color: white; }
        .criticality-non_essential { background: var(--gray-500); color: white; }

        .phi-status {
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.875rem;
            font-weight: 500;
            display: inline-block;
        }

        .phi-yes { background: var(--error-red); color: white; }
        .phi-no { background: var(--success-green); color: white; }

        .timeline {
            position: relative;
            padding-left: 2rem;
        }

        .timeline::before {
            content: '';
            position: absolute;
            left: 1rem;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--border-primary);
        }

        .timeline-item {
            position: relative;
            margin-bottom: 2rem;
        }

        .timeline-marker {
            position: absolute;
            left: -2rem;
            top: 0.5rem;
            width: 1rem;
            height: 1rem;
            background: var(--siemens-petrol);
            border-radius: 50%;
            border: 3px solid var(--bg-card);
        }

        .timeline-marker.mapped {
            background: var(--siemens-orange);
        }
        
        .timeline-marker.patch-verified {
            background: #10b981;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.75rem;
        }
        
        .timeline-marker.patch-failed {
            background: #ef4444;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.75rem;
        }
        
        .timeline-marker.patch-pending {
            background: #f59e0b;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.75rem;
        }
        
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .badge-verified {
            background: #10b981;
            color: white;
        }
        
        .badge-failed {
            background: #ef4444;
            color: white;
        }
        
        .badge-pending {
            background: #f59e0b;
            color: white;
        }

        .timeline-content h4 {
            color: var(--text-primary);
            margin: 0 0 0.5rem 0;
            font-size: 1rem;
            font-weight: 600;
        }

        .timeline-content p {
            color: var(--text-secondary);
            margin: 0;
            font-size: 0.875rem;
        }

        .related-data {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .related-item {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1rem;
        }

        .related-item-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .related-item-header h4 {
            color: var(--text-primary);
            margin: 0;
            font-size: 1rem;
            font-weight: 600;
        }

        .related-item p {
            color: var(--text-secondary);
            margin: 0.25rem 0;
            font-size: 0.875rem;
        }

        .scan-status,
        .sbom-status {
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 500;
            display: inline-block;
        }

        .status-pending { background: var(--warning-orange); color: white; }
        .status-success { background: var(--success-green); color: white; }
        .status-failed { background: var(--error-red); color: white; }
        .status-partial { background: var(--warning-orange); color: white; }
    </style>

    <!-- Profile Dropdown Script -->
    <script src="/assets/js/dashboard-common.js"></script>
    <script>
        // Pass user data to the profile dropdown
        window.userData = {
            name: '<?php echo dave_htmlspecialchars($user['username']); ?>',
            role: '<?php echo dave_htmlspecialchars($user['role']); ?>',
            email: '<?php echo dave_htmlspecialchars($user['email'] ?? 'user@example.com'); ?>'
        };
    </script>
</body>
</html>
