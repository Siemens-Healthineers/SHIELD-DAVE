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

// Check permissions
if (!$auth->hasPermission('remediations.view')) {
    header('Location: /pages/dashboard.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['ajax']) {
        case 'get_remediations':
            try {
                $page = intval($_GET['page'] ?? 1);
                $limit = intval($_GET['limit'] ?? 25);
                $offset = ($page - 1) * $limit;
                
                // Build filters
                $filters = [];
                $params = [];
                
                if (!empty($_GET['search'])) {
                    $filters[] = "(r.remediation_id::text ILIKE ? OR r.description ILIKE ? OR r.narrative ILIKE ? OR v.cve_id ILIKE ?)";
                    $searchTerm = '%' . $_GET['search'] . '%';
                    $params = array_merge($params, [$searchTerm, $searchTerm, $searchTerm, $searchTerm]);
                }
                
                if (!empty($_GET['vulnerability_id'])) {
                    $filters[] = "r.vulnerability_id = ?";
                    $params[] = $_GET['vulnerability_id'];
                }
                
                $whereClause = !empty($filters) ? 'WHERE ' . implode(' AND ', $filters) : '';
                
                // Get total count
                $countSql = "SELECT COUNT(*) as total 
                            FROM remediations r
                            LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.vulnerability_id
                            $whereClause";
                $countStmt = $db->query($countSql, $params);
                $total = $countStmt->fetch()['total'];
                
                // Get remediations
                $sql = "SELECT 
                            r.remediation_id,
                            r.vulnerability_id,
                            r.description,
                            r.narrative,
                            r.upstream_api,
                            r.created_at,
                            r.updated_at,
                            r.user_id,
                            u.username as created_by,
                            u.email as creator_email,
                            v.cve_id,
                            v.severity as vulnerability_severity,
                            v.cvss_v3_score,
                            (SELECT COUNT(*) FROM remediation_assets_link WHERE remediation_id = r.remediation_id) as asset_count,
                            (SELECT COUNT(*) FROM remediation_patches_link WHERE remediation_id = r.remediation_id) as patch_count
                        FROM remediations r
                        LEFT JOIN users u ON r.user_id = u.user_id
                        LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.vulnerability_id
                        $whereClause
                        ORDER BY r.created_at DESC
                        LIMIT ? OFFSET ?";
                
                $params[] = $limit;
                $params[] = $offset;
                
                $stmt = $db->query($sql, $params);
                $remediations = $stmt->fetchAll();
                
                echo json_encode([
                    'success' => true,
                    'data' => $remediations,
                    'pagination' => [
                        'page' => $page,
                        'limit' => $limit,
                        'total' => $total,
                        'pages' => ceil($total / $limit)
                    ]
                ]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            exit;
            
        case 'get_remediation':
            try {
                $remediationId = $_GET['id'] ?? '';
                if (!$remediationId) {
                    throw new Exception('Remediation ID is required');
                }
                
                // Get remediation details with linked assets and patches
                $sql = "SELECT 
                            r.*,
                            u.username as created_by,
                            u.email as creator_email,
                            v.cve_id,
                            v.description as vulnerability_description,
                            v.severity as vulnerability_severity,
                            v.cvss_v3_score
                        FROM remediations r
                        LEFT JOIN users u ON r.user_id = u.user_id
                        LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.vulnerability_id
                        WHERE r.remediation_id = ?";
                
                $stmt = $db->query($sql, [$remediationId]);
                $remediation = $stmt->fetch();
                
                if (!$remediation) {
                    throw new Exception('Remediation not found');
                }
                
                // Get linked assets
                $assetsSql = "SELECT 
                                a.asset_id,
                                a.hostname,
                                a.ip_address,
                                a.asset_type,
                                a.manufacturer,
                                a.model,
                                a.criticality,
                                a.department
                            FROM remediation_assets_link ral
                            JOIN assets a ON ral.asset_id = a.asset_id
                            WHERE ral.remediation_id = ?";
                $assetsStmt = $db->query($assetsSql, [$remediationId]);
                $remediation['assets'] = $assetsStmt->fetchAll();
                
                // Get linked patches
                $patchesSql = "SELECT 
                                p.patch_id,
                                p.patch_name,
                                p.patch_type,
                                p.release_date,
                                p.description
                            FROM remediation_patches_link rpl
                            JOIN patches p ON rpl.patch_id = p.patch_id
                            WHERE rpl.remediation_id = ?";
                $patchesStmt = $db->query($patchesSql, [$remediationId]);
                $remediation['patches'] = $patchesStmt->fetchAll();
                
                echo json_encode([
                    'success' => true,
                    'data' => $remediation
                ]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            exit;
            
        case 'delete_remediation':
            try {
                if (!$auth->hasPermission('remediations.delete')) {
                    throw new Exception('Permission denied');
                }
                
                $input = json_decode(file_get_contents('php://input'), true);
                $remediationId = $input['remediation_id'] ?? '';
                
                if (!$remediationId) {
                    throw new Exception('Remediation ID is required');
                }
                
                $pdo = $db->getConnection();
                $pdo->beginTransaction();
                
                // Delete linked records
                $pdo->prepare("DELETE FROM remediation_assets_link WHERE remediation_id = ?")->execute([$remediationId]);
                $pdo->prepare("DELETE FROM remediation_patches_link WHERE remediation_id = ?")->execute([$remediationId]);
                $pdo->prepare("DELETE FROM remediations WHERE remediation_id = ?")->execute([$remediationId]);
                
                $pdo->commit();
                
                echo json_encode(['success' => true, 'message' => 'Remediation deleted successfully']);
            } catch (Exception $e) {
                if (isset($pdo) && $pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            exit;
            
        case 'get_asset_details':
            try {
                $assetId = $_GET['asset_id'] ?? '';
                if (!$assetId) {
                    throw new Exception('Asset ID is required');
                }
                
                $sql = "SELECT 
                            a.*,
                            l.location_name,
                            l.location_code,
                            md.device_id,
                            md.device_name,
                            md.brand_name
                        FROM assets a
                        LEFT JOIN locations l ON a.location_id = l.location_id
                        LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
                        WHERE a.asset_id = ?";
                
                $stmt = $db->query($sql, [$assetId]);
                $asset = $stmt->fetch();
                
                if (!$asset) {
                    throw new Exception('Asset not found');
                }
                
                // Get vulnerability count for this asset
                $vulnSql = "SELECT COUNT(*) as count 
                           FROM device_vulnerabilities_link dvl 
                           JOIN medical_devices md ON dvl.device_id = md.device_id
                           WHERE md.asset_id = ?";
                $vulnStmt = $db->query($vulnSql, [$assetId]);
                $asset['vulnerability_count'] = $vulnStmt->fetch()['count'];
                
                echo json_encode([
                    'success' => true,
                    'data' => $asset
                ]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            exit;
            
        case 'get_patch_details':
            try {
                $patchId = $_GET['patch_id'] ?? '';
                if (!$patchId) {
                    throw new Exception('Patch ID is required');
                }
                
                $sql = "SELECT * FROM patches WHERE patch_id = ?";
                $stmt = $db->query($sql, [$patchId]);
                $patch = $stmt->fetch();
                
                if (!$patch) {
                    throw new Exception('Patch not found');
                }
                
                echo json_encode([
                    'success' => true,
                    'data' => $patch
                ]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            exit;
            
        case 'get_vulnerability_details':
            try {
                $vulnerabilityId = $_GET['vulnerability_id'] ?? '';
                if (!$vulnerabilityId) {
                    throw new Exception('Vulnerability ID is required');
                }
                
                $sql = "SELECT 
                            v.*,
                            (SELECT COUNT(*) FROM device_vulnerabilities_link WHERE cve_id = v.cve_id) as affected_devices
                        FROM vulnerabilities v
                        WHERE v.vulnerability_id = ?";
                
                $stmt = $db->query($sql, [$vulnerabilityId]);
                $vulnerability = $stmt->fetch();
                
                if (!$vulnerability) {
                    throw new Exception('Vulnerability not found');
                }
                
                echo json_encode([
                    'success' => true,
                    'data' => $vulnerability
                ]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            exit;
            
        case 'search_vulnerabilities':
            try {
                $search = $_GET['search'] ?? '';
                $sql = "SELECT vulnerability_id, cve_id, description, severity, cvss_v3_score 
                       FROM vulnerabilities 
                       WHERE cve_id ILIKE ? OR description ILIKE ?
                       LIMIT 20";
                $stmt = $db->query($sql, ["%$search%", "%$search%"]);
                $results = $stmt->fetchAll();
                
                echo json_encode([
                    'success' => true,
                    'data' => $results
                ]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            exit;
            
        case 'search_assets':
            try {
                $search = $_GET['search'] ?? '';
                $sql = "SELECT asset_id, hostname, ip_address, asset_type, manufacturer, model 
                       FROM assets 
                       WHERE hostname ILIKE ? OR ip_address::text ILIKE ? OR manufacturer ILIKE ?
                       LIMIT 20";
                $stmt = $db->query($sql, ["%$search%", "%$search%", "%$search%"]);
                $results = $stmt->fetchAll();
                
                echo json_encode([
                    'success' => true,
                    'data' => $results
                ]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            exit;
            
        case 'search_patches':
            try {
                $search = $_GET['search'] ?? '';
                $sql = "SELECT p.patch_id, p.patch_name, p.patch_type, p.release_date, p.description, p.vendor 
                       FROM patches p
                       WHERE p.patch_name ILIKE ? OR p.description ILIKE ? OR p.vendor ILIKE ? OR p.kb_article ILIKE ?
                       LIMIT 20";
                $stmt = $db->query($sql, ["%$search%", "%$search%", "%$search%", "%$search%"]);
                $results = $stmt->fetchAll();
                
                echo json_encode([
                    'success' => true,
                    'data' => $results
                ]);
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'error' => $e->getMessage()]);
            }
            exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Remediations - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .remediations-container {
            padding: 2rem;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid var(--border-card, #1f2937);
        }
        
        .page-title {
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-primary, #ffffff);
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .page-title i {
            color: var(--siemens-petrol-light, #00bbbb);
        }
        
        .filters-section {
            background: var(--bg-card, #111111);
            border: 1px solid var(--border-card, #1f2937);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .filters-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        
        .filter-group label {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-secondary, #cbd5e1);
        }
        
        .filter-group input,
        .filter-group select {
            padding: 0.5rem;
            border: 1px solid var(--border-secondary, #374151);
            border-radius: 0.375rem;
            background: var(--bg-secondary, #0a0a0a);
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
        }
        
        .filter-actions {
            display: flex;
            gap: 1rem;
            justify-content: flex-end;
        }
        
        .btn {
            padding: 0.5rem 1.5rem;
            border: none;
            border-radius: 0.375rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .btn-primary {
            background: var(--siemens-petrol, #009999);
            color: white;
        }
        
        .btn-primary:hover {
            background: var(--siemens-petrol-light, #00bbbb);
        }
        
        .btn-secondary {
            background: var(--bg-tertiary, #1a1a1a);
            color: var(--text-primary, #ffffff);
            border: 1px solid var(--border-card, #1f2937);
        }
        
        .btn-secondary:hover {
            background: var(--bg-card, #111111);
        }
        
        .btn-danger {
            background: var(--error-red, #ef4444);
            color: white;
        }
        
        .btn-danger:hover {
            background: #dc2626;
        }
        
        .remediations-table {
            background: var(--bg-card, #111111);
            border: 1px solid var(--border-card, #1f2937);
            border-radius: 0.75rem;
            overflow: hidden;
        }
        
        .table-wrapper {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead {
            background: var(--bg-tertiary, #1a1a1a);
            border-bottom: 2px solid var(--border-card, #1f2937);
        }
        
        th {
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            color: var(--text-secondary, #cbd5e1);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        td {
            padding: 1rem;
            border-bottom: 1px solid var(--border-secondary, #374151);
            color: var(--text-primary, #ffffff);
        }
        
        tbody tr:hover {
            background: var(--bg-tertiary, #1a1a1a);
        }
        
        .status-badge,
        .priority-badge,
        .severity-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status-badge.planning { background: #3b82f6; color: white; }
        .status-badge.in-progress { background: #f59e0b; color: white; }
        .status-badge.testing { background: #8b5cf6; color: white; }
        .status-badge.completed { background: #10b981; color: white; }
        .status-badge.on-hold { background: #6b7280; color: white; }
        .status-badge.cancelled { background: #ef4444; color: white; }
        
        .priority-badge.critical { background: #dc2626; color: white; }
        .priority-badge.high { background: #f97316; color: white; }
        .priority-badge.medium { background: #eab308; color: white; }
        .priority-badge.low { background: #22c55e; color: white; }
        
        .severity-badge.critical { background: #dc2626; color: white; }
        .severity-badge.high { background: #f97316; color: white; }
        .severity-badge.medium { background: #eab308; color: white; }
        .severity-badge.low { background: #22c55e; color: white; }
        
        .action-buttons {
            display: flex;
            gap: 0.5rem;
        }
        
        .action-btn {
            padding: 0.25rem 0.5rem;
            border: none;
            border-radius: 0.25rem;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.875rem;
        }
        
        .action-btn.view {
            background: var(--siemens-petrol, #009999);
            color: white;
        }
        
        .action-btn.edit {
            background: #3b82f6;
            color: white;
        }
        
        .action-btn.delete {
            background: var(--error-red, #ef4444);
            color: white;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 1rem;
            padding: 1.5rem;
            background: var(--bg-tertiary, #1a1a1a);
        }
        
        .pagination button {
            padding: 0.5rem 1rem;
            border: 1px solid var(--border-card, #1f2937);
            border-radius: 0.375rem;
            background: var(--bg-card, #111111);
            color: var(--text-primary, #ffffff);
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .pagination button:hover:not(:disabled) {
            background: var(--siemens-petrol, #009999);
        }
        
        .pagination button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .pagination-info {
            color: var(--text-secondary, #cbd5e1);
            font-size: 0.875rem;
        }
        
        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            overflow-y: auto;
        }
        
        .modal.show {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }
        
        /* Full-screen modal for remediation create/edit */
        #remediationModal.show {
            padding: 2em;
            align-items: center;
            justify-content: center;
        }
        
        .modal-content {
            background: var(--bg-card, #111111);
            border: 1px solid var(--border-card, #1f2937);
            border-radius: 0.75rem;
            width: 100%;
            max-width: 800px;
            max-height: 90vh;
            overflow-y: auto;
        }
        
        /* Centered content for remediation modal */
        #remediationModal .modal-content {
            max-width: 1200px;
            max-height: calc(100vh - 4em);
            display: flex;
            flex-direction: column;
        }
        
        #remediationModal .modal-body {
            flex: 1;
            overflow-y: auto;
        }
        
        .modal-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-card, #1f2937);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--bg-tertiary, #1a1a1a);
        }
        
        .modal-header h3 {
            margin: 0;
            font-size: 1.5rem;
            color: var(--text-primary, #ffffff);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .modal-close {
            background: none;
            border: none;
            font-size: 1.5rem;
            color: var(--text-secondary, #cbd5e1);
            cursor: pointer;
            padding: 0;
            width: 2rem;
            height: 2rem;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 0.25rem;
        }
        
        .modal-close:hover {
            background: var(--bg-secondary, #0a0a0a);
            color: var(--text-primary, #ffffff);
        }
        
        .modal-body {
            padding: 1.5rem;
        }
        
        .modal-footer {
            padding: 1.5rem;
            border-top: 1px solid var(--border-card, #1f2937);
            display: flex;
            justify-content: flex-end;
            gap: 1rem;
            background: var(--bg-tertiary, #1a1a1a);
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: var(--text-secondary, #cbd5e1);
        }
        
        .required {
            color: #ef4444;
            margin-left: 0.25rem;
        }
        
        .linked-items h4 .required {
            color: #ef4444;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border-secondary, #374151);
            border-radius: 0.375rem;
            background: var(--bg-secondary, #0a0a0a);
            color: var(--text-primary, #ffffff);
        }
        
        .form-group textarea {
            min-height: 100px;
            resize: vertical;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }
        
        .info-item {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        .info-item label {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted, #9ca3af);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .info-item span {
            font-size: 1rem;
            color: var(--text-primary, #ffffff);
        }
        
        .linked-items {
            margin-top: 1.5rem;
        }
        
        .linked-items h4 {
            color: var(--text-secondary, #cbd5e1);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .linked-items-grid {
            display: grid;
            gap: 0.75rem;
        }
        
        .linked-item {
            padding: 0.75rem;
            background: var(--bg-secondary, #0a0a0a);
            border: 1px solid var(--border-secondary, #374151);
            border-radius: 0.375rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .linked-item:hover {
            background: var(--bg-tertiary, #1a1a1a);
            border-color: var(--siemens-petrol, #009999);
        }
        
        .linked-item-info {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        .linked-item-title {
            font-weight: 600;
            color: var(--text-primary, #ffffff);
        }
        
        .linked-item-subtitle {
            font-size: 0.875rem;
            color: var(--text-muted, #9ca3af);
        }
        
        .linked-item-remove {
            background: var(--error-red, #ef4444);
            color: white;
            border: none;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            cursor: pointer;
            font-size: 0.75rem;
        }
        
        .search-results {
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid var(--border-secondary, #374151);
            border-radius: 0.375rem;
            margin-top: 0.5rem;
            display: none;
        }
        
        .search-results.show {
            display: block;
        }
        
        .search-result-item {
            padding: 0.75rem;
            border-bottom: 1px solid var(--border-secondary, #374151);
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .search-result-item:last-child {
            border-bottom: none;
        }
        
        .search-result-item:hover {
            background: var(--bg-tertiary, #1a1a1a);
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: var(--bg-secondary, #0a0a0a);
            border-radius: 4px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: var(--siemens-petrol, #009999);
            transition: width 0.3s;
        }
        
        .empty-state {
            text-align: center;
            padding: 3rem;
            color: var(--text-muted, #9ca3af);
        }
        
        .empty-state i {
            font-size: 3rem;
            margin-bottom: 1rem;
            color: var(--border-card, #1f2937);
        }
        
        .clickable-link {
            color: var(--siemens-petrol-light, #00bbbb);
            cursor: pointer;
            text-decoration: underline;
            transition: color 0.2s;
        }
        
        .clickable-link:hover {
            color: var(--siemens-petrol, #009999);
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>
        
        <div class="remediations-container">
            <div class="page-header">
                <h1 class="page-title">
                    <i class="fas fa-tools"></i>
                    Remediations
                </h1>
                <?php if ($auth->hasPermission('remediations.create')): ?>
                <button class="btn btn-primary" onclick="openCreateModal()">
                    <i class="fas fa-plus"></i>
                    Create Remediation
                </button>
                <?php endif; ?>
            </div>
            
            <!-- Filters Section -->
            <div class="filters-section">
                <div class="filters-grid">
                    <div class="filter-group">
                        <label>Search</label>
                        <input type="text" id="searchInput" placeholder="Search remediations...">
                    </div>
                </div>
                <div class="filter-actions">
                    <button class="btn btn-secondary" onclick="clearFilters()">
                        <i class="fas fa-times"></i>
                        Clear Filters
                    </button>
                    <button class="btn btn-primary" onclick="loadRemediations()">
                        <i class="fas fa-search"></i>
                        Apply Filters
                    </button>
                </div>
            </div>
            
            <!-- Remediations Table -->
            <div class="remediations-table">
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Description</th>
                                <th>Vulnerability</th>
                                <th>Assets</th>
                                <th>Patches</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="remediationsTableBody">
                            <tr>
                                <td colspan="6" class="empty-state">
                                    <i class="fas fa-circle-notch fa-spin"></i>
                                    <p>Loading remediations...</p>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <div class="pagination" id="paginationContainer"></div>
            </div>
        </div>
    </div>
    
    <!-- Create/Edit Remediation Modal -->
    <div id="remediationModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>
                    <i class="fas fa-tools"></i>
                    <span id="modalTitle">Create Remediation</span>
                </h3>
                <button class="modal-close" onclick="closeRemediationModal()">&times;</button>
            </div>
            <div class="modal-body">
                <form id="remediationForm">
                    <input type="hidden" id="remediationId">
                    
                    <div class="form-group">
                        <label>Description *</label>
                        <input type="text" id="description" required placeholder="Brief description of the remediation">
                    </div>
                    
                    <div class="form-group">
                        <label>Narrative</label>
                        <textarea id="narrative" placeholder="Detailed narrative or explanation of the remediation process"></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>Upstream API</label>
                        <input type="text" id="upstreamApi" placeholder="Source API or system (optional)">
                    </div>
                    
                    <div class="form-group">
                        <label>Vulnerability <span class="required">*</span></label>
                        <input type="text" id="vulnerabilitySearch" placeholder="Search for vulnerability...">
                        <div id="vulnerabilityResults" class="search-results"></div>
                        <input type="hidden" id="vulnerabilityId">
                        <div id="selectedVulnerability" style="margin-top: 0.5rem;"></div>
                    </div>
                    
                    <div class="linked-items">
                        <h4><i class="fas fa-server"></i> Linked Assets <span class="required">*</span></h4>
                        <div class="form-group">
                            <input type="text" id="assetSearch" placeholder="Search for assets...">
                            <div id="assetResults" class="search-results"></div>
                        </div>
                        <div id="selectedAssets" class="linked-items-grid"></div>
                    </div>
                    
                    <div class="linked-items">
                        <h4><i class="fas fa-box"></i> Linked Patches <span class="required">*</span></h4>
                        <div class="form-group">
                            <input type="text" id="patchSearch" placeholder="Search for patches...">
                            <div id="patchResults" class="search-results"></div>
                        </div>
                        <div id="selectedPatches" class="linked-items-grid"></div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeRemediationModal()">Cancel</button>
                <button class="btn btn-primary" onclick="saveRemediation()">
                    <i class="fas fa-save"></i>
                    Save Remediation
                </button>
            </div>
        </div>
    </div>
    
    <!-- Asset Details Modal -->
    <div id="assetModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-server"></i> Asset Details</h3>
                <button class="modal-close" onclick="closeAssetModal()">&times;</button>
            </div>
            <div class="modal-body" id="assetModalBody">
                <div class="empty-state">
                    <i class="fas fa-circle-notch fa-spin"></i>
                    <p>Loading asset details...</p>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeAssetModal()">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Patch Details Modal -->
    <div id="patchModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-box"></i> Patch Details</h3>
                <button class="modal-close" onclick="closePatchModal()">&times;</button>
            </div>
            <div class="modal-body" id="patchModalBody">
                <div class="empty-state">
                    <i class="fas fa-circle-notch fa-spin"></i>
                    <p>Loading patch details...</p>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closePatchModal()">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Vulnerability Details Modal -->
    <div id="vulnerabilityModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-bug"></i> Vulnerability Details</h3>
                <button class="modal-close" onclick="closeVulnerabilityModal()">&times;</button>
            </div>
            <div class="modal-body" id="vulnerabilityModalBody">
                <div class="empty-state">
                    <i class="fas fa-circle-notch fa-spin"></i>
                    <p>Loading vulnerability details...</p>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeVulnerabilityModal()">Close</button>
            </div>
        </div>
    </div>
    
    <script>
        let currentPage = 1;
        let totalPages = 1;
        let selectedAssets = [];
        let selectedPatches = [];
        let selectedVulnerability = null;
        
        // Load remediations on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadRemediations();
            
            // Setup search delays
            let searchTimeout;
            document.getElementById('searchInput').addEventListener('input', function() {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    currentPage = 1;
                    loadRemediations();
                }, 500);
            });
            
            // Setup vulnerability search
            document.getElementById('vulnerabilitySearch').addEventListener('input', function() {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => searchVulnerabilities(), 300);
            });
            
            // Setup asset search
            document.getElementById('assetSearch').addEventListener('input', function() {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => searchAssets(), 300);
            });
            
            // Setup patch search
            document.getElementById('patchSearch').addEventListener('input', function() {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => searchPatches(), 300);
            });
        });
        
        async function loadRemediations() {
            const params = new URLSearchParams({
                ajax: 'get_remediations',
                page: currentPage,
                limit: 25,
                search: document.getElementById('searchInput').value
            });
            
            try {
                const response = await fetch(`?${params}`);
                const result = await response.json();
                
                if (result.success) {
                    displayRemediations(result.data);
                    displayPagination(result.pagination);
                } else {
                    showError('Failed to load remediations: ' + result.error);
                }
            } catch (error) {
                showError('Error loading remediations: ' + error.message);
            }
        }
        
        function displayRemediations(remediations) {
            const tbody = document.getElementById('remediationsTableBody');
            
            if (remediations.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6" class="empty-state">
                            <i class="fas fa-inbox"></i>
                            <p>No remediations found</p>
                        </td>
                    </tr>
                `;
                return;
            }
            
            tbody.innerHTML = remediations.map(r => `
                <tr>
                    <td>
                        <div style="font-weight: 600;">${escapeHtml(r.description ? r.description.substring(0, 60) : 'No description')}</div>
                        <div style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(r.narrative ? r.narrative.substring(0, 80) : '')}${r.narrative && r.narrative.length > 80 ? '...' : ''}</div>
                    </td>
                    <td>
                        ${r.cve_id ? `
                            <span class="clickable-link" onclick="openVulnerabilityModal('${r.vulnerability_id}')">
                                ${escapeHtml(r.cve_id)}
                            </span>
                            <div style="font-size: 0.75rem;">
                                <span class="severity-badge ${r.vulnerability_severity ? r.vulnerability_severity.toLowerCase() : ''}">${escapeHtml(r.vulnerability_severity || 'N/A')}</span>
                                CVSS: ${r.cvss_v3_score || 'N/A'}
                            </div>
                        ` : '<span style="color: var(--text-muted);">None</span>'}
                    </td>
                    <td><span class="badge">${r.asset_count || 0}</span></td>
                    <td><span class="badge">${r.patch_count || 0}</span></td>
                    <td>
                        <div style="font-size: 0.875rem;">${formatDate(r.created_at)}</div>
                        <div style="font-size: 0.75rem; color: var(--text-muted);">by ${escapeHtml(r.created_by || 'Unknown')}</div>
                    </td>
                    <td>
                        <div class="action-buttons">
                            <button class="action-btn view" onclick="viewRemediation('${r.remediation_id}')" title="View Details">
                                <i class="fas fa-eye"></i>
                            </button>
                            <?php if ($auth->hasPermission('remediations.delete')): ?>
                            <button class="action-btn delete" onclick="deleteRemediation('${r.remediation_id}')" title="Delete">
                                <i class="fas fa-trash"></i>
                            </button>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
            `).join('');
        }
        
        function displayPagination(pagination) {
            const container = document.getElementById('paginationContainer');
            totalPages = pagination.pages;
            currentPage = pagination.page;
            
            container.innerHTML = `
                <button onclick="changePage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>
                    <i class="fas fa-chevron-left"></i> Previous
                </button>
                <span class="pagination-info">
                    Page ${currentPage} of ${totalPages} (${pagination.total} total)
                </span>
                <button onclick="changePage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>
                    Next <i class="fas fa-chevron-right"></i>
                </button>
            `;
        }
        
        function changePage(page) {
            if (page < 1 || page > totalPages) return;
            currentPage = page;
            loadRemediations();
        }
        
        function clearFilters() {
            document.getElementById('searchInput').value = '';
            currentPage = 1;
            loadRemediations();
        }
        
        function openCreateModal() {
            document.getElementById('modalTitle').textContent = 'Create Remediation';
            document.getElementById('remediationForm').reset();
            document.getElementById('remediationId').value = '';
            selectedAssets = [];
            selectedPatches = [];
            selectedVulnerability = null;
            updateSelectedAssets();
            updateSelectedPatches();
            updateSelectedVulnerability();
            document.getElementById('remediationModal').classList.add('show');
        }
        
        function closeRemediationModal() {
            document.getElementById('remediationModal').classList.remove('show');
        }
        
        async function saveRemediation() {
            const remediationId = document.getElementById('remediationId').value;
            const isUpdate = remediationId !== '';
            
            // Validation
            if (!selectedVulnerability) {
                showError('Please select a vulnerability');
                return;
            }
            
            if (selectedAssets.length === 0) {
                showError('Please select at least one asset');
                return;
            }
            
            if (selectedPatches.length === 0) {
                showError('Please select at least one patch');
                return;
            }
            
            const data = {
                description: document.getElementById('description').value,
                narrative: document.getElementById('narrative').value,
                upstream_api: document.getElementById('upstreamApi').value || null,
                vulnerability_id: selectedVulnerability.vulnerability_id,
                asset_ids: selectedAssets.map(a => a.asset_id),
                patch_ids: selectedPatches.map(p => p.patch_id)
            };
            
            try {
                const url = isUpdate ? `/api/v1/remediations/${remediationId}` : '/api/v1/remediations';
                const method = isUpdate ? 'PUT' : 'POST';
                
                const response = await fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showSuccess(isUpdate ? 'Remediation updated successfully' : 'Remediation created successfully');
                    closeRemediationModal();
                    loadRemediations();
                } else {
                    showError(`Failed to ${isUpdate ? 'update' : 'create'} remediation: ` + JSON.stringify(result.error));
                }
            } catch (error) {
                showError(`Error ${isUpdate ? 'updating' : 'creating'} remediation: ` + error.message);
            }
        }
        
        async function viewRemediation(id) {
            try {
                const response = await fetch(`?ajax=get_remediation&id=${id}`);
                const result = await response.json();
                
                if (result.success) {
                    const r = result.data;
                    
                    // Populate modal with details
                    document.getElementById('modalTitle').textContent = 'View Remediation';
                    document.getElementById('remediationId').value = r.remediation_id;
                    document.getElementById('description').value = r.description;
                    document.getElementById('narrative').value = r.narrative;
                    document.getElementById('upstreamApi').value = r.upstream_api || '';
                    
                    if (r.vulnerability_id) {
                        selectedVulnerability = {
                            vulnerability_id: r.vulnerability_id,
                            cve_id: r.cve_id,
                            description: r.vulnerability_description,
                            severity: r.vulnerability_severity
                        };
                        updateSelectedVulnerability();
                    }
                    
                    selectedAssets = r.assets || [];
                    selectedPatches = r.patches || [];
                    updateSelectedAssets();
                    updateSelectedPatches();
                    
                    document.getElementById('remediationModal').classList.add('show');
                } else {
                    showError('Failed to load remediation: ' + result.error);
                }
            } catch (error) {
                showError('Error loading remediation: ' + error.message);
            }
        }
        
        async function deleteRemediation(id) {
            if (!confirm('Are you sure you want to delete this remediation?')) return;
            
            try {
                const response = await fetch('?ajax=delete_remediation', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ remediation_id: id })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showSuccess('Remediation deleted successfully');
                    loadRemediations();
                } else {
                    showError('Failed to delete remediation: ' + result.error);
                }
            } catch (error) {
                showError('Error deleting remediation: ' + error.message);
            }
        }
        
        // Search functions
        async function searchVulnerabilities() {
            const search = document.getElementById('vulnerabilitySearch').value;
            if (search.length < 2) {
                document.getElementById('vulnerabilityResults').classList.remove('show');
                return;
            }
            
            try {
                const response = await fetch(`?ajax=search_vulnerabilities&search=${encodeURIComponent(search)}`);
                const result = await response.json();
                
                if (result.success) {
                    const resultsDiv = document.getElementById('vulnerabilityResults');
                    resultsDiv.innerHTML = '';
                    result.data.forEach(v => {
                        const div = document.createElement('div');
                        div.className = 'search-result-item';
                        div.innerHTML = `
                            <div style="font-weight: 600;">${escapeHtml(v.cve_id)}</div>
                            <div style="font-size: 0.875rem; color: var(--text-muted);">
                                ${escapeHtml(v.description.substring(0, 100))}...
                            </div>
                            <div style="font-size: 0.75rem; margin-top: 0.25rem;">
                                <span class="severity-badge ${v.severity.toLowerCase()}">${escapeHtml(v.severity)}</span>
                                CVSS: ${v.cvss_v3_score || 'N/A'}
                            </div>
                        `;
                        div.addEventListener('click', () => selectVulnerability(v));
                        resultsDiv.appendChild(div);
                    });
                    resultsDiv.classList.add('show');
                }
            } catch (error) {
                console.error('Error searching vulnerabilities:', error);
            }
        }
        
        async function searchAssets() {
            const search = document.getElementById('assetSearch').value;
            if (search.length < 2) {
                document.getElementById('assetResults').classList.remove('show');
                return;
            }
            
            try {
                const response = await fetch(`?ajax=search_assets&search=${encodeURIComponent(search)}`);
                const result = await response.json();
                
                if (result.success) {
                    const resultsDiv = document.getElementById('assetResults');
                    resultsDiv.innerHTML = '';
                    result.data.forEach(a => {
                        const div = document.createElement('div');
                        div.className = 'search-result-item';
                        div.innerHTML = `
                            <div style="font-weight: 600;">${escapeHtml(a.hostname || 'Unknown')}</div>
                            <div style="font-size: 0.875rem; color: var(--text-muted);">
                                ${escapeHtml(a.ip_address)} • ${escapeHtml(a.asset_type)}
                            </div>
                            <div style="font-size: 0.75rem;">
                                ${escapeHtml(a.manufacturer)} ${escapeHtml(a.model)}
                            </div>
                        `;
                        div.addEventListener('click', () => addAsset(a));
                        resultsDiv.appendChild(div);
                    });
                    resultsDiv.classList.add('show');
                }
            } catch (error) {
                console.error('Error searching assets:', error);
            }
        }
        
        async function searchPatches() {
            const search = document.getElementById('patchSearch').value;
            if (search.length < 2) {
                document.getElementById('patchResults').classList.remove('show');
                return;
            }
            
            try {
                const response = await fetch(`?ajax=search_patches&search=${encodeURIComponent(search)}`);
                const result = await response.json();
                
                if (result.success) {
                    const resultsDiv = document.getElementById('patchResults');
                    resultsDiv.innerHTML = '';
                    result.data.forEach(p => {
                        const div = document.createElement('div');
                        div.className = 'search-result-item';
                        div.innerHTML = `
                            <div style="font-weight: 600;">${escapeHtml(p.patch_name)}</div>
                            <div style="font-size: 0.875rem; color: var(--text-muted);">
                                ${escapeHtml(p.patch_type)}${p.vendor ? ' • ' + escapeHtml(p.vendor) : ''} • ${formatDate(p.release_date)}
                            </div>
                            ${p.description ? `<div style="font-size: 0.75rem;">${escapeHtml(p.description.substring(0, 100))}...</div>` : ''}
                        `;
                        div.addEventListener('click', () => addPatch(p));
                        resultsDiv.appendChild(div);
                    });
                    resultsDiv.classList.add('show');
                }
            } catch (error) {
                console.error('Error searching patches:', error);
            }
        }
        
        function selectVulnerability(vuln) {
            console.log('Selected vulnerability:', vuln);
            selectedVulnerability = vuln;
            document.getElementById('vulnerabilitySearch').value = vuln.cve_id || 'Unknown';
            document.getElementById('vulnerabilityResults').classList.remove('show');
            updateSelectedVulnerability();
        }
        
        function updateSelectedVulnerability() {
            const div = document.getElementById('selectedVulnerability');
            if (selectedVulnerability) {
                div.innerHTML = `
                    <div class="linked-item" onclick="openVulnerabilityModal('${selectedVulnerability.vulnerability_id}')">
                        <div class="linked-item-info">
                            <div class="linked-item-title">${escapeHtml(selectedVulnerability.cve_id || 'Unknown CVE')}</div>
                            <div class="linked-item-subtitle">
                                <span class="severity-badge ${(selectedVulnerability.severity || '').toLowerCase()}">${escapeHtml(selectedVulnerability.severity || 'N/A')}</span>
                                ${selectedVulnerability.cvss_v3_score ? ' • CVSS: ' + selectedVulnerability.cvss_v3_score : ''}
                            </div>
                        </div>
                        <button class="linked-item-remove" onclick="event.stopPropagation(); removeVulnerability()">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                `;
            } else {
                div.innerHTML = '';
            }
        }
        
        function removeVulnerability() {
            selectedVulnerability = null;
            document.getElementById('vulnerabilitySearch').value = '';
            updateSelectedVulnerability();
        }
        
        function addAsset(asset) {
            if (!selectedAssets.find(a => a.asset_id === asset.asset_id)) {
                selectedAssets.push(asset);
                updateSelectedAssets();
            }
            document.getElementById('assetSearch').value = '';
            document.getElementById('assetResults').classList.remove('show');
        }
        
        function removeAsset(assetId) {
            selectedAssets = selectedAssets.filter(a => a.asset_id !== assetId);
            updateSelectedAssets();
        }
        
        function updateSelectedAssets() {
            const div = document.getElementById('selectedAssets');
            if (selectedAssets.length === 0) {
                div.innerHTML = '<p style="color: var(--text-muted); text-align: center; padding: 1rem;">No assets selected</p>';
            } else {
                div.innerHTML = selectedAssets.map(a => `
                    <div class="linked-item" onclick="openAssetModal('${a.asset_id}')">
                        <div class="linked-item-info">
                            <div class="linked-item-title">${escapeHtml(a.hostname || 'Unknown')}</div>
                            <div class="linked-item-subtitle">${escapeHtml(a.ip_address)} • ${escapeHtml(a.asset_type)}</div>
                        </div>
                        <button class="linked-item-remove" onclick="event.stopPropagation(); removeAsset('${a.asset_id}')">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                `).join('');
            }
        }
        
        function addPatch(patch) {
            if (!selectedPatches.find(p => p.patch_id === patch.patch_id)) {
                selectedPatches.push(patch);
                updateSelectedPatches();
            }
            document.getElementById('patchSearch').value = '';
            document.getElementById('patchResults').classList.remove('show');
        }
        
        function removePatch(patchId) {
            selectedPatches = selectedPatches.filter(p => p.patch_id !== patchId);
            updateSelectedPatches();
        }
        
        function updateSelectedPatches() {
            const div = document.getElementById('selectedPatches');
            if (selectedPatches.length === 0) {
                div.innerHTML = '<p style="color: var(--text-muted); text-align: center; padding: 1rem;">No patches selected</p>';
            } else {
                div.innerHTML = selectedPatches.map(p => `
                    <div class="linked-item" onclick="openPatchModal('${p.patch_id}')">
                        <div class="linked-item-info">
                            <div class="linked-item-title">${escapeHtml(p.patch_name)}</div>
                            <div class="linked-item-subtitle">${escapeHtml(p.patch_type)} • ${formatDate(p.release_date)}</div>
                        </div>
                        <button class="linked-item-remove" onclick="event.stopPropagation(); removePatch('${p.patch_id}')">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                `).join('');
            }
        }
        
        // Modal functions for viewing details
        async function openAssetModal(assetId) {
            document.getElementById('assetModal').classList.add('show');
            
            try {
                const response = await fetch(`?ajax=get_asset_details&asset_id=${assetId}`);
                const result = await response.json();
                
                if (result.success) {
                    const a = result.data;
                    document.getElementById('assetModalBody').innerHTML = `
                        <div class="info-grid">
                            <div class="info-item">
                                <label>Asset ID</label>
                                <span>${escapeHtml(a.asset_id)}</span>
                            </div>
                            <div class="info-item">
                                <label>Hostname</label>
                                <span>${escapeHtml(a.hostname || 'N/A')}</span>
                            </div>
                            <div class="info-item">
                                <label>IP Address</label>
                                <span>${escapeHtml(a.ip_address)}</span>
                            </div>
                            <div class="info-item">
                                <label>MAC Address</label>
                                <span>${escapeHtml(a.mac_address || 'N/A')}</span>
                            </div>
                            <div class="info-item">
                                <label>Asset Type</label>
                                <span>${escapeHtml(a.asset_type)}</span>
                            </div>
                            <div class="info-item">
                                <label>Manufacturer</label>
                                <span>${escapeHtml(a.manufacturer || 'N/A')}</span>
                            </div>
                            <div class="info-item">
                                <label>Model</label>
                                <span>${escapeHtml(a.model || 'N/A')}</span>
                            </div>
                            <div class="info-item">
                                <label>Criticality</label>
                                <span class="priority-badge ${(a.criticality || '').toLowerCase().replace(' ', '-')}">${escapeHtml(a.criticality || 'N/A')}</span>
                            </div>
                            <div class="info-item">
                                <label>Department</label>
                                <span>${escapeHtml(a.department || 'N/A')}</span>
                            </div>
                            <div class="info-item">
                                <label>Location</label>
                                <span>${escapeHtml(a.location_name || 'N/A')}</span>
                            </div>
                            <div class="info-item">
                                <label>Medical Device</label>
                                <span>${a.device_id ? escapeHtml(a.device_name || a.brand_name) : 'Not mapped'}</span>
                            </div>
                            <div class="info-item">
                                <label>Vulnerabilities</label>
                                <span>${a.vulnerability_count || 0}</span>
                            </div>
                        </div>
                    `;
                } else {
                    showError('Failed to load asset details');
                }
            } catch (error) {
                showError('Error loading asset details: ' + error.message);
            }
        }
        
        function closeAssetModal() {
            document.getElementById('assetModal').classList.remove('show');
        }
        
        async function openPatchModal(patchId) {
            document.getElementById('patchModal').classList.add('show');
            
            try {
                const response = await fetch(`?ajax=get_patch_details&patch_id=${patchId}`);
                const result = await response.json();
                
                if (result.success) {
                    const p = result.data;
                    document.getElementById('patchModalBody').innerHTML = `
                        <div class="info-grid">
                            <div class="info-item">
                                <label>Patch ID</label>
                                <span>${escapeHtml(p.patch_id)}</span>
                            </div>
                            <div class="info-item">
                                <label>Patch Name</label>
                                <span>${escapeHtml(p.patch_name)}</span>
                            </div>
                            <div class="info-item">
                                <label>Patch Type</label>
                                <span>${escapeHtml(p.patch_type)}</span>
                            </div>
                            <div class="info-item">
                                <label>Release Date</label>
                                <span>${formatDate(p.release_date)}</span>
                            </div>
                            <div class="info-item" style="grid-column: 1 / -1;">
                                <label>Description</label>
                                <span>${escapeHtml(p.description || 'No description available')}</span>
                            </div>
                        </div>
                    `;
                } else {
                    showError('Failed to load patch details');
                }
            } catch (error) {
                showError('Error loading patch details: ' + error.message);
            }
        }
        
        function closePatchModal() {
            document.getElementById('patchModal').classList.remove('show');
        }
        
        async function openVulnerabilityModal(vulnerabilityId) {
            document.getElementById('vulnerabilityModal').classList.add('show');
            
            try {
                const response = await fetch(`?ajax=get_vulnerability_details&vulnerability_id=${vulnerabilityId}`);
                const result = await response.json();
                
                if (result.success) {
                    const v = result.data;
                    document.getElementById('vulnerabilityModalBody').innerHTML = `
                        <div class="info-grid">
                            <div class="info-item">
                                <label>CVE ID</label>
                                <span>${escapeHtml(v.cve_id)}</span>
                            </div>
                            <div class="info-item">
                                <label>Severity</label>
                                <span class="severity-badge ${v.severity.toLowerCase()}">${escapeHtml(v.severity)}</span>
                            </div>
                            <div class="info-item">
                                <label>CVSS v3 Score</label>
                                <span>${v.cvss_v3_score || 'N/A'}</span>
                            </div>
                            <div class="info-item">
                                <label>CVSS v4 Score</label>
                                <span>${v.cvss_v4_score || 'N/A'}</span>
                            </div>
                            <div class="info-item">
                                <label>Published Date</label>
                                <span>${formatDate(v.published_date)}</span>
                            </div>
                            <div class="info-item">
                                <label>Affected Devices</label>
                                <span>${v.affected_devices || 0}</span>
                            </div>
                            <div class="info-item" style="grid-column: 1 / -1;">
                                <label>Description</label>
                                <span>${escapeHtml(v.description || 'No description available')}</span>
                            </div>
                            ${v.is_kev ? `
                                <div class="info-item" style="grid-column: 1 / -1;">
                                    <label>KEV Information</label>
                                    <div style="padding: 0.75rem; background: rgba(220, 38, 38, 0.1); border: 1px solid #dc2626; border-radius: 0.375rem;">
                                        <strong style="color: #dc2626;">⚠️ This is a CISA Known Exploited Vulnerability</strong>
                                        <div style="margin-top: 0.5rem;">Due Date: ${formatDate(v.kev_due_date)}</div>
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                    `;
                } else {
                    showError('Failed to load vulnerability details');
                }
            } catch (error) {
                showError('Error loading vulnerability details: ' + error.message);
            }
        }
        
        function closeVulnerabilityModal() {
            document.getElementById('vulnerabilityModal').classList.remove('show');
        }
        
        // Utility functions
        function escapeHtml(text) {
            if (text === null || text === undefined) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function formatDate(dateString) {
            if (!dateString) return 'N/A';
            const date = new Date(dateString);
            return date.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });
        }
        
        function showSuccess(message) {
            alert(message); // Replace with better notification system
        }
        
        function showError(message) {
            alert(message); // Replace with better notification system
        }
        
        // Close modals on outside click
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.classList.remove('show');
            }
        }
    </script>
    
    <!-- Configuration -->
    <script>
        <?php include __DIR__ . '/../../assets/js/config.js'; ?>
    </script>
    
    <!-- Common Dashboard JavaScript -->
    <script src="/assets/js/dashboard-common.js"></script>
</body>
</html>
