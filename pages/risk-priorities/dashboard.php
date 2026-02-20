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

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['ajax']) {
        case 'get_tier_stats':
            // Use new risk-based tier statistics function
            $sql = "SELECT * FROM get_tier_statistics()";
            $stmt = $db->query($sql);
            $tiers = $stmt->fetchAll();
            
            // Get additional statistics (overdue, assigned) from materialized view
            $sql = "SELECT 
                priority_tier,
                COUNT(CASE WHEN days_overdue > 0 THEN 1 END) as overdue_count,
                COUNT(CASE WHEN assigned_to IS NOT NULL THEN 1 END) as assigned_count,
                COUNT(CASE WHEN assigned_to IS NULL THEN 1 END) as unassigned_count,
                ROUND(AVG(calculated_risk_score), 0) as avg_risk_score
            FROM risk_priority_view
            GROUP BY priority_tier
            ORDER BY priority_tier";
            
            $stmt = $db->query($sql);
            $additionalStats = [];
            while ($row = $stmt->fetch()) {
                $additionalStats[$row['priority_tier']] = $row;
            }
            
            // Merge the statistics
            foreach ($tiers as &$tier) {
                $tierNum = $tier['tier'];
                if (isset($additionalStats[$tierNum])) {
                    $tier['overdue_count'] = $additionalStats[$tierNum]['overdue_count'];
                    $tier['assigned_count'] = $additionalStats[$tierNum]['assigned_count'];
                    $tier['unassigned_count'] = $additionalStats[$tierNum]['unassigned_count'];
                    $tier['avg_risk_score'] = $additionalStats[$tierNum]['avg_risk_score'];
                } else {
                    $tier['overdue_count'] = 0;
                    $tier['assigned_count'] = 0;
                    $tier['unassigned_count'] = 0;
                    $tier['avg_risk_score'] = 0;
                }
            }
            
            echo json_encode(['success' => true, 'data' => $tiers]);
            exit;
            
        case 'get_priorities_list':
            error_log("get_priorities_list called with tier: " . ($_GET['tier'] ?? 'none'));
            $page = intval($_GET['page'] ?? 1);
            $limit = intval($_GET['limit'] ?? 25);
            $offset = ($page - 1) * $limit;
            $tier = $_GET['tier'] ?? '';
            $overdue = $_GET['overdue'] ?? '';
            $assigned = $_GET['assigned'] ?? '';
            $department = $_GET['department'] ?? '';
            $location = $_GET['location'] ?? '';
            $search = trim($_GET['search'] ?? '');
            
            // Build filters
            $filters = [];
            $params = [];
            
            if (!empty($tier)) {
                // Use the same tier calculation logic as the cards (urgency_score based)
                $tierNum = intval($tier);
                if ($tierNum == 1) {
                    $filters[] = "ars.urgency_score >= 1000";
                } elseif ($tierNum == 2) {
                    $filters[] = "ars.urgency_score >= 180 AND ars.urgency_score < 1000";
                } elseif ($tierNum == 3) {
                    $filters[] = "ars.urgency_score >= 160 AND ars.urgency_score < 180";
                } elseif ($tierNum == 4) {
                    $filters[] = "ars.urgency_score < 160";
                }
            }
            
            if ($overdue === 'true') {
                $filters[] = "ra.due_date < CURRENT_DATE AND ra.status != 'Completed'";
            }
            
            if ($assigned === 'my') {
                $filters[] = "ra.assigned_to = ?";
                $params[] = $user['user_id'];
            } elseif ($assigned === 'unassigned') {
                $filters[] = "ra.assigned_to IS NULL";
            }
            
            if (!empty($department)) {
                $filters[] = "a.department = ?";
                $params[] = $department;
            }
            
            if (!empty($location)) {
                $filters[] = "a.location_id = ?";
                $params[] = $location;
            }
            
            // Search filter - search across CVE ID, device name, location, and action description
            if (!empty($search)) {
                $searchTerm = '%' . $search . '%';
                $filters[] = "(
                    ra.cve_id ILIKE ? OR 
                    ra.action_description ILIKE ? OR
                    a.hostname ILIKE ? OR
                    a.ip_address::text ILIKE ? OR
                    md.device_name ILIKE ? OR
                    md.brand_name ILIKE ? OR
                    md.model_number ILIKE ? OR
                    l.location_name ILIKE ? OR
                    a.asset_tag ILIKE ?
                )";
                // Add search parameter 9 times (once for each field)
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }
            
            // Always exclude completed actions and actions with no devices
            $filters[] = "ra.status != 'Completed'";
            $filters[] = "EXISTS (SELECT 1 FROM action_device_links adl WHERE adl.action_id = ra.action_id)";
            $whereClause = !empty($filters) ? 'WHERE ' . implode(' AND ', $filters) : '';
            
            // Get total count from remediation_actions with proper joins (exclude completed)
            $sql = "SELECT COUNT(DISTINCT ra.action_id) as total 
                    FROM remediation_actions ra
                    LEFT JOIN action_risk_scores ars ON ra.action_id = ars.action_id
                    LEFT JOIN action_device_links adl ON ra.action_id = adl.action_id
                    LEFT JOIN medical_devices md ON adl.device_id = md.device_id
                    LEFT JOIN assets a ON md.asset_id = a.asset_id
                    LEFT JOIN locations l ON a.location_id = l.location_id
                    $whereClause";
            $stmt = $db->prepare($sql);
            try {
                $stmt->execute($params);
                $total = $stmt->fetch()['total'];
                error_log("Count query successful, total: " . $total);
            } catch (Exception $e) {
                error_log("Count query error: " . $e->getMessage());
                echo json_encode(['success' => false, 'error' => 'Database error: ' . $e->getMessage()]);
                exit;
            }
            
            // Get paginated results from remediation_actions with proper asset and location data
            $sql = "SELECT ra.*, ars.urgency_score, ars.efficiency_score, 
                           CASE WHEN ra.cve_id IS NOT NULL THEN 1 ELSE 0 END as cve_count,
                           v.epss_score, v.epss_percentile, v.epss_date, v.epss_last_updated,
                           -- Count affected devices for this action (exclude completed devices)
                           (SELECT COUNT(DISTINCT adl2.device_id) 
                            FROM action_device_links adl2 
                            WHERE adl2.action_id = ra.action_id 
                              AND (adl2.patch_status IS NULL OR adl2.patch_status != 'Completed')) as affected_device_count,
                           -- Get real device and location info from assets
                           CASE 
                               WHEN a.hostname IS NOT NULL AND a.hostname != '' THEN a.hostname
                               WHEN a.asset_tag IS NOT NULL AND a.asset_tag != '' THEN a.asset_tag
                               WHEN md.brand_name IS NOT NULL THEN md.brand_name || ' ' || COALESCE(md.model_number, '') || ' (' || COALESCE(md.manufacturer_name, '') || ')'
                               WHEN a.asset_type IS NOT NULL THEN a.asset_type || ' ' || COALESCE(a.manufacturer, '') || ' ' || COALESCE(a.model, '')
                               ELSE 'Unidentified Device'
                           END as device_name,
                           COALESCE(a.hostname, 'N/A') as hostname,
                           COALESCE(a.ip_address::text, 'N/A') as ip_address,
                           COALESCE(a.criticality, 'High') as asset_criticality,
                           COALESCE(l.location_name, 'Location Not Mapped') as location_name,
                           COALESCE(l.criticality, 5) as location_criticality,
                           -- Calculate tier using same logic as cards
                           CASE 
                               WHEN ars.urgency_score >= 1000 THEN 1
                               WHEN ars.urgency_score >= 180 THEN 2
                               WHEN ars.urgency_score >= 160 THEN 3
                               ELSE 4
                           END as priority_tier,
                           -- Add missing fields for compatibility
                           COALESCE(v.severity, 'High') as severity,
                           ars.urgency_score as calculated_risk_score,
                           ra.action_id as link_id,
                           ra.assigned_to,
                           ra.due_date,
                           ra.created_at,
                           ra.status,
                           ra.action_description,
                           ra.cve_id
                    FROM remediation_actions ra
                    LEFT JOIN action_risk_scores ars ON ra.action_id = ars.action_id
                    LEFT JOIN vulnerabilities v ON ra.cve_id = v.cve_id
                    LEFT JOIN action_device_links adl ON ra.action_id = adl.action_id
                    LEFT JOIN medical_devices md ON adl.device_id = md.device_id
                    LEFT JOIN assets a ON md.asset_id = a.asset_id
                    LEFT JOIN locations l ON a.location_id = l.location_id
                    $whereClause
                    ORDER BY priority_tier ASC, ars.urgency_score DESC, ra.due_date ASC
                    LIMIT ? OFFSET ?";
            $params[] = $limit;
            $params[] = $offset;
            
            $stmt = $db->prepare($sql);
            try {
                $stmt->execute($params);
                $priorities = $stmt->fetchAll();
                error_log("Main query successful, found " . count($priorities) . " priorities");
            } catch (Exception $e) {
                error_log("Main query error: " . $e->getMessage());
                echo json_encode(['success' => false, 'error' => 'Database error: ' . $e->getMessage()]);
                exit;
            }
            
            echo json_encode([
                'success' => true,
                'data' => $priorities,
                'total' => $total,
                'page' => $page,
                'limit' => $limit
            ]);
            exit;
            
        case 'get_departments':
            $sql = "SELECT DISTINCT department 
                    FROM risk_priority_view 
                    WHERE department IS NOT NULL 
                    ORDER BY department";
            $stmt = $db->query($sql);
            $departments = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            echo json_encode(['success' => true, 'data' => $departments]);
            exit;
            
        case 'get_locations':
            $sql = "SELECT DISTINCT location_id, location_name 
                    FROM risk_priority_view 
                    WHERE location_id IS NOT NULL 
                    ORDER BY location_name";
            $stmt = $db->query($sql);
            $locations = $stmt->fetchAll();
            
            echo json_encode(['success' => true, 'data' => $locations]);
            exit;
            
        case 'get_epss_stats':
            // Use standardized vulnerability statistics service
            require_once __DIR__ . '/../../includes/vulnerability-stats.php';
            $vulnStats = new VulnerabilityStats();
            
            // Get comprehensive vulnerability statistics
            $comprehensiveStats = $vulnStats->getComprehensiveStats();
            
            if ($comprehensiveStats['success']) {
                $stats = $comprehensiveStats['data'];
                
                // Get EPSS statistics with standardized approach
                $sql = "SELECT 
                    COUNT(*) as total_vulnerabilities,
                    COUNT(CASE WHEN epss_score IS NOT NULL THEN 1 END) as vulnerabilities_with_epss,
                    COUNT(CASE WHEN epss_score >= 0.7 THEN 1 END) as high_epss_count,
                    COUNT(CASE WHEN epss_score >= 0.3 AND epss_score < 0.7 THEN 1 END) as medium_epss_count,
                    COUNT(CASE WHEN epss_score < 0.3 THEN 1 END) as low_epss_count,
                    ROUND(AVG(epss_score), 4) as avg_epss_score,
                    ROUND(AVG(epss_percentile), 4) as avg_epss_percentile,
                    MAX(epss_last_updated) as last_epss_update
                FROM vulnerabilities 
                WHERE epss_score IS NOT NULL";
                
                $stmt = $db->query($sql);
                $epss_stats = $stmt->fetch();
                
                // Override with standardized counts
                $epss_stats['total_vulnerabilities'] = $stats['unique_vulnerabilities']['count'];
                $epss_stats['vulnerabilities_with_epss'] = $stats['vulnerabilities_with_epss']['count'];
                
                echo json_encode([
                    'success' => true, 
                    'data' => [
                        'overall' => $epss_stats,
                        'standardized_stats' => $stats,
                        'debug' => [
                            'total_vulnerabilities_in_db' => $stats['unique_vulnerabilities']['count'],
                            'device_vulnerability_links' => $stats['device_vulnerability_links']['count'],
                            'vulnerabilities_with_epss' => $stats['vulnerabilities_with_epss']['count']
                        ]
                    ]
                ]);
            } else {
                // Fallback to original query if service fails
                $sql = "SELECT 
                    COUNT(*) as total_vulnerabilities,
                    COUNT(CASE WHEN epss_score IS NOT NULL THEN 1 END) as vulnerabilities_with_epss,
                    COUNT(CASE WHEN epss_score >= 0.7 THEN 1 END) as high_epss_count,
                    COUNT(CASE WHEN epss_score >= 0.3 AND epss_score < 0.7 THEN 1 END) as medium_epss_count,
                    COUNT(CASE WHEN epss_score < 0.3 THEN 1 END) as low_epss_count,
                    ROUND(AVG(epss_score), 4) as avg_epss_score,
                    ROUND(AVG(epss_percentile), 4) as avg_epss_percentile,
                    MAX(epss_last_updated) as last_epss_update
                FROM vulnerabilities 
                WHERE epss_score IS NOT NULL";
                
                $stmt = $db->query($sql);
                $epss_stats = $stmt->fetch();
                
                // Debug: Also get total vulnerabilities count
                $total_sql = "SELECT COUNT(*) as total FROM vulnerabilities";
                $total_stmt = $db->query($total_sql);
                $total_count = $total_stmt->fetch()['total'];
                
                echo json_encode([
                    'success' => true, 
                    'data' => [
                        'overall' => $epss_stats,
                        'debug' => [
                            'total_vulnerabilities_in_db' => $total_count,
                            'vulnerabilities_with_epss' => $epss_stats['vulnerabilities_with_epss']
                        ]
                    ]
                ]);
            }
            exit;
    }
}

// Get action-based tier statistics (exclude completed and actions with no devices)
$sql = "SELECT 
    CASE 
        WHEN ars.urgency_score >= 1000 THEN 1
        WHEN ars.urgency_score >= 180 THEN 2
        WHEN ars.urgency_score >= 160 THEN 3
        ELSE 4
    END as tier,
    COUNT(*) as count,
    COUNT(CASE WHEN ra.status = 'In Progress' THEN 1 END) as in_progress_count,
    COUNT(CASE WHEN ra.status = 'Pending' THEN 1 END) as pending_count,
    COUNT(CASE WHEN ra.assigned_to IS NOT NULL THEN 1 END) as assigned_count,
    COUNT(CASE WHEN ra.due_date < CURRENT_DATE AND ra.status != 'Completed' THEN 1 END) as overdue_count
FROM remediation_actions ra
LEFT JOIN action_risk_scores ars ON ra.action_id = ars.action_id
WHERE ra.status != 'Completed'
  AND EXISTS (SELECT 1 FROM action_device_links adl WHERE adl.action_id = ra.action_id)
GROUP BY 
    CASE 
        WHEN ars.urgency_score >= 1000 THEN 1
        WHEN ars.urgency_score >= 180 THEN 2
        WHEN ars.urgency_score >= 160 THEN 3
        ELSE 4
    END
ORDER BY tier";

$stmt = $db->query($sql);
$tierStats = [];
$totalActions = 0;

while ($row = $stmt->fetch()) {
    $tier = $row['tier'];
    $tierStats[$tier] = [
        'total_count' => $row['count'],
        'in_progress_count' => $row['in_progress_count'],
        'pending_count' => $row['pending_count'],
        'assigned_count' => $row['assigned_count'],
        'overdue_count' => $row['overdue_count']
    ];
    $totalActions += $row['count'];
}

// Calculate percentages
foreach ($tierStats as $tier => &$stats) {
    $stats['percentage'] = $totalActions > 0 ? round(($stats['total_count'] / $totalActions) * 100, 1) : 0;
}

// Get KEV action statistics (exclude completed)
// KEV actions may not have device links yet, so we don't require them for KEV stats
$sql = "SELECT 
    COUNT(*) as total_kev_actions,
    COUNT(CASE WHEN ra.status = 'In Progress' THEN 1 END) as in_progress_kev_actions,
    COUNT(CASE WHEN ra.status = 'Pending' THEN 1 END) as pending_kev_actions,
    COUNT(CASE WHEN ra.due_date < CURRENT_DATE AND ra.status != 'Completed' THEN 1 END) as overdue_kev_actions,
    SUM(ars.kev_count) as total_kev_devices
FROM remediation_actions ra
INNER JOIN action_risk_scores ars ON ra.action_id = ars.action_id
WHERE ars.kev_count > 0 
  AND ra.status != 'Completed'";

$stmt = $db->query($sql);
$kevStats = $stmt->fetch();

// Get user's action assignments count (exclude completed and actions with no devices)
$sql = "SELECT COUNT(*) as my_assignments 
        FROM remediation_actions ra
        WHERE ra.assigned_to = ? 
          AND ra.status != 'Completed'
          AND EXISTS (SELECT 1 FROM action_device_links adl WHERE adl.action_id = ra.action_id)";
$stmt = $db->prepare($sql);
$stmt->execute([$user['user_id']]);
$myAssignments = $stmt->fetch()['my_assignments'];

// Get list of users for assignment dropdown
$sql = "SELECT user_id, username, email FROM users WHERE is_active = TRUE ORDER BY username";
$stmt = $db->query($sql);
$users = $stmt->fetchAll();

// Get actions data for the dashboard
$actionsData = [];
try {
    $sql = "SELECT 
                ra.action_id,
                ra.action_type,
                ra.action_description,
                ars.urgency_score,
                ars.efficiency_score,
                ars.affected_device_count,
                CASE WHEN ra.cve_id IS NOT NULL THEN 1 ELSE 0 END as cve_count,
                CASE 
                    WHEN ars.urgency_score >= 1000 THEN 1
                    WHEN ars.urgency_score >= 180 THEN 2
                    WHEN ars.urgency_score >= 160 THEN 3
                    ELSE 4
                END as priority_tier,
                -- KEV flag: true if action has affected devices with KEV vulnerability (ars.kev_count > 0)
                -- This matches the logic in action_priority_view
                CASE WHEN ars.kev_count > 0 THEN true ELSE false END as is_kev,
                ra.status,
                ra.assigned_to,
                ra.due_date,
                ra.created_at
            FROM remediation_actions ra
            LEFT JOIN action_risk_scores ars ON ra.action_id = ars.action_id
            LEFT JOIN vulnerabilities v ON ra.cve_id = v.cve_id
            WHERE EXISTS (SELECT 1 FROM action_device_links adl WHERE adl.action_id = ra.action_id)
            ORDER BY 
                CASE 
                    WHEN ars.urgency_score >= 1000 THEN 1
                    WHEN ars.urgency_score >= 180 THEN 2
                    WHEN ars.urgency_score >= 160 THEN 3
                    ELSE 4
                END ASC, 
                ars.urgency_score DESC, 
                ars.efficiency_score DESC
            LIMIT 1000";
    
    $stmt = $db->getConnection()->prepare($sql);
    $stmt->execute();
    $actionsData = $stmt->fetchAll();
} catch (Exception $e) {
    error_log("Error fetching actions data: " . $e->getMessage());
    $actionsData = [];
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Risk Priority Management - </title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/priority-badges.css">
    <link rel="stylesheet" href="/assets/css/epss-badges.css">
    <link rel="stylesheet" href="/assets/css/remediation-actions.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Siemens Healthineers Brand Color Variables */
        :root {
            --siemens-petrol: #009999;
            --siemens-petrol-dark: #007777;
            --siemens-petrol-light: #00bbbb;
            --siemens-orange: #ff6b35;
            --siemens-orange-dark: #e55a2b;
            --siemens-orange-light: #ff8c5a;
        }
        
        /* Siemens Healthineers Typography */
        body, .priorities-header, .table-controls, .btn-action, .devices-badge, .status-badge {
            font-family: 'Siemens Sans', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        /* Dark Theme Risk Priority Management Styles */
        .priorities-header {
            margin-bottom: 2rem;
            margin-top: 3rem;
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 2rem;
        }
        
        .header-text {
            flex: 1;
        }
        
        .header-actions {
            display: flex;
            gap: 0.5rem;
            flex-shrink: 0;
            background: var(--bg-card, #1a1a1a);
            padding: 0.5rem;
            border-radius: 0.5rem;
            border: 1px solid var(--border-primary, #333333);
        }
        
        .priorities-header h1 {
            font-size: 2rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.5rem;
        }
        
        .priorities-header .subtitle {
            color: var(--text-secondary, #cbd5e1);
            font-size: 1rem;
        }
        
        .filter-section {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        
        .filter-section h3 {
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--text-primary, #ffffff);
        }
        
        .filter-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        
        .filter-group {
            display: flex;
            flex-direction: column;
        }
        
        .filter-group label {
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-secondary, #cbd5e1);
            margin-bottom: 0.375rem;
        }
        
        .filter-group select,
        .filter-group input {
            padding: 0.5rem 0.75rem;
            border: 1px solid var(--border-primary, #333333);
            background: var(--bg-secondary, #0f0f0f);
            color: var(--text-primary, #ffffff);
            border-radius: 0.375rem;
            font-size: 0.875rem;
        }
        
        .filter-group select:focus,
        .filter-group input:focus {
            outline: none;
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.2);
        }
        
        .filter-actions {
            display: flex;
            gap: 0.75rem;
            margin-top: 1rem;
        }
        
        .priorities-table {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            min-width: 1400px;
            margin: 0 auto;
            max-width: 100%;
        }
        
        /* Center the main container and its contents */
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 1rem;
        }
        
        /* Ensure all cards match the 1400px width */
        .priority-tiers {
            max-width: 1400px;
            min-width: 1400px;
            margin-left: auto;
            margin-right: auto;
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 0.75rem;
        }
        
        /* Consolidate tier cards - make them more compact for 4x4 layout */
        .tier-card {
            padding: 0.75rem;
            min-height: auto;
        }
        
        .tier-card-header {
            margin-bottom: 0.5rem;
        }
        
        .tier-card h3 {
            font-size: 0.8rem;
            line-height: 1.1;
        }
        
        .tier-card .metric-value {
            font-size: 1.25rem;
            margin: 0.375rem 0;
        }
        
        .tier-description {
            font-size: 0.7rem;
            margin-bottom: 0.5rem;
            line-height: 1.2;
        }
        
        .tier-stats {
            grid-template-columns: repeat(2, 1fr);
            gap: 0.375rem;
            margin: 0.5rem 0;
        }
        
        .tier-stat-label {
            font-size: 0.65rem;
        }
        
        .tier-stat-value {
            font-size: 0.9rem;
        }
        
        .tier-card .btn {
            padding: 0.375rem 0.75rem;
            font-size: 0.8rem;
        }
        
        /* Responsive grid for 6 cards in 4x4 layout */
        @media (min-width: 1400px) {
            .priority-tiers {
                grid-template-columns: repeat(4, 1fr);
            }
        }
        
        @media (max-width: 1399px) and (min-width: 1000px) {
            .priority-tiers {
                grid-template-columns: repeat(3, 1fr);
            }
        }
        
        @media (max-width: 999px) and (min-width: 600px) {
            .priority-tiers {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (max-width: 599px) {
            .priority-tiers {
                grid-template-columns: 1fr;
            }
        }
        
        .filter-section {
            max-width: 1400px;
            min-width: 1400px;
            margin-left: auto;
            margin-right: auto;
        }
        
        /* Modern Filter Design */
        .filters-section {
            max-width: 1400px;
            min-width: 1400px;
            margin-left: auto;
            margin-right: auto;
            margin-bottom: 2rem;
        }
        
        .search-bar-container {
            display: flex;
            gap: 1rem;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .search-input-wrapper {
            position: relative;
            flex: 1;
            max-width: 500px;
        }
        
        .search-input {
            width: 100%;
            padding: 0.75rem 1rem 0.75rem 2.5rem;
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            transition: all 0.2s ease;
        }
        
        .search-input:focus {
            outline: none;
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
        }
        
        .search-icon {
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted, #94a3b8);
            font-size: 0.875rem;
        }
        
        .clear-search-btn {
            position: absolute;
            right: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--text-muted, #94a3b8);
            cursor: pointer;
            padding: 0.25rem;
            border-radius: 0.25rem;
            transition: all 0.2s ease;
        }
        
        .clear-search-btn:hover {
            color: var(--text-primary, #ffffff);
            background: var(--bg-hover, #333333);
        }
        
        .btn-toggle-filters {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1rem;
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            color: var(--text-primary, #ffffff);
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.2s ease;
            white-space: nowrap;
        }
        
        .btn-toggle-filters:hover {
            background: var(--bg-hover, #333333);
            border-color: var(--siemens-petrol, #009999);
        }
        
        .filter-count {
            background: var(--siemens-orange, #ff6b35);
            color: white;
            border-radius: 50%;
            width: 1.25rem;
            height: 1.25rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 600;
            margin-left: 0.25rem;
        }
        
        .filters-panel {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-top: 1rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        
        .filters-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }
        
        .filters-header h4 {
            color: var(--text-primary, #ffffff);
            font-size: 1.125rem;
            font-weight: 600;
            margin: 0;
        }
        
        .btn-clear-filters {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: transparent;
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.375rem;
            color: var(--text-secondary, #cbd5e1);
            cursor: pointer;
            font-size: 0.875rem;
            transition: all 0.2s ease;
        }
        
        .btn-clear-filters:hover {
            background: var(--bg-hover, #333333);
            color: var(--text-primary, #ffffff);
        }
        
        .filters-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
        }
        
        .filter-group {
            display: flex;
            flex-direction: column;
        }
        
        .filter-group label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.5rem;
        }
        
        .filter-select {
            padding: 0.75rem 1rem;
            background: var(--bg-secondary, #333333);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            transition: all 0.2s ease;
        }
        
        .filter-select:focus {
            outline: none;
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
        }
        
        .view-toggle-section {
            max-width: 700px;
            min-width: 700px;
            margin-left: auto;
            margin-right: auto;
        }
        
        /* View toggle as grid item - 2 columns width */
        .view-toggle-grid-item {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            grid-column: span 2;
        }
        
        .tab-container {
            max-width: 1400px;
            min-width: 1400px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .table-container {
            overflow-x: auto;
            overflow-y: visible;
            -webkit-overflow-scrolling: touch;
        }
        
        
        .table-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-primary, #333333);
        }
        
        .table-header h3 {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            margin: 0;
        }
        
        .table-controls {
            display: flex;
            gap: 0.75rem;
            align-items: center;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
            min-width: 100%;
        }
        
        /* Data table specific styling */
        #actions-table, #vulnerabilities-table {
            table-layout: fixed !important;
            width: 100% !important;
            min-width: 1400px; /* Ensure minimum width for proper column spacing */
        }
        
        /* Make table container scrollable on smaller screens */
        .table-container {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }
        
        /* Column width constraints for actions table */
        #actions-table th:nth-child(1), #actions-table td:nth-child(1) { width: 5%; } /* Tier */
        #actions-table th:nth-child(2), #actions-table td:nth-child(2) { width: 32%; } /* Action Description */
        #actions-table th:nth-child(3), #actions-table td:nth-child(3) { width: 10%; } /* Scores (Urgency + Efficiency) */
        #actions-table th:nth-child(4), #actions-table td:nth-child(4) { width: 12%; } /* Affected Devices */
        #actions-table th:nth-child(5), #actions-table td:nth-child(5) { width: 6%; } /* CVE Count */
        #actions-table th:nth-child(6), #actions-table td:nth-child(6) { width: 5%; } /* KEV */
        #actions-table th:nth-child(7), #actions-table td:nth-child(7) { width: 12%; } /* Status */
        #actions-table th:nth-child(8), #actions-table td:nth-child(8) { width: 12%; } /* Assigned To */
        #actions-table th:nth-child(9), #actions-table td:nth-child(9) { width: 8%; } /* Actions */
        
        /* Column width constraints for vulnerabilities table - SEPARATE SCORES */
        #vulnerabilities-table th:nth-child(1), #vulnerabilities-table td:nth-child(1) { width: 7% !important; min-width: 70px; } /* Priority */
        #vulnerabilities-table th:nth-child(2), #vulnerabilities-table td:nth-child(2) { width: 13% !important; min-width: 130px; } /* CVE */
        #vulnerabilities-table th:nth-child(3), #vulnerabilities-table td:nth-child(3) { width: 22% !important; min-width: 180px; } /* Device/Asset */
        #vulnerabilities-table th:nth-child(4), #vulnerabilities-table td:nth-child(4) { width: 14% !important; min-width: 140px; } /* Location */
        #vulnerabilities-table th:nth-child(5), #vulnerabilities-table td:nth-child(5) { width: 8% !important; min-width: 80px; } /* Severity */
        #vulnerabilities-table th:nth-child(6), #vulnerabilities-table td:nth-child(6) { width: 9% !important; min-width: 90px; } /* Risk Score */
        #vulnerabilities-table th:nth-child(7), #vulnerabilities-table td:nth-child(7) { width: 9% !important; min-width: 90px; } /* EPSS Score */
        #vulnerabilities-table th:nth-child(8), #vulnerabilities-table td:nth-child(8) { width: 9% !important; min-width: 90px; } /* Vendor Status */
        #vulnerabilities-table th:nth-child(9), #vulnerabilities-table td:nth-child(9) { width: 9% !important; min-width: 90px; } /* Due Date */
        #vulnerabilities-table th:nth-child(10), #vulnerabilities-table td:nth-child(10) { width: 11% !important; min-width: 110px; } /* Assigned To */
        #vulnerabilities-table th:nth-child(11), #vulnerabilities-table td:nth-child(11) { width: 7% !important; min-width: 70px; } /* Actions */
        
        /* Cell content styling - ISOLATED for each table */
        #actions-table td {
            word-wrap: break-word;
            overflow-wrap: break-word;
            vertical-align: top;
            border-bottom: none;
            padding: 0.5rem 0.25rem;
        }
        
        #vulnerabilities-table td {
            word-wrap: break-word;
            overflow-wrap: break-word;
            vertical-align: top;
            border-bottom: none;
            padding: 0.75rem 0.5rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        /* Allow specific columns to wrap text */
        #vulnerabilities-table td:nth-child(3) { /* Device/Asset */
            white-space: normal;
            overflow: visible;
            text-overflow: initial;
            word-wrap: break-word;
            overflow-wrap: break-word;
            line-height: 1.4;
        }
        
        #vulnerabilities-table td:nth-child(4) { /* Location */
            white-space: normal;
            overflow: visible;
            text-overflow: initial;
            word-wrap: break-word;
            overflow-wrap: break-word;
            line-height: 1.4;
        }
        
        /* Device info styling */
        .device-info {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        .device-name {
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            line-height: 1.2;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .device-details {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        
        .device-hostname {
            color: var(--text-muted, #94a3b8);
            font-size: 0.75rem;
        }
        
        /* Stacked scores styling */
        .scores-stacked {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
            align-items: center;
        }
        
        .risk-score {
            font-weight: 600;
            font-size: 0.875rem;
        }
        
        .epss-score {
            font-size: 0.75rem;
        }
        
        /* Remove bottom border from table rows - ISOLATED for each table */
        #actions-table tr {
            border-bottom: none;
        }
        
        #vulnerabilities-table tr {
            border-bottom: none;
        }
        
        /* Add subtle border only between rows - ISOLATED for each table */
        #actions-table tr:not(:last-child) {
            border-bottom: 1px solid var(--border-primary, #333333);
        }
        
        #vulnerabilities-table tr:not(:last-child) {
            border-bottom: 1px solid var(--border-primary, #333333);
        }
        
        /* Modal Styles */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .modal-content {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.75rem;
            max-width: 800px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        }
        
        .modal-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-primary, #333333);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .modal-header h2 {
            margin: 0;
            color: var(--text-primary, #ffffff);
            font-size: 1.25rem;
            font-weight: 600;
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-secondary, #cbd5e1);
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0.25rem;
            border-radius: 0.25rem;
            transition: all 0.2s ease;
        }
        
        .modal-close:hover {
            color: var(--text-primary, #ffffff);
            background: var(--bg-hover, #333333);
        }
        
        .modal-body {
            padding: 1.5rem;
        }
        
        .priority-details {
            color: var(--text-primary, #ffffff);
        }
        
        .detail-section {
            margin-bottom: 2rem;
        }
        
        .detail-section h3 {
            color: var(--siemens-petrol, #009999);
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1rem;
            border-bottom: 1px solid var(--border-primary, #333333);
            padding-bottom: 0.5rem;
        }
        
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }
        
        .detail-item {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        .detail-item label {
            font-weight: 600;
            color: var(--text-secondary, #cbd5e1);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .detail-item p {
            margin: 0;
            color: var(--text-primary, #ffffff);
        }
        
        .priority-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .priority-badge.tier-1 {
            background: #dc2626;
            color: white;
        }
        
        .priority-badge.tier-2 {
            background: #ea580c;
            color: white;
        }
        
        .priority-badge.tier-3 {
            background: #d97706;
            color: white;
        }
        
        .priority-badge.tier-4 {
            background: #6b7280;
            color: white;
        }
        
        .criticality-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .criticality-badge.clinical-high {
            background: #dc2626;
            color: white;
        }
        
        .criticality-badge.business-medium {
            background: #d97706;
            color: white;
        }
        
        .criticality-badge.non-essential {
            background: #6b7280;
            color: white;
        }
        
        .criticality-badge.location-1,
        .criticality-badge.location-2,
        .criticality-badge.location-3 {
            background: #dc2626;
            color: white;
        }
        
        .criticality-badge.location-4,
        .criticality-badge.location-5,
        .criticality-badge.location-6 {
            background: #d97706;
            color: white;
        }
        
        .criticality-badge.location-7,
        .criticality-badge.location-8,
        .criticality-badge.location-9,
        .criticality-badge.location-10 {
            background: #6b7280;
            color: white;
        }
        
        /* Action description cell styling */
        .action-description {
            max-width: 100%;
            word-wrap: break-word;
            overflow-wrap: break-word;
            hyphens: auto;
        }
        
        .action-description .action-title {
            word-wrap: break-word;
            overflow-wrap: break-word;
            white-space: normal;
            line-height: 1.4;
        }
        
        .action-description .action-subtitle {
            word-wrap: break-word;
            overflow-wrap: break-word;
            white-space: normal;
            line-height: 1.3;
        }
        
        .action-title {
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.25rem;
            display: flex;
            align-items: flex-start;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        
        .action-icon {
            flex-shrink: 0;
            width: 1.5rem;
            height: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--siemens-petrol, #009999);
            border-radius: 0.25rem;
            color: white;
            font-size: 0.75rem;
        }
        
        .action-subtitle {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
        }
        
        /* Score cells */
        .scores-cell {
            text-align: left;
            vertical-align: middle;
        }

        .score-row {
            margin-bottom: 0.5rem;
        }

        .score-row:last-child {
            margin-bottom: 0;
        }

        .score-value {
            font-weight: 600;
            font-size: 0.875rem;
            display: block;
        }

        .score-value.urgency {
            color: var(--siemens-orange);
        }

        .score-value.efficiency {
            color: var(--siemens-petrol);
        }

        .score-description {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
            display: block;
            margin-top: 0.125rem;
        }
        
        /* Device count badge */
        .devices-badge {
            background: var(--bg-secondary, #0f0f0f);
            border: 1px solid var(--border-primary, #333333);
            color: var(--text-primary, #ffffff);
            padding: 0.25rem 0.5rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-block;
            white-space: nowrap;
            max-width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .devices-badge:hover {
            background: var(--bg-hover, #333333);
            border-color: var(--siemens-petrol);
        }
        
        .devices-badge.expanded {
            background: var(--siemens-petrol);
            border-color: var(--siemens-petrol);
        }
        
        /* Devices cell styling */
        .devices-cell {
            max-width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        /* Device details table styling */
        .devices-table {
            width: 100%;
            border-collapse: collapse;
            margin: 0;
            background: var(--bg-secondary, #1a1a1a);
        }
        
        .devices-table th {
            background: var(--bg-tertiary, #333333);
            color: var(--text-primary, #ffffff);
            padding: 0.75rem 0.5rem;
            text-align: left;
            font-weight: 600;
            font-size: 0.875rem;
            border-bottom: 1px solid var(--border-primary, #333333);
        }
        
        .devices-table td {
            padding: 0.75rem 0.5rem;
            border-bottom: 1px solid var(--border-primary, #333333);
            vertical-align: middle;
        }
        
        /* Extra padding for device name and location columns - OVERRIDE external CSS */
        .devices-details .devices-table td:nth-child(1), 
        .devices-details .devices-table td:nth-child(2) {
            padding-left: 1rem !important;
            padding-right: 1rem !important;
        }
        
        /* Compact padding for smaller columns - OVERRIDE external CSS */
        .devices-details .devices-table td:nth-child(3), 
        .devices-details .devices-table td:nth-child(4), 
        .devices-details .devices-table td:nth-child(5), 
        .devices-details .devices-table td:nth-child(6) {
            padding-left: 0.5rem !important;
            padding-right: 0.5rem !important;
        }
        
        /* Device table column widths - optimized for content - OVERRIDE external CSS */
        .devices-details .devices-table th:nth-child(1), 
        .devices-details .devices-table td:nth-child(1) { 
            width: 35% !important; 
        } /* Device */
        
        .devices-details .devices-table th:nth-child(2), 
        .devices-details .devices-table td:nth-child(2) { 
            width: 20% !important; 
        } /* Location */
        
        .devices-details .devices-table th:nth-child(3), 
        .devices-details .devices-table td:nth-child(3) { 
            width: 12% !important; 
        } /* Criticality */
        
        .devices-details .devices-table th:nth-child(4), 
        .devices-details .devices-table td:nth-child(4) { 
            width: 10% !important; 
        } /* Risk Score */
        
        .devices-details .devices-table th:nth-child(5), 
        .devices-details .devices-table td:nth-child(5) { 
            width: 10% !important; 
        } /* Status */
        
        .devices-details .devices-table th:nth-child(6), 
        .devices-details .devices-table td:nth-child(6) { 
            width: 13% !important; 
        } /* Actions */
        
        /* Device name styling */
        .device-name {
            font-weight: 600;
            color: var(--text-primary, #ffffff);
            margin-bottom: 0.25rem;
        }
        
        .device-location {
            color: var(--text-secondary, #cbd5e1);
            font-size: 0.875rem;
        }
        
        /* Device risk score styling */
        .device-risk-score {
            font-weight: 600;
            font-size: 0.875rem;
            text-align: center;
        }
        
        .device-risk-score.drives-urgency {
            color: var(--siemens-orange, #ff6b35);
        }
        
        /* Action button in device table */
        .devices-table .btn-action {
            width: 100%;
            padding: 0.5rem 0.75rem;
            font-size: 0.75rem;
            white-space: nowrap;
        }
        
        /* CVE count */
        .cve-count {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
        }
        
        /* Status badges */
        .status-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 500;
            white-space: nowrap;
        }
        
        .status-badge.in-progress {
            background: #fbbf24;
            color: #000000;
        }
        
        .status-badge.pending {
            background: #6b7280;
            color: #ffffff;
        }
        
        .status-badge.completed {
            background: #10b981;
            color: #ffffff;
        }
        
        /* Assignment dropdown */
        .assign-select {
            background: var(--bg-secondary, #0f0f0f);
            border: 1px solid var(--border-primary, #333333);
            color: var(--text-primary, #ffffff);
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            width: 100%;
        }
        
        /* Action buttons - ensure clicks work */
        .btn-action {
            background: var(--siemens-petrol) !important;
            color: white !important;
            border: none !important;
            padding: 0.25rem 0.5rem !important;
            border-radius: 0.25rem !important;
            font-size: 0.75rem !important;
            cursor: pointer !important;
            transition: all 0.2s ease !important;
            white-space: nowrap !important;
            pointer-events: auto !important;
            position: relative !important;
            z-index: 1000 !important;
            display: inline-block !important;
            text-decoration: none !important;
        }

        .btn-action:hover {
            background: var(--siemens-petrol-dark) !important;
            transform: translateY(-1px) !important;
        }
        
        /* Ensure buttons in action rows are clickable */
        .action-row td button.btn-action {
            pointer-events: auto !important;
        }
        
        /* Table controls styling */
        .table-controls {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .table-controls select {
            background: var(--bg-secondary, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            color: var(--text-primary, #ffffff);
            padding: 0.5rem 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .table-controls select:hover {
            border-color: var(--siemens-petrol);
        }
        
        .table-controls select:focus {
            outline: none;
            border-color: var(--siemens-petrol);
            box-shadow: 0 0 0 2px rgba(0, 153, 153, 0.2);
        }
        
        thead {
            background-color: var(--bg-secondary, #0f0f0f);
        }
        
        th {
            padding: 1rem 0.75rem;
            text-align: left;
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted, #94a3b8);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            white-space: nowrap;
            border-bottom: 2px solid var(--border-primary, #333333);
        }
        
        /* Improved column widths for better content display */
        th:nth-child(1), td:nth-child(1) { 
            width: 12%; 
            min-width: 120px;
        }  /* Priority */
        th:nth-child(2), td:nth-child(2) { 
            width: 10%; 
            min-width: 100px;
        } /* CVE */
        th:nth-child(3), td:nth-child(3) { 
            width: 20%; 
            min-width: 200px;
        } /* Device/Asset */
        th:nth-child(4), td:nth-child(4) { 
            width: 15%; 
            min-width: 150px;
        } /* Location */
        th:nth-child(5), td:nth-child(5) { 
            width: 10%; 
            min-width: 100px;
        }  /* Severity */
        th:nth-child(6), td:nth-child(6) { 
            width: 10%; 
            min-width: 100px;
        }  /* Risk Score */
        th:nth-child(7), td:nth-child(7) { 
            width: 12%; 
            min-width: 120px;
        } /* Vendor Status */
        th:nth-child(8), td:nth-child(8) { 
            width: 12%; 
            min-width: 120px;
        } /* Due Date */
        th:nth-child(9), td:nth-child(9) { 
            width: 12%; 
            min-width: 120px;
        } /* Assigned To */
        th:nth-child(10), td:nth-child(10) { 
            width: 7%; 
            min-width: 80px;
        } /* Actions */
        
        td {
            padding: 1rem 0.75rem;
            border-top: 1px solid var(--border-primary, #333333);
            font-size: 0.875rem;
            color: var(--text-primary, #ffffff);
            vertical-align: top;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        
        tbody tr:hover {
            background-color: var(--bg-hover, #222222);
        }
        
        .device-info {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
            max-width: 100%;
        }
        
        .device-name {
            font-weight: 500;
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            line-height: 1.3;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        
        .device-hostname {
            font-size: 0.75rem;
            color: var(--text-muted, #94a3b8);
            line-height: 1.2;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        
        .cve-link {
            color: var(--siemens-petrol, #009999);
            text-decoration: none;
            font-weight: 500;
        }
        
        .cve-link:hover {
            text-decoration: underline;
            color: var(--siemens-petrol-light, #00bbbb);
        }
        
        .action-buttons {
            display: flex;
            gap: 0.25rem;
            justify-content: flex-start;
        }
        
        .btn-icon {
            padding: 0.25rem;
            border: 1px solid var(--border-primary, #333333);
            background: var(--bg-secondary, #0f0f0f);
            color: var(--text-primary, #ffffff);
            border-radius: 0.25rem;
            cursor: pointer;
            transition: all 0.2s;
            min-width: 28px;
            height: 28px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }
        
        .btn-icon svg {
            width: 14px;
            height: 14px;
        }
        
        .btn-icon:hover {
            background: var(--bg-hover, #222222);
            border-color: var(--siemens-petrol, #009999);
        }
        
        .pagination {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--border-primary, #333333);
        }
        
        .pagination-info {
            font-size: 0.875rem;
            color: var(--text-muted, #94a3b8);
        }
        
        .pagination-controls {
            display: flex;
            gap: 0.5rem;
        }
        
        .tab-container {
            border-bottom: 2px solid var(--border-primary, #333333);
            margin-bottom: 2rem;
        }
        
        .tabs {
            display: flex;
            gap: 2rem;
        }
        
        .tab {
            padding: 1rem 0;
            font-weight: 500;
            color: var(--text-muted, #94a3b8);
            cursor: pointer;
            border-bottom: 2px solid transparent;
            margin-bottom: -2px;
            transition: all 0.2s;
        }
        
        .tab:hover {
            color: var(--siemens-petrol, #009999);
        }
        
        .tab.active {
            color: var(--siemens-petrol, #009999);
            border-bottom-color: var(--siemens-petrol, #009999);
        }
        
        /* Responsive Design */
        @media (max-width: 1400px) {
            table {
                min-width: 1000px;
            }
            
            th:nth-child(3), td:nth-child(3) { 
                min-width: 180px;
            } /* Device/Asset */
            
            th:nth-child(4), td:nth-child(4) { 
                min-width: 130px;
            } /* Location */
        }
        
        @media (max-width: 1200px) {
            table {
                min-width: 900px;
            }
            
            th, td {
                padding: 0.75rem 0.5rem;
            }
            
            th:nth-child(3), td:nth-child(3) { 
                min-width: 160px;
            } /* Device/Asset */
            
            th:nth-child(4), td:nth-child(4) { 
                min-width: 120px;
            } /* Location */
        }
        
        @media (max-width: 768px) {
            .filter-grid {
                grid-template-columns: 1fr;
            }
            
            .table-header {
                flex-direction: column;
                gap: 1rem;
                align-items: stretch;
            }
            
            
            .table-controls {
                justify-content: center;
            }
            
            table {
                min-width: 800px;
            }
            
            th, td {
                padding: 0.5rem 0.25rem;
                font-size: 0.8rem;
            }
            
            .device-name {
                font-size: 0.8rem;
            }
            
            .device-hostname {
                font-size: 0.7rem;
            }
        }
        
        /* Notification System */
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 0.5rem;
            padding: 1rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
            z-index: 10000;
            max-width: 400px;
            transform: translateX(100%);
            transition: transform 0.3s ease;
        }

        .notification.show {
            transform: translateX(0);
        }

        .notification-content {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .notification-content i {
            font-size: 1.25rem;
        }

        .notification-success {
            border-left: 4px solid var(--success-green, #10b981);
        }

        .notification-success .notification-content i {
            color: var(--success-green, #10b981);
        }

        .notification-error {
            border-left: 4px solid var(--error-red, #ef4444);
        }

        .notification-error .notification-content i {
            color: var(--error-red, #ef4444);
        }

        .notification-info {
            border-left: 4px solid var(--siemens-petrol, #009999);
        }

        .notification-info .notification-content i {
            color: var(--siemens-petrol, #009999);
        }

        .notification-content span {
            color: var(--text-primary, #ffffff);
            font-size: 0.875rem;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>
    
    <main class="main-content">
        <div class="container">
            <!-- Page Header -->
            <div class="priorities-header">
                <div class="header-content">
                    <div class="header-text">
                        <h1>Risk Priority Management</h1>
                        <p class="subtitle">Tiered vulnerability management with comprehensive remediation tracking</p>
                    </div>
                    <div class="header-actions">
                        <button style="padding: 0.75rem 1.5rem; background: transparent; color: var(--text-secondary, #cbd5e1); border: none; border-radius: 0.375rem; cursor: pointer; font-weight: 500; transition: all 0.2s;" onclick="switchPackageView('package')">
                            <i class="fas fa-boxes"></i> Package View (Recommended)
                        </button>
                        <button class="active" style="padding: 0.75rem 1.5rem; background: var(--siemens-petrol, #009999); color: white; border: none; border-radius: 0.375rem; cursor: pointer; font-weight: 500; transition: all 0.2s;" onclick="switchPackageView('cve')">
                            <i class="fas fa-list"></i> CVE View (Detail)
                        </button>
                    </div>
                </div>
            </div>
            
            
            <!-- Priority Tier Summary Cards -->
            <div class="priority-tiers">
                <!-- Tier 1 Card -->
                <div class="tier-card tier-card-tier-1">
                    <div class="tier-card-header">
                        <h3>Immediate Action Required</h3>
                        <svg class="tier-card-icon" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                        </svg>
                    </div>
                    <div class="metric-value"><?= $tierStats[1]['total_count'] ?? 0 ?></div>
                    <div class="tier-description">Remediation Actions (Urgency Score ≥1000) + KEVs (Score ≥180)</div>
                    <div class="tier-stats">
                        <div class="tier-stat">
                            <span class="tier-stat-label">Overdue</span>
                            <span class="tier-stat-value"><?= $tierStats[1]['overdue_count'] ?? 0 ?></span>
                        </div>
                        <div class="tier-stat">
                            <span class="tier-stat-label">Assigned</span>
                            <span class="tier-stat-value"><?= $tierStats[1]['assigned_count'] ?? 0 ?></span>
                        </div>
                    </div>
                    <button class="btn btn-primary" onclick="filterByTier(1)">View Details</button>
                </div>
                
                <!-- Tier 2 Card -->
                <div class="tier-card tier-card-tier-2">
                    <div class="tier-card-header">
                        <h3>Short-Term Actions</h3>
                        <svg class="tier-card-icon" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                        </svg>
                    </div>
                    <div class="metric-value"><?= $tierStats[2]['total_count'] ?? 0 ?></div>
                    <div class="tier-description">Remediation Actions (Urgency Score ≥180)</div>
                    <div class="tier-stats">
                        <div class="tier-stat">
                            <span class="tier-stat-label">Overdue</span>
                            <span class="tier-stat-value"><?= $tierStats[2]['overdue_count'] ?? 0 ?></span>
                        </div>
                        <div class="tier-stat">
                            <span class="tier-stat-label">Assigned</span>
                            <span class="tier-stat-value"><?= $tierStats[2]['assigned_count'] ?? 0 ?></span>
                        </div>
                    </div>
                    <button class="btn btn-primary" onclick="filterByTier(2)">View Details</button>
                </div>
                
                <!-- Tier 3 Card -->
                <div class="tier-card tier-card-tier-3">
                    <div class="tier-card-header">
                        <h3>Long-Term Actions</h3>
                        <svg class="tier-card-icon" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clip-rule="evenodd" />
                        </svg>
                    </div>
                    <div class="metric-value"><?= $tierStats[3]['total_count'] ?? 0 ?></div>
                    <div class="tier-description">Remediation Actions (Urgency Score ≥160)</div>
                    <div class="tier-stats">
                        <div class="tier-stat">
                            <span class="tier-stat-label">Overdue</span>
                            <span class="tier-stat-value"><?= $tierStats[3]['overdue_count'] ?? 0 ?></span>
                        </div>
                        <div class="tier-stat">
                            <span class="tier-stat-label">Assigned</span>
                            <span class="tier-stat-value"><?= $tierStats[3]['assigned_count'] ?? 0 ?></span>
                        </div>
                    </div>
                    <button class="btn btn-primary" onclick="filterByTier(3)">View Details</button>
                </div>
                
                <!-- Tier 4 Card -->
                <div class="tier-card tier-card-tier-4">
                    <div class="tier-card-header">
                        <h3>Tier 4: Low Priority</h3>
                        <svg class="tier-card-icon" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                        </svg>
                    </div>
                    <div class="metric-value"><?= $tierStats[4]['total_count'] ?? 0 ?></div>
                    <div class="tier-description">Low Risk (Score <160)</div>
                    <div class="tier-stats">
                        <div class="tier-stat">
                            <span class="tier-stat-label">Overdue</span>
                            <span class="tier-stat-value"><?= $tierStats[4]['overdue_count'] ?? 0 ?></span>
                        </div>
                        <div class="tier-stat">
                            <span class="tier-stat-label">Assigned</span>
                            <span class="tier-stat-value"><?= $tierStats[4]['assigned_count'] ?? 0 ?></span>
                        </div>
                    </div>
                    <button class="btn btn-primary" onclick="filterByTier(4)">View Details</button>
                </div>
                
                <!-- KEV Card -->
                <div class="tier-card tier-card-kev">
                    <div class="tier-card-header">
                        <h3>Known Exploited Vulnerabilities (KEVs)</h3>
                        <svg class="tier-card-icon" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                        </svg>
                    </div>
                    <div class="metric-value"><?= $kevStats['total_kev_actions'] ?? 0 ?></div>
                    <div class="tier-description">Known Exploited Vulnerabilities requiring immediate attention</div>
                    <div class="tier-stats">
                        <div class="tier-stat">
                            <span class="tier-stat-label">Affected Devices</span>
                            <span class="tier-stat-value"><?= number_format($kevStats['total_kev_devices'] ?? 0) ?></span>
                        </div>
                        <div class="tier-stat">
                            <span class="tier-stat-label">In Progress</span>
                            <span class="tier-stat-value"><?= $kevStats['in_progress_kev_actions'] ?? 0 ?></span>
                        </div>
                        <div class="tier-stat">
                            <span class="tier-stat-label">Overdue</span>
                            <span class="tier-stat-value"><?= $kevStats['overdue_kev_actions'] ?? 0 ?></span>
                        </div>
                    </div>
                    <button class="btn btn-primary" onclick="filterByKEV()">View KEVs</button>
                </div>
                
                <!-- EPSS Card -->
                <div class="tier-card tier-card-epss">
                    <div class="tier-card-header">
                        <h3>EPSS Risk Assessment</h3>
                        <svg class="tier-card-icon" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd" />
                        </svg>
                    </div>
                    <div class="metric-value" id="epss-total-count">-</div>
                    <div class="tier-description">Exploit Prediction Scoring System risk levels</div>
                    <div class="tier-stats">
                        <div class="tier-stat">
                            <span class="tier-stat-label">High Risk (≥70%)</span>
                            <span class="tier-stat-value" id="epss-high-count">-</span>
                        </div>
                        <div class="tier-stat">
                            <span class="tier-stat-label">Medium Risk (≥30%)</span>
                            <span class="tier-stat-value" id="epss-medium-count">-</span>
                        </div>
                    </div>
                    <button class="btn btn-primary" onclick="filterByEPSS()">View EPSS</button>
                </div>
                
            </div>
            
            <!-- View Tabs -->
            <div class="tab-container">
                <div class="tabs">
                    <div class="tab active" data-view="actions" onclick="switchView('actions')">
                        <i class="fas fa-tasks"></i> Actions (<span id="actions-count">-</span>)
                    </div>
                    <div class="tab" data-view="vulnerabilities" onclick="switchView('vulnerabilities')">
                        <i class="fas fa-bug"></i> Vulnerabilities (<span id="vulnerabilities-count">-</span>)
                    </div>
                </div>
            </div>
            
            <!-- Filters -->
            <div class="filters-section">
                <!-- Search Bar -->
                <div class="search-bar-container">
                    <div class="search-input-wrapper">
                        <i class="fas fa-search search-icon"></i>
                        <input 
                            type="text" 
                            id="search" 
                            class="search-input" 
                            placeholder="Search by CVE, device, location, or description..."
                            autocomplete="off"
                        >
                        <button type="button" id="clearSearch" class="clear-search-btn" style="display: none;">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <button type="button" id="toggleFilters" class="btn-toggle-filters">
                        <i class="fas fa-sliders-h"></i>
                        Filters
                        <span class="filter-count" id="filterCount" style="display: none;"></span>
                    </button>
                </div>

                <!-- Advanced Filters Panel -->
                <div class="filters-panel" id="filtersPanel" style="display: none;">
                    <div class="filters-header">
                        <h4><i class="fas fa-filter"></i> Advanced Filters</h4>
                        <button type="button" id="clearFilters" class="btn-clear-filters">
                            <i class="fas fa-undo"></i> Reset All
                        </button>
                    </div>
                    
                    <div class="filters-grid">
                        <div class="filter-group">
                            <label for="filter-tier">
                                <i class="fas fa-exclamation-triangle"></i> Priority Tier
                            </label>
                            <select id="filter-tier" class="filter-select">
                                <option value="">All Tiers</option>
                                <option value="1">Tier 1 - Immediate</option>
                                <option value="2">Tier 2 - Short-Term</option>
                                <option value="3">Tier 3 - Long-Term</option>
                            </select>
                        </div>
                        
                        <div class="filter-group">
                            <label for="filter-department">
                                <i class="fas fa-building"></i> Department
                            </label>
                            <select id="filter-department" class="filter-select">
                                <option value="">All Departments</option>
                            </select>
                        </div>
                        
                        <div class="filter-group">
                            <label for="filter-location">
                                <i class="fas fa-map-marker-alt"></i> Location
                            </label>
                            <select id="filter-location" class="filter-select">
                                <option value="">All Locations</option>
                            </select>
                        </div>
                        
                        <div class="filter-group">
                            <label for="filter-assigned">
                                <i class="fas fa-user-check"></i> Assignment Status
                            </label>
                            <select id="filter-assigned" class="filter-select">
                                <option value="">All Assignments</option>
                                <option value="assigned">Assigned</option>
                                <option value="unassigned">Unassigned</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Priorities Table -->
            <div class="priorities-table">
                <div class="table-header">
                    <h3>Risk Priorities</h3>
                    <div class="table-controls">
                        <select id="table-limit" onchange="changeLimit()">
                            <option value="10" selected>10 per page</option>
                            <option value="25">25 per page</option>
                            <option value="50">50 per page</option>
                            <option value="100">100 per page</option>
                        </select>
                    </div>
                </div>
                
                <div class="table-container">
                    <!-- Actions View Table -->
                    <table id="actions-table" style="display: table;">
                        <thead>
                            <tr>
                                <th>Tier</th>
                                <th>Action Description</th>
                                <th>Scores</th>
                                <th>Affected Devices</th>
                                <th>CVE</th>
                                <th>KEV</th>
                                <th>Status</th>
                                <th>Assigned To</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="actions-tbody">
                            <tr>
                                <td colspan="10" style="text-align: center; padding: 2rem;">
                                    Loading actions...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                    
                    <!-- Vulnerabilities View Table -->
                    <table id="vulnerabilities-table" style="display: none;">
                        <thead>
                            <tr>
                                <th>Priority</th>
                                <th>CVE</th>
                                <th>Device/Asset</th>
                                <th>Location</th>
                                <th>Severity</th>
                                <th>Risk Score</th>
                                <th>EPSS Score</th>
                                <th>Vendor Status</th>
                                <th>Due Date</th>
                                <th>Assigned To</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="priorities-tbody">
                            <tr>
                                <td colspan="11" style="text-align: center; padding: 2rem;">
                                    Loading priorities...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <div class="pagination">
                    <div class="pagination-info" id="pagination-info">
                        Showing 0 of 0 priorities
                    </div>
                    <div class="pagination-controls" id="pagination-controls">
                        <!-- Pagination buttons will be inserted here -->
                    </div>
                </div>
            </div>
        </div>
    </main>
    
    <!-- Priority Detail Modal (will be loaded dynamically) -->
    <div id="priority-modal" style="display: none;"></div>
    
    <script src="/assets/js/risk-priorities.js"></script>
    <script src="/assets/js/epss-utils.js"></script>
    <script>
        // Make users available to JavaScript
        window.assignUsers = <?php echo json_encode($users); ?>;
        
        let currentPage = 1;
        let currentLimit = 10;
        let currentFilters = {};
        let currentTab = 'all';
        
        // Load vulnerability count
        async function loadVulnerabilityCount() {
            try {
                const response = await fetch('?ajax=get_epss_stats');
                const result = await response.json();
                
                if (result.success && result.data.standardized_stats) {
                    const stats = result.data.standardized_stats;
                    const count = stats.unique_vulnerabilities ? stats.unique_vulnerabilities.count : 0;
                    document.getElementById('vulnerabilities-count').textContent = count.toLocaleString();
                } else {
                    // Fallback to original query
                    const response = await fetch('?ajax=get_epss_stats');
                    const result = await response.json();
                    if (result.success && result.data.debug) {
                        const count = result.data.debug.total_vulnerabilities_in_db || 0;
                        document.getElementById('vulnerabilities-count').textContent = count.toLocaleString();
                    } else {
                        document.getElementById('vulnerabilities-count').textContent = '-';
                    }
                }
            } catch (error) {
                console.error('Error loading vulnerability count:', error);
                document.getElementById('vulnerabilities-count').textContent = '-';
            }
        }

        // Load actions count
        async function loadActionsCount() {
            try {
                const params = new URLSearchParams({
                    ajax: 'get_priorities_list',
                    page: 1,
                    limit: 1
                });
                
                const response = await fetch(`?${params.toString()}`);
                const result = await response.json();
                
                if (result.success) {
                    const count = result.total || 0;
                    document.getElementById('actions-count').textContent = count.toLocaleString();
                } else {
                    document.getElementById('actions-count').textContent = '-';
                }
            } catch (error) {
                console.error('Error loading actions count:', error);
                document.getElementById('actions-count').textContent = '-';
            }
        }

        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {
            loadDepartments();
            loadLocations();
            loadEPSSStats();
            loadVulnerabilityCount();
            loadActionsCount();
            initializeFilters();
            
            // Initialize view buttons based on current page
            updateViewButtons('cve');
            
            // Check for URL parameters and apply filters
            const urlParams = new URLSearchParams(window.location.search);
            const tierParam = urlParams.get('tier');
            
            if (tierParam) {
                // Apply tier filter from URL parameter
                filterByTier(parseInt(tierParam));
            } else {
                // Initialize with actions view
                switchView('actions');
            }
        });
        
        // Initialize filter functionality
        function initializeFilters() {
            const searchInput = document.getElementById('search');
            const clearSearchBtn = document.getElementById('clearSearch');
            const toggleFiltersBtn = document.getElementById('toggleFilters');
            const filtersPanel = document.getElementById('filtersPanel');
            const clearFiltersBtn = document.getElementById('clearFilters');
            
            // Search functionality
            if (searchInput) {
                searchInput.addEventListener('input', function() {
                    if (this.value.length > 0) {
                        clearSearchBtn.style.display = 'block';
                    } else {
                        clearSearchBtn.style.display = 'none';
                    }
                    // Update filter count
                    updateFilterCount();
                    // Trigger search with debounce
                    clearTimeout(window.searchTimeout);
                    window.searchTimeout = setTimeout(() => {
                        applySearch();
                    }, 300);
                });
            }
            
            // Clear search
            if (clearSearchBtn) {
                clearSearchBtn.addEventListener('click', function() {
                    searchInput.value = '';
                    this.style.display = 'none';
                    applySearch();
                });
            }
            
            // Toggle filters panel
            if (toggleFiltersBtn && filtersPanel) {
                toggleFiltersBtn.addEventListener('click', function() {
                    const isVisible = filtersPanel.style.display !== 'none';
                    filtersPanel.style.display = isVisible ? 'none' : 'block';
                    this.classList.toggle('active', !isVisible);
                });
            }
            
            // Clear all filters
            if (clearFiltersBtn) {
                clearFiltersBtn.addEventListener('click', function() {
                    // Clear all filter selects
                    document.querySelectorAll('.filter-select').forEach(select => {
                        select.value = '';
                    });
                    // Clear search
                    if (searchInput) {
                        searchInput.value = '';
                        clearSearchBtn.style.display = 'none';
                    }
                    // Apply filters
                    applyFilters();
                });
            }
            
            // Filter change listeners
            document.querySelectorAll('.filter-select').forEach(select => {
                select.addEventListener('change', function() {
                    updateFilterCount();
                    applyFilters();
                });
            });
        }
        
        // Apply search functionality
        function applySearch() {
            const searchTerm = document.getElementById('search').value;
            currentFilters.search = searchTerm;
            currentPage = 1;
            
            // Load data based on current view
            if (currentView === 'actions') {
                loadActionsList();
            } else {
                loadPrioritiesList();
            }
        }
        
        // Update filter count badge
        function updateFilterCount() {
            const filterCount = document.getElementById('filterCount');
            const searchElement = document.getElementById('search');
            const searchActive = searchElement && searchElement.value.trim() !== '';
            
            let activeFilters = 0;
            document.querySelectorAll('.filter-select').forEach(select => {
                if (select.value !== '') {
                    activeFilters++;
                }
            });
            
            if (searchActive) {
                activeFilters++;
            }
            
            if (activeFilters > 0) {
                filterCount.textContent = activeFilters;
                filterCount.style.display = 'inline';
            } else {
                filterCount.style.display = 'none';
            }
        }
        
        
        // Filter by tier
        function filterByTier(tier) {
            
            // Select Tier in filter dropdown
            const tierSelect = document.getElementById('filter-tier');
            if (tierSelect) {
                tierSelect.value = String(tier);
            }
            
            // Set current filters with tier
            currentFilters = { tier: String(tier) };
            currentPage = 1;
            
            // Ensure actions view is active
            if (currentView !== 'actions') {
                switchView('actions');
            }
            
            // Apply the filter and load data
            loadActionsList();
            
            // Update filter count badge
            updateFilterCount();
            
            // Smooth scroll to the table header area
            const tableHeader = document.querySelector('.table-header') || document.querySelector('.priorities-table .table-header');
            if (tableHeader && typeof tableHeader.scrollIntoView === 'function') {
                tableHeader.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
            
        }
        
        // Sort by tier (alternative to filtering)
        function sortByTier(tier) {
            
            // Load ALL data without any filters
            loadAllPrioritiesForSorting(tier);
        }
        
        // Load all priorities for sorting (no filters)
        async function loadAllPrioritiesForSorting(tier) {
            try {
                const params = new URLSearchParams({
                    ajax: 'get_priorities_list',
                    page: 1,
                    limit: 1000, // Load a large number to get all data
                    // No tier filter - load everything
                });
                
                
                const response = await fetch(`?${params.toString()}`);
                const result = await response.json();
                
                
                if (result.success) {
                    renderPrioritiesTable(result.data);
                    updatePaginationInfo(result.total, result.page, result.limit);
                    renderPaginationControls(result.total, result.page, result.limit);
                    
                    // Sort the table after rendering
                    setTimeout(() => {
                        sortTableByTier(tier);
                    }, 100);
                } else {
                    showError('Failed to load priorities for sorting');
                }
            } catch (error) {
                console.error('Error loading all priorities:', error);
                showError('Error loading priorities for sorting');
            }
        }
        
        // Sort table by tier
        function sortTableByTier(tier) {
            const tableBody = document.getElementById('priorities-tbody');
            if (!tableBody) return;
            
            const rows = Array.from(tableBody.querySelectorAll('tr'));
            
            // Sort rows by tier (tier 1 first, then tier 2, etc.)
            rows.sort((a, b) => {
                const aTier = parseInt(a.dataset.tier || '999');
                const bTier = parseInt(b.dataset.tier || '999');
                
                if (tier === 'all') {
                    return aTier - bTier; // Sort by tier number
                } else {
                    const targetTier = parseInt(tier);
                    if (aTier === targetTier && bTier !== targetTier) return -1;
                    if (bTier === targetTier && aTier !== targetTier) return 1;
                    return aTier - bTier;
                }
            });
            
            // Re-append sorted rows
            rows.forEach(row => tableBody.appendChild(row));
        }
        
        // Filter by KEV
        function filterByKEV() {
            // Redirect to KEV dashboard page
            window.location.href = '/pages/vulnerabilities/kev-dashboard.php';
        }
        
        // Filter by EPSS
        function filterByEPSS() {
            // Redirect to dedicated EPSS dashboard
            window.location.href = '/pages/epss/dashboard.php';
        }
        
        // Apply filters
        function applyFilters() {
            const tierElement = document.getElementById('filter-tier');
            const departmentElement = document.getElementById('filter-department');
            const locationElement = document.getElementById('filter-location');
            const assignedElement = document.getElementById('filter-assigned');
            const searchElement = document.getElementById('search');
            
            if (!tierElement || !departmentElement || !locationElement || !assignedElement) {
                console.error('One or more filter elements not found');
                return;
            }
            
            currentFilters = {
                tier: tierElement.value,
                department: departmentElement.value,
                location: locationElement.value,
                assigned: assignedElement.value,
                search: searchElement ? searchElement.value : ''
            };
            
            
            // Maintain tab-specific filters
            if (currentTab === 'my') {
                currentFilters.assigned = 'my';
            } else if (currentTab === 'overdue') {
                currentFilters.overdue = 'true';
            }
            
            
            currentPage = 1;
            
            // Apply filters based on current view
            if (currentView === 'actions') {
                loadActionsList();
            } else {
                loadPrioritiesList();
            }
        }
        
        // Clear filters
        function clearFilters() {
            document.getElementById('filter-tier').value = '';
            document.getElementById('filter-department').value = '';
            document.getElementById('filter-location').value = '';
            document.getElementById('filter-assigned').value = '';
            
            // Clear search
            const searchElement = document.getElementById('search');
            if (searchElement) {
                searchElement.value = '';
            }
            
            // Hide clear search button
            const clearSearchBtn = document.getElementById('clearSearch');
            if (clearSearchBtn) {
                clearSearchBtn.style.display = 'none';
            }
            
            currentFilters = {};
            currentPage = 1;
            
            // Clear filters based on current view
            if (currentView === 'actions') {
                loadActionsList();
            } else {
                loadPrioritiesList();
            }
        }
        
        // Change limit
        function changeLimit() {
            currentLimit = parseInt(document.getElementById('table-limit').value);
            currentPage = 1;
            if (currentView === 'actions') {
                loadActionsList();
            } else {
                loadPrioritiesList();
            }
        }
        
        // Load departments for filter
        async function loadDepartments() {
            try {
                const response = await fetch('?ajax=get_departments');
                const result = await response.json();
                
                if (result.success) {
                    const select = document.getElementById('filter-department');
                    result.data.forEach(dept => {
                        const option = document.createElement('option');
                        option.value = dept;
                        option.textContent = dept;
                        select.appendChild(option);
                    });
                }
            } catch (error) {
                console.error('Error loading departments:', error);
            }
        }
        
        // Load locations for filter
        async function loadLocations() {
            try {
                const response = await fetch('?ajax=get_locations');
                const result = await response.json();
                
                if (result.success) {
                    const select = document.getElementById('filter-location');
                    result.data.forEach(loc => {
                        const option = document.createElement('option');
                        option.value = loc.location_id;
                        option.textContent = loc.location_name;
                        select.appendChild(option);
                    });
                }
            } catch (error) {
                console.error('Error loading locations:', error);
            }
        }
        
        // Display EPSS statistics
        function displayEPSSStats(result) {
            if (!result.success) {
                throw new Error('API returned error: ' + (result.error || 'Unknown error'));
            }
            
            const stats = result.data?.overall;
            if (!stats) {
                // No EPSS data available
                document.getElementById('epss-total-count').textContent = '0';
                document.getElementById('epss-high-count').textContent = '0';
                document.getElementById('epss-medium-count').textContent = '0';
                return;
            }
            
            const totalEPSS = (stats.high_epss_count || 0) + (stats.medium_epss_count || 0) + (stats.low_epss_count || 0);
            
            document.getElementById('epss-total-count').textContent = totalEPSS;
            document.getElementById('epss-high-count').textContent = stats.high_epss_count || 0;
            document.getElementById('epss-medium-count').textContent = stats.medium_epss_count || 0;
        }
        
        // Load EPSS statistics
        async function loadEPSSStats() {
            try {
                // Try the main EPSS API first
                const response = await fetch('/api/v1/epss/', {
                    method: 'GET',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });
                
                if (!response.ok) {
                    // Try to get error message from response
                    let errorMessage = `HTTP error! status: ${response.status}`;
                    try {
                        const errorText = await response.text();
                        const errorJson = JSON.parse(errorText);
                        errorMessage = errorJson.error || errorMessage;
                    } catch (e) {
                        // Ignore parse errors
                    }
                    throw new Error(errorMessage);
                }
                
                // Check if response is JSON
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    // Try to parse as JSON anyway (some servers don't set content-type correctly)
                    const text = await response.text();
                    try {
                        const result = JSON.parse(text);
                        if (result.success && result.data) {
                            // Successfully parsed JSON, use it
                            displayEPSSStats(result);
                            return;
                        }
                    } catch (e) {
                        // Not JSON, throw error
                    }
                    throw new Error('Response is not JSON. Content-Type: ' + (contentType || 'not set'));
                }
                
                const result = await response.json();
                displayEPSSStats(result);
            } catch (error) {
                console.error('Error loading EPSS stats from API:', error);
                
                // Fallback: Try to get EPSS stats from dashboard endpoint
                try {
                    const fallbackResponse = await fetch('?ajax=get_epss_stats', {
                        method: 'GET',
                        credentials: 'same-origin',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest'
                        }
                    });
                    
                    if (fallbackResponse.ok) {
                        const fallbackResult = await fallbackResponse.json();
                        displayEPSSStats(fallbackResult);
                        return;
                    }
                } catch (fallbackError) {
                    console.error('Error loading EPSS stats from fallback:', fallbackError);
                }
                
                // Set default values when all methods fail
                document.getElementById('epss-total-count').textContent = '-';
                document.getElementById('epss-high-count').textContent = '-';
                document.getElementById('epss-medium-count').textContent = '-';
            }
        }
        
        // Load priorities list
        async function loadPrioritiesList() {
            try {
                const params = new URLSearchParams({
                    ajax: 'get_priorities_list',
                    page: currentPage,
                    limit: currentLimit,
                    ...currentFilters
                });
                
                
                const response = await fetch(`?${params.toString()}`);
                const result = await response.json();
                
                
                if (result.success) {
                    renderPrioritiesTable(result.data);
                    updatePaginationInfo(result.total, result.page, result.limit);
                    renderPaginationControls(result.total, result.page, result.limit);
                } else {
                    showError('Failed to load priorities');
                }
            } catch (error) {
                console.error('Error loading priorities:', error);
                showError('Error loading priorities');
            }
        }
        
        // Render priorities table
        function renderPrioritiesTable(priorities) {
            const tbody = document.getElementById('priorities-tbody');
            
            if (priorities.length === 0) {
                tbody.innerHTML = '<tr><td colspan="11" style="text-align: center; padding: 2rem;">No priorities found</td></tr>';
                return;
            }
            
            tbody.innerHTML = priorities.map(p => `
                <tr data-tier="${p.priority_tier}">
                    <td>
                        ${generatePriorityBadge(p.priority_tier)}
                        ${p.is_kev ? generateKEVBadge() : ''}
                    </td>
                    <td>
                        <a href="#" class="cve-link" onclick="viewPriority('${p.link_id}'); return false;">
                            ${p.cve_id}
                        </a>
                    </td>
                    <td>
                        <div class="device-info">
                            <div class="device-name" title="${(() => {
                                const name = p.device_name || p.original_device_name || p.hostname || (p.brand_name ? `${p.brand_name} ${p.model_number || ''}`.trim() : '') || 'Unidentified Device';
                                return name;
                            })()}">${(() => {
                                const name = p.device_name || p.original_device_name || p.hostname || (p.brand_name ? `${p.brand_name} ${p.model_number || ''}`.trim() : '') || 'Unidentified Device';
                                return name;
                            })()}</div>
                            <div class="device-details">
                                <small class="device-hostname">${p.ip_address || p.hostname || 'No IP'}</small>
                                ${generateCriticalityBadge(p.asset_criticality)}
                            </div>
                        </div>
                    </td>
                    <td>
                        ${p.location_name || 'Location Not Mapped'}
                        ${p.location_criticality ? generateLocationCriticality(p.location_criticality) : ''}
                    </td>
                    <td>
                        <span class="badge badge-${p.severity ? p.severity.toLowerCase() : 'high'}">${p.severity || 'High'}</span>
                    </td>
                    <td>${generateRiskScoreIndicator(p.calculated_risk_score || p.urgency_score || 0)}</td>
                    <td>
                        ${p.epss_score !== null && p.epss_score !== undefined ? 
                            generateEPSSBadge(p.epss_score, p.epss_percentile) : 
                            '<span class="text-muted">N/A</span>'
                        }
                    </td>
                    <td>${generateVendorStatusBadge(p.vendor_status)}</td>
                    <td>
                        ${p.due_date || 'Not Set'}
                        ${p.days_overdue > 0 ? generateOverdueBadge(p.days_overdue) : ''}
                    </td>
                    <td>${p.assigned_to_name || 'Unassigned'}</td>
                    <td>
                        <div class="action-buttons">
                            <button class="btn-icon" type="button" onclick="viewPriority('${p.link_id}', event)" title="View/Edit Details">
                                <svg fill="currentColor" viewBox="0 0 20 20">
                                    <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
                                    <path fill-rule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clip-rule="evenodd" />
                                </svg>
                            </button>
                        </div>
                    </td>
                </tr>
            `).join('');
        }
        
        // Update pagination info
        function updatePaginationInfo(total, page, limit) {
            const start = (page - 1) * limit + 1;
            const end = Math.min(page * limit, total);
            document.getElementById('pagination-info').textContent = 
                `Showing ${start}-${end} of ${total} priorities`;
        }
        
        // Update pagination info for actions
        function updateActionsPaginationInfo(total, page, limit) {
            const start = (page - 1) * limit + 1;
            const end = Math.min(page * limit, total);
            document.getElementById('pagination-info').textContent = 
                `Showing ${start}-${end} of ${total} actions`;
        }
        
        // Render pagination controls
        function renderPaginationControls(total, page, limit) {
            const totalPages = Math.ceil(total / limit);
            const controls = document.getElementById('pagination-controls');
            
            let html = '';
            
            // Previous button
            html += `<button class="btn btn-secondary" ${page === 1 ? 'disabled' : ''} 
                     onclick="changePage(${page - 1})">Previous</button>`;
            
            // Page numbers
            for (let i = Math.max(1, page - 2); i <= Math.min(totalPages, page + 2); i++) {
                html += `<button class="btn ${i === page ? 'btn-primary' : 'btn-secondary'}" 
                         onclick="changePage(${i})">${i}</button>`;
            }
            
            // Next button
            html += `<button class="btn btn-secondary" ${page === totalPages ? 'disabled' : ''} 
                     onclick="changePage(${page + 1})">Next</button>`;
            
            controls.innerHTML = html;
        }
        
        // Change page
        function changePage(page) {
            currentPage = page;
            if (currentView === 'actions') {
                loadActionsList();
            } else {
                loadPrioritiesList();
            }
        }
        
        // View priority details
        function viewPriority(linkId, event) {
            try { if (event) { event.preventDefault(); event.stopPropagation(); } } catch (e) {}
            showPriorityModal(linkId);
            return false;
        }
        
        // Show priority modal
        async function showPriorityModal(linkId) {
            try {
                // Show loading state
                const modal = document.getElementById('priority-modal');
                modal.style.display = 'block';
                modal.innerHTML = `
                    <div class="modal-overlay" onclick="closePriorityModal()">
                        <div class="modal-content" onclick="event.stopPropagation()">
                            <div class="modal-header">
                                <h2>Loading Priority Details...</h2>
                                <button class="modal-close" onclick="closePriorityModal()">&times;</button>
                            </div>
                            <div class="modal-body">
                                <div style="text-align: center; padding: 2rem;">
                                    <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--siemens-petrol, #009999);"></i>
                                    <p style="color: var(--text-secondary, #cbd5e1); margin-top: 1rem;">Loading details...</p>
                                </div>
                            </div>
                        </div>
                    </div>
                `;

                // Fetch priority details
                const response = await fetch(`/pages/risk-priorities/view.php?ajax=get_priority_details&id=${linkId}`);
                const result = await response.json();
                
                if (result.success) {
                    displayPriorityModal(result.data);
                } else {
                    modal.innerHTML = `
                        <div class="modal-overlay" onclick="closePriorityModal()">
                            <div class="modal-content" onclick="event.stopPropagation()">
                                <div class="modal-header">
                                    <h2>Error</h2>
                                    <button class="modal-close" onclick="closePriorityModal()">&times;</button>
                                </div>
                                <div class="modal-body">
                                    <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                                        <i class="fas fa-exclamation-circle"></i> Error loading priority details: ${result.error || 'Unknown error'}
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                }
            } catch (error) {
                console.error('Error loading priority details:', error);
                const modal = document.getElementById('priority-modal');
                modal.innerHTML = `
                    <div class="modal-overlay" onclick="closePriorityModal()">
                        <div class="modal-content" onclick="event.stopPropagation()">
                            <div class="modal-header">
                                <h2>Error</h2>
                                <button class="modal-close" onclick="closePriorityModal()">&times;</button>
                            </div>
                            <div class="modal-body">
                                <div style="background: #ef4444; color: white; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                                    <i class="fas fa-exclamation-circle"></i> Error loading priority details: ${error.message}
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }
        }

        // Display priority modal content
        function displayPriorityModal(priority) {
            const modal = document.getElementById('priority-modal');
            modal.innerHTML = `
                <div class="modal-overlay" onclick="closePriorityModal()">
                    <div class="modal-content" onclick="event.stopPropagation()">
                        <div class="modal-header">
                            <h2>Priority Details: ${priority.cve_id || 'Unknown CVE'}</h2>
                            <button class="modal-close" onclick="closePriorityModal()">&times;</button>
                        </div>
                        <div class="modal-body">
                            <div class="priority-details">
                                <div class="detail-section">
                                    <h3>Vulnerability Information</h3>
                                    <div class="detail-grid">
                                        <div class="detail-item">
                                            <label>CVE ID:</label>
                                            <p><strong>${priority.cve_id || 'N/A'}</strong></p>
                                        </div>
                                        <div class="detail-item">
                                            <label>Severity:</label>
                                            <span class="severity-badge ${priority.severity?.toLowerCase() || 'unknown'}">
                                                ${priority.severity || 'Unknown'}
                                            </span>
                                        </div>
                                        <div class="detail-item">
                                            <label>Risk Score:</label>
                                            <p><strong>${priority.calculated_risk_score || priority.urgency_score || 0}</strong></p>
                                        </div>
                                        <div class="detail-item">
                                            <label>Priority Tier:</label>
                                            <span class="priority-badge tier-${priority.priority_tier || 4}">
                                                Tier ${priority.priority_tier || 4}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="detail-section">
                                    <h3>Device Information</h3>
                                    <div class="detail-grid">
                                        <div class="detail-item">
                                            <label>Device Name:</label>
                                            <p>${priority.device_name || 'Unidentified Device'}</p>
                                        </div>
                                        <div class="detail-item">
                                            <label>Hostname:</label>
                                            <p>${priority.hostname || 'N/A'}</p>
                                        </div>
                                        <div class="detail-item">
                                            <label>IP Address:</label>
                                            <p>${priority.ip_address || 'N/A'}</p>
                                        </div>
                                        <div class="detail-item">
                                            <label>Asset Criticality:</label>
                                            <span class="criticality-badge ${priority.asset_criticality?.toLowerCase().replace('-', '-') || 'unknown'}">
                                                ${priority.asset_criticality || 'Unknown'}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="detail-section">
                                    <h3>Location Information</h3>
                                    <div class="detail-grid">
                                        <div class="detail-item">
                                            <label>Location:</label>
                                            <p>${priority.location_name || 'Location Not Mapped'}</p>
                                        </div>
                                        <div class="detail-item">
                                            <label>Location Criticality:</label>
                                            <span class="criticality-badge location-${priority.location_criticality || 5}">
                                                Level ${priority.location_criticality || 5}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="detail-section">
                                    <h3>Remediation Status</h3>
                                    <div class="detail-grid">
                                        <div class="detail-item">
                                            <label>Status:</label>
                                            <span class="status-badge ${priority.status?.toLowerCase().replace(' ', '-') || 'unknown'}">
                                                ${priority.status || 'Unknown'}
                                            </span>
                                        </div>
                                        <div class="detail-item">
                                            <label>Assigned To:</label>
                                            <p>${priority.assigned_to_name || 'Unassigned'}</p>
                                        </div>
                                        <div class="detail-item">
                                            <label>Due Date:</label>
                                            <p>${priority.due_date || 'Not Set'}</p>
                                        </div>
                                        <div class="detail-item">
                                            <label>Action Description:</label>
                                            <p>${priority.action_description || 'No description available'}</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        // Close priority modal
        function closePriorityModal() {
            document.getElementById('priority-modal').style.display = 'none';
        }

        // Edit priority
        // Notification System
        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <div class="notification-content">
                    <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                    <span>${message}</span>
                </div>
            `;
            document.body.appendChild(notification);
            setTimeout(() => notification.classList.add('show'), 100);
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        }

        function editPriority(linkId) {
            // Edit functionality not yet implemented
            showNotification('Edit functionality is not yet available. Please contact your administrator.', 'info');
        }
        
        // Switch between package and CVE views
        function switchPackageView(view) {
            localStorage.setItem('risk_priority_view', view);
            
            if (view === 'package') {
                window.location.href = '/pages/risk-priorities/software-packages.php';
            } else if (view === 'cve') {
                // Already on CVE view, just update the UI
                updateViewButtons(view);
            }
        }
        
        // Update view button states
        function updateViewButtons(activeView) {
            const buttons = document.querySelectorAll('.header-actions button');
            buttons.forEach(button => {
                button.classList.remove('active');
                if (button.textContent.includes('Package View') && activeView === 'package') {
                    button.classList.add('active');
                } else if (button.textContent.includes('CVE View') && activeView === 'cve') {
                    button.classList.add('active');
                }
            });
        }
        
        // Refresh risk priorities (admin only)
        async function refreshRiskPriorities() {
            showRefreshConfirmationModal();
        }

        function showRefreshConfirmationModal() {
            const modal = document.createElement('div');
            modal.className = 'modal';
            modal.id = 'refresh-confirmation-modal';
            modal.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10001;
            `;
            
            modal.innerHTML = `
                <div style="
                    background: var(--bg-card, #1a1a1a);
                    border: 1px solid var(--border-primary, #333333);
                    border-radius: 0.75rem;
                    max-width: 400px;
                    width: 90%;
                    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
                ">
                    <div style="
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 1.5rem;
                        border-bottom: 1px solid var(--border-primary, #333333);
                        background: var(--bg-secondary, #0f0f0f);
                    ">
                        <h2 style="margin: 0; color: var(--text-primary, #ffffff);">Refresh Risk Priorities</h2>
                        <button onclick="document.getElementById('refresh-confirmation-modal').remove()" style="
                            background: transparent;
                            border: none;
                            color: var(--text-secondary, #cbd5e1);
                            font-size: 1.5rem;
                            cursor: pointer;
                            padding: 0.5rem;
                        ">×</button>
                    </div>
                    <div style="padding: 1.5rem;">
                        <div style="margin-bottom: 1.5rem;">
                            <div style="
                                display: flex;
                                align-items: center;
                                gap: 1rem;
                                margin-bottom: 1rem;
                            ">
                                <i class="fas fa-sync-alt" style="
                                    font-size: 2rem;
                                    color: var(--siemens-petrol, #009999);
                                "></i>
                                <div>
                                    <h3 style="margin: 0; color: var(--text-primary, #ffffff);">Confirm Refresh</h3>
                                    <p style="margin: 0.5rem 0 0 0; color: var(--text-secondary, #cbd5e1);">
                                        Refresh the risk priority view? This will recalculate all priority scores.
                                    </p>
                                </div>
                            </div>
                        </div>
                        <div style="display: flex; gap: 0.75rem; justify-content: flex-end;">
                            <button onclick="document.getElementById('refresh-confirmation-modal').remove()" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--bg-secondary, #0f0f0f);
                                color: var(--text-secondary, #cbd5e1);
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Cancel</button>
                            <button onclick="confirmRefreshRiskPriorities()" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--siemens-petrol, #009999);
                                color: white;
                                border: none;
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Refresh</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
        }

        async function confirmRefreshRiskPriorities() {
            // Close the refresh confirmation modal
            const refreshModal = document.getElementById('refresh-confirmation-modal');
            if (refreshModal) {
                refreshModal.remove();
            }
            
            try {
                const response = await fetch('/pages/risk-priorities/refresh-priorities.php', {
                    method: 'POST'
                });
                const result = await response.json();
                
                if (result.success) {
                    showNotification('Risk priorities refreshed successfully', 'success');
                    location.reload();
                } else {
                    showNotification('Failed to refresh: ' + result.error, 'error');
                }
            } catch (error) {
                showNotification('Error refreshing priorities: ' + error.message, 'error');
            }
        }
        
        // View switching functionality
        let currentView = 'actions'; // Default to actions view
        
        function switchView(view) {
            currentView = view;
            
            // Update main tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelector(`[data-view="${view}"]`).classList.add('active');
            
            // Show/hide appropriate tables
            const actionsTable = document.getElementById('actions-table');
            const vulnerabilitiesTable = document.getElementById('vulnerabilities-table');
            
            if (view === 'actions') {
                actionsTable.style.display = 'table';
                vulnerabilitiesTable.style.display = 'none';
                loadActionsList();
            } else {
                actionsTable.style.display = 'none';
                vulnerabilitiesTable.style.display = 'table';
                loadPrioritiesList(); // Use existing function
            }
        }
        
        // Load actions list
        async function loadActionsList() {
            try {
                // Validate current state
                if (typeof currentFilters === 'undefined') {
                    currentFilters = {};
                }
                if (typeof currentPage === 'undefined') {
                    currentPage = 1;
                }
                if (typeof currentLimit === 'undefined') {
                    currentLimit = 10;
                }
                
                // Use API endpoint with filters
                const params = new URLSearchParams({
                    ajax: 'get_priorities_list',
                    page: currentPage,
                    limit: currentLimit,
                    ...currentFilters
                });
                
                
                const response = await fetch(`?${params.toString()}`);
                const result = await response.json();
                
                
                if (result.success) {
                    displayActions(result.data);
                    updatePaginationInfo(result.total, result.page, result.limit);
                    renderPaginationControls(result.total, result.page, result.limit);
                } else {
                    throw new Error(result.message || 'Failed to load actions');
                }
            } catch (error) {
                console.error('Error in loadActionsList:', error);
                showError('Error loading actions: ' + error.message);
            }
        }
        
        // Display actions in table
        function displayActions(actions) {
            try {
                const tbody = document.getElementById('actions-tbody');
                
                // Validate inputs
                if (!tbody) {
                    throw new Error('Actions table body not found');
                }
                
                if (!Array.isArray(actions)) {
                    throw new Error('Actions data must be an array');
                }
                
                if (actions.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 2rem;">No actions found</td></tr>';
                    return;
                }
            
            tbody.innerHTML = actions.map(action => `
                <tr class="action-row tier-${action.priority_tier}" data-action-id="${action.action_id}">
                    <td>
                        <span class="tier-badge tier-${action.priority_tier}">${action.priority_tier}</span>
                    </td>
                    <td class="action-description">
                        <div class="action-title">
                            ${action.action_description || 'No description available'}
                        </div>
                        <div class="action-subtitle">${action.cve_id || 'N/A'}</div>
                    </td>
                    <td class="scores-cell">
                        <div class="score-row">
                            <div class="score-value urgency">${action.urgency_score.toLocaleString()}</div>
                            <div class="score-description">Urgency</div>
                        </div>
                        <div class="score-row">
                            <div class="score-value efficiency">${action.efficiency_score.toLocaleString()}</div>
                            <div class="score-description">Efficiency</div>
                        </div>
                    </td>
                    <td class="devices-cell">
                        <button class="devices-badge" onclick="toggleDevices('${action.action_id}')">
                            <i class="fas fa-server"></i> ${action.affected_device_count} devices
                            <i class="fas fa-chevron-down"></i>
                        </button>
                    </td>
                    <td>
                        <span class="cve-count">${action.cve_count || 0} CVE${(action.cve_count || 0) !== 1 ? 's' : ''}</span>
                    </td>
                    <td>
                        ${action.is_kev ? '<span class="kev-badge">KEV</span>' : '-'}
                    </td>
                    <td>
                        <span class="status-badge ${action.status.toLowerCase().replace(' ', '-')}">${action.status}</span>
                    </td>
                    <td>
                        <select class="assign-select" onchange="assignAction('${action.action_id}', this.value)">
                            <option value="">Unassigned</option>
                            ${(window.assignUsers || []).map(user => 
                                `<option value="${user.user_id}" ${action.assigned_to === user.user_id ? 'selected' : ''}>${user.username}${user.email ? ' (' + user.email + ')' : ''}</option>`
                            ).join('')}
                        </select>
                    </td>
                    <td style="pointer-events: auto !important;">
                        <a href="/pages/risk-priorities/action-detail.php?id=${encodeURIComponent(action.action_id)}" 
                           class="btn-action" 
                           style="display: inline-block; text-decoration: none; cursor: pointer;"
                           title="View Action Details">
                            <i class="fas fa-eye"></i> View
                        </a>
                    </td>
                </tr>
                <tr class="devices-details-row" id="devices-${action.action_id}" style="display:none;">
                    <td colspan="9" style="padding: 0 !important;">
                        <div class="devices-details" style="padding: 1.5rem !important; min-height: 100px !important;">
                            <div class="empty-state" style="padding: 2rem !important;">
                                <i class="fas fa-spinner fa-spin"></i>
                                <p>Loading device details...</p>
                            </div>
                        </div>
                    </td>
                </tr>
            `).join('');
            
            
            } catch (error) {
                console.error('Error in displayActions:', error);
                showError('Error displaying actions: ' + error.message);
            }
        }
        
        // Toggle device details - make it globally accessible
        window.toggleDevices = async function(actionId) {
            
            try {
                // Validate input
                if (!actionId || typeof actionId !== 'string') {
                    console.error('Invalid action ID:', actionId);
                    throw new Error('Invalid action ID provided');
                }
                
                // Sanitize actionId to prevent XSS
                const sanitizedActionId = actionId.replace(/[^a-zA-Z0-9_-]/g, '');
                if (sanitizedActionId !== actionId) {
                    console.error('Invalid characters in action ID:', actionId);
                    throw new Error('Invalid characters in action ID');
                }
                
                const detailsRow = document.getElementById(`devices-${actionId}`);
                const badge = document.querySelector(`[onclick*="toggleDevices('${actionId}')"]`);
                
                if (!detailsRow) {
                    throw new Error('Device details row not found');
                }
                
                if (detailsRow.style.display === 'none' || detailsRow.style.display === '') {
                // Show devices - use direct PHP approach
                try {
                    const detailsContainer = detailsRow.querySelector('.devices-details');
                    if (!detailsContainer) {
                        throw new Error('Device details container not found');
                    }
                    
                    const response = await fetch(`/pages/risk-priorities/get-device-details.php?action_id=${actionId}`);
                    
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        if (result.data && Array.isArray(result.data) && result.data.length > 0) {
                            displayDeviceDetails(actionId, result.data);
                            detailsRow.style.display = 'table-row';
                            if (badge) badge.classList.add('expanded');
                        } else {
                            detailsContainer.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><p>No devices found for this action</p></div>';
                            detailsRow.style.display = 'table-row';
                            if (badge) badge.classList.add('expanded');
                        }
                    } else {
                        showError('Failed to load device details: ' + (result.error || 'Unknown error'));
                    }
                } catch (error) {
                    console.error('Error loading device details:', error);
                    showError('Error loading device details: ' + error.message);
                }
            } else {
                // Hide devices
                detailsRow.style.display = 'none';
                if (badge) badge.classList.remove('expanded');
            }
            } catch (error) {
                console.error('Error in toggleDevices:', error);
                showError('Error toggling device details: ' + error.message);
            }
        };
        
        // Display device details
        function displayDeviceDetails(actionId, devices) {
            const detailsRow = document.getElementById(`devices-${actionId}`);
            const detailsContainer = detailsRow.querySelector('.devices-details');
            
            if (!devices || devices.length === 0) {
                detailsContainer.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><p>No devices found for this action</p></div>';
                return;
            }
            
            // Helper function to escape HTML
            function escapeHtml(text) {
                if (!text) return '';
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }
            
            // Build HTML string manually to avoid template literal issues
            let html = '<table class="devices-table">';
            html += '<thead><tr>';
            html += '<th>Device</th>';
            html += '<th>Location</th>';
            html += '<th>Criticality</th>';
            html += '<th>Device Risk</th>';
            html += '<th>Status</th>';
            html += '<th>Actions</th>';
            html += '</tr></thead><tbody>';
            
            devices.forEach(function(device) {
                const deviceName = device.device_name || device.hostname || device.asset_tag || 'Unidentified Device';
                const locationName = device.location_name || 'Location Not Mapped';
                const criticality = device.device_criticality || 'Not Classified';
                const riskScore = Number(device.device_risk_score) || 0;
                const patchStatus = device.patch_status || 'Pending';
                const deviceId = device.device_id || '';
                
                const safeName = escapeHtml(deviceName);
                const safeLocation = escapeHtml(locationName);
                const safeCriticality = escapeHtml(criticality);
                const safeStatus = escapeHtml(patchStatus);
                const safeActionId = escapeHtml(actionId);
                const safeDeviceId = escapeHtml(deviceId);
                const criticalityClass = escapeHtml(criticality.toLowerCase().replace(/-/g, '-').replace(/ /g, '-'));
                const statusClass = escapeHtml(patchStatus.toLowerCase().replace(/ /g, '-'));
                
                html += '<tr>';
                html += '<td>';
                html += '<div class="device-name" title="' + safeName + '">' + safeName + '</div>';
                html += '<div class="device-id" style="font-size: 0.75rem; color: var(--text-muted, #94a3b8);">' + (safeDeviceId || 'N/A') + '</div>';
                html += '</td>';
                html += '<td><div class="device-location">' + safeLocation + '</div></td>';
                html += '<td><span class="criticality-badge ' + criticalityClass + '">' + safeCriticality + '</span></td>';
                html += '<td class="device-risk-score' + (riskScore >= 1000 ? ' drives-urgency' : '') + '">' + riskScore.toLocaleString() + '</td>';
                html += '<td><span class="status-badge ' + statusClass + '">' + safeStatus + '</span></td>';
                html += '<td><button class="btn-action" onclick="markDevicePatched(\'' + safeActionId + '\', \'' + safeDeviceId + '\')">';
                html += '<i class="fas fa-check"></i> Mark Patched</button></td>';
                html += '</tr>';
            });
            
            html += '</tbody></table>';
            detailsContainer.innerHTML = html;
        }
        
        // Assign action to user
        async function assignAction(actionId, userId) {
            if (!userId) return;
            
            try {
                const response = await fetch('/pages/risk-priorities/assign-action.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        action_id: actionId,
                        assigned_to: userId,
                        due_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0] // 7 days from now
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    // Update UI to show assignment
                } else {
                    showError('Failed to assign action: ' + result.error);
                }
            } catch (error) {
                showError('Error assigning action: ' + error.message);
            }
        }
        
        // Mark device as patched
        async function markDevicePatched(actionId, deviceId) {
            try {
                const formData = new FormData();
                formData.append('action_id', actionId);
                formData.append('device_id', deviceId);
                
                const response = await fetch('/pages/risk-priorities/mark-device-patched.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    // Refresh the device details
                    await toggleDevices(actionId);
                    await toggleDevices(actionId); // Toggle to refresh
                } else {
                    showError('Failed to mark device as patched: ' + result.error);
                }
            } catch (error) {
                showError('Error marking device as patched: ' + error.message);
            }
        }
        
        // View action details - navigate to detail page
        function viewActionDetails(actionId, event) {
            console.log('viewActionDetails called with actionId:', actionId);
            
            if (!actionId || actionId === 'undefined' || actionId === 'null' || actionId === '') {
                console.error('viewActionDetails: Invalid actionId:', actionId);
                alert('Error: Invalid action ID. Cannot open action details.');
                if (event) {
                    try { event.preventDefault(); } catch (e) {}
                }
                return false;
            }
            
            // Navigate to action detail page
            const url = `/pages/risk-priorities/action-detail.php?id=${encodeURIComponent(actionId)}`;
            console.log('Navigating to:', url);
            
            // Prevent default link behavior
            if (event) {
                try {
                    event.preventDefault();
                    event.stopPropagation();
                    event.stopImmediatePropagation();
                } catch (e) {
                    console.log('Error preventing default:', e);
                }
            }
            
            // Navigate - use location.assign for better reliability
            try {
                window.location.assign(url);
            } catch (e) {
                console.error('Error navigating:', e);
                // Fallback to href
                window.location.href = url;
            }
            
            return false;
        }
        
        // Show error
        function showError(message) {
            showNotification(message, 'error');
        }
    </script>
</body>
</html>

