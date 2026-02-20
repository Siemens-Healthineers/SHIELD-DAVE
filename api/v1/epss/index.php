<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}

// Start output buffering to prevent PHP warnings/notices from corrupting JSON
ob_start();

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

// Get HTTP method (may not be set if included from router)
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Get path from GET parameter (set by router) or parse from REQUEST_URI (direct access)
$path = $_GET['path'] ?? null;

// If path is empty string (set by router), use it as-is (means root endpoint)
// If path is null (not set), parse from REQUEST_URI
if ($path === null) {
    // Direct access - parse from REQUEST_URI
    $request_uri = $_SERVER['REQUEST_URI'] ?? '';
    $parsed_path = parse_url($request_uri, PHP_URL_PATH);
    // Remove /api/v1/epss prefix if present
    $parsed_path = preg_replace('#^/api/v1/epss#', '', $parsed_path);
    $parsed_path = trim($parsed_path, '/');
    $path = $parsed_path ?: '/';
} elseif ($path === '') {
    // Empty string from router means root endpoint - normalize to '/'
    $path = '/';
}

try {
    // Route requests - normalize path
    // If path is empty or '/', treat as root endpoint
    $normalizedPath = trim($path, '/');
    
    // Debug: Log routing information (remove in production if needed)
    error_log("EPSS API - Method: $method, Path: [$path], Normalized: [$normalizedPath]");
    
    // Handle root endpoint (GET /api/v1/epss/)
    if ($method === 'GET' && ($normalizedPath === '' || $normalizedPath === '/' || empty($normalizedPath))) {
        handleGetStatistics($db, $user);
        exit; // Ensure we exit after handling
    } elseif ($method === 'GET' && preg_match('/^trends\/(.+)$/', $normalizedPath, $matches)) {
        // Handle /trends/{cve_id} path
        handleGetTrends($db, $user, $matches[1]);
        exit;
    } elseif ($method === 'GET' && $normalizedPath === 'sync-status') {
        handleGetSyncStatus($db, $user);
        exit;
    } elseif ($method === 'GET' && $normalizedPath === 'high-risk') {
        handleGetHighRiskVulnerabilities($db, $user);
        exit;
    } elseif ($method === 'GET' && $normalizedPath === 'trending') {
        handleGetTrendingVulnerabilities($db, $user);
        exit;
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'Endpoint not found', 'path' => $normalizedPath, 'method' => $method]);
        exit;
    }
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Server error: ' . $e->getMessage()
    ]);
    exit;
}

/**
 * Handle GET /api/v1/epss - Get EPSS statistics
 */
function handleGetStatistics($db, $user) {
    try {
        // Get overall EPSS statistics
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
        $overall_stats = $stmt->fetch();
        
        // Ensure we have valid data structure with defaults
        if (!$overall_stats || !is_array($overall_stats)) {
            $overall_stats = [
                'total_vulnerabilities' => 0,
                'vulnerabilities_with_epss' => 0,
                'high_epss_count' => 0,
                'medium_epss_count' => 0,
                'low_epss_count' => 0,
                'avg_epss_score' => '0.0000',
                'avg_epss_percentile' => '0.0000',
                'last_epss_update' => null
            ];
        }
        
        // Get EPSS statistics by severity
        $sql = "SELECT 
            v.severity,
            COUNT(*) as count,
            ROUND(AVG(v.epss_score), 4) as avg_epss_score,
            ROUND(AVG(v.epss_percentile), 4) as avg_epss_percentile,
            COUNT(CASE WHEN v.epss_score >= 0.7 THEN 1 END) as high_epss_count
        FROM vulnerabilities v
        WHERE v.epss_score IS NOT NULL
        GROUP BY v.severity
        ORDER BY 
            CASE v.severity 
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
                ELSE 5
            END";
        
        $stmt = $db->query($sql);
        $severity_stats = $stmt->fetchAll();
        
        // Get recent EPSS trends (last 7 days)
        $sql = "SELECT 
            recorded_date,
            COUNT(*) as vulnerabilities_count,
            ROUND(AVG(epss_score), 4) as avg_epss_score,
            COUNT(CASE WHEN epss_score >= 0.7 THEN 1 END) as high_epss_count
        FROM epss_score_history 
        WHERE recorded_date >= CURRENT_DATE - INTERVAL '7 days'
        GROUP BY recorded_date
        ORDER BY recorded_date DESC";
        
        $stmt = $db->query($sql);
        $recent_trends = $stmt->fetchAll();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'overall' => $overall_stats,
                'by_severity' => $severity_stats,
                'recent_trends' => $recent_trends
            ],
            'timestamp' => date('c')
        ]);
        exit;
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Failed to get EPSS statistics: ' . $e->getMessage()
        ]);
        exit;
    }
}

/**
 * Handle GET /api/v1/epss/trends/{cve_id} - Get EPSS trend data for a specific CVE
 */
function handleGetTrends($db, $user, $cve_id) {
    try {
        // Validate CVE ID format
        if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve_id)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => 'Invalid CVE ID format'
            ]);
            return;
        }
        
        $days = intval($_GET['days'] ?? 30);
        $days = min(365, max(1, $days)); // Limit to 1-365 days
        
        // Get trend data using the database function
        $sql = "SELECT * FROM get_epss_trend_data(?, ?)";
        $stmt = $db->prepare($sql);
        $stmt->execute([$cve_id, $days]);
        $trend_data = $stmt->fetchAll();
        
        // Get current EPSS data
        $sql = "SELECT 
            epss_score,
            epss_percentile,
            epss_date,
            epss_last_updated
        FROM vulnerabilities 
        WHERE cve_id = ?";
        
        $stmt = $db->prepare($sql);
        $stmt->execute([$cve_id]);
        $current_data = $stmt->fetch();
        
        if (!$current_data && empty($trend_data)) {
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => 'No EPSS data found for this CVE'
            ]);
            return;
        }
        
        echo json_encode([
            'success' => true,
            'data' => [
                'cve_id' => $cve_id,
                'current' => $current_data,
                'trend' => $trend_data,
                'days_requested' => $days
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Failed to get EPSS trends: ' . $e->getMessage()
        ]);
    }
}

/**
 * Handle GET /api/v1/epss/sync-status - Get EPSS sync status
 */
function handleGetSyncStatus($db, $user) {
    try {
        // Get last sync information
        $sql = "SELECT 
            sync_started_at,
            sync_completed_at,
            sync_status,
            total_cves_processed,
            cves_updated,
            cves_new,
            api_date,
            api_total_cves,
            api_version,
            error_message
        FROM epss_sync_log 
        ORDER BY sync_started_at DESC 
        LIMIT 1";
        
        $stmt = $db->query($sql);
        $last_sync = $stmt->fetch();
        
        // Get sync history (last 10 syncs)
        $sql = "SELECT 
            sync_started_at,
            sync_completed_at,
            sync_status,
            total_cves_processed,
            cves_updated,
            cves_new,
            error_message
        FROM epss_sync_log 
        ORDER BY sync_started_at DESC 
        LIMIT 10";
        
        $stmt = $db->query($sql);
        $sync_history = $stmt->fetchAll();
        
        // Get coverage statistics
        $sql = "SELECT 
            COUNT(*) as total_vulnerabilities,
            COUNT(CASE WHEN epss_score IS NOT NULL THEN 1 END) as vulnerabilities_with_epss,
            COUNT(CASE WHEN epss_last_updated >= CURRENT_DATE THEN 1 END) as updated_today,
            MAX(epss_last_updated) as last_epss_update
        FROM vulnerabilities";
        
        $stmt = $db->query($sql);
        $coverage_stats = $stmt->fetch();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'last_sync' => $last_sync,
                'sync_history' => $sync_history,
                'coverage' => $coverage_stats
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Failed to get sync status: ' . $e->getMessage()
        ]);
    }
}

/**
 * Handle GET /api/v1/epss/high-risk - Get high EPSS risk vulnerabilities
 */
function handleGetHighRiskVulnerabilities($db, $user) {
    try {
        $limit = min(100, max(1, intval($_GET['limit'] ?? 20)));
        $threshold = floatval($_GET['threshold'] ?? 0.7);
        
        $sql = "SELECT 
            v.cve_id,
            v.description,
            v.severity,
            v.epss_score,
            v.epss_percentile,
            v.epss_date,
            v.is_kev,
            COUNT(dvl.device_id) as affected_assets,
            COUNT(CASE WHEN dvl.remediation_status = 'Open' THEN 1 END) as open_count
        FROM vulnerabilities v
        LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
        WHERE v.epss_score >= ?
        GROUP BY v.cve_id, v.description, v.severity, v.epss_score, v.epss_percentile, v.epss_date, v.is_kev
        ORDER BY v.epss_score DESC, v.epss_percentile DESC
        LIMIT ?";
        
        $stmt = $db->prepare($sql);
        $stmt->execute([$threshold, $limit]);
        $high_risk_vulns = $stmt->fetchAll();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'vulnerabilities' => $high_risk_vulns,
                'threshold' => $threshold,
                'count' => count($high_risk_vulns)
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Failed to get high-risk vulnerabilities: ' . $e->getMessage()
        ]);
    }
}

/**
 * Handle GET /api/v1/epss/trending - Get trending vulnerabilities (largest EPSS increases)
 */
function handleGetTrendingVulnerabilities($db, $user) {
    try {
        $limit = min(50, max(1, intval($_GET['limit'] ?? 10)));
        $days = intval($_GET['days'] ?? 7);
        
        // Get vulnerabilities with largest EPSS score increases
        $sql = "WITH epss_changes AS (
            SELECT 
                h1.cve_id,
                h1.epss_score as current_score,
                h2.epss_score as previous_score,
                (h1.epss_score - h2.epss_score) as score_change,
                h1.recorded_date as current_date,
                h2.recorded_date as previous_date
            FROM epss_score_history h1
            JOIN epss_score_history h2 ON h1.cve_id = h2.cve_id
            WHERE h1.recorded_date = CURRENT_DATE
              AND h2.recorded_date = CURRENT_DATE - INTERVAL '1 day' * ?
              AND h1.epss_score > h2.epss_score
        )
        SELECT 
            ec.cve_id,
            v.description,
            v.severity,
            ec.current_score,
            ec.previous_score,
            ec.score_change,
            v.is_kev,
            COUNT(dvl.device_id) as affected_assets
        FROM epss_changes ec
        JOIN vulnerabilities v ON ec.cve_id = v.cve_id
        LEFT JOIN device_vulnerabilities_link dvl ON v.cve_id = dvl.cve_id
        GROUP BY ec.cve_id, v.description, v.severity, ec.current_score, ec.previous_score, ec.score_change, v.is_kev
        ORDER BY ec.score_change DESC
        LIMIT ?";
        
        $stmt = $db->prepare($sql);
        $stmt->execute([$days, $limit]);
        $trending_vulns = $stmt->fetchAll();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'vulnerabilities' => $trending_vulns,
                'days_analyzed' => $days,
                'count' => count($trending_vulns)
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Failed to get trending vulnerabilities: ' . $e->getMessage()
        ]);
    }
}
