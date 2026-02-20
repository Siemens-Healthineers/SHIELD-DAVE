<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../includes/unified-auth.php';
require_once __DIR__ . '/../../../includes/vulnerability-stats.php';

header('Content-Type: application/json');

$auth = new Auth();
$auth->requireAuth();

$user = $auth->getCurrentUser();
if (!$user) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Authentication required']);
    exit;
}

try {
    $stats = new VulnerabilityStats();
    
    // Get count type from request
    $countType = $_GET['type'] ?? 'unique';
    $filters = [];
    
    // Parse filters from request
    if (!empty($_GET['severity'])) {
        $filters['severity'] = is_array($_GET['severity']) ? $_GET['severity'] : [$_GET['severity']];
    }
    
    if (!empty($_GET['is_kev'])) {
        $filters['is_kev'] = filter_var($_GET['is_kev'], FILTER_VALIDATE_BOOLEAN);
    }
    
    if (!empty($_GET['has_epss'])) {
        $filters['has_epss'] = filter_var($_GET['has_epss'], FILTER_VALIDATE_BOOLEAN);
    }
    
    if (!empty($_GET['epss_threshold'])) {
        $filters['epss_threshold'] = floatval($_GET['epss_threshold']);
    }
    
    // Get comprehensive stats if requested
    if ($countType === 'comprehensive') {
        $result = $stats->getComprehensiveStats();
    } else {
        $result = $stats->getVulnerabilityCounts($countType, $filters);
    }
    
    echo json_encode($result);
    
} catch (Exception $e) {
    error_log("Vulnerability Stats API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Internal server error',
        'message' => $e->getMessage()
    ]);
}
?>
