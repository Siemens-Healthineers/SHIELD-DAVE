<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../../config/config.php';
require_once __DIR__ . '/../../../config/database.php';
require_once __DIR__ . '/../../../services/async_sbom_processor.php';

// Set JSON response headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'error' => 'Method not allowed'
    ]);
    exit;
}

try {
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        throw new Exception('Invalid JSON input');
    }
    
    $sbomId = $input['sbom_id'] ?? null;
    $deviceId = $input['device_id'] ?? null;
    $userId = $input['user_id'] ?? null;
    
    if (!$sbomId || !$deviceId || !$userId) {
        throw new Exception('Missing required parameters: sbom_id, device_id, user_id');
    }
    
    // Validate SBOM exists
    $db = DatabaseConfig::getInstance();
    $stmt = $db->prepare("SELECT sbom_id FROM sboms WHERE sbom_id = ?");
    $stmt->execute([$sbomId]);
    
    if (!$stmt->fetch()) {
        throw new Exception('SBOM not found');
    }
    
    // Process SBOM evaluation
    $stats = evaluateSBOM($sbomId, $deviceId, $userId);
    
    if ($stats === false) {
        throw new Exception('SBOM evaluation failed');
    }
    
    // Return success response
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'message' => 'SBOM evaluation completed',
        'stats' => $stats,
        'timestamp' => date('c')
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'timestamp' => date('c')
    ]);
}
?>
