<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

/**
 * Device Assessment and Vulnerability Exposure () - Main Entry Point
 * Main index file that handles routing and application initialization
 */

// Define  access constant
if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}

// Start output buffering
ob_start();

// Include configuration
require_once __DIR__ . '/config/config.php';

// Include database configuration
require_once __DIR__ . '/config/database.php';

// Include authentication
require_once __DIR__ . '/includes/auth.php';

// Include utility functions
require_once __DIR__ . '/includes/functions.php';

// Handle routing
$request_uri = $_SERVER['REQUEST_URI'];
$script_name = $_SERVER['SCRIPT_NAME'];
$path_info = str_replace($script_name, '', $request_uri);
$path_info = trim($path_info, '/');

// Remove query string
if (strpos($path_info, '?') !== false) {
    $path_info = substr($path_info, 0, strpos($path_info, '?'));
}

// Route handling
if (empty($path_info) || $path_info === 'index.php') {
    // Default route - redirect to dashboard
    if (isset($_SESSION['user_id'])) {
        header('Location: /pages/dashboard.php');
    } else {
        header('Location: /pages/login.php');
    }
    exit;
} elseif (strpos($path_info, 'api/') === 0) {
    // API routes
    $api_path = substr($path_info, 4); // Remove 'api/' prefix
    $api_file = __DIR__ . '/api/v1/' . $api_path . '.php';
    
    if (file_exists($api_file)) {
        require_once $api_file;
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'API endpoint not found']);
    }
    exit;
} elseif (strpos($path_info, 'pages/') === 0) {
    // Page routes
    $page_path = substr($path_info, 6); // Remove 'pages/' prefix
    $page_file = __DIR__ . '/pages/' . $page_path . '.php';
    
    if (file_exists($page_file)) {
        require_once $page_file;
    } else {
        http_response_code(404);
        include __DIR__ . '/pages/404.php';
    }
    exit;
} elseif (strpos($path_info, 'assets/') === 0) {
    // Asset routes
    $asset_path = substr($path_info, 7); // Remove 'assets/' prefix
    $asset_file = __DIR__ . '/assets/' . $asset_path;
    
    if (file_exists($asset_file)) {
        $mime_type = mime_content_type($asset_file);
        header('Content-Type: ' . $mime_type);
        readfile($asset_file);
    } else {
        http_response_code(404);
        echo 'Asset not found';
    }
    exit;
} elseif (strpos($path_info, 'downloads/') === 0) {
    // Download routes
    $download_path = substr($path_info, 10); // Remove 'downloads/' prefix
    $download_file = __DIR__ . '/uploads/' . $download_path;
    
    if (file_exists($download_file)) {
        $mime_type = mime_content_type($download_file);
        header('Content-Type: ' . $mime_type);
        header('Content-Disposition: attachment; filename="' . basename($download_file) . '"');
        readfile($download_file);
    } else {
        http_response_code(404);
        echo 'File not found';
    }
    exit;
} else {
    // Try to find the file directly
    $file_path = __DIR__ . '/' . $path_info;
    
    if (file_exists($file_path) && is_file($file_path)) {
        $mime_type = mime_content_type($file_path);
        header('Content-Type: ' . $mime_type);
        readfile($file_path);
    } else {
        // 404 - Page not found
        http_response_code(404);
        include __DIR__ . '/pages/404.php';
    }
    exit;
}

// Clean output buffer
ob_end_flush();
?>
