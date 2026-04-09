<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/api-lockdown-middleware.php';

// Get the request path first to determine endpoint
$request_uri = $_SERVER['REQUEST_URI'];
$path = parse_url($request_uri, PHP_URL_PATH);
$path = str_replace('/api/v1', '', $path);
$path = trim($path, '/');
$segments = explode('/', $path);
$endpoint = $segments[0] ?? 'unknown';

// Enforce API lockdown
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
enforceApiLockdown($endpoint, $method);

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS - Allow all origins
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key, X-Requested-With');
header('Access-Control-Max-Age: 86400'); // Cache preflight for 24 hours

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Reuse the path segments we already parsed for API lockdown

// Route to appropriate endpoint
if (empty($segments[0])) {
    // API root - return API info
    echo json_encode([
        'name' => ' API v1',
        'version' => '1.0.0',
        'description' => 'Device Assessment and Vulnerability Exposure API',
        'endpoints' => [
            'auth' => '/api/v1/auth/',
            'assets' => '/api/v1/assets/',
            'vulnerabilities' => '/api/v1/vulnerabilities/',
            'risks' => '/api/v1/risks/',
            'recalls' => '/api/v1/recalls/',
            'users' => '/api/v1/users/',
            'system' => '/api/v1/system/',
            'analytics' => '/api/v1/analytics/',
            'devices' => '/api/v1/devices/',
            'reports' => '/api/v1/reports/',
            'epss' => '/api/v1/epss/',
            'remediation-actions' => '/api/v1/remediation-actions/',
            'remediations' => '/api/v1/remediations/'
        ],
        'timestamp' => date('c')
    ]);
    exit;
}

// Route to specific endpoints
$endpoint = $segments[0];
$sub_path = isset($segments[1]) ? implode('/', array_slice($segments, 1)) : '';

switch ($endpoint) {
    case 'auth':
        if (file_exists(__DIR__ . '/auth/' . $sub_path . '.php')) {
            include __DIR__ . '/auth/' . $sub_path . '.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Auth endpoint not found']);
        }
        break;
        
    case 'assets':
        if (file_exists(__DIR__ . '/assets/index.php')) {
            $_GET['path'] = $sub_path;
            include __DIR__ . '/assets/index.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Assets endpoint not found']);
        }
        break;
        
    case 'vulnerabilities':
        if (file_exists(__DIR__ . '/vulnerabilities/index.php')) {
            $_GET['path'] = $sub_path;
            include __DIR__ . '/vulnerabilities/index.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Vulnerabilities endpoint not found']);
        }
        break;
        
    case 'risks':
        if (file_exists(__DIR__ . '/risks/index.php')) {
            $_GET['path'] = $sub_path;
            include __DIR__ . '/risks/index.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Risks endpoint not found']);
        }
        break;
        
    case 'recalls':
        if (file_exists(__DIR__ . '/recalls/index.php')) {
            $_GET['path'] = $sub_path;
            include __DIR__ . '/recalls/index.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Recalls endpoint not found']);
        }
        break;
        
    case 'users':
        if (file_exists(__DIR__ . '/users/index.php')) {
            $_GET['path'] = $sub_path;
            include __DIR__ . '/users/index.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Users endpoint not found']);
        }
        break;
        
    case 'components':
        if (file_exists(__DIR__ . '/components/index.php')) {
            $_GET['path'] = $sub_path;
            include __DIR__ . '/components/index.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Components endpoint not found']);
        }
        break;

    case 'patches':
        if (file_exists(__DIR__ . '/patches/index.php')) {
            $_GET['path'] = $sub_path;
            include __DIR__ . '/patches/index.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Patches endpoint not found']);
        }
        break;

    case 'system':
        if (file_exists(__DIR__ . '/system/' . $sub_path . '.php')) {
            include __DIR__ . '/system/' . $sub_path . '.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'System endpoint not found']);
        }
        break;
        
    case 'analytics':
        if (file_exists(__DIR__ . '/analytics/' . $sub_path . '.php')) {
            include __DIR__ . '/analytics/' . $sub_path . '.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Analytics endpoint not found']);
        }
        break;
        
    case 'devices':
        if (file_exists(__DIR__ . '/devices/' . $sub_path . '.php')) {
            include __DIR__ . '/devices/' . $sub_path . '.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Devices endpoint not found']);
        }
        break;
        
    case 'reports':
        if (file_exists(__DIR__ . '/reports/' . $sub_path . '.php')) {
            include __DIR__ . '/reports/' . $sub_path . '.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Reports endpoint not found']);
        }
        break;
        
    case 'epss':
        $epss_file = __DIR__ . '/epss/index.php';
        if (file_exists($epss_file)) {
            // Set path for EPSS endpoint - use empty string if no sub_path
            $_GET['path'] = $sub_path === '' ? '' : ($sub_path ?: '');
            // Clear any previous output
            if (ob_get_level()) {
                ob_clean();
            }
            // Include the EPSS endpoint file (use require to ensure it loads)
            require $epss_file;
            // File should exit, but safety exit here
            exit;
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'EPSS endpoint not found', 'file' => $epss_file]);
            exit;
        }
        break;
        
    case 'remediation-actions':
        if (file_exists(__DIR__ . '/remediation-actions/index.php')) {
            $_GET['path'] = $sub_path;
            include __DIR__ . '/remediation-actions/index.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Remediation actions endpoint not found']);
        }
        break;
    
    case 'remediations':
        if (file_exists(__DIR__ . '/remediations/index.php')) {
            $_GET['path'] = $sub_path;
            include __DIR__ . '/remediations/index.php';
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Remediations endpoint not found']);
        }
        break;
    
    case 'software-packages':
        if (file_exists(__DIR__ . '/software-packages/' . $sub_path)) {
            include __DIR__ . '/software-packages/' . $sub_path;
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Software packages endpoint not found: ' . $sub_path]);
        }
        break;
    
    case 'admin':
        if (file_exists(__DIR__ . '/admin/' . $sub_path)) {
            include __DIR__ . '/admin/' . $sub_path;
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Admin endpoint not found: ' . $sub_path]);
        }
        break;

    default:
        http_response_code(404);
        echo json_encode([
            'error' => 'Endpoint not found',
            'endpoint' => $endpoint,
            'segments' => $segments,
            'path' => $path,
            'sub_path' => $sub_path
        ]);
        break;
}
?>
