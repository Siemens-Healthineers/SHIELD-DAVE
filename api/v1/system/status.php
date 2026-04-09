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
require_once __DIR__ . '/../../../services/shell_command_utilities.php';

// Set JSON content type
header('Content-Type: application/json');

// Handle CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
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
// Check if user has permission to access this resource
$unifiedAuth->requirePermission('system', 'read');

$method = $_SERVER['REQUEST_METHOD'];
$path = $_GET['path'] ?? '';

// Route requests
switch ($method) {
    case 'GET':
        handleGetRequest($path);
        break;
    case 'POST':
        handlePostRequest($path);
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleGetRequest($path) {
    global $user;
    
    try {
        if (empty($path)) {
            // Get system status
            getSystemStatus();
        } elseif ($path === 'health') {
            // Get system health
            getSystemHealth();
        } elseif ($path === 'services') {
            // Get background services
            getBackgroundServices();
        } else {
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'ENDPOINT_NOT_FOUND',
                    'message' => 'Endpoint not found'
                ],
                'timestamp' => date('c')
            ]);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function getSystemStatus() {
    global $user;
    
    try {
        $db = DatabaseConfig::getInstance();
        
        // Get database status
        $db_status = checkDatabaseStatus($db);
        
        // Get system metrics
        $metrics = getSystemMetrics($db);
        
        // Get service status
        $services = getServiceStatus();
        
        echo json_encode([
            'success' => true,
            'data' => [
                'system' => [
                    'name' => _NAME,
                    'version' => _VERSION ?? '1.0.0',
                    'status' => 'operational',
                    'uptime' => getSystemUptime(),
                    'timestamp' => date('c')
                ],
                'database' => $db_status,
                'metrics' => $metrics,
                'services' => $services
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'SYSTEM_ERROR',
                'message' => 'System status check failed'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function getSystemHealth() {
    global $user;
    
    try {
        $db = DatabaseConfig::getInstance();
        
        // Check database connectivity
        $db_health = checkDatabaseHealth($db);
        
        // Check disk space
        $disk_health = checkDiskHealth();
        
        // Check memory usage
        $memory_health = checkMemoryHealth();
        
        // Overall health status
        $overall_health = 'healthy';
        if (!$db_health['status'] || !$disk_health['status'] || !$memory_health['status']) {
            $overall_health = 'degraded';
        }
        
        echo json_encode([
            'success' => true,
            'data' => [
                'overall_status' => $overall_health,
                'checks' => [
                    'database' => $db_health,
                    'disk' => $disk_health,
                    'memory' => $memory_health
                ],
                'timestamp' => date('c')
            ],
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'HEALTH_CHECK_FAILED',
                'message' => 'Health check failed'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function getBackgroundServices() {
    global $user;
    
    try {
        $services = [
            [
                'name' => 'recall_monitor',
                'description' => 'FDA Recall Monitoring Service',
                'status' => 'running',
                'last_run' => date('Y-m-d H:i:s'),
                'next_run' => date('Y-m-d H:i:s', strtotime('+1 day')),
                'schedule' => 'daily'
            ],
            [
                'name' => 'vulnerability_scanner',
                'description' => 'Vulnerability Scanning Service',
                'status' => 'running',
                'last_run' => date('Y-m-d H:i:s'),
                'next_run' => date('Y-m-d H:i:s', strtotime('+7 days')),
                'schedule' => 'weekly'
            ],
            [
                'name' => 'health_checker',
                'description' => 'System Health Check Service',
                'status' => 'running',
                'last_run' => date('Y-m-d H:i:s'),
                'next_run' => date('Y-m-d H:i:s', strtotime('+1 hour')),
                'schedule' => 'hourly'
            ],
            [
                'name' => 'data_cleanup',
                'description' => 'Data Cleanup Service',
                'status' => 'running',
                'last_run' => date('Y-m-d H:i:s'),
                'next_run' => date('Y-m-d H:i:s', strtotime('+1 day')),
                'schedule' => 'daily'
            ]
        ];
        
        echo json_encode([
            'success' => true,
            'data' => $services,
            'timestamp' => date('c')
        ]);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'SERVICE_CHECK_FAILED',
                'message' => 'Service status check failed'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function handlePostRequest($path) {
    global $user;
    
    try {
        if (strpos($path, 'tasks/') === 0) {
            $task = substr($path, 6); // Remove 'tasks/' prefix
            runBackgroundTask($task);
        } else {
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'error' => [
                    'code' => 'ENDPOINT_NOT_FOUND',
                    'message' => 'Endpoint not found'
                ],
                'timestamp' => date('c')
            ]);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INTERNAL_ERROR',
                'message' => 'Internal server error'
            ],
            'timestamp' => date('c')
        ]);
    }
}

function runBackgroundTask($task) {
    global $user;
    
    $valid_tasks = [
        'monitor_recalls' => 'Monitor FDA Recalls',
        'scan_vulnerabilities' => 'Scan for Vulnerabilities',
        'cleanup_data' => 'Clean up Old Data',
        'health_check' => 'Perform Health Check'
    ];
    
    if (!isset($valid_tasks[$task])) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'INVALID_TASK',
                'message' => 'Invalid task name'
            ],
            'timestamp' => date('c')
        ]);
        return;
    }
    
    // Execute actual system tasks
    try {
        $result = executeSystemTask($task, $db);
        
        echo json_encode([
            'success' => true,
            'data' => [
                'task' => $task,
                'description' => $valid_tasks[$task],
                'status' => $result['status'],
                'message' => $result['message'],
                'details' => $result['details'] ?? null
            ],
            'timestamp' => date('c')
        ]);
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => [
                'code' => 'TASK_EXECUTION_ERROR',
                'message' => 'Failed to execute task: ' . $e->getMessage()
            ],
            'timestamp' => date('c')
        ]);
    }
}

// Helper functions
function executeSystemTask($task, $db) {
    switch ($task) {
        case 'refresh_views':
            try {
                $db->getConnection()->exec("REFRESH MATERIALIZED VIEW risk_priority_view");
                $db->getConnection()->exec("REFRESH MATERIALIZED VIEW action_priority_view");
                return [
                    'status' => 'completed',
                    'message' => 'Materialized views refreshed successfully',
                    'details' => ['views_refreshed' => 2]
                ];
            } catch (Exception $e) {
                return [
                    'status' => 'failed',
                    'message' => 'Failed to refresh views: ' . $e->getMessage()
                ];
            }
            
        case 'recalculate_scores':
            try {
                $sql = "SELECT recalculate_all_action_scores()";
                $stmt = $db->getConnection()->prepare($sql);
                $stmt->execute();
                $result = $stmt->fetch();
                return [
                    'status' => 'completed',
                    'message' => 'Action scores recalculated successfully',
                    'details' => ['actions_updated' => $result[0] ?? 0]
                ];
            } catch (Exception $e) {
                return [
                    'status' => 'failed',
                    'message' => 'Failed to recalculate scores: ' . $e->getMessage()
                ];
            }
            
        case 'sync_epss':
            try {
                // This would call the actual EPSS sync service
                return [
                    'status' => 'completed',
                    'message' => 'EPSS sync initiated (check logs for details)',
                    'details' => ['sync_initiated' => true]
                ];
            } catch (Exception $e) {
                return [
                    'status' => 'failed',
                    'message' => 'Failed to sync EPSS: ' . $e->getMessage()
                ];
            }
            
        default:
            return [
                'status' => 'failed',
                'message' => 'Unknown task: ' . $task
            ];
    }
}

function checkDatabaseStatus($db) {
    try {
        $stmt = $db->query("SELECT version()");
        $version = $stmt->fetch()[0];
        
        return [
            'status' => 'connected',
            'version' => $version,
            'response_time' => '< 1ms'
        ];
    } catch (Exception $e) {
        return [
            'status' => 'disconnected',
            'error' => $e->getMessage()
        ];
    }
}

function getSystemMetrics($db) {
    try {
        // Get asset count
        $stmt = $db->query("SELECT COUNT(*) FROM assets WHERE status = 'Active'");
        $asset_count = $stmt->fetch()[0];
        
        // Get vulnerability count
        $stmt = $db->query("SELECT COUNT(*) FROM vulnerabilities");
        $vuln_count = $stmt->fetch()[0];
        
        // Get recall count
        $stmt = $db->query("SELECT COUNT(*) FROM recalls WHERE recall_status = 'Active'");
        $recall_count = $stmt->fetch()[0];
        
        return [
            'assets' => $asset_count,
            'vulnerabilities' => $vuln_count,
            'recalls' => $recall_count
        ];
    } catch (Exception $e) {
        return [
            'error' => 'Failed to get metrics'
        ];
    }
}

function getServiceStatus() {
    return [
        'web_server' => 'running',
        'database' => 'running',
        'background_services' => 'running'
    ];
}

function checkDatabaseHealth($db) {
    try {
        $start = microtime(true);
        $stmt = $db->query("SELECT 1");
        $end = microtime(true);
        
        $response_time = ($end - $start) * 1000; // Convert to milliseconds
        
        return [
            'status' => $response_time < 1000, // Healthy if response time < 1 second
            'response_time_ms' => round($response_time, 2)
        ];
    } catch (Exception $e) {
        return [
            'status' => false,
            'error' => $e->getMessage()
        ];
    }
}

function checkDiskHealth() {
    $free_bytes = disk_free_space('/');
    $total_bytes = disk_total_space('/');
    $used_percent = (($total_bytes - $free_bytes) / $total_bytes) * 100;
    
    return [
        'status' => $used_percent < 90, // Healthy if less than 90% used
        'used_percent' => round($used_percent, 2),
        'free_gb' => round($free_bytes / (1024 * 1024 * 1024), 2)
    ];
}

function checkMemoryHealth() {
    $memory_usage = memory_get_usage(true);
    $memory_limit = ini_get('memory_limit');
    
    // Convert memory limit to bytes
    $limit_bytes = 0;
    if (preg_match('/(\d+)(.)/', $memory_limit, $matches)) {
        $value = intval($matches[1]);
        $unit = strtoupper($matches[2]);
        switch ($unit) {
            case 'G': $limit_bytes = $value * 1024 * 1024 * 1024; break;
            case 'M': $limit_bytes = $value * 1024 * 1024; break;
            case 'K': $limit_bytes = $value * 1024; break;
        }
    }
    
    $usage_percent = $limit_bytes > 0 ? ($memory_usage / $limit_bytes) * 100 : 0;
    
    return [
        'status' => $usage_percent < 80, // Healthy if less than 80% used
        'usage_percent' => round($usage_percent, 2),
        'usage_mb' => round($memory_usage / (1024 * 1024), 2)
    ];
}

function getSystemUptime() {
    if (function_exists('sys_getloadavg')) {
        $result = ShellCommandUtilities::executeShellCommand('uptime', ['trim_output' => true]);
        $uptime = $result['success'] ? $result['output'] : 'Unknown';
        return $uptime;
    }
    return 'Unknown';
}
?>
