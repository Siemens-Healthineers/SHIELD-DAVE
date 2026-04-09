<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../services/shell_command_utilities.php';

class HealthChecker {
    private $db;
    private $issues = [];
    private $warnings = [];
    private $success = [];
    private $results = [];
    private $startTime;

    public function __construct() {
        $this->db = DatabaseConfig::getInstance();
    }

    public function runHealthCheck() {
        $this->startTime = microtime(true);

        $this->checkDatabaseConnection();
        $this->checkDatabaseTables();
        $this->checkDiskSpace();
        $this->checkMemoryUsage();
        $this->checkLogFiles();
        $this->checkCronJobs();
        $this->checkServices();
        $this->checkDataIntegrity();

        $this->displayResults();
    }

    private function checkDatabaseConnection() {
        try {
            $stmt = $this->db->query("SELECT 1");
            $this->success[] = "Database connection: OK";
            $this->results['database_connection'] = true;
        } catch (Exception $e) {
            $this->issues[] = "Database connection failed: " . $e->getMessage();
            $this->results['database_connection'] = false;
        }
    }

    private function checkDatabaseTables() {
        $requiredTables = [
            'assets', 'vulnerabilities', 'device_vulnerabilities_link',
            'remediation_actions', 'action_risk_scores', 'medical_devices'
        ];

        $tableStats = [];
        foreach ($requiredTables as $table) {
            try {
                $stmt = $this->db->query("SELECT COUNT(*) FROM $table");
                $count = $stmt->fetchColumn();
                $this->success[] = "Table '$table': $count records";
                $tableStats[$table] = $count;
            } catch (Exception $e) {
                $this->issues[] = "Table '$table' missing or inaccessible: " . $e->getMessage();
                $tableStats[$table] = 0;
            }
        }
        $this->results['table_stats'] = $tableStats;
    }

    private function checkDiskSpace() {
        $diskUsage = disk_free_space('/');
        $diskTotal = disk_total_space('/');
        $diskPercent = (($diskTotal - $diskUsage) / $diskTotal) * 100;

        if ($diskPercent > 90) {
            $this->issues[] = "Disk usage critical: " . number_format($diskPercent, 1) . "%";
        } elseif ($diskPercent > 80) {
            $this->warnings[] = "Disk usage high: " . number_format($diskPercent, 1) . "%";
        } else {
            $this->success[] = "Disk usage: " . number_format($diskPercent, 1) . "%";
        }
    }

    private function checkMemoryUsage() {
        $memInfo = file_get_contents('/proc/meminfo');
        preg_match('/MemTotal:\s+(\d+)/', $memInfo, $total);
        preg_match('/MemAvailable:\s+(\d+)/', $memInfo, $available);
        
        if (isset($total[1]) && isset($available[1])) {
            $memPercent = (($total[1] - $available[1]) / $total[1]) * 100;
            if ($memPercent > 90) {
                $this->issues[] = "Memory usage critical: " . number_format($memPercent, 1) . "%";
            } elseif ($memPercent > 80) {
                $this->warnings[] = "Memory usage high: " . number_format($memPercent, 1) . "%";
            } else {
                $this->success[] = "Memory usage: " . number_format($memPercent, 1) . "%";
            }
        }
    }

    private function checkLogFiles() {
        $logDir = _ROOT . '/logs';
        if (!is_dir($logDir)) {
            $this->warnings[] = "Log directory not found: $logDir";
            return;
        }

        $logFiles = glob($logDir . '/*.log');
        if (empty($logFiles)) {
            $this->warnings[] = "No log files found in $logDir";
        } else {
            $this->success[] = "Found " . count($logFiles) . " log files";
            
            // Check for recent errors
            foreach ($logFiles as $logFile) {
                $result = ShellCommandUtilities::executeShellCommand(
                    "grep -i 'error\\|fatal\\|exception' $logFile | tail -5",
                    ['trim_output' => true]
                );
                $recentErrors = $result['success'] ? $result['output'] : '';
                if (!empty($recentErrors)) {
                    $this->warnings[] = "Recent errors in " . basename($logFile);
                }
            }
        }
    }

    private function checkCronJobs() {
        $result = ShellCommandUtilities::executeShellCommand('crontab -l 2>/dev/null');
        $cronOutput = $result['success'] ? $result['output'] : '';
        if (empty($cronOutput)) {
            $this->warnings[] = "No cron jobs configured";
        } else {
            $cronLines = array_filter(explode("\n", $cronOutput), function($line) {
                $trimmed = trim($line);
                return !empty($trimmed) && substr($trimmed, 0, 1) !== '#';
            });
            $this->success[] = "Found " . count($cronLines) . " active cron jobs";
        }
    }

    private function checkServices() {
        $services = ['apache2', 'postgresql'];
        
        foreach ($services as $service) {
            $result = ShellCommandUtilities::executeShellCommand(
                "systemctl is-active $service 2>/dev/null",
                ['trim_output' => true]
            );
            $status = $result['success'] ? $result['output'] : '';
            if ($status === 'active') {
                $this->success[] = "Service '$service': Running";
            } else {
                $this->issues[] = "Service '$service': Not running";
            }
        }
    }

    private function checkDataIntegrity() {
        
        // Check for orphaned device-vulnerability links
        try {
            $stmt = $this->db->query("
                SELECT COUNT(*) as orphaned 
                FROM device_vulnerabilities_link dvl 
                LEFT JOIN medical_devices md ON dvl.device_id = md.device_id 
                WHERE md.device_id IS NULL
            ");
            $orphaned = $stmt->fetchColumn();
            if ($orphaned > 0) {
                $this->warnings[] = "Found $orphaned orphaned device-vulnerability links";
            } else {
                $this->success[] = "No orphaned device-vulnerability links";
            }
        } catch (Exception $e) {
            $this->warnings[] = "Could not check data integrity: " . $e->getMessage();
        }
        
        // Check for orphaned medical devices
        try {
            $stmt = $this->db->query("
                SELECT COUNT(*) as orphaned 
                FROM medical_devices md 
                LEFT JOIN assets a ON md.asset_id = a.asset_id 
                WHERE a.asset_id IS NULL
            ");
            $orphaned = $stmt->fetchColumn();
            if ($orphaned > 0) {
                $this->warnings[] = "Found $orphaned orphaned medical devices";
            } else {
                $this->success[] = "No orphaned medical devices";
            }
        } catch (Exception $e) {
            $this->warnings[] = "Could not check medical device integrity: " . $e->getMessage();
        }
    }

    private function displayResults() {
        $executionTime = round((microtime(true) - $this->startTime) * 1000, 2);
        
        echo '<div class="health-check-report">';
        echo '<div class="report-header">';
        echo '<h2><i class="fas fa-heartbeat"></i>  System Health Check</h2>';
        echo '<p class="timestamp">Completed: ' . date('Y-m-d H:i:s') . ' | Execution Time: ' . $executionTime . 'ms</p>';
        echo '</div>';
        
        // System Status Summary
        $totalIssues = count($this->issues);
        $totalWarnings = count($this->warnings);
        $totalSuccess = count($this->success);
        
        echo '<div class="status-summary">';
        echo '<div class="status-cards">';
        
        echo '<div class="status-card success">';
        echo '<div class="status-icon"><i class="fas fa-check-circle"></i></div>';
        echo '<div class="status-content">';
        echo '<div class="status-value">' . $totalSuccess . '</div>';
        echo '<div class="status-label">Success Items</div>';
        echo '</div>';
        echo '</div>';
        
        echo '<div class="status-card warning">';
        echo '<div class="status-icon"><i class="fas fa-exclamation-triangle"></i></div>';
        echo '<div class="status-content">';
        echo '<div class="status-value">' . $totalWarnings . '</div>';
        echo '<div class="status-label">Warnings</div>';
        echo '</div>';
        echo '</div>';
        
        echo '<div class="status-card error">';
        echo '<div class="status-icon"><i class="fas fa-times-circle"></i></div>';
        echo '<div class="status-content">';
        echo '<div class="status-value">' . $totalIssues . '</div>';
        echo '<div class="status-label">Issues</div>';
        echo '</div>';
        echo '</div>';
        
        echo '</div>';
        echo '</div>';
        
        // Overall Status
        if ($totalIssues === 0 && $totalWarnings === 0) {
            echo '<div class="overall-status success">';
            echo '<div class="status-icon"><i class="fas fa-heart"></i></div>';
            echo '<div class="status-content">';
            echo '<h3>System is Healthy!</h3>';
            echo '<p>All checks passed successfully. Your  system is operating optimally.</p>';
            echo '</div>';
            echo '</div>';
        } elseif ($totalIssues === 0) {
            echo '<div class="overall-status warning">';
            echo '<div class="status-icon"><i class="fas fa-exclamation-triangle"></i></div>';
            echo '<div class="status-content">';
            echo '<h3>System Operational with Warnings</h3>';
            echo '<p>System has ' . $totalWarnings . ' warning(s) but is operational. Review warnings below.</p>';
            echo '</div>';
            echo '</div>';
        } else {
            echo '<div class="overall-status error">';
            echo '<div class="status-icon"><i class="fas fa-times-circle"></i></div>';
            echo '<div class="status-content">';
            echo '<h3>System Issues Detected</h3>';
            echo '<p>System has ' . $totalIssues . ' issue(s) that need immediate attention.</p>';
            echo '</div>';
            echo '</div>';
        }
        
        // Success Items
        if (!empty($this->success)) {
            echo '<div class="results-section success">';
            echo '<h3><i class="fas fa-check-circle"></i> Success Items</h3>';
            echo '<div class="items-list">';
            foreach ($this->success as $item) {
                echo '<div class="item success-item">';
                echo '<i class="fas fa-check"></i>';
                echo '<span>' . dave_htmlspecialchars($item) . '</span>';
                echo '</div>';
            }
            echo '</div>';
            echo '</div>';
        }
        
        // Warnings
        if (!empty($this->warnings)) {
            echo '<div class="results-section warning">';
            echo '<h3><i class="fas fa-exclamation-triangle"></i> Warnings</h3>';
            echo '<div class="items-list">';
            foreach ($this->warnings as $item) {
                echo '<div class="item warning-item">';
                echo '<i class="fas fa-exclamation-triangle"></i>';
                echo '<span>' . dave_htmlspecialchars($item) . '</span>';
                echo '</div>';
            }
            echo '</div>';
            echo '</div>';
        }
        
        // Issues
        if (!empty($this->issues)) {
            echo '<div class="results-section error">';
            echo '<h3><i class="fas fa-times-circle"></i> Critical Issues</h3>';
            echo '<div class="items-list">';
            foreach ($this->issues as $item) {
                echo '<div class="item error-item">';
                echo '<i class="fas fa-times"></i>';
                echo '<span>' . dave_htmlspecialchars($item) . '</span>';
                echo '</div>';
            }
            echo '</div>';
            echo '</div>';
        }
        
        echo '</div>';
    }
}

// Run the health check
$checker = new HealthChecker();
$checker->runHealthCheck();
?>
