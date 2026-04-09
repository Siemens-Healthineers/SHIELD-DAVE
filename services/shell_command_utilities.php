<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

/**
 * Shell Command Utilities
 * 
 * Provides secure and flexible shell command execution with support for
 * both blocking and non-blocking operations.
 */
class ShellCommandUtilities {
    
    /**
     * Execute a shell command with configurable blocking behavior
     * 
     * @param string $command The shell command to execute
     * @param array $options Configuration options:
     *   - blocking: bool (default: true) - Wait for command completion
     *   - capture_stderr: bool (default: true) - Redirect stderr to stdout
     *   - trim_output: bool (default: false) - Trim whitespace from output
     *   - return_pid: bool (default: false) - Return process ID (non-blocking only)
     *   - timeout: int (default: 0) - Command timeout in seconds (0 = no timeout)
     *   - working_dir: string (default: null) - Working directory for command
     *   - log_file: string (default: null) - Log file path for non-blocking commands
     * 
     * @return array Result array with keys:
     *   - success: bool - Command execution status
     *   - output: string|null - Command output (blocking) or null (non-blocking)
     *   - pid: int|null - Process ID (non-blocking with return_pid=true)
     *   - error: string|null - Error message if failed
     */
    public static function executeShellCommand($command, $options = []) {
        // Default options
        $defaults = [
            'blocking' => true,
            'capture_stderr' => true,
            'trim_output' => false,
            'return_pid' => false,
            'timeout' => 0,
            'working_dir' => null,
            'log_file' => null
        ];
        
        $opts = array_merge($defaults, $options);
        
        // Log function entry
        if ($opts['log_file'] !== null) {
            $logMsg = "[" . date('Y-m-d H:i:s') . "] ShellCommandUtilities::executeShellCommand() called\n";
            $logMsg .= "  Command: " . $command . "\n";
            $logMsg .= "  Options: " . json_encode($opts) . "\n";
            file_put_contents($opts['log_file'], $logMsg, FILE_APPEND);
        }
        
        // Validate command
        if (empty($command)) {
            if ($opts['log_file'] !== null) {
                file_put_contents($opts['log_file'], "[" . date('Y-m-d H:i:s') . "] ERROR: Command is empty\n", FILE_APPEND);
            }
            return [
                'success' => false,
                'output' => null,
                'pid' => null,
                'error' => 'Command cannot be empty'
            ];
        }
        
        // Build the final command
        $finalCommand = $command;
        
        // Add working directory if specified
        if ($opts['working_dir'] !== null) {
            $finalCommand = "cd " . escapeshellarg($opts['working_dir']) . " && " . $finalCommand;
            if ($opts['log_file'] !== null) {
                file_put_contents($opts['log_file'], "[" . date('Y-m-d H:i:s') . "] Added working directory: " . $opts['working_dir'] . "\n", FILE_APPEND);
            }
        }
        
        // Handle stderr redirection
        if ($opts['capture_stderr'] && $opts['blocking']) {
            // Only add for blocking mode - non-blocking handles it in nohup command
            if (strpos($finalCommand, '2>&1') === false) {
                $finalCommand .= ' 2>&1';
            }
        }
        
        if ($opts['log_file'] !== null) {
            file_put_contents($opts['log_file'], "[" . date('Y-m-d H:i:s') . "] Final command: " . $finalCommand . "\n", FILE_APPEND);
            file_put_contents($opts['log_file'], "[" . date('Y-m-d H:i:s') . "] Execution mode: " . ($opts['blocking'] ? 'BLOCKING' : 'NON-BLOCKING') . "\n", FILE_APPEND);
        }
        
        if ($opts['blocking']) {
            return self::executeBlocking($finalCommand, $opts);
        } else {
            return self::executeNonBlocking($finalCommand, $opts);
        }
    }
    
    /**
     * Execute command in blocking mode
     */
    private static function executeBlocking($command, $opts) {
        try {
            if ($opts['log_file'] !== null) {
                file_put_contents($opts['log_file'], "[" . date('Y-m-d H:i:s') . "] executeBlocking() started\n", FILE_APPEND);
            }
            
            // Apply timeout if specified
            if ($opts['timeout'] > 0) {
                // Wrap command in sh -c to ensure timeout applies to entire command chain
                $escapedCommand = str_replace("'", "'\\''", $command); // Escape single quotes
                $command = "timeout {$opts['timeout']} sh -c '" . $escapedCommand . "'";
                if ($opts['log_file'] !== null) {
                    file_put_contents($opts['log_file'], "[" . date('Y-m-d H:i:s') . "] Timeout applied: {$opts['timeout']} seconds\n", FILE_APPEND);
                }
            }
            
            if ($opts['log_file'] !== null) {
                file_put_contents($opts['log_file'], "[" . date('Y-m-d H:i:s') . "] Executing shell_exec()...\n", FILE_APPEND);
            }
            
            // Execute command
            $output = shell_exec($command);
            
            if ($opts['log_file'] !== null) {
                file_put_contents($opts['log_file'], "[" . date('Y-m-d H:i:s') . "] shell_exec() completed\n", FILE_APPEND);
                file_put_contents($opts['log_file'], "[" . date('Y-m-d H:i:s') . "] Output length: " . strlen($output ?? '') . " bytes\n", FILE_APPEND);
            }
            
            // Handle output
            if ($output === null) {
                if ($opts['log_file'] !== null) {
                    file_put_contents($opts['log_file'], "[" . date('Y-m-d H:i:s') . "] ERROR: Command returned null output\n", FILE_APPEND);
                }
                return [
                    'success' => false,
                    'output' => null,
                    'pid' => null,
                    'error' => 'Command execution failed or returned no output'
                ];
            }
            
            // Trim output if requested
            if ($opts['trim_output']) {
                $output = trim($output);
            }
            
            if ($opts['log_file'] !== null) {
                file_put_contents($opts['log_file'], "[" . date('Y-m-d H:i:s') . "] SUCCESS: Blocking execution completed\n", FILE_APPEND);
            }
            
            return [
                'success' => true,
                'output' => $output,
                'pid' => null,
                'error' => null
            ];
            
        } catch (Exception $e) {
            if ($opts['log_file'] !== null) {
                file_put_contents($opts['log_file'], "[" . date('Y-m-d H:i:s') . "] EXCEPTION: " . $e->getMessage() . "\n", FILE_APPEND);
            }
            return [
                'success' => false,
                'output' => null,
                'pid' => null,
                'error' => 'Exception: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Execute command in non-blocking mode
     */
    private static function executeNonBlocking($command, $opts) {
        // Determine log file path
        $logFile = $opts['log_file'];
        if ($logFile === null) {
            $logFile = '/tmp/shell_cmd_' . uniqid() . '_' . date('Ymd_His') . '.log';
        }
        
        try {
            if ($logFile !== null) {
                file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] executeNonBlocking() started\n", FILE_APPEND);
                file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] PHP OS: " . PHP_OS . "\n", FILE_APPEND);
                file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] shell_exec available: " . (function_exists('shell_exec') ? 'YES' : 'NO') . "\n", FILE_APPEND);
                file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] Output log file: " . $logFile . "\n", FILE_APPEND);
            }
            
            // Build non-blocking command
            // Use nohup to detach from terminal
            // Wrap command in sh -c to ensure nohup applies to entire command chain
            // Redirect output to log file
            // Use & to run in background
            // Echo $! to capture PID
            $escapedCommand = str_replace("'", "'\\''", $command); // Escape single quotes for sh -c
            $nonBlockingCmd = "nohup sh -c '" . $escapedCommand . "' >> " . escapeshellarg($logFile) . " 2>&1 & echo \$!";
            
            if ($logFile !== null) {
                file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] Non-blocking command: " . $nonBlockingCmd . "\n", FILE_APPEND);
                file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] Executing shell_exec() to get PID...\n", FILE_APPEND);
            }
            
            // Execute and capture PID
            $pid = shell_exec($nonBlockingCmd);
            
            if ($logFile !== null) {
                file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] Raw PID output: '" . var_export($pid, true) . "'\n", FILE_APPEND);
            }
            
            if ($pid !== null) {
                $pid = trim($pid);
                
                if ($logFile !== null) {
                    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] Trimmed PID: '" . $pid . "'\n", FILE_APPEND);
                }
                
                // Validate PID
                if (!is_numeric($pid) || empty($pid)) {
                    if ($logFile !== null) {
                        file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] ERROR: Invalid PID (not numeric or empty)\n", FILE_APPEND);
                    }
                    return [
                        'success' => false,
                        'output' => null,
                        'pid' => null,
                        'error' => 'Failed to capture valid process ID',
                        'log_file' => $logFile
                    ];
                }
                
                // Verify process is running
                $checkCmd = "ps -p $pid > /dev/null 2>&1 && echo 'running' || echo 'not_running'";
                $processStatus = trim(shell_exec($checkCmd));
                
                if ($logFile !== null) {
                    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] Process status: " . $processStatus . "\n", FILE_APPEND);
                }
                
                $result = [
                    'success' => true,
                    'output' => null,
                    'pid' => (int)$pid,
                    'error' => null,
                    'log_file' => $logFile,
                    'process_status' => $processStatus
                ];
                
                // Optionally return PID in output for backward compatibility
                if ($opts['return_pid']) {
                    $result['output'] = $pid;
                }
                
                if ($logFile !== null) {
                    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] SUCCESS: Non-blocking execution started, PID=" . $pid . "\n", FILE_APPEND);
                }
                
                return $result;
            } else {
                if ($logFile !== null) {
                    file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] ERROR: shell_exec() returned null\n", FILE_APPEND);
                }
                return [
                    'success' => false,
                    'output' => null,
                    'pid' => null,
                    'error' => 'Failed to execute non-blocking command',
                    'log_file' => $logFile
                ];
            }
            
        } catch (Exception $e) {
            if ($logFile !== null) {
                file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] EXCEPTION: " . $e->getMessage() . "\n", FILE_APPEND);
            }
            return [
                'success' => false,
                'output' => null,
                'pid' => null,
                'error' => 'Exception: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Check if a process is still running
     * 
     * @param int $pid Process ID
     * @return bool True if process is running, false otherwise
     */
    public static function isProcessRunning($pid) {
        if (!is_numeric($pid) || $pid <= 0) {
            return false;
        }
        
        $command = "ps -p $pid > /dev/null 2>&1 && echo '1' || echo '0'";
        $result = trim(shell_exec($command));
        
        return $result === '1';
    }
    
    /**
     * Kill a process by PID
     * 
     * @param int $pid Process ID
     * @param bool $force Use SIGKILL instead of SIGTERM
     * @return bool True if kill signal sent successfully
     */
    public static function killProcess($pid, $force = false) {
        if (!is_numeric($pid) || $pid <= 0) {
            return false;
        }
        
        $signal = $force ? '-9' : '-15';
        $command = "kill $signal $pid 2>&1";
        $output = shell_exec($command);
        
        // If no output, kill was successful
        return empty(trim($output));
    }
    
    /**
     * Get the output from a non-blocking command's log file
     * 
     * @param string $logFile Path to the log file
     * @param bool $tail Get only the last n lines (false = all content)
     * @param int $lines Number of lines to tail if tail is true
     * @return string|null Log file content or null if file doesn't exist
     */
    public static function getCommandOutput($logFile, $tail = false, $lines = 100) {
        if (!file_exists($logFile)) {
            return null;
        }
        
        if ($tail) {
            $command = "tail -n $lines " . escapeshellarg($logFile);
            return shell_exec($command);
        } else {
            return file_get_contents($logFile);
        }
    }
    
    /**
     * Wait for a non-blocking process to complete
     * 
     * @param int $pid Process ID
     * @param int $timeout Maximum wait time in seconds (0 = no timeout)
     * @param int $pollInterval How often to check in microseconds (default: 100ms)
     * @return array Result with keys: completed, timed_out, duration
     */
    public static function waitForProcess($pid, $timeout = 0, $pollInterval = 100000) {
        if (!is_numeric($pid) || $pid <= 0) {
            return [
                'completed' => false,
                'timed_out' => false,
                'duration' => 0,
                'error' => 'Invalid PID'
            ];
        }
        
        $startTime = microtime(true);
        $hasTimeout = $timeout > 0;
        
        while (self::isProcessRunning($pid)) {
            usleep($pollInterval);
            
            $elapsed = microtime(true) - $startTime;
            
            if ($hasTimeout && $elapsed >= $timeout) {
                return [
                    'completed' => false,
                    'timed_out' => true,
                    'duration' => $elapsed
                ];
            }
        }
        
        return [
            'completed' => true,
            'timed_out' => false,
            'duration' => microtime(true) - $startTime
        ];
    }
    
    /**
     * Execute multiple commands in parallel (non-blocking)
     * 
     * @param array $commands Array of commands to execute
     * @param array $options Common options for all commands
     * @return array Array of results for each command
     */
    public static function executeParallel($commands, $options = []) {
        $results = [];
        $options['blocking'] = false;
        
        foreach ($commands as $index => $command) {
            $results[$index] = self::executeShellCommand($command, $options);
        }
        
        return $results;
    }
    
    /**
     * Clean up old log files
     * 
     * @param string $directory Directory containing log files
     * @param int $olderThanDays Delete logs older than this many days
     * @param string $pattern File pattern to match (default: shell_cmd_*.log)
     * @return int Number of files deleted
     */
    public static function cleanupLogFiles($directory = '/tmp', $olderThanDays = 7, $pattern = 'shell_cmd_*.log') {
        $command = "find " . escapeshellarg($directory) . " -name " . escapeshellarg($pattern) . " -type f -mtime +$olderThanDays -delete -print";
        $output = shell_exec($command);
        
        if ($output === null) {
            return 0;
        }
        
        $deletedFiles = array_filter(explode("\n", trim($output)));
        return count($deletedFiles);
    }
}
