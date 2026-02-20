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

class RecallImporter {
    private $db;
    private $fdaApiKey;
    private $baseUrl = 'https://api.fda.gov';
    private $logFile;
    
    public function __construct() {
        $this->db = DatabaseConfig::getInstance();
        $this->fdaApiKey = getenv('OPENFDA_API_KEY') ?: '';
        $this->logFile = __DIR__ . '/../logs/recall_import.log';
        
        // Ensure log directory exists
        $logDir = dirname($this->logFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
    }
    
    /**
     * Import recalls from FDA API
     */
    public function importRecalls($daysBack = 30, $limit = 100) {
        $this->log("Starting recall import for last {$daysBack} days (limit: {$limit})");
        
        try {
            // Calculate date range
            $endDate = date('Ymd');
            $startDate = date('Ymd', strtotime("-{$daysBack} days"));
            
            // Fetch recalls from FDA API
            $recalls = $this->fetchRecallsFromFDA($startDate, $endDate, $limit);
            
            if (empty($recalls)) {
                $this->log("No recalls found in date range");
                return [
                    'success' => true,
                    'imported' => 0,
                    'updated' => 0,
                    'errors' => 0
                ];
            }
            
            $this->log("Found " . count($recalls) . " recalls to process");
            
            // Process each recall
            $imported = 0;
            $updated = 0;
            $errors = 0;
            
            foreach ($recalls as $recallData) {
                try {
                    $result = $this->processRecall($recallData);
                    if ($result['action'] === 'inserted') {
                        $imported++;
                    } elseif ($result['action'] === 'updated') {
                        $updated++;
                    }
                } catch (Exception $e) {
                    $this->log("Error processing recall: " . $e->getMessage());
                    $errors++;
                }
            }
            
            $this->log("Import completed: {$imported} imported, {$updated} updated, {$errors} errors");
            
            return [
                'success' => true,
                'imported' => $imported,
                'updated' => $updated,
                'errors' => $errors,
                'total_processed' => count($recalls)
            ];
            
        } catch (Exception $e) {
            $this->log("Import failed: " . $e->getMessage());
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Fetch recalls from FDA API
     */
    private function fetchRecallsFromFDA($startDate, $endDate, $limit) {
        $url = $this->baseUrl . '/device/enforcement.json';
        
        // Implement proper date range filtering
        $params = [
            'limit' => $limit,
            'search' => "recall_initiation_date:[{$startDate}+TO+{$endDate}]"
        ];
        
        if ($this->fdaApiKey) {
            $params['api_key'] = $this->fdaApiKey;
        }
        
        $this->log("Fetching recalls from FDA API: " . $url);
        $this->log("Parameters: " . json_encode($params));
        
        // Manually construct URL to preserve +TO+ syntax for FDA API
        $queryString = "limit={$limit}&search=recall_initiation_date:[{$startDate}+TO+{$endDate}]";
        if ($this->fdaApiKey) {
            $queryString .= "&api_key=" . urlencode($this->fdaApiKey);
        }
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url . '?' . $queryString);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_USERAGENT, '-RecallImporter/1.0');
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            throw new Exception("cURL error: " . $error);
        }
        
        if ($httpCode !== 200) {
            throw new Exception("HTTP error: {$httpCode} - " . substr($response, 0, 500));
        }
        
        $data = json_decode($response, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("JSON decode error: " . json_last_error_msg());
        }
        
        if (!isset($data['results'])) {
            $this->log("No results in FDA response");
            return [];
        }
        
        $this->log("FDA API returned " . count($data['results']) . " recalls");
        return $data['results'];
    }
    
    /**
     * Process individual recall data
     */
    private function processRecall($recallData) {
        // Parse and clean recall data
        $recall = $this->parseRecallData($recallData);
        
        if (!$recall) {
            throw new Exception("Failed to parse recall data");
        }
        
        // Check if recall already exists
        $existing = $this->getExistingRecall($recall['fda_recall_number']);
        
        if ($existing) {
            // Update existing recall
            $this->updateRecall($existing['recall_id'], $recall);
            return ['action' => 'updated', 'recall_id' => $existing['recall_id']];
        } else {
            // Insert new recall
            $recallId = $this->insertRecall($recall);
            return ['action' => 'inserted', 'recall_id' => $recallId];
        }
    }
    
    /**
     * Parse FDA recall data into standardized format
     */
    private function parseRecallData($data) {
        try {
            $recall = [
                'fda_recall_number' => $this->safeString($data['recall_number'] ?? ''),
                'recall_date' => $this->parseDate($data['recall_initiation_date'] ?? $data['center_classification_date'] ?? ''),
                'product_description' => $this->safeString($data['product_description'] ?? ''),
                'reason_for_recall' => $this->safeString($data['reason_for_recall'] ?? ''),
                'manufacturer_name' => $this->safeString($data['recalling_firm'] ?? ''),
                'product_code' => $this->safeString($data['code_info'] ?? ''),
                'recall_classification' => $this->safeString($data['classification'] ?? ''),
                'recall_status' => $this->mapRecallStatus($data['status'] ?? ''),
                'fda_data' => json_encode($data)
            ];
            
            // Validate required fields
            if (empty($recall['fda_recall_number'])) {
                $this->log("Missing recall number, skipping");
                return null;
            }
            
            return $recall;
            
        } catch (Exception $e) {
            $this->log("Error parsing recall data: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Map FDA status to our status
     */
    private function mapRecallStatus($fdaStatus) {
        switch (strtolower($fdaStatus)) {
            case 'ongoing':
                return 'Active';
            case 'completed':
                return 'Resolved';
            case 'terminated':
                return 'Closed';
            default:
                return 'Active';
        }
    }
    
    /**
     * Get existing recall by FDA recall number
     */
    private function getExistingRecall($fdaRecallNumber) {
        $sql = "SELECT recall_id FROM recalls WHERE fda_recall_number = ?";
        $stmt = $this->db->prepare($sql);
        $stmt->execute([$fdaRecallNumber]);
        return $stmt->fetch();
    }
    
    /**
     * Insert new recall
     */
    private function insertRecall($recall) {
        // Generate UUID for recall_id
        $recallId = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
        
        $sql = "INSERT INTO recalls (
            recall_id, fda_recall_number, recall_date, product_description, reason_for_recall,
            manufacturer_name, product_code, recall_classification, recall_status, fda_data
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        $stmt = $this->db->prepare($sql);
        $stmt->execute([
            $recallId,
            $this->truncateString($recall['fda_recall_number'], 50),
            $recall['recall_date'],
            $recall['product_description'], // TEXT field, no truncation needed
            $recall['reason_for_recall'], // TEXT field, no truncation needed
            $this->truncateString($recall['manufacturer_name'], 100),
            $recall['product_code'], // TEXT field, no truncation needed
            $this->truncateString($recall['recall_classification'], 20),
            $this->truncateString($recall['recall_status'], 20),
            $recall['fda_data']
        ]);
        
        return $recallId;
    }
    
    /**
     * Truncate string to specified length
     */
    private function truncateString($string, $maxLength) {
        if (strlen($string) > $maxLength) {
            return substr($string, 0, $maxLength - 3) . '...';
        }
        return $string;
    }
    
    /**
     * Update existing recall
     */
    private function updateRecall($recallId, $recall) {
        $sql = "UPDATE recalls SET 
            recall_date = ?, product_description = ?, reason_for_recall = ?,
            manufacturer_name = ?, product_code = ?, recall_classification = ?,
            recall_status = ?, fda_data = ?, updated_at = CURRENT_TIMESTAMP
            WHERE recall_id = ?";
        
        $stmt = $this->db->prepare($sql);
        $stmt->execute([
            $recall['recall_date'],
            $recall['product_description'],
            $recall['reason_for_recall'],
            $recall['manufacturer_name'],
            $recall['product_code'],
            $recall['recall_classification'],
            $recall['recall_status'],
            $recall['fda_data'],
            $recallId
        ]);
    }
    
    /**
     * Parse FDA date format
     */
    private function parseDate($dateString) {
        if (empty($dateString)) {
            return null;
        }
        
        // FDA dates are typically in YYYYMMDD format
        if (preg_match('/^(\d{4})(\d{2})(\d{2})$/', $dateString, $matches)) {
            return $matches[1] . '-' . $matches[2] . '-' . $matches[3];
        }
        
        // Try other common formats
        $timestamp = strtotime($dateString);
        if ($timestamp !== false) {
            return date('Y-m-d', $timestamp);
        }
        
        return null;
    }
    
    /**
     * Safe string conversion
     */
    private function safeString($value) {
        if (is_null($value)) {
            return '';
        }
        return trim((string)$value);
    }
    
    /**
     * Log message
     */
    private function log($message) {
        $timestamp = date('Y-m-d H:i:s');
        $logMessage = "[{$timestamp}] {$message}" . PHP_EOL;
        file_put_contents($this->logFile, $logMessage, FILE_APPEND | LOCK_EX);
        
        // Only output to console for CLI usage when called directly, not when included
        if (php_sapi_name() === 'cli' && !isset($_GET['ajax']) && basename($_SERVER['PHP_SELF']) === basename(__FILE__)) {
            echo $logMessage;
        }
    }
}

// Command line interface - only run when called directly from CLI
if (php_sapi_name() === 'cli' && basename($_SERVER['PHP_SELF']) === basename(__FILE__)) {
    $daysBack = isset($argv[1]) ? (int)$argv[1] : 30;
    $limit = isset($argv[2]) ? (int)$argv[2] : 100;
    
    echo " Recall Import Tool\n";
    echo "======================\n\n";
    
    $importer = new RecallImporter();
    $result = $importer->importRecalls($daysBack, $limit);
    
    if ($result['success']) {
        echo "\n✅ Import completed successfully!\n";
        echo "   Imported: {$result['imported']}\n";
        echo "   Updated: {$result['updated']}\n";
        echo "   Errors: {$result['errors']}\n";
        echo "   Total processed: {$result['total_processed']}\n";
    } else {
        echo "\n❌ Import failed: {$result['error']}\n";
        exit(1);
    }
}
