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

class RecallDeviceMatcher {
    private $db;
    private $logFile;
    
    public function __construct() {
        $this->db = DatabaseConfig::getInstance();
        $this->logFile = __DIR__ . '/../logs/recall_matching.log';
        
        // Ensure log directory exists
        $logDir = dirname($this->logFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
    }
    
    /**
     * Match recalls to devices
     */
    public function matchRecallsToDevices($recallId = null) {
        $this->log("Starting recall-device matching process");
        
        try {
            // Get recalls to process
            $recalls = $this->getRecallsToProcess($recallId);
            
            if (empty($recalls)) {
                $this->log("No recalls found to process");
                return [
                    'success' => true,
                    'matched' => 0,
                    'total_recalls' => 0
                ];
            }
            
            $this->log("Processing " . count($recalls) . " recalls");
            
            $totalMatched = 0;
            
            foreach ($recalls as $recall) {
                $matched = $this->matchRecallToDevices($recall);
                $totalMatched += $matched;
                $this->log("Recall {$recall['fda_recall_number']}: {$matched} devices matched");
            }
            
            $this->log("Matching completed: {$totalMatched} total matches");
            
            return [
                'success' => true,
                'matched' => $totalMatched,
                'total_recalls' => count($recalls)
            ];
            
        } catch (Exception $e) {
            $this->log("Matching failed: " . $e->getMessage());
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    /**
     * Get recalls to process
     */
    private function getRecallsToProcess($recallId = null) {
        if ($recallId) {
            $sql = "SELECT * FROM recalls WHERE recall_id = ?";
            $stmt = $this->db->prepare($sql);
            $stmt->execute([$recallId]);
            $recalls = $stmt->fetchAll();
        } else {
            // Get all active recalls
            $sql = "SELECT * FROM recalls WHERE recall_status = 'Active' ORDER BY recall_date DESC";
            $stmt = $this->db->query($sql);
            $recalls = $stmt->fetchAll();
        }
        
        return $recalls;
    }
    
    /**
     * Match a single recall to devices
     */
    private function matchRecallToDevices($recall) {
        $matched = 0;
        
        // Get all mapped devices
        $devices = $this->getMappedDevices();
        
        foreach ($devices as $device) {
            if ($this->isDeviceAffectedByRecall($device, $recall)) {
                $this->createDeviceRecallLink($device['device_id'], $recall['recall_id']);
                $matched++;
            }
        }
        
        return $matched;
    }
    
    /**
     * Get all mapped devices
     */
    private function getMappedDevices() {
        $sql = "SELECT 
            md.device_id,
            md.manufacturer_name,
            md.brand_name,
            md.device_name,
            md.model_number,
            md.product_code,
            md.k_number,
            md.udi,
            a.hostname,
            a.manufacturer as asset_manufacturer,
            a.model as asset_model
            FROM medical_devices md
            JOIN assets a ON md.asset_id = a.asset_id
            WHERE md.device_id IS NOT NULL";
        
        $stmt = $this->db->query($sql);
        return $stmt->fetchAll();
    }
    
    /**
     * Check if device is affected by recall
     */
    private function isDeviceAffectedByRecall($device, $recall) {
        // First, check for exact manufacturer match (required)
        if (!$this->matchManufacturerExact($device, $recall)) {
            return false;
        }
        
        // If we have a 510k number, try to match it exactly
        if (!empty($device['k_number'])) {
            if ($this->match510kNumber($device, $recall)) {
                $this->log("Exact 510k match: Device K{$device['k_number']} -> Recall {$recall['fda_recall_number']}");
                return true;
            }
        }
        
        // If we have a UDI, try to match it
        if (!empty($device['udi'])) {
            if ($this->matchUDI($device, $recall)) {
                $this->log("Exact UDI match: Device UDI {$device['udi']} -> Recall {$recall['fda_recall_number']}");
                return true;
            }
        }
        
        // If we have a product code, try exact match
        if (!empty($device['product_code']) && !empty($recall['product_code'])) {
            if ($this->matchProductCodeExact($device, $recall)) {
                $this->log("Exact product code match: Device {$device['product_code']} -> Recall {$recall['fda_recall_number']}");
                return true;
            }
        }
        
        // For high-confidence matches only, check model number in description
        if (!empty($device['model_number'])) {
            if ($this->matchModelInDescription($device, $recall)) {
                $this->log("Model number match: Device model {$device['model_number']} -> Recall {$recall['fda_recall_number']}");
                return true;
            }
        }
        
        // Check for brand name in recall description (lower confidence)
        if (!empty($device['brand_name'])) {
            if ($this->matchBrandInDescription($device, $recall)) {
                $this->log("Brand name match: Device brand {$device['brand_name']} -> Recall {$recall['fda_recall_number']}");
                return true;
            }
        }
        
        // No match found
        return false;
    }
    
    /**
     * Match manufacturer names
     */
    private function matchManufacturer($device, $recall) {
        $deviceManufacturers = [
            $device['manufacturer_name'],
            $device['asset_manufacturer']
        ];
        
        $recallManufacturer = $recall['manufacturer_name'];
        
        foreach ($deviceManufacturers as $deviceManufacturer) {
            if (empty($deviceManufacturer) || empty($recallManufacturer)) {
                continue;
            }
            
            // Exact match
            if (strcasecmp($deviceManufacturer, $recallManufacturer) === 0) {
                return true;
            }
            
            // Partial match (contains)
            if (stripos($deviceManufacturer, $recallManufacturer) !== false ||
                stripos($recallManufacturer, $deviceManufacturer) !== false) {
                return true;
            }
            
            // Common manufacturer name variations
            $variations = $this->getManufacturerVariations($deviceManufacturer);
            foreach ($variations as $variation) {
                if (stripos($recallManufacturer, $variation) !== false) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Get manufacturer name variations
     */
    private function getManufacturerVariations($manufacturer) {
        $variations = [];
        
        // Remove common suffixes
        $base = preg_replace('/\s+(inc|llc|ltd|corp|corporation|company|co\.?)$/i', '', $manufacturer);
        if ($base !== $manufacturer) {
            $variations[] = $base;
        }
        
        // Remove common prefixes
        $base = preg_replace('/^(the\s+)/i', '', $manufacturer);
        if ($base !== $manufacturer) {
            $variations[] = $base;
        }
        
        // Split on common separators
        $parts = preg_split('/[\s,&\-]+/', $manufacturer);
        if (count($parts) > 1) {
            $variations[] = $parts[0]; // First part
            $variations[] = implode(' ', array_slice($parts, 0, 2)); // First two parts
        }
        
        // Special handling for Siemens variations
        if (stripos($manufacturer, 'siemens') !== false) {
            $variations[] = 'Siemens';
            $variations[] = 'Siemens Healthcare';
            $variations[] = 'Siemens Medical';
            $variations[] = 'Siemens Healthcare GmbH';
            $variations[] = 'Siemens Healthcare Diagnostics';
            $variations[] = 'Siemens Medical Solutions';
        }
        
        // Special handling for Philips variations
        if (stripos($manufacturer, 'philips') !== false) {
            $variations[] = 'Philips';
            $variations[] = 'Philips Medical';
            $variations[] = 'Philips Healthcare';
            $variations[] = 'Philips Medical Systems';
            $variations[] = 'Philips Medical Systems North America';
            $variations[] = 'Philips Medical Systems Nederland';
            $variations[] = 'Philips Medical Systems Nederland B.V.';
            $variations[] = 'Philips Medical Systems North America, Inc.';
            $variations[] = 'Philips Healthcare B.V.';
            $variations[] = 'Philips Medical Systems B.V.';
        }
        
        return array_unique($variations);
    }
    
    /**
     * Match product codes
     */
    private function matchProductCode($device, $recall) {
        $deviceProductCode = $device['product_code'];
        $recallProductCode = $recall['product_code'];
        
        if (empty($deviceProductCode) || empty($recallProductCode)) {
            return false;
        }
        
        // Exact match
        if (strcasecmp($deviceProductCode, $recallProductCode) === 0) {
            return true;
        }
        
        // Partial match
        if (stripos($deviceProductCode, $recallProductCode) !== false ||
            stripos($recallProductCode, $deviceProductCode) !== false) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Match brand names
     */
    private function matchBrandName($device, $recall) {
        $deviceBrands = [
            $device['brand_name'],
            $device['device_name']
        ];
        
        $recallDescription = $recall['product_description'];
        
        foreach ($deviceBrands as $deviceBrand) {
            if (empty($deviceBrand) || empty($recallDescription)) {
                continue;
            }
            
            // Check if brand name appears in product description
            if (stripos($recallDescription, $deviceBrand) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Match model numbers
     */
    private function matchModelNumber($device, $recall) {
        $deviceModels = [
            $device['model_number'],
            $device['asset_model']
        ];
        
        $recallDescription = $recall['product_description'];
        
        foreach ($deviceModels as $deviceModel) {
            if (empty($deviceModel) || empty($recallDescription)) {
                continue;
            }
            
            // Check if model appears in product description
            if (stripos($recallDescription, $deviceModel) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Match product descriptions
     */
    private function matchProductDescription($device, $recall) {
        $deviceNames = [
            $device['brand_name'],
            $device['device_name'],
            $device['model_number']
        ];
        
        $recallDescription = $recall['product_description'];
        
        foreach ($deviceNames as $deviceName) {
            if (empty($deviceName) || empty($recallDescription)) {
                continue;
            }
            
            // Check for partial matches in description
            if (stripos($recallDescription, $deviceName) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Match manufacturer names exactly (required for all matches)
     */
    private function matchManufacturerExact($device, $recall) {
        $deviceManufacturers = [
            $device['manufacturer_name'],
            $device['asset_manufacturer']
        ];
        
        $recallManufacturer = $recall['manufacturer_name'];
        
        foreach ($deviceManufacturers as $deviceManufacturer) {
            if (empty($deviceManufacturer) || empty($recallManufacturer)) {
                continue;
            }
            
            // Exact match (case insensitive)
            if (strcasecmp($deviceManufacturer, $recallManufacturer) === 0) {
                return true;
            }
            
            // Check for common variations
            $variations = $this->getManufacturerVariations($deviceManufacturer);
            foreach ($variations as $variation) {
                if (strcasecmp($variation, $recallManufacturer) === 0) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Match 510k number in recall data
     */
    private function match510kNumber($device, $recall) {
        $kNumber = $device['k_number'];
        $recallDescription = $recall['product_description'];
        $recallProductCode = $recall['product_code'];
        
        // Look for K number in product description
        if (stripos($recallDescription, $kNumber) !== false) {
            return true;
        }
        
        // Look for K number in product code
        if (stripos($recallProductCode, $kNumber) !== false) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Match UDI in recall data
     */
    private function matchUDI($device, $recall) {
        $udi = $device['udi'];
        $recallDescription = $recall['product_description'];
        $recallProductCode = $recall['product_code'];
        
        // Look for UDI in product description
        if (stripos($recallDescription, $udi) !== false) {
            return true;
        }
        
        // Look for UDI in product code
        if (stripos($recallProductCode, $udi) !== false) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Match product code exactly
     */
    private function matchProductCodeExact($device, $recall) {
        $deviceProductCode = $device['product_code'];
        $recallProductCode = $recall['product_code'];
        
        // Exact match
        if (strcasecmp($deviceProductCode, $recallProductCode) === 0) {
            return true;
        }
        
        // Check if device product code appears in recall product code
        if (stripos($recallProductCode, $deviceProductCode) !== false) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Match model number in recall description (high confidence only)
     */
    private function matchModelInDescription($device, $recall) {
        $modelNumber = $device['model_number'];
        $recallDescription = $recall['product_description'];
        
        if (empty($modelNumber) || empty($recallDescription)) {
            return false;
        }
        
        // Look for exact model number in description
        if (stripos($recallDescription, $modelNumber) !== false) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Match brand name in recall description (lower confidence)
     */
    private function matchBrandInDescription($device, $recall) {
        $brandName = $device['brand_name'];
        $recallDescription = $recall['product_description'];
        
        if (empty($brandName) || empty($recallDescription)) {
            return false;
        }
        
        // Look for brand name in description (case insensitive)
        if (stripos($recallDescription, $brandName) !== false) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Create device-recall link
     */
    private function createDeviceRecallLink($deviceId, $recallId) {
        // Check if link already exists
        $sql = "SELECT link_id FROM device_recalls_link WHERE device_id = ? AND recall_id = ?";
        $stmt = $this->db->prepare($sql);
        $stmt->execute([$deviceId, $recallId]);
        
        if ($stmt->fetch()) {
            // Link already exists
            return;
        }
        
        // Generate UUID for link_id
        $linkId = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
        
        // Create new link
        $sql = "INSERT INTO device_recalls_link (
            link_id, device_id, recall_id, remediation_status, created_at
        ) VALUES (?, ?, ?, 'Open', CURRENT_TIMESTAMP)";
        
        $stmt = $this->db->prepare($sql);
        $stmt->execute([$linkId, $deviceId, $recallId]);
        
        $this->log("Created device-recall link: {$deviceId} -> {$recallId}");
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
    $recallId = isset($argv[1]) ? $argv[1] : null;
    
    echo " Recall-Device Matching Tool\n";
    echo "=================================\n\n";
    
    $matcher = new RecallDeviceMatcher();
    $result = $matcher->matchRecallsToDevices($recallId);
    
    if ($result['success']) {
        echo "\n✅ Matching completed successfully!\n";
        echo "   Matches created: {$result['matched']}\n";
        echo "   Recalls processed: {$result['total_recalls']}\n";
    } else {
        echo "\n❌ Matching failed: {$result['error']}\n";
        exit(1);
    }
}
