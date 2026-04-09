<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

require_once __DIR__ . '/../services/shell_command_utilities.php';

/**
 * Look up manufacturer from MAC address using Python OUI service
 * 
 * @param string $macAddress MAC address (format: XX:XX:XX:XX:XX:XX or XXXXXX)
 * @return string|null Manufacturer name or null if not found
 */
function lookupManufacturerFromMac($macAddress) {
    if (empty($macAddress)) {
        return null;
    }
    
    try {
        // Clean and validate MAC address
        $mac = str_replace([':', '-', ' '], '', strtoupper(trim($macAddress)));
        if (strlen($mac) < 6) {
            return null;
        }
        
        // Get OUI (first 6 characters)
        $oui = substr($mac, 0, 6);
        
        // Call Python OUI lookup service
        // Redirect stderr to /dev/null to suppress logging errors
        $pythonScript = _ROOT . '/python/services/oui_lookup.py';
        $command = "cd " . _ROOT . " && python3 " . escapeshellarg($pythonScript) . " --lookup " . escapeshellarg($oui) . " 2>/dev/null";
        
        $result = ShellCommandUtilities::executeShellCommand($command, ['trim_output' => true]);
        $output = $result['success'] ? $result['output'] : '';
        
        if (empty($output)) {
            return null;
        }
        
        // Clean output - the Python script with --lookup should only output the manufacturer name
        $manufacturer = $output;
        
        // Remove any trailing newlines or whitespace
        $manufacturer = rtrim($manufacturer, " \n\r\t\0\x0B$");
        
        // Validate it's a reasonable manufacturer name
        if (empty($manufacturer) || 
            strlen($manufacturer) < 2 || 
            strlen($manufacturer) > 100 ||
            stripos($manufacturer, 'Error') !== false || 
            stripos($manufacturer, 'Not Found') !== false ||
            stripos($manufacturer, 'Traceback') !== false ||
            stripos($manufacturer, 'Testing') !== false ||
            stripos($manufacturer, 'fatal') !== false ||
            preg_match('/^\d{4}-\d{2}-\d{2}/', $manufacturer)) { // Skip date prefixes
            return null;
        }
        
        return $manufacturer;
        
    } catch (Exception $e) {
        error_log("OUI lookup error for MAC {$macAddress}: " . $e->getMessage());
        return null;
    }
}

/**
 * Batch lookup manufacturers for multiple MAC addresses
 * 
 * @param array $macAddresses Array of MAC addresses
 * @return array Associative array of MAC => Manufacturer
 */
function batchLookupManufacturers($macAddresses) {
    if (empty($macAddresses)) {
        return [];
    }
    
    $results = [];
    
    foreach ($macAddresses as $mac) {
        $manufacturer = lookupManufacturerFromMac($mac);
        if ($manufacturer) {
            $results[$mac] = $manufacturer;
        }
    }
    
    return $results;
}

