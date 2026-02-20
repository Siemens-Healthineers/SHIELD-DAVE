<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

require_once __DIR__ . '/../config/database.php';

/**
 * GeoIP Service
 * Handles IP address geolocation using MaxMind API
 */
class GeoIPService {
    
    private $db;
    private $apiKey;
    private $baseUrl = 'https://geoip.maxmind.com/geoip/v2.1/';
    
    public function __construct() {
        $this->db = DatabaseConfig::getInstance();
        
        // Get MaxMind API key from config
        $this->apiKey = defined('MAXMIND_API_KEY') ? MAXMIND_API_KEY : null;
        
        // Check if API key is properly configured
        if (empty($this->apiKey) || $this->apiKey === 'your_maxmind_api_key_here') {
            $this->apiKey = null;
            error_log('GeoIPService: MAXMIND_API_KEY not configured or using placeholder value');
        }
    }
    
    /**
     * Get location information for an IP address
     * 
     * @param string $ipAddress IP address to lookup
     * @return array Location data or null if not found
     */
    public function getLocation($ipAddress) {
        // Skip private/local IPs
        if ($this->isPrivateIP($ipAddress)) {
            return [
                'country' => 'Local Network',
                'country_code' => 'LOCAL',
                'region' => 'Local',
                'city' => 'Local',
                'latitude' => null,
                'longitude' => null,
                'timezone' => null,
                'isp' => 'Local Network'
            ];
        }
        
        // Check cache first
        $cached = $this->getCachedLocation($ipAddress);
        if ($cached) {
            return $cached;
        }
        
        // If no API key, return unknown
        if (!$this->apiKey) {
            return [
                'country' => 'Unknown',
                'country_code' => 'UNKNOWN',
                'region' => 'Unknown',
                'city' => 'Unknown',
                'latitude' => null,
                'longitude' => null,
                'timezone' => null,
                'isp' => 'Unknown'
            ];
        }
        
        // Query MaxMind API
        $location = $this->queryMaxMindAPI($ipAddress);
        
        // Cache the result
        if ($location) {
            $this->cacheLocation($ipAddress, $location);
        }
        
        return $location;
    }
    
    /**
     * Check if IP is private/local
     * 
     * @param string $ipAddress IP address to check
     * @return bool True if private IP
     */
    private function isPrivateIP($ipAddress) {
        return !filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }
    
    /**
     * Query MaxMind API for IP location
     * 
     * @param string $ipAddress IP address to lookup
     * @return array|null Location data or null on error
     */
    private function queryMaxMindAPI($ipAddress) {
        // If no API key configured, return null
        if (!$this->apiKey) {
            error_log("GeoIPService: Cannot query MaxMind API - no API key configured");
            return null;
        }
        
        try {
            $url = $this->baseUrl . 'city/' . $ipAddress;
            
            $context = stream_context_create([
                'http' => [
                    'method' => 'GET',
                    'header' => [
                        'Authorization: Basic ' . base64_encode($this->apiKey . ':'),
                        'Accept: application/json'
                    ],
                    'timeout' => 10
                ]
            ]);
            
            $response = file_get_contents($url, false, $context);
            
            if ($response === false) {
                error_log("GeoIPService: Failed to query MaxMind API for IP: $ipAddress");
                return null;
            }
            
            $data = json_decode($response, true);
            
            if (!$data || isset($data['error'])) {
                error_log("GeoIPService: MaxMind API error for IP $ipAddress: " . ($data['error']['error'] ?? 'Unknown error'));
                return null;
            }
            
            return $this->parseMaxMindResponse($data);
            
        } catch (Exception $e) {
            error_log("GeoIPService: Exception querying MaxMind API: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Parse MaxMind API response
     * 
     * @param array $data Raw API response
     * @return array Parsed location data
     */
    private function parseMaxMindResponse($data) {
        $location = [
            'country' => 'Unknown',
            'country_code' => 'UNKNOWN',
            'region' => 'Unknown',
            'city' => 'Unknown',
            'latitude' => null,
            'longitude' => null,
            'timezone' => null,
            'isp' => 'Unknown'
        ];
        
        // Country information
        if (isset($data['country']['names']['en'])) {
            $location['country'] = $data['country']['names']['en'];
        }
        if (isset($data['country']['iso_code'])) {
            $location['country_code'] = $data['country']['iso_code'];
        }
        
        // Region/State information
        if (isset($data['subdivisions'][0]['names']['en'])) {
            $location['region'] = $data['subdivisions'][0]['names']['en'];
        }
        
        // City information
        if (isset($data['city']['names']['en'])) {
            $location['city'] = $data['city']['names']['en'];
        }
        
        // Coordinates
        if (isset($data['location']['latitude'])) {
            $location['latitude'] = (float) $data['location']['latitude'];
        }
        if (isset($data['location']['longitude'])) {
            $location['longitude'] = (float) $data['location']['longitude'];
        }
        
        // Timezone
        if (isset($data['location']['time_zone'])) {
            $location['timezone'] = $data['location']['time_zone'];
        }
        
        // ISP information
        if (isset($data['traits']['isp'])) {
            $location['isp'] = $data['traits']['isp'];
        } elseif (isset($data['traits']['organization'])) {
            $location['isp'] = $data['traits']['organization'];
        }
        
        return $location;
    }
    
    /**
     * Get cached location data
     * 
     * @param string $ipAddress IP address
     * @return array|null Cached location or null
     */
    private function getCachedLocation($ipAddress) {
        try {
            $stmt = $this->db->prepare("
                SELECT location_data, created_at 
                FROM ip_locations 
                WHERE ip_address = ? 
                AND created_at > NOW() - INTERVAL '7 days'
                ORDER BY created_at DESC 
                LIMIT 1
            ");
            $stmt->execute([$ipAddress]);
            $result = $stmt->fetch();
            
            if ($result) {
                return json_decode($result['location_data'], true);
            }
            
            return null;
        } catch (Exception $e) {
            error_log("GeoIPService: Error getting cached location: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Cache location data
     * 
     * @param string $ipAddress IP address
     * @param array $locationData Location data to cache
     * @return bool Success status
     */
    private function cacheLocation($ipAddress, $locationData) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO ip_locations (ip_address, location_data, created_at) 
                VALUES (?, ?, NOW())
                ON CONFLICT (ip_address) 
                DO UPDATE SET 
                    location_data = EXCLUDED.location_data,
                    created_at = EXCLUDED.created_at
            ");
            
            return $stmt->execute([$ipAddress, json_encode($locationData)]);
        } catch (Exception $e) {
            error_log("GeoIPService: Error caching location: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get location string for display
     * 
     * @param string $ipAddress IP address
     * @return string Formatted location string
     */
    public function getLocationString($ipAddress) {
        $location = $this->getLocation($ipAddress);
        
        if (!$location) {
            return 'Unknown Location';
        }
        
        $parts = [];
        
        if ($location['city'] !== 'Unknown' && $location['city'] !== 'Local') {
            $parts[] = $location['city'];
        }
        
        if ($location['region'] !== 'Unknown' && $location['region'] !== 'Local') {
            $parts[] = $location['region'];
        }
        
        if ($location['country'] !== 'Unknown' && $location['country'] !== 'Local Network') {
            $parts[] = $location['country'];
        }
        
        if (empty($parts)) {
            return $location['country'] === 'Local Network' ? 'Local Network' : 'Unknown Location';
        }
        
        return implode(', ', $parts);
    }
    
    /**
     * Get country flag emoji for display
     * 
     * @param string $countryCode ISO country code
     * @return string Flag emoji or empty string
     */
    public function getCountryFlag($countryCode) {
        if ($countryCode === 'UNKNOWN' || $countryCode === 'LOCAL') {
            return '';
        }
        
        // Convert country code to flag emoji
        $flag = '';
        for ($i = 0; $i < strlen($countryCode); $i++) {
            $flag .= mb_chr(ord($countryCode[$i]) - ord('A') + 0x1F1E6);
        }
        
        return $flag;
    }
}
?>
