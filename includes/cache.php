<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

class Cache {
    private static $cache_dir;
    private static $enabled;
    private static $lifetime;
    
    /**
     * Initialize cache system
     */
    public static function init() {
        self::$cache_dir = _CACHE_DIR;
        self::$enabled = _CACHE_ENABLED;
        self::$lifetime = _CACHE_LIFETIME;
        
        // Ensure cache directory exists
        if (!file_exists(self::$cache_dir)) {
            mkdir(self::$cache_dir, 0755, true);
        }
    }
    
    /**
     * Get cached value
     */
    public static function get($key, $default = null) {
        if (!self::$enabled) {
            return $default;
        }
        
        $file_path = self::getFilePath($key);
        
        if (!file_exists($file_path)) {
            return $default;
        }
        
        $data = file_get_contents($file_path);
        $cache_data = json_decode($data, true);
        
        if (!$cache_data) {
            return $default;
        }
        
        // Check if cache has expired
        if (time() > $cache_data['expires_at']) {
            self::delete($key);
            return $default;
        }
        
        return $cache_data['value'];
    }
    
    /**
     * Set cached value
     */
    public static function set($key, $value, $lifetime = null) {
        if (!self::$enabled) {
            return false;
        }
        
        $lifetime = $lifetime ?? self::$lifetime;
        $expires_at = time() + $lifetime;
        
        $cache_data = [
            'value' => $value,
            'created_at' => time(),
            'expires_at' => $expires_at,
            'lifetime' => $lifetime
        ];
        
        $file_path = self::getFilePath($key);
        $data = json_encode($cache_data);
        
        return file_put_contents($file_path, $data) !== false;
    }
    
    /**
     * Delete cached value
     */
    public static function delete($key) {
        $file_path = self::getFilePath($key);
        
        if (file_exists($file_path)) {
            return unlink($file_path);
        }
        
        return true;
    }
    
    /**
     * Check if cache key exists and is valid
     */
    public static function has($key) {
        if (!self::$enabled) {
            return false;
        }
        
        $file_path = self::getFilePath($key);
        
        if (!file_exists($file_path)) {
            return false;
        }
        
        $data = file_get_contents($file_path);
        $cache_data = json_decode($data, true);
        
        if (!$cache_data) {
            return false;
        }
        
        // Check if cache has expired
        if (time() > $cache_data['expires_at']) {
            self::delete($key);
            return false;
        }
        
        return true;
    }
    
    /**
     * Clear all cache
     */
    public static function clear() {
        if (!self::$enabled) {
            return false;
        }
        
        $files = glob(self::$cache_dir . '/*.cache');
        $deleted = 0;
        
        foreach ($files as $file) {
            if (unlink($file)) {
                $deleted++;
            }
        }
        
        // Log cache clear action
        if (function_exists('logMessage')) {
            logMessage('INFO', 'Cache cleared', [
                'files_deleted' => $deleted,
                'cache_dir' => self::$cache_dir
            ]);
        }
        
        return $deleted;
    }
    
    /**
     * Get cache statistics
     */
    public static function getStats() {
        if (!self::$enabled) {
            return [
                'enabled' => false,
                'total_files' => 0,
                'total_size' => 0,
                'expired_files' => 0
            ];
        }
        
        $files = glob(self::$cache_dir . '/*.cache');
        $total_size = 0;
        $expired_files = 0;
        $current_time = time();
        
        foreach ($files as $file) {
            $total_size += filesize($file);
            
            $data = file_get_contents($file);
            $cache_data = json_decode($data, true);
            
            if ($cache_data && $current_time > $cache_data['expires_at']) {
                $expired_files++;
            }
        }
        
        return [
            'enabled' => self::$enabled,
            'total_files' => count($files),
            'total_size' => $total_size,
            'expired_files' => $expired_files,
            'cache_dir' => self::$cache_dir,
            'lifetime' => self::$lifetime
        ];
    }
    
    /**
     * Clean expired cache files
     */
    public static function clean() {
        if (!self::$enabled) {
            return 0;
        }
        
        $files = glob(self::$cache_dir . '/*.cache');
        $cleaned = 0;
        $current_time = time();
        
        foreach ($files as $file) {
            $data = file_get_contents($file);
            $cache_data = json_decode($data, true);
            
            if ($cache_data && $current_time > $cache_data['expires_at']) {
                if (unlink($file)) {
                    $cleaned++;
                }
            }
        }
        
        return $cleaned;
    }
    
    /**
     * Get file path for cache key
     */
    private static function getFilePath($key) {
        $safe_key = preg_replace('/[^a-zA-Z0-9_-]/', '_', $key);
        return self::$cache_dir . '/' . $safe_key . '.cache';
    }
    
    /**
     * Update cache configuration
     */
    public static function updateConfig($enabled = null, $lifetime = null) {
        if ($enabled !== null) {
            self::$enabled = $enabled;
        }
        
        if ($lifetime !== null) {
            self::$lifetime = $lifetime;
        }
    }
}

// Initialize cache system
Cache::init();
?>
