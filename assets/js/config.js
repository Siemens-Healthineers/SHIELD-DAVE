<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

// Prevent direct access
if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}
?>

/* ====================================================================================
 *  JavaScript Configuration
 * ====================================================================================
 */

// Dynamic base URL detection
(function() {
    'use strict';
    
    // Try to get URLs from PHP-generated script tag first
    let baseUrl, apiUrl, assetsUrl;
    
    // Look for PHP-generated configuration
    const configScript = document.getElementById('dave-config');
    if (configScript) {
        try {
            const config = JSON.parse(configScript.textContent);
            baseUrl = config.baseUrl;
            apiUrl = config.apiUrl;
            assetsUrl = config.assetsUrl;
        } catch (e) {
            console.warn('Failed to parse  configuration, falling back to auto-detection');
        }
    }
    
    // Fallback to auto-detection
    if (!baseUrl) {
        const protocol = window.location.protocol;
        const host = window.location.host;
        baseUrl = `${protocol}//${host}`;
        apiUrl = `${baseUrl}/api`;
        assetsUrl = `${baseUrl}/assets`;
    }
    
    // Set global configuration
    window._CONFIG = {
        baseUrl: baseUrl,
        apiUrl: apiUrl,
        assetsUrl: assetsUrl,
        pagesUrl: `${baseUrl}/pages`
    };
    
    // Backward compatibility
    window._BASE_URL = baseUrl;
    
    // Log configuration for debugging
    console.log(' Configuration loaded:', window._CONFIG);
})();

/**
 * Get API endpoint URL
 * @param {string} endpoint - API endpoint path (e.g., '/v1/assets/list.php')
 * @returns {string} Full API URL
 */
function getApiUrl(endpoint) {
    // Remove leading slash if present
    const cleanEndpoint = endpoint.startsWith('/') ? endpoint.substring(1) : endpoint;
    return `${window._CONFIG.apiUrl}/${cleanEndpoint}`;
}

/**
 * Get asset URL
 * @param {string} assetPath - Asset path (e.g., '/css/style.css')
 * @returns {string} Full asset URL
 */
function getAssetUrl(assetPath) {
    // Remove leading slash if present
    const cleanPath = assetPath.startsWith('/') ? assetPath.substring(1) : assetPath;
    return `${window._CONFIG.assetsUrl}/${cleanPath}`;
}

/**
 * Get page URL
 * @param {string} pagePath - Page path (e.g., '/dashboard.php')
 * @returns {string} Full page URL
 */
function getPageUrl(pagePath) {
    // Remove leading slash if present
    const cleanPath = pagePath.startsWith('/') ? pagePath.substring(1) : pagePath;
    return `${window._CONFIG.pagesUrl}/${cleanPath}`;
}

/**
 * Make authenticated API request
 * @param {string} endpoint - API endpoint
 * @param {object} options - Fetch options
 * @returns {Promise} Fetch promise
 */
function apiRequest(endpoint, options = {}) {
    const url = getApiUrl(endpoint);
    
    const defaultOptions = {
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        }
    };
    
    return fetch(url, { ...defaultOptions, ...options });
}

/**
 * Make authenticated POST request
 * @param {string} endpoint - API endpoint
 * @param {object} data - Request data
 * @param {object} options - Additional options
 * @returns {Promise} Fetch promise
 */
function apiPost(endpoint, data, options = {}) {
    return apiRequest(endpoint, {
        method: 'POST',
        body: JSON.stringify(data),
        ...options
    });
}

/**
 * Make authenticated GET request
 * @param {string} endpoint - API endpoint
 * @param {object} options - Additional options
 * @returns {Promise} Fetch promise
 */
function apiGet(endpoint, options = {}) {
    return apiRequest(endpoint, {
        method: 'GET',
        ...options
    });
}

/**
 * Make authenticated PUT request
 * @param {string} endpoint - API endpoint
 * @param {object} data - Request data
 * @param {object} options - Additional options
 * @returns {Promise} Fetch promise
 */
function apiPut(endpoint, data, options = {}) {
    return apiRequest(endpoint, {
        method: 'PUT',
        body: JSON.stringify(data),
        ...options
    });
}

/**
 * Make authenticated DELETE request
 * @param {string} endpoint - API endpoint
 * @param {object} options - Additional options
 * @returns {Promise} Fetch promise
 */
function apiDelete(endpoint, options = {}) {
    return apiRequest(endpoint, {
        method: 'DELETE',
        ...options
    });
}

