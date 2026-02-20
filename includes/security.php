<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    die('Direct access is not permitted.');
}

/**
 * Validates a redirect URL to prevent open redirect vulnerabilities.
 *
 * @param string|null $url The URL to validate.
 * @param string $defaultUrl The default URL to use if validation fails.
 * @return string The sanitized, safe URL.
 */
function validate_redirect_url(?string $url, string $defaultUrl = '/pages/dashboard.php'): string
{
    if (empty($url)) {
        return $defaultUrl;
    }

    $parsed_url = parse_url($url);

    // Allow relative URLs that start with '/'
    if (!isset($parsed_url['host'])) {
        if (substr($url, 0, 1) === '/') {
            return $url;
        }
        return $defaultUrl;
    }

    // Check if the host matches the application's host
    $allowed_host = $_SERVER['HTTP_HOST'];
    if (strtolower($parsed_url['host']) !== strtolower($allowed_host)) {
        return $defaultUrl;
    }
    
    // Rebuild the URL to ensure it's clean
    $safe_url = $parsed_url['path'] ?? '';
    if (!empty($parsed_url['query'])) {
        $safe_url .= '?' . $parsed_url['query'];
    }

    return $safe_url;
}


