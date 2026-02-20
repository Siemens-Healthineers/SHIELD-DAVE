<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    die('Direct access not permitted');
}

// Ensure config is loaded for helper functions
require_once __DIR__ . '/../config/config.php';

/**
 * Get the best available CVSS score from a vulnerability record
 * Priority: v4 > v3 > v2
 * 
 * @param array $vulnerability Vulnerability record with cvss_v4_score, cvss_v3_score, cvss_v2_score
 * @return array ['score' => float|null, 'version' => string|null, 'vector' => string|null]
 */
function getCvssScore($vulnerability) {
    // Priority 1: CVSS v4.0 (newest standard)
    if (isset($vulnerability['cvss_v4_score']) && $vulnerability['cvss_v4_score'] !== null) {
        return [
            'score' => (float)$vulnerability['cvss_v4_score'],
            'version' => 'v4.0',
            'vector' => $vulnerability['cvss_v4_vector'] ?? null
        ];
    }
    
    // Priority 2: CVSS v3.x
    if (isset($vulnerability['cvss_v3_score']) && $vulnerability['cvss_v3_score'] !== null) {
        return [
            'score' => (float)$vulnerability['cvss_v3_score'],
            'version' => 'v3.x',
            'vector' => $vulnerability['cvss_v3_vector'] ?? null
        ];
    }
    
    // Priority 3: CVSS v2.0 (legacy)
    if (isset($vulnerability['cvss_v2_score']) && $vulnerability['cvss_v2_score'] !== null) {
        return [
            'score' => (float)$vulnerability['cvss_v2_score'],
            'version' => 'v2.0',
            'vector' => $vulnerability['cvss_v2_vector'] ?? null
        ];
    }
    
    // No score available
    return [
        'score' => null,
        'version' => null,
        'vector' => null
    ];
}

/**
 * Format CVSS score for display with version
 * 
 * @param array $vulnerability Vulnerability record
 * @param bool $includeVersion Whether to include version in output
 * @return string Formatted score like "7.5 (v3.x)" or "N/A"
 */
function formatCvssScore($vulnerability, $includeVersion = true) {
    $cvss = getCvssScore($vulnerability);
    
    if ($cvss['score'] === null) {
        return 'N/A';
    }
    
    if ($includeVersion && $cvss['version']) {
        return number_format($cvss['score'], 1) . ' (' . $cvss['version'] . ')';
    }
    
    return number_format($cvss['score'], 1);
}

/**
 * Get CSS class for CVSS score severity
 * 
 * @param float|null $score CVSS score (0.0-10.0)
 * @return string CSS class name
 */
function getCvssSeverityClass($score) {
    if ($score === null) {
        return 'unknown';
    }
    
    if ($score >= 9.0) {
        return 'critical';
    } elseif ($score >= 7.0) {
        return 'high';
    } elseif ($score >= 4.0) {
        return 'medium';
    } else {
        return 'low';
    }
}

/**
 * Get all available CVSS scores for a vulnerability
 * 
 * @param array $vulnerability Vulnerability record
 * @return array Array of all available scores ['v4' => ..., 'v3' => ..., 'v2' => ...]
 */
function getAllCvssScores($vulnerability) {
    $scores = [];
    
    if (isset($vulnerability['cvss_v4_score']) && $vulnerability['cvss_v4_score'] !== null) {
        $scores['v4'] = [
            'score' => (float)$vulnerability['cvss_v4_score'],
            'vector' => $vulnerability['cvss_v4_vector'] ?? null
        ];
    }
    
    if (isset($vulnerability['cvss_v3_score']) && $vulnerability['cvss_v3_score'] !== null) {
        $scores['v3'] = [
            'score' => (float)$vulnerability['cvss_v3_score'],
            'vector' => $vulnerability['cvss_v3_vector'] ?? null
        ];
    }
    
    if (isset($vulnerability['cvss_v2_score']) && $vulnerability['cvss_v2_score'] !== null) {
        $scores['v2'] = [
            'score' => (float)$vulnerability['cvss_v2_score'],
            'vector' => $vulnerability['cvss_v2_vector'] ?? null
        ];
    }
    
    return $scores;
}

/**
 * Generate HTML for CVSS score display with tooltip showing all versions
 * 
 * @param array $vulnerability Vulnerability record
 * @return string HTML markup
 */
function renderCvssScore($vulnerability) {
    $primary = getCvssScore($vulnerability);
    $all = getAllCvssScores($vulnerability);
    
    if ($primary['score'] === null) {
        return '<span class="cvss-score unknown">N/A</span>';
    }
    
    $severityClass = getCvssSeverityClass($primary['score']);
    $scoreText = number_format($primary['score'], 1);
    
    // Build tooltip with all available scores
    $tooltip = "Primary: {$scoreText} ({$primary['version']})";
    if (count($all) > 1) {
        $tooltip .= "\n\nAll versions:";
        foreach ($all as $version => $data) {
            $tooltip .= "\n• " . strtoupper($version) . ": " . number_format($data['score'], 1);
        }
    }
    
    $html = sprintf(
        '<span class="cvss-score %s" title="%s">%s <span class="cvss-version">(%s)</span></span>',
        $severityClass,
        dave_htmlspecialchars($tooltip),
        $scoreText,
        $primary['version']
    );
    
    return $html;
}
?>

