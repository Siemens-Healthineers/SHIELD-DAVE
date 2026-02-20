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
require_once __DIR__ . '/../includes/vulnerability-stats.php';

/**
 * Data Consistency Validator
 * Checks for inconsistencies across the application
 */
class DataConsistencyValidator {
    private $db;
    private $stats;
    private $issues = [];
    private $results = [];
    private $startTime;
    
    public function __construct() {
        $this->db = DatabaseConfig::getInstance();
        $this->stats = new VulnerabilityStats();
    }
    
    /**
     * Run comprehensive data consistency validation
     */
    public function validateAll() {
        $this->startTime = microtime(true);
        
        $this->validateVulnerabilityCounts();
        $this->validateTierCalculations();
        $this->validateDeviceCounts();
        $this->validateRiskScores();
        
        $this->generateReport();
    }
    
    /**
     * Validate vulnerability counts across different queries
     */
    private function validateVulnerabilityCounts() {
        // Get all different count types
        $uniqueCount = $this->stats->getVulnerabilityCounts('unique');
        $deviceLinksCount = $this->stats->getVulnerabilityCounts('device_links');
        $epssCount = $this->stats->getVulnerabilityCounts('with_epss');
        $severityCount = $this->stats->getVulnerabilityCounts('by_severity');
        
        $this->results['vulnerability_stats'] = [
            'unique_vulnerabilities' => $uniqueCount['count'],
            'device_vulnerability_links' => $deviceLinksCount['count'],
            'with_epss_scores' => $epssCount['count'],
            'total_by_severity' => $severityCount['count']
        ];
        
        // Check for inconsistencies
        if ($uniqueCount['count'] !== $severityCount['count']) {
            $this->issues[] = [
                'type' => 'vulnerability_count_mismatch',
                'severity' => 'high',
                'message' => "Unique vulnerabilities (" . number_format($uniqueCount['count']) . ") != Severity total (" . number_format($severityCount['count']) . ")",
                'recommendation' => 'Check severity data integrity'
            ];
        }
        
        if ($deviceLinksCount['count'] < $uniqueCount['count']) {
            $this->issues[] = [
                'type' => 'device_links_less_than_unique',
                'severity' => 'medium',
                'message' => "Device-vulnerability links (" . number_format($deviceLinksCount['count']) . ") < Unique vulnerabilities (" . number_format($uniqueCount['count']) . ")",
                'recommendation' => 'Some vulnerabilities may not be linked to devices'
            ];
        }
    }
    
    /**
     * Validate tier calculations
     */
    private function validateTierCalculations() {
        // Get tier counts from different sources
        $sql = "SELECT 
                    CASE 
                        WHEN ars.urgency_score >= 1000 THEN 1
                        WHEN ars.urgency_score >= 180 THEN 2
                        WHEN ars.urgency_score >= 160 THEN 3
                        ELSE 4
                    END as tier,
                    COUNT(*) as count
                FROM remediation_actions ra
                LEFT JOIN action_risk_scores ars ON ra.action_id = ars.action_id
                GROUP BY tier
                ORDER BY tier";
        
        $stmt = $this->db->query($sql);
        $tierCounts = $stmt->fetchAll();
        
        $totalTiers = array_sum(array_column($tierCounts, 'count'));
        
        $this->results['tier_stats'] = [
            'total_actions' => $totalTiers,
            'tier_breakdown' => $tierCounts
        ];
        
        // Validate tier calculations
        $sql = "SELECT COUNT(*) as total_actions FROM remediation_actions";
        $stmt = $this->db->query($sql);
        $result = $stmt->fetch();
        $totalActions = $result ? $result['total_actions'] : 0;
        
        if ($totalTiers !== $totalActions) {
            $this->issues[] = [
                'type' => 'tier_calculation_mismatch',
                'severity' => 'high',
                'message' => "Tier total (" . number_format($totalTiers) . ") != Total actions (" . number_format($totalActions) . ")",
                'recommendation' => 'Check tier calculation logic'
            ];
        }
    }
    
    /**
     * Get tier name for display
     */
    private function getTierName($tier) {
        switch ($tier) {
            case 1: return 'Critical';
            case 2: return 'High';
            case 3: return 'Medium';
            case 4: return 'Low';
            default: return 'Unknown';
        }
    }
    
    /**
     * Validate device counts
     */
    private function validateDeviceCounts() {
        // Get device counts from different sources
        $sql = "SELECT COUNT(*) as total_assets FROM assets WHERE status = 'Active'";
        $stmt = $this->db->query($sql);
        $result = $stmt->fetch();
        $totalAssets = $result ? $result['total_assets'] : 0;
        
        $sql = "SELECT COUNT(*) as mapped_devices FROM medical_devices";
        $stmt = $this->db->query($sql);
        $result = $stmt->fetch();
        $mappedDevices = $result ? $result['mapped_devices'] : 0;
        
        $sql = "SELECT COUNT(DISTINCT device_id) as unique_devices FROM device_vulnerabilities_link";
        $stmt = $this->db->query($sql);
        $result = $stmt->fetch();
        $devicesWithVulns = $result ? $result['unique_devices'] : 0;
        
        $this->results['device_stats'] = [
            'total_assets' => $totalAssets,
            'mapped_devices' => $mappedDevices,
            'devices_with_vulnerabilities' => $devicesWithVulns
        ];
        
        if ($mappedDevices > $totalAssets) {
            $this->issues[] = [
                'type' => 'mapped_devices_exceed_assets',
                'severity' => 'high',
                'message' => "Mapped devices (" . number_format($mappedDevices) . ") > Total assets (" . number_format($totalAssets) . ")",
                'recommendation' => 'Check for duplicate device mappings'
            ];
        }
    }
    
    /**
     * Validate risk scores
     */
    private function validateRiskScores() {
        // Check for NULL risk scores
        $sql = "SELECT COUNT(*) as null_risk_scores FROM device_vulnerabilities_link WHERE risk_score IS NULL";
        $stmt = $this->db->query($sql);
        $result = $stmt->fetch();
        $nullRiskScores = $result ? $result['null_risk_scores'] : 0;
        
        // Check for invalid risk scores
        $sql = "SELECT COUNT(*) as invalid_risk_scores FROM device_vulnerabilities_link WHERE risk_score < 0 OR risk_score > 10000";
        $stmt = $this->db->query($sql);
        $result = $stmt->fetch();
        $invalidRiskScores = $result ? $result['invalid_risk_scores'] : 0;
        
        $this->results['risk_score_stats'] = [
            'null_risk_scores' => $nullRiskScores,
            'invalid_risk_scores' => $invalidRiskScores
        ];
        
        if ($nullRiskScores > 0) {
            $this->issues[] = [
                'type' => 'null_risk_scores',
                'severity' => 'medium',
                'message' => number_format($nullRiskScores) . " device-vulnerability links have NULL risk scores",
                'recommendation' => 'Recalculate risk scores for affected records'
            ];
        }
        
        if ($invalidRiskScores > 0) {
            $this->issues[] = [
                'type' => 'invalid_risk_scores',
                'severity' => 'high',
                'message' => number_format($invalidRiskScores) . " device-vulnerability links have invalid risk scores",
                'recommendation' => 'Fix risk score calculation logic'
            ];
        }
    }
    
    /**
     * Generate validation report
     */
    private function generateReport() {
        $executionTime = round((microtime(true) - $this->startTime) * 1000, 2);
        
        echo '<div class="data-consistency-report">';
        echo '<div class="report-header">';
        echo '<h2><i class="fas fa-shield-alt"></i>  Data Consistency Validation</h2>';
        echo '<p class="timestamp">Completed: ' . date('Y-m-d H:i:s') . ' | Execution Time: ' . $executionTime . 'ms</p>';
        echo '</div>';
        
        // Statistics Summary
        echo '<div class="stats-summary">';
        echo '<h3><i class="fas fa-chart-bar"></i> System Statistics</h3>';
        echo '<div class="stats-grid">';
        
        if (isset($this->results['vulnerability_stats'])) {
            $stats = $this->results['vulnerability_stats'];
            echo '<div class="stat-card">';
            echo '<div class="stat-icon"><i class="fas fa-bug"></i></div>';
            echo '<div class="stat-content">';
            echo '<div class="stat-value">' . number_format($stats['unique_vulnerabilities']) . '</div>';
            echo '<div class="stat-label">Unique Vulnerabilities</div>';
            echo '</div>';
            echo '</div>';
            
            echo '<div class="stat-card">';
            echo '<div class="stat-icon"><i class="fas fa-link"></i></div>';
            echo '<div class="stat-content">';
            echo '<div class="stat-value">' . number_format($stats['device_vulnerability_links']) . '</div>';
            echo '<div class="stat-label">Device-Vulnerability Links</div>';
            echo '</div>';
            echo '</div>';
            
            echo '<div class="stat-card">';
            echo '<div class="stat-icon"><i class="fas fa-chart-line"></i></div>';
            echo '<div class="stat-content">';
            echo '<div class="stat-value">' . number_format($stats['with_epss_scores']) . '</div>';
            echo '<div class="stat-label">With EPSS Scores</div>';
            echo '</div>';
            echo '</div>';
        }
        
        echo '</div>';
        echo '</div>';
        
        // Issues Section
        if (empty($this->issues)) {
            echo '<div class="validation-result success">';
            echo '<div class="result-icon"><i class="fas fa-check-circle"></i></div>';
            echo '<div class="result-content">';
            echo '<h3>All Checks Passed</h3>';
            echo '<p>No data consistency issues found. Your  data is consistent and properly configured!</p>';
            echo '</div>';
            echo '</div>';
        } else {
            echo '<div class="validation-result warning">';
            echo '<div class="result-icon"><i class="fas fa-exclamation-triangle"></i></div>';
            echo '<div class="result-content">';
            echo '<h3>Found ' . count($this->issues) . ' Data Consistency Issues</h3>';
            echo '<p>The following issues require attention:</p>';
            echo '</div>';
            echo '</div>';
            
            echo '<div class="issues-list">';
            foreach ($this->issues as $index => $issue) {
                $severityClass = 'severity-' . strtolower($issue['severity']);
                $severityIcon = $this->getSeverityIcon($issue['severity']);
                
                echo '<div class="issue-card ' . $severityClass . '">';
                echo '<div class="issue-header">';
                echo '<div class="issue-number">#' . ($index + 1) . '</div>';
                echo '<div class="issue-severity">' . $severityIcon . ' ' . strtoupper($issue['severity']) . '</div>';
                echo '</div>';
                echo '<div class="issue-content">';
                echo '<h4>' . ucwords(str_replace('_', ' ', $issue['type'])) . '</h4>';
                echo '<p class="issue-message">' . dave_htmlspecialchars($issue['message']) . '</p>';
                echo '<div class="issue-recommendation">';
                echo '<strong>Recommendation:</strong> ' . dave_htmlspecialchars($issue['recommendation']);
                echo '</div>';
                echo '</div>';
                echo '</div>';
            }
            echo '</div>';
        }
        
        echo '</div>';
    }
    
    /**
     * Get severity icon for display
     */
    private function getSeverityIcon($severity) {
        switch (strtolower($severity)) {
            case 'high': return '🔴';
            case 'medium': return '🟡';
            case 'low': return '🟢';
            default: return '⚪';
        }
    }
}

// Run validation if called directly
if (php_sapi_name() === 'cli') {
    $validator = new DataConsistencyValidator();
    $validator->validateAll();
}
?>
