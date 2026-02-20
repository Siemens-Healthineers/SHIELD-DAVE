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

class SBOMQueueProcessor {
    private $db;
    private $processed = 0;
    private $errors = 0;
    private $total = 0;
    private $results = [];
    private $startTime;

    public function __construct() {
        $this->db = DatabaseConfig::getInstance();
    }

    public function processQueue() {
        $this->startTime = microtime(true);

        $this->processFailedSBOMs();
        $this->processStuckSBOMs();
        $this->cleanupOrphanedSBOMs();
        $this->displayResults();
    }

    private function processFailedSBOMs() {
        
        try {
            // Find SBOMs that failed processing
            $sql = "SELECT sbom_id, device_id, uploaded_by, file_name, uploaded_at 
                    FROM sboms 
                    WHERE evaluation_status = 'Failed' 
                    ORDER BY uploaded_at ASC";
            $stmt = $this->db->query($sql);
            $failedSBOMs = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $this->total += count($failedSBOMs);
            
            foreach ($failedSBOMs as $sbom) {
                echo "  🔄 Retrying SBOM: {$sbom['file_name']} (ID: {$sbom['sbom_id']})\n";
                
                if ($this->retrySBOMProcessing($sbom)) {
                    $this->processed++;
                    echo "    ✅ Successfully reprocessed\n";
                } else {
                    $this->errors++;
                    echo "    ❌ Failed to reprocess\n";
                }
            }
            
        } catch (Exception $e) {
            $this->results[] = [
                'success' => false,
                'message' => 'Error processing failed SBOMs: ' . $e->getMessage()
            ];
            $this->errors++;
        }
    }

    private function processStuckSBOMs() {
        
        try {
            // Find SBOMs that have been processing for more than 30 minutes
            $sql = "SELECT sbom_id, device_id, uploaded_by, file_name, uploaded_at 
                    FROM sboms 
                    WHERE evaluation_status = 'Queued' 
                    AND uploaded_at < NOW() - INTERVAL '30 minutes'
                    ORDER BY uploaded_at ASC";
            $stmt = $this->db->query($sql);
            $stuckSBOMs = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $this->total += count($stuckSBOMs);
            
            foreach ($stuckSBOMs as $sbom) {
                echo "  🔄 Retrying stuck SBOM: {$sbom['file_name']} (ID: {$sbom['sbom_id']})\n";
                
                // Reset status to pending
                $updateSql = "UPDATE sboms SET evaluation_status = 'Pending' WHERE sbom_id = ?";
                $updateStmt = $this->db->prepare($updateSql);
                $updateStmt->execute([$sbom['sbom_id']]);
                
                if ($this->retrySBOMProcessing($sbom)) {
                    $this->processed++;
                    echo "    ✅ Successfully reprocessed\n";
                } else {
                    $this->errors++;
                    echo "    ❌ Failed to reprocess\n";
                }
            }
            
        } catch (Exception $e) {
            $this->results[] = [
                'success' => false,
                'message' => 'Error processing stuck SBOMs: ' . $e->getMessage()
            ];
            $this->errors++;
        }
    }

    private function cleanupOrphanedSBOMs() {
        
        try {
            // Find SBOMs without corresponding device
            $sql = "SELECT s.sbom_id, s.file_name, s.uploaded_at 
                    FROM sboms s
                    LEFT JOIN medical_devices md ON s.device_id = md.device_id
                    WHERE md.device_id IS NULL
                    AND s.uploaded_at < NOW() - INTERVAL '1 hour'";
            $stmt = $this->db->query($sql);
            $orphanedSBOMs = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            foreach ($orphanedSBOMs as $sbom) {
                echo "  🗑️ Removing orphaned SBOM: {$sbom['file_name']} (ID: {$sbom['sbom_id']})\n";
                
                // Delete orphaned SBOM
                $deleteSql = "DELETE FROM sboms WHERE sbom_id = ?";
                $deleteStmt = $this->db->prepare($deleteSql);
                $deleteStmt->execute([$sbom['sbom_id']]);
            }
            
            // Track cleanup results
            $this->results[] = [
                'success' => true,
                'message' => 'Cleaned up ' . count($orphanedSBOMs) . ' orphaned SBOMs'
            ];
            
        } catch (Exception $e) {
            $this->results[] = [
                'success' => false,
                'message' => 'Error cleaning up orphaned SBOMs: ' . $e->getMessage()
            ];
        }
    }

    private function retrySBOMProcessing($sbom) {
        try {
            // Start async SBOM processing
            $command = "cd /var/www/html && /usr/bin/php /var/www/html/services/async_sbom_processor.php --sbom-id={$sbom['sbom_id']} --device-id={$sbom['device_id']} --user-id={$sbom['uploaded_by']} > /dev/null 2>&1 &";
            exec($command);
            
            // Update status to processing
            $updateSql = "UPDATE sboms SET evaluation_status = 'Queued' WHERE sbom_id = ?";
            $updateStmt = $this->db->prepare($updateSql);
            $updateStmt->execute([$sbom['sbom_id']]);
            
            return true;
            
        } catch (Exception $e) {
            error_log("Error retrying SBOM processing for {$sbom['sbom_id']}: " . $e->getMessage());
            return false;
        }
    }

    private function displayResults() {
        $executionTime = round((microtime(true) - $this->startTime) * 1000, 2);
        
        echo '<div class="sbom-queue-report">';
        echo '<div class="report-header">';
        echo '<h2><i class="fas fa-tasks"></i> SBOM Queue Processing</h2>';
        echo '<p class="timestamp">Completed: ' . date('Y-m-d H:i:s') . ' | Execution Time: ' . $executionTime . 'ms</p>';
        echo '</div>';
        
        // Processing Summary
        echo '<div class="processing-summary">';
        echo '<h3><i class="fas fa-chart-bar"></i> Processing Summary</h3>';
        echo '<div class="summary-cards">';
        
        echo '<div class="summary-card total">';
        echo '<div class="card-icon"><i class="fas fa-list"></i></div>';
        echo '<div class="card-content">';
        echo '<div class="card-value">' . $this->total . '</div>';
        echo '<div class="card-label">Total SBOMs</div>';
        echo '</div>';
        echo '</div>';
        
        echo '<div class="summary-card success">';
        echo '<div class="card-icon"><i class="fas fa-check-circle"></i></div>';
        echo '<div class="card-content">';
        echo '<div class="card-value">' . $this->processed . '</div>';
        echo '<div class="card-label">Successfully Processed</div>';
        echo '</div>';
        echo '</div>';
        
        echo '<div class="summary-card error">';
        echo '<div class="card-icon"><i class="fas fa-times-circle"></i></div>';
        echo '<div class="card-content">';
        echo '<div class="card-value">' . $this->errors . '</div>';
        echo '<div class="card-label">Errors</div>';
        echo '</div>';
        echo '</div>';
        
        echo '</div>';
        echo '</div>';
        
        // Overall Status
        if ($this->errors === 0) {
            echo '<div class="overall-status success">';
            echo '<div class="status-icon"><i class="fas fa-check-circle"></i></div>';
            echo '<div class="status-content">';
            echo '<h3>Queue Processing Completed Successfully!</h3>';
            echo '<p>All SBOMs in the queue have been processed without errors.</p>';
            echo '</div>';
            echo '</div>';
        } else {
            echo '<div class="overall-status warning">';
            echo '<div class="status-icon"><i class="fas fa-exclamation-triangle"></i></div>';
            echo '<div class="status-content">';
            echo '<h3>Queue Processing Completed with Errors</h3>';
            echo '<p>SBOM queue processing completed with ' . $this->errors . ' error(s). Review the details above.</p>';
            echo '</div>';
            echo '</div>';
        }
        
        // Processing Details
        if (!empty($this->results)) {
            echo '<div class="processing-details">';
            echo '<h3><i class="fas fa-info-circle"></i> Processing Details</h3>';
            echo '<div class="details-list">';
            
            foreach ($this->results as $result) {
                $statusClass = $result['success'] ? 'success' : 'error';
                $statusIcon = $result['success'] ? 'fa-check' : 'fa-times';
                
                echo '<div class="detail-item ' . $statusClass . '">';
                echo '<i class="fas ' . $statusIcon . '"></i>';
                echo '<span>' . dave_htmlspecialchars($result['message']) . '</span>';
                echo '</div>';
            }
            
            echo '</div>';
            echo '</div>';
        }
        
        echo '</div>';
    }
}

// Run the SBOM queue processor
$processor = new SBOMQueueProcessor();
$processor->processQueue();
?>
