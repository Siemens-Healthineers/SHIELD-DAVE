<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/auth.php';

// Authentication required
$auth = new Auth();
$auth->requireAuth();

$db = DatabaseConfig::getInstance();

// Get location statistics
try {
    $statsSql = "SELECT 
                    COUNT(*) as total_locations,
                    COUNT(CASE WHEN is_active = TRUE THEN 1 END) as active_locations,
                    COUNT(CASE WHEN criticality >= 8 THEN 1 END) as high_criticality,
                    COUNT(CASE WHEN criticality >= 5 AND criticality < 8 THEN 1 END) as medium_criticality,
                    COUNT(CASE WHEN criticality < 5 THEN 1 END) as low_criticality
                FROM locations";
    
    $stmt = $db->query($statsSql);
    $locationStats = $stmt->fetch();
    
    // Get assets without locations
    $assetsSql = "SELECT COUNT(*) as assets_without_location 
                  FROM assets 
                  WHERE location_id IS NULL AND ip_address IS NOT NULL";
    $stmt = $db->query($assetsSql);
    $assetsWithoutLocation = $stmt->fetchColumn();
    
} catch (Exception $e) {
    error_log("Error fetching location statistics: " . $e->getMessage());
    $locationStats = [
        'total_locations' => 0,
        'active_locations' => 0,
        'high_criticality' => 0,
        'medium_criticality' => 0,
        'low_criticality' => 0
    ];
    $assetsWithoutLocation = 0;
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Location Management - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="/assets/css/locations.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-map-marker-alt"></i> Location Management</h1>
                    <p>Manage hospital locations, IP ranges, and asset assignments</p>
                </div>
                <div class="page-actions">
                    <button class="btn btn-primary" onclick="openLocationModal()">
                        <i class="fas fa-plus"></i> Add Location
                    </button>
                    <button class="btn btn-accent" onclick="runAutoAssignment()">
                        <i class="fas fa-magic"></i> Auto-Assign Assets
                    </button>
                </div>
            </div>


            <!-- Statistics Cards -->
            <section class="metrics-section">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-map-marker-alt"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Total Locations</h3>
                            <div class="metric-value"><?php echo number_format($locationStats['total_locations']); ?></div>
                            <div class="metric-detail"><?php echo number_format($locationStats['active_locations']); ?> active</div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon critical">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <div class="metric-content">
                            <h3>High Criticality</h3>
                            <div class="metric-value"><?php echo number_format($locationStats['high_criticality']); ?></div>
                            <div class="metric-detail">Criticality 8-10</div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon warning">
                            <i class="fas fa-exclamation-circle"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Medium Criticality</h3>
                            <div class="metric-value"><?php echo number_format($locationStats['medium_criticality']); ?></div>
                            <div class="metric-detail">Criticality 5-7</div>
                        </div>
                    </div>

                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-server"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Unassigned Assets</h3>
                            <div class="metric-value"><?php echo number_format($assetsWithoutLocation); ?></div>
                            <div class="metric-detail">Need location assignment</div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Filters and Search -->
            <section class="filters-section">
                <div class="filters-grid">
                    <div class="filter-group">
                        <label for="locationTypeFilter">Location Type:</label>
                        <select id="locationTypeFilter" class="form-select">
                            <option value="">All Types</option>
                            <option value="Building">Building</option>
                            <option value="Floor">Floor</option>
                            <option value="Department">Department</option>
                            <option value="Ward">Ward</option>
                            <option value="Lab">Lab</option>
                            <option value="Room">Room</option>
                            <option value="Other">Other</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="criticalityFilter">Criticality:</label>
                        <select id="criticalityFilter" class="form-select">
                            <option value="">All Levels</option>
                            <option value="1-3">Low (1-3)</option>
                            <option value="4-6">Medium (4-6)</option>
                            <option value="7-8">High (7-8)</option>
                            <option value="9-10">Critical (9-10)</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="searchInput">Search:</label>
                        <input type="text" id="searchInput" class="form-input" placeholder="Search locations...">
                    </div>
                    
                    <div class="filter-actions">
                        <button class="btn btn-secondary" onclick="clearFilters()">
                            <i class="fas fa-times"></i> Clear
                        </button>
                        <button class="btn btn-primary" onclick="applyFilters()">
                            <i class="fas fa-search"></i> Filter
                        </button>
                    </div>
                </div>
            </section>

            <!-- Location Tree View -->
            <section class="locations-section">
                <div class="locations-header">
                    <h2><i class="fas fa-sitemap"></i> Location Hierarchy</h2>
                    <div class="tree-actions">
                        <button class="btn btn-sm btn-secondary" onclick="expandAll()">
                            <i class="fas fa-expand-arrows-alt"></i> Expand All
                        </button>
                        <button class="btn btn-sm btn-secondary" onclick="collapseAll()">
                            <i class="fas fa-compress-arrows-alt"></i> Collapse All
                        </button>
                    </div>
                </div>
                
                <div class="locations-tree" id="locationsTree">
                    <div class="loading-spinner">
                        <i class="fas fa-spinner fa-spin"></i> Loading locations...
                    </div>
                </div>
            </section>
        </main>
    </div>

    <!-- Location Modal -->
    <div id="locationModal" class="modal">
        <div class="modal-content large">
            <div class="modal-header">
                <h3 id="modalTitle">Add Location</h3>
                <button class="modal-close" onclick="closeLocationModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <form id="locationForm">
                    <input type="hidden" id="locationId" name="location_id">
                    
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="locationName">Location Name *</label>
                            <input type="text" id="locationName" name="location_name" class="form-input" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="locationType">Location Type *</label>
                            <select id="locationType" name="location_type" class="form-select" required>
                                <option value="">Select Type</option>
                                <option value="Building">Building</option>
                                <option value="Floor">Floor</option>
                                <option value="Department">Department</option>
                                <option value="Ward">Ward</option>
                                <option value="Lab">Lab</option>
                                <option value="Room">Room</option>
                                <option value="Other">Other</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="parentLocation">Parent Location</label>
                            <select id="parentLocation" name="parent_location_id" class="form-select">
                                <option value="">No Parent (Root Location)</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="locationCode">Location Code</label>
                            <input type="text" id="locationCode" name="location_code" class="form-input" placeholder="Auto-generated if empty">
                        </div>
                        
                        <div class="form-group full-width">
                            <label for="description">Description</label>
                            <textarea id="description" name="description" class="form-textarea" rows="3"></textarea>
                        </div>
                        
                        <div class="form-group">
                            <label for="criticality">Criticality Level *</label>
                            <div class="criticality-slider">
                                <input type="range" id="criticality" name="criticality" min="1" max="10" value="5" class="slider">
                                <div class="slider-labels">
                                    <span>1 (Low)</span>
                                    <span id="criticalityValue">5</span>
                                    <span>10 (Critical)</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="form-group checkbox-group">
                            <label class="checkbox-label">
                                <input type="checkbox" id="isActive" name="is_active" checked>
                                <span class="checkmark"></span>
                                Active
                            </label>
                        </div>
                    </div>
                    
                    <!-- IP Ranges Section -->
                    <div class="ip-ranges-section">
                        <h4><i class="fas fa-network-wired"></i> IP Ranges</h4>
                        <div id="ipRangesContainer">
                            <div class="ip-range-item">
                                <div class="ip-range-header">
                                    <select class="form-select range-format" onchange="toggleRangeFormat(this)">
                                        <option value="CIDR">CIDR Notation</option>
                                        <option value="StartEnd">Start - End IP</option>
                                    </select>
                                    <button type="button" class="btn btn-sm btn-danger" onclick="removeIpRange(this)">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                                <div class="ip-range-fields">
                                    <div class="cidr-field">
                                        <input type="text" class="form-input cidr-input" placeholder="192.168.1.0/24">
                                    </div>
                                    <div class="startend-fields" style="display: none;">
                                        <input type="text" class="form-input start-ip" placeholder="192.168.1.1">
                                        <span class="range-separator">to</span>
                                        <input type="text" class="form-input end-ip" placeholder="192.168.1.255">
                                    </div>
                                </div>
                                <input type="text" class="form-input range-description" placeholder="Range description (optional)">
                            </div>
                        </div>
                        <button type="button" class="btn btn-secondary" onclick="addIpRange()">
                            <i class="fas fa-plus"></i> Add IP Range
                        </button>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeLocationModal()">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="saveLocation()">
                    <i class="fas fa-save"></i> Save Location
                </button>
            </div>
        </div>
    </div>

    <!-- Auto Assignment Modal -->
    <div id="autoAssignmentModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Auto-Assign Asset Locations</h3>
                <button class="modal-close" onclick="closeAutoAssignmentModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <p>This will automatically assign assets to locations based on their IP addresses.</p>
                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" id="forceReassign">
                        <span class="checkmark"></span>
                        Force reassignment (override manual assignments)
                    </label>
                </div>
                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" id="dryRun" checked>
                        <span class="checkmark"></span>
                        Dry run (preview changes without applying)
                    </label>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeAutoAssignmentModal()">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="executeAutoAssignment()">
                    <i class="fas fa-magic"></i> Run Auto-Assignment
                </button>
            </div>
        </div>
    </div>

    <!-- Common Dashboard JavaScript -->
    <script src="/assets/js/dashboard-common.js"></script>
    <script src="/assets/js/locations.js"></script>
    <script>
        // Initialize the location manager
        document.addEventListener('DOMContentLoaded', function() {
            const locationManager = new LocationManager();
        });
    </script>
</body>
</html>
