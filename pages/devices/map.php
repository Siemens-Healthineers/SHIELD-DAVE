<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/auth.php';

// Initialize authentication
$auth = new Auth();

// Require authentication
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Mapping - <?php echo _NAME; ?></title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <!-- Custom CSS -->
    <link href="/assets/css/dashboard.css" rel="stylesheet">
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/pages/dashboard.php">
                <i class="fas fa-shield-alt"></i> 
            </a>
            
            <div class="navbar-nav ms-auto">
                <div class="nav-item dropdown">
                    <button class="profile-trigger" onclick="toggleProfileDropdown()">
                        <i class="fas fa-user-circle"></i> <?php echo dave_htmlspecialchars($user['username']); ?>
                        <i class="fas fa-chevron-down ms-1"></i>
                    </button>
                    <div class="dropdown-menu" id="profileDropdown">
                        <a href="/pages/settings.php" class="dropdown-item">
                            <i class="fas fa-cog"></i> Settings
                        </a>
                        <a href="/pages/about.php" class="dropdown-item">
                            <i class="fas fa-info-circle"></i> About
                        </a>
                        <a href="/docs/index.php" class="dropdown-item">
                            <i class="fas fa-question-circle"></i> Help
                        </a>
                        <a href="/api/logout.php" class="dropdown-item">
                            <i class="fas fa-sign-out-alt"></i> Logout
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </nav>

<div class="container-fluid">
    <div class="dashboard-header">
        <div class="row align-items-center">
            <div class="col-md-6">
                <h1 class="h3 mb-0">Device Mapping</h1>
                <p class="text-muted mb-0">Map and manage medical devices and assets</p>
            </div>
            <div class="col-md-6 text-end">
                <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addDeviceModal">
                    <i class="fas fa-plus"></i> Add Device
                </button>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-12">
            <div class="card">
                <div class="card-header">
                    <h5 class="card-title mb-0">Device Mapping Dashboard</h5>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-3">
                            <div class="card bg-primary text-white">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between">
                                        <div>
                                            <h4 class="mb-0"><?php echo $db->query("SELECT COUNT(*) FROM medical_devices")->fetchColumn(); ?></h4>
                                            <p class="mb-0">Total Devices</p>
                                        </div>
                                        <div class="align-self-center">
                                            <i class="fas fa-laptop-medical fa-2x"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card bg-success text-white">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between">
                                        <div>
                                            <h4 class="mb-0"><?php echo $db->query("SELECT COUNT(*) FROM medical_devices WHERE mapped_by IS NOT NULL")->fetchColumn(); ?></h4>
                                            <p class="mb-0">Mapped Devices</p>
                                        </div>
                                        <div class="align-self-center">
                                            <i class="fas fa-check-circle fa-2x"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card bg-warning text-white">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between">
                                        <div>
                                            <h4 class="mb-0"><?php echo $db->query("SELECT COUNT(*) FROM medical_devices WHERE mapped_by IS NULL")->fetchColumn(); ?></h4>
                                            <p class="mb-0">Unmapped Devices</p>
                                        </div>
                                        <div class="align-self-center">
                                            <i class="fas fa-exclamation-triangle fa-2x"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card bg-info text-white">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between">
                                        <div>
                                            <h4 class="mb-0"><?php echo $db->query("SELECT COUNT(*) FROM assets")->fetchColumn(); ?></h4>
                                            <p class="mb-0">Total Assets</p>
                                        </div>
                                        <div class="align-self-center">
                                            <i class="fas fa-server fa-2x"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="row mt-4">
                        <div class="col-12">
                            <div class="card">
                                <div class="card-header">
                                    <h5 class="card-title mb-0">Device Mapping Table</h5>
                                </div>
                                <div class="card-body">
                                    <div class="table-responsive">
                                        <table class="table table-striped" id="deviceMappingTable">
                                            <thead>
                                                <tr>
                                                    <th>Device Name</th>
                                                    <th>Manufacturer</th>
                                                    <th>Model</th>
                                                    <th>Serial Number</th>
                                                    <th>Mapped By</th>
                                                    <th>Status</th>
                                                    <th>Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php
                                                $devices = $db->query("
                                                    SELECT md.*, 
                                                           u.username as mapped_by_username,
                                                           COALESCE(md.manufacturer_name, a.manufacturer) as manufacturer,
                                                           COALESCE(md.model_number, a.model) as model,
                                                           a.serial_number
                                                    FROM medical_devices md 
                                                    LEFT JOIN users u ON md.mapped_by = u.user_id 
                                                    LEFT JOIN assets a ON md.asset_id = a.asset_id
                                                    ORDER BY md.created_at DESC 
                                                    LIMIT 50
                                                ")->fetchAll();
                                                
                                                foreach ($devices as $device): ?>
                                                <tr>
                                                    <td><?php echo dave_htmlspecialchars($device['device_name'] ?? 'N/A'); ?></td>
                                                    <td><?php echo dave_htmlspecialchars($device['manufacturer'] ?? 'N/A'); ?></td>
                                                    <td><?php echo dave_htmlspecialchars($device['model'] ?? 'N/A'); ?></td>
                                                    <td><?php echo dave_htmlspecialchars($device['serial_number'] ?? 'N/A'); ?></td>
                                                    <td><?php echo dave_htmlspecialchars($device['mapped_by_username'] ?? 'Unmapped'); ?></td>
                                                    <td>
                                                        <?php if ($device['mapped_by']): ?>
                                                            <span class="badge bg-success">Mapped</span>
                                                        <?php else: ?>
                                                            <span class="badge bg-warning">Unmapped</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <button class="btn btn-sm btn-primary" onclick="editDevice('<?php echo $device['device_id']; ?>')">
                                                            <i class="fas fa-edit"></i>
                                                        </button>
                                                        <button class="btn btn-sm btn-info" onclick="viewDevice('<?php echo $device['device_id']; ?>')">
                                                            <i class="fas fa-eye"></i>
                                                        </button>
                                                    </td>
                                                </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Add Device Modal -->
<div class="modal fade" id="addDeviceModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Add New Device</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="addDeviceForm">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="deviceName" class="form-label">Device Name</label>
                                <input type="text" class="form-control" id="deviceName" name="device_name" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="manufacturer" class="form-label">Manufacturer</label>
                                <input type="text" class="form-control" id="manufacturer" name="manufacturer" required>
                            </div>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="model" class="form-label">Model</label>
                                <input type="text" class="form-control" id="model" name="model" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label for="serialNumber" class="form-label">Serial Number</label>
                                <input type="text" class="form-control" id="serialNumber" name="serial_number" required>
                            </div>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="addDevice()">Add Device</button>
            </div>
        </div>
    </div>
</div>

<script>
function editDevice(deviceId) {
    // Implementation for editing device
}

function viewDevice(deviceId) {
    // Implementation for viewing device details
}

function addDevice() {
    // Implementation for adding device
    const form = document.getElementById('addDeviceForm');
    const formData = new FormData(form);
    
    // Here you would typically send the data to a backend endpoint
    
    // Close modal
    const modal = bootstrap.Modal.getInstance(document.getElementById('addDeviceModal'));
    modal.hide();
}
</script>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        function toggleProfileDropdown() {
            const dropdown = document.getElementById('profileDropdown');
            dropdown.classList.toggle('show');
        }
        
        // Close dropdown when clicking outside
        document.addEventListener('click', function(event) {
            const dropdown = document.getElementById('profileDropdown');
            const trigger = document.querySelector('.profile-trigger');
            
            if (!trigger.contains(event.target) && !dropdown.contains(event.target)) {
                dropdown.classList.remove('show');
            }
        });
    </script>
</body>
</html>
