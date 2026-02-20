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
require_once __DIR__ . '/../../includes/location-assignment.php';

// Require authentication and permission
$auth->requireAuth();
$auth->requirePermission('assets.create');

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();
$error = '';
$success = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $db->beginTransaction();
        
        // Validate required fields
        $requiredFields = ['asset_type', 'manufacturer', 'model', 'criticality'];
        $missingFields = [];
        
        foreach ($requiredFields as $field) {
            if (empty($_POST[$field])) {
                $missingFields[] = $field;
            }
        }
        
        if (!empty($missingFields)) {
            throw new Exception('Required fields missing: ' . implode(', ', $missingFields));
        }
        
        // Prepare asset data
        $assetData = [
            'hostname' => trim($_POST['hostname']),
            'ip_address' => !empty($_POST['ip_address']) ? $_POST['ip_address'] : null,
            'mac_address' => !empty($_POST['mac_address']) ? $_POST['mac_address'] : null,
            'asset_type' => $_POST['asset_type'],
            'asset_subtype' => !empty($_POST['asset_subtype']) ? $_POST['asset_subtype'] : null,
            'manufacturer' => trim($_POST['manufacturer']),
            'model' => trim($_POST['model']),
            'serial_number' => !empty($_POST['serial_number']) ? trim($_POST['serial_number']) : null,
            'location' => !empty($_POST['location']) ? trim($_POST['location']) : null,
            'firmware_version' => !empty($_POST['firmware_version']) ? trim($_POST['firmware_version']) : null,
            'cpu' => !empty($_POST['cpu']) ? trim($_POST['cpu']) : null,
            'memory_ram' => !empty($_POST['memory_ram']) ? trim($_POST['memory_ram']) : null,
            'storage' => !empty($_POST['storage']) ? trim($_POST['storage']) : null,
            'power_requirements' => !empty($_POST['power_requirements']) ? trim($_POST['power_requirements']) : null,
            'primary_communication_protocol' => !empty($_POST['primary_communication_protocol']) ? $_POST['primary_communication_protocol'] : null,
            'assigned_admin_user' => !empty($_POST['assigned_admin_user']) ? trim($_POST['assigned_admin_user']) : null,
            'business_unit' => !empty($_POST['business_unit']) ? trim($_POST['business_unit']) : null,
            'department' => trim($_POST['department']),
            'cost_center' => !empty($_POST['cost_center']) ? trim($_POST['cost_center']) : null,
            'warranty_expiration_date' => !empty($_POST['warranty_expiration_date']) ? $_POST['warranty_expiration_date'] : null,
            'scheduled_replacement_date' => !empty($_POST['scheduled_replacement_date']) ? $_POST['scheduled_replacement_date'] : null,
            'disposal_date' => !empty($_POST['disposal_date']) ? $_POST['disposal_date'] : null,
            'disposal_method' => !empty($_POST['disposal_method']) ? trim($_POST['disposal_method']) : null,
            'criticality' => $_POST['criticality'],
            'regulatory_classification' => !empty($_POST['regulatory_classification']) ? $_POST['regulatory_classification'] : null,
            'phi_status' => !empty($_POST['phi_status']) && $_POST['phi_status'] !== 'false' ? 'true' : 'false',
            'data_encryption_transit' => !empty($_POST['data_encryption_transit']) ? trim($_POST['data_encryption_transit']) : null,
            'data_encryption_rest' => !empty($_POST['data_encryption_rest']) ? trim($_POST['data_encryption_rest']) : null,
            'authentication_method' => !empty($_POST['authentication_method']) ? trim($_POST['authentication_method']) : null,
            'patch_level_last_update' => !empty($_POST['patch_level_last_update']) ? $_POST['patch_level_last_update'] : null,
            'last_audit_date' => !empty($_POST['last_audit_date']) ? $_POST['last_audit_date'] : null,
            'source' => 'manual',
            'status' => 'Active'
        ];
        
        // Insert asset
        $sql = "INSERT INTO assets (
            hostname, ip_address, mac_address, asset_type, asset_subtype, manufacturer, model,
            serial_number, location, firmware_version, cpu, memory_ram, storage, power_requirements,
            primary_communication_protocol, assigned_admin_user, business_unit, department, cost_center,
            warranty_expiration_date, scheduled_replacement_date, disposal_date, disposal_method,
            criticality, regulatory_classification, phi_status, data_encryption_transit, data_encryption_rest,
            authentication_method, patch_level_last_update, last_audit_date, source, status
        ) VALUES (
            :hostname, :ip_address, :mac_address, :asset_type, :asset_subtype, :manufacturer, :model,
            :serial_number, :location, :firmware_version, :cpu, :memory_ram, :storage, :power_requirements,
            :primary_communication_protocol, :assigned_admin_user, :business_unit, :department, :cost_center,
            :warranty_expiration_date, :scheduled_replacement_date, :disposal_date, :disposal_method,
            :criticality, :regulatory_classification, :phi_status, :data_encryption_transit, :data_encryption_rest,
            :authentication_method, :patch_level_last_update, :last_audit_date, :source, :status
        ) RETURNING asset_id";
        
        $stmt = $db->prepare($sql);
        $stmt->execute($assetData);
        $assetId = $stmt->fetch()['asset_id'];
        
        $db->commit();
        
        // Auto-assign location based on IP address if available
        if (!empty($assetData['ip_address'])) {
            $locationResult = autoAssignAssetLocation($db, $assetId, $assetData['ip_address']);
            if ($locationResult['success']) {
                $success = 'Asset created successfully and automatically assigned to location: ' . $locationResult['location_name'];
            } else {
                $success = 'Asset created successfully!';
            }
        } else {
            $success = 'Asset created successfully!';
        }
        
        // Log action
        $auth->logUserAction($user['user_id'], 'CREATE_ASSET', 'assets', $assetId);
        
        // Redirect to asset view after successful creation
        header('Location: /pages/assets/view.php?id=' . $assetId);
        exit;
        
    } catch (Exception $e) {
        $db->rollback();
        $error = 'Failed to create asset: ' . $e->getMessage();
    }
}

// Get departments for dropdown
$departments = $db->query("SELECT DISTINCT department FROM assets WHERE department IS NOT NULL ORDER BY department")->fetchAll(PDO::FETCH_COLUMN);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add Asset - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-plus"></i> Add New Asset</h1>
                    <p>Enter asset information manually</p>
                </div>
                <div class="page-actions">
                    <a href="/pages/assets/manage.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Back to Assets
                    </a>
                </div>
            </div>

            <div class="form-container">
                <?php if ($error): ?>
                    <div class="alert alert-error">
                        <i class="fas fa-exclamation-circle"></i>
                        <?php echo dave_htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i>
                        <?php echo dave_htmlspecialchars($success); ?>
                    </div>
                <?php endif; ?>

                <form method="POST" action="" class="asset-form">
                    <!-- Basic Information -->
                    <div class="form-section">
                        <h3><i class="fas fa-info-circle"></i> Basic Information</h3>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="hostname">Hostname</label>
                                <input type="text" id="hostname" name="hostname" value="<?php echo dave_htmlspecialchars($_POST['hostname'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="ip_address">IP Address</label>
                                <input type="text" id="ip_address" name="ip_address" value="<?php echo dave_htmlspecialchars($_POST['ip_address'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="mac_address">MAC Address</label>
                                <input type="text" id="mac_address" name="mac_address" value="<?php echo dave_htmlspecialchars($_POST['mac_address'] ?? ''); ?>">
                            </div>
                            <div class="form-group required">
                                <label for="asset_type">Asset Type *</label>
                                <select id="asset_type" name="asset_type" required>
                                    <option value="">Select Type</option>
                                    <option value="Server" <?php echo ($_POST['asset_type'] ?? '') === 'Server' ? 'selected' : ''; ?>>Server</option>
                                    <option value="Laptop" <?php echo ($_POST['asset_type'] ?? '') === 'Laptop' ? 'selected' : ''; ?>>Laptop</option>
                                    <option value="Switch" <?php echo ($_POST['asset_type'] ?? '') === 'Switch' ? 'selected' : ''; ?>>Switch</option>
                                    <option value="Software" <?php echo ($_POST['asset_type'] ?? '') === 'Software' ? 'selected' : ''; ?>>Software</option>
                                    <option value="Cloud Resource" <?php echo ($_POST['asset_type'] ?? '') === 'Cloud Resource' ? 'selected' : ''; ?>>Cloud Resource</option>
                                    <option value="IoT Gateway" <?php echo ($_POST['asset_type'] ?? '') === 'IoT Gateway' ? 'selected' : ''; ?>>IoT Gateway</option>
                                    <option value="IoMT Sensor" <?php echo ($_POST['asset_type'] ?? '') === 'IoMT Sensor' ? 'selected' : ''; ?>>IoMT Sensor</option>
                                    <option value="Smart Device" <?php echo ($_POST['asset_type'] ?? '') === 'Smart Device' ? 'selected' : ''; ?>>Smart Device</option>
                                    <option value="Medical Device" <?php echo ($_POST['asset_type'] ?? '') === 'Medical Device' ? 'selected' : ''; ?>>Medical Device</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="asset_subtype">Asset Sub-type</label>
                                <select id="asset_subtype" name="asset_subtype">
                                    <option value="">Select Sub-type</option>
                                    <option value="Virtual Machine" <?php echo ($_POST['asset_subtype'] ?? '') === 'Virtual Machine' ? 'selected' : ''; ?>>Virtual Machine</option>
                                    <option value="Environmental Sensor" <?php echo ($_POST['asset_subtype'] ?? '') === 'Environmental Sensor' ? 'selected' : ''; ?>>Environmental Sensor</option>
                                    <option value="Infusion Pump" <?php echo ($_POST['asset_subtype'] ?? '') === 'Infusion Pump' ? 'selected' : ''; ?>>Infusion Pump</option>
                                    <option value="Security Camera" <?php echo ($_POST['asset_subtype'] ?? '') === 'Security Camera' ? 'selected' : ''; ?>>Security Camera</option>
                                </select>
                            </div>
                        </div>
                    </div>

                    <!-- Device Information -->
                    <div class="form-section">
                        <h3><i class="fas fa-cog"></i> Device Information</h3>
                        <div class="form-grid">
                            <div class="form-group required">
                                <label for="manufacturer">Manufacturer *</label>
                                <input type="text" id="manufacturer" name="manufacturer" required value="<?php echo dave_htmlspecialchars($_POST['manufacturer'] ?? ''); ?>">
                            </div>
                            <div class="form-group required">
                                <label for="model">Model *</label>
                                <input type="text" id="model" name="model" required value="<?php echo dave_htmlspecialchars($_POST['model'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="serial_number">Serial Number</label>
                                <input type="text" id="serial_number" name="serial_number" value="<?php echo dave_htmlspecialchars($_POST['serial_number'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="firmware_version">Firmware Version</label>
                                <input type="text" id="firmware_version" name="firmware_version" value="<?php echo dave_htmlspecialchars($_POST['firmware_version'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="cpu">CPU</label>
                                <input type="text" id="cpu" name="cpu" value="<?php echo dave_htmlspecialchars($_POST['cpu'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="memory_ram">Memory (RAM)</label>
                                <input type="text" id="memory_ram" name="memory_ram" value="<?php echo dave_htmlspecialchars($_POST['memory_ram'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="storage">Storage</label>
                                <input type="text" id="storage" name="storage" value="<?php echo dave_htmlspecialchars($_POST['storage'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="power_requirements">Power Requirements</label>
                                <input type="text" id="power_requirements" name="power_requirements" value="<?php echo dave_htmlspecialchars($_POST['power_requirements'] ?? ''); ?>">
                            </div>
                        </div>
                    </div>

                    <!-- Network & Communication -->
                    <div class="form-section">
                        <h3><i class="fas fa-network-wired"></i> Network & Communication</h3>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="primary_communication_protocol">Primary Communication Protocol</label>
                                <select id="primary_communication_protocol" name="primary_communication_protocol">
                                    <option value="">Select Protocol</option>
                                    <option value="Wi-Fi" <?php echo ($_POST['primary_communication_protocol'] ?? '') === 'Wi-Fi' ? 'selected' : ''; ?>>Wi-Fi</option>
                                    <option value="Ethernet" <?php echo ($_POST['primary_communication_protocol'] ?? '') === 'Ethernet' ? 'selected' : ''; ?>>Ethernet</option>
                                    <option value="Bluetooth/BLE" <?php echo ($_POST['primary_communication_protocol'] ?? '') === 'Bluetooth/BLE' ? 'selected' : ''; ?>>Bluetooth/BLE</option>
                                    <option value="Zigbee" <?php echo ($_POST['primary_communication_protocol'] ?? '') === 'Zigbee' ? 'selected' : ''; ?>>Zigbee</option>
                                    <option value="LoRaWAN" <?php echo ($_POST['primary_communication_protocol'] ?? '') === 'LoRaWAN' ? 'selected' : ''; ?>>LoRaWAN</option>
                                    <option value="Cellular (4G/5G)" <?php echo ($_POST['primary_communication_protocol'] ?? '') === 'Cellular (4G/5G)' ? 'selected' : ''; ?>>Cellular (4G/5G)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="authentication_method">Authentication Method</label>
                                <input type="text" id="authentication_method" name="authentication_method" placeholder="e.g., Certificate-based, Pre-shared Key, 802.1x" value="<?php echo dave_htmlspecialchars($_POST['authentication_method'] ?? ''); ?>">
                            </div>
                        </div>
                    </div>

                    <!-- Organizational Information -->
                    <div class="form-section">
                        <h3><i class="fas fa-building"></i> Organizational Information</h3>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="department">Department</label>
                                <select id="department" name="department">
                                    <option value="">Select Department</option>
                                    <?php foreach ($departments as $dept): ?>
                                        <option value="<?php echo dave_htmlspecialchars($dept); ?>" <?php echo ($_POST['department'] ?? '') === $dept ? 'selected' : ''; ?>>
                                            <?php echo dave_htmlspecialchars($dept); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="business_unit">Business Unit</label>
                                <input type="text" id="business_unit" name="business_unit" value="<?php echo dave_htmlspecialchars($_POST['business_unit'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="cost_center">Cost Center</label>
                                <input type="text" id="cost_center" name="cost_center" value="<?php echo dave_htmlspecialchars($_POST['cost_center'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="location">Location</label>
                                <input type="text" id="location" name="location" value="<?php echo dave_htmlspecialchars($_POST['location'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="assigned_admin_user">Assigned Administrative User</label>
                                <input type="text" id="assigned_admin_user" name="assigned_admin_user" value="<?php echo dave_htmlspecialchars($_POST['assigned_admin_user'] ?? ''); ?>">
                            </div>
                        </div>
                    </div>

                    <!-- Criticality & Compliance -->
                    <div class="form-section">
                        <h3><i class="fas fa-shield-alt"></i> Criticality & Compliance</h3>
                        <div class="form-grid">
                            <div class="form-group required">
                                <label for="criticality">Criticality *</label>
                                <select id="criticality" name="criticality" required>
                                    <option value="">Select Criticality</option>
                                    <option value="Clinical-High" <?php echo ($_POST['criticality'] ?? '') === 'Clinical-High' ? 'selected' : ''; ?>>Clinical-High</option>
                                    <option value="Business-Medium" <?php echo ($_POST['criticality'] ?? '') === 'Business-Medium' ? 'selected' : ''; ?>>Business-Medium</option>
                                    <option value="Non-Essential" <?php echo ($_POST['criticality'] ?? '') === 'Non-Essential' ? 'selected' : ''; ?>>Non-Essential</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="regulatory_classification">Regulatory Classification</label>
                                <select id="regulatory_classification" name="regulatory_classification">
                                    <option value="">Select Classification</option>
                                    <option value="FDA Class I" <?php echo ($_POST['regulatory_classification'] ?? '') === 'FDA Class I' ? 'selected' : ''; ?>>FDA Class I</option>
                                    <option value="FDA Class II" <?php echo ($_POST['regulatory_classification'] ?? '') === 'FDA Class II' ? 'selected' : ''; ?>>FDA Class II</option>
                                    <option value="FDA Class III" <?php echo ($_POST['regulatory_classification'] ?? '') === 'FDA Class III' ? 'selected' : ''; ?>>FDA Class III</option>
                                    <option value="HIPAA-subject" <?php echo ($_POST['regulatory_classification'] ?? '') === 'HIPAA-subject' ? 'selected' : ''; ?>>HIPAA-subject</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="phi_status">Patient Data (PHI) Status</label>
                                <div class="checkbox-group">
                                    <label class="checkbox-label">
                                        <input type="checkbox" name="phi_status" value="1" <?php echo isset($_POST['phi_status']) ? 'checked' : ''; ?>>
                                        <span class="checkmark"></span>
                                        Device stores, processes, or transmits Protected Health Information
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Security & Encryption -->
                    <div class="form-section">
                        <h3><i class="fas fa-lock"></i> Security & Encryption</h3>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="data_encryption_transit">Data Encryption (In Transit)</label>
                                <input type="text" id="data_encryption_transit" name="data_encryption_transit" value="<?php echo dave_htmlspecialchars($_POST['data_encryption_transit'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="data_encryption_rest">Data Encryption (At Rest)</label>
                                <input type="text" id="data_encryption_rest" name="data_encryption_rest" value="<?php echo dave_htmlspecialchars($_POST['data_encryption_rest'] ?? ''); ?>">
                            </div>
                        </div>
                    </div>

                    <!-- Maintenance & Lifecycle -->
                    <div class="form-section">
                        <h3><i class="fas fa-calendar"></i> Maintenance & Lifecycle</h3>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="warranty_expiration_date">Warranty Expiration Date</label>
                                <input type="date" id="warranty_expiration_date" name="warranty_expiration_date" value="<?php echo dave_htmlspecialchars($_POST['warranty_expiration_date'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="scheduled_replacement_date">Scheduled Replacement Date</label>
                                <input type="date" id="scheduled_replacement_date" name="scheduled_replacement_date" value="<?php echo dave_htmlspecialchars($_POST['scheduled_replacement_date'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="disposal_date">Disposal Date</label>
                                <input type="date" id="disposal_date" name="disposal_date" value="<?php echo dave_htmlspecialchars($_POST['disposal_date'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="disposal_method">Disposal Method</label>
                                <input type="text" id="disposal_method" name="disposal_method" value="<?php echo dave_htmlspecialchars($_POST['disposal_method'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="patch_level_last_update">Patch Level / Last Update</label>
                                <input type="date" id="patch_level_last_update" name="patch_level_last_update" value="<?php echo dave_htmlspecialchars($_POST['patch_level_last_update'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="last_audit_date">Last Audit Date</label>
                                <input type="date" id="last_audit_date" name="last_audit_date" value="<?php echo dave_htmlspecialchars($_POST['last_audit_date'] ?? ''); ?>">
                            </div>
                        </div>
                    </div>

                    <!-- Form Actions -->
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i>
                            Create Asset
                        </button>
                        <a href="/pages/assets/manage.php" class="btn btn-secondary">
                            <i class="fas fa-times"></i>
                            Cancel
                        </a>
                    </div>
                </form>
            </div>
        </main>
    </div>

    <script>
        // Form validation and enhancement
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-fill department if it exists in URL
            const urlParams = new URLSearchParams(window.location.search);
            const department = urlParams.get('department');
            if (department) {
                document.getElementById('department').value = department;
            }
            
            // Form validation
            const form = document.querySelector('.asset-form');
            form.addEventListener('submit', function(e) {
                const requiredFields = form.querySelectorAll('[required]');
                let isValid = true;
                
                requiredFields.forEach(field => {
                    if (!field.value.trim()) {
                        field.classList.add('error');
                        isValid = false;
                    } else {
                        field.classList.remove('error');
                    }
                });
                
                if (!isValid) {
                    e.preventDefault();
                    alert('Please fill in all required fields.');
                }
            });
            
            // Real-time validation
            document.querySelectorAll('[required]').forEach(field => {
                field.addEventListener('blur', function() {
                    if (!this.value.trim()) {
                        this.classList.add('error');
                    } else {
                        this.classList.remove('error');
                    }
                });
            });
        });
    </script>
    <!-- Profile Dropdown Script -->
    <script src="/assets/js/dashboard-common.js"></script>
    <script>
        // Pass user data to the profile dropdown
        window.userData = {
            name: '<?php echo dave_htmlspecialchars($user['username']); ?>',
            role: '<?php echo dave_htmlspecialchars($user['role']); ?>',
            email: '<?php echo dave_htmlspecialchars($user['email'] ?? 'user@example.com'); ?>'
        };
    </script>
</body>
</html>
