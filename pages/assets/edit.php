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

// Require authentication and permission
$auth->requireAuth();
$auth->requirePermission('assets.edit');

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

$db = DatabaseConfig::getInstance();
$error = '';
$success = '';

// Get asset ID from URL
$assetId = $_GET['id'] ?? '';

if (empty($assetId)) {
    header('Location: /pages/assets/manage.php?error=Asset ID required');
    exit;
}

// Get existing asset data with medical device mapping
try {
    $sql = "SELECT 
        a.*,
        md.device_id,
        md.device_identifier,
        md.brand_name,
        md.model_number,
        md.manufacturer_name,
        md.device_description,
        md.gmdn_term,
        md.is_implantable,
        md.fda_class,
        md.udi,
        md.mapping_confidence,
        md.mapping_method,
        md.mapped_at
    FROM assets a
    LEFT JOIN medical_devices md ON a.asset_id = md.asset_id
    WHERE a.asset_id = ?";
    
    $stmt = $db->prepare($sql);
    $stmt->execute([$assetId]);
    $asset = $stmt->fetch();
    
    if (!$asset) {
        header('Location: /pages/assets/manage.php?error=Asset not found');
        exit;
    }
} catch (Exception $e) {
    error_log("Error fetching asset: " . $e->getMessage());
    header('Location: /pages/assets/manage.php?error=Database error');
    exit;
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $db->beginTransaction();
        
        // Validate required fields
        $requiredFields = ['manufacturer', 'model', 'criticality'];
        
        // For unmapped assets, asset_type is also required
        if (!$asset['device_id']) {
            $requiredFields[] = 'asset_type';
        }
        
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
            'asset_type' => $asset['device_id'] ? 'Medical Device' : $_POST['asset_type'], // Force Medical Device for mapped assets
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
            'regulatory_classification' => $asset['device_id'] && $asset['fda_class'] ? 
                'FDA ' . $asset['fda_class'] : 
                (!empty($_POST['regulatory_classification']) ? $_POST['regulatory_classification'] : null),
            'phi_status' => !empty($_POST['phi_status']) && $_POST['phi_status'] !== 'false' ? 'true' : 'false',
            'data_encryption_transit' => !empty($_POST['data_encryption_transit']) ? trim($_POST['data_encryption_transit']) : null,
            'data_encryption_rest' => !empty($_POST['data_encryption_rest']) ? trim($_POST['data_encryption_rest']) : null,
            'authentication_method' => !empty($_POST['authentication_method']) ? trim($_POST['authentication_method']) : null,
            'patch_level_last_update' => !empty($_POST['patch_level_last_update']) ? $_POST['patch_level_last_update'] : null,
            'last_audit_date' => !empty($_POST['last_audit_date']) ? $_POST['last_audit_date'] : null,
            'status' => $_POST['status'] ?? 'Active'
        ];
        
        // Update asset
        $sql = "UPDATE assets SET 
            hostname = :hostname, 
            ip_address = :ip_address, 
            mac_address = :mac_address, 
            asset_type = :asset_type, 
            asset_subtype = :asset_subtype, 
            manufacturer = :manufacturer, 
            model = :model, 
            serial_number = :serial_number, 
            location = :location, 
            firmware_version = :firmware_version, 
            cpu = :cpu, 
            memory_ram = :memory_ram, 
            storage = :storage, 
            power_requirements = :power_requirements, 
            primary_communication_protocol = :primary_communication_protocol, 
            assigned_admin_user = :assigned_admin_user, 
            business_unit = :business_unit, 
            department = :department, 
            cost_center = :cost_center, 
            warranty_expiration_date = :warranty_expiration_date, 
            scheduled_replacement_date = :scheduled_replacement_date, 
            disposal_date = :disposal_date, 
            disposal_method = :disposal_method, 
            criticality = :criticality, 
            regulatory_classification = :regulatory_classification, 
            phi_status = :phi_status, 
            data_encryption_transit = :data_encryption_transit, 
            data_encryption_rest = :data_encryption_rest, 
            authentication_method = :authentication_method, 
            patch_level_last_update = :patch_level_last_update, 
            last_audit_date = :last_audit_date, 
            status = :status,
            updated_at = CURRENT_TIMESTAMP
            WHERE asset_id = :asset_id";
        
        $assetData['asset_id'] = $assetId;
        $stmt = $db->prepare($sql);
        $stmt->execute($assetData);
        
        $db->commit();
        
        // Log action
        $auth->logUserAction($user['user_id'], 'UPDATE_ASSET', 'assets', $assetId);
        
        $success = 'Asset updated successfully!';
        
        // Redirect to asset view after successful update
        header('Location: /pages/assets/view.php?id=' . $assetId . '&success=Asset updated successfully');
        exit;
        
    } catch (Exception $e) {
        $db->rollback();
        #Print $asset
        $error = 'Failed to update asset: ' . $e->getMessage();
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
    <title>Edit Asset - <?php echo dave_htmlspecialchars($asset['hostname'] ?: $asset['ip_address']); ?> - <?php echo _NAME; ?></title>
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
                    <h1><i class="fas fa-edit"></i> Edit Asset</h1>
                    <p><?php echo dave_htmlspecialchars($asset['hostname'] ?: $asset['ip_address']); ?></p>
                </div>
                <div class="page-actions">
                    <a href="/pages/assets/view.php?id=<?php echo dave_htmlspecialchars($assetId); ?>" class="btn btn-secondary">
                        <i class="fas fa-eye"></i>
                        View Asset
                    </a>
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
                                <input type="text" id="hostname" name="hostname" value="<?php echo dave_htmlspecialchars($asset['hostname']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="ip_address">IP Address</label>
                                <input type="text" id="ip_address" name="ip_address" value="<?php echo dave_htmlspecialchars($asset['ip_address']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="mac_address">MAC Address</label>
                                <input type="text" id="mac_address" name="mac_address" value="<?php echo dave_htmlspecialchars($asset['mac_address']); ?>">
                            </div>
                            <div class="form-group required">
                                <label for="asset_type">Asset Type *</label>
                                <?php if ($asset['device_id']): ?>
                                    <!-- Mapped asset - force Medical Device type -->
                                    <select id="asset_type" name="asset_type" required disabled>
                                        <option value="Medical Device" selected>Medical Device (Auto-set for mapped devices)</option>
                                    </select>
                                    <input type="hidden" name="asset_type" value="Medical Device">
                                    <small class="form-help">Asset type is automatically set to "Medical Device" for mapped devices</small>
                                <?php else: ?>
                                    <!-- Unmapped asset - allow selection -->
                                    <select id="asset_type" name="asset_type" required>
                                        <option value="">Select Type</option>
                                        <option value="Server" <?php echo $asset['asset_type'] === 'Server' ? 'selected' : ''; ?>>Server</option>
                                        <option value="Laptop" <?php echo $asset['asset_type'] === 'Laptop' ? 'selected' : ''; ?>>Laptop</option>
                                        <option value="Switch" <?php echo $asset['asset_type'] === 'Switch' ? 'selected' : ''; ?>>Switch</option>
                                        <option value="Software" <?php echo $asset['asset_type'] === 'Software' ? 'selected' : ''; ?>>Software</option>
                                        <option value="Cloud Resource" <?php echo $asset['asset_type'] === 'Cloud Resource' ? 'selected' : ''; ?>>Cloud Resource</option>
                                        <option value="IoT Gateway" <?php echo $asset['asset_type'] === 'IoT Gateway' ? 'selected' : ''; ?>>IoT Gateway</option>
                                        <option value="IoMT Sensor" <?php echo $asset['asset_type'] === 'IoMT Sensor' ? 'selected' : ''; ?>>IoMT Sensor</option>
                                        <option value="Smart Device" <?php echo $asset['asset_type'] === 'Smart Device' ? 'selected' : ''; ?>>Smart Device</option>
                                        <option value="Medical Device" <?php echo $asset['asset_type'] === 'Medical Device' ? 'selected' : ''; ?>>Medical Device</option>
                                    </select>
                                <?php endif; ?>
                            </div>
                            <div class="form-group">
                                <label for="asset_subtype">Asset Sub-type</label>
                                <select id="asset_subtype" name="asset_subtype">
                                    <option value="">Select Sub-type</option>
                                    <option value="Virtual Machine" <?php echo $asset['asset_subtype'] === 'Virtual Machine' ? 'selected' : ''; ?>>Virtual Machine</option>
                                    <option value="Environmental Sensor" <?php echo $asset['asset_subtype'] === 'Environmental Sensor' ? 'selected' : ''; ?>>Environmental Sensor</option>
                                    <option value="Infusion Pump" <?php echo $asset['asset_subtype'] === 'Infusion Pump' ? 'selected' : ''; ?>>Infusion Pump</option>
                                    <option value="Security Camera" <?php echo $asset['asset_subtype'] === 'Security Camera' ? 'selected' : ''; ?>>Security Camera</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="status">Status</label>
                                <select id="status" name="status">
                                    <option value="Active" <?php echo $asset['status'] === 'Active' ? 'selected' : ''; ?>>Active</option>
                                    <option value="Inactive" <?php echo $asset['status'] === 'Inactive' ? 'selected' : ''; ?>>Inactive</option>
                                    <option value="Retired" <?php echo $asset['status'] === 'Retired' ? 'selected' : ''; ?>>Retired</option>
                                    <option value="Disposed" <?php echo $asset['status'] === 'Disposed' ? 'selected' : ''; ?>>Disposed</option>
                                </select>
                            </div>
                        </div>
                    </div>

                    <!-- Medical Device Mapping Information -->
                    <?php if ($asset['device_id']): ?>
                    <div class="form-section">
                        <h3><i class="fas fa-heartbeat"></i> Medical Device Mapping</h3>
                        <div class="mapping-info">
                            <div class="mapping-details">
                                <div class="mapping-item">
                                    <label>Device Identifier:</label>
                                    <span><?php echo dave_htmlspecialchars($asset['device_identifier'] ?: 'N/A'); ?></span>
                                </div>
                                <div class="mapping-item">
                                    <label>Brand Name:</label>
                                    <span><?php echo dave_htmlspecialchars($asset['brand_name'] ?: 'N/A'); ?></span>
                                </div>
                                <div class="mapping-item">
                                    <label>FDA Class:</label>
                                    <span><?php echo dave_htmlspecialchars($asset['fda_class'] ?: 'N/A'); ?></span>
                                </div>
                                <div class="mapping-item">
                                    <label>GMDN Term:</label>
                                    <span><?php echo dave_htmlspecialchars($asset['gmdn_term'] ?: 'N/A'); ?></span>
                                </div>
                                <div class="mapping-item">
                                    <label>Mapping Confidence:</label>
                                    <span class="confidence-badge"><?php echo number_format($asset['mapping_confidence'] * 100, 1); ?>%</span>
                                </div>
                            </div>
                            <div class="mapping-note">
                                <i class="fas fa-info-circle"></i>
                                <p>This asset is mapped to a medical device. The manufacturer and model fields below will show the medical device data when available.</p>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>

                    <!-- Device Information -->
                    <div class="form-section">
                        <h3><i class="fas fa-cog"></i> Device Information</h3>
                        <div class="form-grid">
                            <div class="form-group required">
                                <label for="manufacturer">Manufacturer *</label>
                                <input type="text" id="manufacturer" name="manufacturer" required value="<?php echo dave_htmlspecialchars($asset['manufacturer_name'] ?: $asset['manufacturer']); ?>">
                            </div>
                            <div class="form-group required">
                                <label for="model">Model *</label>
                                <input type="text" id="model" name="model" required value="<?php echo dave_htmlspecialchars($asset['model_number'] ?: $asset['model']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="serial_number">Serial Number</label>
                                <input type="text" id="serial_number" name="serial_number" value="<?php echo dave_htmlspecialchars($asset['serial_number']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="firmware_version">Firmware Version</label>
                                <input type="text" id="firmware_version" name="firmware_version" value="<?php echo dave_htmlspecialchars($asset['firmware_version']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="cpu">CPU</label>
                                <input type="text" id="cpu" name="cpu" value="<?php echo dave_htmlspecialchars($asset['cpu']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="memory_ram">Memory (RAM)</label>
                                <input type="text" id="memory_ram" name="memory_ram" value="<?php echo dave_htmlspecialchars($asset['memory_ram']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="storage">Storage</label>
                                <input type="text" id="storage" name="storage" value="<?php echo dave_htmlspecialchars($asset['storage']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="power_requirements">Power Requirements</label>
                                <input type="text" id="power_requirements" name="power_requirements" value="<?php echo dave_htmlspecialchars($asset['power_requirements']); ?>">
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
                                    <option value="Wi-Fi" <?php echo $asset['primary_communication_protocol'] === 'Wi-Fi' ? 'selected' : ''; ?>>Wi-Fi</option>
                                    <option value="Ethernet" <?php echo $asset['primary_communication_protocol'] === 'Ethernet' ? 'selected' : ''; ?>>Ethernet</option>
                                    <option value="Bluetooth/BLE" <?php echo $asset['primary_communication_protocol'] === 'Bluetooth/BLE' ? 'selected' : ''; ?>>Bluetooth/BLE</option>
                                    <option value="Zigbee" <?php echo $asset['primary_communication_protocol'] === 'Zigbee' ? 'selected' : ''; ?>>Zigbee</option>
                                    <option value="LoRaWAN" <?php echo $asset['primary_communication_protocol'] === 'LoRaWAN' ? 'selected' : ''; ?>>LoRaWAN</option>
                                    <option value="Cellular (4G/5G)" <?php echo $asset['primary_communication_protocol'] === 'Cellular (4G/5G)' ? 'selected' : ''; ?>>Cellular (4G/5G)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="authentication_method">Authentication Method</label>
                                <input type="text" id="authentication_method" name="authentication_method" placeholder="e.g., Certificate-based, Pre-shared Key, 802.1x" value="<?php echo dave_htmlspecialchars($asset['authentication_method']); ?>">
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
                                        <option value="<?php echo dave_htmlspecialchars($dept); ?>" <?php echo $asset['department'] === $dept ? 'selected' : ''; ?>>
                                            <?php echo dave_htmlspecialchars($dept); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="business_unit">Business Unit</label>
                                <input type="text" id="business_unit" name="business_unit" value="<?php echo dave_htmlspecialchars($asset['business_unit']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="cost_center">Cost Center</label>
                                <input type="text" id="cost_center" name="cost_center" value="<?php echo dave_htmlspecialchars($asset['cost_center']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="location">Location</label>
                                <input type="text" id="location" name="location" value="<?php echo dave_htmlspecialchars($asset['location']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="assigned_admin_user">Assigned Administrative User</label>
                                <input type="text" id="assigned_admin_user" name="assigned_admin_user" value="<?php echo dave_htmlspecialchars($asset['assigned_admin_user']); ?>">
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
                                    <option value="Clinical-High" <?php echo $asset['criticality'] === 'Clinical-High' ? 'selected' : ''; ?>>Clinical-High</option>
                                    <option value="Business-Medium" <?php echo $asset['criticality'] === 'Business-Medium' ? 'selected' : ''; ?>>Business-Medium</option>
                                    <option value="Non-Essential" <?php echo $asset['criticality'] === 'Non-Essential' ? 'selected' : ''; ?>>Non-Essential</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="regulatory_classification">Regulatory Classification</label>
                                <?php if ($asset['device_id'] && $asset['fda_class']): ?>
                                    <!-- Mapped asset with FDA class - auto-populate -->
                                    <select id="regulatory_classification" name="regulatory_classification">
                                        <option value="">Select Classification</option>
                                        <option value="FDA Class I" <?php echo ($asset['regulatory_classification'] === 'FDA Class I' || $asset['fda_class'] === 'Class I') ? 'selected' : ''; ?>>FDA Class I</option>
                                        <option value="FDA Class II" <?php echo ($asset['regulatory_classification'] === 'FDA Class II' || $asset['fda_class'] === 'Class II') ? 'selected' : ''; ?>>FDA Class II</option>
                                        <option value="FDA Class III" <?php echo ($asset['regulatory_classification'] === 'FDA Class III' || $asset['fda_class'] === 'Class III') ? 'selected' : ''; ?>>FDA Class III</option>
                                        <option value="HIPAA-subject" <?php echo $asset['regulatory_classification'] === 'HIPAA-subject' ? 'selected' : ''; ?>>HIPAA-subject</option>
                                    </select>
                                    <small class="form-help">Auto-populated from medical device FDA class: <?php echo dave_htmlspecialchars($asset['fda_class']); ?></small>
                                <?php else: ?>
                                    <!-- Unmapped asset or no FDA class - normal selection -->
                                    <select id="regulatory_classification" name="regulatory_classification">
                                        <option value="">Select Classification</option>
                                        <option value="FDA Class I" <?php echo $asset['regulatory_classification'] === 'FDA Class I' ? 'selected' : ''; ?>>FDA Class I</option>
                                        <option value="FDA Class II" <?php echo $asset['regulatory_classification'] === 'FDA Class II' ? 'selected' : ''; ?>>FDA Class II</option>
                                        <option value="FDA Class III" <?php echo $asset['regulatory_classification'] === 'FDA Class III' ? 'selected' : ''; ?>>FDA Class III</option>
                                        <option value="HIPAA-subject" <?php echo $asset['regulatory_classification'] === 'HIPAA-subject' ? 'selected' : ''; ?>>HIPAA-subject</option>
                                    </select>
                                <?php endif; ?>
                            </div>
                            <div class="form-group">
                                <label for="phi_status">Patient Data (PHI) Status</label>
                                <div class="checkbox-group">
                                    <label class="checkbox-label">
                                        <input type="checkbox" name="phi_status" value="1" <?php echo $asset['phi_status'] === 'true' ? 'checked' : ''; ?>>
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
                                <input type="text" id="data_encryption_transit" name="data_encryption_transit" value="<?php echo dave_htmlspecialchars($asset['data_encryption_transit']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="data_encryption_rest">Data Encryption (At Rest)</label>
                                <input type="text" id="data_encryption_rest" name="data_encryption_rest" value="<?php echo dave_htmlspecialchars($asset['data_encryption_rest']); ?>">
                            </div>
                        </div>
                    </div>

                    <!-- Maintenance & Lifecycle -->
                    <div class="form-section">
                        <h3><i class="fas fa-calendar"></i> Maintenance & Lifecycle</h3>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="warranty_expiration_date">Warranty Expiration Date</label>
                                <input type="date" id="warranty_expiration_date" name="warranty_expiration_date" value="<?php echo dave_htmlspecialchars($asset['warranty_expiration_date']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="scheduled_replacement_date">Scheduled Replacement Date</label>
                                <input type="date" id="scheduled_replacement_date" name="scheduled_replacement_date" value="<?php echo dave_htmlspecialchars($asset['scheduled_replacement_date']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="disposal_date">Disposal Date</label>
                                <input type="date" id="disposal_date" name="disposal_date" value="<?php echo dave_htmlspecialchars($asset['disposal_date']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="disposal_method">Disposal Method</label>
                                <input type="text" id="disposal_method" name="disposal_method" value="<?php echo dave_htmlspecialchars($asset['disposal_method']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="patch_level_last_update">Patch Level / Last Update</label>
                                <input type="date" id="patch_level_last_update" name="patch_level_last_update" value="<?php echo dave_htmlspecialchars($asset['patch_level_last_update']); ?>">
                            </div>
                            <div class="form-group">
                                <label for="last_audit_date">Last Audit Date</label>
                                <input type="date" id="last_audit_date" name="last_audit_date" value="<?php echo dave_htmlspecialchars($asset['last_audit_date']); ?>">
                            </div>
                        </div>
                    </div>

                    <!-- Form Actions -->
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i>
                            Update Asset
                        </button>
                        <a href="/pages/assets/view.php?id=<?php echo dave_htmlspecialchars($assetId); ?>" class="btn btn-secondary">
                            <i class="fas fa-times"></i>
                            Cancel
                        </a>
                    </div>
                </form>
            </div>
        </main>
    </div>

    <style>
        .mapping-info {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }

        .mapping-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .mapping-item {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .mapping-item label {
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .mapping-item span {
            color: var(--text-primary);
            font-size: 1rem;
        }

        .confidence-badge {
            background: var(--siemens-petrol);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.875rem;
            font-weight: 500;
            display: inline-block;
        }

        .mapping-note {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-secondary);
            border-radius: 0.5rem;
            padding: 1rem;
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
        }

        .mapping-note i {
            color: var(--siemens-petrol);
            margin-top: 0.125rem;
        }

        .mapping-note p {
            color: var(--text-secondary);
            margin: 0;
            font-size: 0.875rem;
            line-height: 1.5;
        }

        .form-help {
            color: var(--text-secondary);
            font-size: 0.75rem;
            margin-top: 0.25rem;
            font-style: italic;
        }

        select[disabled] {
            background-color: var(--bg-secondary);
            color: var(--text-secondary);
            cursor: not-allowed;
            opacity: 0.7;
        }
    </style>

    <script>
        // Form validation and enhancement
        document.addEventListener('DOMContentLoaded', function() {
            // Form validation
            const form = document.querySelector('.asset-form');
            const requiredFields = form.querySelectorAll('[required]');
            
            form.addEventListener('submit', function(e) {
                let isValid = true;
                
                requiredFields.forEach(function(field) {
                    if (!field.value.trim()) {
                        field.classList.add('error');
                        isValid = false;
                    } else {
                        field.classList.remove('error');
                    }
                });
                
                if (!isValid) {
                    e.preventDefault();
                    alert('Please fill in all required fields (marked with *).');
                }
            });
            
            // Remove error class on input
            requiredFields.forEach(function(field) {
                field.addEventListener('input', function() {
                    this.classList.remove('error');
                });
            });
        });
    </script>

    <!-- Dashboard Common Scripts -->
    <script src="/assets/js/dashboard-common.js"></script>
</body>
</html>
