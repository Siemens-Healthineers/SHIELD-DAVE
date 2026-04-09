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
require_once __DIR__ . '/../../includes/api-key-manager.php';

// Require authentication
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

// Initialize API key manager
$apiKeyManager = new ApiKeyManager();

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'create':
            if (empty($_POST['key_name'])) {
                $errorMessage = "Key name is required.";
            } else {
                $result = $apiKeyManager->createApiKey([
                    'key_name' => trim($_POST['key_name']),
                    'description' => trim($_POST['description'] ?? ''),
                    'user_id' => $user['user_id'],
                    'scopes' => $_POST['scopes'] ?? [],
                    'rate_limit_per_hour' => min((int)($_POST['rate_limit_per_hour'] ?? 100), 1000),
                    'ip_whitelist' => !empty($_POST['ip_whitelist']) ? explode(',', $_POST['ip_whitelist']) : null,
                    'expires_at' => !empty($_POST['expires_at']) ? $_POST['expires_at'] : null,
                    'created_by' => $user['user_id']
                ]);
                
                if ($result['success']) {
                    $successMessage = "API key created successfully. Key: " . $result['api_key'];
                    // Redirect to prevent duplicate submission on refresh
                    header("Location: " . $_SERVER['PHP_SELF'] . "?success=created&key=" . urlencode($result['api_key']));
                    exit;
                } else {
                    $errorMessage = $result['error'];
                }
            }
            break;
            
        case 'update':
            $keyData = $apiKeyManager->getApiKeyById($_POST['key_id']);
            if (!$keyData || $keyData['user_id'] !== $user['user_id']) {
                $errorMessage = "Access denied. You can only manage your own API keys.";
                break;
            }
            
            $result = $apiKeyManager->updateApiKey($_POST['key_id'], [
                'key_name' => $_POST['key_name'],
                'description' => $_POST['description'],
                'scopes' => $_POST['scopes'] ?? [],
                'rate_limit_per_hour' => min((int)($_POST['rate_limit_per_hour'] ?? 100), 1000),
                'ip_whitelist' => !empty($_POST['ip_whitelist']) ? explode(',', $_POST['ip_whitelist']) : null,
                'expires_at' => !empty($_POST['expires_at']) ? $_POST['expires_at'] : null,
                'is_active' => isset($_POST['is_active'])
            ]);
            
            if ($result['success']) {
                $successMessage = "API key updated successfully";
            } else {
                $errorMessage = $result['error'];
            }
            break;
            
        case 'delete':
            $keyData = $apiKeyManager->getApiKeyById($_POST['key_id']);
            if (!$keyData || $keyData['user_id'] !== $user['user_id']) {
                $errorMessage = "Access denied. You can only manage your own API keys.";
                break;
            }
            
            $result = $apiKeyManager->deleteApiKey($_POST['key_id']);
            
            if ($result['success']) {
                $successMessage = "API key deleted successfully";
            } else {
                $errorMessage = $result['error'];
            }
            break;
            
        case 'regenerate':
            $keyData = $apiKeyManager->getApiKeyById($_POST['key_id']);
            if (!$keyData || $keyData['user_id'] !== $user['user_id']) {
                $errorMessage = "Access denied. You can only manage your own API keys.";
                break;
            }
            
            $result = $apiKeyManager->regenerateApiKey($_POST['key_id']);
            
            if ($result['success']) {
                $successMessage = "API key regenerated successfully. New key: " . $result['api_key'];
            } else {
                $errorMessage = $result['error'];
            }
            break;
    }
}

// Handle success message from redirect
if (isset($_GET['success']) && $_GET['success'] === 'created') {
    if (isset($_GET['key'])) {
        $newlyCreatedApiKey = $_GET['key'];
        $successMessage = "API key created successfully! Your new API key is:  " . dave_htmlspecialchars($newlyCreatedApiKey) . " Please copy this key now - you won't be able to see it again!</small>";
    } else {
        $successMessage = "API key created successfully!";
    }
}

// Get user's API keys
$apiKeys = $apiKeyManager->listApiKeys($user['user_id'], true);

// Get available scopes based on user role
$availableScopes = [];
switch (strtolower($user['role'])) {
    case 'admin':
        $availableScopes = [
            'users:read', 'users:write', 'users:delete',
            'assets:read', 'assets:write', 'assets:delete',
            'vulnerabilities:read', 'vulnerabilities:write', 'vulnerabilities:delete',
            'components:read', 'components:write', 'components:delete',
            'recalls:read', 'recalls:write', 'recalls:delete',
            'reports:read', 'reports:write', 'reports:delete',
            'risks:read', 'risks:write', 'risks:delete',
            'system:read', 'system:write',
            'analytics:read', 'analytics:write',
            'patches:read', 'patches:write',
            'remediations:read', 'remediations:write', 'remediations:delete',
            'locations:read', 'locations:write', 'locations:delete',
            'api_keys:read', 'api_keys:write', 'api_keys:delete'
        ];
        break;
    case 'user':
        $availableScopes = [
            'assets:read', 'assets:write',
            'vulnerabilities:read', 'vulnerabilities:write',
            'risks:read', 'risks:write',
            'components:read', 'components:write',
            'recalls:read', 'recalls:write',
            'reports:read', 'reports:write',
            'analytics:read', 'analytics:write',
            'patches:read', 'patches:write',
            'remediations:read', 'remediations:write',
            'locations:read', 'locations:write',
            'api_keys:read', 'api_keys:write'
        ];
        break;
    default:
        $availableScopes = [
            'assets:read', 'assets:write',
            'vulnerabilities:read', 'vulnerabilities:write',
            'risks:read', 'risks:write',
            'components:read', 'components:write',
            'recalls:read', 'recalls:write',
            'reports:read', 'reports:write',
            'analytics:read', 'analytics:write',
            'patches:read', 'patches:write',
            'remediations:read', 'remediations:write',
            'locations:read', 'locations:write',
            'api_keys:read', 'api_keys:write'
        ];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My API Keys - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <!-- Page Header -->
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-key"></i> My API Keys</h1>
                    <p>Manage your API keys for external system integration</p>
                </div>
            </div>

            <!-- Alerts -->
            <?php if (isset($successMessage)): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <?php echo dave_htmlspecialchars($successMessage); ?>
            </div>
            <?php endif; ?>

            <?php if (isset($errorMessage)): ?>
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i>
                <?php echo dave_htmlspecialchars($errorMessage); ?>
            </div>
            <?php endif; ?>

            <!-- Metrics Section -->
            <section class="metrics-section">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-key"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Total Keys</h3>
                            <div class="metric-value"><?php echo count($apiKeys); ?></div>
                        </div>
                    </div>
                    
                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-check-circle"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Active Keys</h3>
                            <div class="metric-value"><?php echo count(array_filter($apiKeys, function($k) { return $k['is_active']; })); ?></div>
                        </div>
                    </div>
                    
                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-chart-line"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Total Requests</h3>
                            <div class="metric-value"><?php echo array_sum(array_column($apiKeys, 'usage_count')); ?></div>
                        </div>
                    </div>
                    
                    <div class="metric-card">
                        <div class="metric-icon">
                            <i class="fas fa-clock"></i>
                        </div>
                        <div class="metric-content">
                            <h3>Used This Week</h3>
                            <div class="metric-value"><?php echo count(array_filter($apiKeys, function($k) { return $k['last_used'] && strtotime($k['last_used']) > strtotime('-7 days'); })); ?></div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- API Keys Section -->
            <section class="dashboard-grid">
                <div class="dashboard-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-key"></i> My API Keys</h3>
                        <button class="btn btn-primary btn-sm" onclick="showCreateModal()">
                            <i class="fas fa-plus"></i>
                            Create New
                        </button>
                    </div>
                    <div class="widget-content">
                        <?php if (empty($apiKeys)): ?>
                        <div class="empty-state">
                            <i class="fas fa-key fa-3x"></i>
                            <h3>No API Keys</h3>
                            <p>You haven't created any API keys yet. Create your first API key to start integrating with external systems.</p>
                            <button class="btn btn-primary" onclick="showCreateModal()">
                                <i class="fas fa-plus"></i>
                                Create Your First API Key
                            </button>
                        </div>
                        <?php else: ?>
                        <div class="api-keys-grid">
                            <?php foreach ($apiKeys as $key): ?>
                            <?php 
                            $scopes = json_decode($key['scopes'] ?? '[]', true);
                            ?>
                            <div class="api-key-card">
                                <div class="api-key-header">
                                    <div class="api-key-title">
                                        <h4><?php echo dave_htmlspecialchars($key['key_name']); ?></h4>
                                        <?php if ($key['description']): ?>
                                        <p class="api-key-description"><?php echo dave_htmlspecialchars($key['description']); ?></p>
                                        <?php endif; ?>
                                    </div>
                                    <div class="api-key-status">
                                        <?php if ($key['is_active']): ?>
                                            <span class="badge badge-success">Active</span>
                                        <?php else: ?>
                                            <span class="badge badge-secondary">Inactive</span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                
                                <div class="api-key-details">
                                    <div class="detail-row">
                                        <div class="detail-item">
                                            <label>Last Used:</label>
                                            <span class="text-muted"><?php echo $key['last_used'] ? date('Y-m-d H:i', strtotime($key['last_used'])) : 'Never'; ?></span>
                                        </div>
                                        <div class="detail-item">
                                            <label>Usage Count:</label>
                                            <span class="text-muted"><?php echo number_format($key['usage_count']); ?></span>
                                        </div>
                                    </div>
                                    
                                    <div class="detail-row">
                                        <div class="detail-item">
                                            <label>Expires:</label>
                                            <span class="text-muted"><?php echo $key['expires_at'] ? date('Y-m-d', strtotime($key['expires_at'])) : 'Never'; ?></span>
                                        </div>
                                        <div class="detail-item">
                                            <label>Rate Limit:</label>
                                            <span class="text-muted"><?php echo number_format($key['rate_limit_per_hour']); ?>/hour</span>
                                        </div>
                                    </div>
                                    
                                    <div class="detail-row">
                                        <div class="detail-item full-width">
                                            <label>Scopes:</label>
                                            <div class="scopes-container">
                                                <?php foreach (array_slice($scopes, 0, 4) as $scope): ?>
                                                    <span class="badge badge-primary"><?php echo dave_htmlspecialchars($scope); ?></span>
                                                <?php endforeach; ?>
                                                <?php if (count($scopes) > 4): ?>
                                                    <span class="badge badge-secondary">+<?php echo count($scopes) - 4; ?> more</span>
                                                <?php endif; ?>
                                                <?php if (empty($scopes)): ?>
                                                    <span class="text-muted">No scopes defined</span>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="api-key-actions">
                                    <button class="btn btn-sm btn-secondary" onclick="showEditModal(<?php echo dave_htmlspecialchars(json_encode($key)); ?>)" title="Edit">
                                        <i class="fas fa-edit"></i> Edit
                                    </button>
                                    <button class="btn btn-sm btn-warning" onclick="regenerateKey('<?php echo $key['key_id']; ?>')" title="Regenerate">
                                        <i class="fas fa-sync"></i> Regenerate
                                    </button>
                                    <button class="btn btn-sm btn-danger" onclick="deleteKey('<?php echo $key['key_id']; ?>')" title="Delete">
                                        <i class="fas fa-trash"></i> Delete
                                    </button>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
            </section>

            <!-- Help Section -->
            <section class="dashboard-grid">
                <div class="dashboard-widget">
                    <div class="widget-header">
                        <h3><i class="fas fa-question-circle"></i> API Key Help</h3>
                    </div>
                    <div class="widget-content">
                        <div class="help-content">
                            <div class="help-item">
                                <h4><i class="fas fa-info-circle"></i> What are API Keys?</h4>
                                <p>API keys allow external systems to authenticate with the  API without requiring a username and password. They're perfect for automated scripts, integrations, and third-party applications.</p>
                            </div>
                            
                            <div class="help-item">
                                <h4><i class="fas fa-shield-alt"></i> Security Best Practices</h4>
                                <ul>
                                    <li>Store API keys securely (environment variables, key management systems)</li>
                                    <li>Never commit API keys to version control</li>
                                    <li>Use IP whitelisting when possible</li>
                                    <li>Set appropriate expiration dates</li>
                                    <li>Rotate keys regularly</li>
                                </ul>
                            </div>
                            
                            <div class="help-item">
                                <h4><i class="fas fa-code"></i> Usage Example</h4>
                                <div class="code-block">
                                    <code>curl -H "Authorization: Bearer dave_your_api_key_here" \<br>
&nbsp;&nbsp;&nbsp;&nbsp;https://your-domain.com/api/v1/assets/api-example</code>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
        </main>
    </div>

    <!-- Create/Edit Modal -->
    <div id="keyModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modalTitle">Create API Key</h3>
                <span class="close" onclick="closeModal()">&times;</span>
            </div>
            <form id="keyForm" method="POST">
                <input type="hidden" name="action" id="formAction" value="create">
                <input type="hidden" name="key_id" id="keyId">
                
                <div class="modal-body">
                    <div class="form-group">
                        <label for="key_name">Key Name *</label>
                        <input type="text" id="key_name" name="key_name" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="description">Description</label>
                        <textarea id="description" name="description" rows="3" placeholder="Describe what this API key will be used for"></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>Scopes</label>
                        <p class="help-text">Select the permissions this API key should have. You can only select scopes available to your role.</p>
                        
                        <!-- Quick Actions -->
                        <div class="permission-actions">
                            <button type="button" onclick="selectAllPermissions()">Select All</button>
                            <button type="button" onclick="clearAllPermissions()">Clear All</button>
                            <button type="button" onclick="selectReadOnly()">Read Only</button>
                        </div>
                        
                        <!-- Permission Tabs -->
                        <div class="permission-tabs">
                            <div class="permission-tab active" data-tab="core">Core</div>
                            <div class="permission-tab" data-tab="management">Management</div>
                        </div>
                        
                        <!-- Core Permissions -->
                        <div class="permission-content active" id="core-permissions">
                            <div class="permission-grid">
                                <?php if (in_array('assets:read', $availableScopes)): ?>
                                <div class="permission-group">
                                    <h4>Assets</h4>
                                    <div class="permission-checkboxes">
                                        <div class="permission-checkbox">
                                            <input type="checkbox" name="scopes[]" value="assets:read" id="assets_read">
                                            <label for="assets_read">Read</label>
                                        </div>
                                        <div class="permission-checkbox">
                                            <input type="checkbox" name="scopes[]" value="assets:write" id="assets_write">
                                            <label for="assets_write">Write</label>
                                        </div>
                                    </div>
                                </div>
                                <?php endif; ?>
                                
                                <?php if (in_array('vulnerabilities:read', $availableScopes)): ?>
                                <div class="permission-group">
                                    <h4>Vulnerabilities</h4>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="vulnerabilities:read" id="vulns_read">
                                        <label for="vulns_read">Read</label>
                                    </div>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="vulnerabilities:write" id="vulns_write">
                                        <label for="vulns_write">Write</label>
                                    </div>
                                </div>
                                <?php endif; ?>


                                <?php if (in_array('components:read', $availableScopes)): ?>
                                <div class="permission-group">
                                    <h4>Components</h4>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="components:read" id="components_read">
                                        <label for="components_read">Read</label>
                                    </div>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="components:write" id="components_write">
                                        <label for="components_write">Write</label>
                                    </div>
                                </div>
                                <?php endif; ?>

                                <?php if (in_array('recalls:read', $availableScopes)): ?>
                                <div class="permission-group">
                                    <h4>Recalls</h4>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="recalls:read" id="recalls_read">
                                        <label for="recalls_read">Read</label>
                                    </div>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="recalls:write" id="recalls_write">
                                        <label for="recalls_write">Write</label>
                                    </div>
                                </div>
                                <?php endif; ?>
                                
                                <?php if (in_array('reports:read', $availableScopes)): ?>
                                <div class="permission-group">
                                    <h4>Reports</h4>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="reports:read" id="reports_read">
                                        <label for="reports_read">Read</label>
                                    </div>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="reports:write" id="reports_write">
                                        <label for="reports_write">Write</label>
                                    </div>
                                </div>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <!-- Management Permissions -->
                        <div class="permission-content" id="management-permissions">
                            <div class="permission-grid">
                                <?php if (in_array('analytics:read', $availableScopes)): ?>
                                <div class="permission-group">
                                    <h4>Analytics</h4>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="analytics:read" id="analytics_read">
                                        <label for="analytics_read">Read</label>
                                    </div>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="analytics:write" id="analytics_write">
                                        <label for="analytics_write">Write</label>
                                    </div>
                                </div>
                                <?php endif; ?>
                                
                                <?php if (in_array('patches:read', $availableScopes)): ?>
                                <div class="permission-group">
                                    <h4>Patches</h4>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="patches:read" id="patches_read">
                                        <label for="patches_read">Read</label>
                                    </div>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="patches:write" id="patches_write">
                                        <label for="patches_write">Write</label>
                                    </div>
                                </div>
                                <?php endif; ?>
                                
                                <?php if (in_array('locations:read', $availableScopes)): ?>
                                <div class="permission-group">
                                    <h4>Locations</h4>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="locations:read" id="locations_read">
                                        <label for="locations_read">Read</label>
                                    </div>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="locations:write" id="locations_write">
                                        <label for="locations_write">Write</label>
                                    </div>
                                </div>
                                <?php endif; ?>

                                <?php if (in_array('risks:read', $availableScopes)): ?>
                                <div class="permission-group">
                                    <h4>Risks</h4>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="risks:read" id="risks_read">
                                        <label for="risks_read">Read</label>
                                    </div>
                                    <div class="permission-checkbox">
                                        <input type="checkbox" name="scopes[]" value="risks:write" id="risks_write">
                                        <label for="risks_write">Write</label>
                                    </div>
                                </div>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <!-- Permission Summary -->
                        <div class="permission-summary">
                            <h5>Selected Permissions</h5>
                            <div class="selected-scopes" id="selectedScopes">
                                <span class="text-muted">No permissions selected</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="rate_limit_per_hour">Rate Limit (requests per hour)</label>
                        <input type="number" id="rate_limit_per_hour" name="rate_limit_per_hour" value="100" min="1" max="1000">
                        <small>Maximum: 1000 requests per hour</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="ip_whitelist">IP Whitelist (comma-separated)</label>
                        <input type="text" id="ip_whitelist" name="ip_whitelist" placeholder="192.168.1.1, 10.0.0.1">
                        <small>Leave empty to allow all IPs</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="expires_at">Expiration Date</label>
                        <input type="date" id="expires_at" name="expires_at">
                        <small>Leave empty for no expiration</small>
                    </div>
                    
                    <div class="form-group" id="activeGroup" style="display: none;">
                        <label class="checkbox-label">
                            <input type="checkbox" name="is_active" id="is_active" checked>
                            <span class="checkmark"></span>
                            Active
                        </label>
                    </div>
                </div>
                
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save</button>
                </div>
            </form>
        </div>
    </div>

    <style>
        /* API Key Management Specific Styles */
        .api-keys-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 1.5rem;
            margin: 1rem 0;
        }
        
        .api-key-card {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            padding: 1.5rem;
            transition: all 0.2s ease;
        }
        
        .api-key-card:hover {
            border-color: var(--siemens-petrol);
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.1);
        }
        
        .api-key-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid var(--border-secondary);
        }
        
        .api-key-title h4 {
            margin: 0 0 0.25rem 0;
            color: var(--text-primary);
            font-size: 1.125rem;
            font-weight: var(--font-weight-semibold);
        }
        
        .api-key-description {
            margin: 0;
            color: var(--text-secondary);
            font-size: 0.875rem;
            line-height: 1.4;
        }
        
        .api-key-status {
            flex-shrink: 0;
        }
        
        .api-key-details {
            margin-bottom: 1rem;
        }
        
        .detail-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-bottom: 0.75rem;
        }
        
        .detail-row:last-child {
            margin-bottom: 0;
        }
        
        .detail-item.full-width {
            grid-column: 1 / -1;
        }
        
        .detail-item label {
            display: block;
            font-size: 0.75rem;
            font-weight: var(--font-weight-semibold);
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.25rem;
        }
        
        .detail-item span {
            color: var(--text-primary);
            font-size: 0.875rem;
        }
        
        .scopes-container {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.25rem;
        }
        
        .api-key-actions {
            display: flex;
            gap: 0.5rem;
            padding-top: 0.75rem;
            border-top: 1px solid var(--border-secondary);
        }
        
        .api-key-actions .btn {
            flex: 1;
            justify-content: center;
        }
        
        /* Compact Permission Design */
        .permission-tabs {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin: 1rem 0;
            border-bottom: 1px solid var(--border-secondary);
            padding-bottom: 0.5rem;
        }
        
        .permission-tab {
            background: var(--bg-secondary);
            border: 1px solid var(--border-secondary);
            border-radius: 6px;
            padding: 0.5rem 1rem;
            cursor: pointer;
            font-size: 0.875rem;
            color: var(--text-secondary);
            transition: all 0.2s ease;
            user-select: none;
        }
        
        .permission-tab:hover {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }
        
        .permission-tab.active {
            background: var(--siemens-petrol);
            color: white;
            border-color: var(--siemens-petrol);
        }
        
        .permission-content {
            display: none;
            margin-top: 1rem;
        }
        
        .permission-content.active {
            display: block;
        }
        
        .permission-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            align-items: start;
        }
        
        .permission-group {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 8px;
            padding: 1rem;
            min-height: 120px;
            display: flex;
            flex-direction: column;
        }
        
        .permission-group h4 {
            margin: 0 0 0.75rem 0;
            color: var(--siemens-petrol);
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border-secondary);
            padding-bottom: 0.5rem;
        }
        
        .permission-checkboxes {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            flex: 1;
        }
        
        .permission-checkbox {
            display: flex;
            align-items: center;
            padding: 0.25rem 0;
            min-height: 24px;
        }
        
        .permission-checkbox input[type="checkbox"] {
            margin: 0;
            margin-right: 0.75rem;
            accent-color: var(--siemens-petrol);
            transform: scale(1);
            flex-shrink: 0;
            width: 16px;
            height: 16px;
        }
        
        .permission-checkbox label {
            font-size: 0.85rem;
            color: var(--text-secondary);
            cursor: pointer;
            line-height: 1.3;
            flex: 1;
            margin: 0;
            display: flex;
            align-items: center;
            min-height: 20px;
        }
        
        /* Quick Actions */
        .permission-actions {
            display: flex;
            gap: 0.75rem;
            margin: 1rem 0;
            padding: 1rem;
            background: var(--bg-secondary);
            border-radius: 8px;
            border: 1px solid var(--border-secondary);
            flex-wrap: wrap;
            justify-content: center;
        }
        
        .permission-actions button {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-secondary);
            color: var(--text-secondary);
            padding: 0.6rem 1.2rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 500;
            transition: all 0.2s ease;
            min-width: 100px;
            text-align: center;
        }
        
        .permission-actions button:hover {
            background: var(--siemens-petrol);
            color: white;
            border-color: var(--siemens-petrol);
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(0, 153, 153, 0.2);
        }
        
        .permission-actions button:active {
            transform: translateY(0);
        }
        
        .permission-summary {
            background: var(--bg-secondary);
            border: 1px solid var(--border-secondary);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
            border-left: 4px solid var(--siemens-petrol);
        }
        
        .permission-summary h5 {
            margin: 0 0 0.75rem 0;
            color: var(--siemens-petrol);
            font-size: 0.9rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .permission-summary h5::before {
            content: "✓";
            background: var(--siemens-petrol);
            color: white;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: bold;
        }
        
        .selected-scopes {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            min-height: 24px;
        }
        
        .scope-badge {
            background: var(--siemens-petrol);
            color: white;
            padding: 0.4rem 0.75rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 500;
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            transition: all 0.2s ease;
        }
        
        .scope-badge:hover {
            background: var(--siemens-petrol-dark);
            transform: translateY(-1px);
        }
        
        .text-muted {
            color: var(--text-muted);
            font-style: italic;
        }
        
        .help-content {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
        }
        
        .help-item {
            margin-bottom: 1.5rem;
        }
        
        .help-item:last-child {
            margin-bottom: 0;
        }
        
        .help-item h4 {
            color: var(--siemens-petrol);
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .help-item p {
            color: var(--text-secondary);
            line-height: 1.6;
        }
        
        .help-item ul {
            color: var(--text-secondary);
            padding-left: 1.5rem;
        }
        
        .help-item li {
            margin-bottom: 0.25rem;
        }
        
        .code-block {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-secondary);
            border-radius: 0.5rem;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            color: var(--text-primary);
            overflow-x: auto;
        }
        
        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(4px);
        }
        
        .modal-content {
            background: var(--bg-primary);
            margin: 5% auto;
            padding: 0;
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            width: 90%;
            max-width: 640px;
            max-height: 90vh;
            overflow-y: auto;
            box-shadow: var(--shadow-xl);
        }
        
        .modal-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .modal-header h3 {
            margin: 0;
            color: var(--text-primary);
            font-size: 1.25rem;
            font-weight: 600;
        }
        
        .close {
            color: var(--text-muted);
            font-size: 1.5rem;
            font-weight: bold;
            cursor: pointer;
            transition: color 0.2s ease;
        }
        
        .close:hover {
            color: var(--text-primary);
        }
        
        .modal-body {
            padding: 1.5rem;
        }
        
        .modal-footer {
            padding: 1.5rem;
            border-top: 1px solid var(--border-primary);
            display: flex;
            justify-content: flex-end;
            gap: 0.75rem;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--text-primary);
            font-weight: 500;
        }
        
        .form-group input,
        .form-group textarea,
        .form-group select {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border-secondary);
            border-radius: 0.5rem;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 0.875rem;
            transition: border-color 0.2s ease;
        }
        
        .form-group input:focus,
        .form-group textarea:focus,
        .form-group select:focus {
            outline: none;
            border-color: var(--siemens-petrol);
            box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
        }
        
        .form-group small {
            display: block;
            margin-top: 0.25rem;
            color: var(--text-muted);
            font-size: 0.75rem;
        }
        
        .checkbox-label {
            display: flex;
            align-items: center;
            cursor: pointer;
            font-size: 0.875rem;
            color: var(--text-primary);
        }
        
        .checkbox-label input[type="checkbox"] {
            margin-right: 0.5rem;
            accent-color: var(--siemens-petrol);
        }
        
        .help-text {
            color: var(--text-muted);
            font-size: 0.875rem;
            margin-top: 0.25rem;
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .permission-grid {
                grid-template-columns: 1fr;
            }
            
            .modal-content {
                width: 95%;
                margin: 2% auto;
            }
        }
    </style>

    <!-- Confirmation Modal -->
    <div id="confirmModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="confirmTitle">Confirm Action</h3>
                <span class="close" onclick="closeConfirmModal()">&times;</span>
            </div>
            <div class="modal-body">
                <p id="confirmMessage">Are you sure you want to perform this action?</p>
                <input type="hidden" id="confirmAction" value="">
                <input type="hidden" id="confirmKeyId" value="">
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeConfirmModal()">Cancel</button>
                <button type="button" class="btn btn-danger" id="confirmButton" onclick="confirmAction()">Confirm</button>
            </div>
        </div>
    </div>

    <script>
        function showCreateModal() {
            document.getElementById('modalTitle').textContent = 'Create API Key';
            document.getElementById('formAction').value = 'create';
            document.getElementById('keyForm').reset();
            document.getElementById('activeGroup').style.display = 'none';
            document.getElementById('keyModal').style.display = 'block';
        }
        
        function showEditModal(key) {
            document.getElementById('modalTitle').textContent = 'Edit API Key';
            document.getElementById('formAction').value = 'update';
            document.getElementById('keyId').value = key.key_id;
            document.getElementById('key_name').value = key.key_name;
            document.getElementById('description').value = key.description || '';
            document.getElementById('rate_limit_per_hour').value = key.rate_limit_per_hour;
            document.getElementById('ip_whitelist').value = key.ip_whitelist ? JSON.parse(key.ip_whitelist).join(', ') : '';
            document.getElementById('expires_at').value = key.expires_at ? key.expires_at.split(' ')[0] : '';
            document.getElementById('is_active').checked = key.is_active;
            document.getElementById('activeGroup').style.display = 'block';
            
            // Set scopes
            const scopes = JSON.parse(key.scopes || '[]');
            document.querySelectorAll('input[name="scopes[]"]').forEach(checkbox => {
                checkbox.checked = scopes.includes(checkbox.value);
            });
            
            document.getElementById('keyModal').style.display = 'block';
        }
        
        function closeModal() {
            document.getElementById('keyModal').style.display = 'none';
        }
        
        function regenerateKey(keyId) {
            document.getElementById('confirmAction').value = 'regenerate';
            document.getElementById('confirmKeyId').value = keyId;
            document.getElementById('confirmTitle').textContent = 'Regenerate API Key';
            document.getElementById('confirmMessage').textContent = 'Are you sure you want to regenerate this API key? The old key will no longer work and any systems using it will need to be updated.';
            document.getElementById('confirmButton').textContent = 'Regenerate Key';
            document.getElementById('confirmButton').className = 'btn btn-warning';
            document.getElementById('confirmModal').style.display = 'block';
        }
        
        function deleteKey(keyId) {
            document.getElementById('confirmAction').value = 'delete';
            document.getElementById('confirmKeyId').value = keyId;
            document.getElementById('confirmTitle').textContent = 'Delete API Key';
            document.getElementById('confirmMessage').textContent = 'Are you sure you want to delete this API key? This action cannot be undone and will immediately revoke access for any systems using this key.';
            document.getElementById('confirmButton').textContent = 'Delete Key';
            document.getElementById('confirmButton').className = 'btn btn-danger';
            document.getElementById('confirmModal').style.display = 'block';
        }
        
        function confirmAction() {
            const action = document.getElementById('confirmAction').value;
            const keyId = document.getElementById('confirmKeyId').value;
            
            const form = document.createElement('form');
            form.method = 'POST';
            form.innerHTML = `
                <input type="hidden" name="action" value="${action}">
                <input type="hidden" name="key_id" value="${keyId}">
            `;
            document.body.appendChild(form);
            form.submit();
        }
        
        function closeConfirmModal() {
            document.getElementById('confirmModal').style.display = 'none';
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const keyModal = document.getElementById('keyModal');
            const confirmModal = document.getElementById('confirmModal');
            if (event.target === keyModal) {
                closeModal();
            } else if (event.target === confirmModal) {
                closeConfirmModal();
            }
        }
        
        // Tab switching functionality
        document.querySelectorAll('.permission-tab').forEach(tab => {
            tab.addEventListener('click', function() {
                // Remove active class from all tabs and content
                document.querySelectorAll('.permission-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.permission-content').forEach(c => c.classList.remove('active'));
                
                // Add active class to clicked tab
                this.classList.add('active');
                
                // Show corresponding content
                const tabName = this.getAttribute('data-tab');
                document.getElementById(tabName + '-permissions').classList.add('active');
            });
        });
        
        // Quick action functions
        function selectAllPermissions() {
            document.querySelectorAll('input[name="scopes[]"]').forEach(checkbox => {
                checkbox.checked = true;
            });
            updatePermissionSummary();
        }
        
        function clearAllPermissions() {
            document.querySelectorAll('input[name="scopes[]"]').forEach(checkbox => {
                checkbox.checked = false;
            });
            updatePermissionSummary();
        }
        
        function selectReadOnly() {
            clearAllPermissions();
            document.querySelectorAll('input[name="scopes[]"][value$=":read"]').forEach(checkbox => {
                checkbox.checked = true;
            });
            updatePermissionSummary();
        }
        
        function updatePermissionSummary() {
            const selectedScopes = Array.from(document.querySelectorAll('input[name="scopes[]"]:checked'))
                .map(checkbox => checkbox.value);
            
            const summaryDiv = document.getElementById('selectedScopes');
            
            if (selectedScopes.length === 0) {
                summaryDiv.innerHTML = '<span class="text-muted">No permissions selected</span>';
            } else {
                summaryDiv.innerHTML = selectedScopes.map(scope => 
                    `<span class="scope-badge">${scope}</span>`
                ).join('');
            }
        }
        
        // Update summary when checkboxes change
        document.addEventListener('change', function(e) {
            if (e.target.name === 'scopes[]') {
                updatePermissionSummary();
            }
        });
    </script>
</body>
</html>