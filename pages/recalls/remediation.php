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

// Require authentication
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

// Check permissions
if (!$auth->hasPermission('recalls.manage')) {
    header('Location: /pages/dashboard.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['ajax']) {
        case 'get_remediation_list':
            $page = intval($_GET['page'] ?? 1);
            $limit = intval($_GET['limit'] ?? 25);
            $offset = ($page - 1) * $limit;
            $status = $_GET['status'] ?? '';
            $assigned_to = $_GET['assigned_to'] ?? '';
            
            $whereConditions = [];
            $params = [];
            
            if ($status) {
                $whereConditions[] = "drl.remediation_status = ?";
                $params[] = $status;
            }
            
            if ($assigned_to) {
                $whereConditions[] = "drl.assigned_to = ?";
                $params[] = $assigned_to;
            }
            
            $whereClause = $whereConditions ? 'WHERE ' . implode(' AND ', $whereConditions) : '';
            
            $sql = "SELECT 
                drl.link_id,
                drl.remediation_status,
                drl.remediation_notes,
                drl.assigned_to,
                drl.due_date,
                drl.created_at,
                drl.updated_at,
                r.recall_id,
                r.fda_recall_number,
                r.recall_date,
                r.manufacturer_name,
                r.product_description,
                r.reason_for_recall,
                r.recall_classification,
                md.device_id,
                md.brand_name,
                md.device_name,
                md.model_number,
                md.device_identifier,
                a.ip_address,
                a.hostname,
                a.location,
                a.department,
                l.location_name,
                u.username as assigned_to_username
                FROM device_recalls_link drl
                JOIN recalls r ON drl.recall_id = r.recall_id
                JOIN medical_devices md ON drl.device_id = md.device_id
                JOIN assets a ON md.asset_id = a.asset_id
                LEFT JOIN locations l ON a.location_id = l.location_id
                LEFT JOIN users u ON drl.assigned_to = u.user_id
                {$whereClause}
                ORDER BY drl.due_date ASC, drl.created_at DESC
                LIMIT ? OFFSET ?";
            
            $params[] = $limit;
            $params[] = $offset;
            
            $stmt = $db->prepare($sql);
            $stmt->execute($params);
            $remediations = $stmt->fetchAll();
            
            // Get total count
            $countSql = "SELECT COUNT(*) as count
                        FROM device_recalls_link drl
                        JOIN recalls r ON drl.recall_id = r.recall_id
                        JOIN medical_devices md ON drl.device_id = md.device_id
                        {$whereClause}";
            
            $countStmt = $db->prepare($countSql);
            $countStmt->execute(array_slice($params, 0, -2));
            $total = $countStmt->fetch()['count'];
            
            echo json_encode([
                'remediations' => $remediations,
                'total' => $total,
                'page' => $page,
                'limit' => $limit,
                'total_pages' => ceil($total / $limit)
            ]);
            exit;
            
        case 'update_remediation':
            // Suppress PHP notices/warnings that could corrupt JSON
            error_reporting(E_ERROR | E_PARSE);
            
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                echo json_encode(['success' => false, 'message' => 'Invalid request method']);
                exit;
            }
            
            $linkId = $_POST['link_id'] ?? '';
            $status = $_POST['status'] ?? '';
            $notes = $_POST['notes'] ?? '';
            $assignedTo = $_POST['assigned_to'] ?? null;
            $dueDate = $_POST['due_date'] ?? null;
            
            if (!$linkId || !$status) {
                echo json_encode(['success' => false, 'message' => 'Missing required fields']);
                exit;
            }
            
            try {
                $db->beginTransaction();
                
                $sql = "UPDATE device_recalls_link 
                        SET remediation_status = ?, 
                            remediation_notes = ?, 
                            assigned_to = ?, 
                            due_date = ?,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE link_id = ?";
                
                $stmt = $db->prepare($sql);
                $result = $stmt->execute([$status, $notes, $assignedTo, $dueDate, $linkId]);
                
                if (!$result) {
                    throw new Exception('Failed to update remediation record');
                }
                
                // Log the action
                $auth->logUserAction($user['user_id'], 'remediation_update', 'device_recalls_link', $linkId, [
                    'status' => $status,
                    'assigned_to' => $assignedTo,
                    'due_date' => $dueDate
                ]);
                
                $db->commit();
                
                echo json_encode(['success' => true, 'message' => 'Remediation updated successfully']);
                
            } catch (Exception $e) {
                $db->rollback();
                echo json_encode(['success' => false, 'message' => 'Error updating remediation: ' . $e->getMessage()]);
            }
            exit;
            
        case 'get_remediation_details':
            // Suppress PHP notices/warnings that could corrupt JSON
            error_reporting(E_ERROR | E_PARSE);
            
            $linkId = $_GET['link_id'] ?? '';
            
            if (!$linkId) {
                echo json_encode(['success' => false, 'message' => 'Link ID required']);
                exit;
            }
            
            $sql = "SELECT 
                drl.link_id,
                drl.remediation_status,
                drl.remediation_notes,
                drl.assigned_to,
                drl.due_date,
                drl.created_at,
                drl.updated_at,
                r.fda_recall_number,
                r.recall_date,
                r.manufacturer_name,
                r.product_description,
                r.reason_for_recall,
                r.recall_classification,
                md.device_id,
                md.brand_name,
                md.device_name,
                md.model_number,
                md.device_identifier,
                a.ip_address,
                a.hostname,
                a.location,
                a.department,
                l.location_name,
                u.username as assigned_to_username
                FROM device_recalls_link drl
                JOIN recalls r ON drl.recall_id = r.recall_id
                JOIN medical_devices md ON drl.device_id = md.device_id
                JOIN assets a ON md.asset_id = a.asset_id
                LEFT JOIN locations l ON a.location_id = l.location_id
                LEFT JOIN users u ON drl.assigned_to = u.user_id
                WHERE drl.link_id = ?";
            
            $stmt = $db->prepare($sql);
            $stmt->execute([$linkId]);
            $remediation = $stmt->fetch();
            
            if (!$remediation) {
                echo json_encode(['success' => false, 'message' => 'Remediation not found']);
                exit;
            }
            
            echo json_encode(['success' => true, 'remediation' => $remediation]);
            exit;
            
        case 'get_users':
            $sql = "SELECT user_id, username, role 
                    FROM users 
                    WHERE is_active = TRUE 
                    ORDER BY username";
            $stmt = $db->query($sql);
            $users = $stmt->fetchAll();
            
            echo json_encode(['users' => $users]);
            exit;
            
    }
}

// Get remediation statistics
$sql = "SELECT 
    COUNT(*) as total_remediations,
    COUNT(CASE WHEN remediation_status = 'Open' THEN 1 END) as open_remediations,
    COUNT(CASE WHEN remediation_status = 'In Progress' THEN 1 END) as in_progress_remediations,
    COUNT(CASE WHEN remediation_status = 'Completed' THEN 1 END) as completed_remediations,
    COUNT(CASE WHEN remediation_status = 'Closed' THEN 1 END) as closed_remediations,
    COUNT(CASE WHEN due_date < CURRENT_DATE AND remediation_status IN ('Open', 'In Progress') THEN 1 END) as overdue_remediations
    FROM device_recalls_link";
$stmt = $db->query($sql);
$stats = $stmt->fetch();

// Get users for assignment dropdown
$sql = "SELECT user_id, username, role 
        FROM users 
        WHERE is_active = TRUE 
        ORDER BY username";
$stmt = $db->query($sql);
$users = $stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recall Remediation - </title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/admin.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/recalls.css">
    <link rel="stylesheet" href="/assets/css/remediation.css">
    <link rel="stylesheet" href="/assets/css/components/recall-scheduling-modal.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
        <div class="content-header" style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 2rem; padding-bottom: 1.5rem; border-bottom: 1px solid var(--border-primary);">
            <div class="header-left" style="display: flex; flex-direction: column; align-items: flex-start; flex: 1;">
                <h1 style="margin: 0 0 0.5rem 0; font-size: 2rem; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 0.75rem; width: 100%;"><i class="fas fa-tools"></i> Recall Remediation</h1>
                <p style="margin: 0; font-size: 1rem; color: var(--text-secondary); line-height: 1.5; display: block; width: 100%;">Manage and track recall remediation actions</p>
            </div>
            <div class="header-actions" style="display: flex; align-items: center; gap: 1rem;">
                <button class="btn btn-primary" onclick="refreshRemediations()">
                    <i class="fas fa-sync-alt"></i> Refresh
                </button>
            </div>
        </div>

        <!-- Statistics Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon open">
                    <i class="fas fa-exclamation-circle"></i>
                </div>
                <div class="stat-content">
                    <h3>Open</h3>
                    <div class="stat-value"><?php echo number_format($stats['open_remediations']); ?></div>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon in-progress">
                    <i class="fas fa-clock"></i>
                </div>
                <div class="stat-content">
                    <h3>In Progress</h3>
                    <div class="stat-value"><?php echo number_format($stats['in_progress_remediations']); ?></div>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon completed">
                    <i class="fas fa-check-circle"></i>
                </div>
                <div class="stat-content">
                    <h3>Completed</h3>
                    <div class="stat-value"><?php echo number_format($stats['completed_remediations']); ?></div>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon overdue">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="stat-content">
                    <h3>Overdue</h3>
                    <div class="stat-value"><?php echo number_format($stats['overdue_remediations']); ?></div>
                </div>
            </div>
        </div>

        <!-- Filters -->
        <div class="filters-section">
            <div class="filters-row">
                <div class="filter-group">
                    <label for="statusFilter">Status:</label>
                    <select id="statusFilter" onchange="applyFilters()">
                        <option value="">All Statuses</option>
                        <option value="Open">Open</option>
                        <option value="In Progress">In Progress</option>
                        <option value="Completed">Completed</option>
                        <option value="Closed">Closed</option>
                    </select>
                </div>
                
                <div class="filter-group">
                    <label for="assignedFilter">Assigned To:</label>
                    <select id="assignedFilter" onchange="applyFilters()">
                        <option value="">All Users</option>
                        <?php foreach ($users as $userOption): ?>
                            <option value="<?php echo dave_htmlspecialchars($userOption['user_id']); ?>">
                                <?php echo dave_htmlspecialchars($userOption['username']); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                
                <div class="filter-actions">
                    <button class="btn btn-secondary" onclick="clearFilters()">
                        <i class="fas fa-times"></i> Clear Filters
                    </button>
                </div>
            </div>
        </div>

        <!-- Remediation List -->
        <div class="content-section">
            <div class="section-header">
                <h2>Remediation Items</h2>
                <div class="section-actions">
                    <span id="remediationCount" class="count-badge">Loading...</span>
                </div>
            </div>
            
            <div id="remediationList" class="remediation-list">
                <!-- Remediation items will be loaded here -->
            </div>
            
            <!-- Pagination -->
            <div id="pagination" class="pagination">
                <!-- Pagination will be loaded here -->
            </div>
        </div>
    </div>

    <!-- Remediation Modal -->
    <div id="remediationModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Update Remediation</h2>
                <button class="modal-close" onclick="closeRemediationModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <form id="remediationForm">
                    <input type="hidden" id="remediationLinkId" name="link_id">
                    
                    <div class="form-group">
                        <label for="remediationStatus">Status:</label>
                        <select id="remediationStatus" name="status" required>
                            <option value="Open">Open</option>
                            <option value="In Progress">In Progress</option>
                            <option value="Completed">Completed</option>
                            <option value="Closed">Closed</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="remediationAssignedTo">Assigned To:</label>
                        <select id="remediationAssignedTo" name="assigned_to">
                            <option value="">Unassigned</option>
                            <?php foreach ($users as $userOption): ?>
                                <option value="<?php echo dave_htmlspecialchars($userOption['user_id']); ?>">
                                    <?php echo dave_htmlspecialchars($userOption['username']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="remediationDueDate">Due Date:</label>
                        <input type="date" id="remediationDueDate" name="due_date">
                    </div>
                    
                    <div class="form-group">
                        <label for="remediationNotes">Notes:</label>
                        <textarea id="remediationNotes" name="notes" rows="4" placeholder="Enter remediation notes..."></textarea>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeRemediationModal()">Cancel</button>
                <button class="btn btn-primary" onclick="saveRemediation()">
                    <i class="fas fa-save"></i> Save Changes
                </button>
            </div>
        </div>
    </div>

    <!-- Scripts -->
    <script src="/assets/js/components/recall-scheduling-modal.js"></script>
    <script>
        let currentPage = 1;
        let currentFilters = {};

        // Load remediations on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadRemediations();
        });

        function loadRemediations(page = 1) {
            currentPage = page;
            
            const params = new URLSearchParams({
                ajax: 'get_remediation_list',
                page: page,
                limit: 25,
                ...currentFilters
            });

            fetch('?' + params.toString())
                .then(response => response.json())
                .then(data => {
                    displayRemediations(data.remediations);
                    updatePagination(data);
                    updateCount(data.total);
                })
                .catch(error => {
                    console.error('Error loading remediations:', error);
                    showNotification('Error loading remediations', 'error');
                });
        }

        function displayRemediations(remediations) {
            const container = document.getElementById('remediationList');
            
            if (remediations.length === 0) {
                container.innerHTML = '<div class="empty-state">No remediation items found</div>';
                return;
            }

            const html = remediations.map(remediation => `
                <div class="remediation-item ${getStatusClass(remediation.remediation_status)}">
                    <div class="remediation-header">
                        <div class="remediation-title">
                            <h3>${remediation.fda_recall_number}</h3>
                            <span class="recall-date">${formatDate(remediation.recall_date)}</span>
                        </div>
                        <div class="remediation-status">
                            <span class="status-badge ${getStatusClass(remediation.remediation_status)}">
                                ${remediation.remediation_status}
                            </span>
                        </div>
                    </div>
                    
                    <div class="remediation-content">
                        <div class="remediation-info">
                            <div class="info-row">
                                <strong>Device:</strong> ${remediation.brand_name} ${remediation.device_name} ${remediation.model_number}
                            </div>
                            <div class="info-row">
                                <strong>Manufacturer:</strong> ${remediation.manufacturer_name}
                            </div>
                            <div class="info-row">
                                <strong>Reason:</strong> ${remediation.reason_for_recall}
                            </div>
                            <div class="info-row">
                                <strong>Classification:</strong> ${remediation.recall_classification}
                            </div>
                        </div>
                        
                        <div class="remediation-details">
                            <div class="detail-item">
                                <strong>Assigned To:</strong> 
                                ${remediation.assigned_to_username || 'Unassigned'}
                            </div>
                            <div class="detail-item">
                                <strong>Due Date:</strong> 
                                ${remediation.due_date ? formatDate(remediation.due_date) : 'Not set'}
                            </div>
                            <div class="detail-item">
                                <strong>Created:</strong> ${formatDateTime(remediation.created_at)}
                            </div>
                        </div>
                    </div>
                    
                    ${remediation.remediation_notes ? `
                        <div class="remediation-notes">
                            <strong>Notes:</strong> ${remediation.remediation_notes}
                        </div>
                    ` : ''}
                    
                    <div class="remediation-actions">
                        <button class="btn btn-sm btn-primary" onclick="editRemediation('${remediation.link_id}')">
                            <i class="fas fa-edit"></i> Edit
                        </button>
                        <button class="btn btn-sm btn-warning" onclick="scheduleRecallMaintenance('${remediation.recall_id}', '${remediation.device_id}', '${remediation.fda_recall_number}', '${remediation.manufacturer_name}', '${remediation.product_description}', '${remediation.recall_classification}', '${remediation.recall_date}', '${remediation.brand_name}', '${remediation.device_name}', '${remediation.model_number}', '${remediation.device_identifier}', '${remediation.ip_address}', '${remediation.hostname}', '${remediation.location}', '${remediation.department}', '${remediation.location_name}')">
                            <i class="fas fa-calendar-plus"></i> Schedule Maintenance
                        </button>
                    </div>
                </div>
            `).join('');

            container.innerHTML = html;
        }

        function getStatusClass(status) {
            switch (status) {
                case 'Open': return 'status-open';
                case 'In Progress': return 'status-in-progress';
                case 'Completed': return 'status-completed';
                case 'Closed': return 'status-closed';
                default: return 'status-unknown';
            }
        }

        function formatDate(dateString) {
            if (!dateString) return 'N/A';
            return new Date(dateString).toLocaleDateString();
        }

        function formatDateTime(dateString) {
            if (!dateString) return 'N/A';
            return new Date(dateString).toLocaleString();
        }

        function updatePagination(data) {
            const container = document.getElementById('pagination');
            
            if (data.total_pages <= 1) {
                container.innerHTML = '';
                return;
            }

            let html = '<div class="pagination-controls">';
            
            // Previous button
            if (data.page > 1) {
                html += `<button class="btn btn-sm" onclick="loadRemediations(${data.page - 1})">Previous</button>`;
            }
            
            // Page numbers
            for (let i = Math.max(1, data.page - 2); i <= Math.min(data.total_pages, data.page + 2); i++) {
                html += `<button class="btn btn-sm ${i === data.page ? 'active' : ''}" onclick="loadRemediations(${i})">${i}</button>`;
            }
            
            // Next button
            if (data.page < data.total_pages) {
                html += `<button class="btn btn-sm" onclick="loadRemediations(${data.page + 1})">Next</button>`;
            }
            
            html += '</div>';
            container.innerHTML = html;
        }

        function updateCount(total) {
            document.getElementById('remediationCount').textContent = `${total} items`;
        }

        function applyFilters() {
            currentFilters = {
                status: document.getElementById('statusFilter').value,
                assigned_to: document.getElementById('assignedFilter').value
            };
            loadRemediations(1);
        }

        function clearFilters() {
            document.getElementById('statusFilter').value = '';
            document.getElementById('assignedFilter').value = '';
            currentFilters = {};
            loadRemediations(1);
        }

        function refreshRemediations() {
            loadRemediations(currentPage);
        }


        // Callback for when recall maintenance is scheduled
        window.onRecallScheduled = function(data) {
            console.log('Recall maintenance scheduled:', data);
            if (data.success) {
                showNotification(`Successfully scheduled ${data.total_created} maintenance tasks`, 'success');
                // Refresh the remediation list to show any new items
                loadRemediations(currentPage);
            } else {
                showNotification('Error scheduling maintenance: ' + (data.message || 'Unknown error'), 'error');
            }
        };

        function editRemediation(linkId) {
            
            const params = new URLSearchParams({
                ajax: 'get_remediation_details',
                link_id: linkId
            });

            fetch('?' + params.toString())
                .then(response => response.json())
                .then(data => {
                    if (data.success && data.remediation) {
                        openRemediationModal(data.remediation);
                    } else {
                        showNotification(data.message || 'Error loading remediation details', 'error');
                    }
                })
                .catch(error => {
                    console.error('Error loading remediation data:', error);
                    showNotification('Error loading remediation details', 'error');
                });
        }

        function openRemediationModal(remediation) {
            
            // Populate form fields
            document.getElementById('remediationLinkId').value = remediation.link_id;
            document.getElementById('remediationStatus').value = remediation.remediation_status;
            document.getElementById('remediationAssignedTo').value = remediation.assigned_to || '';
            document.getElementById('remediationDueDate').value = remediation.due_date ? remediation.due_date.split(' ')[0] : '';
            document.getElementById('remediationNotes').value = remediation.remediation_notes || '';
            
            // Show modal with animation
            const modal = document.getElementById('remediationModal');
            modal.style.display = 'flex';
            
            // Trigger animation
            setTimeout(() => {
                modal.classList.add('show');
            }, 10);
        }

        function closeRemediationModal() {
            const modal = document.getElementById('remediationModal');
            modal.classList.remove('show');
            setTimeout(() => {
                modal.style.display = 'none';
            }, 300);
        }

        function saveRemediation() {
            const form = document.getElementById('remediationForm');
            const formData = new FormData(form);
            
            // Show loading state
            const saveButton = document.querySelector('#remediationModal .btn-primary');
            const originalText = saveButton.innerHTML;
            saveButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
            saveButton.disabled = true;
            
            fetch('?ajax=update_remediation', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Remediation updated successfully', 'success');
                    closeRemediationModal();
                    loadRemediations(currentPage);
                } else {
                    showNotification(data.message || 'Error updating remediation', 'error');
                }
            })
            .catch(error => {
                console.error('Error updating remediation:', error);
                showNotification('Error updating remediation', 'error');
            })
            .finally(() => {
                // Restore button state
                saveButton.innerHTML = originalText;
                saveButton.disabled = false;
            });
        }

        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
                ${message}
            `;
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 3000);
        }

        // Close modal when clicking outside
        document.getElementById('remediationModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeRemediationModal();
            }
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
        
        // Function to schedule recall maintenance
        function scheduleRecallMaintenance(recallId, deviceId, fdaNumber, manufacturer, productDescription, classification, recallDate, brandName, deviceName, modelNumber, deviceIdentifier, ipAddress, hostname, location, department, locationName) {
            console.log('scheduleRecallMaintenance called with:', {
                recallId, deviceId, fdaNumber, manufacturer, productDescription, 
                classification, recallDate, brandName, deviceName, modelNumber, 
                deviceIdentifier, ipAddress, hostname, location, department, locationName
            });
            
            const recallData = {
                recall_id: recallId,
                fda_recall_number: fdaNumber,
                manufacturer_name: manufacturer,
                product_description: productDescription,
                recall_classification: classification,
                recall_date: recallDate
            };
            
            const deviceData = {
                device_id: deviceId,
                brand_name: brandName,
                device_name: deviceName,
                model_number: modelNumber,
                device_identifier: deviceIdentifier,
                ip_address: ipAddress,
                hostname: hostname,
                location: location,
                department: department,
                location_name: locationName,
                manufacturer_name: manufacturer
            };
            
            // Show the scheduling modal with specific device
            if (window.recallSchedulingModal) {
                window.recallSchedulingModal.showForSpecificDevice(recallId, recallData, deviceData);
            } else {
                console.error('Recall scheduling modal not loaded');
                alert('Scheduling functionality not available. Please refresh the page.');
            }
        }
        
        // Callback for when recall maintenance is scheduled
        window.onRecallScheduled = function(data) {
            console.log('Recall maintenance scheduled:', data);
            // Refresh the remediation list
            loadRemediations();
            // Show success message
            showNotification(`Successfully scheduled ${data.total_created} maintenance tasks`, 'success');
        };
    </script>
    
        </main>
    </div>
</body>
</html>
