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

$db = DatabaseConfig::getInstance();

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['ajax']) {
        case 'get_recalls':
            // Suppress PHP notices/warnings that could corrupt JSON
            error_reporting(E_ERROR | E_PARSE);
            
            $page = intval($_GET['page'] ?? 1);
            $limit = intval($_GET['limit'] ?? 25);
            $offset = ($page - 1) * $limit;
            $search = $_GET['search'] ?? '';
            $status = $_GET['status'] ?? '';
            $classification = $_GET['classification'] ?? '';
            $manufacturer = $_GET['manufacturer'] ?? '';
            $dateFrom = $_GET['date_from'] ?? '';
            $dateTo = $_GET['date_to'] ?? '';
            
            // Build filters
            $filters = [];
            $params = [];
            
            if (!empty($search)) {
                $filters[] = "(r.fda_recall_number ILIKE ? OR r.product_description ILIKE ? OR r.manufacturer_name ILIKE ?)";
                $searchParam = '%' . $search . '%';
                $params[] = $searchParam;
                $params[] = $searchParam;
                $params[] = $searchParam;
            }
            
            if (!empty($status)) {
                $filters[] = "r.recall_status = ?";
                $params[] = $status;
            }
            
            if (!empty($classification)) {
                $filters[] = "r.recall_classification = ?";
                $params[] = $classification;
            }
            
            if (!empty($manufacturer)) {
                $filters[] = "r.manufacturer_name ILIKE ?";
                $params[] = '%' . $manufacturer . '%';
            }
            
            if (!empty($dateFrom)) {
                $filters[] = "r.recall_date >= ?";
                $params[] = $dateFrom;
            }
            
            if (!empty($dateTo)) {
                $filters[] = "r.recall_date <= ?";
                $params[] = $dateTo;
            }
            
            $whereClause = !empty($filters) ? 'WHERE ' . implode(' AND ', $filters) : '';
            
            // Get recalls
            $sql = "SELECT 
                r.recall_id,
                r.fda_recall_number,
                r.recall_date,
                r.product_description,
                r.reason_for_recall,
                r.manufacturer_name,
                r.product_code,
                r.recall_classification,
                r.recall_status,
                COUNT(DISTINCT drl.device_id) as affected_devices,
                COUNT(DISTINCT CASE WHEN drl.remediation_status = 'Open' THEN drl.device_id END) as open_remediations,
                COUNT(DISTINCT CASE WHEN drl.remediation_status = 'In Progress' THEN drl.device_id END) as in_progress_remediations,
                COUNT(DISTINCT CASE WHEN drl.remediation_status = 'Resolved' THEN drl.device_id END) as resolved_remediations
                FROM recalls r
                LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
                $whereClause
                GROUP BY r.recall_id, r.fda_recall_number, r.recall_date, r.product_description, 
                         r.reason_for_recall, r.manufacturer_name, r.product_code, 
                         r.recall_classification, r.recall_status
                ORDER BY r.recall_date DESC
                LIMIT ? OFFSET ?";
            
            $params[] = $limit;
            $params[] = $offset;
            $stmt = $db->query($sql, $params);
            $recalls = $stmt->fetchAll();
            
            // Get total count
            $countSql = "SELECT COUNT(DISTINCT r.recall_id) 
                        FROM recalls r
                        LEFT JOIN device_recalls_link drl ON r.recall_id = drl.recall_id
                        $whereClause";
            $countStmt = $db->query($countSql, array_slice($params, 0, -2));
            $total = $countStmt->fetch()['count'];
            
            echo json_encode([
                'recalls' => $recalls,
                'total' => $total,
                'page' => $page,
                'limit' => $limit,
                'pages' => ceil($total / $limit)
            ]);
            exit;
            
        case 'get_recall_details':
            // Suppress PHP notices/warnings that could corrupt JSON
            error_reporting(E_ERROR | E_PARSE);
            
            $recallId = $_GET['recall_id'] ?? '';
            
            if (empty($recallId)) {
                echo json_encode(['error' => 'Recall ID required']);
                exit;
            }
            
            try {
                // Get recall details
                $sql = "SELECT * FROM recalls WHERE recall_id = ?";
                $stmt = $db->prepare($sql);
                $stmt->execute([$recallId]);
                $recall = $stmt->fetch();
                
                if (!$recall) {
                    echo json_encode(['error' => 'Recall not found']);
                    exit;
                }
                
                // Get affected devices
                $sql = "SELECT 
                    drl.link_id,
                    drl.remediation_status,
                    drl.remediation_notes,
                    drl.created_at as linked_at,
                    a.hostname,
                    a.ip_address,
                    md.brand_name,
                    md.model_number,
                    md.device_identifier
                    FROM device_recalls_link drl
                    JOIN medical_devices md ON drl.device_id = md.device_id
                    JOIN assets a ON md.asset_id = a.asset_id
                    WHERE drl.recall_id = ?
                    ORDER BY drl.created_at DESC";
                
                $stmt = $db->prepare($sql);
                $stmt->execute([$recallId]);
                $affectedDevices = $stmt->fetchAll();
                
                echo json_encode([
                    'recall' => $recall,
                    'affected_devices' => $affectedDevices
                ]);
                
            } catch (Exception $e) {
                echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
            }
            exit;
            
        case 'update_remediation':
            // Suppress PHP notices/warnings that could corrupt JSON
            error_reporting(E_ERROR | E_PARSE);
            
            if (!$auth->hasPermission('recalls.manage')) {
                echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                exit;
            }
            
            $linkId = $_POST['link_id'] ?? '';
            $status = $_POST['status'] ?? '';
            $notes = $_POST['notes'] ?? '';
            
            if (empty($linkId) || empty($status)) {
                echo json_encode(['success' => false, 'message' => 'Missing required parameters']);
                exit;
            }
            
            $sql = "UPDATE device_recalls_link 
                    SET remediation_status = ?, remediation_notes = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE link_id = ?";
            
            $stmt = $db->prepare($sql);
            $result = $stmt->execute([$status, $notes, $linkId]);
            
            if ($result) {
                // Log action
                $auth->logUserAction($user['user_id'], 'UPDATE_REMEDIATION', 'device_recalls_link', $linkId, [
                    'status' => $status,
                    'notes' => $notes
                ]);
                
                echo json_encode(['success' => true, 'message' => 'Remediation status updated']);
            } else {
                echo json_encode(['success' => false, 'message' => 'Failed to update status']);
            }
            exit;
    }
}

// Get filter options
$sql = "SELECT DISTINCT recall_classification FROM recalls ORDER BY recall_classification";
$stmt = $db->query($sql);
$classifications = $stmt->fetchAll();

$sql = "SELECT DISTINCT recall_status FROM recalls ORDER BY recall_status";
$stmt = $db->query($sql);
$statuses = $stmt->fetchAll();

$sql = "SELECT DISTINCT manufacturer_name FROM recalls WHERE manufacturer_name IS NOT NULL ORDER BY manufacturer_name";
$stmt = $db->query($sql);
$manufacturers = $stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recall Management - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/assets.css">
    <link rel="stylesheet" href="/assets/css/recalls.css">
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
                    <h1><i class="fas fa-exclamation-triangle"></i> Recall Management</h1>
                    <p>Monitor and manage FDA recalls affecting your devices</p>
                </div>
                <div class="page-actions">
                    <a href="/pages/recalls/dashboard.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Back to Dashboard
                    </a>
                    <a href="/pages/recalls/remediation.php" class="btn btn-secondary">
                        <i class="fas fa-tools"></i>
                        Manage Remediation
                    </a>
                </div>
            </div>

            <!-- Filters -->
            <div class="filters-section">
                <div class="filters-header">
                    <h3><i class="fas fa-filter"></i> Filters</h3>
                    <button type="button" id="clearFilters" class="btn btn-outline">
                        <i class="fas fa-times"></i>
                        Clear
                    </button>
                </div>
                <div class="filters-grid">
                    <div class="filter-group">
                        <label for="search">Search</label>
                        <input type="text" id="search" placeholder="Search recalls, products, manufacturers...">
                    </div>
                    
                    <div class="filter-group">
                        <label for="status">Status</label>
                        <select id="status">
                            <option value="">All Statuses</option>
                            <?php foreach ($statuses as $status): ?>
                                <option value="<?php echo dave_htmlspecialchars($status['recall_status']); ?>">
                                    <?php echo dave_htmlspecialchars($status['recall_status']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="classification">Classification</label>
                        <select id="classification">
                            <option value="">All Classifications</option>
                            <?php foreach ($classifications as $classification): ?>
                                <option value="<?php echo dave_htmlspecialchars($classification['recall_classification']); ?>">
                                    <?php echo dave_htmlspecialchars($classification['recall_classification']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="manufacturer">Manufacturer</label>
                        <select id="manufacturer">
                            <option value="">All Manufacturers</option>
                            <?php foreach ($manufacturers as $manufacturer): ?>
                                <option value="<?php echo dave_htmlspecialchars($manufacturer['manufacturer_name']); ?>">
                                    <?php echo dave_htmlspecialchars($manufacturer['manufacturer_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="dateFrom">Date From</label>
                        <input type="date" id="dateFrom">
                    </div>
                    
                    <div class="filter-group">
                        <label for="dateTo">Date To</label>
                        <input type="date" id="dateTo">
                    </div>
                </div>
            </div>

            <!-- Recalls List -->
            <div class="content-section">
                <div class="section-header">
                    <h3><i class="fas fa-list"></i> Recalls</h3>
                    <div class="view-controls">
                        <button type="button" id="refreshRecalls" class="btn btn-outline">
                            <i class="fas fa-sync"></i>
                            Refresh
                        </button>
                    </div>
                </div>
                
                <div id="recallsList" class="recalls-list">
                    <!-- Recalls will be loaded here -->
                </div>
                
                <div id="pagination" class="pagination">
                    <!-- Pagination will be loaded here -->
                </div>
            </div>
        </main>
    </div>

    <!-- Recall Details Modal -->
    <div id="recallModal" class="modal">
        <div class="modal-content recall-modal-content">
            <div class="modal-header">
                <div class="modal-title-section">
                    <h3 id="modalTitle">Recall Details</h3>
                    <div class="modal-subtitle" id="modalSubtitle"></div>
                </div>
                <button type="button" class="modal-close" onclick="closeRecallModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body" id="modalBody">
                <!-- Modal content will be loaded here -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeRecallModal()">
                    <i class="fas fa-times"></i>
                    Close
                </button>
                <button type="button" class="btn btn-primary" onclick="openRemediationWorkflow()">
                    <i class="fas fa-tools"></i>
                    Manage Remediation
                </button>
            </div>
        </div>
    </div>

    <!-- Remediation Modal -->
    <div id="remediationModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Update Remediation Status</h3>
                <button type="button" class="modal-close">&times;</button>
            </div>
            <div class="modal-body">
                <form id="remediationForm">
                    <input type="hidden" id="linkId" name="link_id">
                    
                    <div class="form-group">
                        <label for="remediationStatus">Status</label>
                        <select id="remediationStatus" name="status" required>
                            <option value="Open">Open</option>
                            <option value="In Progress">In Progress</option>
                            <option value="Resolved">Resolved</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="remediationNotes">Notes</label>
                        <textarea id="remediationNotes" name="notes" rows="4" placeholder="Add remediation notes..."></textarea>
                    </div>
                    
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary modal-close">Cancel</button>
                        <button type="submit" class="btn btn-primary">Update Status</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        // Recall List JavaScript
        let currentPage = 1;
        let currentFilters = {};
        
        document.addEventListener('DOMContentLoaded', function() {
            setupEventListeners();
            loadRecalls();
        });
        
        function setupEventListeners() {
            // Filter controls
            const filterInputs = ['search', 'status', 'classification', 'manufacturer', 'dateFrom', 'dateTo'];
            filterInputs.forEach(id => {
                const element = document.getElementById(id);
                if (element) {
                    element.addEventListener('change', applyFilters);
                }
            });
            
            // Clear filters
            document.getElementById('clearFilters').addEventListener('click', clearFilters);
            
            // Refresh button
            document.getElementById('refreshRecalls').addEventListener('click', loadRecalls);
            
            // Modal close buttons
            document.querySelectorAll('.modal-close').forEach(btn => {
                btn.addEventListener('click', closeModals);
            });
            
            // Close modals when clicking outside
            document.querySelectorAll('.modal').forEach(modal => {
                modal.addEventListener('click', function(e) {
                    if (e.target === modal) {
                        closeModals();
                    }
                });
            });
            
            // Close modals with Escape key
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') {
                    closeModals();
                }
            });
            
            // Remediation form
            document.getElementById('remediationForm').addEventListener('submit', updateRemediation);
        }
        
        function loadRecalls(page = 1) {
            currentPage = page;
            
            const params = new URLSearchParams({
                ajax: 'get_recalls',
                page: page,
                limit: 25,
                ...currentFilters
            });
            
            fetch('?' + params.toString())
            .then(response => response.json())
            .then(data => {
                displayRecalls(data.recalls);
                displayPagination(data);
            })
            .catch(error => {
                console.error('Error loading recalls:', error);
                showNotification('Error loading recalls', 'error');
            });
        }
        
        function displayRecalls(recalls) {
            const container = document.getElementById('recallsList');
            
            if (recalls.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-exclamation-triangle"></i>
                        <p>No recalls found</p>
                    </div>
                `;
                return;
            }
            
            const html = recalls.map(recall => `
                <div class="recall-item">
                    <div class="recall-header">
                        <div class="recall-title-section">
                            <div class="recall-number">${recall.fda_recall_number}</div>
                            <div class="recall-date">${formatDate(recall.recall_date)}</div>
                            <div class="recall-metrics-grid">
                                <div class="metric-item">
                                    <i class="fas fa-server"></i>
                                    <strong>${recall.affected_devices}</strong> devices
                                </div>
                                <div class="metric-item">
                                    <i class="fas fa-exclamation-circle"></i>
                                    <strong>${recall.open_remediations}</strong> open
                                </div>
                                <div class="metric-item">
                                    <i class="fas fa-clock"></i>
                                    <strong>${recall.in_progress_remediations}</strong> in progress
                                </div>
                                <div class="metric-item">
                                    <i class="fas fa-check-circle"></i>
                                    <strong>${recall.resolved_remediations}</strong> resolved
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="recall-content">
                        <div class="recall-description">${recall.product_description}</div>
                        <div class="recall-reason">${recall.reason_for_recall}</div>
                        <div class="recall-meta">
                            <span class="manufacturer">${recall.manufacturer_name}</span>
                            <span class="classification-badge ${getClassificationClass(recall.recall_classification)}">
                                <i class="${getClassificationIcon(recall.recall_classification)}"></i>
                                ${recall.recall_classification}
                            </span>
                            <span class="status-badge ${recall.recall_status.toLowerCase()}">${recall.recall_status}</span>
                        </div>
                    </div>
                    
                    <div class="recall-actions">
                        <button type="button" class="btn btn-primary" onclick="viewRecallDetails('${recall.recall_id}')">
                            <i class="fas fa-eye"></i>
                            View Details
                        </button>
                    </div>
                </div>
            `).join('');
            
            container.innerHTML = html;
        }
        
        function displayPagination(data) {
            const container = document.getElementById('pagination');
            const totalPages = data.pages;
            
            if (totalPages <= 1) {
                container.innerHTML = '';
                return;
            }
            
            let html = '<div class="pagination-controls">';
            
            // Previous button
            if (data.page > 1) {
                html += `<button type="button" class="btn btn-outline" onclick="loadRecalls(${data.page - 1})">
                    <i class="fas fa-chevron-left"></i>
                    Previous
                </button>`;
            }
            
            // Page numbers
            const startPage = Math.max(1, data.page - 2);
            const endPage = Math.min(totalPages, data.page + 2);
            
            for (let i = startPage; i <= endPage; i++) {
                const activeClass = i === data.page ? 'active' : '';
                html += `<button type="button" class="btn btn-outline ${activeClass}" onclick="loadRecalls(${i})">${i}</button>`;
            }
            
            // Next button
            if (data.page < totalPages) {
                html += `<button type="button" class="btn btn-outline" onclick="loadRecalls(${data.page + 1})">
                    Next
                    <i class="fas fa-chevron-right"></i>
                </button>`;
            }
            
            html += '</div>';
            container.innerHTML = html;
        }
        
        function applyFilters() {
            currentFilters = {
                search: document.getElementById('search').value,
                status: document.getElementById('status').value,
                classification: document.getElementById('classification').value,
                manufacturer: document.getElementById('manufacturer').value,
                date_from: document.getElementById('dateFrom').value,
                date_to: document.getElementById('dateTo').value
            };
            
            loadRecalls(1);
        }
        
        function clearFilters() {
            document.getElementById('search').value = '';
            document.getElementById('status').value = '';
            document.getElementById('classification').value = '';
            document.getElementById('manufacturer').value = '';
            document.getElementById('dateFrom').value = '';
            document.getElementById('dateTo').value = '';
            
            currentFilters = {};
            loadRecalls(1);
        }
        
        function viewRecallDetails(recallId) {
            fetch(`?ajax=get_recall_details&recall_id=${recallId}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showNotification(data.error, 'error');
                    return;
                }
                
                displayRecallModal(data.recall, data.affected_devices);
            })
            .catch(error => {
                console.error('Error loading recall details:', error);
                showNotification('Error loading recall details', 'error');
            });
        }
        
        function displayRecallModal(recall, affectedDevices) {
            const modal = document.getElementById('recallModal');
            const title = document.getElementById('modalTitle');
            const subtitle = document.getElementById('modalSubtitle');
            const body = document.getElementById('modalBody');
            
            title.textContent = recall.fda_recall_number;
            subtitle.textContent = `${recall.manufacturer_name} • ${formatDate(recall.recall_date)}`;
            
            // Calculate remediation statistics
            const stats = {
                total: affectedDevices.length,
                open: affectedDevices.filter(d => d.remediation_status === 'Open').length,
                inProgress: affectedDevices.filter(d => d.remediation_status === 'In Progress').length,
                completed: affectedDevices.filter(d => d.remediation_status === 'Completed').length,
                closed: affectedDevices.filter(d => d.remediation_status === 'Closed').length
            };
            
            const devicesHtml = affectedDevices.map(device => `
                <div class="device-item">
                    <div class="device-info">
                        <div class="device-name">${device.hostname || device.brand_name || 'Unknown Device'}</div>
                        <div class="device-details">
                            <span class="device-brand">${device.brand_name || 'Unknown Brand'}</span>
                            ${device.model_number ? `<span class="device-model">${device.model_number}</span>` : ''}
                            ${device.device_identifier ? `<span class="device-serial">SN: ${device.device_identifier}</span>` : ''}
                        </div>
                    </div>
                    <div class="device-status">
                        <span class="status-badge ${device.remediation_status.toLowerCase().replace(' ', '-')}">${device.remediation_status}</span>
                        <button type="button" class="btn btn-sm btn-outline" onclick="openRemediationModal('${device.link_id}', '${device.remediation_status}', '${device.remediation_notes || ''}')">
                            <i class="fas fa-edit"></i>
                            Update
                        </button>
                    </div>
                </div>
            `).join('');
            
            body.innerHTML = `
                <div class="recall-details">
                    <!-- Recall Overview -->
                    <div class="recall-overview">
                        <div class="overview-stats">
                            <div class="stat-item">
                                <div class="stat-value">${stats.total}</div>
                                <div class="stat-label">Total Devices</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">${stats.open}</div>
                                <div class="stat-label">Open</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">${stats.inProgress}</div>
                                <div class="stat-label">In Progress</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">${stats.completed}</div>
                                <div class="stat-label">Completed</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Recall Information -->
                    <div class="detail-section">
                        <h4><i class="fas fa-info-circle"></i> Recall Information</h4>
                        <div class="detail-grid">
                            <div class="detail-item">
                                <label>FDA Recall Number:</label>
                                <span class="detail-value">${recall.fda_recall_number}</span>
                            </div>
                            <div class="detail-item">
                                <label>Recall Date:</label>
                                <span class="detail-value">${formatDate(recall.recall_date)}</span>
                            </div>
                            <div class="detail-item">
                                <label>Manufacturer:</label>
                                <span class="detail-value">${recall.manufacturer_name}</span>
                            </div>
                            <div class="detail-item">
                                <label>Classification:</label>
                                <span class="classification-badge ${getClassificationClass(recall.recall_classification)}">
                                    <i class="${getClassificationIcon(recall.recall_classification)}"></i>
                                    ${recall.recall_classification}
                                </span>
                            </div>
                            <div class="detail-item">
                                <label>Status:</label>
                                <span class="status-badge ${recall.recall_status.toLowerCase()}">${recall.recall_status}</span>
                            </div>
                        </div>
                        
                        <!-- Product Code - Full Width -->
                        <div class="detail-item-full">
                            <label>Product Code:</label>
                            <div class="detail-content">
                                <p>${recall.product_code || 'No product code available'}</p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Product Description -->
                    <div class="detail-section">
                        <h4><i class="fas fa-box"></i> Product Description</h4>
                        <div class="detail-content">
                            <p>${recall.product_description || 'No description available'}</p>
                        </div>
                    </div>
                    
                    <!-- Reason for Recall -->
                    <div class="detail-section">
                        <h4><i class="fas fa-exclamation-triangle"></i> Reason for Recall</h4>
                        <div class="detail-content">
                            <p>${recall.reason_for_recall || 'No reason provided'}</p>
                        </div>
                    </div>
                    
                    <!-- Affected Devices -->
                    <div class="detail-section">
                        <h4><i class="fas fa-server"></i> Affected Devices (${affectedDevices.length})</h4>
                        <div class="devices-list">
                            ${devicesHtml}
                        </div>
                    </div>
                </div>
            `;
            
            modal.style.display = 'flex';
            // Trigger animation
            setTimeout(() => {
                modal.classList.add('show');
            }, 10);
        }
        
        function closeRecallModal() {
            const modal = document.getElementById('recallModal');
            modal.classList.remove('show');
            setTimeout(() => {
                modal.style.display = 'none';
            }, 300);
        }
        
        function openRemediationWorkflow() {
            closeRecallModal();
            // Navigate to remediation page
            window.location.href = '/pages/recalls/remediation.php';
        }
        
        function openRemediationModal(linkId, currentStatus, currentNotes) {
            document.getElementById('linkId').value = linkId;
            document.getElementById('remediationStatus').value = currentStatus;
            document.getElementById('remediationNotes').value = currentNotes;
            
            const modal = document.getElementById('remediationModal');
            modal.style.display = 'flex';
            // Trigger animation
            setTimeout(() => {
                modal.classList.add('show');
            }, 10);
        }
        
        function updateRemediation(e) {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            
            fetch('?ajax=update_remediation', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(data.message, 'success');
                    closeModals();
                    loadRecalls(currentPage);
                } else {
                    showNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error updating remediation:', error);
                showNotification('Error updating remediation status', 'error');
            });
        }
        
        function closeModals() {
            document.querySelectorAll('.modal').forEach(modal => {
                modal.classList.remove('show');
                setTimeout(() => {
                    modal.style.display = 'none';
                }, 300);
            });
        }
        
        function formatDate(dateString) {
            const date = new Date(dateString);
            return date.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
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
        
        // Classification helper functions
        function getClassificationClass(classification) {
            switch(classification.toLowerCase()) {
                case 'class i':
                    return 'class-i';
                case 'class ii':
                    return 'class-ii';
                case 'class iii':
                    return 'class-iii';
                default:
                    return 'class-unknown';
            }
        }
        
        function getClassificationIcon(classification) {
            switch(classification.toLowerCase()) {
                case 'class i':
                    return 'fas fa-exclamation-triangle';
                case 'class ii':
                    return 'fas fa-exclamation-circle';
                case 'class iii':
                    return 'fas fa-info-circle';
                default:
                    return 'fas fa-question-circle';
            }
        }
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
