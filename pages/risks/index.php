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
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}

// Check permissions
if (!$auth->hasPermission('risks.view')) {
    header('Location: /pages/dashboard.php');
    exit;
}

$db = DatabaseConfig::getInstance();

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['ajax']) {
        case 'get_risks':
            try {
                $page = (int)($_GET['page'] ?? 1);
                $limit = (int)($_GET['limit'] ?? 25);
                $offset = ($page - 1) * $limit;
                
                $search = $_GET['search'] ?? '';
                $risk_score_level = $_GET['risk_score_level'] ?? '';
                $device_class = $_GET['device_class'] ?? '';
                $status = $_GET['status'] ?? '';
                $site = $_GET['site'] ?? '';
                
                // Build query
                $whereConditions = [];
                $params = [];
                
                if (!empty($search)) {
                    $whereConditions[] = "(r.risk_id ILIKE ? OR r.name ILIKE ? OR r.description ILIKE ?)";
                    $params[] = "%$search%";
                    $params[] = "%$search%";
                    $params[] = "%$search%";
                }
                
                if (!empty($risk_score_level)) {
                    $whereConditions[] = "r.risk_score_level = ?";
                    $params[] = $risk_score_level;
                }
                
                if (!empty($device_class)) {
                    $whereConditions[] = "r.device_class = ?";
                    $params[] = $device_class;
                }
                
                if (!empty($status)) {
                    $whereConditions[] = "r.status_display_name = ?";
                    $params[] = $status;
                }
                
                if (!empty($site)) {
                    $whereConditions[] = "r.site = ?";
                    $params[] = $site;
                }
                
                $whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';
                
                // Get total count
                $countSql = "SELECT COUNT(*) as total FROM risks r $whereClause";
                $countStmt = $db->prepare($countSql);
                $countStmt->execute($params);
                $total = $countStmt->fetch()['total'];
                
                // Get risks
                $sql = "SELECT 
                            r.id,
                            r.asset_id,
                            r.device_class,
                            r.type,
                            r.type_display_name,
                            r.display_name,
                            r.risk_id,
                            r.risk_type_display_name,
                            r.risk_group,
                            r.name,
                            r.risk_score,
                            r.risk_score_level,
                            r.cvss,
                            r.epss,
                            r.availability_score,
                            r.confidentiality_score,
                            r.integrity_score,
                            r.impact_confidentiality,
                            r.impact_patient_safety,
                            r.impact_service_disruption,
                            r.nhs_published_date,
                            r.nhs_severity,
                            r.nhs_threat_id,
                            r.description,
                            r.status_display_name,
                            r.category,
                            r.has_malware,
                            r.tags_easy_to_weaponize,
                            r.tags_exploit_code_maturity,
                            r.tags_exploited_in_the_wild,
                            r.tags_lateral_movement,
                            r.tags_malware,
                            r.site,
                            r.link,
                            r.external_id,
                            r.created_at,
                            r.updated_at
                        FROM risks r
                        $whereClause
                        ORDER BY r.risk_score DESC NULLS LAST, r.created_at DESC
                        LIMIT ? OFFSET ?";
                
                $params[] = $limit;
                $params[] = $offset;
                
                $stmt = $db->prepare($sql);
                $stmt->execute($params);
                $risks = $stmt->fetchAll();
                
                // Parse JSON fields
                foreach ($risks as &$risk) {
                    if (!empty($risk['tags_malware'])) {
                        $risk['tags_malware'] = json_decode($risk['tags_malware'], true);
                    }
                    if (!empty($risk['link'])) {
                        $risk['link'] = json_decode($risk['link'], true);
                    }
                }
                
                echo json_encode([
                    'success' => true,
                    'data' => $risks,
                    'pagination' => [
                        'page' => $page,
                        'limit' => $limit,
                        'total' => $total,
                        'pages' => ceil($total / $limit)
                    ]
                ]);
                
            } catch (Exception $e) {
                echo json_encode([
                    'success' => false,
                    'error' => $e->getMessage()
                ]);
            }
            exit;
    }
}

// Get risk statistics
try {
    $riskStatsSql = "SELECT 
                        COUNT(*) as total_risks,
                        COUNT(CASE WHEN risk_score_level = 'Critical' THEN 1 END) as critical_count,
                        COUNT(CASE WHEN risk_score_level = 'High' THEN 1 END) as high_count,
                        COUNT(CASE WHEN risk_score_level = 'Medium' THEN 1 END) as medium_count,
                        COUNT(CASE WHEN risk_score_level = 'Low' THEN 1 END) as low_count,
                        COUNT(CASE WHEN tags_exploited_in_the_wild = true THEN 1 END) as exploited_count,
                        COUNT(CASE WHEN has_malware = true THEN 1 END) as malware_count,
                        COUNT(DISTINCT asset_id) as affected_assets
                     FROM risks";
    
    $riskStatsStmt = $db->query($riskStatsSql);
    $stats = $riskStatsStmt->fetch();
    
} catch (Exception $e) {
    $stats = [
        'total_risks' => 0,
        'critical_count' => 0,
        'high_count' => 0,
        'medium_count' => 0,
        'low_count' => 0,
        'exploited_count' => 0,
        'malware_count' => 0,
        'affected_assets' => 0
    ];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>Risk Management - CSMS</title>
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/vulnerabilities.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-shield-alt"></i> Risk Management</h1>
                    <p>Monitor and track security risks across your medical device inventory</p>
                </div>
            </div>

            <!-- Risk Metrics -->
            <div class="metrics-section">
                <div class="metrics-header">
                    <h2><i class="fas fa-chart-bar"></i> Risk Metrics</h2>
                    <div class="metrics-summary">
                        <span class="summary-item">
                            <strong><?php echo number_format($stats['total_risks']); ?></strong> Total Risks
                        </span>
                        <span class="summary-item">
                            <strong><?php echo number_format($stats['affected_assets']); ?></strong> Affected Assets
                        </span>
                        <span class="summary-item">
                            <strong><?php echo number_format($stats['exploited_count']); ?></strong> Exploited in Wild
                        </span>
                    </div>
                </div>
                
                <div class="metrics-grid">
                    <div class="metric-card critical">
                        <div class="metric-icon">
                            <i class="fas fa-fire"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value"><?php echo number_format($stats['critical_count']); ?></div>
                            <div class="metric-label">Critical</div>
                            <div class="metric-description">Immediate attention required</div>
                        </div>
                    </div>
                    
                    <div class="metric-card high">
                        <div class="metric-icon">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value"><?php echo number_format($stats['high_count']); ?></div>
                            <div class="metric-label">High</div>
                            <div class="metric-description">Priority remediation</div>
                        </div>
                    </div>
                    
                    <div class="metric-card medium">
                        <div class="metric-icon">
                            <i class="fas fa-exclamation-circle"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value"><?php echo number_format($stats['medium_count']); ?></div>
                            <div class="metric-label">Medium</div>
                            <div class="metric-description">Schedule remediation</div>
                        </div>
                    </div>
                    
                    <div class="metric-card low">
                        <div class="metric-icon">
                            <i class="fas fa-info-circle"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value"><?php echo number_format($stats['low_count']); ?></div>
                            <div class="metric-label">Low</div>
                            <div class="metric-description">Monitor and assess</div>
                        </div>
                    </div>
                    
                    <div class="metric-card high">
                        <div class="metric-icon">
                            <i class="fas fa-bug"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value"><?php echo number_format($stats['malware_count']); ?></div>
                            <div class="metric-label">Malware</div>
                            <div class="metric-description">Risks with malware</div>
                        </div>
                    </div>
                    
                    <div class="metric-card total">
                        <div class="metric-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div class="metric-content">
                            <div class="metric-value"><?php echo number_format($stats['total_risks']); ?></div>
                            <div class="metric-label">Total</div>
                            <div class="metric-description">All risks</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Filters and Search -->
            <div class="filters-section">
                <!-- Search Bar -->
                <div class="search-bar-container">
                    <div class="search-input-wrapper">
                        <i class="fas fa-search search-icon"></i>
                        <input 
                            type="text" 
                            id="searchInput" 
                            class="search-input" 
                            placeholder="Search risks by ID, name or description..."
                            autocomplete="off"
                        >
                        <button type="button" id="clearSearch" class="clear-search-btn" style="display: none;">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                </div>
                
                <!-- Filters Grid -->
                <div class="filters-grid">
                    <div class="filter-group">
                        <label for="riskScoreFilter">
                            <i class="fas fa-exclamation-triangle"></i> Risk Level
                        </label>
                        <select id="riskScoreFilter" class="filter-select">
                            <option value="">All Risk Levels</option>
                            <option value="Critical">Critical</option>
                            <option value="High">High</option>
                            <option value="Medium">Medium</option>
                            <option value="Low">Low</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="deviceClassFilter">
                            <i class="fas fa-laptop-medical"></i> Device Class
                        </label>
                        <select id="deviceClassFilter" class="filter-select">
                            <option value="">All Device Classes</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="statusFilter">
                            <i class="fas fa-signal"></i> Status
                        </label>
                        <select id="statusFilter" class="filter-select">
                            <option value="">All Statuses</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label>&nbsp;</label>
                        <button type="button" id="clearFilters" class="btn btn-secondary">
                            <i class="fas fa-times"></i> Clear All
                        </button>
                    </div>
                </div>
            </div>

            <!-- Risks DataTable -->
            <div class="datatable-container">
                <div class="datatable-header">
                    <div class="datatable-title">
                        <h3><i class="fas fa-table"></i> Risks Database</h3>
                        <p>Complete list of identified risks with search and filtering capabilities</p>
                    </div>
                    <div class="datatable-actions">
                        <div class="table-controls">
                            <label for="pageSize">Show:</label>
                            <select id="pageSize" class="page-size-select">
                                <option value="25">25</option>
                                <option value="50">50</option>
                                <option value="100">100</option>
                            </select>
                            <span class="results-info">
                                <span id="resultsCount">Loading...</span>
                            </span>
                        </div>
                    </div>
                </div>
                
                <div class="datatable-wrapper">
                    <table class="data-table" id="risksTable">
                        <thead>
                            <tr>
                                <th>Risk ID</th>
                                <th>Name</th>
                                <th>Asset ID</th>
                                <th>Risk Score</th>
                                <th>Risk Level</th>
                                <th>CVSS</th>
                                <th>EPSS</th>
                                <th>Device Class</th>
                                <th>Status</th>
                                <th>Exploited</th>
                            </tr>
                        </thead>
                        <tbody id="risksTableBody">
                            <tr>
                                <td colspan="10" class="loading-cell">
                                    <div class="loading-content">
                                        <i class="fas fa-spinner fa-spin"></i>
                                        <span>Loading risks...</span>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <!-- Pagination and Table Info -->
                <div class="datatable-footer">
                    <div class="table-info">
                        <span id="tableInfo">Loading...</span>
                    </div>
                    <div class="pagination-container" id="paginationContainer">
                        <!-- Pagination will be populated by JavaScript -->
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script src="/assets/js/dashboard-common.js?v=<?php echo time(); ?>"></script>
    <script>
        // Utility Functions
        function debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }

        function showNotification(message, type = 'info') {
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <div class="notification-content">
                    <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                    <span>${message}</span>
                </div>
                <button class="notification-close" onclick="this.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            `;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.remove();
                }
            }, 5000);
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function truncateText(text, maxLength) {
            if (!text) return '';
            if (text.length <= maxLength) return escapeHtml(text);
            return escapeHtml(text.substring(0, maxLength)) + '...';
        }

        function getRiskScoreClass(score) {
            if (score === null || score === undefined) return '';
            const numScore = parseFloat(score);
            if (numScore >= 9.0) return 'critical';
            if (numScore >= 7.0) return 'high';
            if (numScore >= 4.0) return 'medium';
            return 'low';
        }

        let currentPage = 1;
        let currentPageSize = 25;
        let currentFilters = {
            search: '',
            risk_score_level: '',
            device_class: '',
            status: '',
            site: ''
        };

        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {
            loadRisks();
            setupEventListeners();
            populateFilterOptions();
        });

        function setupEventListeners() {
            // Search input
            document.getElementById('searchInput').addEventListener('input', debounce(function() {
                currentFilters.search = this.value;
                currentPage = 1;
                loadRisks();
                
                // Show/hide clear button
                document.getElementById('clearSearch').style.display = this.value ? 'block' : 'none';
            }, 500));

            // Clear search
            document.getElementById('clearSearch').addEventListener('click', function() {
                document.getElementById('searchInput').value = '';
                currentFilters.search = '';
                this.style.display = 'none';
                currentPage = 1;
                loadRisks();
            });

            // Filter selects
            document.getElementById('riskScoreFilter').addEventListener('change', function() {
                currentFilters.risk_score_level = this.value;
                currentPage = 1;
                loadRisks();
            });

            document.getElementById('deviceClassFilter').addEventListener('change', function() {
                currentFilters.device_class = this.value;
                currentPage = 1;
                loadRisks();
            });

            document.getElementById('statusFilter').addEventListener('change', function() {
                currentFilters.status = this.value;
                currentPage = 1;
                loadRisks();
            });

            // Page size selector
            document.getElementById('pageSize').addEventListener('change', function() {
                currentPageSize = parseInt(this.value);
                currentPage = 1;
                loadRisks();
            });

            // Clear filters
            document.getElementById('clearFilters').addEventListener('click', function() {
                document.getElementById('searchInput').value = '';
                document.getElementById('riskScoreFilter').value = '';
                document.getElementById('deviceClassFilter').value = '';
                document.getElementById('statusFilter').value = '';
                document.getElementById('clearSearch').style.display = 'none';
                currentFilters = { search: '', risk_score_level: '', device_class: '', status: '', site: '' };
                currentPage = 1;
                loadRisks();
            });
        }

        function populateFilterOptions() {
            // Populate device class filter
            fetch('/api/v1/risks?limit=1000')
                .then(response => response.json())
                .then(data => {
                    if (data.success && data.data) {
                        const deviceClasses = new Set();
                        const statuses = new Set();
                        
                        data.data.forEach(risk => {
                            if (risk.device_class) deviceClasses.add(risk.device_class);
                            if (risk.status_display_name) statuses.add(risk.status_display_name);
                        });
                        
                        const deviceClassFilter = document.getElementById('deviceClassFilter');
                        Array.from(deviceClasses).sort().forEach(deviceClass => {
                            const option = document.createElement('option');
                            option.value = deviceClass;
                            option.textContent = deviceClass;
                            deviceClassFilter.appendChild(option);
                        });
                        
                        const statusFilter = document.getElementById('statusFilter');
                        Array.from(statuses).sort().forEach(status => {
                            const option = document.createElement('option');
                            option.value = status;
                            option.textContent = status;
                            statusFilter.appendChild(option);
                        });
                    }
                })
                .catch(error => console.error('Error loading filter options:', error));
        }

        function loadRisks() {
            const params = new URLSearchParams({
                ajax: 'get_risks',
                page: currentPage,
                limit: currentPageSize,
                ...currentFilters,
                _t: Date.now()
            });

            fetch(`?${params}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        displayRisks(data.data);
                        updatePagination(data.pagination);
                        updateResultsCount(data.pagination.total);
                        updateTableInfo(data.pagination);
                    } else {
                        showNotification('Error loading risks: ' + data.error, 'error');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showNotification('Error loading risks', 'error');
                });
        }

        function displayRisks(risks) {
            const tbody = document.getElementById('risksTableBody');
            
            if (risks.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="10" class="empty-cell">
                            <i class="fas fa-search"></i>
                            <p>No risks found</p>
                            <small>Try adjusting your search criteria</small>
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = risks.map(risk => `
                <tr>
                    <td>
                        <span class="risk-id" title="${escapeHtml(risk.risk_id)}">
                            ${truncateText(risk.risk_id, 30)}
                        </span>
                    </td>
                    <td>
                        <div class="risk-name" title="${escapeHtml(risk.name || risk.display_name || '')}">
                            ${truncateText(risk.name || risk.display_name || 'N/A', 50)}
                        </div>
                    </td>
                    <td>
                        <span class="asset-id">${escapeHtml(risk.asset_id || 'N/A')}</span>
                    </td>
                    <td>
                        <span class="risk-score-value ${getRiskScoreClass(risk.risk_score)}">
                            ${risk.risk_score !== null && risk.risk_score !== undefined ? parseFloat(risk.risk_score).toFixed(1) : 'N/A'}
                        </span>
                    </td>
                    <td>
                        <span class="severity-badge ${(risk.risk_score_level || '').toLowerCase()}">
                            ${risk.risk_score_level || 'Unknown'}
                        </span>
                    </td>
                    <td>
                        ${risk.cvss !== null && risk.cvss !== undefined ? 
                            `<span class="cvss-score ${getRiskScoreClass(risk.cvss)}">${parseFloat(risk.cvss).toFixed(1)}</span>` : 
                            '<span class="text-muted">N/A</span>'
                        }
                    </td>
                    <td>
                        ${risk.epss !== null && risk.epss !== undefined ? 
                            `<span class="epss-score">${(parseFloat(risk.epss) * 100).toFixed(1)}%</span>` : 
                            '<span class="text-muted">N/A</span>'
                        }
                    </td>
                    <td>
                        <span class="device-class">${escapeHtml(risk.device_class || 'N/A')}</span>
                    </td>
                    <td>
                        <span class="status-badge">${escapeHtml(risk.status_display_name || 'Unknown')}</span>
                    </td>
                    <td class="text-center">
                        ${risk.tags_exploited_in_the_wild ? 
                            '<span class="exploited-badge" title="Exploited in the Wild"><i class="fas fa-exclamation-triangle"></i></span>' : 
                            '<span class="text-muted">—</span>'
                        }
                    </td>
                </tr>
            `).join('');
        }

        function updatePagination(pagination) {
            const container = document.getElementById('paginationContainer');
            const totalPages = pagination.pages;
            const currentPage = pagination.page;
            
            if (totalPages <= 1) {
                container.innerHTML = '';
                return;
            }

            let html = '<div class="pagination">';
            
            // Previous button
            if (currentPage > 1) {
                html += `<button class="page-btn" onclick="goToPage(${currentPage - 1})">
                    <i class="fas fa-chevron-left"></i>
                </button>`;
            }
            
            // Page numbers
            const maxVisiblePages = 7;
            let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
            let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
            
            if (endPage - startPage < maxVisiblePages - 1) {
                startPage = Math.max(1, endPage - maxVisiblePages + 1);
            }
            
            if (startPage > 1) {
                html += `<button class="page-btn" onclick="goToPage(1)">1</button>`;
                if (startPage > 2) {
                    html += '<span class="page-ellipsis">...</span>';
                }
            }
            
            for (let i = startPage; i <= endPage; i++) {
                html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" onclick="goToPage(${i})">${i}</button>`;
            }
            
            if (endPage < totalPages) {
                if (endPage < totalPages - 1) {
                    html += '<span class="page-ellipsis">...</span>';
                }
                html += `<button class="page-btn" onclick="goToPage(${totalPages})">${totalPages}</button>`;
            }
            
            // Next button
            if (currentPage < totalPages) {
                html += `<button class="page-btn" onclick="goToPage(${currentPage + 1})">
                    <i class="fas fa-chevron-right"></i>
                </button>`;
            }
            
            html += '</div>';
            container.innerHTML = html;
        }

        function goToPage(page) {
            currentPage = page;
            loadRisks();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function updateResultsCount(total) {
            document.getElementById('resultsCount').textContent = `${total.toLocaleString()} result${total !== 1 ? 's' : ''}`;
        }

        function updateTableInfo(pagination) {
            const start = (pagination.page - 1) * pagination.limit + 1;
            const end = Math.min(pagination.page * pagination.limit, pagination.total);
            document.getElementById('tableInfo').textContent = 
                `Showing ${start.toLocaleString()} to ${end.toLocaleString()} of ${pagination.total.toLocaleString()} risks`;
        }
    </script>
</body>
</html>
