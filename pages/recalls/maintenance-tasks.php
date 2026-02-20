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
        case 'get_tasks':
            getMaintenanceTasks();
            break;
        case 'get_statistics':
            getMaintenanceStatistics();
            break;
        case 'update_status':
            updateTaskStatus();
            break;
        default:
            echo json_encode([
                'success' => false,
                'error' => ['message' => 'Invalid AJAX request']
            ]);
    }
    exit;
}

function getMaintenanceTasks() {
    global $db;
    
    $filters = [
        'status' => $_GET['status'] ?? null,
        'priority' => $_GET['priority'] ?? null,
        'assigned_to' => $_GET['assigned_to'] ?? null,
        'recall_id' => $_GET['recall_id'] ?? null,
        'limit' => intval($_GET['limit'] ?? 25),
        'offset' => intval($_GET['offset'] ?? 0)
    ];
    
    $whereConditions = ["st.task_type = 'recall_maintenance'"];
    $params = [];
    
    if ($filters['status']) {
        $whereConditions[] = "st.status = :status";
        $params['status'] = $filters['status'];
    }
    
    if ($filters['priority']) {
        $whereConditions[] = "st.recall_priority = :priority";
        $params['priority'] = $filters['priority'];
    }
    
    if ($filters['assigned_to']) {
        $whereConditions[] = "st.assigned_to = :assigned_to";
        $params['assigned_to'] = $filters['assigned_to'];
    }
    
    if ($filters['recall_id']) {
        $whereConditions[] = "st.recall_id = :recall_id";
        $params['recall_id'] = $filters['recall_id'];
    }
    
    $whereClause = implode(' AND ', $whereConditions);
    
    $sql = "SELECT * FROM scheduled_recall_tasks_view 
            WHERE $whereClause
            ORDER BY urgency_score DESC, st.scheduled_date ASC
            LIMIT :limit OFFSET :offset";
    
    $stmt = $db->prepare($sql);
    foreach ($params as $key => $value) {
        $stmt->bindValue(":$key", $value);
    }
    $stmt->bindValue(':limit', $filters['limit'], PDO::PARAM_INT);
    $stmt->bindValue(':offset', $filters['offset'], PDO::PARAM_INT);
    $stmt->execute();
    $tasks = $stmt->fetchAll();
    
    // Get total count
    $countSql = "SELECT COUNT(*) FROM scheduled_recall_tasks_view WHERE $whereClause";
    $countStmt = $db->prepare($countSql);
    foreach ($params as $key => $value) {
        $countStmt->bindValue(":$key", $value);
    }
    $countStmt->execute();
    $totalCount = $countStmt->fetchColumn();
    
    echo json_encode([
        'success' => true,
        'data' => $tasks,
        'pagination' => [
            'total' => $totalCount,
            'limit' => $filters['limit'],
            'offset' => $filters['offset'],
            'has_more' => ($filters['offset'] + $filters['limit']) < $totalCount
        ]
    ]);
}

function getMaintenanceStatistics() {
    global $db;
    
    $sql = "SELECT * FROM get_recall_maintenance_stats()";
    $stmt = $db->query($sql);
    $stats = $stmt->fetch();
    
    echo json_encode([
        'success' => true,
        'data' => $stats
    ]);
}

function updateTaskStatus() {
    global $db, $user;
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input || empty($input['task_id']) || empty($input['status'])) {
        echo json_encode([
            'success' => false,
            'error' => ['message' => 'Task ID and status are required']
        ]);
        return;
    }
    
    $validStatuses = ['Scheduled', 'In Progress', 'Completed', 'Cancelled', 'Failed'];
    if (!in_array($input['status'], $validStatuses)) {
        echo json_encode([
            'success' => false,
            'error' => ['message' => 'Invalid status']
        ]);
        return;
    }
    
    $sql = "UPDATE scheduled_tasks SET 
            status = :status,
            updated_at = CURRENT_TIMESTAMP,
            completed_at = CASE WHEN :status = 'Completed' THEN CURRENT_TIMESTAMP ELSE completed_at END,
            completed_by = CASE WHEN :status = 'Completed' THEN :completed_by ELSE completed_by END
            WHERE task_id = :task_id AND task_type = 'recall_maintenance'";
    
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':status', $input['status']);
    $stmt->bindValue(':task_id', $input['task_id']);
    if ($input['status'] === 'Completed') {
        $stmt->bindValue(':completed_by', $user['user_id']);
    }
    $stmt->execute();
    
    if ($stmt->rowCount() === 0) {
        echo json_encode([
            'success' => false,
            'error' => ['message' => 'Task not found']
        ]);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Task status updated successfully'
    ]);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recall Maintenance Tasks - </title>
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/recalls.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .maintenance-tasks-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--siemens-petrol, #009999);
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: var(--text-secondary, #cbd5e1);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .filters-section {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .filters-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        
        .filter-group label {
            color: var(--text-primary, #f8fafc);
            font-weight: 500;
            font-size: 0.9rem;
        }
        
        .filter-group select,
        .filter-group input {
            padding: 0.75rem;
            border: 1px solid var(--border-secondary, #555555);
            border-radius: 6px;
            background: var(--bg-secondary, #1a1a1a);
            color: var(--text-primary, #f8fafc);
            font-size: 0.9rem;
        }
        
        .filter-actions {
            display: flex;
            gap: 1rem;
            justify-content: flex-end;
        }
        
        .tasks-table {
            background: var(--bg-card, #1a1a1a);
            border: 1px solid var(--border-primary, #333333);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .table-header {
            background: var(--bg-secondary, #1a1a1a);
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-primary, #333333);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .table-title {
            color: var(--text-primary, #f8fafc);
            font-size: 1.25rem;
            font-weight: 600;
            margin: 0;
        }
        
        .table-actions {
            display: flex;
            gap: 0.75rem;
        }
        
        .table-content {
            overflow-x: auto;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th,
        .table td {
            padding: 1rem 1.5rem;
            text-align: left;
            border-bottom: 1px solid var(--border-primary, #333333);
        }
        
        .table th {
            background: var(--bg-secondary, #1a1a1a);
            color: var(--text-primary, #f8fafc);
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .table td {
            color: var(--text-secondary, #cbd5e1);
            font-size: 0.9rem;
        }
        
        .table tbody tr:hover {
            background: var(--bg-hover, #333333);
        }
        
        .priority-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .priority-critical {
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
        }
        
        .priority-high {
            background: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
        }
        
        .priority-medium {
            background: rgba(59, 130, 246, 0.2);
            color: #93c5fd;
        }
        
        .priority-low {
            background: rgba(34, 197, 94, 0.2);
            color: #4ade80;
        }
        
        .status-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status-scheduled {
            background: rgba(59, 130, 246, 0.2);
            color: #93c5fd;
        }
        
        .status-in-progress {
            background: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
        }
        
        .status-completed {
            background: rgba(34, 197, 94, 0.2);
            color: #4ade80;
        }
        
        .status-cancelled {
            background: rgba(107, 114, 128, 0.2);
            color: #9ca3af;
        }
        
        .status-failed {
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
        }
        
        .task-actions {
            display: flex;
            gap: 0.5rem;
        }
        
        .btn-sm {
            padding: 0.5rem 0.75rem;
            font-size: 0.8rem;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 0.5rem;
            padding: 1.5rem;
            background: var(--bg-secondary, #1a1a1a);
            border-top: 1px solid var(--border-primary, #333333);
        }
        
        .pagination button {
            padding: 0.5rem 0.75rem;
            border: 1px solid var(--border-secondary, #555555);
            background: var(--bg-card, #1a1a1a);
            color: var(--text-primary, #f8fafc);
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .pagination button:hover:not(:disabled) {
            background: var(--siemens-petrol, #009999);
            border-color: var(--siemens-petrol, #009999);
        }
        
        .pagination button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .pagination .current-page {
            background: var(--siemens-petrol, #009999);
            border-color: var(--siemens-petrol, #009999);
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-calendar-check"></i> Recall Maintenance Tasks</h1>
                    <p>Manage scheduled maintenance tasks for FDA recalls</p>
                </div>
                <div class="page-actions">
                    <a href="/pages/recalls/list.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Back to Recalls
                    </a>
                </div>
            </div>

            <!-- Statistics -->
            <div class="stats-grid" id="statistics">
                <!-- Statistics will be loaded here -->
            </div>

            <!-- Filters -->
            <div class="filters-section">
                <div class="filters-grid">
                    <div class="filter-group">
                        <label for="status-filter">Status</label>
                        <select id="status-filter">
                            <option value="">All Statuses</option>
                            <option value="Scheduled">Scheduled</option>
                            <option value="In Progress">In Progress</option>
                            <option value="Completed">Completed</option>
                            <option value="Cancelled">Cancelled</option>
                            <option value="Failed">Failed</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label for="priority-filter">Priority</label>
                        <select id="priority-filter">
                            <option value="">All Priorities</option>
                            <option value="Critical">Critical</option>
                            <option value="High">High</option>
                            <option value="Medium">Medium</option>
                            <option value="Low">Low</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label for="assigned-filter">Assigned To</label>
                        <select id="assigned-filter">
                            <option value="">All Users</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label for="search-filter">Search</label>
                        <input type="text" id="search-filter" placeholder="Search tasks...">
                    </div>
                </div>
                <div class="filter-actions">
                    <button type="button" class="btn btn-primary" onclick="applyFilters()">
                        <i class="fas fa-filter"></i>
                        Apply Filters
                    </button>
                    <button type="button" class="btn btn-secondary" onclick="clearFilters()">
                        <i class="fas fa-times"></i>
                        Clear
                    </button>
                </div>
            </div>

            <!-- Tasks Table -->
            <div class="tasks-table">
                <div class="table-header">
                    <h3 class="table-title">Maintenance Tasks</h3>
                    <div class="table-actions">
                        <button type="button" class="btn btn-outline" onclick="refreshTasks()">
                            <i class="fas fa-sync"></i>
                            Refresh
                        </button>
                    </div>
                </div>
                <div class="table-content">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Task ID</th>
                                <th>Recall</th>
                                <th>Device</th>
                                <th>Priority</th>
                                <th>Status</th>
                                <th>Assigned To</th>
                                <th>Scheduled Date</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="tasks-tbody">
                            <!-- Tasks will be loaded here -->
                        </tbody>
                    </table>
                </div>
                <div class="pagination" id="pagination">
                    <!-- Pagination will be loaded here -->
                </div>
            </div>
        </main>
    </div>

    <script>
        let currentPage = 1;
        let currentFilters = {};
        let tasks = [];

        // Load initial data
        document.addEventListener('DOMContentLoaded', function() {
            loadStatistics();
            loadUsers();
            loadTasks();
        });

        async function loadStatistics() {
            try {
                const response = await fetch('?ajax=get_statistics');
                const result = await response.json();
                
                if (result.success) {
                    displayStatistics(result.data);
                }
            } catch (error) {
                console.error('Error loading statistics:', error);
            }
        }

        function displayStatistics(stats) {
            const container = document.getElementById('statistics');
            container.innerHTML = `
                <div class="stat-card">
                    <div class="stat-value">${stats.total_tasks || 0}</div>
                    <div class="stat-label">Total Tasks</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.scheduled_tasks || 0}</div>
                    <div class="stat-label">Scheduled</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.in_progress_tasks || 0}</div>
                    <div class="stat-label">In Progress</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.completed_tasks || 0}</div>
                    <div class="stat-label">Completed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.critical_priority_tasks || 0}</div>
                    <div class="stat-label">Critical Priority</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.overdue_tasks || 0}</div>
                    <div class="stat-label">Overdue</div>
                </div>
            `;
        }

        async function loadUsers() {
            try {
                const response = await fetch('/api/v1/users/');
                const result = await response.json();
                
                if (result.success) {
                    const select = document.getElementById('assigned-filter');
                    select.innerHTML = '<option value="">All Users</option>';
                    result.data.forEach(user => {
                        const option = document.createElement('option');
                        option.value = user.user_id;
                        option.textContent = user.username;
                        select.appendChild(option);
                    });
                }
            } catch (error) {
                console.error('Error loading users:', error);
            }
        }

        async function loadTasks() {
            try {
                const params = new URLSearchParams({
                    ...currentFilters,
                    limit: 25,
                    offset: (currentPage - 1) * 25
                });
                
                const response = await fetch(`?ajax=get_tasks&${params}`);
                const result = await response.json();
                
                if (result.success) {
                    tasks = result.data;
                    displayTasks(tasks);
                    displayPagination(result.pagination);
                }
            } catch (error) {
                console.error('Error loading tasks:', error);
            }
        }

        function displayTasks(tasks) {
            const tbody = document.getElementById('tasks-tbody');
            tbody.innerHTML = tasks.map(task => `
                <tr>
                    <td>${task.task_id.substring(0, 8)}...</td>
                    <td>
                        <div>
                            <strong>${task.fda_recall_number}</strong>
                            <div style="font-size: 0.8rem; color: var(--text-muted, #94a3b8);">
                                ${task.manufacturer_name}
                            </div>
                        </div>
                    </td>
                    <td>
                        <div>
                            <strong>${task.device_name || 'Unknown Device'}</strong>
                            <div style="font-size: 0.8rem; color: var(--text-muted, #94a3b8);">
                                ${task.location_name || task.location || 'Unknown Location'}
                            </div>
                        </div>
                    </td>
                    <td>
                        <span class="priority-badge priority-${task.recall_priority.toLowerCase()}">
                            ${task.recall_priority}
                        </span>
                    </td>
                    <td>
                        <span class="status-badge status-${task.status.toLowerCase().replace(' ', '-')}">
                            ${task.status}
                        </span>
                    </td>
                    <td>${task.assigned_to_username || 'Unassigned'}</td>
                    <td>${formatDateTime(task.scheduled_date)}</td>
                    <td>
                        <div class="task-actions">
                            <button class="btn btn-sm btn-primary" onclick="viewTaskDetails('${task.task_id}')">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="btn btn-sm btn-warning" onclick="updateTaskStatus('${task.task_id}', 'In Progress')">
                                <i class="fas fa-play"></i>
                            </button>
                            <button class="btn btn-sm btn-success" onclick="updateTaskStatus('${task.task_id}', 'Completed')">
                                <i class="fas fa-check"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `).join('');
        }

        function displayPagination(pagination) {
            const container = document.getElementById('pagination');
            const totalPages = Math.ceil(pagination.total / 25);
            
            let html = '';
            
            // Previous button
            html += `<button ${currentPage === 1 ? 'disabled' : ''} onclick="changePage(${currentPage - 1})">
                <i class="fas fa-chevron-left"></i>
            </button>`;
            
            // Page numbers
            for (let i = Math.max(1, currentPage - 2); i <= Math.min(totalPages, currentPage + 2); i++) {
                html += `<button class="${i === currentPage ? 'current-page' : ''}" onclick="changePage(${i})">
                    ${i}
                </button>`;
            }
            
            // Next button
            html += `<button ${currentPage === totalPages ? 'disabled' : ''} onclick="changePage(${currentPage + 1})">
                <i class="fas fa-chevron-right"></i>
            </button>`;
            
            container.innerHTML = html;
        }

        function changePage(page) {
            currentPage = page;
            loadTasks();
        }

        function applyFilters() {
            currentFilters = {
                status: document.getElementById('status-filter').value,
                priority: document.getElementById('priority-filter').value,
                assigned_to: document.getElementById('assigned-filter').value,
                search: document.getElementById('search-filter').value
            };
            currentPage = 1;
            loadTasks();
        }

        function clearFilters() {
            document.getElementById('status-filter').value = '';
            document.getElementById('priority-filter').value = '';
            document.getElementById('assigned-filter').value = '';
            document.getElementById('search-filter').value = '';
            currentFilters = {};
            currentPage = 1;
            loadTasks();
        }

        function refreshTasks() {
            loadTasks();
            loadStatistics();
        }

        async function updateTaskStatus(taskId, status) {
            try {
                const response = await fetch('?ajax=update_status', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        task_id: taskId,
                        status: status
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification(`Task status updated to ${status}`, 'success');
                    loadTasks();
                    loadStatistics();
                } else {
                    showNotification('Error updating task status: ' + result.error.message, 'error');
                }
            } catch (error) {
                console.error('Error updating task status:', error);
                showNotification('Error updating task status', 'error');
            }
        }

        function viewTaskDetails(taskId) {
            // TODO: Implement task details modal
            console.log('View task details:', taskId);
        }

        function formatDateTime(dateString) {
            if (!dateString) return 'N/A';
            const date = new Date(dateString);
            return date.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        }

        function showNotification(message, type = 'info') {
            // Create notification element
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                <span>${message}</span>
            `;

            // Add styles
            notification.style.cssText = `
                position: fixed;
                top: 2rem;
                right: 2rem;
                padding: 1rem 1.5rem;
                border-radius: 8px;
                color: white;
                font-weight: 500;
                z-index: 10001;
                transform: translateX(100%);
                transition: transform 0.3s ease;
                display: flex;
                align-items: center;
                gap: 0.75rem;
                min-width: 300px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
                background: ${type === 'success' ? 'linear-gradient(135deg, #10b981, #059669)' : 
                           type === 'error' ? 'linear-gradient(135deg, #ef4444, #dc2626)' : 
                           'linear-gradient(135deg, #009999, #007777)'};
            `;

            // Add to page
            document.body.appendChild(notification);

            // Show notification
            setTimeout(() => notification.style.transform = 'translateX(0)', 100);

            // Remove notification after 5 seconds
            setTimeout(() => {
                notification.style.transform = 'translateX(100%)';
                setTimeout(() => notification.remove(), 300);
            }, 5000);
        }
    </script>
</body>
</html>




