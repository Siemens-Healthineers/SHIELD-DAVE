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

// Get database connection
$db = DatabaseConfig::getInstance();

// Get filter parameters
$filters = [
    'assigned_to' => $_GET['assigned_to'] ?? '',
    'start_date' => $_GET['start_date'] ?? date('Y-m-d', strtotime('-3 months')),
    'end_date' => $_GET['end_date'] ?? date('Y-m-d', strtotime('+3 months')),
    'status' => $_GET['status'] ?? '',
    'location' => $_GET['location'] ?? '',
    'department' => $_GET['department'] ?? '',
    'tier' => $_GET['tier'] ?? '',
    'package_name' => $_GET['package_name'] ?? '',
    'severity' => $_GET['severity'] ?? '',
    'task_type' => $_GET['task_type'] ?? ''
];

// Get unique values for filter dropdowns
try {
    // Get users for filter
    $users_sql = "SELECT user_id, username, email FROM users WHERE is_active = true ORDER BY username";
    $users = $db->query($users_sql)->fetchAll();
    
    // Get locations for filter
    $locations_sql = "SELECT DISTINCT location FROM assets WHERE location IS NOT NULL AND location != '' ORDER BY location";
    $locations = $db->query($locations_sql)->fetchAll();
    
    // Get departments for filter
    $departments_sql = "SELECT DISTINCT department FROM assets WHERE department IS NOT NULL AND department != '' ORDER BY department";
    $departments = $db->query($departments_sql)->fetchAll();
    
    // Get package names for filter
    $packages_sql = "SELECT DISTINCT package_name FROM scheduled_tasks_view WHERE package_name IS NOT NULL ORDER BY package_name";
    $packages = $db->query($packages_sql)->fetchAll();
    
} catch (Exception $e) {
    error_log("Error loading filter data: " . $e->getMessage());
    $users = $locations = $departments = $packages = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Schedule - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/schedule.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

    <main class="main-content">
        <div class="container" style="max-width: 1400px; margin: 0 auto; padding: 2rem;">
            
            <!-- Page Header -->
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-calendar-alt"></i> Schedule</h1>
                    <p>Manage scheduled remediation tasks and downtime</p>
                </div>
                        <div class="page-actions">
                            <button class="btn btn-secondary" onclick="toggleConsolidationPanel()">
                                <i class="fas fa-compress-arrows-alt"></i> Consolidation
                            </button>
                            <button class="btn btn-primary" onclick="refreshSchedule()">
                                <i class="fas fa-sync"></i> Refresh
                            </button>
                            <button class="btn btn-secondary" onclick="exportSchedule()">
                                <i class="fas fa-download"></i> Export
                            </button>
                        </div>
            </div>

            <!-- Filters Section -->
            <div class="filters-section">
                <!-- Search Bar -->
                <div class="search-bar-container">
                    <div class="search-input-wrapper">
                        <i class="fas fa-search search-icon"></i>
                        <input 
                            type="text" 
                            id="search" 
                            class="search-input" 
                            placeholder="Search by task, device, user, or description..."
                            autocomplete="off"
                        >
                        <button type="button" id="clearSearch" class="clear-search-btn" style="display: none;">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <button type="button" id="toggleFilters" class="btn-toggle-filters">
                        <i class="fas fa-sliders-h"></i>
                        Filters
                        <span class="filter-count" id="filterCount" style="display: none;"></span>
                    </button>
                </div>

                <!-- Advanced Filters Panel -->
                <div class="filters-panel" id="filtersPanel" style="display: none;">
                    <div class="filters-header">
                        <h4><i class="fas fa-filter"></i> Advanced Filters</h4>
                        <button type="button" id="clearFilters" class="btn-clear-filters">
                            <i class="fas fa-undo"></i> Reset All
                        </button>
                    </div>
                    
                    <form id="filterForm" class="filters-grid">
                    <div class="filter-group">
                        <label for="assigned_to">Assigned To</label>
                        <select id="assigned_to" name="assigned_to" class="filter-select">
                            <option value="">All Users</option>
                            <?php foreach ($users as $user): ?>
                                <option value="<?php echo dave_htmlspecialchars($user['user_id']); ?>" 
                                        <?php echo $filters['assigned_to'] === $user['user_id'] ? 'selected' : ''; ?>>
                                    <?php echo dave_htmlspecialchars($user['username']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label for="start_date">Start Date</label>
                        <input type="date" id="start_date" name="start_date" value="<?php echo dave_htmlspecialchars($filters['start_date']); ?>">
                    </div>

                    <div class="filter-group">
                        <label for="end_date">End Date</label>
                        <input type="date" id="end_date" name="end_date" value="<?php echo dave_htmlspecialchars($filters['end_date']); ?>">
                    </div>

                    <div class="filter-group">
                        <label for="status">Status</label>
                        <select id="status" name="status" class="filter-select">
                            <option value="">All Statuses</option>
                            <option value="Scheduled" <?php echo $filters['status'] === 'Scheduled' ? 'selected' : ''; ?>>Scheduled</option>
                            <option value="In Progress" <?php echo $filters['status'] === 'In Progress' ? 'selected' : ''; ?>>In Progress</option>
                            <option value="Completed" <?php echo $filters['status'] === 'Completed' ? 'selected' : ''; ?>>Completed</option>
                            <option value="Cancelled" <?php echo $filters['status'] === 'Cancelled' ? 'selected' : ''; ?>>Cancelled</option>
                            <option value="Failed" <?php echo $filters['status'] === 'Failed' ? 'selected' : ''; ?>>Failed</option>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label for="location">Location</label>
                        <select id="location" name="location" class="filter-select">
                            <option value="">All Locations</option>
                            <?php foreach ($locations as $location): ?>
                                <option value="<?php echo dave_htmlspecialchars($location['location']); ?>" 
                                        <?php echo $filters['location'] === $location['location'] ? 'selected' : ''; ?>>
                                    <?php echo dave_htmlspecialchars($location['location']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label for="department">Department</label>
                        <select id="department" name="department" class="filter-select">
                            <option value="">All Departments</option>
                            <?php foreach ($departments as $department): ?>
                                <option value="<?php echo dave_htmlspecialchars($department['department']); ?>" 
                                        <?php echo $filters['department'] === $department['department'] ? 'selected' : ''; ?>>
                                    <?php echo dave_htmlspecialchars($department['department']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label for="max_spread_hours">Max Spread (hours)</label>
                        <input type="number" id="max_spread_hours" name="max_spread_hours" min="0" step="1" placeholder="e.g. 72">
                        <small style="color: var(--text-muted, #94a3b8);">Warning only; does not block consolidation</small>
                    </div>

                    <div class="filter-group">
                        <label for="tier">Tier</label>
                        <select id="tier" name="tier" class="filter-select">
                            <option value="">All Tiers</option>
                            <option value="1" <?php echo $filters['tier'] === '1' ? 'selected' : ''; ?>>Tier 1 (Clinical-High)</option>
                            <option value="2" <?php echo $filters['tier'] === '2' ? 'selected' : ''; ?>>Tier 2 (Business-Medium)</option>
                            <option value="3" <?php echo $filters['tier'] === '3' ? 'selected' : ''; ?>>Tier 3 (Non-Essential)</option>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label for="package_name">Package</label>
                        <select id="package_name" name="package_name" class="filter-select">
                            <option value="">All Packages</option>
                            <?php foreach ($packages as $package): ?>
                                <option value="<?php echo dave_htmlspecialchars($package['package_name']); ?>" 
                                        <?php echo $filters['package_name'] === $package['package_name'] ? 'selected' : ''; ?>>
                                    <?php echo dave_htmlspecialchars($package['package_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label for="severity">Severity</label>
                        <select id="severity" name="severity" class="filter-select">
                            <option value="">All Severities</option>
                            <option value="Critical" <?php echo $filters['severity'] === 'Critical' ? 'selected' : ''; ?>>Critical</option>
                            <option value="High" <?php echo $filters['severity'] === 'High' ? 'selected' : ''; ?>>High</option>
                            <option value="Medium" <?php echo $filters['severity'] === 'Medium' ? 'selected' : ''; ?>>Medium</option>
                            <option value="Low" <?php echo $filters['severity'] === 'Low' ? 'selected' : ''; ?>>Low</option>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label for="task_type">Task Type</label>
                        <select id="task_type" name="task_type" class="filter-select">
                            <option value="">All Types</option>
                            <option value="package_remediation" <?php echo $filters['task_type'] === 'package_remediation' ? 'selected' : ''; ?>>Package Remediation</option>
                            <option value="cve_remediation" <?php echo $filters['task_type'] === 'cve_remediation' ? 'selected' : ''; ?>>CVE Remediation</option>
                            <option value="patch_application" <?php echo $filters['task_type'] === 'patch_application' ? 'selected' : ''; ?>>Patch Application</option>
                        </select>
                    </div>

                        <div class="filter-actions">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-search"></i> Apply Filters
                            </button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Summary Cards -->
            <div class="summary-cards" id="summaryCards">
                <div class="summary-card">
                    <div class="summary-icon">
                        <i class="fas fa-tasks"></i>
                    </div>
                    <div class="summary-content">
                        <div class="summary-value" id="totalTasks">-</div>
                        <div class="summary-label">Total Tasks</div>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="summary-icon">
                        <i class="fas fa-clock"></i>
                    </div>
                    <div class="summary-content">
                        <div class="summary-value" id="totalDowntime">-</div>
                        <div class="summary-label">Total Downtime</div>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="summary-icon">
                        <i class="fas fa-server"></i>
                    </div>
                    <div class="summary-content">
                        <div class="summary-value" id="affectedDevices">-</div>
                        <div class="summary-label">Affected Devices</div>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="summary-icon">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="summary-content">
                        <div class="summary-value" id="criticalTasks">-</div>
                        <div class="summary-label">Critical Tasks</div>
                    </div>
                </div>
            </div>

            <!-- View Toggle -->
            <div class="view-toggle">
                <button class="toggle-btn active" onclick="switchView('list')" id="listViewBtn">
                    <i class="fas fa-list"></i> List View
                </button>
                <button class="toggle-btn" onclick="switchView('calendar')" id="calendarViewBtn">
                    <i class="fas fa-calendar"></i> Calendar View
                </button>
                <button class="toggle-btn" onclick="switchView('completed')" id="completedViewBtn">
                    <i class="fas fa-check-circle"></i> Completed
                </button>
            </div>

            <!-- Consolidation Opportunities Panel -->
            <div id="consolidationPanel" class="consolidation-panel" style="display: none;">
                <style>
                .task-item {
                    display: flex;
                    align-items: flex-start;
                    padding: 12px;
                    margin: 8px 0;
                    background: var(--bg-card, #1a1a1a);
                    border: 1px solid var(--border-primary, #333333);
                    border-radius: 6px;
                    transition: all 0.2s ease;
                }
                
                .task-item:hover {
                    background: var(--bg-hover, #333333);
                    border-color: var(--siemens-petrol, #009999);
                }
                
                .task-checkbox {
                    display: flex;
                    align-items: center;
                    margin-right: 12px;
                    cursor: pointer;
                }
                
                .task-checkbox input[type="checkbox"] {
                    margin-right: 8px;
                }
                
                .task-details {
                    flex: 1;
                    min-width: 0;
                }
                
                .task-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 6px;
                }
                
                .task-type {
                    font-weight: 600;
                    color: var(--siemens-petrol, #009999);
                    font-size: 14px;
                }
                
                .task-assigned {
                    font-size: 12px;
                    color: var(--text-muted, #94a3b8);
                }
                
                .task-info {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 8px;
                    margin-bottom: 4px;
                }
                
                .task-info span {
                    font-size: 12px;
                    padding: 2px 6px;
                    background: var(--bg-tertiary, #333333);
                    border-radius: 3px;
                    color: var(--text-secondary, #cbd5e1);
                }
                
                .task-package {
                    color: var(--siemens-orange, #ff6b35) !important;
                }
                
                .task-work {
                    background: #fff3e0;
                    color: #f57c00;
                    font-weight: 600;
                    padding: 4px 8px;
                    border-radius: 4px;
                    display: inline-block;
                    margin-right: 8px;
                }
                
                .task-status {
                    margin-top: 8px;
                    display: flex;
                    gap: 8px;
                    flex-wrap: wrap;
                }
                
                .task-status-badge, .approval-status-badge {
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-size: 0.75rem;
                    font-weight: 600;
                    text-transform: uppercase;
                }
                
                .task-status-badge {
                    background: #e3f2fd;
                    color: #1976d2;
                }
                
                .status-scheduled {
                    background: #e8f5e8;
                    color: #2e7d32;
                }
                
                .status-in-progress {
                    background: #fff3e0;
                    color: #f57c00;
                }
                
                .approval-status-badge {
                    background: #f3e5f5;
                    color: #7b1fa2;
                }
                
                .approval-approved {
                    background: #e8f5e8;
                    color: #2e7d32;
                }
                
                .approval-pending {
                    background: #fff3e0;
                    color: #f57c00;
                }
                
                .approval-rejected {
                    background: #ffebee;
                    color: #c62828;
                }
                
                .task-cve {
                    color: var(--error-red, #ef4444) !important;
                }
                
                .task-approval {
                    color: var(--siemens-petrol, #009999) !important;
                }
                
                .task-id {
                    font-size: 11px;
                    color: var(--text-muted, #94a3b8);
                    font-family: monospace;
                }
                </style>
                <div class="panel-header">
                    <h3><i class="fas fa-compress-arrows-alt"></i> Task Consolidation Opportunities</h3>
                    <button onclick="toggleConsolidationPanel()" class="btn-close-panel">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div id="consolidationContent" class="consolidation-content">
                    <div class="loading-message">
                        <i class="fas fa-spinner fa-spin"></i> Loading consolidation opportunities...
                    </div>
                </div>
            </div>

            <!-- Tasks List View -->
            <div id="listView" class="view-content">
                <div class="tasks-table-container">
                    <table class="tasks-table" id="tasksTable">
                        <thead>
                            <tr>
                                <th>Task Type</th>
                                <th>Device & Location</th>
                                <th>Package/CVE</th>
                                <th>Assigned To</th>
                                <th>Schedule & Downtime</th>
                                <th>Approval Status</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="tasksTableBody">
                            <tr>
                                <td colspan="8" class="loading-cell">
                                    <i class="fas fa-spinner fa-spin"></i> Loading tasks...
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Calendar View -->
            <div id="calendarView" class="view-content" style="display: none;">
                <!-- Overdue Tasks Section -->
                <div id="overdueSection" class="overdue-section" style="display: none; margin-bottom: 2rem;">
                    <div class="section-header">
                        <h3><i class="fas fa-exclamation-triangle" style="color: #ef4444;"></i> Overdue Tasks</h3>
                    </div>
                    <div id="overdueTasksList" class="overdue-tasks-list"></div>
                </div>
                
                <!-- Calendar Navigation -->
                <div class="calendar-navigation">
                    <button class="btn btn-secondary" onclick="navigateCalendarMonth(-1)">
                        <i class="fas fa-chevron-left"></i> Previous Month
                    </button>
                    <div class="calendar-month-display">
                        <span id="calendarMonthYear"></span>
                    </div>
                    <button class="btn btn-secondary" onclick="navigateCalendarMonth(1)">
                        Next Month <i class="fas fa-chevron-right"></i>
                    </button>
                </div>
                
                <div class="calendar-container" id="calendarContainer">
                    <div class="loading-message">
                        <i class="fas fa-spinner fa-spin"></i> Loading calendar...
                    </div>
                </div>
            </div>

            <!-- Completed View -->
            <div id="completedView" class="view-content" style="display: none;">
                <!-- Completed Calendar Navigation -->
                <div class="calendar-navigation">
                    <button class="btn btn-secondary" onclick="navigateCompletedMonth(-1)">
                        <i class="fas fa-chevron-left"></i> Previous Month
                    </button>
                    <div class="calendar-month-display">
                        <span id="completedMonthYear"></span>
                    </div>
                    <button class="btn btn-secondary" onclick="navigateCompletedMonth(1)">
                        Next Month <i class="fas fa-chevron-right"></i>
                    </button>
                </div>
                
                <div class="calendar-container" id="completedContainer">
                    <div class="loading-message">
                        <i class="fas fa-spinner fa-spin"></i> Loading completed tasks...
                    </div>
                </div>
            </div>

        </div>
    </main>

    <script>
        // Complete Task Modal
        let completeTaskId = null;

        function showCompleteTaskModal(taskId) {
            completeTaskId = taskId;
            
            // Close any existing modals first
            // Close any other standard modals that might be open
            const existingModals = document.querySelectorAll('.schedule-page-modal:not(#task-details-modal)');
            existingModals.forEach(m => {
                if (m.id !== 'task-details-modal' && m.id !== 'scheduleDayTasksModal') {
                    m.remove();
                }
            });
            
            const modal = document.createElement('div');
            modal.className = 'schedule-page-modal';
            modal.id = 'complete-task-modal';
            modal.style.cssText = `
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100vw !important;
                height: 100vh !important;
                background: rgba(0, 0, 0, 0.85) !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                z-index: 11000 !important;
                padding: 1rem;
                box-sizing: border-box;
            `;
            modal.innerHTML = `
                <div class="schedule-page-modal-content" style="
                    position: relative !important;
                    max-width: 560px !important;
                    width: 90% !important;
                    background: var(--bg-card, #1a1a1a) !important;
                    border: 1px solid var(--border-primary, #333333) !important;
                    border-radius: 0.75rem !important;
                    padding: 1.5rem !important;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5) !important;
                    z-index: 11001 !important;
                ">
                    <div class="schedule-page-modal-header" style="
                        display: flex !important;
                        align-items: center !important;
                        justify-content: space-between !important;
                        margin-bottom: 1rem !important;
                        padding-bottom: 1rem !important;
                        border-bottom: 1px solid var(--border-primary, #333333) !important;
                    ">
                        <h3 style="margin: 0; color: var(--text-primary, #ffffff);"><i class="fas fa-check-circle"></i> Complete Task</h3>
                        <button class="schedule-page-modal-close" onclick="document.getElementById('complete-task-modal').remove()" style="
                            background: transparent;
                            border: none;
                            color: var(--text-secondary, #cbd5e1);
                            font-size: 1.5rem;
                            cursor: pointer;
                            padding: 0.5rem;
                            line-height: 1;
                        "><i class="fas fa-times"></i></button>
                    </div>
                    <div class="schedule-page-modal-body" style="padding: 0 !important;">
                        <div id="taskSummary" style="margin-bottom: 1rem; color: var(--text-secondary, #cbd5e1);"></div>
                        <form id="completeTaskForm" onsubmit="event.preventDefault(); completeTask();">
                            <label class="form-label" style="
                                display: block;
                                margin-bottom: 0.5rem;
                                color: var(--text-primary, #ffffff);
                                font-weight: 600;
                            ">Completion Notes (required)</label>
                            <textarea id="completionNotes" class="form-input" required placeholder="Describe what was done..." style="
                                width: 100%;
                                padding: 0.75rem;
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                background: var(--bg-secondary, #1a1a1a);
                                color: var(--text-primary, #f8fafc);
                                font-family: 'Siemens Sans', sans-serif;
                                resize: vertical;
                            "></textarea>
                            <div style="height: 0.75rem;"></div>
                            <label class="form-label" style="
                                display: block;
                                margin-bottom: 0.5rem;
                                color: var(--text-primary, #ffffff);
                                font-weight: 600;
                            ">Actual Downtime (minutes, optional)</label>
                            <input id="actualDowntime" type="number" class="form-input" min="0" placeholder="e.g., 45" style="
                                width: 100%;
                                padding: 0.75rem;
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                background: var(--bg-secondary, #1a1a1a);
                                color: var(--text-primary, #f8fafc);
                                font-family: 'Siemens Sans', sans-serif;
                            " />
                            <div class="warning-box" style="margin-top: 1rem; padding: 0.75rem; border-left: 4px solid var(--siemens-petrol); background: var(--bg-secondary, #1a1a1a); color: var(--text-secondary, #cbd5e1); border-radius: 0.375rem;">
                                Note: This marks the task complete for the associated device only. The same CVE/patch/recall on other devices remains open.
                            </div>
                            <div class="schedule-page-modal-footer" style="margin-top: 1.5rem !important; display: flex !important; gap: 0.5rem !important; justify-content: flex-end !important; padding-top: 1rem !important; border-top: 1px solid var(--border-primary, #333333) !important;">
                                <button type="button" class="btn btn-secondary" onclick="document.getElementById('complete-task-modal').remove()" style="
                                    padding: 0.75rem 1.5rem;
                                    background: transparent;
                                    color: var(--text-secondary, #cbd5e1);
                                    border: 1px solid var(--border-secondary, #555555);
                                    border-radius: 0.5rem;
                                    cursor: pointer;
                                    font-weight: 600;
                                    transition: all 0.2s;
                                    font-family: 'Siemens Sans', sans-serif;
                                ">Cancel</button>
                                <button type="submit" class="btn btn-primary" style="
                                    padding: 0.75rem 1.5rem;
                                    background: var(--siemens-petrol, #009999);
                                    color: white;
                                    border: 1px solid var(--siemens-petrol, #009999);
                                    border-radius: 0.5rem;
                                    cursor: pointer;
                                    font-weight: 600;
                                    transition: all 0.2s;
                                    font-family: 'Siemens Sans', sans-serif;
                                ">Complete Task</button>
                            </div>
                        </form>
                    </div>
                </div>`;
            document.body.appendChild(modal);

            // Fill summary
            const task = tasksData.find(t => t.task_id === taskId);
            if (task) {
                document.getElementById('taskSummary').innerHTML = `
                    <div><strong>Device:</strong> ${escapeHtml(task.device_name || 'Unknown')}</div>
                    <div><strong>Task Type:</strong> ${escapeHtml(getTaskTypeLabel(task.task_type))}</div>
                    <div><strong>Scheduled:</strong> ${escapeHtml(formatDateTime(task.scheduled_date))}</div>
                `;
            }
        }

        async function completeTask() {
            try {
                const notes = document.getElementById('completionNotes').value.trim();
                const downtimeStr = document.getElementById('actualDowntime').value;
                const downtime = downtimeStr === '' ? null : parseInt(downtimeStr, 10);
                if (!notes) {
                    showNotification('Completion notes are required', 'error');
                    return;
                }
                const resp = await fetch(`/api/v1/scheduled-tasks/complete.php?task_id=${encodeURIComponent(completeTaskId)}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ completion_notes: notes, actual_downtime: downtime })
                });
                
                // Always read as text first to handle any errors gracefully
                const responseText = await resp.text();
                
                // Check if response is actually JSON
                const contentType = resp.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    console.error('Non-JSON response:', responseText.substring(0, 500));
                    throw new Error('Server returned invalid response. Please check console for details.');
                }
                
                // Try to parse JSON
                let result;
                try {
                    result = JSON.parse(responseText);
                } catch (parseError) {
                    console.error('JSON parse error:', parseError);
                    console.error('Response text:', responseText.substring(0, 500));
                    throw new Error('Invalid JSON response from server. Please check console for details.');
                }
                
                if (!result.success) {
                    throw new Error(result.error?.message || 'Failed to complete task');
                }
                showNotification('Task completed successfully', 'success');
                // Close complete task modal
                const completeModal = document.getElementById('complete-task-modal');
                if (completeModal) {
                    completeModal.remove();
                }
                // Refresh tasks based on current view
                if (currentView === 'completed') {
                    // Refresh completed calendar view
                    loadCompletedCalendar();
                } else {
                    // Refresh list/calendar view
                    loadTasks();
                }
            } catch (e) {
                console.error(e);
                showNotification(e.message || 'Error completing task', 'error');
            }
        }

        let currentView = 'list';
        let tasksData = [];
        let calendarData = [];
        let overdueTasks = [];
        let currentCalendarMonth = new Date(); // Initialize to current month
        let completedCalendarData = [];
        let currentCompletedMonth = new Date(); // Initialize to current month

        document.addEventListener('DOMContentLoaded', function() {
            loadTasks();
            setupEventListeners();
        });

        function setupEventListeners() {
            // Filter form submission
            document.getElementById('filterForm').addEventListener('submit', function(e) {
                e.preventDefault();
                loadTasks();
            });

            // Initialize accordion functionality
            initializeFilters();

            // Auto-refresh every 5 minutes
            setInterval(loadTasks, 300000);
        }

        // Initialize filter functionality (accordion)
        function initializeFilters() {
            const searchInput = document.getElementById('search');
            const clearSearchBtn = document.getElementById('clearSearch');
            const toggleFiltersBtn = document.getElementById('toggleFilters');
            const filtersPanel = document.getElementById('filtersPanel');
            const clearFiltersBtn = document.getElementById('clearFilters');
            
            // Search functionality
            if (searchInput) {
                searchInput.addEventListener('input', function() {
                    if (this.value.length > 0) {
                        clearSearchBtn.style.display = 'block';
                    } else {
                        clearSearchBtn.style.display = 'none';
                    }
                    applySearch();
                });
            }
            
            // Clear search
            if (clearSearchBtn) {
                clearSearchBtn.addEventListener('click', function() {
                    searchInput.value = '';
                    this.style.display = 'none';
                    applySearch();
                });
            }
            
            // Toggle filters panel
            if (toggleFiltersBtn && filtersPanel) {
                toggleFiltersBtn.addEventListener('click', function() {
                    const isVisible = filtersPanel.style.display !== 'none';
                    filtersPanel.style.display = isVisible ? 'none' : 'block';
                    this.classList.toggle('active', !isVisible);
                });
            }
            
            // Clear all filters
            if (clearFiltersBtn) {
                clearFiltersBtn.addEventListener('click', function() {
                    // Clear all filter selects
                    document.querySelectorAll('.filter-select').forEach(select => {
                        select.value = '';
                    });
                    // Clear search
                    if (searchInput) {
                        searchInput.value = '';
                        clearSearchBtn.style.display = 'none';
                    }
                    // Reload tasks
                    loadTasks();
                });
            }
        }

        // Apply search functionality
        function applySearch() {
            const searchTerm = document.getElementById('search').value.toLowerCase();
            const rows = document.querySelectorAll('#tasksTableBody tr');
            
            rows.forEach(row => {
                if (row.querySelector('.loading-cell')) return; // Skip loading row
                
                const text = row.textContent.toLowerCase();
                if (text.includes(searchTerm)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }

        async function loadTasks() {
            try {
                const params = new URLSearchParams();
                const formData = new FormData(document.getElementById('filterForm'));
                
                for (let [key, value] of formData.entries()) {
                    if (value) {
                        params.append(key, value);
                    }
                }
                
                // Explicitly exclude completed tasks from list/calendar views
                // Only show completed tasks if user explicitly selects "Completed" status filter
                const statusValue = formData.get('status');
                if (statusValue !== 'Completed') {
                    // Don't include completed tasks unless explicitly requested
                    // The API defaults to excluding them, which is what we want
                }

                // Add cache-busting parameter
                params.append('_t', Date.now());
                const response = await fetch(`/api/v1/scheduled-tasks/list.php?${params.toString()}`, {
                    credentials: 'same-origin',
                    cache: 'no-cache'
                });
                const result = await response.json();
                
                if (result.success) {
                    tasksData = result.data;
                    displayTasks();
                    updateSummaryCards();
                } else {
                    console.error('Failed to load tasks:', result.error);
                    showError('Failed to load tasks');
                }
            } catch (error) {
                console.error('Error loading tasks:', error);
                showError('Error loading tasks');
            }
        }

        function displayTasks() {
            const tbody = document.getElementById('tasksTableBody');
            
            if (tasksData.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="empty-cell">No tasks found</td></tr>';
                return;
            }

            tbody.innerHTML = tasksData.map(task => `
                <tr class="task-row" data-task-id="${task.task_id}">
                    <td>
                        <span class="task-type-badge task-type-${task.task_type}">
                            ${getTaskTypeLabel(task.task_type)}
                        </span>
                    </td>
                    <td>
                        <div class="device-info">
                            <div class="device-name">${(() => {
                                const name = (task.device_name && task.device_name !== 'Unknown Device') ? task.device_name
                                    : (task.original_device_name || task.original_hostname || task.hostname || ((task.original_brand_name ? (task.original_brand_name + (task.original_model_number ? (' ' + task.original_model_number) : '')) : '')));
                                return escapeHtml(name || 'Unidentified Device');
                            })()}</div>
                            <div class="device-details">
                                <span class="device-location">${escapeHtml(task.location || 'Unknown')}</span>
                                <span class="device-department">${escapeHtml(task.department || 'Unknown')}</span>
                                <span class="device-criticality criticality-${(task.device_criticality || '').toLowerCase().replace('-', '_')}">
                                    ${escapeHtml(task.device_criticality || 'Unknown')}
                                </span>
                            </div>
                        </div>
                    </td>
                    <td>
                        <div class="package-cve-info">
                            ${task.package_cve_display ? `
                                <div class="package-cve-display">${escapeHtml(task.package_cve_display)}</div>
                            ` : ''}
                            ${!task.package_cve_display && task.task_type === 'patch_application' && task.patch_name ? `
                                <div class="patch-name">${escapeHtml(task.patch_name)}</div>
                                ${task.action_target_version ? `
                                    <div class="patch-version">v${escapeHtml(task.action_target_version)}</div>
                                ` : ''}
                            ` : ''}
                            ${!task.package_cve_display && task.task_type !== 'patch_application' && task.package_name ? `
                                <div class="package-name">${escapeHtml(task.package_name)}</div>
                                <div class="package-vendor">${escapeHtml(task.package_vendor || '')}</div>
                            ` : ''}
                            ${!task.package_cve_display && task.cve_id ? `
                                <div class="cve-id">${escapeHtml(task.cve_id)}</div>
                                <div class="cve-severity severity-${(task.cve_severity || '').toLowerCase()}">
                                    ${escapeHtml(task.cve_severity || 'Unknown')}
                                </div>
                            ` : ''}
                            ${!task.package_cve_display ? `
                                <div class="no-data">N/A</div>
                            ` : ''}
                        </div>
                    </td>
                    <td>
                        <div class="user-info">
                            <div class="username">${escapeHtml(task.assigned_to_username)}</div>
                            <div class="user-email">${escapeHtml(task.assigned_to_email)}</div>
                        </div>
                    </td>
                    <td>
                        <div class="schedule-downtime-info">
                            <div class="scheduled-date">${formatDateTime(task.scheduled_date)}</div>
                            ${task.implementation_date ? `
                                <div class="implementation-date">Due: ${formatDateTime(task.implementation_date)}</div>
                            ` : ''}
                            <div class="downtime-info">
                                <span class="downtime-label">Downtime:</span>
                                <span class="estimated-downtime">${task.estimated_downtime_display}</span>
                                ${task.actual_downtime_display !== 'N/A' ? `
                                    <span class="actual-downtime">(Actual: ${task.actual_downtime_display})</span>
                                ` : ''}
                            </div>
                        </div>
                    </td>
                    <td>
                        <div class="approval-status-info">
                            <div class="approval-row">
                                <span class="approval-label">Notified:</span>
                                <span class="approval-badge ${task.department_notified ? 'approved' : 'pending'}">
                                    ${task.department_notified ? 'Yes' : 'No'}
                                </span>
                            </div>
                            <div class="approval-row">
                                <span class="approval-label">Status:</span>
                                <span class="approval-badge ${getApprovalStatusClass(task.department_approval_status)}">
                                    ${escapeHtml(task.department_approval_status || 'Pending')}
                                </span>
                            </div>
                            ${task.department_approval_contact ? `
                                <div class="approval-contact">${escapeHtml(task.department_approval_contact)}</div>
                            ` : ''}
                        </div>
                    </td>
                    <td>
                        <div class="status-info">
                            <span class="status-badge status-${task.status_class}">
                                ${escapeHtml(task.status)}
                            </span>
                            ${task.status === 'Completed' && task.completed_at ? `
                                <div class="completion-info" style="margin-top: 0.5rem; font-size: 0.875rem; color: var(--text-secondary, #cbd5e1);">
                                    ${task.completed_by_username ? `
                                        <div><strong>Completed by:</strong> ${escapeHtml(task.completed_by_username)}</div>
                                    ` : ''}
                                    <div><strong>Completed:</strong> ${formatDateTime(task.completed_at)}</div>
                                    ${task.completion_notes ? `
                                        <div style="margin-top: 0.25rem;"><strong>Notes:</strong> ${escapeHtml(task.completion_notes.substring(0, 100))}${task.completion_notes.length > 100 ? '...' : ''}</div>
                                    ` : ''}
                                </div>
                            ` : ''}
                        </div>
                    </td>
                    <td>
                        <div class="action-dropdown">
                            <button type="button" class="dropdown-trigger" onclick="toggleScheduleDropdown('${task.task_id}')" title="Actions">
                                <i class="fas fa-ellipsis-v"></i>
                            </button>
                            <div class="dropdown-menu" id="dropdown-${task.task_id}">
                                <button type="button" class="dropdown-item view" onclick="viewTask('${task.task_id}')">
                                    <i class="fas fa-eye"></i>
                                    <span>View Details</span>
                                </button>
                                <button type="button" class="dropdown-item edit" onclick="editTask('${task.task_id}')">
                                    <i class="fas fa-edit"></i>
                                    <span>Edit Task</span>
                                </button>
                                ${task.status !== 'Completed' && task.status !== 'Cancelled' ? `
                                <button type="button" class="dropdown-item complete" onclick="showCompleteTaskModal('${task.task_id}')">
                                    <i class=\"fas fa-check\"></i>
                                    <span>Complete Task</span>
                                </button>
                                ` : ''}
                                <button type="button" class="dropdown-item delete" onclick="deleteTask('${task.task_id}')">
                                    <i class="fas fa-trash"></i>
                                    <span>Delete Task</span>
                                </button>
                            </div>
                        </div>
                    </td>
                </tr>
            `).join('');
        }

        function updateSummaryCards() {
            const totalTasks = tasksData.length;
            const totalDowntime = tasksData.reduce((sum, task) => sum + (task.estimated_downtime || 0), 0);
            const affectedDevices = new Set(tasksData.map(task => task.device_id)).size;
            const criticalTasks = tasksData.filter(task => 
                task.device_criticality === 'Clinical-High' || task.cve_severity === 'Critical'
            ).length;

            document.getElementById('totalTasks').textContent = totalTasks;
            document.getElementById('totalDowntime').textContent = formatDuration(totalDowntime);
            document.getElementById('affectedDevices').textContent = affectedDevices;
            document.getElementById('criticalTasks').textContent = criticalTasks;
        }

        function switchView(view) {
            console.log('Switching to view:', view);
            currentView = view;
            
            // Update toggle buttons
            document.querySelectorAll('.toggle-btn').forEach(btn => btn.classList.remove('active'));
            const btnMap = {
                'list': 'listViewBtn',
                'calendar': 'calendarViewBtn',
                'completed': 'completedViewBtn'
            };
            if (btnMap[view]) {
                document.getElementById(btnMap[view]).classList.add('active');
            }
            
            // Show/hide views
            document.getElementById('listView').style.display = view === 'list' ? 'block' : 'none';
            document.getElementById('calendarView').style.display = view === 'calendar' ? 'block' : 'none';
            document.getElementById('completedView').style.display = view === 'completed' ? 'block' : 'none';
            
            if (view === 'calendar') {
                console.log('Loading calendar...');
                loadOverdueTasks();
                loadCalendar();
            } else if (view === 'completed') {
                console.log('Loading completed tasks...');
                loadCompletedCalendar();
            }
        }

        async function loadOverdueTasks() {
            try {
                const response = await fetch('/api/v1/scheduled-tasks/overdue.php', {
                    credentials: 'same-origin'
                });

                if (!response.ok) {
                    console.error('Failed to load overdue tasks:', response.status);
                    const errorText = await response.text();
                    console.error('Error response:', errorText);
                    document.getElementById('overdueSection').style.display = 'none';
                    return;
                }

                const result = await response.json();
                console.log('Overdue tasks result:', result);
                
                if (!result.success) {
                    console.error('API returned error:', result.error);
                    document.getElementById('overdueSection').style.display = 'none';
                    return;
                }
                if (result.success && result.data && result.data.length > 0) {
                    overdueTasks = result.data;
                    displayOverdueTasks();
                } else {
                    overdueTasks = [];
                    document.getElementById('overdueSection').style.display = 'none';
                }
            } catch (error) {
                console.error('Error loading overdue tasks:', error);
                document.getElementById('overdueSection').style.display = 'none';
            }
        }

        function displayOverdueTasks() {
            const section = document.getElementById('overdueSection');
            const list = document.getElementById('overdueTasksList');
            
            if (!section || !list) {
                console.error('Overdue section elements not found');
                return;
            }
            
            if (overdueTasks.length === 0) {
                section.style.display = 'none';
                return;
            }
            
            console.log('Displaying', overdueTasks.length, 'overdue tasks');
            section.style.display = 'block';
            
            list.innerHTML = overdueTasks.map(task => {
                const scheduledDate = new Date(task.scheduled_date);
                const daysOverdue = Math.floor((new Date() - scheduledDate) / (1000 * 60 * 60 * 24));
                const deviceName = escapeHtml(task.device_name || 'Unknown Device');
                const location = escapeHtml(task.location || 'Unknown');
                const formattedDate = formatDate(task.scheduled_date);
                const taskTypeLabel = getTaskTypeLabel(task.task_type);
                const packageInfo = task.package_name ? '<div><strong>Package:</strong> ' + escapeHtml(task.package_name) + '</div>' : '';
                const cveInfo = task.cve_id ? '<div><strong>CVE:</strong> ' + escapeHtml(task.cve_id) + '</div>' : '';
                const daysText = daysOverdue === 1 ? 'day' : 'days';
                
                return '<div class="overdue-task-item">' +
                    '<div class="overdue-task-header">' +
                    '<span class="overdue-badge">' + daysOverdue + ' ' + daysText + ' overdue</span>' +
                    '<span class="task-type-badge task-type-' + task.task_type + '">' + taskTypeLabel + '</span>' +
                    '</div>' +
                    '<div class="overdue-task-details">' +
                    '<div><strong>Device:</strong> ' + deviceName + '</div>' +
                    '<div><strong>Location:</strong> ' + location + '</div>' +
                    '<div><strong>Scheduled:</strong> ' + formattedDate + '</div>' +
                    packageInfo +
                    cveInfo +
                    '</div>' +
                    '<div class="overdue-task-actions">' +
                    '<button class="btn btn-sm btn-primary" onclick="viewTask(\'' + task.task_id + '\')">View Details</button>' +
                    '</div>' +
                    '</div>';
            }).join('');
        }

        async function loadCalendar() {
            const container = document.getElementById('calendarContainer');
            container.innerHTML = '<div class="loading-message"><i class="fas fa-spinner fa-spin"></i> Loading calendar...</div>';
            
            // Calculate start and end of current month
            const year = currentCalendarMonth.getFullYear();
            const month = currentCalendarMonth.getMonth();
            const startDate = new Date(year, month, 1);
            const endDate = new Date(year, month + 1, 0); // Last day of month
            
            try {
                const params = new URLSearchParams();
                params.append('start_date', formatDateForAPI(startDate));
                params.append('end_date', formatDateForAPI(endDate));

                const response = await fetch(`/api/v1/scheduled-tasks/downtime-calendar.php?${params.toString()}` , {
                    credentials: 'same-origin'
                });

                if (!response.ok) {
                    const text = await response.text().catch(() => '');
                    console.error('Calendar HTTP error:', response.status, text);
                    container.innerHTML = '<div class="error-message">Failed to load calendar data</div>';
                    return;
                }

                const contentType = response.headers.get('content-type') || '';
                if (!contentType.includes('application/json')) {
                    const text = await response.text().catch(() => '');
                    console.error('Calendar non-JSON response:', text);
                    container.innerHTML = '<div class="error-message">Invalid calendar response</div>';
                    return;
                }

                const result = await response.json();
                if (result.success) {
                    calendarData = result.data;
                    displayCalendar();
                    updateCalendarMonthDisplay();
                } else {
                    console.error('Calendar API error:', result.error);
                    container.innerHTML = `<div class="error-message">Failed to load calendar data${result.error?.message ? ': ' + result.error.message : ''}</div>`;
                }
            } catch (error) {
                container.innerHTML = '<div class="error-message">Error loading calendar data</div>';
            }
        }

        function formatDateForAPI(date) {
            const year = date.getFullYear();
            const month = String(date.getMonth() + 1).padStart(2, '0');
            const day = String(date.getDate()).padStart(2, '0');
            return `${year}-${month}-${day}`;
        }

        function navigateCalendarMonth(direction) {
            currentCalendarMonth.setMonth(currentCalendarMonth.getMonth() + direction);
            loadCalendar();
        }

        function updateCalendarMonthDisplay() {
            const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
                              'July', 'August', 'September', 'October', 'November', 'December'];
            const monthYear = `${monthNames[currentCalendarMonth.getMonth()]} ${currentCalendarMonth.getFullYear()}`;
            document.getElementById('calendarMonthYear').textContent = monthYear;
        }

        function displayCalendar() {
            const container = document.getElementById('calendarContainer');
            
            if (calendarData.length === 0) {
                container.innerHTML = '<div class="empty-message">No tasks scheduled for this month</div>';
                return;
            }

            const daysHTML = calendarData.map(day => {
                const dayDate = new Date(day.calendar_date + 'T00:00:00');
                const today = new Date();
                today.setHours(0, 0, 0, 0);
                const isOverdue = dayDate < today;
                const dayClass = isOverdue ? 'calendar-day overdue-day' : 'calendar-day';
                const formattedDate = formatDate(day.calendar_date);
                const formattedDuration = formatDuration(day.total_estimated_downtime);
                const overdueIndicator = isOverdue ? '<span class="overdue-indicator" title="Overdue"><i class="fas fa-exclamation-triangle"></i></span>' : '';
                const cancelledBadge = day.cancelled_count > 0 ? '<span class="status-item cancelled">' + day.cancelled_count + ' Cancelled</span>' : '';
                const failedBadge = day.failed_count > 0 ? '<span class="status-item failed">' + day.failed_count + ' Failed</span>' : '';
                const criticalItem = day.critical_devices_affected > 0 ? '<div class="impact-item critical"><i class="fas fa-exclamation-triangle"></i> ' + day.critical_devices_affected + ' critical</div>' : '';
                
                return '<div class="' + dayClass + '" data-date="' + day.calendar_date + '">' +
                    '<div class="day-header">' +
                    '<div class="day-date">' + formattedDate + overdueIndicator + '</div>' +
                    '<div class="day-stats">' +
                    '<span class="task-count">' + day.total_tasks + ' tasks</span>' +
                    '<span class="downtime-count">' + formattedDuration + '</span>' +
                    '</div>' +
                    '</div>' +
                    '<div class="day-content">' +
                    '<div class="status-breakdown">' +
                    '<span class="status-item scheduled">' + day.scheduled_count + ' Scheduled</span>' +
                    '<span class="status-item in_progress">' + day.in_progress_count + ' In Progress</span>' +
                    '<span class="status-item completed">' + day.completed_count + ' Completed</span>' +
                    cancelledBadge +
                    failedBadge +
                    '</div>' +
                    '<div class="impact-summary">' +
                    '<div class="impact-item">' +
                    '<i class="fas fa-server"></i> ' + day.affected_devices + ' devices' +
                    '</div>' +
                    '<div class="impact-item">' +
                    '<i class="fas fa-users"></i> ' + day.assigned_users + ' users' +
                    '</div>' +
                    '<div class="impact-item">' +
                    '<i class="fas fa-map-marker-alt"></i> ' + day.affected_locations + ' locations' +
                    '</div>' +
                    criticalItem +
                    '</div>' +
                    '<div class="day-actions">' +
                    '<button class="btn btn-sm btn-primary" onclick="viewDayTasks(\'' + day.calendar_date + '\', false)">' +
                    '<i class="fas fa-list"></i> View Tasks' +
                    '</button>' +
                    '</div>' +
                    '</div>' +
                    '</div>';
            }).join('');

            const calendarHTML = '<div class="calendar-grid">' + daysHTML + '</div>';
            container.innerHTML = calendarHTML;
        }

        async function loadCompletedCalendar() {
            const container = document.getElementById('completedContainer');
            container.innerHTML = '<div class="loading-message"><i class="fas fa-spinner fa-spin"></i> Loading completed tasks...</div>';
            
            // Calculate start and end of current month
            const year = currentCompletedMonth.getFullYear();
            const month = currentCompletedMonth.getMonth();
            const startDate = new Date(year, month, 1);
            const endDate = new Date(year, month + 1, 0);
            
            try {
                const params = new URLSearchParams();
                params.append('start_date', formatDateForAPI(startDate));
                params.append('end_date', formatDateForAPI(endDate));
                params.append('status', 'Completed');

                const response = await fetch(`/api/v1/scheduled-tasks/downtime-calendar.php?${params.toString()}`, {
                    credentials: 'same-origin'
                });

                if (!response.ok) {
                    container.innerHTML = '<div class="error-message">Failed to load completed tasks</div>';
                    return;
                }

                const result = await response.json();
                if (result.success) {
                    completedCalendarData = result.data;
                    displayCompletedCalendar();
                    updateCompletedMonthDisplay();
                } else {
                    container.innerHTML = `<div class="error-message">Failed to load completed tasks</div>`;
                }
            } catch (error) {
                container.innerHTML = '<div class="error-message">Error loading completed tasks</div>';
            }
        }

        function displayCompletedCalendar() {
            const container = document.getElementById('completedContainer');
            
            if (completedCalendarData.length === 0) {
                container.innerHTML = '<div class="empty-message">No completed tasks for this month</div>';
                return;
            }

            const daysHTML = completedCalendarData.map(day => {
                const actualDowntime = day.total_actual_downtime || 0;
                const formattedDate = formatDate(day.calendar_date);
                const formattedDuration = formatDuration(actualDowntime);
                return '<div class="calendar-day completed-day" data-date="' + day.calendar_date + '">' +
                    '<div class="day-header">' +
                    '<div class="day-date">' + formattedDate + '</div>' +
                    '<div class="day-stats">' +
                    '<span class="task-count">' + day.completed_count + ' completed</span>' +
                    '<span class="downtime-count">' + formattedDuration + ' actual</span>' +
                    '</div>' +
                    '</div>' +
                    '<div class="day-content">' +
                    '<div class="status-breakdown">' +
                    '<span class="status-item completed">' + day.completed_count + ' Completed</span>' +
                    '</div>' +
                    '<div class="impact-summary">' +
                    '<div class="impact-item">' +
                    '<i class="fas fa-server"></i> ' + day.affected_devices + ' devices' +
                    '</div>' +
                    '<div class="impact-item">' +
                    '<i class="fas fa-users"></i> ' + day.assigned_users + ' users' +
                    '</div>' +
                    '<div class="impact-item">' +
                    '<i class="fas fa-map-marker-alt"></i> ' + day.affected_locations + ' locations' +
                    '</div>' +
                    '</div>' +
                    '<div class="day-actions">' +
                    '<button class="btn btn-sm btn-primary" onclick="viewDayTasks(\'' + day.calendar_date + '\', true)">' +
                    '<i class="fas fa-list"></i> View Tasks' +
                    '</button>' +
                    '</div>' +
                    '</div>' +
                    '</div>';
            }).join('');

            const calendarHTML = '<div class="calendar-grid">' + daysHTML + '</div>';
            container.innerHTML = calendarHTML;
        }

        function navigateCompletedMonth(direction) {
            currentCompletedMonth.setMonth(currentCompletedMonth.getMonth() + direction);
            loadCompletedCalendar();
        }

        async function viewDayTasks(date, isCompleted = false) {
            try {
                const params = new URLSearchParams();
                
                if (isCompleted) {
                    // For completed tasks, filter by completed_at date, not scheduled_date
                    params.append('status', 'Completed');
                    params.append('completed_date_from', date + ' 00:00:00');
                    params.append('completed_date_to', date + ' 23:59:59');
                } else {
                    // For active tasks, filter by scheduled_date
                    const startOfDay = date + ' 00:00:00';
                    const endOfDay = date + ' 23:59:59';
                    params.append('date_from', startOfDay);
                    params.append('date_to', endOfDay);
                    params.append('status', 'all');
                    params.append('include_completed', '1');
                }

                const response = await fetch(`/api/v1/scheduled-tasks/list.php?${params.toString()}`, {
                    credentials: 'same-origin'
                });

                if (!response.ok) {
                    showNotification('Failed to load tasks for this date', 'error');
                    return;
                }

                const result = await response.json();
                if (result.success && result.data) {
                    // Debug: Log first task to check available fields
                    if (result.data.length > 0 && isCompleted) {
                        console.log('Sample completed task fields:', Object.keys(result.data[0]));
                        console.log('completed_by_username:', result.data[0].completed_by_username);
                        console.log('completed_by_email:', result.data[0].completed_by_email);
                        console.log('completed_by:', result.data[0].completed_by);
                    }
                    showDayTasksModal(date, result.data, isCompleted);
                } else {
                    showNotification('No tasks found for this date', 'info');
                }
            } catch (error) {
                console.error('Error loading day tasks:', error);
                showNotification('Error loading tasks', 'error');
            }
        }

        function showDayTasksModal(date, tasks, isCompleted) {
            const formattedDate = formatDate(date);
            const viewType = isCompleted ? 'Completed' : 'Scheduled';
            
            // Close any existing modal first
            closeDayTasksModal();
            
            const tasksHTML = tasks.map(task => {
                // Better fallback logic for device name - check multiple sources
                let deviceName = task.device_name;
                if (!deviceName || deviceName === 'Unknown Device') {
                    deviceName = task.original_device_name || 
                                task.original_hostname || 
                                task.hostname ||
                                (task.original_brand_name ? 
                                    (task.original_brand_name + (task.original_model_number ? ' ' + task.original_model_number : '')) : 
                                    null) ||
                                'Unknown Device';
                }
                deviceName = escapeHtml(deviceName);
                
                // Better fallback logic for location - check multiple sources
                let location = task.location;
                if (!location || location === 'Unknown') {
                    location = task.original_location || 
                              task.location_name || 
                              (task.department ? task.department : 'Unknown');
                }
                location = escapeHtml(location || 'Unknown');
                const taskType = escapeHtml(getTaskTypeLabel(task.task_type));
                const status = escapeHtml(task.status);
                const scheduledTime = formatDateTime(task.scheduled_date);
                
                let completionInfo = '';
                if (isCompleted && task.status === 'Completed' && task.completed_at) {
                    completionInfo = '<div style="margin-top: 0.5rem; font-size: 0.875rem; color: var(--text-secondary, #cbd5e1);">';
                    // Show completed by username - should always be present for new completions
                    if (task.completed_by_username) {
                        completionInfo += '<div><strong>Completed by:</strong> ' + escapeHtml(task.completed_by_username) + '</div>';
                    } else if (task.completed_by_email) {
                        // Fallback to email if username not available
                        completionInfo += '<div><strong>Completed by:</strong> ' + escapeHtml(task.completed_by_email) + '</div>';
                    }
                    // Note: We removed "Not recorded" message since completed_by should always be set for authenticated completions
                    completionInfo += '<div><strong>Completed:</strong> ' + formatDateTime(task.completed_at) + '</div>';
                    if (task.completion_notes) {
                        completionInfo += '<div style="margin-top: 0.25rem;"><strong>Notes:</strong> ' + escapeHtml(task.completion_notes.substring(0, 150)) + (task.completion_notes.length > 150 ? '...' : '') + '</div>';
                    }
                    completionInfo += '</div>';
                }
                
                return '<tr style="border-bottom: 1px solid var(--border-primary, #333333);">' +
                    '<td style="padding: 0.75rem 1rem; color: var(--text-primary, #ffffff);">' + deviceName + '</td>' +
                    '<td style="padding: 0.75rem 1rem; color: var(--text-secondary, #cbd5e1);">' + location + '</td>' +
                    '<td style="padding: 0.75rem 1rem;"><span class="task-type-badge task-type-' + task.task_type + '">' + taskType + '</span></td>' +
                    '<td style="padding: 0.75rem 1rem;"><span class="status-badge status-' + status.toLowerCase().replace(' ', '-') + '">' + status + '</span>' + completionInfo + '</td>' +
                    '<td style="padding: 0.75rem 1rem; color: var(--text-secondary, #cbd5e1);">' + scheduledTime + '</td>' +
                    '<td style="padding: 0.75rem 1rem; text-align: center;">' +
                    '<button class="btn btn-sm btn-primary" onclick="viewTask(\'' + task.task_id + '\')" style="padding: 0.5rem 1rem; font-size: 0.875rem;">View</button>' +
                    '</td>' +
                    '</tr>';
            }).join('');

            // Use scoped class names to avoid conflicts
            const modalClass = isCompleted 
                ? 'schedule-page-modal modal-completed' 
                : 'schedule-page-modal';
            const contentClass = isCompleted 
                ? 'schedule-page-modal-content modal-content-completed' 
                : 'schedule-page-modal-content';
            
            const modalHTML = 
                '<div class="' + modalClass + '" id="scheduleDayTasksModal">' +
                    '<div class="' + contentClass + '">' +
                        '<div class="schedule-page-modal-header">' +
                            '<h2>' + viewType + ' Tasks - ' + formattedDate + '</h2>' +
                            '<button class="schedule-page-modal-close" onclick="closeDayTasksModal()" aria-label="Close">&times;</button>' +
                        '</div>' +
                        '<div class="schedule-page-modal-body">' +
                            '<div style="margin-bottom: 1rem;">' +
                                '<strong>Total Tasks:</strong> ' + tasks.length +
                            '</div>' +
                            '<table class="data-table" style="width: 100%; border-collapse: collapse;">' +
                                '<thead>' +
                                    '<tr>' +
                                        '<th style="padding: 0.75rem 1rem; text-align: left; border-bottom: 2px solid var(--border-primary, #333333); min-width: 150px;">Device</th>' +
                                        '<th style="padding: 0.75rem 1rem; text-align: left; border-bottom: 2px solid var(--border-primary, #333333); min-width: 120px;">Location</th>' +
                                        '<th style="padding: 0.75rem 1rem; text-align: left; border-bottom: 2px solid var(--border-primary, #333333); min-width: 140px;">Task Type</th>' +
                                        '<th style="padding: 0.75rem 1rem; text-align: left; border-bottom: 2px solid var(--border-primary, #333333); min-width: 200px;">Status</th>' +
                                        '<th style="padding: 0.75rem 1rem; text-align: left; border-bottom: 2px solid var(--border-primary, #333333); min-width: 160px;">Scheduled Time</th>' +
                                        '<th style="padding: 0.75rem 1rem; text-align: center; border-bottom: 2px solid var(--border-primary, #333333); min-width: 100px;">Actions</th>' +
                                    '</tr>' +
                                '</thead>' +
                                '<tbody>' +
                                    tasksHTML +
                                '</tbody>' +
                            '</table>' +
                        '</div>' +
                        '<div class="schedule-page-modal-footer">' +
                            '<button class="btn btn-secondary" onclick="closeDayTasksModal()">Close</button>' +
                        '</div>' +
                    '</div>' +
                '</div>';

            document.body.insertAdjacentHTML('beforeend', modalHTML);
            
            // Add backdrop with scoped class
            const backdrop = document.createElement('div');
            backdrop.className = 'schedule-modal-backdrop';
            backdrop.onclick = closeDayTasksModal;
            document.body.insertBefore(backdrop, document.body.lastChild);
        }

        function closeDayTasksModal() {
            // Use scoped selector to avoid conflicts
            const modal = document.getElementById('scheduleDayTasksModal');
            if (modal) {
                modal.remove();
            }
            const backdrop = document.querySelector('.schedule-modal-backdrop');
            if (backdrop) {
                backdrop.remove();
            }
        }

        function updateCompletedMonthDisplay() {
            const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
                              'July', 'August', 'September', 'October', 'November', 'December'];
            const monthYear = `${monthNames[currentCompletedMonth.getMonth()]} ${currentCompletedMonth.getFullYear()}`;
            document.getElementById('completedMonthYear').textContent = monthYear;
        }

        function refreshSchedule() {
            loadTasks();
            if (currentView === 'calendar') {
                loadOverdueTasks();
                loadCalendar();
            } else if (currentView === 'completed') {
                loadCompletedCalendar();
            }
        }

        function clearFilters() {
            document.getElementById('filterForm').reset();
            loadTasks();
        }

        function exportSchedule() {
            const params = new URLSearchParams();
            const formData = new FormData(document.getElementById('filterForm'));
            
            for (let [key, value] of formData.entries()) {
                if (value) {
                    params.append(key, value);
                }
            }
            
            window.open(`/api/v1/scheduled-tasks/export?${params.toString()}`, '_blank');
        }

        function viewTask(taskId) {
            console.log('viewTask called with taskId:', taskId);
            // Close any existing modals first
            const existingModal = document.getElementById('task-details-modal');
            if (existingModal) {
                existingModal.remove();
            }
            
            // Show task details in a modal
            fetch(`/api/v1/scheduled-tasks/operations.php?task_id=${taskId}`, {
                credentials: 'same-origin'
            })
            .then(response => {
                console.log('Response status:', response.status);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(result => {
                console.log('API result:', result);
                if (result.success) {
                    showTaskDetailsModal(result.data);
                } else {
                    console.error('API returned error:', result.error);
                    showNotification('Error loading task details: ' + (result.error?.message || 'Unknown error'), 'error');
                }
            })
            .catch(error => {
                console.error('Error loading task details:', error);
                showNotification('Error loading task details: ' + error.message, 'error');
            });
        }

        function editTask(taskId) {
            // Load task data and show edit modal
            fetch(`/api/v1/scheduled-tasks/operations.php?task_id=${taskId}`, {
                credentials: 'same-origin'
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    showEditTaskModal(result.data);
                } else {
                    showNotification('Error loading task for editing: ' + (result.error?.message || 'Unknown error'), 'error');
                }
            })
            .catch(error => {
                console.error('Error loading task for editing:', error);
                showNotification('Error loading task for editing', 'error');
            });
        }

        function deleteTask(taskId) {
            showDeleteConfirmationModal(taskId);
        }

        function showDeleteConfirmationModal(taskId) {
            // Close any existing modals first
            const existingModal = document.getElementById('delete-confirmation-modal');
            if (existingModal) {
                existingModal.remove();
            }
            
            const modal = document.createElement('div');
            modal.className = 'schedule-page-modal';
            modal.id = 'delete-confirmation-modal';
            modal.style.cssText = `
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100vw !important;
                height: 100vh !important;
                background: rgba(0, 0, 0, 0.85) !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                z-index: 11000 !important;
                padding: 1rem;
                box-sizing: border-box;
            `;
            
            modal.innerHTML = `
                <div class="schedule-page-modal-content" style="
                    position: relative !important;
                    background: var(--bg-card, #1a1a1a) !important;
                    border: 1px solid var(--border-primary, #333333) !important;
                    border-radius: 0.75rem !important;
                    max-width: 400px !important;
                    width: 90% !important;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5) !important;
                    z-index: 11001 !important;
                ">
                    <div class="schedule-page-modal-header" style="
                        display: flex !important;
                        justify-content: space-between !important;
                        align-items: center !important;
                        padding: 1.5rem !important;
                        border-bottom: 1px solid var(--border-primary, #333333) !important;
                        background: var(--bg-secondary, #0f0f0f) !important;
                    ">
                        <h2 style="margin: 0 !important; color: var(--text-primary, #ffffff) !important;">Confirm Delete</h2>
                        <button class="schedule-page-modal-close" onclick="document.getElementById('delete-confirmation-modal').remove()" aria-label="Close">&times;</button>
                    </div>
                    <div class="schedule-page-modal-body" style="padding: 1.5rem !important;">
                        <div style="margin-bottom: 1.5rem;">
                            <div style="
                                display: flex;
                                align-items: center;
                                gap: 1rem;
                                margin-bottom: 1rem;
                            ">
                                <i class="fas fa-exclamation-triangle" style="
                                    font-size: 2rem;
                                    color: var(--error-red, #ef4444);
                                "></i>
                                <div>
                                    <h3 style="margin: 0; color: var(--text-primary, #ffffff);">Delete Task</h3>
                                    <p style="margin: 0.5rem 0 0 0; color: var(--text-secondary, #cbd5e1);">
                                        Are you sure you want to delete this task? This action cannot be undone.
                                    </p>
                                </div>
                            </div>
                        </div>
                        <div style="display: flex; gap: 0.75rem; justify-content: flex-end;">
                            <button onclick="document.getElementById('delete-confirmation-modal').remove()" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--bg-secondary, #0f0f0f);
                                color: var(--text-secondary, #cbd5e1);
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Cancel</button>
                            <button onclick="confirmDeleteTask('${taskId}')" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--error-red, #ef4444);
                                color: white;
                                border: none;
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Delete Task</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
        }

        function confirmDeleteTask(taskId) {
            fetch(`/api/v1/scheduled-tasks/operations.php?task_id=${taskId}`, {
                method: 'DELETE',
                credentials: 'same-origin'
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    showNotification('Task deleted successfully', 'success');
                    // Close the delete confirmation modal
                    const deleteModal = document.getElementById('delete-confirmation-modal');
                    if (deleteModal) {
                        deleteModal.remove();
                    }
                    loadTasks();
                } else {
                    showNotification('Error deleting task: ' + (result.error?.message || 'Unknown error'), 'error');
                }
            })
            .catch(error => {
                console.error('Error deleting task:', error);
                showNotification('Error deleting task', 'error');
            });
        }

        // Task Details Modal
        function showTaskDetailsModal(task) {
            console.log('showTaskDetailsModal called with task:', task);
            
            // Close any existing modals first
            const existingModal = document.getElementById('task-details-modal');
            if (existingModal) {
                existingModal.remove();
            }
            
            // Also close the day tasks modal if it's open - completely remove it
            closeDayTasksModal();
            
            const modal = document.createElement('div');
            modal.className = 'schedule-page-modal';
            modal.id = 'task-details-modal';
            modal.style.cssText = `
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100vw !important;
                height: 100vh !important;
                background: rgba(0, 0, 0, 0.85) !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                z-index: 11002 !important;
                padding: 1rem;
                box-sizing: border-box;
            `;
            
            modal.innerHTML = `
                <div class="schedule-page-modal-content" style="
                    position: relative !important;
                    background: var(--bg-card, #1a1a1a) !important;
                    border: 1px solid var(--border-primary, #333333) !important;
                    border-radius: 0.75rem !important;
                    max-width: 740px !important;
                    width: 90% !important;
                    max-height: 90vh !important;
                    overflow-y: auto !important;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5) !important;
                    z-index: 11003 !important;
                ">
                    <div class="schedule-page-modal-header" style="
                        display: flex !important;
                        justify-content: space-between !important;
                        align-items: center !important;
                        padding: 1.5rem !important;
                        border-bottom: 1px solid var(--border-primary, #333333) !important;
                        background: var(--bg-secondary, #0f0f0f) !important;
                    ">
                        <h2 style="margin: 0 !important; color: var(--text-primary, #ffffff) !important; font-family: 'Siemens Sans', sans-serif !important;">Task Details</h2>
                        <button class="schedule-page-modal-close" onclick="const m = document.getElementById('task-details-modal'); if(m) m.remove();" style="
                            background: none !important;
                            border: none !important;
                            color: var(--text-secondary, #cbd5e1) !important;
                            font-size: 2rem !important;
                            cursor: pointer !important;
                            padding: 0 !important;
                            width: 2rem !important;
                            height: 2rem !important;
                            display: flex !important;
                            align-items: center !important;
                            justify-content: center !important;
                            border-radius: 0.25rem !important;
                            transition: all 0.2s ease !important;
                            line-height: 1 !important;
                        " aria-label="Close">&times;</button>
                    </div>
                    <div class="schedule-page-modal-body" style="padding: 1.5rem !important;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                            <div>
                                <strong style="color: var(--text-primary, #ffffff);">Task Type:</strong><br>
                                <span style="color: var(--text-secondary, #cbd5e1);">${getTaskTypeLabel(task.task_type)}</span>
                            </div>
                            <div>
                                <strong style="color: var(--text-primary, #ffffff);">Status:</strong><br>
                                <span class="status-badge status-${task.status_class}">${task.status}</span>
                            </div>
                            <div>
                                <strong style="color: var(--text-primary, #ffffff);">Device:</strong><br>
                                <span style="color: var(--text-secondary, #cbd5e1);">${(() => {
                                    const name = (task.device_name && task.device_name !== 'Unknown Device') ? task.device_name
                                        : (task.original_device_name || task.original_hostname || task.hostname || ((task.original_brand_name ? (task.original_brand_name + (task.original_model_number ? (' ' + task.original_model_number) : '')) : '')));
                                    return escapeHtml(name || 'Unidentified Device');
                                })()}</span>
                            </div>
                            <div>
                                <strong style="color: var(--text-primary, #ffffff);">Assigned To:</strong><br>
                                <span style="color: var(--text-secondary, #cbd5e1);">${task.assigned_to_username || 'Unknown'}</span>
                            </div>
                            <div>
                                <strong style="color: var(--text-primary, #ffffff);">Scheduled Date:</strong><br>
                                <span style="color: var(--text-secondary, #cbd5e1);">${new Date(task.scheduled_date).toLocaleString()}</span>
                            </div>
                            <div>
                                <strong style="color: var(--text-primary, #ffffff);">Implementation Date:</strong><br>
                                <span style="color: var(--text-secondary, #cbd5e1);">${task.implementation_date ? new Date(task.implementation_date).toLocaleString() : 'Not set'}</span>
                            </div>
                            <div>
                                <strong style="color: var(--text-primary, #ffffff);">Estimated Downtime:</strong><br>
                                <span style="color: var(--text-secondary, #cbd5e1);">${task.estimated_downtime_display}</span>
                            </div>
                            <div>
                                <strong style="color: var(--text-primary, #ffffff);">Priority Score:</strong><br>
                                <span style="color: var(--text-secondary, #cbd5e1);">${task.priority_score}</span>
                            </div>
                        </div>
                        
                        <!-- Completion Information Section -->
                        ${task.status === 'Completed' && task.completed_at ? `
                        <div style="margin: 1.5rem 0; padding: 1rem; background: var(--bg-secondary, #0f0f0f); border-radius: 0.5rem; border: 1px solid #10b981;">
                            <h3 style="margin: 0 0 1rem 0; color: #10b981; font-size: 1.1rem;">
                                <i class="fas fa-check-circle"></i> Completion Information
                            </h3>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                ${task.completed_by_username || task.completed_by_email ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Completed By:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${escapeHtml(task.completed_by_username || task.completed_by_email || 'Not recorded')}</span>
                                </div>
                                ` : ''}
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Completed Date:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${new Date(task.completed_at).toLocaleString()}</span>
                                </div>
                                ${task.actual_downtime ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Actual Downtime:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.actual_downtime >= 60 ? Math.floor(task.actual_downtime / 60) + 'h ' + (task.actual_downtime % 60) + 'm' : task.actual_downtime + 'm'}</span>
                                </div>
                                ` : ''}
                            </div>
                            ${task.completion_notes ? `
                                <div style="margin-top: 1rem;">
                                    <strong style="color: var(--text-primary, #ffffff);">Completion Notes:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1); white-space: pre-wrap;">${escapeHtml(task.completion_notes)}</span>
                                </div>
                            ` : ''}
                        </div>
                        ` : ''}
                        
                        <!-- Original Information Section -->
                        ${(task.original_fda_recall_number || task.original_cve_id || task.original_patch_name || task.original_action_type) ? `
                        <div style="margin: 1.5rem 0; padding: 1rem; background: var(--bg-secondary, #0f0f0f); border-radius: 0.5rem; border: 1px solid var(--border-primary, #333333);">
                            <h3 style="margin: 0 0 1rem 0; color: var(--text-primary, #ffffff); font-size: 1.1rem;">
                                <i class="fas fa-info-circle"></i> Original Information
                            </h3>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                ${task.original_fda_recall_number ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">FDA Recall Number:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.original_fda_recall_number}</span>
                                </div>
                                ` : ''}
                                ${task.original_manufacturer_name ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Manufacturer:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.original_manufacturer_name}</span>
                                </div>
                                ` : ''}
                                ${task.original_recall_date ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Recall Date:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${new Date(task.original_recall_date).toLocaleDateString()}</span>
                                </div>
                                ` : ''}
                                ${task.original_cve_severity ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">CVE Severity:</strong><br>
                                    <span class="severity-badge severity-${task.original_cve_severity.toLowerCase()}">${task.original_cve_severity}</span>
                                </div>
                                ` : ''}
                                ${task.original_patch_name ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Patch Name:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.original_patch_name}</span>
                                </div>
                                ` : ''}
                                ${task.original_patch_vendor ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Patch Vendor:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.original_patch_vendor}</span>
                                </div>
                                ` : ''}
                                ${task.original_action_type ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Action Type:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.original_action_type}</span>
                                </div>
                                ` : ''}
                                ${task.original_device_name ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Device Name:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.original_device_name}</span>
                                </div>
                                ` : ''}
                                ${task.original_ip_address ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">IP Address:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.original_ip_address}</span>
                                </div>
                                ` : ''}
                                ${task.original_location ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Location:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.original_location}</span>
                                </div>
                                ` : ''}
                                ${task.original_department ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Department:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.original_department}</span>
                                </div>
                                ` : ''}
                                ${task.original_brand_name ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Brand:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.original_brand_name}</span>
                                </div>
                                ` : ''}
                                ${task.original_model_number ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Model:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.original_model_number}</span>
                                </div>
                                ` : ''}
                                ${task.original_hostname ? `
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Hostname:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.original_hostname}</span>
                                </div>
                                ` : ''}
                            </div>
                            ${task.original_product_description ? `
                                <div style="margin-top: 1rem;">
                                    <strong style="color: var(--text-primary, #ffffff);">Product Description:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">${task.original_product_description}</span>
                                </div>
                            ` : ''}
                            ${task.original_reason_for_recall ? `
                                <div style="margin-top: 1rem;">
                                    <strong style="color: var(--text-primary, #ffffff);">Reason for Recall:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">${task.original_reason_for_recall}</span>
                                </div>
                            ` : ''}
                            ${task.original_action_description ? `
                                <div style="margin-top: 1rem;">
                                    <strong style="color: var(--text-primary, #ffffff);">Action Description:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">${task.original_action_description}</span>
                                </div>
                            ` : ''}
                            ${task.original_patch_description ? `
                                <div style="margin-top: 1rem;">
                                    <strong style="color: var(--text-primary, #ffffff);">Patch Description:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">${task.original_patch_description}</span>
                                </div>
                            ` : ''}
                            ${task.original_cve_id ? `
                                <div style="margin-top: 1rem;">
                                    <strong style="color: var(--text-primary, #ffffff);">CVE IDs:</strong><br>
                                    <div style="
                                        color: var(--text-secondary, #cbd5e1); 
                                        font-size: 0.875rem; 
                                        max-height: 120px; 
                                        overflow-y: auto; 
                                        padding: 0.5rem; 
                                        background: rgba(255, 255, 255, 0.05); 
                                        border-radius: 0.375rem; 
                                        border: 1px solid rgba(255, 255, 255, 0.1);
                                        white-space: pre-wrap;
                                        word-break: break-all;
                                    ">${task.original_cve_id}</div>
                                </div>
                            ` : ''}
                        </div>
                        ` : ''}
                        
                        ${task.task_type === 'consolidated_task' ? `
                        <!-- Consolidated Tasks Section -->
                        <div style="margin: 1.5rem 0; padding: 1rem; background: var(--bg-secondary, #0f0f0f); border-radius: 0.5rem; border: 1px solid var(--border-primary, #333333);">
                            <h3 style="margin: 0 0 1rem 0; color: var(--text-primary, #ffffff); font-size: 1.1rem;">
                                <i class="fas fa-compress-arrows-alt"></i> Consolidated Tasks
                            </h3>
                            <div id="consolidated-tasks-list" style="max-height: 300px; overflow-y: auto;">
                                <div style="text-align: center; padding: 2rem; color: var(--text-muted, #94a3b8);">
                                    <i class="fas fa-spinner fa-spin"></i> Loading consolidated tasks...
                                </div>
                            </div>
                        </div>
                        ` : ''}
                        
                        <!-- Approval Tracking Section -->
                        <div style="margin: 1.5rem 0; padding: 1rem; background: var(--bg-secondary, #0f0f0f); border-radius: 0.5rem; border: 1px solid var(--border-primary, #333333);">
                            <h3 style="margin: 0 0 1rem 0; color: var(--text-primary, #ffffff); font-size: 1.1rem;">
                                <i class="fas fa-clipboard-check"></i> Department Approval
                            </h3>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Department Notified:</strong><br>
                                    <span class="approval-badge ${task.department_notified ? 'approved' : 'pending'}">
                                        ${task.department_notified ? 'Yes' : 'No'}
                                    </span>
                                </div>
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Approval Status:</strong><br>
                                    <span class="approval-badge ${getApprovalStatusClass(task.department_approval_status)}">
                                        ${task.department_approval_status || 'Pending'}
                                    </span>
                                </div>
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Approval Contact:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.department_approval_contact || 'Not specified'}</span>
                                </div>
                                <div>
                                    <strong style="color: var(--text-primary, #ffffff);">Approval Date:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.department_approval_date ? new Date(task.department_approval_date).toLocaleString() : 'Not approved'}</span>
                                </div>
                            </div>
                            ${task.department_approval_notes ? `
                                <div style="margin-top: 1rem;">
                                    <strong style="color: var(--text-primary, #ffffff);">Approval Notes:</strong><br>
                                    <span style="color: var(--text-secondary, #cbd5e1);">${task.department_approval_notes}</span>
                                </div>
                            ` : ''}
                        </div>
                        
                        ${task.task_description ? `
                            <div style="margin-bottom: 1rem;">
                                <strong style="color: var(--text-primary, #ffffff);">Description:</strong><br>
                                <span style="color: var(--text-secondary, #cbd5e1);">${task.task_description}</span>
                            </div>
                        ` : ''}
                        ${task.notes ? (() => {
                            const hasDetails = typeof task.notes === 'string' && task.notes.includes('DETAILED TASK INFORMATION:');
                            if (hasDetails) {
                                return `
                                    <div style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
                                        <strong style=\"color: var(--text-primary, #ffffff);\">Notes:</strong>
                                        <span style=\"background: var(--bg-tertiary, #333333); color: var(--text-secondary, #cbd5e1); padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.85rem; border: 1px solid var(--border-secondary, #555555);\">Consolidated task with detailed items</span>
                                        <button onclick=\"showConsolidatedTaskDetails('${task.task_id}')\" class=\"btn btn-primary\" style=\"padding: 0.5rem 1rem; background: var(--siemens-petrol, #009999); color: #fff; border: 1px solid var(--siemens-petrol, #009999); border-radius: 0.5rem; font-weight: 600;\">
                                            <i class=\"fas fa-eye\"></i> View Details
                                        </button>
                                    </div>
                                `;
                            }
                            return `
                                <div style=\"margin-bottom: 1rem;\">
                                    <strong style=\"color: var(--text-primary, #ffffff);\">Notes:</strong><br>
                                    <span style=\"color: var(--text-secondary, #cbd5e1);\">${task.notes}</span>
                                </div>
                            `;
                        })() : ''}
                        
                        <!-- Action Buttons -->
                        <div style="margin-top: 1.5rem; display: flex; gap: 0.75rem; justify-content: flex-end;">
                            ${task.status !== 'Completed' ? `
                            <button onclick="markDepartmentNotified('${task.task_id}')" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--siemens-orange, #ff6b35);
                                color: white;
                                border: none;
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Mark Notified</button>
                            <button onclick="updateApprovalStatus('${task.task_id}')" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--siemens-petrol, #009999);
                                color: white;
                                border: none;
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Update Approval</button>
                            ` : ''}
                            <button onclick="document.getElementById('task-details-modal').remove()" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--bg-secondary, #0f0f0f);
                                color: var(--text-secondary, #cbd5e1);
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Close</button>
                        </div>
                    </div>
                </div>
            `;
            
            // Append to body and ensure it's on top
            document.body.appendChild(modal);
            
            // Force focus and ensure z-index is correct - use higher priority
            setTimeout(() => {
                modal.style.zIndex = '11002';
                modal.style.display = 'flex';
                const content = modal.querySelector('.schedule-page-modal-content');
                if (content) {
                    content.style.zIndex = '11003';
                }
                // Ensure it's visible
                modal.style.visibility = 'visible';
                modal.style.opacity = '1';
            }, 10);
        }

        // Edit Task Modal
        function showEditTaskModal(task) {
            // Close any existing modals first
            const existingModal = document.getElementById('edit-task-modal');
            if (existingModal) {
                existingModal.remove();
            }
            
            const modal = document.createElement('div');
            modal.className = 'schedule-page-modal';
            modal.id = 'edit-task-modal';
            modal.style.cssText = `
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100vw !important;
                height: 100vh !important;
                background: rgba(0, 0, 0, 0.85) !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                z-index: 11000 !important;
                padding: 1rem;
                box-sizing: border-box;
            `;
            
            modal.innerHTML = `
                <div class="schedule-page-modal-content" style="
                    position: relative !important;
                    background: var(--bg-card, #1a1a1a) !important;
                    border: 1px solid var(--border-primary, #333333) !important;
                    border-radius: 0.75rem !important;
                    max-width: 500px !important;
                    width: 90% !important;
                    max-height: 90vh !important;
                    overflow-y: auto !important;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5) !important;
                    z-index: 11001 !important;
                ">
                    <div class="schedule-page-modal-header" style="
                        display: flex !important;
                        justify-content: space-between !important;
                        align-items: center !important;
                        padding: 1.5rem !important;
                        border-bottom: 1px solid var(--border-primary, #333333) !important;
                        background: var(--bg-secondary, #0f0f0f) !important;
                    ">
                        <h2 style="margin: 0 !important; color: var(--text-primary, #ffffff) !important;">Edit Task</h2>
                        <button class="schedule-page-modal-close" onclick="document.getElementById('edit-task-modal').remove()" aria-label="Close">&times;</button>
                    </div>
                    <div class="schedule-page-modal-body" style="padding: 1.5rem !important;">
                    <form id="editTaskForm">
                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary, #ffffff); font-weight: 600;">Status:</label>
                            <select name="status" style="
                                width: 100%;
                                padding: 0.75rem;
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                background: var(--bg-tertiary, #333333);
                                color: var(--text-primary, #ffffff);
                            ">
                                <option value="Scheduled" ${task.status === 'Scheduled' ? 'selected' : ''}>Scheduled</option>
                                <option value="In Progress" ${task.status === 'In Progress' ? 'selected' : ''}>In Progress</option>
                                <option value="Completed" ${task.status === 'Completed' ? 'selected' : ''}>Completed</option>
                                <option value="Cancelled" ${task.status === 'Cancelled' ? 'selected' : ''}>Cancelled</option>
                                <option value="Failed" ${task.status === 'Failed' ? 'selected' : ''}>Failed</option>
                            </select>
                        </div>
                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary, #ffffff); font-weight: 600;">Scheduled Date:</label>
                            <input type="datetime-local" name="scheduled_date" value="${task.scheduled_date ? new Date(task.scheduled_date).toISOString().slice(0, 16) : ''}" style="
                                width: 100%;
                                padding: 0.75rem;
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                background: var(--bg-tertiary, #333333);
                                color: var(--text-primary, #ffffff);
                            ">
                        </div>
                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary, #ffffff); font-weight: 600;">Implementation Date:</label>
                            <input type="datetime-local" name="implementation_date" value="${task.implementation_date ? new Date(task.implementation_date).toISOString().slice(0, 16) : ''}" style="
                                width: 100%;
                                padding: 0.75rem;
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                background: var(--bg-tertiary, #333333);
                                color: var(--text-primary, #ffffff);
                            ">
                        </div>
                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary, #ffffff); font-weight: 600;">Estimated Downtime (minutes):</label>
                            <input type="number" name="estimated_downtime" value="${task.estimated_downtime}" min="0" style="
                                width: 100%;
                                padding: 0.75rem;
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                background: var(--bg-tertiary, #333333);
                                color: var(--text-primary, #ffffff);
                            ">
                        </div>
                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary, #ffffff); font-weight: 600;">Task Description:</label>
                            <textarea name="task_description" rows="3" style="
                                width: 100%;
                                padding: 0.75rem;
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                background: var(--bg-tertiary, #333333);
                                color: var(--text-primary, #ffffff);
                                resize: vertical;
                            ">${task.task_description || ''}</textarea>
                        </div>
                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary, #ffffff); font-weight: 600;">Notes:</label>
                            <textarea name="notes" rows="2" style="
                                width: 100%;
                                padding: 0.75rem;
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                background: var(--bg-tertiary, #333333);
                                color: var(--text-primary, #ffffff);
                                resize: vertical;
                            ">${task.notes || ''}</textarea>
                        </div>
                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary, #ffffff); font-weight: 600;">Completion Notes:</label>
                            <textarea name="completion_notes" rows="2" style="
                                width: 100%;
                                padding: 0.75rem;
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                background: var(--bg-tertiary, #333333);
                                color: var(--text-primary, #ffffff);
                                resize: vertical;
                            ">${task.completion_notes || ''}</textarea>
                        </div>
                    </form>
                    </div>
                    <div class="schedule-page-modal-footer" style="
                        display: flex !important;
                        gap: 1rem !important;
                        justify-content: flex-end !important;
                        padding: 1.5rem !important;
                        border-top: 1px solid var(--border-primary, #333333) !important;
                        background: var(--bg-secondary, #0f0f0f) !important;
                    ">
                        <button type="button" onclick="document.getElementById('edit-task-modal').remove()" style="
                            padding: 0.75rem 1.5rem;
                            background: transparent;
                            color: var(--text-secondary, #cbd5e1);
                            border: 1px solid var(--border-secondary, #555555);
                            border-radius: 0.5rem;
                            cursor: pointer;
                            font-weight: 600;
                        ">Cancel</button>
                        <button type="submit" form="editTaskForm" style="
                            padding: 0.75rem 1.5rem;
                            background: var(--siemens-petrol, #009999);
                            color: white;
                            border: none;
                            border-radius: 0.5rem;
                            cursor: pointer;
                            font-weight: 600;
                        ">Save Changes</button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
            
            // Load consolidated tasks if this is a consolidated task
            if (task.task_type === 'consolidated_task') {
                loadConsolidatedTasks(task.task_id);
            }
            
            // Handle form submission
            document.getElementById('editTaskForm').addEventListener('submit', function(e) {
                e.preventDefault();
                updateTask(task.task_id, new FormData(this));
            });
        }

        // Update task function
        function updateTask(taskId, formData) {
            const updateData = {};
            for (let [key, value] of formData.entries()) {
                if (value) {
                    updateData[key] = value;
                }
            }
            
            fetch(`/api/v1/scheduled-tasks/operations.php?task_id=${taskId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
                body: JSON.stringify(updateData)
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    showNotification('Task updated successfully', 'success');
                    const modal = document.getElementById('edit-task-modal');
                    if (modal) modal.remove();
                    loadTasks();
                } else {
                    showNotification('Error updating task: ' + (result.error?.message || 'Unknown error'), 'error');
                }
            })
            .catch(error => {
                console.error('Error updating task:', error);
                showNotification('Error updating task', 'error');
            });
        }

        // Utility functions
        function getTaskTypeLabel(taskType) {
            const labels = {
                'package_remediation': 'Package',
                'cve_remediation': 'CVE',
                'patch_application': 'Patch',
                'recall_maintenance': 'Recall',
                'consolidated_task': 'Consolidated Task'
            };
            return labels[taskType] || taskType;
        }

        function loadConsolidatedTasks(consolidatedTaskId) {
            fetch(`/api/v1/scheduled-tasks/consolidated-tasks.php?consolidated_task_id=${consolidatedTaskId}`, {
                credentials: 'same-origin'
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    displayConsolidatedTasks(result.data);
                } else {
                    document.getElementById('consolidated-tasks-list').innerHTML = `
                        <div style="text-align: center; padding: 2rem; color: var(--error-red, #ef4444);">
                            <i class="fas fa-exclamation-triangle"></i> Error loading consolidated tasks: ${result.error?.message || 'Unknown error'}
                        </div>
                    `;
                }
            })
            .catch(error => {
                console.error('Error loading consolidated tasks:', error);
                document.getElementById('consolidated-tasks-list').innerHTML = `
                    <div style="text-align: center; padding: 2rem; color: var(--error-red, #ef4444);">
                        <i class="fas fa-exclamation-triangle"></i> Error loading consolidated tasks
                    </div>
                `;
            });
        }

        function displayConsolidatedTasks(tasks) {
            const container = document.getElementById('consolidated-tasks-list');
            
            if (!tasks || tasks.length === 0) {
                container.innerHTML = `
                    <div style="text-align: center; padding: 2rem; color: var(--text-muted, #94a3b8);">
                        <i class="fas fa-info-circle"></i> No consolidated tasks found
                    </div>
                `;
                return;
            }
            
            container.innerHTML = tasks.map(task => `
                <div style="
                    padding: 1rem;
                    margin-bottom: 0.75rem;
                    background: var(--bg-card, #1a1a1a);
                    border: 1px solid var(--border-primary, #333333);
                    border-radius: 0.5rem;
                    border-left: 4px solid var(--siemens-petrol, #009999);
                ">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem;">
                        <div>
                            <div style="font-weight: 600; color: var(--text-primary, #ffffff); margin-bottom: 0.25rem;">
                                ${getTaskTypeLabel(task.task_type)}
                            </div>
                            <div style="font-size: 0.875rem; color: var(--text-secondary, #cbd5e1);">
                                Task ID: ${task.task_id.substring(0, 8)}...
                            </div>
                        </div>
                        <div style="text-align: right;">
                            <span class="status-badge status-${task.status_class || 'pending'}" style="font-size: 0.75rem;">
                                ${task.status}
                            </span>
                        </div>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; font-size: 0.875rem;">
                        <div>
                            <strong style="color: var(--text-primary, #ffffff);">Scheduled:</strong><br>
                            <span style="color: var(--text-secondary, #cbd5e1);">${new Date(task.scheduled_date).toLocaleString()}</span>
                        </div>
                        <div>
                            <strong style="color: var(--text-primary, #ffffff);">Downtime:</strong><br>
                            <span style="color: var(--text-secondary, #cbd5e1);">${task.estimated_downtime_display || 'Unknown'}</span>
                        </div>
                        <div>
                            <strong style="color: var(--text-primary, #ffffff);">Package/CVE:</strong><br>
                            <span style="color: var(--text-secondary, #cbd5e1);">${task.package_cve_display || 'N/A'}</span>
                        </div>
                        <div>
                            <strong style="color: var(--text-primary, #ffffff);">Priority:</strong><br>
                            <span style="color: var(--text-secondary, #cbd5e1);">${task.priority_score || 'N/A'}</span>
                        </div>
                    </div>
                    
                    ${task.task_description ? `
                        <div style="margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--border-primary, #333333);">
                            <strong style="color: var(--text-primary, #ffffff);">Description:</strong><br>
                            <span style="color: var(--text-secondary, #cbd5e1); font-size: 0.875rem;">${escapeHtml(task.task_description)}</span>
                        </div>
                    ` : ''}
                </div>
            `).join('');
        }

        function formatDateTime(dateString) {
            if (!dateString) return 'N/A';
            const date = new Date(dateString);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        }

        function formatDate(dateString) {
            if (!dateString) return 'N/A';
            const date = new Date(dateString);
            return date.toLocaleDateString();
        }

        function formatDuration(minutes) {
            if (!minutes) return '0m';
            const hours = Math.floor(minutes / 60);
            const mins = minutes % 60;
            return hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
        }

        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Function to get approval status CSS class
        function getApprovalStatusClass(status) {
            switch (status) {
                case 'Approved':
                    return 'approved';
                case 'Denied':
                    return 'denied';
                case 'Not Required':
                    return 'not-required';
                case 'Pending':
                default:
                    return 'pending';
            }
        }

        function showError(message) {
            const tbody = document.getElementById('tasksTableBody');
            tbody.innerHTML = `<tr><td colspan="10" class="error-cell">${escapeHtml(message)}</td></tr>`;
        }

        // Approval management functions
        function markDepartmentNotified(taskId) {
            showNotificationConfirmationModal(taskId);
        }

        function showNotificationConfirmationModal(taskId) {
            // Close any existing modals first
            const existingModal = document.getElementById('notification-confirmation-modal');
            if (existingModal) {
                existingModal.remove();
            }
            
            const modal = document.createElement('div');
            modal.className = 'schedule-page-modal';
            modal.id = 'notification-confirmation-modal';
            modal.style.cssText = `
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100vw !important;
                height: 100vh !important;
                background: rgba(0, 0, 0, 0.85) !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                z-index: 11000 !important;
                padding: 1rem;
                box-sizing: border-box;
            `;
            
            modal.innerHTML = `
                <div class="schedule-page-modal-content" style="
                    position: relative !important;
                    background: var(--bg-card, #1a1a1a) !important;
                    border: 1px solid var(--border-primary, #333333) !important;
                    border-radius: 0.75rem !important;
                    max-width: 400px !important;
                    width: 90% !important;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5) !important;
                    z-index: 11001 !important;
                ">
                    <div class="schedule-page-modal-header" style="
                        display: flex !important;
                        justify-content: space-between !important;
                        align-items: center !important;
                        padding: 1.5rem !important;
                        border-bottom: 1px solid var(--border-primary, #333333) !important;
                        background: var(--bg-secondary, #0f0f0f) !important;
                    ">
                        <h2 style="margin: 0 !important; color: var(--text-primary, #ffffff) !important;">Mark Notified</h2>
                        <button class="schedule-page-modal-close" onclick="document.getElementById('notification-confirmation-modal').remove()" aria-label="Close">&times;</button>
                    </div>
                    <div class="schedule-page-modal-body" style="padding: 1.5rem !important;">
                        <div style="margin-bottom: 1.5rem;">
                            <div style="
                                display: flex;
                                align-items: center;
                                gap: 1rem;
                                margin-bottom: 1rem;
                            ">
                                <i class="fas fa-bell" style="
                                    font-size: 2rem;
                                    color: var(--siemens-orange, #ff6b35);
                                "></i>
                                <div>
                                    <h3 style="margin: 0; color: var(--text-primary, #ffffff);">Department Notification</h3>
                                    <p style="margin: 0.5rem 0 0 0; color: var(--text-secondary, #cbd5e1);">
                                        Mark this task as department notified?
                                    </p>
                                </div>
                            </div>
                        </div>
                        <div style="display: flex; gap: 0.75rem; justify-content: flex-end;">
                            <button onclick="document.getElementById('notification-confirmation-modal').remove()" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--bg-secondary, #0f0f0f);
                                color: var(--text-secondary, #cbd5e1);
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Cancel</button>
                            <button onclick="confirmMarkNotified('${taskId}')" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--siemens-orange, #ff6b35);
                                color: white;
                                border: none;
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Mark Notified</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
        }

        function confirmMarkNotified(taskId) {
            fetch(`/api/v1/scheduled-tasks/operations.php?task_id=${taskId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    department_notified: true
                })
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    showNotification('Department marked as notified', 'success');
                    // Close the notification confirmation modal
                    const notificationModal = document.getElementById('notification-confirmation-modal');
                    if (notificationModal) {
                        notificationModal.remove();
                    }
                    // Close the task details modal
                    const taskModal = document.getElementById('task-details-modal');
                    if (taskModal) {
                        taskModal.remove();
                    }
                    loadTasks();
                } else {
                    showNotification('Error updating notification status: ' + (result.error?.message || 'Unknown error'), 'error');
                }
            })
            .catch(error => {
                console.error('Error updating notification status:', error);
                showNotification('Error updating notification status', 'error');
            });
        }

        function updateApprovalStatus(taskId) {
            showApprovalUpdateModal(taskId);
        }

        function showApprovalUpdateModal(taskId) {
            // Close any existing modals first
            const existingModal = document.getElementById('approval-update-modal');
            if (existingModal) {
                existingModal.remove();
            }
            
            const modal = document.createElement('div');
            modal.className = 'schedule-page-modal';
            modal.id = 'approval-update-modal';
            modal.style.cssText = `
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100vw !important;
                height: 100vh !important;
                background: rgba(0, 0, 0, 0.85) !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                z-index: 11000 !important;
                padding: 1rem;
                box-sizing: border-box;
            `;
            
            modal.innerHTML = `
                <div class="schedule-page-modal-content" style="
                    position: relative !important;
                    background: var(--bg-card, #1a1a1a) !important;
                    border: 1px solid var(--border-primary, #333333) !important;
                    border-radius: 0.75rem !important;
                    max-width: 500px !important;
                    width: 90% !important;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5) !important;
                    z-index: 11001 !important;
                ">
                    <div class="schedule-page-modal-header" style="
                        display: flex !important;
                        justify-content: space-between !important;
                        align-items: center !important;
                        padding: 1.5rem !important;
                        border-bottom: 1px solid var(--border-primary, #333333) !important;
                        background: var(--bg-secondary, #0f0f0f) !important;
                    ">
                        <h2 style="margin: 0 !important; color: var(--text-primary, #ffffff) !important;">Update Approval Status</h2>
                        <button class="schedule-page-modal-close" onclick="document.getElementById('approval-update-modal').remove()" aria-label="Close">&times;</button>
                    </div>
                    <div class="schedule-page-modal-body" style="padding: 1.5rem !important;">
                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary, #ffffff); font-weight: 600;">
                                Approval Status:
                            </label>
                            <select id="approvalStatus" style="
                                width: 100%;
                                padding: 0.75rem;
                                border: 1px solid var(--border-primary, #333333);
                                border-radius: 0.5rem;
                                background: var(--bg-card, #1a1a1a);
                                color: var(--text-primary, #ffffff);
                                font-size: 1rem;
                            ">
                                <option value="">Select status...</option>
                                <option value="Approved">Approved</option>
                                <option value="Denied">Denied</option>
                                <option value="Not Required">Not Required</option>
                            </select>
                        </div>
                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary, #ffffff); font-weight: 600;">
                                Approval Contact:
                            </label>
                            <input type="text" id="approvalContact" placeholder="Enter contact person name" style="
                                width: 100%;
                                padding: 0.75rem;
                                border: 1px solid var(--border-primary, #333333);
                                border-radius: 0.5rem;
                                background: var(--bg-card, #1a1a1a);
                                color: var(--text-primary, #ffffff);
                                font-size: 1rem;
                            ">
                        </div>
                        <div style="margin-bottom: 1.5rem;">
                            <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary, #ffffff); font-weight: 600;">
                                Approval Notes (Optional):
                            </label>
                            <textarea id="approvalNotes" placeholder="Enter any additional notes..." rows="3" style="
                                width: 100%;
                                padding: 0.75rem;
                                border: 1px solid var(--border-primary, #333333);
                                border-radius: 0.5rem;
                                background: var(--bg-card, #1a1a1a);
                                color: var(--text-primary, #ffffff);
                                font-size: 1rem;
                                resize: vertical;
                            "></textarea>
                        </div>
                        <div style="display: flex; gap: 0.75rem; justify-content: flex-end;">
                            <button onclick="document.getElementById('approval-update-modal').remove()" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--bg-secondary, #0f0f0f);
                                color: var(--text-secondary, #cbd5e1);
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Cancel</button>
                            <button onclick="submitApprovalUpdate('${taskId}')" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--siemens-petrol, #009999);
                                color: white;
                                border: none;
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Update Approval</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
        }

        function submitApprovalUpdate(taskId) {
            const status = document.getElementById('approvalStatus').value;
            const contact = document.getElementById('approvalContact').value;
            const notes = document.getElementById('approvalNotes').value;
            
            if (!status) {
                showNotification('Please select an approval status', 'error');
                return;
            }
            
            if (!['Approved', 'Denied', 'Not Required'].includes(status)) {
                showNotification('Invalid status. Please use: Approved, Denied, or Not Required', 'error');
                return;
            }
            
            fetch(`/api/v1/scheduled-tasks/operations.php?task_id=${taskId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    department_approval_status: status,
                    department_approval_contact: contact,
                    department_approval_notes: notes
                })
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    showNotification('Approval status updated successfully', 'success');
                    // Close the approval update modal
                    const approvalModal = document.getElementById('approval-update-modal');
                    if (approvalModal) {
                        approvalModal.remove();
                    }
                    // Find and remove the specific task details modal
                    const modal = document.getElementById('task-details-modal');
                    if (modal) {
                        modal.remove();
                    }
                    loadTasks();
                } else {
                    showNotification('Error updating approval status: ' + (result.error?.message || 'Unknown error'), 'error');
                }
            })
            .catch(error => {
                console.error('Error updating approval status:', error);
                showNotification('Error updating approval status', 'error');
            });
        }

        // Action dropdown functions
        function toggleScheduleDropdown(taskId) {
            // Close all other dropdowns first
            document.querySelectorAll('.dropdown-menu').forEach(dropdown => {
                if (dropdown.id !== `dropdown-${taskId}`) {
                    dropdown.classList.remove('show');
                }
            });
            
            // Toggle current dropdown
            const dropdown = document.getElementById(`dropdown-${taskId}`);
            if (dropdown) {
                dropdown.classList.toggle('show');
            }
        }

        // Close dropdowns when clicking outside
        document.addEventListener('click', function(event) {
            if (!event.target.closest('.action-dropdown')) {
                document.querySelectorAll('.dropdown-menu').forEach(dropdown => {
                    dropdown.classList.remove('show');
                });
            }
        });

        // Consolidation panel functions
        function toggleConsolidationPanel() {
            const panel = document.getElementById('consolidationPanel');
            if (panel.style.display === 'none') {
                panel.style.display = 'block';
                loadConsolidationOpportunities();
            } else {
                panel.style.display = 'none';
            }
        }

        async function loadConsolidationOpportunities() {
            const content = document.getElementById('consolidationContent');
            content.innerHTML = '<div class="loading-message"><i class="fas fa-spinner fa-spin"></i> Loading consolidation opportunities...</div>';
            
            try {
                const response = await fetch('/api/v1/scheduled-tasks/consolidation-opportunities.php', {
                    credentials: 'same-origin'
                });
                const result = await response.json();
                
                if (result.success) {
                    displayConsolidationOpportunities(result.data);
                } else {
                    content.innerHTML = '<div class="error-message">Failed to load consolidation opportunities</div>';
                }
            } catch (error) {
                console.error('Error loading consolidation opportunities:', error);
                content.innerHTML = '<div class="error-message">Error loading consolidation opportunities</div>';
            }
        }

        function displayConsolidationOpportunities(opportunities) {
            const content = document.getElementById('consolidationContent');
            
            if (opportunities.length === 0) {
                content.innerHTML = '<div class="empty-message">No consolidation opportunities found</div>';
                return;
            }

            content.innerHTML = opportunities.map((opp, index) => {
                // Calculate time spread in minutes
                const earliest = new Date(opp.earliest_time);
                const latest = new Date(opp.latest_time);
                const timeSpreadMinutes = Math.round((latest - earliest) / (1000 * 60));
                
                return `
                <div class="consolidation-opportunity" data-opportunity-index="${index}">
                    <div class="opportunity-header">
                        <div class="asset-info">
                            <div class="asset-name">${escapeHtml(opp.device_name || 'Unknown Device')}</div>
                            <div class="task-count">${opp.task_count} tasks available for consolidation</div>
                        </div>
                        <div class="location-info">
                            <i class="fas fa-map-marker-alt"></i> ${escapeHtml(opp.location || 'Unknown Location')} 
                            <span class="department">• ${escapeHtml(opp.department || 'Unknown Department')}</span>
                        </div>
                    </div>
                    
                    <div class="task-selection">
                        <div class="selection-header">
                            <label class="select-all-checkbox">
                                <input type="checkbox" id="select-all-${index}" onchange="toggleAllTasks(${index})">
                                <span class="checkmark"></span>
                                Select All Tasks
                            </label>
                            <div class="time-range">
                                <i class="fas fa-clock"></i> 
                                ${formatDateTime(opp.earliest_time)} - ${formatDateTime(opp.latest_time)}
                                <span class="time-spread">(${timeSpreadMinutes}min spread)</span>
                            </div>
                        </div>
                        
                <div class="task-list" id="task-list-${index}" data-task-details='${JSON.stringify(opp.task_details).replace(/'/g, '&#39;')}'>
                    ${renderTaskSelectionList(opp.task_details, opp.task_ids, index, opp.task_types, opp.packages, opp.cves, opp.approval_statuses, opp.assigned_to_username, opp.package_cve_displays)}
                </div>
                    </div>
                    
                <div class="consolidation-actions">
                    <button class="consolidate-selected-btn" onclick="consolidateSelectedTasks(${index})" disabled>
                        <i class="fas fa-compress-arrows-alt"></i> Consolidate Selected Tasks
                    </button>
                    <button class="view-details-btn" id="view-details-${index}" style="display:none; margin-left: 0.75rem; padding: 0.5rem 1rem; background: var(--siemens-petrol, #009999); color: #fff; border: 1px solid var(--siemens-petrol, #009999); border-radius: 0.5rem; font-weight: 600; cursor: pointer;">
                        <i class="fas fa-eye"></i> View Details
                    </button>
                    <div class="selected-count" id="selected-count-${index}">0 tasks selected</div>
                </div>
                </div>
                `;
            }).join('');
        }

        function renderTaskSelectionList(taskDetails, taskIds, opportunityIndex, taskTypes, packages, cves, approvalStatuses, assignedToUsername, packageCveDisplays) {
            // If taskDetails is empty or not available, create basic task items from taskIds
            if (!taskDetails || !Array.isArray(taskDetails) || taskDetails.length === 0) {
                if (!taskIds || !Array.isArray(taskIds)) {
                    return '<div class="no-tasks">No task details available</div>';
                }
                
                // Create detailed task items from available data
                return taskIds.map((taskId, taskIndex) => {
                    const taskType = taskTypes && taskTypes[taskIndex] ? taskTypes[taskIndex] : 'Maintenance Task';
                    const packageCveDisplay = packageCveDisplays && packageCveDisplays[taskIndex] ? packageCveDisplays[taskIndex] : '';
                    const approvalStatus = approvalStatuses && approvalStatuses[taskIndex] ? approvalStatuses[taskIndex] : 'Pending';
                    const assignedTo = assignedToUsername || 'Unassigned';
                    
                    return `
                        <div class="task-item">
                            <label class="task-checkbox">
                                <input type="checkbox" 
                                       id="task-${opportunityIndex}-${taskIndex}" 
                                       value="${taskId}"
                                       onchange="updateConsolidationButton(${opportunityIndex})">
                                <span class="checkmark"></span>
                            </label>
                            <div class="task-details">
                                <div class="task-header">
                                    <div class="task-type">${escapeHtml(taskType)}</div>
                                    <div class="task-assigned">Assigned to: ${escapeHtml(assignedTo)}</div>
                                </div>
                                <div class="task-info">
                                    ${packageCveDisplay ? `<span class="task-work">${escapeHtml(packageCveDisplay)}</span>` : ''}
                                </div>
                                <div class="task-status">
                                    <span class="task-status-badge status-scheduled">Scheduled</span>
                                    <span class="approval-status-badge approval-${approvalStatus.toLowerCase()}">${escapeHtml(approvalStatus)}</span>
                                </div>
                            </div>
                        </div>
                    `;
                }).join('');
            }
            
            // If we have task details, use them
            return taskDetails.map((taskDetail, taskIndex) => {
                let taskId, taskType, scheduledDate, packageCveDisplay, estimatedDowntime, status, departmentApprovalStatus;
                
                if (typeof taskDetail === 'object') {
                    // Task detail is an object
                    taskId = taskDetail.task_id || '';
                    taskType = taskDetail.task_type || 'Unknown';
                    scheduledDate = taskDetail.scheduled_date || '';
                    packageCveDisplay = taskDetail.package_cve_display || '';
                    estimatedDowntime = taskDetail.estimated_downtime || 0;
                    status = taskDetail.status || 'Unknown';
                    departmentApprovalStatus = taskDetail.department_approval_status || 'Pending';
                } else {
                    // Task detail is a string (legacy format)
                    const parts = taskDetail.split('|');
                    taskId = parts[0] || '';
                    taskType = parts[1] || 'Unknown';
                    scheduledDate = parts[2] || '';
                    packageCveDisplay = parts[3] || '';
                    estimatedDowntime = parts[5] || '0';
                    status = parts[6] || 'Unknown';
                    departmentApprovalStatus = parts[7] || 'Pending';
                }
                
                return `
                    <div class="task-item">
                        <label class="task-checkbox">
                            <input type="checkbox" 
                                   id="task-${opportunityIndex}-${taskIndex}" 
                                   value="${taskId}"
                                   onchange="updateConsolidationButton(${opportunityIndex})">
                            <span class="checkmark"></span>
                        </label>
                        <div class="task-details">
                            <div class="task-header">
                                <div class="task-type">${escapeHtml(taskType)}</div>
                                <div class="task-date">${formatDateTime(scheduledDate)}</div>
                            </div>
                            <div class="task-info">
                                ${packageCveDisplay ? `<span class="task-work">${escapeHtml(packageCveDisplay)}</span>` : ''}
                                <span class="task-duration">${formatDuration(parseInt(estimatedDowntime))}</span>
                            </div>
                            <div class="task-status">
                                <span class="task-status-badge status-${status.toLowerCase().replace(' ', '-')}">${escapeHtml(status)}</span>
                                <span class="approval-status-badge approval-${departmentApprovalStatus.toLowerCase()}">${escapeHtml(departmentApprovalStatus)}</span>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }

        function toggleAllTasks(opportunityIndex) {
            const selectAllCheckbox = document.getElementById(`select-all-${opportunityIndex}`);
            const taskCheckboxes = document.querySelectorAll(`#task-list-${opportunityIndex} input[type="checkbox"]`);
            
            taskCheckboxes.forEach(checkbox => {
                checkbox.checked = selectAllCheckbox.checked;
            });
            
            updateConsolidationButton(opportunityIndex);
        }

function getConsolidationMaxSpreadHours() {
    const input = document.getElementById('max_spread_hours');
    const stored = localStorage.getItem('dave_max_spread_hours');
    // Initialize input from storage once UI exists
    if (input && stored && !input.dataset._initialized) {
        input.value = stored;
        input.dataset._initialized = '1';
    }
    const val = input && input.value ? parseInt(input.value, 10) : (stored ? parseInt(stored, 10) : 72);
    return Number.isFinite(val) && val >= 0 ? val : 72;
}

// Persist user change
document.addEventListener('input', (e) => {
    if (e.target && e.target.id === 'max_spread_hours') {
        const v = parseInt(e.target.value, 10);
        if (Number.isFinite(v) && v >= 0) {
            localStorage.setItem('dave_max_spread_hours', String(v));
        }
    }
});

function updateConsolidationButton(opportunityIndex) {
    const opportunityEl = document.querySelector(`[data-opportunity-index="${opportunityIndex}"]`);
    const taskCheckboxes = document.querySelectorAll(`#task-list-${opportunityIndex} input[type="checkbox"]`);
    const selectedTasks = Array.from(taskCheckboxes).filter(cb => cb.checked);
    const consolidateBtn = document.querySelector(`[data-opportunity-index="${opportunityIndex}"] .consolidate-selected-btn`);
    const selectedCount = document.getElementById(`selected-count-${opportunityIndex}`);
    const warningId = `spread-warning-${opportunityIndex}`;
    let warningEl = opportunityEl ? opportunityEl.querySelector(`#${warningId}`) : null;
    
    if (selectedTasks.length >= 2) {
        consolidateBtn.disabled = false;
        consolidateBtn.onclick = () => consolidateSelectedTasks(opportunityIndex);
    } else {
        consolidateBtn.disabled = true;
        consolidateBtn.onclick = null;
    }
    
    selectedCount.textContent = `${selectedTasks.length} tasks selected`;

    // Compute time spread across selected tasks and show visual warning if exceeding threshold
    try {
        const allDetailsAttr = document.querySelector(`#task-list-${opportunityIndex}`)?.getAttribute('data-task-details') || '[]';
        const allDetails = JSON.parse(allDetailsAttr);
        const selectedIds = new Set(selectedTasks.map(cb => cb.value));
        const selectedDetails = allDetails.filter(td => selectedIds.has(td.task_id));
        if (selectedDetails.length >= 2) {
            const times = selectedDetails.map(td => new Date(td.scheduled_date).getTime()).filter(Boolean);
            if (times.length >= 2) {
                const minT = Math.min(...times);
                const maxT = Math.max(...times);
                const threshold = getConsolidationMaxSpreadHours();
                const spreadHours = Math.round((maxT - minT) / (1000 * 60 * 60));
                if (spreadHours > threshold) {
                    if (!warningEl && opportunityEl) {
                        warningEl = document.createElement('div');
                        warningEl.id = warningId;
                        warningEl.style.cssText = 'margin-top: 0.5rem; color: var(--siemens-orange, #ff6b35); font-weight: 600;';
                        selectedCount.insertAdjacentElement('afterend', warningEl);
                    }
                    if (warningEl) {
                        warningEl.textContent = `Warning: Selected tasks span ${spreadHours}h which exceeds the ${threshold}h threshold.`;
                    }
                } else if (warningEl) {
                    warningEl.remove();
                }
            }
        } else if (warningEl) {
            warningEl.remove();
        }
    } catch (e) {
        // ignore
    }
}

        function consolidateSelectedTasks(opportunityIndex) {
            const taskCheckboxes = document.querySelectorAll(`#task-list-${opportunityIndex} input[type="checkbox"]`);
            const selectedTaskIds = Array.from(taskCheckboxes)
                .filter(cb => cb.checked)
                .map(cb => cb.value);
            
            if (selectedTaskIds.length >= 2) {
                showConsolidationConfirmationModal(selectedTaskIds, opportunityIndex);
            } else {
                showNotification('Please select at least 2 tasks to consolidate', 'error');
            }
        }

        async function consolidateTasks(taskIds, opportunityIndex) {
            showConsolidationConfirmationModal(taskIds, opportunityIndex);
        }

        function showConsolidationConfirmationModal(taskIds, opportunityIndex) {
            // Close any existing modals first
            const existingModal = document.getElementById('consolidation-confirmation-modal');
            if (existingModal) {
                existingModal.remove();
            }
            
            const modal = document.createElement('div');
            modal.className = 'schedule-page-modal';
            modal.id = 'consolidation-confirmation-modal';
            modal.style.cssText = `
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100vw !important;
                height: 100vh !important;
                background: rgba(0, 0, 0, 0.85) !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                z-index: 11000 !important;
                padding: 1rem;
                box-sizing: border-box;
            `;
            
            modal.innerHTML = `
                <div class="schedule-page-modal-content" style="
                    position: relative !important;
                    background: var(--bg-card, #1a1a1a) !important;
                    border: 1px solid var(--border-primary, #333333) !important;
                    border-radius: 0.75rem !important;
                    max-width: 500px !important;
                    width: 90% !important;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5) !important;
                    z-index: 11001 !important;
                ">
                    <div class="schedule-page-modal-header" style="
                        display: flex !important;
                        justify-content: space-between !important;
                        align-items: center !important;
                        padding: 1.5rem !important;
                        border-bottom: 1px solid var(--border-primary, #333333) !important;
                        background: var(--bg-secondary, #0f0f0f) !important;
                    ">
                        <h2 style="margin: 0 !important; color: var(--text-primary, #ffffff) !important;">Consolidate Tasks</h2>
                        <button class="schedule-page-modal-close" onclick="document.getElementById('consolidation-confirmation-modal').remove()" aria-label="Close">&times;</button>
                    </div>
                    <div class="schedule-page-modal-body" style="padding: 1.5rem !important;">
                        <div style="margin-bottom: 1.5rem;">
                            <div style="
                                display: flex;
                                align-items: center;
                                gap: 1rem;
                                margin-bottom: 1rem;
                            ">
                                <i class="fas fa-compress-arrows-alt" style="
                                    font-size: 2rem;
                                    color: var(--siemens-petrol, #009999);
                                "></i>
                                <div>
                                    <h3 style="margin: 0; color: var(--text-primary, #ffffff);">Task Consolidation</h3>
                                    <p style="margin: 0.5rem 0 0 0; color: var(--text-secondary, #cbd5e1);">
                                        Consolidate ${taskIds.length} tasks on the same device?
                                    </p>
                                    <p style="margin: 0.5rem 0 0 0; color: var(--text-muted, #94a3b8); font-size: 0.875rem;">
                                        This will combine multiple tasks into a single consolidated task for better efficiency.
                                    </p>
                                </div>
                            </div>
                        </div>
                        <div style="display: flex; gap: 0.75rem; justify-content: flex-end;">
                            <button onclick="document.getElementById('consolidation-confirmation-modal').remove()" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--bg-secondary, #0f0f0f);
                                color: var(--text-secondary, #cbd5e1);
                                border: 1px solid var(--border-secondary, #555555);
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Cancel</button>
                            <button onclick="confirmConsolidateTasks(${JSON.stringify(taskIds).replace(/"/g, '&quot;')}, ${opportunityIndex})" style="
                                padding: 0.75rem 1.5rem;
                                background: var(--siemens-petrol, #009999);
                                color: white;
                                border: none;
                                border-radius: 0.5rem;
                                cursor: pointer;
                                font-weight: 600;
                            ">Consolidate Tasks</button>
                        </div>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
        }

        async function confirmConsolidateTasks(taskIds, opportunityIndex) {

            try {
                const response = await fetch('/api/v1/scheduled-tasks/consolidate.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({
                        task_ids: taskIds
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification(`Successfully consolidated ${taskIds.length} tasks`, 'success');
                    // Close the consolidation confirmation modal
                    const consolidationModal = document.getElementById('consolidation-confirmation-modal');
                    if (consolidationModal) {
                        consolidationModal.remove();
                    }
                    // Reveal the View Details button for this opportunity with the new consolidated task id
                    try {
                        const consolidatedId = result?.data?.consolidated_task_id || result?.data?.consolidated_task?.task_id;
                        const viewBtn = document.getElementById(`view-details-${opportunityIndex}`);
                        if (consolidatedId && viewBtn) {
                            viewBtn.style.display = 'inline-block';
                            viewBtn.onclick = () => showConsolidatedTaskDetails(consolidatedId);
                        }
                    } catch (e) {
                        console.warn('Unable to wire View Details button:', e);
                    }
                    loadConsolidationOpportunities();
                    loadTasks();
                } else {
                    showNotification('Error consolidating tasks: ' + (result.error?.message || 'Unknown error'), 'error');
                }
            } catch (error) {
                console.error('Error consolidating tasks:', error);
                showNotification('Error consolidating tasks', 'error');
            }
        }

        function showConsolidatedTaskDetails(taskId) {
            fetch(`/api/v1/scheduled-tasks/consolidated-task-details.php?task_id=${taskId}`, {
                credentials: 'same-origin'
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    displayConsolidatedTaskModal(result.data);
                } else {
                    showNotification('Error loading consolidated task details: ' + (result.error?.message || 'Unknown error'), 'error');
                }
            })
            .catch(error => {
                console.error('Error loading consolidated task details:', error);
                showNotification('Error loading consolidated task details', 'error');
            });
        }

        function displayConsolidatedTaskModal(data) {
            // Close any existing modals first
            const existingModal = document.getElementById('consolidated-task-details-modal');
            if (existingModal) {
                existingModal.remove();
            }
            closeDayTasksModal();
            
            const modal = document.createElement('div');
            modal.className = 'schedule-page-modal';
            modal.id = 'consolidated-task-details-modal';
            modal.style.cssText = `
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100vw !important;
                height: 100vh !important;
                background: rgba(0, 0, 0, 0.85) !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                z-index: 11001 !important;
                padding: 1rem;
                box-sizing: border-box;
            `;
            
            const task = data.task;
            const details = data.detailed_information || [];
            
            modal.innerHTML = `
                <div class="schedule-page-modal-content" style="
                    position: relative !important;
                    background: var(--bg-card, #1a1a1a) !important;
                    border-radius: 0.75rem !important;
                    padding: 2rem !important;
                    max-width: 90vw !important;
                    max-height: 90vh !important;
                    overflow-y: auto !important;
                    border: 1px solid var(--border-primary, #333333) !important;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5) !important;
                    z-index: 11002 !important;
                ">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                        <h2 style="color: var(--text-primary, #f8fafc); margin: 0; font-size: 1.5rem;">
                            <i class="fas fa-compress-arrows-alt" style="color: var(--siemens-petrol, #009999); margin-right: 0.5rem;"></i>
                            Consolidated Task Details
                        </h2>
                        <button onclick="closeConsolidatedTaskModal()" style="
                            background: none;
                            border: none;
                            color: var(--text-secondary, #cbd5e1);
                            font-size: 1.5rem;
                            cursor: pointer;
                            padding: 0.5rem;
                        ">×</button>
                    </div>
                    
                    <div style="margin-bottom: 1.5rem; padding: 1rem; background: var(--bg-tertiary, #333333); border-radius: 0.5rem;">
                        <h3 style="color: var(--text-primary, #f8fafc); margin: 0 0 0.5rem 0;">Task Overview</h3>
                        <p style="color: var(--text-secondary, #cbd5e1); margin: 0;"><strong>Description:</strong> ${escapeHtml(task.task_description)}</p>
                        <p style="color: var(--text-secondary, #cbd5e1); margin: 0.5rem 0 0 0;"><strong>Scheduled:</strong> ${formatDateTime(task.scheduled_date)}</p>
                        <p style="color: var(--text-secondary, #cbd5e1); margin: 0.5rem 0 0 0;"><strong>Duration:</strong> ${formatDuration(task.estimated_downtime)}</p>
                        <p style="color: var(--text-secondary, #cbd5e1); margin: 0.5rem 0 0 0;"><strong>Status:</strong> ${escapeHtml(task.status)}</p>
                    </div>
                    
                    <div style="margin-bottom: 1.5rem;">
                        <h3 style="color: var(--text-primary, #f8fafc); margin: 0 0 1rem 0;">Individual Task Details (${details.length} tasks)</h3>
                        <div style="display: grid; gap: 1rem;">
                            ${details.map((detail, index) => renderTaskDetail(detail, index)).join('')}
                        </div>
                    </div>
                    
                    <div style="display: flex; justify-content: flex-end; gap: 1rem;">
                        <button onclick="closeConsolidatedTaskModal()" style="
                            padding: 0.75rem 1.5rem;
                            background: var(--bg-tertiary, #333333);
                            color: var(--text-primary, #f8fafc);
                            border: 1px solid var(--border-secondary, #555555);
                            border-radius: 0.5rem;
                            cursor: pointer;
                            font-weight: 600;
                        ">Close</button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
        }

        function renderTaskDetail(detail, index) {
            const orig = detail.original_information || {};
            const action = orig.action || {};
            const cve = orig.cve || {};
            const device = orig.device || {};
            const patch = orig.patch || {};
            const recall = orig.recall || {};
            
            return `
                <div style="
                    background: var(--bg-secondary, #1a1a1a);
                    border: 1px solid var(--border-primary, #333333);
                    border-radius: 0.5rem;
                    padding: 1rem;
                ">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                        <h4 style="color: var(--text-primary, #f8fafc); margin: 0; font-size: 1.1rem;">
                            Task ${index + 1}: ${escapeHtml(detail.task_type.replace('_', ' ').toUpperCase())}
                        </h4>
                        <span style="
                            background: var(--siemens-petrol, #009999);
                            color: white;
                            padding: 0.25rem 0.5rem;
                            border-radius: 0.25rem;
                            font-size: 0.75rem;
                            font-weight: 600;
                        ">${formatDuration(detail.estimated_downtime)}</span>
                    </div>
                    
                    <p style="color: var(--text-secondary, #cbd5e1); margin: 0 0 0.75rem 0; font-size: 0.9rem;">
                        ${escapeHtml(detail.task_description)}
                    </p>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem; font-size: 0.85rem;">
                        ${renderDetailSection('CVE Information', cve, ['id', 'description', 'severity', 'cvss_v3_score'])}
                        ${renderDetailSection('Device Information', device, ['name', 'brand_name', 'model_number', 'k_number', 'location'])}
                        ${renderDetailSection('Patch Information', patch, ['name', 'type', 'vendor', 'version', 'description', 'release_date', 'kb_article', 'download_url', 'install_instructions', 'prerequisites', 'estimated_install_time', 'requires_reboot'])}
                        ${renderDetailSection('Recall Information', recall, ['fda_recall_number', 'manufacturer_name', 'product_description', 'recall_date'])}
                        ${renderDetailSection('Action Information', action, ['type', 'description', 'vendor', 'target_version'])}
                    </div>
                </div>
            `;
        }

        function renderDetailSection(title, data, fields) {
            const hasData = fields.some(field => data[field] && data[field] !== '');
            if (!hasData) return '';
            
            return `
                <div style="background: var(--bg-tertiary, #333333); padding: 0.75rem; border-radius: 0.375rem;">
                    <h5 style="color: var(--siemens-orange, #ff6b35); margin: 0 0 0.5rem 0; font-size: 0.8rem; font-weight: 600;">${title}</h5>
                    ${fields.map(field => {
                        const value = data[field];
                        if (!value || value === '') return '';
                        if (field === 'download_url') {
                            return `<div style="margin-bottom: 0.25rem;">
                                <span style="color: var(--text-muted, #94a3b8); font-weight: 500;">Download URL:</span>
                                <a href="${escapeHtml(String(value))}" target="_blank" rel="noopener" class="brand-link" style="margin-left: 0.5rem;">Open link</a>
                            </div>`;
                        }
                        return `<div style="margin-bottom: 0.25rem;">
                            <span style="color: var(--text-muted, #94a3b8); font-weight: 500;">${field.replace('_', ' ')}:</span>
                            <span style="color: var(--text-secondary, #cbd5e1); margin-left: 0.5rem;">${escapeHtml(String(value))}</span>
                        </div>`;
                    }).join('')}
                </div>
            `;
        }

        function closeConsolidatedTaskModal() {
            const modal = document.getElementById('consolidated-task-details-modal');
            if (modal) {
                modal.remove();
            }
        }

        function showNotification(message, type) {
            // Simple notification system
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <div class="notification-content">
                    <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                    <span>${message}</span>
                </div>
            `;
            document.body.appendChild(notification);
            
            // Add show class for animation
            setTimeout(() => notification.classList.add('show'), 100);
            
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        }
    </script>

</body>
</html>
