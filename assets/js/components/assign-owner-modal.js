/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

class AssignOwnerModal {
    constructor() {
        this.modal = null;
        this.devices = [];
        this.users = [];
        this.selectedDevices = new Set();
        this.patchData = null;
        this.taskContext = {
            taskType: null,
            packageId: null,
            cveId: null,
            actionId: null
        };
    }

    /**
     * Initialize the modal
     */
    init() {
        this.createModal();
        this.loadUsers();
        this.setupEventListeners();
    }

    /**
     * Show modal for package remediation
     */
    showForPackage(packageId, devices) {
        this.taskContext = {
            taskType: 'package_remediation',
            packageId: packageId,
            cveId: null,
            actionId: null
        };
        this.devices = devices;
        this.selectedDevices.clear();
        this.show();
    }

    /**
     * Show modal for CVE remediation
     */
    showForCVE(cveId, actionId, devices) {
        console.log('showForCVE called with:', { cveId, actionId, devices });
        
        this.taskContext = {
            taskType: 'cve_remediation',
            packageId: null,
            cveId: cveId,
            actionId: actionId
        };
        this.devices = devices;
        this.selectedDevices.clear();
        
        console.log('About to call show() method');
        this.show();
        console.log('show() method completed');
    }

    /**
     * Show modal for patch application
     */
    showForPatch(patchId, devices) {
        this.taskContext = {
            taskType: 'patch_application',
            packageId: null,
            cveId: null,
            actionId: patchId  // Store patch_id in action_id for patch tasks
        };
        this.devices = devices;
        this.selectedDevices.clear();
        this.loadPatchData(patchId);
        this.show();
    }

    /**
     * Create modal HTML structure
     */
    createModal() {
        const modalHTML = `
            <div id="assignOwnerModal" class="modal" style="display: none;">
                <div class="modal-content" style="
                    background: var(--bg-card, #1a1a1a);
                    border: 1px solid var(--border-primary, #333333);
                    border-radius: 0.75rem;
                    max-width: 800px;
                    width: 90%;
                    max-height: 90vh;
                    overflow-y: auto;
                    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.1);
                ">
                    <div class="modal-header" style="
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 1.5rem;
                        border-bottom: 1px solid var(--border-primary, #333333);
                        background: var(--bg-secondary, #0f0f0f);
                    ">
                        <h2 id="modalTitle" style="
                            margin: 0;
                            font-size: 1.5rem;
                            color: var(--text-primary, #ffffff);
                            font-weight: 600;
                        ">Assign Task</h2>
                        <button type="button" class="modal-close" onclick="assignOwnerModal.close()" style="
                            background: transparent;
                            border: none;
                            color: var(--text-secondary, #cbd5e1);
                            font-size: 1.5rem;
                            cursor: pointer;
                            padding: 0.5rem;
                            line-height: 1;
                            transition: color 0.2s;
                        ">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div class="modal-body" style="padding: 1.5rem;">
                        <form id="assignTaskForm">
                            <!-- Device Selection -->
                            <div class="form-group">
                                <label for="deviceSelection">Select Devices <span class="required">*</span></label>
                                <div class="device-selection-container">
                                    <div class="device-selection-header">
                                        <button type="button" class="btn btn-secondary btn-sm" onclick="assignOwnerModal.selectAllDevices()">
                                            <i class="fas fa-check-square"></i> Select All
                                        </button>
                                        <button type="button" class="btn btn-secondary btn-sm" onclick="assignOwnerModal.clearDeviceSelection()">
                                            <i class="fas fa-square"></i> Clear All
                                        </button>
                                        <span class="selected-count">0 devices selected</span>
                                    </div>
                                    <div class="device-list" id="deviceList">
                                        <!-- Devices will be populated here -->
                                    </div>
                                </div>
                            </div>

                            <!-- User Assignment -->
                            <div class="form-group">
                                <label for="assignedTo">Assign To <span class="required">*</span></label>
                                <select id="assignedTo" name="assigned_to" required>
                                    <option value="">Select user...</option>
                                </select>
                            </div>

                            <!-- Scheduled Date -->
                            <div class="form-group">
                                <label for="scheduledDate">Scheduled Date & Time <span class="required">*</span></label>
                                <input type="datetime-local" id="scheduledDate" name="scheduled_date" required>
                            </div>

                            <!-- Implementation Date -->
                            <div class="form-group">
                                <label for="implementationDate">Implementation Date <span class="required">*</span></label>
                                <input type="datetime-local" id="implementationDate" name="implementation_date" required>
                            </div>

                            <!-- Estimated Downtime -->
                            <div class="form-group">
                                <label for="estimatedDowntime">Estimated Downtime (minutes) <span class="required">*</span></label>
                                <div class="downtime-input-group">
                                    <input type="number" id="estimatedDowntime" name="estimated_downtime" min="1" required>
                                    <button type="button" class="btn btn-secondary btn-sm" onclick="assignOwnerModal.calculateDowntime()">
                                        <i class="fas fa-calculator"></i> Auto-calculate
                                    </button>
                                </div>
                                <small class="form-help">Auto-calculation based on patch estimated install time</small>
                            </div>

                            <!-- Task Description -->
                            <div class="form-group">
                                <label for="taskDescription">Task Description</label>
                                <textarea id="taskDescription" name="task_description" rows="3" 
                                    placeholder="Describe the remediation task..."></textarea>
                            </div>

                            <!-- Notes -->
                            <div class="form-group">
                                <label for="notes">Notes</label>
                                <textarea id="notes" name="notes" rows="2" 
                                    placeholder="Additional notes or instructions..."></textarea>
                            </div>

                            <!-- Form Actions -->
                            <div class="form-actions" style="
                                display: flex;
                                justify-content: flex-end;
                                gap: 1rem;
                                padding-top: 1.5rem;
                                border-top: 1px solid var(--border-primary, #333333);
                                margin-top: 1.5rem;
                            ">
                                <button type="button" class="btn btn-secondary" onclick="assignOwnerModal.close()" style="
                                    padding: 0.75rem 1.5rem;
                                    background: transparent;
                                    color: var(--text-secondary, #cbd5e1);
                                    border: 1px solid var(--border-secondary, #555555);
                                    border-radius: 0.5rem;
                                    cursor: pointer;
                                    font-weight: 600;
                                    transition: all 0.2s;
                                ">
                                    <i class="fas fa-times"></i> Cancel
                                </button>
                                <button type="submit" class="btn btn-primary" style="
                                    padding: 0.75rem 1.5rem;
                                    background: var(--siemens-petrol, #009999);
                                    color: white;
                                    border: 1px solid var(--siemens-petrol, #009999);
                                    border-radius: 0.5rem;
                                    cursor: pointer;
                                    font-weight: 600;
                                    transition: all 0.2s;
                                ">
                                    <i class="fas fa-save"></i> Create Tasks
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        `;

        // Remove existing modal if present
        const existingModal = document.getElementById('assignOwnerModal');
        if (existingModal) {
            existingModal.remove();
        }

        // Add modal to body
        document.body.insertAdjacentHTML('beforeend', modalHTML);
        this.modal = document.getElementById('assignOwnerModal');
        
        // Add basic styling for form elements
        this.addModalStyles();
        
        console.log('Modal created and added to DOM:', this.modal);
        console.log('Modal HTML length:', modalHTML.length);
    }

    /**
     * Add modal styles
     */
    addModalStyles() {
        const style = document.createElement('style');
        style.textContent = `
            .modal .form-group {
                margin-bottom: 1rem;
            }
            
            .modal .form-group label {
                display: block;
                margin-bottom: 0.375rem;
                font-weight: 600;
                color: var(--text-primary, #ffffff);
                font-size: 0.875rem;
            }
            
            .modal .form-group .required {
                color: #ef4444;
            }
            
            .modal .form-group input,
            .modal .form-group select,
            .modal .form-group textarea {
                width: 100%;
                padding: 0.75rem;
                border: 1px solid var(--border-secondary, #555555);
                border-radius: 0.5rem;
                background: var(--bg-tertiary, #333333);
                color: var(--text-primary, #ffffff);
                font-size: 1rem;
                transition: border-color 0.2s;
            }
            
            .modal .form-group input:focus,
            .modal .form-group select:focus,
            .modal .form-group textarea:focus {
                outline: none;
                border-color: var(--siemens-petrol, #009999);
                box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
            }
            
            .modal .device-selection-container {
                max-height: 160px !important;
                overflow-y: auto !important;
                border: 1px solid var(--border-secondary, #555555) !important;
                border-radius: 0.5rem !important;
                padding: 0.75rem !important;
                background: var(--bg-tertiary, #333333) !important;
            }
            
            .modal .device-selection-header {
                display: flex !important;
                justify-content: space-between !important;
                align-items: center !important;
                margin-bottom: 0.75rem !important;
                padding: 0.75rem !important;
                padding-bottom: 0.375rem !important;
                border-bottom: 1px solid var(--border-primary, #333333) !important;
                background: var(--bg-tertiary, #333333) !important;
                font-size: 0.875rem !important;
            }
            
            .modal .device-item {
                display: flex !important;
                align-items: center !important;
                padding: 0.375rem 0.5rem !important;
                margin-bottom: 0.25rem !important;
                background: var(--bg-card, #1a1a1a) !important;
                border: 1px solid var(--border-primary, #333333) !important;
                border-radius: 0.25rem !important;
                transition: background-color 0.2s !important;
                font-size: 0.875rem !important;
            }
            
            .modal .device-item:hover {
                background: var(--bg-hover, #333333) !important;
            }
            
            .modal .device-checkbox {
                display: flex !important;
                align-items: flex-start !important;
                gap: 0.75rem !important;
                padding: 0.375rem 0.5rem !important;
                margin-bottom: 0.25rem !important;
                background: var(--bg-card, #1a1a1a) !important;
                border: 1px solid var(--border-primary, #333333) !important;
                border-radius: 0.25rem !important;
                transition: background-color 0.2s !important;
                font-size: 0.875rem !important;
                cursor: pointer !important;
            }
            
            .modal .device-checkbox:hover {
                background: var(--bg-hover, #333333) !important;
            }
            
            .modal .device-item input[type="checkbox"] {
                width: auto !important;
                margin-right: 0.75rem !important;
            }
            
            .modal .device-checkbox input[type="checkbox"] {
                width: auto !important;
                margin: 0 !important;
                margin-top: 0.25rem !important;
            }
            
            .modal .device-info {
                flex: 1 !important;
            }
            
            .modal .device-name {
                font-weight: 600;
                color: var(--text-primary, #ffffff);
                margin-bottom: 0.125rem;
                font-size: 0.875rem;
            }
            
            .modal .device-details {
                font-size: 0.75rem;
                color: var(--text-secondary, #cbd5e1);
                line-height: 1.2;
            }
            
            .modal .downtime-input-group {
                display: flex;
                gap: 0.5rem;
            }
            
            .modal .downtime-input-group input {
                flex: 1;
            }
            
            .modal .downtime-input-group button {
                padding: 0.75rem 1rem;
                background: var(--siemens-orange, #ff6b35);
                color: white;
                border: none;
                border-radius: 0.5rem;
                cursor: pointer;
                font-weight: 600;
                transition: background-color 0.2s;
            }
            
            .modal .downtime-input-group button:hover {
                background: var(--siemens-orange-dark, #e55a2b);
            }
            
            .modal .form-help {
                display: block;
                margin-top: 0.25rem;
                font-size: 0.875rem;
                color: var(--text-muted, #94a3b8);
            }
            
            .modal .selected-count {
                font-size: 0.875rem;
                color: var(--text-secondary, #cbd5e1);
                font-weight: 600;
            }
            
            .modal .btn {
                display: inline-flex;
                align-items: center;
                gap: 0.375rem;
                padding: 0.375rem 0.75rem;
                border: none;
                border-radius: 0.25rem;
                cursor: pointer;
                font-weight: 600;
                transition: all 0.2s;
                font-size: 0.75rem;
            }
            
            .modal .btn-secondary {
                background: transparent;
                color: var(--text-secondary, #cbd5e1);
                border: 1px solid var(--border-secondary, #555555);
            }
            
            .modal .btn-secondary:hover {
                background: var(--bg-hover, #333333);
            }
            
            .modal .modal-close:hover {
                color: var(--text-primary, #ffffff);
            }
        `;
        document.head.appendChild(style);
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Form submission
        document.getElementById('assignTaskForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.submitForm();
        });

        // Close modal when clicking outside
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.close();
            }
        });

        // Set default scheduled date to tomorrow
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        tomorrow.setHours(9, 0, 0, 0);
        document.getElementById('scheduledDate').value = tomorrow.toISOString().slice(0, 16);

        // Set default implementation date to day after scheduled date
        const dayAfter = new Date(tomorrow);
        dayAfter.setDate(dayAfter.getDate() + 1);
        dayAfter.setHours(9, 0, 0, 0);
        document.getElementById('implementationDate').value = dayAfter.toISOString().slice(0, 16);
    }

    /**
     * Load users from API
     */
    async loadUsers() {
        try {
            // Try to load users from the simple users endpoint first
            const response = await fetch('/api/v1/users/simple.php', {
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    const result = await response.json();
                    if (result.success && result.data && result.data.length > 0) {
                        this.users = result.data;
                        this.populateUserDropdown();
                        console.log('Loaded users from simple endpoint:', this.users.length);
                        return;
                    }
                }
            }
        } catch (error) {
            console.log('Simple user endpoint failed, trying local endpoint...');
        }
        
        try {
            // Try to load users from the current page's AJAX endpoint
            const currentPage = window.location.pathname;
            const response = await fetch(`${currentPage}?ajax=get_users`, {
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    const result = await response.json();
                    if (result.success && result.data && result.data.length > 0) {
                        this.users = result.data;
                        this.populateUserDropdown();
                        console.log('Loaded users from local endpoint:', this.users.length);
                        return;
                    }
                }
            }
        } catch (error) {
            console.log('Local user endpoint failed, trying API...');
        }
        
        // Fallback to API endpoint
        try {
            const response = await fetch('/api/v1/users', {
                credentials: 'same-origin'
            });
            const result = await response.json();
            
            if (result.success && result.data && result.data.length > 0) {
                this.users = result.data;
                this.populateUserDropdown();
                console.log('Loaded users from API:', this.users.length);
            } else {
                throw new Error('API returned no users');
            }
        } catch (error) {
            console.error('Failed to load users from API:', error);
            // Use hardcoded fallback as last resort
            this.users = [
                { user_id: 'admin-user', username: 'Admin User', email: 'admin@example.com' },
                { user_id: 'tech-user', username: 'Technical User', email: 'tech@example.com' },
                { user_id: 'current-user', username: 'Current User', email: 'user@example.com' }
            ];
            this.populateUserDropdown();
            console.log('Using fallback users');
        }
    }



    /**
     * Load patch data for auto-calculation
     */
    async loadPatchData(patchId) {
        try {
            const response = await fetch(`/api/v1/patches/${patchId}`);
            const result = await response.json();
            
            if (result.success) {
                this.patchData = result.data;
                this.updateDowntimeFromPatch();
            }
        } catch (error) {
            console.error('Error loading patch data:', error);
        }
    }

    /**
     * Populate user dropdown
     */
    populateUserDropdown() {
        const select = document.getElementById('assignedTo');
        select.innerHTML = '<option value="">Select user...</option>';
        
        this.users.forEach(user => {
            const option = document.createElement('option');
            option.value = user.user_id;
            option.textContent = `${user.username} (${user.email})`;
            select.appendChild(option);
        });
    }

    /**
     * Show the modal
     */
    show() {
        if (!this.modal) {
            console.error('Modal element is null!');
            this.showNotification('Modal not initialized. Please refresh the page.', 'error');
            return;
        }
        
        this.populateDeviceList();
        this.updateModalTitle();
        
        this.modal.style.display = 'flex';
        // Ensure compatibility with global CSS that expects .modal.show
        try {
            this.modal.classList.add('show');
        } catch (_) {}
        this.modal.style.alignItems = 'center';
        this.modal.style.justifyContent = 'center';
        this.modal.style.zIndex = '9999';
        this.modal.style.position = 'fixed';
        this.modal.style.top = '0';
        this.modal.style.left = '0';
        this.modal.style.width = '100%';
        this.modal.style.height = '100%';
        this.modal.style.backgroundColor = 'rgba(0, 0, 0, 0.8)';
        
        document.body.style.overflow = 'hidden';
    }

    /**
     * Close the modal
     */
    close() {
        // Clean up URL if we're on patches page with schedule action BEFORE closing
        // We need to navigate away to actually change the page content
        if (this.taskContext.taskType === 'patch_application') {
            const currentPath = window.location.pathname;
            if (currentPath.includes('/admin/patches.php')) {
                const currentSearch = window.location.search;
                // If we're on schedule page, navigate to list
                if (currentSearch.includes('action=schedule')) {
                    // Navigate to list view (this will reload the page)
                    window.location.href = currentPath + '?action=list';
                    return; // Exit early, page will reload
                }
            }
        }
        
        // Remove .show for CSS frameworks that toggle visibility with the class
        try {
            this.modal.classList.remove('show');
        } catch (_) {}
        this.modal.style.display = 'none';
        document.body.style.overflow = '';
        this.resetForm();
    }

    /**
     * Populate device list
     */
    populateDeviceList() {
        const deviceList = document.getElementById('deviceList');
        deviceList.innerHTML = '';

        this.devices.forEach(device => {
            const deviceItem = document.createElement('div');
            deviceItem.className = 'device-item';
            deviceItem.innerHTML = `
                <label class="device-checkbox">
                    <input type="checkbox" value="${device.device_id}" 
                           onchange="assignOwnerModal.toggleDevice('${device.device_id}')">
                    <div class="device-info">
                        <div class="device-name">${this.escapeHtml(device.device_name || device.hostname || 'Unknown Device')}</div>
                        <div class="device-details">
                            <span class="device-type">${this.escapeHtml(device.device_type || 'Unknown')}</span>
                            <span class="device-location">${this.escapeHtml(device.location || 'Unknown')}</span>
                            <span class="device-department">${this.escapeHtml(device.department || 'Unknown')}</span>
                            <span class="device-criticality criticality-${(device.device_criticality || '').toLowerCase().replace('-', '_')}">
                                ${this.escapeHtml(device.device_criticality || 'Unknown')}
                            </span>
                            ${device.package_name ? `<span class="device-package" style="color: var(--siemens-orange, #ff6b35); font-weight: 600;">${this.escapeHtml(device.package_name)}</span>` : ''}
                            ${device.cve_id ? `<span class="device-cve" style="color: var(--text-muted, #94a3b8); font-size: 0.75rem;">${this.escapeHtml(device.cve_id)}</span>` : ''}
                        </div>
                    </div>
                </label>
            `;
            deviceList.appendChild(deviceItem);
        });
    }

    /**
     * Toggle device selection
     */
    toggleDevice(deviceId) {
        if (this.selectedDevices.has(deviceId)) {
            this.selectedDevices.delete(deviceId);
        } else {
            this.selectedDevices.add(deviceId);
        }
        this.updateSelectedCount();
    }

    /**
     * Select all devices
     */
    selectAllDevices() {
        this.devices.forEach(device => {
            this.selectedDevices.add(device.device_id);
        });
        this.updateDeviceCheckboxes();
        this.updateSelectedCount();
    }

    /**
     * Clear device selection
     */
    clearDeviceSelection() {
        this.selectedDevices.clear();
        this.updateDeviceCheckboxes();
        this.updateSelectedCount();
    }

    /**
     * Update device checkboxes
     */
    updateDeviceCheckboxes() {
        const checkboxes = document.querySelectorAll('#deviceList input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            checkbox.checked = this.selectedDevices.has(checkbox.value);
        });
    }

    /**
     * Update selected count display
     */
    updateSelectedCount() {
        const countElement = document.querySelector('.selected-count');
        countElement.textContent = `${this.selectedDevices.size} device${this.selectedDevices.size !== 1 ? 's' : ''} selected`;
    }

    /**
     * Update modal title based on context
     */
    updateModalTitle() {
        const title = document.getElementById('modalTitle');
        switch (this.taskContext.taskType) {
            case 'package_remediation':
                title.textContent = 'Assign Package Remediation Task';
                break;
            case 'cve_remediation':
                title.textContent = 'Assign CVE Remediation Task';
                break;
            case 'patch_application':
                title.textContent = 'Assign Patch Application Task';
                break;
            default:
                title.textContent = 'Assign Task';
        }
    }

    /**
     * Calculate downtime from patch data
     */
    calculateDowntime() {
        if (this.patchData && this.patchData.estimated_install_time) {
            document.getElementById('estimatedDowntime').value = this.patchData.estimated_install_time;
        } else {
            // Default to 30 minutes if no patch data
            document.getElementById('estimatedDowntime').value = 30;
        }
    }

    /**
     * Update downtime from patch data
     */
    updateDowntimeFromPatch() {
        if (this.patchData && this.patchData.estimated_install_time) {
            document.getElementById('estimatedDowntime').value = this.patchData.estimated_install_time;
        }
    }

    /**
     * Submit form and create tasks
     */
    async submitForm() {
        if (this.selectedDevices.size === 0) {
            this.showNotification('Please select at least one device.', 'error');
            return;
        }

        const formData = new FormData(document.getElementById('assignTaskForm'));
        const formObject = Object.fromEntries(formData.entries());

        // Create tasks for each selected device
        const tasks = Array.from(this.selectedDevices).map(deviceId => {
            const task = {
                task_type: this.taskContext.taskType,
                package_id: this.taskContext.packageId,
                cve_id: this.taskContext.cveId,
                action_id: this.taskContext.actionId,
                device_id: deviceId,
                assigned_to: formObject.assigned_to,
                scheduled_date: formObject.scheduled_date,
                implementation_date: formObject.implementation_date,
                estimated_downtime: parseInt(formObject.estimated_downtime),
                task_description: formObject.task_description,
                notes: formObject.notes
            };
            
            // For patch tasks, store patch_id instead of action_id
            if (this.taskContext.taskType === 'patch_application') {
                task.patch_id = this.taskContext.actionId;
                task.action_id = null;
            }
            
            return task;
        });

        console.log('Creating tasks with data:', tasks);
        console.log('Form data:', formObject);

        try {
            const promises = tasks.map(task => 
                fetch('/api/v1/scheduled-tasks/simple.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'same-origin', // Include session cookies
                    body: JSON.stringify(task)
                })
            );

            const responses = await Promise.all(promises);
            const results = await Promise.all(responses.map(r => r.json()));

            // Check if all tasks were created successfully
            const failedTasks = results.filter(r => !r.success);
            if (failedTasks.length > 0) {
                console.error('Some tasks failed to create:', failedTasks);
                console.error('Full error details:', failedTasks[0]);
                this.showNotification(`Created ${results.length - failedTasks.length} tasks successfully. ${failedTasks.length} tasks failed.\n\nError: ${failedTasks[0].error?.message || 'Unknown error'}`, 'error');
            } else {
                this.showNotification(`Successfully created ${results.length} task${results.length !== 1 ? 's' : ''}.`, 'success');
            }

            this.close();
            
            // For patch scheduling, redirect back to patches list
            if (this.taskContext.taskType === 'patch_application') {
                window.location.href = '/pages/admin/patches.php?action=list';
                return;
            }
            
            // Refresh the page or trigger a callback if needed
            if (typeof window.refreshTaskList === 'function') {
                window.refreshTaskList();
            }

        } catch (error) {
            console.error('Error creating tasks:', error);
            this.showNotification('Error creating tasks. Please try again.', 'error');
        }
    }

    /**
     * Reset form
     */
    resetForm() {
        document.getElementById('assignTaskForm').reset();
        this.selectedDevices.clear();
        this.updateSelectedCount();
        this.updateDeviceCheckboxes();
    }

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Show notification
     */
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                <span>${message}</span>
            </div>
        `;
        
        // Style the notification
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 0.5rem;
            color: white;
            font-weight: 600;
            z-index: 10000;
            max-width: 400px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
            transform: translateX(100%);
            opacity: 0;
        `;
        
        // Set background color based on type
        switch (type) {
            case 'success':
                notification.style.backgroundColor = '#10b981';
                break;
            case 'error':
                notification.style.backgroundColor = '#ef4444';
                break;
            case 'warning':
                notification.style.backgroundColor = '#f59e0b';
                break;
            default:
                notification.style.backgroundColor = '#009999';
        }
        
        document.body.appendChild(notification);
        
        // Show notification
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
            notification.style.opacity = '1';
        }, 100);
        
        // Remove notification after 5 seconds
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            notification.style.opacity = '0';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 5000);
    }
}

// Create global instance
window.assignOwnerModal = new AssignOwnerModal();

// Initialize when DOM is loaded or immediately if already loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        window.assignOwnerModal.init();
    });
} else {
    // DOM is already loaded
    window.assignOwnerModal.init();
}
