/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
// Prevent redeclaration
if (typeof RecallSchedulingModal === 'undefined') {
    class RecallSchedulingModal {
    constructor() {
        this.modal = null;
        this.currentRecall = null;
        this.currentDevice = null;
        this.affectedDevices = [];
        this.selectedDevices = [];
        this.users = [];
        this.init();
    }

    init() {
        this.createModal();
        this.loadUsers();
    }

    showForRecall(recallId, recallData) {
        this.currentRecall = recallData;
        this.loadAffectedDevices(recallId);
        this.showModal();
    }

    showForSpecificDevice(recallId, recallData, deviceData) {
        console.log('showForSpecificDevice called with:', { recallId, recallData, deviceData });
        this.currentRecall = recallData;
        this.currentDevice = deviceData; // Store the specific device
        this.renderRecallDetails();
        this.renderDeviceDetails();
        this.showModal();
    }

    createModal() {
        // Remove existing modal if it exists
        const existingModal = document.getElementById('recall-scheduling-modal');
        if (existingModal) {
            existingModal.remove();
        }

        const modalHTML = `
            <div id="recall-scheduling-modal" class="modal-overlay" style="display: none;">
                <div class="modal-content recall-scheduling-modal">
                    <div class="modal-header">
                        <h2>
                            <i class="fas fa-calendar-plus"></i>
                            Schedule Recall Maintenance
                        </h2>
                        <button class="modal-close" onclick="recallSchedulingModal.hide()">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    
                    <div class="modal-body">
                        <div class="recall-info-section">
                            <h3>Recall Information</h3>
                            <div class="recall-details" id="recall-details">
                                <!-- Recall details will be populated here -->
                            </div>
                        </div>
                        
                        <div class="device-info-section">
                            <h3>Device Information</h3>
                            <div class="device-details" id="device-details">
                                <!-- Device details will be populated here -->
                            </div>
                        </div>
                        
                        <div class="scheduling-section">
                            <h3>Scheduling Details</h3>
                            <div class="form-grid">
                                <div class="form-group">
                                    <label for="assigned-to">Assigned To *</label>
                                    <select id="assigned-to" required>
                                        <option value="">Select user...</option>
                                    </select>
                                </div>
                                
                                <div class="form-group">
                                    <label for="scheduled-date">Scheduled Date *</label>
                                    <input type="datetime-local" id="scheduled-date" required>
                                </div>
                                
                                <div class="form-group">
                                    <label for="estimated-downtime">Estimated Downtime (minutes) *</label>
                                    <input type="number" id="estimated-downtime" min="0" required>
                                </div>
                                
                                <div class="form-group">
                                    <label for="recall-priority">Priority *</label>
                                    <select id="recall-priority" required>
                                        <option value="Low">Low</option>
                                        <option value="Medium" selected>Medium</option>
                                        <option value="High">High</option>
                                        <option value="Critical">Critical</option>
                                    </select>
                                </div>
                                
                                <div class="form-group">
                                    <label for="remediation-type">Remediation Type *</label>
                                    <select id="remediation-type" required>
                                        <option value="Inspection" selected>Inspection</option>
                                        <option value="Repair">Repair</option>
                                        <option value="Replacement">Replacement</option>
                                        <option value="Software Update">Software Update</option>
                                        <option value="Configuration Change">Configuration Change</option>
                                        <option value="Other">Other</option>
                                    </select>
                                </div>
                                
                                <div class="form-group full-width">
                                    <label for="task-description">Task Description</label>
                                    <textarea id="task-description" rows="3" placeholder="Describe the maintenance task..."></textarea>
                                </div>
                                
                                <div class="form-group full-width">
                                    <label for="notes">Notes</label>
                                    <textarea id="notes" rows="2" placeholder="Additional notes..."></textarea>
                                </div>
                                
                                <div class="form-group full-width">
                                    <label for="affected-serial-numbers">Affected Serial Numbers</label>
                                    <input type="text" id="affected-serial-numbers" placeholder="Enter serial numbers (comma-separated)">
                                </div>
                            </div>
                            
                            <div class="checkbox-group">
                                <label class="checkbox-label">
                                    <input type="checkbox" id="vendor-contact-required">
                                    <span class="checkmark"></span>
                                    Vendor Contact Required
                                </label>
                                
                                <label class="checkbox-label">
                                    <input type="checkbox" id="fda-notification-required">
                                    <span class="checkmark"></span>
                                    FDA Notification Required
                                </label>
                                
                                <label class="checkbox-label">
                                    <input type="checkbox" id="patient-safety-impact">
                                    <span class="checkmark"></span>
                                    Patient Safety Impact
                                </label>
                            </div>
                        </div>
                    </div>
                    
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" onclick="recallSchedulingModal.hide()">
                            <i class="fas fa-times"></i> Cancel
                        </button>
                        <button type="button" class="btn btn-primary" onclick="recallSchedulingModal.scheduleMaintenance()">
                            <i class="fas fa-calendar-plus"></i> Schedule Maintenance
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHTML);
        this.modal = document.getElementById('recall-scheduling-modal');
    }

    showModal() {
        if (this.modal) {
            this.modal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
    }

    hide() {
        if (this.modal) {
            this.modal.style.display = 'none';
            document.body.style.overflow = '';
        }
    }

    async loadUsers() {
        try {
            const response = await fetch('/api/v1/users/', {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            const result = await response.json();
            
            if (result.success) {
                this.users = result.data;
                this.populateUserSelect();
            }
        } catch (error) {
            console.error('Error loading users:', error);
            this.showNotification('Error loading users', 'error');
        }
    }

    populateUserSelect() {
        const select = document.getElementById('assigned-to');
        if (select) {
            select.innerHTML = '<option value="">Select user...</option>';
            this.users.forEach(user => {
                const option = document.createElement('option');
                option.value = user.user_id;
                option.textContent = user.username;
                select.appendChild(option);
            });
        }
    }

    async loadAffectedDevices(recallId) {
        try {
            const response = await fetch(`/api/v1/recalls/schedule.php?path=affected-devices&recall_id=${recallId}`, {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            const result = await response.json();
            
            if (result.success) {
                this.affectedDevices = result.data;
                this.renderRecallDetails();
                this.renderDevicesList();
            } else {
                this.showNotification('Error loading affected devices: ' + result.error.message, 'error');
            }
        } catch (error) {
            console.error('Error loading affected devices:', error);
            this.showNotification('Error loading affected devices', 'error');
        }
    }

    renderRecallDetails() {
        const container = document.getElementById('recall-details');
        if (container && this.currentRecall) {
            container.innerHTML = `
                <div class="recall-info">
                    <div class="recall-field">
                        <strong>FDA Number:</strong> ${this.escapeHtml(this.currentRecall.fda_recall_number)}
                    </div>
                    <div class="recall-field">
                        <strong>Manufacturer:</strong> ${this.escapeHtml(this.currentRecall.manufacturer_name)}
                    </div>
                    <div class="recall-field">
                        <strong>Product:</strong> ${this.escapeHtml(this.currentRecall.product_description?.substring(0, 100) || '')}...
                    </div>
                    <div class="recall-field">
                        <strong>Classification:</strong> ${this.escapeHtml(this.currentRecall.recall_classification || 'N/A')}
                    </div>
                    <div class="recall-field">
                        <strong>Date:</strong> ${this.formatDate(this.currentRecall.recall_date)}
                    </div>
                </div>
            `;
        }
    }

    renderDeviceDetails() {
        const container = document.getElementById('device-details');
        if (container && this.currentDevice) {
            const device = this.currentDevice;
            container.innerHTML = `
                <div class="device-info">
                    <div class="device-field">
                        <strong>Device Name:</strong> ${this.escapeHtml(device.device_name || 'N/A')}
                    </div>
                    <div class="device-field">
                        <strong>Brand:</strong> ${this.escapeHtml(device.brand_name || 'N/A')}
                    </div>
                    <div class="device-field">
                        <strong>Model:</strong> ${this.escapeHtml(device.model_number || 'N/A')}
                    </div>
                    <div class="device-field">
                        <strong>Serial Number:</strong> ${this.escapeHtml(device.device_identifier || 'N/A')}
                    </div>
                    <div class="device-field">
                        <strong>IP Address:</strong> ${this.escapeHtml(device.ip_address || 'N/A')}
                    </div>
                    <div class="device-field">
                        <strong>Hostname:</strong> ${this.escapeHtml(device.hostname || 'N/A')}
                    </div>
                    <div class="device-field">
                        <strong>Location:</strong> ${this.escapeHtml(device.location_name || device.location || 'N/A')}
                    </div>
                    <div class="device-field">
                        <strong>Department:</strong> ${this.escapeHtml(device.department || 'N/A')}
                    </div>
                    <div class="device-field">
                        <strong>Manufacturer:</strong> ${this.escapeHtml(device.manufacturer_name || 'N/A')}
                    </div>
                </div>
            `;
        }
    }

    renderDevicesList() {
        const container = document.getElementById('devices-list');
        if (container) {
            container.innerHTML = this.affectedDevices.map(device => `
                <div class="device-item ${device.is_scheduled ? 'scheduled' : ''}" data-device-id="${device.device_id}">
                    <label class="device-checkbox">
                        <input type="checkbox" 
                               value="${device.device_id}" 
                               ${device.is_scheduled ? 'disabled' : ''}
                               onchange="recallSchedulingModal.toggleDevice('${device.device_id}')">
                        <span class="checkmark"></span>
                    </label>
                    <div class="device-info">
                        <div class="device-name">${this.escapeHtml(device.device_name || 'Unknown Device')}</div>
                        <div class="device-details">
                            <span class="device-model">${this.escapeHtml(device.model_number || 'N/A')}</span>
                            <span class="device-location">${this.escapeHtml(device.location_name || device.location || 'Unknown Location')}</span>
                            <span class="device-criticality ${device.criticality?.toLowerCase() || 'unknown'}">${this.escapeHtml(device.criticality || 'Unknown')}</span>
                        </div>
                        ${device.is_scheduled ? `
                            <div class="scheduled-info">
                                <i class="fas fa-calendar-check"></i>
                                Already scheduled (${device.task_status})
                            </div>
                        ` : ''}
                    </div>
                </div>
            `).join('');
        }
    }

    toggleAllDevices() {
        const selectAllCheckbox = document.getElementById('select-all-devices');
        const deviceCheckboxes = document.querySelectorAll('#devices-list input[type="checkbox"]:not([disabled])');
        
        deviceCheckboxes.forEach(checkbox => {
            checkbox.checked = selectAllCheckbox.checked;
            this.toggleDevice(checkbox.value);
        });
    }

    toggleDevice(deviceId) {
        const checkbox = document.querySelector(`input[value="${deviceId}"]`);
        if (checkbox) {
            if (checkbox.checked) {
                if (!this.selectedDevices.includes(deviceId)) {
                    this.selectedDevices.push(deviceId);
                }
            } else {
                this.selectedDevices = this.selectedDevices.filter(id => id !== deviceId);
            }
            this.updateSelectedCount();
        }
    }

    updateSelectedCount() {
        const countElement = document.getElementById('selected-devices-count');
        if (countElement) {
            countElement.textContent = `${this.selectedDevices.length} devices selected`;
        }
    }

    async scheduleMaintenance() {
        // Validate form
        if (!this.validateForm()) {
            return;
        }

        if (!this.currentDevice) {
            this.showNotification('No device selected for scheduling', 'error');
            return;
        }

        try {
            const formData = this.getFormData();
            const task = {
                ...formData,
                device_id: this.currentDevice.device_id
            };
            
            console.log('Task data being sent:', task);

            const response = await fetch('/api/v1/recalls/schedule.php?path=bulk-schedule', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ tasks: [task] })
            });

            const result = await response.json();
            console.log('API Response:', result);

            if (result.success) {
                this.showNotification(
                    `Successfully scheduled maintenance task for ${this.currentDevice.device_name || 'device'}`,
                    'success'
                );
                this.hide();
                
                // Refresh the page or trigger a callback
                if (window.onRecallScheduled) {
                    window.onRecallScheduled(result.data);
                }
            } else {
                let errorMessage = 'Unknown error occurred';
                
                if (result.error?.message) {
                    errorMessage = result.error.message;
                } else if (result.data?.errors && result.data.errors.length > 0) {
                    errorMessage = result.data.errors[0];
                } else if (result.message) {
                    errorMessage = result.message;
                }
                
                this.showNotification('Error scheduling maintenance: ' + errorMessage, 'error');
                console.error('API Error Response:', result);
            }
        } catch (error) {
            console.error('Error scheduling maintenance:', error);
            this.showNotification('Error scheduling maintenance: ' + error.message, 'error');
        }
    }

    validateForm() {
        const requiredFields = ['assigned-to', 'scheduled-date', 'estimated-downtime'];
        let isValid = true;

        requiredFields.forEach(fieldId => {
            const field = document.getElementById(fieldId);
            if (!field.value.trim()) {
                field.classList.add('error');
                isValid = false;
            } else {
                field.classList.remove('error');
            }
        });

        if (!isValid) {
            this.showNotification('Please fill in all required fields', 'error');
        }

        return isValid;
    }

    getFormData() {
        // Validate required data
        if (!this.currentRecall || !this.currentRecall.recall_id) {
            throw new Error('Recall data is missing or invalid');
        }
        
        if (!this.currentDevice || !this.currentDevice.device_id) {
            throw new Error('Device data is missing or invalid');
        }
        
        const formData = {
            recall_id: this.currentRecall.recall_id,
            assigned_to: document.getElementById('assigned-to').value,
            scheduled_date: document.getElementById('scheduled-date').value,
            estimated_downtime: parseInt(document.getElementById('estimated-downtime').value),
            recall_priority: document.getElementById('recall-priority').value,
            remediation_type: document.getElementById('remediation-type').value,
            task_description: document.getElementById('task-description').value,
            notes: document.getElementById('notes').value,
            affected_serial_numbers: document.getElementById('affected-serial-numbers').value,
            vendor_contact_required: document.getElementById('vendor-contact-required').checked,
            fda_notification_required: document.getElementById('fda-notification-required').checked,
            patient_safety_impact: document.getElementById('patient-safety-impact').checked
        };
        
        console.log('Form data being sent:', formData);
        return formData;
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        `;

        // Add to page
        document.body.appendChild(notification);

        // Show notification
        setTimeout(() => notification.classList.add('show'), 100);

        // Remove notification after 5 seconds
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 300);
        }, 5000);
    }

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatDate(dateString) {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    }
}

// Initialize the modal
const recallSchedulingModal = new RecallSchedulingModal();

// Make it globally available
window.recallSchedulingModal = recallSchedulingModal;

} // End of redeclaration check
