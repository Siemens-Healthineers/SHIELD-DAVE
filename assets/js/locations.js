/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

class LocationManager {
    constructor() {
        this.locations = [];
        this.currentLocation = null;
        this.isEditing = false;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadLocations();
        this.loadParentLocations();
        this.setupCriticalitySlider();
    }

    setupEventListeners() {
        // Criticality slider
        const criticalitySlider = document.getElementById('criticality');
        if (criticalitySlider) {
            criticalitySlider.addEventListener('input', (e) => {
                document.getElementById('criticalityValue').textContent = e.target.value;
            });
        }

        // Form submission
        const locationForm = document.getElementById('locationForm');
        if (locationForm) {
            locationForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveLocation();
            });
        }

        // Search and filters
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', debounce(() => {
                this.applyFilters();
            }, 300));
        }

        // Modal close on outside click
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    this.closeModal(modal);
                }
            });
        });
    }

    setupCriticalitySlider() {
        const slider = document.getElementById('criticality');
        const valueDisplay = document.getElementById('criticalityValue');
        
        if (slider && valueDisplay) {
            slider.addEventListener('input', (e) => {
                const value = parseInt(e.target.value);
                valueDisplay.textContent = value;
                
                // Update color based on criticality
                valueDisplay.className = `criticality-${value}`;
            });
        }
    }

    async loadLocations() {
        try {
            const response = await fetch('/api/v1/locations/index.php?include_hierarchy=false', {
                credentials: 'same-origin'
            });
            
            // Check if response is a redirect (authentication required)
            if (response.redirected || response.status === 302 || response.status === 401) {
                this.showError('Authentication required. Please log in to access location management.');
                return;
            }
            
            // Check if response is not JSON
            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                this.showError('Invalid response format. Please check your authentication.');
                return;
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.locations = data.data;
                this.renderLocationTree();
            } else {
                this.showError('Failed to load locations: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            console.error('Error loading locations:', error);
            if (error.name === 'SyntaxError') {
                this.showError('Authentication required. Please log in to access location management.');
            } else {
                this.showError('Failed to load locations: ' + error.message);
            }
        }
    }

    async loadParentLocations() {
        try {
            const response = await fetch('/api/v1/locations/index.php?include_hierarchy=false', {
                credentials: 'same-origin'
            });
            const data = await response.json();
            
            if (data.success) {
                const parentSelect = document.getElementById('parentLocation');
                if (parentSelect) {
                    parentSelect.innerHTML = '<option value="">No Parent (Root Location)</option>';
                    
                    data.data.forEach(location => {
                        const option = document.createElement('option');
                        option.value = location.location_id;
                        option.textContent = location.hierarchy_path || location.location_name;
                        parentSelect.appendChild(option);
                    });
                }
            } else {
                console.error('Failed to load parent locations:', data.error);
            }
        } catch (error) {
            console.error('Error loading parent locations:', error);
        }
    }

    renderLocationTree() {
        const treeContainer = document.getElementById('locationsTree');
        if (!treeContainer) return;

        if (this.locations.length === 0) {
            treeContainer.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-map-marker-alt"></i>
                    <h3>No locations found</h3>
                    <p>Create your first location to get started.</p>
                </div>
            `;
            return;
        }

        // Build hierarchy
        const hierarchy = this.buildHierarchy(this.locations);
        
        // Render tree
        treeContainer.innerHTML = '';
        hierarchy.forEach(location => {
            treeContainer.appendChild(this.createLocationNode(location, 0));
        });
    }

    buildHierarchy(locations) {
        const locationMap = new Map();
        const rootLocations = [];

        // Create map of locations
        locations.forEach(location => {
            locationMap.set(location.location_id, { ...location, children: [] });
        });

        // Build hierarchy
        locations.forEach(location => {
            const locationNode = locationMap.get(location.location_id);
            
            if (location.parent_location_id && locationMap.has(location.parent_location_id)) {
                locationMap.get(location.parent_location_id).children.push(locationNode);
            } else {
                rootLocations.push(locationNode);
            }
        });

        return rootLocations;
    }

    createLocationNode(location, level) {
        const node = document.createElement('div');
        node.className = 'location-tree-item';
        node.dataset.locationId = location.location_id;

        const hasChildren = location.children && location.children.length > 0;
        const isExpanded = level < 2; // Auto-expand first 2 levels

        node.innerHTML = `
            <div class="location-tree-header" onclick="locationManager.toggleNode(this)">
                <div class="location-tree-toggle ${hasChildren ? (isExpanded ? 'expanded' : '') : 'no-children'}">
                    ${hasChildren ? '<i class="fas fa-chevron-right"></i>' : ''}
                </div>
                <div class="location-tree-icon location-type-${location.location_type.toLowerCase()}">
                    <i class="fas ${this.getLocationTypeIcon(location.location_type)}"></i>
                </div>
                <div class="location-tree-content">
                    <div class="location-tree-info">
                        <div class="location-tree-name">${this.escapeHtml(location.location_name)}</div>
                        <div class="location-tree-details">
                            <span class="location-type">${location.location_type}</span>
                            <span class="location-code">${location.location_code || 'No Code'}</span>
                            <span class="asset-count">${location.asset_count || 0} assets</span>
                            <span class="child-count">${location.child_count || 0} children</span>
                        </div>
                        <div class="ip-range-display">
                            ${this.renderIpRanges(location.ip_ranges)}
                        </div>
                    </div>
                    <div class="location-tree-actions">
                        <span class="criticality-badge criticality-${location.criticality}">
                            ${location.criticality}
                        </span>
                        <button class="btn btn-sm btn-primary" onclick="locationManager.editLocation('${location.location_id}')">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="locationManager.deleteLocation('${location.location_id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
            </div>
            ${hasChildren ? `
                <div class="location-tree-children ${isExpanded ? 'expanded' : ''}">
                    ${location.children.map(child => this.createLocationNode(child, level + 1).outerHTML).join('')}
                </div>
            ` : ''}
        `;

        return node;
    }

    getLocationTypeIcon(type) {
        const icons = {
            'Building': 'fa-building',
            'Floor': 'fa-layer-group',
            'Department': 'fa-hospital',
            'Ward': 'fa-bed',
            'Lab': 'fa-flask',
            'Room': 'fa-door-open',
            'Other': 'fa-map-marker-alt'
        };
        return icons[type] || 'fa-map-marker-alt';
    }

    renderIpRanges(ipRanges) {
        if (!ipRanges || ipRanges.length === 0) {
            return '<span class="text-muted">No IP ranges</span>';
        }

        return ipRanges.map(range => {
            const rangeClass = range.range_format === 'CIDR' ? 'ip-range-cidr' : 'ip-range-startend';
            const rangeText = range.range_format === 'CIDR' 
                ? range.cidr_notation 
                : `${range.start_ip} - ${range.end_ip}`;
            
            return `<span class="ip-range-item-display ${rangeClass}">${rangeText}</span>`;
        }).join('');
    }

    toggleNode(header) {
        const node = header.closest('.location-tree-item');
        const toggle = header.querySelector('.location-tree-toggle');
        const children = node.querySelector('.location-tree-children');
        
        if (!children) return;

        const isExpanded = children.classList.contains('expanded');
        
        if (isExpanded) {
            children.classList.remove('expanded');
            toggle.classList.remove('expanded');
        } else {
            children.classList.add('expanded');
            toggle.classList.add('expanded');
        }
    }

    expandAll() {
        const toggles = document.querySelectorAll('.location-tree-toggle');
        const children = document.querySelectorAll('.location-tree-children');
        
        toggles.forEach(toggle => toggle.classList.add('expanded'));
        children.forEach(child => child.classList.add('expanded'));
    }

    collapseAll() {
        const toggles = document.querySelectorAll('.location-tree-toggle');
        const children = document.querySelectorAll('.location-tree-children');
        
        toggles.forEach(toggle => toggle.classList.remove('expanded'));
        children.forEach(child => child.classList.remove('expanded'));
    }

    applyFilters() {
        const typeFilter = document.getElementById('locationTypeFilter')?.value;
        const criticalityFilter = document.getElementById('criticalityFilter')?.value;
        const searchTerm = document.getElementById('searchInput')?.value.toLowerCase();

        const items = document.querySelectorAll('.location-tree-item');
        
        items.forEach(item => {
            const name = item.querySelector('.location-tree-name')?.textContent.toLowerCase() || '';
            const type = item.querySelector('.location-type')?.textContent || '';
            const criticalityBadge = item.querySelector('.criticality-badge');
            const criticality = criticalityBadge ? parseInt(criticalityBadge.textContent) : 0;
            
            let show = true;

            // Type filter
            if (typeFilter && type !== typeFilter) {
                show = false;
            }

            // Criticality filter
            if (criticalityFilter) {
                const [min, max] = criticalityFilter.split('-').map(Number);
                if (criticality < min || criticality > max) {
                    show = false;
                }
            }

            // Search filter
            if (searchTerm && !name.includes(searchTerm)) {
                show = false;
            }

            item.style.display = show ? 'block' : 'none';
        });
    }

    clearFilters() {
        document.getElementById('locationTypeFilter').value = '';
        document.getElementById('criticalityFilter').value = '';
        document.getElementById('searchInput').value = '';
        this.applyFilters();
    }

    openLocationModal(locationId = null) {
        this.isEditing = !!locationId;
        this.currentLocation = locationId;
        
        const modal = document.getElementById('locationModal');
        const title = document.getElementById('modalTitle');
        const form = document.getElementById('locationForm');
        
        title.textContent = this.isEditing ? 'Edit Location' : 'Add Location';
        form.reset();
        
        if (this.isEditing) {
            this.loadLocationForEdit(locationId);
        } else {
            // Set default values for new location
            document.getElementById('criticalityValue').textContent = '5';
            document.getElementById('isActive').checked = true;
        }
        
        modal.classList.add('show');
    }

    async loadLocationForEdit(locationId) {
        try {
            const response = await fetch(`/api/v1/locations/index.php?id=${locationId}`, {
                credentials: 'same-origin'
            });
            const data = await response.json();
            
            if (data.success) {
                const location = data.data;
                
                // Populate form fields
                document.getElementById('locationId').value = location.location_id;
                document.getElementById('locationName').value = location.location_name;
                document.getElementById('locationType').value = location.location_type;
                document.getElementById('parentLocation').value = location.parent_location_id || '';
                document.getElementById('locationCode').value = location.location_code || '';
                document.getElementById('description').value = location.description || '';
                document.getElementById('criticality').value = location.criticality;
                document.getElementById('criticalityValue').textContent = location.criticality;
                document.getElementById('criticalityValue').className = `criticality-${location.criticality}`;
                document.getElementById('isActive').checked = Boolean(location.is_active);
                
                // Load IP ranges
                this.loadIpRangesForEdit(location.ip_ranges || []);
            } else {
                this.showError('Failed to load location: ' + data.error);
            }
        } catch (error) {
            console.error('Error loading location:', error);
            this.showError('Failed to load location');
        }
    }

    loadIpRangesForEdit(ipRanges) {
        const container = document.getElementById('ipRangesContainer');
        container.innerHTML = '';
        
        if (!ipRanges || ipRanges.length === 0) {
            this.addIpRange();
            return;
        }
        
        ipRanges.forEach(range => {
            this.addIpRange(range);
        });
    }

    closeLocationModal() {
        const modal = document.getElementById('locationModal');
        modal.classList.remove('show');
        this.isEditing = false;
        this.currentLocation = null;
    }

    async saveLocation() {
        const formData = this.getFormData();
        
        if (!this.validateForm(formData)) {
            return;
        }

        try {
            const url = this.isEditing 
                ? `/api/v1/locations/index.php?id=${this.currentLocation}`
                : '/api/v1/locations/index.php';
            
            const method = this.isEditing ? 'PUT' : 'POST';
            
            const response = await fetch(url, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
                body: JSON.stringify(formData)
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.showSuccess(this.isEditing ? 'Location updated successfully' : 'Location created successfully');
                this.closeLocationModal();
                this.loadLocations();
                this.loadParentLocations();
            } else {
                this.showError('Failed to save location: ' + data.error);
            }
        } catch (error) {
            console.error('Error saving location:', error);
            this.showError('Failed to save location: ' + error.message);
        }
    }

    getFormData() {
        const formData = {
            location_name: document.getElementById('locationName').value,
            location_type: document.getElementById('locationType').value,
            parent_location_id: document.getElementById('parentLocation').value || null,
            location_code: document.getElementById('locationCode').value || null,
            description: document.getElementById('description').value || null,
            criticality: parseInt(document.getElementById('criticality').value),
            is_active: document.getElementById('isActive').checked,
            ip_ranges: this.getIpRangesData()
        };

        return formData;
    }

    getIpRangesData() {
        const ranges = [];
        const rangeItems = document.querySelectorAll('.ip-range-item');
        
        rangeItems.forEach(item => {
            const format = item.querySelector('.range-format').value;
            const description = item.querySelector('.range-description').value;
            
            if (format === 'CIDR') {
                const cidr = item.querySelector('.cidr-input').value.trim();
                if (cidr) {
                    ranges.push({
                        range_format: 'CIDR',
                        cidr_notation: cidr,
                        description: description
                    });
                }
            } else {
                const startIp = item.querySelector('.start-ip').value.trim();
                const endIp = item.querySelector('.end-ip').value.trim();
                if (startIp && endIp) {
                    ranges.push({
                        range_format: 'StartEnd',
                        start_ip: startIp,
                        end_ip: endIp,
                        description: description
                    });
                }
            }
        });
        
        return ranges;
    }

    validateForm(formData) {
        if (!formData.location_name.trim()) {
            this.showError('Location name is required');
            return false;
        }
        
        if (!formData.location_type) {
            this.showError('Location type is required');
            return false;
        }
        
        if (formData.criticality < 1 || formData.criticality > 10) {
            this.showError('Criticality must be between 1 and 10');
            return false;
        }
        
        return true;
    }

    async deleteLocation(locationId) {
        if (!confirm('Are you sure you want to delete this location? This action cannot be undone.')) {
            return;
        }

        try {
            const response = await fetch(`/api/v1/locations/${locationId}`, {
                method: 'DELETE'
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.showSuccess('Location deleted successfully');
                this.loadLocations();
            } else {
                this.showError('Failed to delete location: ' + data.error);
            }
        } catch (error) {
            console.error('Error deleting location:', error);
            this.showError('Failed to delete location');
        }
    }

    editLocation(locationId) {
        this.openLocationModal(locationId);
    }

    // IP Range Management
    addIpRange(rangeData = null) {
        const container = document.getElementById('ipRangesContainer');
        const rangeItem = document.createElement('div');
        rangeItem.className = 'ip-range-item';
        
        rangeItem.innerHTML = `
            <div class="ip-range-header">
                <select class="form-select range-format" onchange="locationManager.toggleRangeFormat(this)">
                    <option value="CIDR" ${rangeData?.range_format === 'CIDR' ? 'selected' : ''}>CIDR Notation</option>
                    <option value="StartEnd" ${rangeData?.range_format === 'StartEnd' ? 'selected' : ''}>Start - End IP</option>
                </select>
                <button type="button" class="btn btn-sm btn-danger" onclick="locationManager.removeIpRange(this)">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
            <div class="ip-range-fields">
                <div class="cidr-field" style="display: ${rangeData?.range_format === 'StartEnd' ? 'none' : 'flex'}">
                    <input type="text" class="form-input cidr-input" 
                           placeholder="192.168.1.0/24" 
                           value="${rangeData?.cidr_notation || ''}">
                </div>
                <div class="startend-fields" style="display: ${rangeData?.range_format === 'StartEnd' ? 'flex' : 'none'}">
                    <input type="text" class="form-input start-ip" 
                           placeholder="192.168.1.1" 
                           value="${rangeData?.start_ip || ''}">
                    <span class="range-separator">to</span>
                    <input type="text" class="form-input end-ip" 
                           placeholder="192.168.1.255" 
                           value="${rangeData?.end_ip || ''}">
                </div>
            </div>
            <input type="text" class="form-input range-description" 
                   placeholder="Range description (optional)" 
                   value="${rangeData?.description || ''}">
        `;
        
        container.appendChild(rangeItem);
    }

    removeIpRange(button) {
        const rangeItem = button.closest('.ip-range-item');
        rangeItem.remove();
    }

    toggleRangeFormat(select) {
        const rangeItem = select.closest('.ip-range-item');
        const cidrField = rangeItem.querySelector('.cidr-field');
        const startEndFields = rangeItem.querySelector('.startend-fields');
        
        if (select.value === 'CIDR') {
            cidrField.style.display = 'flex';
            startEndFields.style.display = 'none';
        } else {
            cidrField.style.display = 'none';
            startEndFields.style.display = 'flex';
        }
    }

    // Auto Assignment
    openAutoAssignmentModal() {
        const modal = document.getElementById('autoAssignmentModal');
        modal.classList.add('show');
    }

    closeAutoAssignmentModal() {
        const modal = document.getElementById('autoAssignmentModal');
        modal.classList.remove('show');
    }

    async executeAutoAssignment() {
        const forceReassign = document.getElementById('forceReassign').checked;
        const dryRun = document.getElementById('dryRun').checked;
        
        try {
            const response = await fetch('/api/v1/locations/assign-assets.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    force_reassign: forceReassign,
                    dry_run: dryRun
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.showAssignmentResults(data.results, dryRun);
                this.closeAutoAssignmentModal();
                this.loadLocations();
            } else {
                this.showError('Auto-assignment failed: ' + data.error);
            }
        } catch (error) {
            console.error('Error running auto-assignment:', error);
            this.showError('Auto-assignment failed');
        }
    }

    showAssignmentResults(results, dryRun) {
        const message = dryRun 
            ? `Dry run completed. Would process ${results.processed} assets, assign ${results.assigned}, update ${results.updated}, skip ${results.skipped}.`
            : `Auto-assignment completed. Processed ${results.processed} assets, assigned ${results.assigned}, updated ${results.updated}, skipped ${results.skipped}.`;
        
        this.showSuccess(message);
        
        if (results.errors > 0) {
            console.warn('Assignment errors:', results.errors_list);
        }
    }

    // Utility Methods
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showSuccess(message) {
        this.showNotification(message, 'success');
    }

    showError(message) {
        this.showNotification(message, 'error');
        
        // If it's an authentication error, show it prominently
        if (message.includes('Authentication required') || message.includes('log in')) {
            const treeContainer = document.getElementById('locationsTree');
            if (treeContainer) {
                treeContainer.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-lock"></i>
                        <h3>Authentication Required</h3>
                        <p>Please log in to access the location management system.</p>
                        <a href="/pages/login-fixed.php" class="btn btn-primary">
                            <i class="fas fa-sign-in-alt"></i> Go to Login
                        </a>
                    </div>
                `;
            }
        }
    }

    showNotification(message, type) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
                <span>${message}</span>
            </div>
        `;
        
        // Add to page
        document.body.appendChild(notification);
        
        // Show notification
        setTimeout(() => notification.classList.add('show'), 100);
        
        // Remove after 5 seconds
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 300);
        }, 5000);
    }

    closeModal(modal) {
        modal.classList.remove('show');
    }
}

// Global functions for onclick handlers
function openLocationModal() {
    locationManager.openLocationModal();
}

function closeLocationModal() {
    locationManager.closeLocationModal();
}

function saveLocation() {
    locationManager.saveLocation();
}

function runAutoAssignment() {
    locationManager.openAutoAssignmentModal();
}

function closeAutoAssignmentModal() {
    locationManager.closeAutoAssignmentModal();
}

function executeAutoAssignment() {
    locationManager.executeAutoAssignment();
}

function expandAll() {
    locationManager.expandAll();
}

function collapseAll() {
    locationManager.collapseAll();
}

function applyFilters() {
    locationManager.applyFilters();
}

function clearFilters() {
    locationManager.clearFilters();
}

function addIpRange() {
    locationManager.addIpRange();
}

function removeIpRange(button) {
    locationManager.removeIpRange(button);
}

function toggleRangeFormat(select) {
    locationManager.toggleRangeFormat(select);
}

// Debounce utility function
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

// Initialize location manager when DOM is loaded
let locationManager;
document.addEventListener('DOMContentLoaded', () => {
    locationManager = new LocationManager();
});
