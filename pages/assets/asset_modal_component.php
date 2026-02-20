<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
?>

<!-- Comprehensive Asset Modal -->
<div id="assetModal" class="modal">
    <div class="modal-content large">
        <div class="modal-header">
            <h3><i class="fas fa-server"></i> Asset Details</h3>
            <button type="button" class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
            <!-- Tab Navigation -->
            <div class="tab-navigation">
                <button class="tab-button active" data-tab="overview">
                    <i class="fas fa-info-circle"></i> Overview
                </button>
                <button class="tab-button" data-tab="fda">
                    <i class="fas fa-certificate"></i> FDA Data
                </button>
                <button class="tab-button" data-tab="security">
                    <i class="fas fa-shield-alt"></i> Security
                </button>
                <button class="tab-button" data-tab="vulnerabilities">
                    <i class="fas fa-bug"></i> Vulnerabilities
                    <span class="badge" id="vulnCount">0</span>
                </button>
                <button class="tab-button" data-tab="recalls">
                    <i class="fas fa-exclamation-triangle"></i> Recalls
                    <span class="badge" id="recallCount">0</span>
                </button>
                <button class="tab-button" data-tab="sbom">
                    <i class="fas fa-list"></i> SBOM
                    <span class="badge" id="sbomCount">0</span>
                </button>
                <button class="tab-button" data-tab="timeline">
                    <i class="fas fa-history"></i> Timeline
                </button>
            </div>

            <!-- Tab Content -->
            <div class="tab-content">
                <!-- Overview Tab -->
                <div id="overview" class="tab-panel active">
                    <div class="section-header">
                        <h4><i class="fas fa-info-circle"></i> Basic Information</h4>
                    </div>
                    <div class="info-grid">
                        <div class="info-item">
                            <label>Asset ID</label>
                            <span id="assetId">-</span>
                        </div>
                        <div class="info-item">
                            <label>Hostname</label>
                            <span id="hostname">-</span>
                        </div>
                        <div class="info-item">
                            <label>IP Address</label>
                            <span id="ipAddress">-</span>
                        </div>
                        <div class="info-item">
                            <label>MAC Address</label>
                            <span id="macAddress">-</span>
                        </div>
                        <div class="info-item">
                            <label>Asset Type</label>
                            <span id="assetType">-</span>
                        </div>
                        <div class="info-item">
                            <label>Manufacturer</label>
                            <span id="manufacturer">-</span>
                        </div>
                        <div class="info-item">
                            <label>Model</label>
                            <span id="model">-</span>
                        </div>
                        <div class="info-item">
                            <label>Serial Number</label>
                            <span id="serialNumber">-</span>
                        </div>
                        <div class="info-item">
                            <label>Location</label>
                            <span id="location">-</span>
                        </div>
                        <div class="info-item">
                            <label>Department</label>
                            <span id="department">-</span>
                        </div>
                        <div class="info-item">
                            <label>Criticality</label>
                            <span id="criticality" class="criticality-badge">-</span>
                        </div>
                        <div class="info-item">
                            <label>Location Path</label>
                            <span id="locationPath">-</span>
                        </div>
                        <div class="info-item">
                            <label>Assignment Method</label>
                            <span id="assignmentMethod">-</span>
                        </div>
                        <div class="info-item">
                            <label>Status</label>
                            <span id="status" class="status-badge">-</span>
                        </div>
                        <div class="info-item">
                            <label>Asset Tag</label>
                            <span id="assetTag">-</span>
                        </div>
                        <div class="info-item">
                            <label>Asset Subtype</label>
                            <span id="assetSubtype">-</span>
                        </div>
                        <div class="info-item">
                            <label>Source</label>
                            <span id="source">-</span>
                        </div>
                        <div class="info-item">
                            <label>Operating System</label>
                            <span id="operatingSystem">-</span>
                        </div>
                        <div class="info-item">
                            <label>Open Ports</label>
                            <span id="openPorts">-</span>
                        </div>
                    </div>

                    <div class="section-header">
                        <h4><i class="fas fa-cogs"></i> Technical Specifications</h4>
                    </div>
                    <div class="info-grid">
                        <div class="info-item">
                            <label>Firmware Version</label>
                            <span id="firmwareVersion">-</span>
                        </div>
                        <div class="info-item">
                            <label>CPU</label>
                            <span id="cpu">-</span>
                        </div>
                        <div class="info-item">
                            <label>Memory/RAM</label>
                            <span id="memoryRam">-</span>
                        </div>
                        <div class="info-item">
                            <label>Storage</label>
                            <span id="storage">-</span>
                        </div>
                        <div class="info-item">
                            <label>Power Requirements</label>
                            <span id="powerRequirements">-</span>
                        </div>
                        <div class="info-item">
                            <label>Communication Protocol</label>
                            <span id="primaryCommunicationProtocol">-</span>
                        </div>
                        <div class="info-item">
                            <label>OS Detection</label>
                            <span id="osDetection">-</span>
                        </div>
                        <div class="info-item">
                            <label>OS Accuracy</label>
                            <span id="osAccuracy">-</span>
                        </div>
                        <div class="info-item">
                            <label>Services Running</label>
                            <span id="servicesRunning">-</span>
                        </div>
                    </div>

                    <!-- Network Services Section -->
                    <div class="section-header">
                        <h4><i class="fas fa-network-wired"></i> Network Services</h4>
                    </div>
                    <div class="services-container">
                        <div id="networkServices">
                            <p class="no-data">No network service data available</p>
                        </div>
                    </div>

                    <div class="section-header">
                        <h4><i class="fas fa-building"></i> Business Information</h4>
                    </div>
                    <div class="info-grid">
                        <div class="info-item">
                            <label>Business Unit</label>
                            <span id="businessUnit">-</span>
                        </div>
                        <div class="info-item">
                            <label>Cost Center</label>
                            <span id="costCenter">-</span>
                        </div>
                        <div class="info-item">
                            <label>Assigned Admin</label>
                            <span id="assignedAdminUser">-</span>
                        </div>
                        <div class="info-item">
                            <label>Warranty Expiration</label>
                            <span id="warrantyExpirationDate">-</span>
                        </div>
                        <div class="info-item">
                            <label>Scheduled Replacement</label>
                            <span id="scheduledReplacementDate">-</span>
                        </div>
                        <div class="info-item">
                            <label>Disposal Date</label>
                            <span id="disposalDate">-</span>
                        </div>
                        <div class="info-item">
                            <label>Disposal Method</label>
                            <span id="disposalMethod">-</span>
                        </div>
                    </div>

                    <div class="section-header">
                        <h4><i class="fas fa-clock"></i> Timestamps</h4>
                    </div>
                    <div class="info-grid">
                        <div class="info-item">
                            <label>First Seen</label>
                            <span id="firstSeen">-</span>
                        </div>
                        <div class="info-item">
                            <label>Last Seen</label>
                            <span id="lastSeen">-</span>
                        </div>
                        <div class="info-item">
                            <label>Created</label>
                            <span id="createdAt">-</span>
                        </div>
                        <div class="info-item">
                            <label>Updated</label>
                            <span id="updatedAt">-</span>
                        </div>
                    </div>
                </div>

                <!-- FDA Data Tab -->
                <div id="fda" class="tab-panel">
                    <div class="section-header">
                        <h4><i class="fas fa-certificate"></i> FDA Device Information</h4>
                    </div>
                    
                    <!-- FDA Sub-tab Navigation -->
                    <div class="sub-tab-navigation">
                        <button class="sub-tab-button active" data-subtab="device-info">
                            <i class="fas fa-info-circle"></i> Device Info
                        </button>
                        <button class="sub-tab-button" data-subtab="510k-info">
                            <i class="fas fa-file-medical"></i> 510k Information
                        </button>
                    </div>
                    
                    <!-- FDA Sub-tab Content -->
                    <div class="sub-tab-content">
                        <!-- Device Information Sub-tab -->
                        <div id="device-info" class="sub-tab-panel active">
                    
                    <div class="fda-section">
                        <h5>Basic Device Info</h5>
                        <div class="info-grid">
                            <div class="info-item">
                                <label>Device Identifier</label>
                                <span id="deviceIdentifier">-</span>
                            </div>
                            <div class="info-item">
                                <label>Brand Name</label>
                                <span id="brandName">-</span>
                            </div>
                            <div class="info-item">
                                <label>Model Number</label>
                                <span id="modelNumber">-</span>
                            </div>
                            <div class="info-item">
                                <label>Manufacturer</label>
                                <span id="manufacturerName">-</span>
                            </div>
                            <div class="info-item">
                                <label>Description</label>
                                <span id="deviceDescription">-</span>
                            </div>
                            <div class="info-item">
                                <label>Catalog Number</label>
                                <span id="catalogNumber">-</span>
                            </div>
                        </div>
                    </div>

                    <div class="fda-section">
                        <h5>Regulatory Information</h5>
                        <div class="info-grid">
                            <div class="info-item">
                                <label>GMDN Term</label>
                                <span id="gmdnTerm">-</span>
                            </div>
                            <div class="info-item">
                                <label>GMDN Code</label>
                                <span id="gmdnCode">-</span>
                            </div>
                            <div class="info-item">
                                <label>FDA Class</label>
                                <span id="fdaClass" class="fda-class-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>FDA Class Name</label>
                                <span id="fdaClassName">-</span>
                            </div>
                            <div class="info-item">
                                <label>Regulation Number</label>
                                <span id="regulationNumber">-</span>
                            </div>
                            <div class="info-item">
                                <label>Medical Specialty</label>
                                <span id="medicalSpecialty">-</span>
                            </div>
                            <div class="info-item">
                                <label>Implantable</label>
                                <span id="isImplantable" class="boolean-badge">-</span>
                            </div>
                        </div>
                    </div>

                    <div class="fda-section">
                        <h5>Device Identifiers</h5>
                        <div class="info-grid">
                            <div class="info-item">
                                <label>Primary UDI</label>
                                <span id="primaryUdi">-</span>
                            </div>
                            <div class="info-item">
                                <label>Package UDI</label>
                                <span id="packageUdi">-</span>
                            </div>
                            <div class="info-item">
                                <label>Issuing Agency</label>
                                <span id="issuingAgency">-</span>
                            </div>
                            <div class="info-item">
                                <label>Product Code</label>
                                <span id="productCode">-</span>
                            </div>
                            <div class="info-item">
                                <label>Product Code Name</label>
                                <span id="productCodeName">-</span>
                            </div>
                        </div>
                    </div>

                    <div class="fda-section">
                        <h5>Commercial Status</h5>
                        <div class="info-grid">
                            <div class="info-item">
                                <label>Commercial Status</label>
                                <span id="commercialStatus" class="status-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>Record Status</label>
                                <span id="recordStatus" class="status-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>Single Use</label>
                                <span id="isSingleUse" class="boolean-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>Kit</label>
                                <span id="isKit" class="boolean-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>Combination Product</label>
                                <span id="isCombinationProduct" class="boolean-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>OTC</label>
                                <span id="isOtc" class="boolean-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>Rx</label>
                                <span id="isRx" class="boolean-badge">-</span>
                            </div>
                        </div>
                    </div>

                    <div class="fda-section">
                        <h5>Sterilization & Safety</h5>
                        <div class="info-grid">
                            <div class="info-item">
                                <label>Is Sterile</label>
                                <span id="isSterile" class="boolean-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>Sterilization Methods</label>
                                <span id="sterilizationMethods">-</span>
                            </div>
                            <div class="info-item">
                                <label>Sterilization Prior Use</label>
                                <span id="isSterilizationPriorUse" class="boolean-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>MRI Safety</label>
                                <span id="mriSafety">-</span>
                            </div>
                        </div>
                    </div>

                    <div class="fda-section">
                        <h5>Regulatory Compliance</h5>
                        <div class="info-grid">
                            <div class="info-item">
                                <label>PM Exempt</label>
                                <span id="isPmExempt" class="boolean-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>Direct Marking Exempt</label>
                                <span id="isDirectMarkingExempt" class="boolean-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>Has Serial Number</label>
                                <span id="hasSerialNumber" class="boolean-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>Has Lot/Batch Number</label>
                                <span id="hasLotBatchNumber" class="boolean-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>Has Expiration Date</label>
                                <span id="hasExpirationDate" class="boolean-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>Has Manufacturing Date</label>
                                <span id="hasManufacturingDate" class="boolean-badge">-</span>
                            </div>
                        </div>
                    </div>

                    <div class="fda-section">
                        <h5>Contact Information</h5>
                        <div class="info-grid">
                            <div class="info-item">
                                <label>Customer Phone</label>
                                <span id="customerPhone">-</span>
                            </div>
                            <div class="info-item">
                                <label>Customer Email</label>
                                <span id="customerEmail">-</span>
                            </div>
                            <div class="info-item">
                                <label>Labeler DUNS Number</label>
                                <span id="labelerDunsNumber">-</span>
                            </div>
                        </div>
                    </div>

                    <div class="fda-section">
                        <h5>Version Information</h5>
                        <div class="info-grid">
                            <div class="info-item">
                                <label>Public Version Number</label>
                                <span id="publicVersionNumber">-</span>
                            </div>
                            <div class="info-item">
                                <label>Public Version Date</label>
                                <span id="publicVersionDate">-</span>
                            </div>
                            <div class="info-item">
                                <label>Public Version Status</label>
                                <span id="publicVersionStatus" class="status-badge">-</span>
                            </div>
                            <div class="info-item">
                                <label>Publish Date</label>
                                <span id="publishDate">-</span>
                            </div>
                            <div class="info-item">
                                <label>Device Count in Package</label>
                                <span id="deviceCountInBasePackage">-</span>
                            </div>
                        </div>
                    </div>
                        </div>
                        
                        <!-- 510k Information Sub-tab -->
                        <div id="510k-info" class="sub-tab-panel">
                            <div class="fda-section">
                                <h5>510k Information</h5>
                                <div id="510kLoading" class="loading-message">
                                    <i class="fas fa-spinner fa-spin"></i> Loading 510k information...
                                </div>
                                <div id="510kContent" class="info-grid" style="display: none;">
                                    <div class="info-item">
                                        <label>510k Number</label>
                                        <span id="510kNumber">-</span>
                                    </div>
                                    <div class="info-item">
                                        <label>510k Status</label>
                                        <span id="510kStatus">-</span>
                                    </div>
                                    <div class="info-item">
                                        <label>Decision Date</label>
                                        <span id="510kDecisionDate">-</span>
                                    </div>
                                    <div class="info-item">
                                        <label>Applicant</label>
                                        <span id="510kApplicant">-</span>
                                    </div>
                                    <div class="info-item">
                                        <label>Device Name</label>
                                        <span id="510kDeviceName">-</span>
                                    </div>
                                    <div class="info-item">
                                        <label>Product Code</label>
                                        <span id="510kProductCode">-</span>
                                    </div>
                                    <div class="info-item">
                                        <label>Regulation Number</label>
                                        <span id="510kRegulationNumber">-</span>
                                    </div>
                                    <div class="info-item">
                                        <label>Statement or Summary</label>
                                        <span id="510kStatement">-</span>
                                    </div>
                                </div>
                                <div id="510kError" class="error-message" style="display: none;">
                                    <i class="fas fa-exclamation-triangle"></i> No 510k information available for this device.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Security Tab -->
                <div id="security" class="tab-panel">
                    <div class="section-header">
                        <h4><i class="fas fa-shield-alt"></i> Security Information</h4>
                    </div>
                    <div class="info-grid">
                        <div class="info-item">
                            <label>Regulatory Classification</label>
                            <span id="regulatoryClassification">-</span>
                        </div>
                        <div class="info-item">
                            <label>PHI Status</label>
                            <span id="phiStatus" class="boolean-badge">-</span>
                        </div>
                        <div class="info-item">
                            <label>Data Encryption (Transit)</label>
                            <span id="dataEncryptionTransit">-</span>
                        </div>
                        <div class="info-item">
                            <label>Data Encryption (Rest)</label>
                            <span id="dataEncryptionRest">-</span>
                        </div>
                        <div class="info-item">
                            <label>Authentication Method</label>
                            <span id="authenticationMethod">-</span>
                        </div>
                        <div class="info-item">
                            <label>Patch Level Last Update</label>
                            <span id="patchLevelLastUpdate">-</span>
                        </div>
                        <div class="info-item">
                            <label>Last Audit Date</label>
                            <span id="lastAuditDate">-</span>
                        </div>
                    </div>
                </div>

                <!-- Vulnerabilities Tab -->
                <div id="vulnerabilities" class="tab-panel">
                    <div class="section-header">
                        <h4><i class="fas fa-bug"></i> Security Vulnerabilities</h4>
                    </div>
                    <div id="vulnerabilitiesList" class="vulnerabilities-list">
                        <!-- Vulnerabilities will be loaded here -->
                    </div>
                </div>

                <!-- Recalls Tab -->
                <div id="recalls" class="tab-panel">
                    <div class="section-header">
                        <h4><i class="fas fa-exclamation-triangle"></i> FDA Recalls</h4>
                    </div>
                    <div id="recallsList" class="recalls-list">
                        <!-- Recalls will be loaded here -->
                    </div>
                </div>

                <!-- SBOM Tab -->
                <div id="sbom" class="tab-panel">
                    <div class="section-header">
                        <h4><i class="fas fa-list"></i> Software Bill of Materials</h4>
                        <div class="section-actions">
                            <button type="button" class="btn btn-sm btn-primary" id="uploadSbomBtn">
                                <i class="fas fa-upload"></i> Upload SBOM
                            </button>
                            <button type="button" class="btn btn-sm btn-secondary" id="evaluateSbomBtn">
                                <i class="fas fa-search"></i> Evaluate Against NVD
                            </button>
                        </div>
                    </div>
                    
                    <!-- SBOM Files Section -->
                    <div class="sbom-section">
                        <h5><i class="fas fa-file"></i> SBOM Files</h5>
                        <div id="sbomFilesList" class="sbom-files-list">
                            <!-- SBOM files will be loaded here -->
                        </div>
                    </div>
                    
                    <!-- Software Components Section -->
                    <div class="sbom-section">
                        <h5><i class="fas fa-cogs"></i> Software Components</h5>
                        <div class="component-controls">
                            <div class="search-box">
                                <input type="text" id="componentSearch" placeholder="Search components..." class="form-control">
                                <i class="fas fa-search"></i>
                            </div>
                            <div class="filter-controls">
                                <select id="vendorFilter" class="form-control">
                                    <option value="">All Vendors</option>
                                </select>
                                <select id="licenseFilter" class="form-control">
                                    <option value="">All Licenses</option>
                                </select>
                            </div>
                        </div>
                        <div id="componentsList" class="components-list">
                            <!-- Software components will be loaded here -->
                        </div>
                    </div>
                </div>

                <!-- Timeline Tab -->
                <div id="timeline" class="tab-panel">
                    <div class="section-header">
                        <h4><i class="fas fa-history"></i> Activity Timeline</h4>
                    </div>
                    <div id="timelineList" class="timeline-list">
                        <!-- Timeline will be loaded here -->
                    </div>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" id="closeAssetModal">Close</button>
            <button type="button" class="btn btn-primary" id="editAsset">Edit Asset</button>
        </div>
    </div>
</div>

<style>
/* Asset Modal Styles */
#assetModal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.8);
    z-index: 1000;
    align-items: center;
    justify-content: center;
}

#assetModal.show {
    display: flex !important;
}

#assetModal .modal-content.large {
    max-width: 1200px;
    width: 95%;
    max-height: 90vh;
    overflow-y: auto;
}

/* Tab Navigation */
.tab-navigation {
    display: flex;
    border-bottom: 2px solid var(--border-primary);
    margin-bottom: 1rem;
    overflow-x: auto;
}

.tab-button {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.75rem 1rem;
    background: transparent;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    transition: all 0.2s ease;
    border-bottom: 3px solid transparent;
    white-space: nowrap;
    font-weight: 500;
    font-size: 0.9rem;
}

.tab-button:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
}

.tab-button.active {
    color: var(--siemens-petrol);
    border-bottom-color: var(--siemens-petrol);
    background: var(--bg-secondary);
}

/* Sub-tab Navigation */
.sub-tab-navigation {
    display: flex;
    border-bottom: 1px solid var(--border-secondary);
    margin-bottom: 1.5rem;
    overflow-x: auto;
}

.sub-tab-button {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.75rem 1.5rem;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    transition: all 0.2s ease;
    font-size: 0.9rem;
    font-weight: 500;
    white-space: nowrap;
}

.sub-tab-button:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
}

.sub-tab-button.active {
    color: var(--siemens-petrol);
    border-bottom-color: var(--siemens-petrol);
    background: var(--bg-hover);
}

.sub-tab-panel {
    display: none;
}

    .sub-tab-panel.active {
        display: block;
    }

    /* 510k Selection Interface */
    .510k-selection {
        padding: 1rem;
    }

    .510k-selection h5 {
        color: var(--text-primary);
        margin-bottom: 0.5rem;
        font-size: 1.1rem;
    }

    .510k-selection p {
        color: var(--text-secondary);
        margin-bottom: 1rem;
        font-size: 0.9rem;
    }

    .510k-options {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
        max-height: 400px;
        overflow-y: auto;
    }

    .510k-option {
        background: var(--bg-card);
        border: 1px solid var(--border-primary);
        border-radius: 0.5rem;
        padding: 1rem;
        cursor: pointer;
        transition: all 0.2s ease;
    }

    .510k-option:hover {
        background: var(--bg-hover);
        border-color: var(--siemens-petrol);
        transform: translateY(-1px);
        box-shadow: 0 2px 8px rgba(0, 153, 153, 0.1);
    }

    .510k-option.exact-match {
        border-color: var(--siemens-petrol);
        background: rgba(0, 153, 153, 0.05);
    }

    .510k-option.exact-match:hover {
        background: rgba(0, 153, 153, 0.1);
        box-shadow: 0 4px 12px rgba(0, 153, 153, 0.2);
    }

    .option-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.5rem;
    }

    .option-header strong {
        color: var(--siemens-petrol);
        font-size: 1rem;
    }

    .option-date {
        color: var(--text-muted);
        font-size: 0.8rem;
    }

    .option-details {
        margin-bottom: 0.75rem;
    }

    .option-device {
        color: var(--text-primary);
        font-weight: 500;
        margin-bottom: 0.25rem;
        font-size: 0.9rem;
    }

    .option-applicant {
        color: var(--text-secondary);
        font-size: 0.8rem;
    }

    .option-badges {
        display: flex;
        gap: 0.5rem;
    }

    .badge {
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
    }

    .badge.recent {
        background: rgba(16, 185, 129, 0.2);
        color: var(--success-green);
        border: 1px solid rgba(16, 185, 129, 0.3);
    }

    .badge.siemens {
        background: rgba(0, 153, 153, 0.2);
        color: var(--siemens-petrol);
        border: 1px solid rgba(0, 153, 153, 0.3);
    }

    .badge.exact {
        background: rgba(0, 153, 153, 0.3);
        color: var(--siemens-petrol);
        border: 1px solid var(--siemens-petrol);
        font-weight: 700;
    }

.tab-button .badge {
    background: var(--error-red);
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    font-weight: 600;
    margin-left: 0.5rem;
}

/* Tab Content */
.tab-content {
    min-height: 400px;
}

.tab-panel {
    display: none;
}

.tab-panel.active {
    display: block;
}

/* Section Headers */
.section-header {
    margin-bottom: 1rem;
    padding: 0.75rem 1rem;
    background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-card) 100%);
    border: 1px solid var(--border-primary);
    border-radius: 6px;
    border-left: 3px solid var(--siemens-petrol);
    position: relative;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.section-header::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--siemens-petrol), var(--siemens-petrol-light));
    border-radius: 8px 8px 0 0;
}

.section-header h4 {
    color: var(--text-primary);
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.section-header h4 i {
    color: var(--siemens-petrol);
    font-size: 0.9rem;
}

.section-header h5 {
    color: var(--text-primary);
    margin: 1.5rem 0 1rem 0;
    font-size: 1rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.section-header h5 i {
    color: var(--siemens-petrol);
    font-size: 0.9rem;
}

/* SBOM Tab Styles - Updated: 2025-01-10 20:55:00 - Fixed form controls and dark theme */
.sbom-section {
    margin-bottom: 2rem;
}

.sbom-files-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.sbom-file-item {
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: 8px;
    padding: 1rem;
    transition: all 0.3s ease;
}

.sbom-file-item:hover {
    border-color: var(--siemens-petrol);
    box-shadow: 0 2px 8px rgba(0, 153, 153, 0.1);
}

.sbom-file-header {
    display: flex;
    justify-content: between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.sbom-file-name {
    font-weight: 600;
    color: var(--text-primary);
    font-size: 1rem;
}

.sbom-file-status {
    padding: 0.25rem 0.75rem;
    border-radius: 1rem;
    font-size: 0.75rem;
    font-weight: 500;
    text-transform: uppercase;
}

.sbom-file-status.success {
    background: var(--success-green);
    color: white;
}

.sbom-file-status.failed {
    background: var(--error-red);
    color: white;
}

.sbom-file-status.pending {
    background: var(--warning-orange);
    color: white;
}

.sbom-file-meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 0.5rem;
    font-size: 0.875rem;
    color: var(--text-secondary);
}

.component-controls {
    display: flex;
    gap: 1rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
}

.search-box {
    position: relative;
    flex: 1;
    min-width: 200px;
}

.search-box input {
    padding-right: 2.5rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-primary);
    color: var(--text-primary);
    border-radius: 0.375rem;
    padding: 0.75rem 1rem;
    font-size: 0.875rem;
    transition: all 0.2s ease;
}

.search-box input:focus {
    outline: none;
    border-color: var(--siemens-petrol);
    box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
}

.search-box input::placeholder {
    color: var(--text-muted);
}

.search-box i {
    position: absolute;
    right: 0.75rem;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-muted);
    pointer-events: none;
}

.filter-controls {
    display: flex;
    gap: 0.5rem;
}

.filter-controls select {
    min-width: 120px;
    background: var(--bg-secondary);
    border: 1px solid var(--border-primary);
    color: var(--text-primary);
    border-radius: 0.375rem;
    padding: 0.75rem 1rem;
    font-size: 0.875rem;
    transition: all 0.2s ease;
    cursor: pointer;
}

.filter-controls select:focus {
    outline: none;
    border-color: var(--siemens-petrol);
    box-shadow: 0 0 0 3px rgba(0, 153, 153, 0.1);
}

.filter-controls select option {
    background: var(--bg-secondary);
    color: var(--text-primary);
    padding: 0.5rem;
}

.components-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    max-height: 400px;
    overflow-y: auto;
}

.component-item {
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: 6px;
    padding: 1rem;
    transition: all 0.3s ease;
}

.component-item:hover {
    border-color: var(--siemens-petrol);
    box-shadow: 0 2px 6px rgba(0, 153, 153, 0.1);
}

.component-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 0.5rem;
}

.component-name {
    font-weight: 600;
    color: var(--text-primary);
    font-size: 1rem;
}

.component-version {
    background: var(--siemens-petrol);
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 500;
}

.component-details {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 0.5rem;
    font-size: 0.875rem;
    color: var(--text-secondary);
}

.component-detail {
    display: flex;
    flex-direction: column;
}

.component-detail-label {
    font-weight: 500;
    color: var(--text-muted);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.component-detail-value {
    color: var(--text-primary);
    word-break: break-word;
}

.empty-state {
    text-align: center;
    padding: 3rem 1rem;
    color: var(--text-muted);
}

.empty-state i {
    font-size: 3rem;
    margin-bottom: 1rem;
    opacity: 0.5;
    color: var(--text-muted);
}

.empty-state h4 {
    color: var(--text-secondary);
    margin-bottom: 0.5rem;
    font-weight: 600;
}

.empty-state p {
    color: var(--text-muted);
    font-size: 0.875rem;
    line-height: 1.5;
}

/* SBOM Tab Button Styling */
.section-actions .btn {
    background: var(--bg-secondary);
    border: 1px solid var(--border-primary);
    color: var(--text-primary);
    transition: all 0.2s ease;
}

.section-actions .btn:hover {
    background: var(--bg-hover);
    border-color: var(--siemens-petrol);
    color: var(--siemens-petrol);
}

.section-actions .btn.btn-primary {
    background: var(--siemens-petrol);
    border-color: var(--siemens-petrol);
    color: white;
}

.section-actions .btn.btn-primary:hover {
    background: var(--siemens-petrol-dark);
    border-color: var(--siemens-petrol-dark);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0, 153, 153, 0.3);
}

.section-actions .btn.btn-secondary {
    background: var(--bg-secondary);
    border-color: var(--border-secondary);
    color: var(--text-primary);
}

.section-actions .btn.btn-secondary:hover {
    background: var(--bg-hover);
    border-color: var(--siemens-petrol);
    color: var(--siemens-petrol);
}

/* SBOM Tab Section Headers */
.sbom-section h5 {
    color: var(--text-primary);
    font-weight: 600;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.sbom-section h5 i {
    color: var(--siemens-petrol);
}

/* SBOM Tab Responsive Design */
@media (max-width: 768px) {
    .component-controls {
        flex-direction: column;
        gap: 0.75rem;
    }
    
    .search-box {
        min-width: 100%;
    }
    
    .filter-controls {
        flex-direction: column;
        gap: 0.5rem;
    }
    
    .filter-controls select {
        min-width: 100%;
    }
    
    .component-details {
        grid-template-columns: 1fr;
        gap: 0.75rem;
    }
    
    .sbom-file-meta {
        grid-template-columns: 1fr;
        gap: 0.75rem;
    }
}

/* SBOM Tab Loading States */
.btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    pointer-events: none;
}

.btn .fa-spinner {
    animation: spin 1s linear infinite;
}

@keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}

/* SBOM Tab Scrollbar Styling */
.components-list::-webkit-scrollbar {
    width: 6px;
}

.components-list::-webkit-scrollbar-track {
    background: var(--bg-secondary);
    border-radius: 3px;
}

.components-list::-webkit-scrollbar-thumb {
    background: var(--border-secondary);
    border-radius: 3px;
}

.components-list::-webkit-scrollbar-thumb:hover {
    background: var(--siemens-petrol);
}

.empty-state p {
    margin: 0;
    font-size: 0.875rem;
}

/* Info Grid */
.info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1rem;
    padding: 1rem;
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: 6px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.services-container {
    margin-bottom: 1.5rem;
}

.service-item {
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: 0.5rem;
    padding: 1rem;
    margin-bottom: 0.75rem;
    transition: all 0.2s ease;
}

.service-item:hover {
    border-color: var(--siemens-petrol);
    box-shadow: 0 2px 8px rgba(0, 153, 153, 0.1);
}

.service-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.service-port {
    font-weight: 600;
    color: var(--siemens-petrol);
    font-family: 'Siemens Sans', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

.service-name {
    font-weight: 500;
    color: var(--text-primary);
}

.service-details {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 0.5rem;
    font-size: 0.875rem;
    color: var(--text-secondary);
}

.service-detail {
    display: flex;
    flex-direction: column;
}

.service-detail-label {
    font-weight: 500;
    color: var(--text-muted);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.service-detail-value {
    color: var(--text-secondary);
    word-break: break-all;
}

.no-data {
    text-align: center;
    color: var(--text-muted);
    font-style: italic;
    padding: 2rem;
}

.info-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    padding: 0.75rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-primary);
    border-radius: 4px;
    transition: all 0.2s ease;
    position: relative;
}

.info-item:hover {
    border-color: var(--siemens-petrol);
    box-shadow: 0 2px 8px rgba(0, 153, 153, 0.1);
    transform: translateY(-1px);
}

.info-item::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 3px;
    height: 100%;
    background: var(--siemens-petrol);
    border-radius: 6px 0 0 6px;
    opacity: 0;
    transition: opacity 0.2s ease;
}

.info-item:hover::before {
    opacity: 1;
}

.info-item label {
    font-size: 0.7rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.3px;
    margin-bottom: 0.125rem;
}

.info-item span {
    color: var(--text-primary);
    font-weight: 500;
    font-size: 0.875rem;
    line-height: 1.3;
    word-break: break-word;
}

/* Badge Styles */
.status-badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 0.375rem;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    transition: all 0.2s ease;
}

.status-badge:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
}

.status-badge.Active {
    background: rgba(16, 185, 129, 0.1);
    color: var(--success-green);
    border: 1px solid var(--success-green);
}

.status-badge.Inactive {
    background: rgba(107, 114, 128, 0.1);
    color: var(--text-muted);
    border: 1px solid var(--text-muted);
}

.criticality-badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 0.375rem;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    transition: all 0.2s ease;
}

.criticality-badge:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
}

.criticality-badge.Clinical-High {
    background: rgba(239, 68, 68, 0.1);
    color: var(--error-red);
    border: 1px solid var(--error-red);
}

.criticality-badge.Business-Medium {
    background: rgba(245, 158, 11, 0.1);
    color: var(--warning-orange);
    border: 1px solid var(--warning-orange);
}

.criticality-badge.Non-Essential {
    background: rgba(107, 114, 128, 0.1);
    color: var(--text-muted);
    border: 1px solid var(--text-muted);
}

.boolean-badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 0.375rem;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    transition: all 0.2s ease;
}

.boolean-badge:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
}

.boolean-badge.True {
    background: rgba(16, 185, 129, 0.1);
    color: var(--success-green);
    border: 1px solid var(--success-green);
}

.boolean-badge.False {
    background: rgba(107, 114, 128, 0.1);
    color: var(--text-muted);
    border: 1px solid var(--text-muted);
}

.fda-class-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 0.375rem;
    font-size: 0.75rem;
    font-weight: 600;
    background: var(--siemens-petrol);
    color: white;
}

/* FDA Sections */
.fda-section {
    margin-bottom: 1rem;
    padding: 1rem;
    background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-card) 100%);
    border-radius: 6px;
    border: 1px solid var(--border-primary);
    border-left: 3px solid var(--siemens-petrol);
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    position: relative;
}

.fda-section::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--siemens-petrol), var(--siemens-petrol-light));
    border-radius: 8px 8px 0 0;
}

.fda-section h5 {
    color: var(--text-primary);
    font-weight: 600;
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.95rem;
}

.fda-section h5 i {
    color: var(--siemens-petrol);
    font-size: 1rem;
}

/* Vulnerabilities List */
.vulnerabilities-list {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

.vuln-section {
    margin-bottom: 2rem;
}

.section-title {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid var(--border-primary);
}

.section-title.kev-title {
    color: var(--siemens-orange);
}

.count-badge {
    background: var(--bg-tertiary);
    padding: 0.25rem 0.75rem;
    border-radius: 1rem;
    font-size: 0.85rem;
    font-weight: 600;
}

.vulnerabilities-grid {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

/* Compact Vulnerability Items */
.vulnerability-item-compact {
    background: var(--bg-secondary);
    border-radius: 0.5rem;
    border: 1px solid var(--border-primary);
    transition: all 0.2s ease;
    overflow: hidden;
}

.vulnerability-item-compact.kev-item {
    border-left: 4px solid var(--siemens-orange);
    background: linear-gradient(to right, rgba(255, 107, 53, 0.05), var(--bg-secondary));
}

.vulnerability-item-compact.overdue {
    border-left-color: var(--error-red);
    background: linear-gradient(to right, rgba(239, 68, 68, 0.05), var(--bg-secondary));
}

.vulnerability-item-compact:hover {
    background: var(--bg-hover);
    box-shadow: 0 2px 8px rgba(0, 153, 153, 0.1);
}

.vuln-compact-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.25rem;
    gap: 1rem;
}

.vuln-compact-left {
    flex: 1;
    min-width: 0;
}

.vuln-compact-title {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-wrap: wrap;
    margin-bottom: 0.5rem;
}

.vuln-compact-info {
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
    font-size: 0.875rem;
    color: var(--text-secondary);
}

.vuln-info-item {
    display: flex;
    align-items: center;
    gap: 0.375rem;
    white-space: nowrap;
}

.vuln-info-item i {
    color: var(--siemens-petrol);
    font-size: 0.85rem;
}

.status-badge-inline {
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    font-weight: 600;
}

.status-badge-inline.Open {
    background: rgba(239, 68, 68, 0.1);
    color: var(--error-red);
}

.status-badge-inline.In-Progress {
    background: rgba(245, 158, 11, 0.1);
    color: var(--warning-orange);
}

.status-badge-inline.Remediated {
    background: rgba(16, 185, 129, 0.1);
    color: var(--success-green);
}

.status-badge-inline.Risk-Accepted {
    background: rgba(59, 130, 246, 0.1);
    color: var(--siemens-petrol);
}

.vuln-compact-right {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.btn-view-vuln {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    background: var(--siemens-petrol);
    color: white;
    border: none;
    border-radius: 0.375rem;
    font-size: 0.875rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    white-space: nowrap;
}

.btn-view-vuln:hover {
    background: var(--siemens-petrol-dark);
    transform: translateY(-1px);
    box-shadow: 0 4px 8px rgba(0, 153, 153, 0.3);
}

.btn-view-vuln.active {
    background: var(--siemens-orange);
}

.btn-view-vuln.active:hover {
    background: var(--siemens-orange-dark);
}

/* Expanded Details Section */
.vuln-details-expanded {
    padding: 1.25rem;
    background: var(--bg-tertiary);
    border-top: 1px solid var(--border-secondary);
    animation: slideDown 0.3s ease;
}

@keyframes slideDown {
    from {
        opacity: 0;
        transform: translateY(-10px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.vuln-detail-row {
    display: grid;
    grid-template-columns: 180px 1fr;
    gap: 1rem;
    padding: 0.75rem 0;
    border-bottom: 1px solid var(--border-secondary);
}

.vuln-detail-row:last-of-type {
    border-bottom: none;
}

.vuln-detail-row strong {
    color: var(--text-primary);
    font-weight: 600;
}

.vuln-detail-row span {
    color: var(--text-secondary);
    line-height: 1.6;
}

.vuln-detail-row.highlight-component {
    background: rgba(0, 153, 153, 0.05);
    padding: 0.75rem;
    border-radius: 0.375rem;
    border: 1px solid rgba(0, 153, 153, 0.2);
    margin: 0.5rem 0;
}

.vuln-detail-row.kev-required-action {
    background: rgba(255, 107, 53, 0.1);
    padding: 0.75rem;
    border-radius: 0.375rem;
    border-left: 3px solid var(--siemens-orange);
    margin: 0.5rem 0;
}

.vuln-detail-row.kev-required-action strong {
    color: var(--siemens-orange);
}

.vuln-details-meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
    padding-top: 1rem;
    border-top: 2px solid var(--border-primary);
}

.meta-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.meta-item strong {
    color: var(--text-muted);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-weight: 600;
}

.meta-item span {
    color: var(--text-primary);
    font-size: 0.95rem;
    display: flex;
    align-items: center;
    gap: 0.375rem;
}

.status-badge-detail {
    padding: 0.375rem 0.75rem;
    border-radius: 0.375rem;
    font-size: 0.875rem;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
    width: fit-content;
}

.status-badge-detail.Open {
    background: rgba(239, 68, 68, 0.1);
    color: var(--error-red);
}

.status-badge-detail.In-Progress {
    background: rgba(245, 158, 11, 0.1);
    color: var(--warning-orange);
}

.status-badge-detail.Remediated {
    background: rgba(16, 185, 129, 0.1);
    color: var(--success-green);
}

.status-badge-detail.Risk-Accepted {
    background: rgba(59, 130, 246, 0.1);
    color: var(--siemens-petrol);
}

/* Responsive adjustments */
@media (max-width: 768px) {
    .vuln-compact-header {
        flex-direction: column;
        align-items: flex-start;
    }
    
    .vuln-compact-right {
        width: 100%;
        justify-content: space-between;
    }
    
    .vuln-detail-row {
        grid-template-columns: 1fr;
        gap: 0.5rem;
    }
    
    .vuln-details-meta {
        grid-template-columns: 1fr;
    }
}

.vulnerability-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 1rem;
    gap: 1rem;
}

.vulnerability-title-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-wrap: wrap;
}

.vulnerability-cve {
    font-weight: 600;
    color: var(--text-primary);
    font-size: 1.1rem;
}

.vulnerability-title {
    font-weight: 600;
    color: var(--text-primary);
    font-size: 1.1rem;
}

.vulnerability-name {
    font-size: 0.95rem;
    color: var(--text-secondary);
    margin-bottom: 0.75rem;
    font-weight: 500;
}

.kev-badge {
    background: var(--siemens-orange);
    color: white;
    padding: 0.25rem 0.75rem;
    border-radius: 0.375rem;
    font-size: 0.75rem;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
}

.ransomware-badge {
    background: var(--error-red);
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 0.375rem;
    font-size: 0.75rem;
    display: inline-flex;
    align-items: center;
}

.overdue-badge {
    background: var(--error-red);
    color: white;
    padding: 0.25rem 0.75rem;
    border-radius: 0.375rem;
    font-size: 0.75rem;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
}

.severity-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 0.375rem;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.severity-badge.Critical {
    background: rgba(239, 68, 68, 0.1);
    color: var(--error-red);
    border: 1px solid var(--error-red);
}

.severity-badge.High {
    background: rgba(245, 158, 11, 0.1);
    color: var(--warning-orange);
    border: 1px solid var(--warning-orange);
}

.severity-badge.Medium {
    background: rgba(59, 130, 246, 0.1);
    color: var(--siemens-petrol);
    border: 1px solid var(--siemens-petrol);
}

.severity-badge.Low {
    background: rgba(16, 185, 129, 0.1);
    color: var(--success-green);
    border: 1px solid var(--success-green);
}

.vulnerability-description {
    color: var(--text-secondary);
    margin-bottom: 1rem;
    line-height: 1.6;
}

.component-info {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.75rem;
    background: var(--bg-tertiary);
    border-radius: 0.375rem;
    margin-bottom: 0.75rem;
    font-size: 0.9rem;
    color: var(--text-secondary);
}

.component-info i {
    color: var(--siemens-petrol);
}

.kev-action {
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
    padding: 0.75rem;
    background: rgba(255, 107, 53, 0.1);
    border-left: 3px solid var(--siemens-orange);
    border-radius: 0.375rem;
    margin-bottom: 0.75rem;
    font-size: 0.9rem;
    color: var(--text-primary);
}

.kev-action i {
    color: var(--siemens-orange);
    margin-top: 0.25rem;
}

.vulnerability-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    margin-top: 1rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border-secondary);
    font-size: 0.9rem;
    color: var(--text-secondary);
}

.vulnerability-meta span {
    display: flex;
    align-items: center;
    gap: 0.375rem;
}

.vulnerability-meta i {
    color: var(--siemens-petrol);
}

.text-danger {
    color: var(--error-red) !important;
}

.text-danger i {
    color: var(--error-red) !important;
}

.status-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 0.375rem;
    font-size: 0.75rem;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
}

.status-badge.Open {
    background: rgba(239, 68, 68, 0.1);
    color: var(--error-red);
}

.status-badge.In.Progress,
.status-badge.In\\ Progress {
    background: rgba(245, 158, 11, 0.1);
    color: var(--warning-orange);
}

.status-badge.Remediated {
    background: rgba(16, 185, 129, 0.1);
    color: var(--success-green);
}

.status-badge.Risk\\ Accepted {
    background: rgba(59, 130, 246, 0.1);
    color: var(--siemens-petrol);
}

.status-badge.False\\ Positive {
    background: rgba(107, 114, 128, 0.1);
    color: var(--text-muted);
}

.assigned-to {
    margin-top: 0.75rem;
    padding-top: 0.75rem;
    border-top: 1px solid var(--border-secondary);
    font-size: 0.9rem;
    color: var(--text-secondary);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.assigned-to i {
    color: var(--siemens-petrol);
}

/* Recalls List */
.recalls-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.recall-item {
    background: var(--bg-secondary);
    border-radius: 0.5rem;
    padding: 1.5rem;
    border: 1px solid var(--border-primary);
    transition: all 0.2s ease;
}

.recall-item:hover {
    background: var(--bg-hover);
    transform: translateY(-1px);
    box-shadow: var(--shadow-sm);
}

.recall-header {
    display: flex;
    justify-content: between;
    align-items: center;
    margin-bottom: 1rem;
}

.recall-title {
    font-weight: 600;
    color: var(--text-primary);
    font-size: 1.1rem;
}

.recall-number {
    color: var(--siemens-petrol);
    font-weight: 600;
}

/* Timeline List */
.timeline-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.timeline-item {
    display: flex;
    gap: 1rem;
    padding: 1rem;
    background: var(--bg-secondary);
    border-radius: 0.5rem;
    border: 1px solid var(--border-primary);
}

.timeline-icon {
    width: 2rem;
    height: 2rem;
    border-radius: 50%;
    background: var(--siemens-petrol);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
}

.timeline-content {
    flex: 1;
}

.timeline-title {
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 0.25rem;
}

.timeline-description {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-bottom: 0.5rem;
}

.timeline-meta {
    display: flex;
    gap: 1rem;
    font-size: 0.75rem;
    color: var(--text-muted);
}

/* FDA Badge */
.fda-badge {
    display: inline-block;
    margin-left: 0.5rem;
    padding: 0.2rem 0.4rem;
    background: var(--siemens-petrol);
    color: white;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    font-weight: 500;
    vertical-align: middle;
}

.fda-badge i {
    margin-right: 0.2rem;
}

/* Medical Device Type Badge - Override existing styles */
.type-badge.medical-device {
    background: var(--siemens-petrol) !important;
    color: white !important;
    border: 1px solid var(--siemens-petrol) !important;
    font-weight: 600 !important;
    padding: 4px 12px !important;
    border-radius: 20px !important;
    white-space: normal !important;
    word-wrap: break-word !important;
    overflow-wrap: break-word !important;
    line-height: 1.2 !important;
    text-align: center !important;
}

/* Empty States */
.empty-state {
    text-align: center;
    padding: 3rem;
    color: var(--text-muted);
}

.empty-state i {
    font-size: 3rem;
    margin-bottom: 1rem;
    color: var(--text-muted);
}

/* Responsive Design */
@media (max-width: 768px) {
    .tab-navigation {
        flex-direction: column;
    }
    
    .tab-button {
        justify-content: center;
    }
    
    .info-grid {
        grid-template-columns: 1fr;
    }
    
    .vulnerability-header,
    .recall-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.5rem;
    }
}
</style>

<script>
// Asset Modal JavaScript
window.currentAssetData = null;

function openAssetModal(assetId) {
    const modal = document.getElementById('assetModal');
    if (modal) {
        modal.classList.add('show');
        loadAssetData(assetId);
    }
}

function closeAssetModal() {
    const modal = document.getElementById('assetModal');
    if (modal) {
        modal.classList.remove('show');
        window.currentAssetData = null;
    }
}

// Edit Asset functionality
function editAsset() {
    if (window.currentAssetData && window.currentAssetData.asset) {
        const assetId = window.currentAssetData.asset.asset_id;
        if (assetId) {
            // Close the modal first
            closeAssetModal();
            // Navigate to edit page (permission check will happen on the edit page)
            window.location.href = `/pages/assets/edit.php?id=${assetId}`;
        } else {
            showNotification('Asset ID not found', 'error');
        }
    } else {
        showNotification('Asset data not loaded', 'error');
    }
}

function loadAssetData(assetId) {
    // Use dynamic base URL detection to prevent CORS issues
    const protocol = window.location.protocol;
    const host = window.location.host;
    const baseUrl = `${protocol}//${host}`;
    const url = `${baseUrl}/pages/assets/asset_modal.php?asset_id=${assetId}&_t=${Date.now()}`;
    
    fetch(url, {
        method: 'GET',
        headers: {
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
    })
        .then(response => {
            return response.json();
        })
        .then(data => {
            console.log('Modal API response:', data);
            if (data.success) {
                window.currentAssetData = data;
                console.log('Calling populateAssetData with:', data);
                populateAssetData(data);
            } else {
                console.error('API error:', data.message);
                showNotification('Error loading asset data: ' + data.message, 'error');
            }
        })
        .catch(error => {
            console.error('Error loading asset data:', error);
            showNotification('Error loading asset data', 'error');
        });
}

function populateAssetData(data) {
    const asset = data.asset;
    
    // Debug logging
    console.log('Modal populateAssetData called with:', asset);
    console.log('assigned_location_name:', asset.assigned_location_name);
    console.log('location_criticality:', asset.location_criticality);
    console.log('location_hierarchy_path:', asset.location_hierarchy_path);
    console.log('location_assignment_method:', asset.location_assignment_method);
    
    // Overview Tab
    document.getElementById('assetId').textContent = asset.asset_id || '-';
    document.getElementById('hostname').textContent = asset.hostname || asset.brand_name || asset.device_name || '-';
    document.getElementById('ipAddress').textContent = asset.ip_address || '-';
    document.getElementById('macAddress').textContent = asset.mac_address || '-';
    // Show "Medical Device" for mapped assets, otherwise show original asset type
    const assetType = asset.mapping_status === 'Mapped' ? 'Medical Device' : (asset.asset_type || '-');
    document.getElementById('assetType').textContent = assetType;
    // Use FDA manufacturer if available, otherwise fall back to asset manufacturer
    const manufacturer = asset.manufacturer_name || asset.manufacturer || '-';
    document.getElementById('manufacturer').textContent = manufacturer;
    
    // Use FDA model if available, otherwise fall back to asset model
    const model = asset.model_number || asset.model || '-';
    document.getElementById('model').textContent = model;
    document.getElementById('serialNumber').textContent = asset.serial_number || '-';
    // Handle location - use more specific selector to avoid conflicts with main page elements
    const locationElement = document.querySelector('#assetModal #location');
    if (locationElement) {
        locationElement.textContent = asset.assigned_location_name || asset.location || '-';
    }
    // Handle department - use more specific selector to avoid conflicts with main page elements
    const departmentElement = document.querySelector('#assetModal #department');
    const departmentValue = asset.assigned_location_name || asset.department || '-';
    
    if (departmentElement) {
        departmentElement.textContent = departmentValue;
    } else {
        console.error('Department element not found in modal!');
    }
    // Handle criticality - use more specific selector to avoid conflicts with main page elements
    const criticalityElement = document.querySelector('#assetModal #criticality');
    const criticalityValue = asset.location_criticality || asset.criticality || '-';
    
    if (criticalityElement) {
        criticalityElement.textContent = criticalityValue;
        criticalityElement.className = `criticality-badge criticality-${asset.location_criticality || asset.criticality || 'unknown'}`;
    } else {
        console.error('Criticality element not found in modal!');
    }
    document.getElementById('locationPath').textContent = asset.location_hierarchy_path || '-';
    document.getElementById('assignmentMethod').textContent = asset.location_assignment_method || 'Manual';
    document.getElementById('status').textContent = asset.status || '-';
    document.getElementById('status').className = `status-badge ${asset.status || ''}`;
    
    // Additional Basic Information
    document.getElementById('assetTag').textContent = asset.asset_tag || '-';
    document.getElementById('assetSubtype').textContent = asset.asset_subtype || '-';
    document.getElementById('source').textContent = asset.source || '-';
    
    // OS and Port Information (from Nmap data)
    populateOSAndPortData(asset);
    
    // Technical Specifications
    document.getElementById('firmwareVersion').textContent = asset.firmware_version || '-';
    document.getElementById('cpu').textContent = asset.cpu || '-';
    document.getElementById('memoryRam').textContent = asset.memory_ram || '-';
    document.getElementById('storage').textContent = asset.storage || '-';
    document.getElementById('powerRequirements').textContent = asset.power_requirements || '-';
    document.getElementById('primaryCommunicationProtocol').textContent = asset.primary_communication_protocol || '-';
    
    // Business Information
    document.getElementById('businessUnit').textContent = asset.business_unit || '-';
    document.getElementById('costCenter').textContent = asset.cost_center || '-';
    document.getElementById('assignedAdminUser').textContent = asset.assigned_admin_user || '-';
    document.getElementById('warrantyExpirationDate').textContent = formatDate(asset.warranty_expiration_date);
    document.getElementById('scheduledReplacementDate').textContent = formatDate(asset.scheduled_replacement_date);
    document.getElementById('disposalDate').textContent = formatDate(asset.disposal_date);
    document.getElementById('disposalMethod').textContent = asset.disposal_method || '-';
    
    // Timestamps
    document.getElementById('firstSeen').textContent = formatDate(asset.first_seen);
    document.getElementById('lastSeen').textContent = formatDate(asset.last_seen);
    document.getElementById('createdAt').textContent = formatDate(asset.created_at);
    document.getElementById('updatedAt').textContent = formatDate(asset.updated_at);
    
    // FDA Data Tab
    populateFDAData(asset);
    
    // Security Tab
    populateSecurityData(asset);
    
    // Vulnerabilities Tab
    populateVulnerabilities(data.vulnerabilities);
    
    // Recalls Tab
    populateRecalls(data.recalls);
    
    // Timeline Tab
    populateTimeline(data.auditLogs);
    
    // SBOM Tab
    populateSbomData(data.sboms, data.components);
}

// Function to populate OS and port data from Nmap scan results
function populateOSAndPortData(asset) {
    // Parse raw data to extract OS and port information
    let osInfo = null;
    let portData = [];
    let services = [];
    
    if (asset.raw_data) {
        try {
            const rawData = JSON.parse(asset.raw_data);
            if (rawData.nmap_data) {
                const nmapData = rawData.nmap_data;
                
                // Extract OS information
                if (nmapData.os && nmapData.os.osmatch) {
                    const osMatches = Array.isArray(nmapData.os.osmatch) ? nmapData.os.osmatch : [nmapData.os.osmatch];
                    if (osMatches.length > 0) {
                        const bestMatch = osMatches[0];
                        osInfo = {
                            name: bestMatch['@attributes']?.name || 'Unknown',
                            accuracy: bestMatch['@attributes']?.accuracy || '0'
                        };
                    }
                }
                
                // Extract port and service information
                if (nmapData.ports && nmapData.ports.port) {
                    const ports = Array.isArray(nmapData.ports.port) ? nmapData.ports.port : [nmapData.ports.port];
                    
                    ports.forEach(port => {
                        const portState = port.state?.['@attributes']?.state;
                        if (portState === 'open') {
                            const portInfo = {
                                port: port['@attributes']?.portid || '',
                                protocol: port['@attributes']?.protocol || '',
                                service: port.service?.['@attributes']?.name || 'unknown',
                                version: port.service?.['@attributes']?.version || '',
                                product: port.service?.['@attributes']?.product || '',
                                extraInfo: port.service?.['@attributes']?.extrainfo || ''
                            };
                            portData.push(portInfo);
                            services.push(portInfo.service);
                        }
                    });
                }
            }
        } catch (e) {
            console.error('Error parsing raw data:', e);
        }
    }
    
    // Populate Overview section
    document.getElementById('operatingSystem').textContent = osInfo ? osInfo.name : (asset.firmware_version || '-');
    document.getElementById('openPorts').textContent = portData.length > 0 ? `${portData.length} ports` : '-';
    
    // Populate Technical Specifications section
    document.getElementById('osDetection').textContent = osInfo ? osInfo.name : '-';
    document.getElementById('osAccuracy').textContent = osInfo ? `${osInfo.accuracy}%` : '-';
    document.getElementById('servicesRunning').textContent = services.length > 0 ? services.join(', ') : '-';
    
    // Populate Network Services section
    populateNetworkServices(portData);
}

// Function to populate the network services section
function populateNetworkServices(portData) {
    const servicesContainer = document.getElementById('networkServices');
    
    if (!portData || portData.length === 0) {
        servicesContainer.innerHTML = '<p class="no-data">No network service data available</p>';
        return;
    }
    
    let servicesHTML = '';
    portData.forEach(service => {
        servicesHTML += `
            <div class="service-item">
                <div class="service-header">
                    <span class="service-port">${service.port}/${service.protocol}</span>
                    <span class="service-name">${service.service}</span>
                </div>
                <div class="service-details">
                    ${service.product ? `
                        <div class="service-detail">
                            <span class="service-detail-label">Product</span>
                            <span class="service-detail-value">${service.product}</span>
                        </div>
                    ` : ''}
                    ${service.version ? `
                        <div class="service-detail">
                            <span class="service-detail-label">Version</span>
                            <span class="service-detail-value">${service.version}</span>
                        </div>
                    ` : ''}
                    ${service.extraInfo ? `
                        <div class="service-detail">
                            <span class="service-detail-label">Extra Info</span>
                            <span class="service-detail-value">${service.extraInfo}</span>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    });
    
    servicesContainer.innerHTML = servicesHTML;
}

// Helper function to convert string boolean values
function parseBoolean(value) {
    if (value === null || value === undefined || value === '') return false;
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string') {
        return value.toLowerCase() === 'true' || value === '1';
    }
    return Boolean(value);
}

function populateFDAData(asset) {
    // Basic Device Info
    document.getElementById('deviceIdentifier').textContent = asset.device_identifier || 'N/A';
    document.getElementById('brandName').textContent = asset.brand_name || 'N/A';
    document.getElementById('modelNumber').textContent = asset.model_number || 'N/A';
    document.getElementById('manufacturerName').textContent = asset.manufacturer_name || 'N/A';
    document.getElementById('deviceDescription').textContent = asset.device_description || 'N/A';
    document.getElementById('catalogNumber').textContent = asset.catalog_number || 'N/A';
    
    // Regulatory Information
    document.getElementById('gmdnTerm').textContent = asset.gmdn_term || 'N/A';
    document.getElementById('gmdnCode').textContent = asset.gmdn_code || 'N/A';
    document.getElementById('fdaClass').textContent = asset.fda_class || 'N/A';
    document.getElementById('fdaClassName').textContent = asset.fda_class_name || 'N/A';
    document.getElementById('regulationNumber').textContent = asset.regulation_number || 'N/A';
    document.getElementById('medicalSpecialty').textContent = asset.medical_specialty || 'N/A';
    const isImplantable = parseBoolean(asset.is_implantable);
    document.getElementById('isImplantable').textContent = isImplantable ? 'True' : 'False';
    document.getElementById('isImplantable').className = `boolean-badge ${isImplantable ? 'true' : 'false'}`;
    
    // Device Identifiers
    document.getElementById('primaryUdi').textContent = asset.primary_udi || 'N/A';
    document.getElementById('packageUdi').textContent = asset.package_udi || 'N/A';
    document.getElementById('issuingAgency').textContent = asset.issuing_agency || 'N/A';
    document.getElementById('productCode').textContent = asset.product_code || 'N/A';
    document.getElementById('productCodeName').textContent = asset.product_code_name || 'N/A';
    
    // Commercial Status
    document.getElementById('commercialStatus').textContent = asset.commercial_status || 'N/A';
    document.getElementById('commercialStatus').className = `status-badge ${asset.commercial_status || ''}`;
    document.getElementById('recordStatus').textContent = asset.record_status || '-';
    document.getElementById('recordStatus').className = `status-badge ${asset.record_status || ''}`;
    const isSingleUse = parseBoolean(asset.is_single_use);
    document.getElementById('isSingleUse').textContent = isSingleUse ? 'True' : 'False';
    document.getElementById('isSingleUse').className = `boolean-badge ${isSingleUse ? 'true' : 'false'}`;
    
    const isKit = parseBoolean(asset.is_kit);
    document.getElementById('isKit').textContent = isKit ? 'True' : 'False';
    document.getElementById('isKit').className = `boolean-badge ${isKit ? 'true' : 'false'}`;
    
    const isCombinationProduct = parseBoolean(asset.is_combination_product);
    document.getElementById('isCombinationProduct').textContent = isCombinationProduct ? 'True' : 'False';
    document.getElementById('isCombinationProduct').className = `boolean-badge ${isCombinationProduct ? 'true' : 'false'}`;
    
    const isOtc = parseBoolean(asset.is_otc);
    document.getElementById('isOtc').textContent = isOtc ? 'True' : 'False';
    document.getElementById('isOtc').className = `boolean-badge ${isOtc ? 'true' : 'false'}`;
    
    const isRx = parseBoolean(asset.is_rx);
    document.getElementById('isRx').textContent = isRx ? 'True' : 'False';
    document.getElementById('isRx').className = `boolean-badge ${isRx ? 'true' : 'false'}`;
    
    // Sterilization & Safety
    const isSterile = parseBoolean(asset.is_sterile);
    document.getElementById('isSterile').textContent = isSterile ? 'True' : 'False';
    document.getElementById('isSterile').className = `boolean-badge ${isSterile ? 'true' : 'false'}`;
    document.getElementById('sterilizationMethods').textContent = asset.sterilization_methods || 'N/A';
    
    const isSterilizationPriorUse = parseBoolean(asset.is_sterilization_prior_use);
    document.getElementById('isSterilizationPriorUse').textContent = isSterilizationPriorUse ? 'True' : 'False';
    document.getElementById('isSterilizationPriorUse').className = `boolean-badge ${isSterilizationPriorUse ? 'true' : 'false'}`;
    document.getElementById('mriSafety').textContent = asset.mri_safety || 'N/A';
    
    // Regulatory Compliance
    const isPmExempt = parseBoolean(asset.is_pm_exempt);
    document.getElementById('isPmExempt').textContent = isPmExempt ? 'True' : 'False';
    document.getElementById('isPmExempt').className = `boolean-badge ${isPmExempt ? 'true' : 'false'}`;
    
    const isDirectMarkingExempt = parseBoolean(asset.is_direct_marking_exempt);
    document.getElementById('isDirectMarkingExempt').textContent = isDirectMarkingExempt ? 'True' : 'False';
    document.getElementById('isDirectMarkingExempt').className = `boolean-badge ${isDirectMarkingExempt ? 'true' : 'false'}`;
    
    const hasSerialNumber = parseBoolean(asset.has_serial_number);
    document.getElementById('hasSerialNumber').textContent = hasSerialNumber ? 'True' : 'False';
    document.getElementById('hasSerialNumber').className = `boolean-badge ${hasSerialNumber ? 'true' : 'false'}`;
    
    const hasLotBatchNumber = parseBoolean(asset.has_lot_batch_number);
    document.getElementById('hasLotBatchNumber').textContent = hasLotBatchNumber ? 'True' : 'False';
    document.getElementById('hasLotBatchNumber').className = `boolean-badge ${hasLotBatchNumber ? 'true' : 'false'}`;
    
    const hasExpirationDate = parseBoolean(asset.has_expiration_date);
    document.getElementById('hasExpirationDate').textContent = hasExpirationDate ? 'True' : 'False';
    document.getElementById('hasExpirationDate').className = `boolean-badge ${hasExpirationDate ? 'true' : 'false'}`;
    
    const hasManufacturingDate = parseBoolean(asset.has_manufacturing_date);
    document.getElementById('hasManufacturingDate').textContent = hasManufacturingDate ? 'True' : 'False';
    document.getElementById('hasManufacturingDate').className = `boolean-badge ${hasManufacturingDate ? 'true' : 'false'}`;
    
    // Contact Information
    document.getElementById('customerPhone').textContent = asset.customer_phone || 'N/A';
    document.getElementById('customerEmail').textContent = asset.customer_email || 'N/A';
    document.getElementById('labelerDunsNumber').textContent = asset.labeler_duns_number || 'N/A';
    
    // Version Information
    document.getElementById('publicVersionNumber').textContent = asset.public_version_number || 'N/A';
    document.getElementById('publicVersionDate').textContent = formatDate(asset.public_version_date);
    document.getElementById('publicVersionStatus').textContent = asset.public_version_status || 'N/A';
    document.getElementById('publicVersionStatus').className = `status-badge ${asset.public_version_status || ''}`;
    document.getElementById('publishDate').textContent = formatDate(asset.publish_date);
    document.getElementById('deviceCountInBasePackage').textContent = asset.device_count_in_base_package || 'N/A';
}

function populateSecurityData(asset) {
    // Use FDA classification if available, otherwise fall back to asset regulatory classification
    const regulatoryClassification = asset.fda_class_name || asset.fda_class || asset.regulatory_classification || '-';
    document.getElementById('regulatoryClassification').textContent = regulatoryClassification;
    
    document.getElementById('phiStatus').textContent = asset.phi_status === 'true' ? 'True' : 'False';
    document.getElementById('phiStatus').className = `boolean-badge ${asset.phi_status === 'true' ? 'True' : 'False'}`;
    document.getElementById('dataEncryptionTransit').textContent = asset.data_encryption_transit || '-';
    document.getElementById('dataEncryptionRest').textContent = asset.data_encryption_rest || '-';
    document.getElementById('authenticationMethod').textContent = asset.authentication_method || '-';
    document.getElementById('patchLevelLastUpdate').textContent = formatDate(asset.patch_level_last_update);
    document.getElementById('lastAuditDate').textContent = formatDate(asset.last_audit_date);
}

function populateVulnerabilities(vulnerabilities) {
    const container = document.getElementById('vulnerabilitiesList');
    const count = document.getElementById('vulnCount');
    
    count.textContent = vulnerabilities.length;
    
    if (vulnerabilities.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-bug"></i><p>No vulnerabilities found</p></div>';
        return;
    }
    
    // Separate KEVs and regular vulnerabilities
    const kevs = vulnerabilities.filter(v => v.is_kev);
    const regular = vulnerabilities.filter(v => !v.is_kev);
    
    let html = '';
    
    // Show KEVs first if any exist
    if (kevs.length > 0) {
        html += `
            <div class="vuln-section">
                <h5 class="section-title kev-title">
                    <i class="fas fa-exclamation-triangle"></i> 
                    Known Exploited Vulnerabilities (KEV) 
                    <span class="count-badge">${kevs.length}</span>
                </h5>
                <div class="vulnerabilities-grid">
                    ${kevs.map(vuln => renderVulnerability(vuln, true)).join('')}
                </div>
            </div>
        `;
    }
    
    // Show regular vulnerabilities
    if (regular.length > 0) {
        html += `
            <div class="vuln-section">
                <h5 class="section-title">
                    <i class="fas fa-bug"></i> 
                    Other Vulnerabilities 
                    <span class="count-badge">${regular.length}</span>
                </h5>
                <div class="vulnerabilities-grid">
                    ${regular.map(vuln => renderVulnerability(vuln, false)).join('')}
                </div>
            </div>
        `;
    }
    
    container.innerHTML = html;
}

function renderVulnerability(vuln, isKEV) {
    const daysOverdue = vuln.kev_due_date && isKEV ? calculateDaysOverdue(vuln.kev_due_date) : null;
    const isOverdue = daysOverdue !== null && daysOverdue > 0;
    const vulnId = `vuln-${vuln.cve_id.replace(/[^a-zA-Z0-9]/g, '-')}`;
    
    // Truncate description for compact view
    const shortDescription = vuln.description ? 
        (vuln.description.length > 120 ? vuln.description.substring(0, 120) + '...' : vuln.description) : 
        'No description available';
    
    return `
        <div class="vulnerability-item-compact ${isKEV ? 'kev-item' : ''} ${isOverdue ? 'overdue' : ''}" id="${vulnId}">
            <div class="vuln-compact-header">
                <div class="vuln-compact-left">
                    <div class="vuln-compact-title">
                        <span class="vulnerability-cve">${vuln.cve_id}</span>
                        ${isKEV ? '<span class="kev-badge"><i class="fas fa-shield-alt"></i> KEV</span>' : ''}
                        ${vuln.kev_ransomware === 'Known' ? '<span class="ransomware-badge" title="Known Ransomware"><i class="fas fa-lock"></i></span>' : ''}
                        ${isOverdue ? `<span class="overdue-badge" title="${daysOverdue} days overdue"><i class="fas fa-clock"></i> ${daysOverdue}d</span>` : ''}
                    </div>
                    <div class="vuln-compact-info">
                        <span class="vuln-info-item">
                            <i class="fas fa-chart-line"></i> ${(() => {
                                // Determine which CVSS score to display (v4 > v3 > v2)
                                if (vuln.cvss_v4_score && parseFloat(vuln.cvss_v4_score) > 0) {
                                    return `${vuln.cvss_v4_score} (v4.0)`;
                                } else if (vuln.cvss_v3_score && parseFloat(vuln.cvss_v3_score) > 0) {
                                    return `${vuln.cvss_v3_score} (v3.x)`;
                                } else if (vuln.cvss_v2_score && parseFloat(vuln.cvss_v2_score) > 0) {
                                    return `${vuln.cvss_v2_score} (v2.0)`;
                                } else {
                                    return 'N/A';
                                }
                            })()}
                        </span>
                        ${vuln.component_name ? `
                            <span class="vuln-info-item">
                                <i class="fas fa-cube"></i> ${vuln.component_name} ${vuln.component_version || ''}
                            </span>
                        ` : ''}
                        <span class="vuln-info-item status-badge-inline ${vuln.remediation_status.replace(/\s+/g, '-')}">
                            <i class="fas fa-${getStatusIcon(vuln.remediation_status)}"></i> 
                            ${vuln.remediation_status}
                        </span>
                    </div>
                </div>
                <div class="vuln-compact-right">
                    <div class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</div>
                    <button class="btn-view-vuln" onclick="toggleVulnDetails('${vulnId}')" title="View Details">
                        <i class="fas fa-eye"></i> View
                    </button>
                </div>
            </div>
            
            <!-- Expanded Details (Hidden by default) -->
            <div class="vuln-details-expanded" id="${vulnId}-details" style="display: none;">
                ${isKEV && vuln.kev_name ? `
                    <div class="vuln-detail-row">
                        <strong>Vulnerability Name:</strong>
                        <span>${vuln.kev_name}</span>
                    </div>
                ` : ''}
                
                <div class="vuln-detail-row">
                    <strong>Description:</strong>
                    <span>${vuln.description || 'No description available'}</span>
                </div>
                
                ${vuln.component_name ? `
                    <div class="vuln-detail-row highlight-component">
                        <strong><i class="fas fa-cube"></i> Affected Component:</strong>
                        <span>${vuln.component_name} ${vuln.component_version || ''}</span>
                    </div>
                ` : ''}
                
                ${isKEV && vuln.kev_required_action ? `
                    <div class="vuln-detail-row kev-required-action">
                        <strong><i class="fas fa-tasks"></i> Required Action:</strong>
                        <span>${vuln.kev_required_action}</span>
                    </div>
                ` : ''}
                
                <div class="vuln-details-meta">
                    <div class="meta-item">
                        <strong>CVSS Score:</strong>
                        <span>${(() => {
                            // Determine which CVSS score to display (v4 > v3 > v2)
                            if (vuln.cvss_v4_score && parseFloat(vuln.cvss_v4_score) > 0) {
                                return `${vuln.cvss_v4_score} (v4.0)`;
                            } else if (vuln.cvss_v3_score && parseFloat(vuln.cvss_v3_score) > 0) {
                                return `${vuln.cvss_v3_score} (v3.x)`;
                            } else if (vuln.cvss_v2_score && parseFloat(vuln.cvss_v2_score) > 0) {
                                return `${vuln.cvss_v2_score} (v2.0)`;
                            } else {
                                return 'N/A';
                            }
                        })()}</span>
                    </div>
                    <div class="meta-item">
                        <strong>Published:</strong>
                        <span>${formatDate(vuln.published_date)}</span>
                    </div>
                    ${isKEV && vuln.kev_due_date ? `
                        <div class="meta-item ${isOverdue ? 'text-danger' : ''}">
                            <strong>KEV Due Date:</strong>
                            <span>${formatDate(vuln.kev_due_date)}</span>
                        </div>
                    ` : ''}
                    <div class="meta-item">
                        <strong>Status:</strong>
                        <span class="status-badge-detail ${vuln.remediation_status.replace(/\s+/g, '-')}">
                            <i class="fas fa-${getStatusIcon(vuln.remediation_status)}"></i> 
                            ${vuln.remediation_status}
                        </span>
                    </div>
                    ${vuln.assigned_to_username ? `
                        <div class="meta-item">
                            <strong>Assigned To:</strong>
                            <span><i class="fas fa-user"></i> ${vuln.assigned_to_username}</span>
                        </div>
                    ` : ''}
                </div>
            </div>
        </div>
    `;
}

// Toggle vulnerability details
function toggleVulnDetails(vulnId) {
    const detailsDiv = document.getElementById(vulnId + '-details');
    const button = document.querySelector(`#${vulnId} .btn-view-vuln`);
    
    if (detailsDiv.style.display === 'none') {
        detailsDiv.style.display = 'block';
        button.innerHTML = '<i class="fas fa-eye-slash"></i> Hide';
        button.classList.add('active');
    } else {
        detailsDiv.style.display = 'none';
        button.innerHTML = '<i class="fas fa-eye"></i> View';
        button.classList.remove('active');
    }
}

function calculateDaysOverdue(dueDate) {
    if (!dueDate) return null;
    const due = new Date(dueDate);
    const today = new Date();
    const diffTime = today - due;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
}

function getStatusIcon(status) {
    const icons = {
        'Open': 'exclamation-circle',
        'In Progress': 'sync',
        'Remediated': 'check-circle',
        'Risk Accepted': 'shield-alt',
        'False Positive': 'times-circle'
    };
    return icons[status] || 'question-circle';
}

function populateRecalls(recalls) {
    const container = document.getElementById('recallsList');
    const count = document.getElementById('recallCount');
    
    count.textContent = recalls.length;
    
    if (recalls.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><p>No recalls found</p></div>';
        return;
    }
    
    container.innerHTML = recalls.map(recall => `
        <div class="recall-item">
            <div class="recall-header">
                <div class="recall-title">${recall.product_description || 'Unknown Product'}</div>
                <div class="recall-number">${recall.fda_recall_number}</div>
            </div>
            <div class="recall-details">
                <p><strong>Reason:</strong> ${recall.reason_for_recall || 'No reason provided'}</p>
                <p><strong>Classification:</strong> ${recall.recall_classification || 'Unknown'}</p>
                <p><strong>Date:</strong> ${formatDate(recall.recall_date)}</p>
                <p><strong>Status:</strong> ${recall.device_recall_status || 'Unknown'}</p>
            </div>
        </div>
    `).join('');
}

function populateTimeline(auditLogs) {
    const container = document.getElementById('timelineList');
    
    if (auditLogs.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-history"></i><p>No activity found</p></div>';
        return;
    }
    
    container.innerHTML = auditLogs.map(log => `
        <div class="timeline-item">
            <div class="timeline-icon">
                <i class="fas fa-${getActionIcon(log.action)}"></i>
            </div>
            <div class="timeline-content">
                <div class="timeline-title">${log.action}</div>
                <div class="timeline-description">${log.new_values || 'No details available'}</div>
                <div class="timeline-meta">
                    <span><i class="fas fa-user"></i> ${log.username || 'System'}</span>
                    <span><i class="fas fa-clock"></i> ${formatDateTime(log.created_at)}</span>
                    <span><i class="fas fa-globe"></i> ${log.ip_address || 'Unknown'}</span>
                </div>
            </div>
        </div>
    `).join('');
}

function getActionIcon(action) {
    const actionIcons = {
        'CREATE': 'plus',
        'UPDATE': 'edit',
        'DELETE': 'trash',
        'LOGIN': 'sign-in-alt',
        'LOGOUT': 'sign-out-alt',
        'VIEW': 'eye',
        'MAP': 'link'
    };
    return actionIcons[action] || 'info';
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString();
}

function formatDateTime(dateStr) {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleString();
}

// Tab functionality
document.addEventListener('DOMContentLoaded', function() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabPanels = document.querySelectorAll('.tab-panel');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');
            
            // Remove active class from all buttons and panels
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanels.forEach(panel => panel.classList.remove('active'));
            
            // Add active class to clicked button and corresponding panel
            button.classList.add('active');
            document.getElementById(targetTab).classList.add('active');
        });
    });
    
    // Sub-tab functionality
    const subTabButtons = document.querySelectorAll('.sub-tab-button');
    const subTabPanels = document.querySelectorAll('.sub-tab-panel');
    
    subTabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetSubTab = button.getAttribute('data-subtab');
            
            // Remove active class from all sub-tab buttons and panels
            subTabButtons.forEach(btn => btn.classList.remove('active'));
            subTabPanels.forEach(panel => panel.classList.remove('active'));
            
            // Add active class to clicked button and corresponding panel
            button.classList.add('active');
            document.getElementById(targetSubTab).classList.add('active');
            
            // If 510k tab is clicked, load 510k data
            if (targetSubTab === '510k-info') {
                load510kData();
            }
        });
    });
    
    // Modal close functionality
    document.getElementById('closeAssetModal').addEventListener('click', closeAssetModal);
    document.querySelector('#assetModal .modal-close').addEventListener('click', closeAssetModal);
    
    // Edit Asset button functionality
    document.getElementById('editAsset').addEventListener('click', editAsset);
    
    // Close modal when clicking outside
    document.getElementById('assetModal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeAssetModal();
        }
    });
    
    // Upload SBOM button functionality
    document.getElementById('uploadSbomBtn').addEventListener('click', function() {
        if (window.currentAssetData && window.currentAssetData.asset) {
            const assetId = window.currentAssetData.asset.asset_id;
            // Use dynamic base URL detection to prevent CORS issues
            const protocol = window.location.protocol;
            const host = window.location.host;
            const baseUrl = `${protocol}//${host}`;
            const url = `${baseUrl}/pages/vulnerabilities/upload-sbom.php?device_id=${assetId}`;
            window.open(url, '_blank', 'noopener');
        }
    });
    
    // Evaluate SBOM button functionality
    document.getElementById('evaluateSbomBtn').addEventListener('click', function() {
        if (window.currentAssetData && window.currentAssetData.asset) {
            const assetId = window.currentAssetData.asset.asset_id;
            evaluateSbomAgainstNvd(assetId);
        }
    });
});

// Load 510k data for the current device
function load510kData() {
    
    const loadingElement = document.getElementById('510kLoading');
    const contentElement = document.getElementById('510kContent');
    const errorElement = document.getElementById('510kError');
    
    // Show loading state
    loadingElement.style.display = 'block';
    contentElement.style.display = 'none';
    errorElement.style.display = 'none';
    
    // Get current asset data
    const currentAsset = window.currentAssetData;
    
    if (!currentAsset || !currentAsset.asset) {
        show510kError();
        return;
    }
    
    const asset = currentAsset.asset;
    
    // Check if asset is mapped to a medical device
    if (asset.mapping_status === 'Mapped') {
        
        // If we have 510k data stored in the medical_devices table, use it
        if (asset.k_number) {
            
            // Use the actual 510k data from the mapped medical device
            const actual510kData = {
                k_number: asset.k_number,
                decision_code: asset.decision_code,
                decision_date: asset.decision_date,
                decision_description: asset.decision_description,
                clearance_type: asset.clearance_type,
                date_received: asset.date_received,
                statement_or_summary: asset.statement_or_summary,
                applicant: asset.applicant,
                contact: asset.contact,
                address_1: asset.address_1,
                address_2: asset.address_2,
                city: asset.city,
                state: asset.state,
                zip_code: asset.zip_code,
                postal_code: asset.postal_code,
                country_code: asset.country_code,
                advisory_committee: asset.advisory_committee,
                advisory_committee_description: asset.advisory_committee_description,
                review_advisory_committee: asset.review_advisory_committee,
                expedited_review_flag: asset.expedited_review_flag,
                third_party_flag: asset.third_party_flag,
                device_class: asset.device_class,
                medical_specialty_description: asset.medical_specialty_description,
                registration_numbers: asset.registration_numbers,
                fei_numbers: asset.fei_numbers,
                device_name: asset.device_name,
                product_code: asset.product_code,
                regulation_number: asset.regulation_number
            };
            
            populate510kData(actual510kData);
            return;
        } else {
            
            // For mapped devices without stored 510k data, show a specific message
            // instead of doing a fuzzy search that would show multiple options
            show510kMappedButNoData();
            return;
        }
    }
    
    // If not mapped, check if we can do a fuzzy search
    if (!asset.device_identifier && !asset.product_code) {
        show510kError();
        return;
    }
    
    // Try multiple search terms in order of preference for fuzzy search
    const searchTerms = [
        asset.brand_name,           // Most specific: "ARTIS pheno"
        asset.product_code,         // Product code: "OWB"
        asset.device_identifier     // Device ID: UUID
    ].filter(term => term && term.trim() !== '');
    
    
    if (searchTerms.length === 0) {
        show510kError();
        return;
    }
    
    // Try each search term until we find results
    search510kWithTerms(searchTerms, 0);
}

// Function to search 510k with multiple terms
function search510kWithTerms(searchTerms, index) {
    if (index >= searchTerms.length) {
        show510kError();
        return;
    }
    
    const searchTerm = searchTerms[index];
    // Use dynamic base URL detection to prevent CORS issues
    const protocol = window.location.protocol;
    const host = window.location.host;
    const baseUrl = `${protocol}//${host}`;
    const url = `${baseUrl}/pages/assets/asset_modal.php?ajax=get_510k&device_id=${encodeURIComponent(searchTerm)}`;
    
    fetch(url)
        .then(response => response.json())
        .then(data => {
            if (data.success && data.data) {
                // Found results - now we need to handle multiple records
                handle510kResults(data.data, searchTerm);
            } else {
                // No results with this term, try next one
                search510kWithTerms(searchTerms, index + 1);
            }
        })
        .catch(error => {
            console.error(`Error searching 510k with term "${searchTerm}":`, error);
            // Try next term on error
            search510kWithTerms(searchTerms, index + 1);
        });
}

// Function to handle multiple 510k results
function handle510kResults(results, searchTerm) {
    
    if (results.length === 1) {
        // Single result - use it directly
        populate510kData(results[0]);
    } else {
        // Multiple results - always show selection interface
        // This allows users to choose the correct version/variant
        show510kSelection(results);
    }
}

// Function to find the best 510k match
function findBest510kMatch(results) {
    const currentAsset = window.currentAssetData.asset;
    const brandName = (currentAsset.brand_name || '').toLowerCase();
    const manufacturer = (currentAsset.manufacturer_name || '').toLowerCase();
    
    // Score each result
    const scoredResults = results.map(result => {
        let score = 0;
        const deviceName = (result.device_name || '').toLowerCase();
        const applicant = (result.applicant || '').toLowerCase();
        
        // Exact brand name match (highest priority)
        if (brandName && deviceName.includes(brandName)) {
            score += 100;
        }
        
        // Manufacturer match
        if (manufacturer && applicant.includes(manufacturer)) {
            score += 50;
        }
        
        // Siemens match (if manufacturer contains siemens)
        if (applicant.includes('siemens')) {
            score += 30;
        }
        
        // Recent date bonus
        if (result.decision_date) {
            const year = parseInt(result.decision_date.split('-')[0]);
            if (year >= 2020) score += 10;
            if (year >= 2023) score += 10;
        }
        
        return { ...result, relevanceScore: score };
    });
    
    // Sort by score and return the best match
    scoredResults.sort((a, b) => b.relevanceScore - a.relevanceScore);
    
    // Return the best match if it has a reasonable score
    const bestMatch = scoredResults[0];
    return bestMatch.relevanceScore > 0 ? bestMatch : null;
}

// Function to show 510k selection interface
function show510kSelection(results) {
    const loadingElement = document.getElementById('510kLoading');
    const contentElement = document.getElementById('510kContent');
    const errorElement = document.getElementById('510kError');
    
    // Hide loading, show selection interface
    loadingElement.style.display = 'none';
    errorElement.style.display = 'none';
    
    // Sort results by relevance (but still require user selection)
    const sortedResults = sort510kResultsByRelevance(results);
    
    // Create selection interface
    let selectionHTML = '<div class="510k-selection">';
    selectionHTML += '<h5>Multiple 510k Records Found</h5>';
    selectionHTML += '<p>Please select the most relevant 510k record for your specific device:</p>';
    selectionHTML += '<div class="510k-options">';
    
    sortedResults.forEach((result, index) => {
        const isRecent = result.decision_date && parseInt(result.decision_date.split('-')[0]) >= 2020;
        const isSiemens = result.applicant && result.applicant.toLowerCase().includes('siemens');
        const isExactMatch = result.relevanceScore >= 100;
        
        selectionHTML += `
            <div class="510k-option ${isExactMatch ? 'exact-match' : ''}" onclick="select510kRecord(${index})">
                <div class="option-header">
                    <strong>${result.k_number}</strong>
                    <span class="option-date">${result.decision_date || 'Unknown Date'}</span>
                </div>
                <div class="option-details">
                    <div class="option-device">${result.device_name || 'Unknown Device'}</div>
                    <div class="option-applicant">${result.applicant || 'Unknown Applicant'}</div>
                </div>
                <div class="option-badges">
                    ${isExactMatch ? '<span class="badge exact">Exact Match</span>' : ''}
                    ${isRecent ? '<span class="badge recent">Recent</span>' : ''}
                    ${isSiemens ? '<span class="badge siemens">Siemens</span>' : ''}
                </div>
            </div>
        `;
    });
    
    selectionHTML += '</div></div>';
    
    contentElement.innerHTML = selectionHTML;
    contentElement.style.display = 'block';
    
    // Store sorted results for selection
    window.current510kResults = sortedResults;
}

// Function to sort 510k results by relevance
function sort510kResultsByRelevance(results) {
    const currentAsset = window.currentAssetData.asset;
    const brandName = (currentAsset.brand_name || '').toLowerCase();
    const manufacturer = (currentAsset.manufacturer_name || '').toLowerCase();
    
    // Score each result
    const scoredResults = results.map(result => {
        let score = 0;
        const deviceName = (result.device_name || '').toLowerCase();
        const applicant = (result.applicant || '').toLowerCase();
        
        // Exact brand name match (highest priority)
        if (brandName && deviceName.includes(brandName)) {
            score += 100;
        }
        
        // Manufacturer match
        if (manufacturer && applicant.includes(manufacturer)) {
            score += 50;
        }
        
        // Siemens match (if manufacturer contains siemens)
        if (applicant.includes('siemens')) {
            score += 30;
        }
        
        // Recent date bonus
        if (result.decision_date) {
            const year = parseInt(result.decision_date.split('-')[0]);
            if (year >= 2020) score += 10;
            if (year >= 2023) score += 10;
        }
        
        return { ...result, relevanceScore: score };
    });
    
    // Sort by score (highest first)
    scoredResults.sort((a, b) => b.relevanceScore - a.relevanceScore);
    
    return scoredResults;
}

// Function to select a 510k record
function select510kRecord(index) {
    const results = window.current510kResults;
    if (results && results[index]) {
        populate510kData(results[index]);
    }
}

function populate510kData(data) {
    const loadingElement = document.getElementById('510kLoading');
    const contentElement = document.getElementById('510kContent');
    const errorElement = document.getElementById('510kError');
    
    // Hide loading and error, show content
    loadingElement.style.display = 'none';
    errorElement.style.display = 'none';
    contentElement.style.display = 'grid';
    
    // Populate 510k fields
    document.getElementById('510kNumber').textContent = data.k_number || 'N/A';
    document.getElementById('510kStatus').textContent = data.decision_code || 'N/A';
    document.getElementById('510kDecisionDate').textContent = data.decision_date || 'N/A';
    document.getElementById('510kApplicant').textContent = data.applicant || 'N/A';
    document.getElementById('510kDeviceName').textContent = data.device_name || 'N/A';
    document.getElementById('510kProductCode').textContent = data.product_code || 'N/A';
    document.getElementById('510kRegulationNumber').textContent = data.regulation_number || 'N/A';
    document.getElementById('510kStatement').textContent = data.statement_or_summary || 'N/A';
}

function show510kError() {
    const loadingElement = document.getElementById('510kLoading');
    const contentElement = document.getElementById('510kContent');
    const errorElement = document.getElementById('510kError');
    
    loadingElement.style.display = 'none';
    contentElement.style.display = 'none';
    errorElement.style.display = 'block';
}

function show510kMappedButNoData() {
    const loadingElement = document.getElementById('510kLoading');
    const contentElement = document.getElementById('510kContent');
    const errorElement = document.getElementById('510kError');
    
    // Hide loading and content
    loadingElement.style.display = 'none';
    contentElement.style.display = 'none';
    
    // Show custom message for mapped devices without 510k data
    errorElement.innerHTML = `
        <i class="fas fa-info-circle"></i> 
        This device is mapped to a medical device but no specific 510k information is available. 
        The device was mapped using general FDA device information rather than a specific 510k record.
    `;
    errorElement.style.display = 'block';
}

function populateSbomData(sboms, components) {
    const sbomCount = document.getElementById('sbomCount');
    const sbomFilesList = document.getElementById('sbomFilesList');
    const componentsList = document.getElementById('componentsList');
    
    // Update SBOM count
    sbomCount.textContent = sboms.length;
    
    // Populate SBOM files
    if (sboms.length === 0) {
        sbomFilesList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-file"></i>
                <h4>No SBOM Files</h4>
                <p>No Software Bill of Materials files have been uploaded for this device.</p>
            </div>
        `;
        componentsList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-cogs"></i>
                <h4>No Components</h4>
                <p>Upload an SBOM file to see software components.</p>
            </div>
        `;
        return;
    }
    
    // Display SBOM files
    sbomFilesList.innerHTML = sboms.map(sbom => `
        <div class="sbom-file-item">
            <div class="sbom-file-header">
                <div class="sbom-file-name">${sbom.file_name}</div>
                <span class="sbom-file-status ${sbom.parsing_status.toLowerCase()}">${sbom.parsing_status}</span>
            </div>
            <div class="sbom-file-meta">
                <div><strong>Format:</strong> ${sbom.format}</div>
                <div><strong>Size:</strong> ${formatFileSize(sbom.file_size)}</div>
                <div><strong>Uploaded:</strong> ${formatDate(sbom.uploaded_at)}</div>
                <div><strong>By:</strong> ${sbom.uploaded_by_username || 'Unknown'}</div>
                <div><strong>Components:</strong> ${components[sbom.sbom_id] ? components[sbom.sbom_id].length : 0}</div>
            </div>
        </div>
    `).join('');
    
    // Collect all components from all SBOMs
    let allComponents = [];
    Object.values(components).forEach(sbomComponents => {
        allComponents = allComponents.concat(sbomComponents);
    });
    
    // Populate components
    if (allComponents.length === 0) {
        componentsList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-cogs"></i>
                <h4>No Components</h4>
                <p>No software components found in uploaded SBOM files.</p>
            </div>
        `;
        return;
    }
    
    // Populate vendor and license filters
    populateFilters(allComponents);
    
    // Display components
    displayComponents(allComponents);
    
    // Add search and filter functionality
    setupComponentFilters(allComponents);
}

function populateFilters(components) {
    const vendorFilter = document.getElementById('vendorFilter');
    const licenseFilter = document.getElementById('licenseFilter');
    
    // Get unique vendors and licenses
    const vendors = [...new Set(components.map(c => c.vendor).filter(v => v))].sort();
    const licenses = [...new Set(components.map(c => c.license).filter(l => l))].sort();
    
    // Populate vendor filter
    vendorFilter.innerHTML = '<option value="">All Vendors</option>' + 
        vendors.map(vendor => `<option value="${vendor}">${vendor}</option>`).join('');
    
    // Populate license filter
    licenseFilter.innerHTML = '<option value="">All Licenses</option>' + 
        licenses.map(license => `<option value="${license}">${license}</option>`).join('');
}

function displayComponents(components) {
    const componentsList = document.getElementById('componentsList');
    
    componentsList.innerHTML = components.map(component => `
        <div class="component-item" data-vendor="${component.vendor || ''}" data-license="${component.license || ''}" data-name="${component.name.toLowerCase()}">
            <div class="component-header">
                <div class="component-name">${component.name}</div>
                <div class="component-version">${component.version || 'Unknown'}</div>
            </div>
            <div class="component-details">
                <div class="component-detail">
                    <div class="component-detail-label">Vendor</div>
                    <div class="component-detail-value">${component.vendor || 'Unknown'}</div>
                </div>
                <div class="component-detail">
                    <div class="component-detail-label">License</div>
                    <div class="component-detail-value">${component.license || 'Unknown'}</div>
                </div>
                <div class="component-detail">
                    <div class="component-detail-label">PURL</div>
                    <div class="component-detail-value">${component.purl || 'N/A'}</div>
                </div>
                <div class="component-detail">
                    <div class="component-detail-label">CPE</div>
                    <div class="component-detail-value">${component.cpe || 'N/A'}</div>
                </div>
            </div>
        </div>
    `).join('');
}

function setupComponentFilters(allComponents) {
    const searchInput = document.getElementById('componentSearch');
    const vendorFilter = document.getElementById('vendorFilter');
    const licenseFilter = document.getElementById('licenseFilter');
    
    function filterComponents() {
        const searchTerm = searchInput.value.toLowerCase();
        const selectedVendor = vendorFilter.value;
        const selectedLicense = licenseFilter.value;
        
        const componentItems = document.querySelectorAll('.component-item');
        
        componentItems.forEach(item => {
            const name = item.dataset.name;
            const vendor = item.dataset.vendor;
            const license = item.dataset.license;
            
            const matchesSearch = name.includes(searchTerm);
            const matchesVendor = !selectedVendor || vendor === selectedVendor;
            const matchesLicense = !selectedLicense || license === selectedLicense;
            
            if (matchesSearch && matchesVendor && matchesLicense) {
                item.style.display = 'block';
            } else {
                item.style.display = 'none';
            }
        });
    }
    
    searchInput.addEventListener('input', filterComponents);
    vendorFilter.addEventListener('change', filterComponents);
    licenseFilter.addEventListener('change', filterComponents);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function evaluateSbomAgainstNvd(assetId) {
    // Show loading state
    const evaluateBtn = document.getElementById('evaluateSbomBtn');
    const originalText = evaluateBtn.innerHTML;
    evaluateBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Evaluating...';
    evaluateBtn.disabled = true;
    
    // Try API endpoint first, then fallback to direct Python execution
    fetch('/api/v1/vulnerabilities/index.php?path=evaluate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            asset_id: assetId,
            evaluation_type: 'sbom'
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            showNotification(`SBOM evaluation initiated successfully. Evaluation ID: ${data.data.evaluation_id}`, 'success');
            // Optionally refresh the modal data to show updated vulnerability information
            setTimeout(() => {
                if (window.currentAssetData && window.currentAssetData.asset) {
                    loadAssetData(window.currentAssetData.asset.asset_id);
                }
            }, 2000);
        } else {
            showNotification(data.error?.message || 'Failed to initiate SBOM evaluation', 'error');
        }
    })
    .catch(error => {
        console.error('API call failed, trying direct Python execution:', error);
        
        // Fallback: Try the asset modal endpoint
        const protocol = window.location.protocol;
        const host = window.location.host;
        const baseUrl = `${protocol}//${host}`;
        const fallbackUrl = `${baseUrl}/pages/assets/asset_modal.php?ajax=evaluate_sbom&asset_id=${encodeURIComponent(assetId)}&_t=${Date.now()}`;
        
        return fetch(fallbackUrl, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                showNotification(`SBOM evaluation completed successfully. Found ${data.vulnerabilities_found} vulnerabilities.`, 'success');
                // Refresh the modal data to show updated vulnerability information
                setTimeout(() => {
                    if (window.currentAssetData && window.currentAssetData.asset) {
                        loadAssetData(window.currentAssetData.asset.asset_id);
                    }
                }, 1000);
            } else {
                showNotification(data.error || 'Failed to evaluate SBOM', 'error');
            }
        });
    })
    .catch(error => {
        console.error('Error evaluating SBOM:', error);
        if (error.message.includes('JSON.parse')) {
            showNotification('Server returned invalid response. Please check if the evaluation service is accessible.', 'error');
        } else if (error.message.includes('HTTP error')) {
            showNotification(`Server error: ${error.message}`, 'error');
        } else {
            showNotification('Error evaluating SBOM against NVD: ' + error.message, 'error');
        }
    })
    .finally(() => {
        // Restore button state
        evaluateBtn.innerHTML = originalText;
        evaluateBtn.disabled = false;
    });
}
</script>
