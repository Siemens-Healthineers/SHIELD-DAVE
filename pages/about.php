<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/

if (!defined('DAVE_ACCESS')) {
    define('DAVE_ACCESS', true);
}
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/auth.php';

// Require authentication
$auth->requireAuth();

// Get current user
$user = $auth->getCurrentUser();
if (!$user) {
    header('Location: /pages/login.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>About - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/dashboard-common.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="dashboard-container">
        <?php include __DIR__ . '/../assets/templates/dashboard-header.php'; ?>

        <!-- Main Content -->
        <main class="dashboard-main">
            <div class="page-header">
                <div class="page-title">
                    <h1><i class="fas fa-info-circle"></i> About</h1>
                    <p>System information and legal disclaimers</p>
                </div>
                <div class="page-actions">
                    <a href="/pages/dashboard.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i>
                        Back to Dashboard
                    </a>
                </div>
            </div>

            <div class="about-container">
                <!-- System Information -->
                <div class="about-section">
                    <div class="section-header">
                        <h2><i class="fas fa-shield-alt"></i> System Information</h2>
                    </div>
                    <div class="info-grid">
                        <div class="info-item">
                            <label>System Name</label>
                            <span><?php echo _NAME; ?></span>
                        </div>
                        <div class="info-item">
                            <label>Version</label>
                            <span>1.0.0</span>
                        </div>
                        <div class="info-item">
                            <label>Description</label>
                            <span>Device Assessment and Vulnerability Exposure for Medical Device Management & Cybersecurity Platform</span>
                        </div>
                        <div class="info-item">
                            <label>Platform</label>
                            <span>Web-based Application</span>
                        </div>
                    </div>
                </div>

                <!-- Author Information -->
                <div class="about-section">
                    <div class="section-header">
                        <h2><i class="fas fa-user"></i> Author Information</h2>
                    </div>
                    <div class="author-info">
                        <div class="author-details">
                            <div class="info-item">
                                <label>Author</label>
                                <span>David Nathans</span>
                            </div>
                            <div class="info-item">
                                <label>Copyright</label>
                                <span>&copy; 2026 Siemens Healthineers - All rights reserved</span>
                            </div>
                            <div class="info-item">
                                <label>Created</label>
                                <span>2025-01-09</span>
                            </div>
                            <div class="info-item">
                                <label>Contact</label>
                                <span>zourick@gmail.com</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Legal Disclaimers -->
                <div class="about-section">
                    <div class="section-header">
                        <h2><i class="fas fa-gavel"></i> Legal Disclaimers</h2>
                    </div>
                    <div class="disclaimer-summary">
                        <p>This system incorporates various data sources, APIs, and methodologies. Comprehensive legal disclaimers and usage terms are available for review.</p>
                        <div class="disclaimer-actions">
                            <button class="btn btn-primary" onclick="showLegalDisclaimersModal()">
                                <i class="fas fa-file-contract"></i>
                                View Legal Disclaimers
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Technical Information -->
                <div class="about-section">
                    <div class="section-header">
                        <h2><i class="fas fa-cogs"></i> Technical Information</h2>
                    </div>
                    <div class="tech-info">
                        <div class="info-grid">
                            <div class="info-item">
                                <label>Database</label>
                                <span>PostgreSQL</span>
                            </div>
                            <div class="info-item">
                                <label>Backend</label>
                                <span>PHP 8.x</span>
                            </div>
                            <div class="info-item">
                                <label>Frontend</label>
                                <span>HTML5, CSS3, JavaScript</span>
                            </div>
                            <div class="info-item">
                                <label>Security</label>
                                <span>Role-based Access Control (RBAC)</span>
                            </div>
                        </div>
                        
                        <div class="tech-actions">
                            <button class="btn btn-primary" onclick="showOpenSourceModal()">
                                <i class="fas fa-code"></i>
                                View Open Source Declaration
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- Open Source Declaration Modal -->
    <div id="openSourceModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fas fa-code"></i> Open Source Declaration</h2>
                <button class="modal-close" onclick="closeOpenSourceModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="opensource-section">
                    <h3><i class="fas fa-info-circle"></i> Declaration Statement</h3>
                    <p>This Device Assessment and Vulnerability Exposure () incorporates various open source libraries, frameworks, and tools. This declaration provides complete transparency about all open source components used in this project, in compliance with open source licensing requirements and legal disclosure obligations.</p>
                </div>

                <div class="opensource-section">
                    <h3><i class="fas fa-list"></i> Open Source Libraries & Dependencies</h3>
                    <div class="library-list">
                        <div class="library-item">
                            <div class="library-header">
                                <h4>Font Awesome 6.0.0</h4>
                                <span class="license-badge">SIL OFL 1.1</span>
                            </div>
                            <div class="library-details">
                                <p><strong>Purpose:</strong> Icon library for user interface elements</p>
                                <p><strong>License:</strong> SIL Open Font License 1.1</p>
                                <p><strong>Source:</strong> https://fontawesome.com/</p>
                                <p><strong>Usage:</strong> Icons throughout the application interface</p>
                            </div>
                        </div>

                        <div class="library-item">
                            <div class="library-header">
                                <h4>Chart.js</h4>
                                <span class="license-badge">MIT</span>
                            </div>
                            <div class="library-details">
                                <p><strong>Purpose:</strong> JavaScript charting library for data visualization</p>
                                <p><strong>License:</strong> MIT License</p>
                                <p><strong>Source:</strong> https://www.chartjs.org/</p>
                                <p><strong>Usage:</strong> EPSS trends charts and analytics visualization</p>
                            </div>
                        </div>

                        <div class="library-item">
                            <div class="library-header">
                                <h4>PostgreSQL</h4>
                                <span class="license-badge">PostgreSQL License</span>
                            </div>
                            <div class="library-details">
                                <p><strong>Purpose:</strong> Relational database management system</p>
                                <p><strong>License:</strong> PostgreSQL License (similar to MIT)</p>
                                <p><strong>Source:</strong> https://www.postgresql.org/</p>
                                <p><strong>Usage:</strong> Primary database for all system data</p>
                            </div>
                        </div>

                        <div class="library-item">
                            <div class="library-header">
                                <h4>PHP 8.x</h4>
                                <span class="license-badge">PHP License</span>
                            </div>
                            <div class="library-details">
                                <p><strong>Purpose:</strong> Server-side scripting language</p>
                                <p><strong>License:</strong> PHP License v3.01</p>
                                <p><strong>Source:</strong> https://www.php.net/</p>
                                <p><strong>Usage:</strong> Backend application logic and API endpoints</p>
                            </div>
                        </div>

                        <div class="library-item">
                            <div class="library-header">
                                <h4>Apache HTTP Server</h4>
                                <span class="license-badge">Apache 2.0</span>
                            </div>
                            <div class="library-details">
                                <p><strong>Purpose:</strong> Web server software</p>
                                <p><strong>License:</strong> Apache License 2.0</p>
                                <p><strong>Source:</strong> https://httpd.apache.org/</p>
                                <p><strong>Usage:</strong> Web server hosting the application</p>
                            </div>
                        </div>

                        <div class="library-item">
                            <div class="library-header">
                                <h4>Ubuntu Linux</h4>
                                <span class="license-badge">Multiple</span>
                            </div>
                            <div class="library-details">
                                <p><strong>Purpose:</strong> Operating system platform</p>
                                <p><strong>License:</strong> Various open source licenses (GPL, LGPL, MIT, etc.)</p>
                                <p><strong>Source:</strong> https://ubuntu.com/</p>
                                <p><strong>Usage:</strong> Server operating system environment</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="opensource-section">
                    <h3><i class="fas fa-gavel"></i> Legal Disclaimers</h3>
                    <div class="disclaimer-content">
                        <div class="disclaimer-item">
                            <h4>Open Source Compliance</h4>
                            <p>This system complies with all applicable open source licenses. All open source components are used in accordance with their respective license terms and conditions.</p>
                        </div>
                        
                        <div class="disclaimer-item">
                            <h4>License Compatibility</h4>
                            <p>All open source licenses used in this project are compatible with the proprietary nature of this application. No copyleft licenses that would require source code disclosure are used.</p>
                        </div>
                        
                        <div class="disclaimer-item">
                            <h4>Attribution Requirements</h4>
                            <p>This declaration fulfills the attribution requirements of all incorporated open source libraries. Individual license texts are available upon request.</p>
                        </div>
                        
                        <div class="disclaimer-item">
                            <h4>No Warranty</h4>
                            <p>Open source components are provided "as is" without warranty. The developers of this system do not assume responsibility for the functionality or security of third-party open source libraries.</p>
                        </div>
                    </div>
                </div>

                <div class="opensource-section">
                    <h3><i class="fas fa-download"></i> Source Code Availability</h3>
                    <p>While this application incorporates open source components, the core application code is proprietary. However, we maintain transparency about all open source dependencies as disclosed in this declaration.</p>
                </div>

                <div class="opensource-section">
                    <h3><i class="fas fa-shield-alt"></i> Security Considerations</h3>
                    <p>All open source components are regularly updated to address security vulnerabilities. We monitor security advisories for all incorporated libraries and apply updates as necessary to maintain system security.</p>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeOpenSourceModal()">
                    <i class="fas fa-times"></i>
                    Close
                </button>
                <button class="btn btn-primary" onclick="printOpenSourceDeclaration()">
                    <i class="fas fa-print"></i>
                    Print Declaration
                </button>
            </div>
        </div>
    </div>

    <!-- Legal Disclaimers Modal -->
    <div id="legalDisclaimersModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fas fa-gavel"></i> Legal Disclaimers & Terms</h2>
                <button class="modal-close" onclick="closeLegalDisclaimersModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="legal-section">
                    <h3><i class="fas fa-info-circle"></i> General Disclaimer</h3>
                    <p>This Device Assessment and Vulnerability Exposure () is provided for informational and analytical purposes. Users are responsible for their own security decisions and should not rely solely on this system for critical security assessments.</p>
                </div>

                <div class="legal-section">
                    <h3><i class="fas fa-database"></i> Data Source Disclaimers</h3>
                    <div class="disclaimer-list">
                        <div class="disclaimer-item">
                            <div class="disclaimer-header">
                                <h4>NVD API Usage</h4>
                                <span class="disclaimer-badge">External API</span>
                            </div>
                            <div class="disclaimer-details">
                                <p>This product uses the NVD API but is not endorsed or certified by the NVD. NVD data is provided for informational purposes only and should be verified independently.</p>
                            </div>
                        </div>

                        <div class="disclaimer-item">
                            <div class="disclaimer-header">
                                <h4>Medical Device Information</h4>
                                <span class="disclaimer-badge">FDA Data</span>
                            </div>
                            <div class="disclaimer-details">
                                <p>Medical device information is sourced from publicly available FDA databases and medical device registries. While we strive for accuracy, users should verify critical information independently. This system is not affiliated with the FDA.</p>
                            </div>
                        </div>

                        <div class="disclaimer-item">
                            <div class="disclaimer-header">
                                <h4>Vulnerability Data</h4>
                                <span class="disclaimer-badge">Security Info</span>
                            </div>
                            <div class="disclaimer-details">
                                <p>Vulnerability information is provided for informational purposes only. Users are responsible for assessing and addressing security risks in their environments. This system does not guarantee the accuracy or completeness of vulnerability data.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="legal-section">
                    <h3><i class="fas fa-chart-line"></i> EPSS (Exploit Prediction Scoring System)</h3>
                    <div class="epss-disclaimer">
                        <div class="disclaimer-item">
                            <h4>EPSS License Disclaimer</h4>
                            <p>This product incorporates EPSS (Exploit Prediction Scoring System) data and methodology. EPSS is provided by the Forum of Incident Response and Security Teams (FIRST) and is subject to the following terms:</p>
                            <ul>
                                <li>EPSS scores are predictions and should not be considered as definitive indicators of exploit likelihood</li>
                                <li>EPSS data is provided "as is" without warranty of any kind</li>
                                <li>Users should not rely solely on EPSS scores for security decision-making</li>
                                <li>EPSS scores may change over time and should be regularly updated</li>
                                <li>This system is not endorsed by or affiliated with FIRST or the EPSS project</li>
                            </ul>
                            <p><strong>Usage Agreement:</strong> By using EPSS data in this system, you acknowledge that EPSS scores are probabilistic predictions and should be used as one factor among many in your security risk assessment process. The accuracy and reliability of EPSS scores cannot be guaranteed.</p>
                        </div>
                    </div>
                </div>

                <div class="legal-section">
                    <h3><i class="fas fa-shield-alt"></i> Compliance & Security</h3>
                    <div class="disclaimer-list">
                        <div class="disclaimer-item">
                            <div class="disclaimer-header">
                                <h4>Compliance Disclaimer</h4>
                                <span class="disclaimer-badge">Legal</span>
                            </div>
                            <div class="disclaimer-details">
                                <p>This system is designed to assist with cybersecurity and compliance management but does not guarantee compliance with any specific regulations or standards. Users are responsible for ensuring their own regulatory compliance.</p>
                            </div>
                        </div>

                        <div class="disclaimer-item">
                            <div class="disclaimer-header">
                                <h4>Security Disclaimer</h4>
                                <span class="disclaimer-badge">Security</span>
                            </div>
                            <div class="disclaimer-details">
                                <p>While this system implements security best practices, no system can guarantee complete security. Users should implement additional security measures as appropriate for their environment and risk tolerance.</p>
                            </div>
                        </div>

                        <div class="disclaimer-item">
                            <div class="disclaimer-header">
                                <h4>Data Accuracy</h4>
                                <span class="disclaimer-badge">Accuracy</span>
                            </div>
                            <div class="disclaimer-details">
                                <p>All data provided by this system is for informational purposes only. While we strive for accuracy, users should verify critical information through official sources before making security decisions.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="legal-section">
                    <h3><i class="fas fa-exclamation-triangle"></i> Limitation of Liability</h3>
                    <div class="liability-disclaimer">
                        <p><strong>No Warranty:</strong> This system is provided "as is" without warranty of any kind, either express or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose.</p>
                        <p><strong>Limitation of Liability:</strong> In no event shall the developers, authors, or contributors be liable for any direct, indirect, incidental, special, consequential, or punitive damages, including but not limited to loss of profits, data, or business interruption, arising out of or in connection with the use of this system.</p>
                        <p><strong>User Responsibility:</strong> Users are solely responsible for their use of this system and any decisions made based on the information provided. Users should consult with qualified security professionals for critical security decisions.</p>
                    </div>
                </div>

                <div class="legal-section">
                    <h3><i class="fas fa-balance-scale"></i> Terms of Use</h3>
                    <div class="terms-content">
                        <p>By using this system, you agree to the following terms:</p>
                        <ul>
                            <li>You will use this system in accordance with applicable laws and regulations</li>
                            <li>You will not use this system for any illegal or unauthorized purposes</li>
                            <li>You acknowledge that this system is provided for informational purposes only</li>
                            <li>You will not hold the developers liable for any damages arising from use of this system</li>
                            <li>You will verify critical information through official sources before making decisions</li>
                            <li>Any use or direvitives of this application must include original attribution to the developers and the original source code</li>
                        </ul>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeLegalDisclaimersModal()">
                    <i class="fas fa-times"></i>
                    Close
                </button>
                <button class="btn btn-primary" onclick="printLegalDisclaimers()">
                    <i class="fas fa-print"></i>
                    Print Disclaimers
                </button>
            </div>
        </div>
    </div>

    <style>
        .about-container {
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }

        .about-section {
            background: var(--bg-card);
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            padding: 1.5rem;
        }

        .section-header {
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-primary);
        }

        .section-header h2 {
            color: var(--text-primary);
            margin: 0;
            font-size: 1.25rem;
            font-weight: 600;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }

        .info-item {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .info-item label {
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .info-item span {
            color: var(--text-primary);
            font-size: 1rem;
        }

        .author-info {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
        }

        .author-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }

        .disclaimer-content {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .disclaimer-item {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
        }

        .disclaimer-item h3 {
            color: var(--text-primary);
            margin: 0 0 1rem 0;
            font-size: 1.125rem;
            font-weight: 600;
        }

        .disclaimer-item p {
            color: var(--text-secondary);
            margin: 0;
            line-height: 1.6;
        }

        .tech-info {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
        }

        .tech-actions {
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-primary);
            text-align: center;
        }

        .disclaimer-summary {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
        }

        .disclaimer-summary p {
            color: var(--text-secondary);
            margin-bottom: 1.5rem;
            line-height: 1.6;
        }

        .disclaimer-actions {
            text-align: center;
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
            background-color: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(4px);
        }

        .modal-content {
            background: var(--bg-card);
            margin: 2% auto;
            padding: 0;
            border: 1px solid var(--border-primary);
            border-radius: 0.75rem;
            width: 90%;
            max-width: 1000px;
            max-height: 90vh;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-primary);
            background: var(--bg-secondary);
        }

        .modal-header h2 {
            margin: 0;
            color: var(--text-primary);
            font-size: 1.5rem;
            font-weight: 600;
        }

        .modal-close {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0.5rem;
            border-radius: 0.375rem;
            transition: all 0.2s ease;
        }

        .modal-close:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
        }

        .modal-body {
            padding: 2rem;
            max-height: 60vh;
            overflow-y: auto;
        }

        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 1rem;
            padding: 1.5rem;
            border-top: 1px solid var(--border-primary);
            background: var(--bg-secondary);
        }

        /* Open Source Content Styles */
        .opensource-section {
            margin-bottom: 2rem;
        }

        .opensource-section h3 {
            color: var(--text-primary);
            margin: 0 0 1rem 0;
            font-size: 1.25rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .opensource-section p {
            color: var(--text-secondary);
            line-height: 1.6;
            margin-bottom: 1rem;
        }

        .library-list {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .library-item {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
            transition: all 0.2s ease;
        }

        .library-item:hover {
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.1);
        }

        .library-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .library-header h4 {
            margin: 0;
            color: var(--text-primary);
            font-size: 1.125rem;
            font-weight: 600;
        }

        .license-badge {
            background: var(--siemens-petrol, #009999);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .library-details p {
            margin: 0.5rem 0;
            color: var(--text-secondary);
        }

        .library-details strong {
            color: var(--text-primary);
        }

        /* Legal Disclaimers Modal Styles */
        .legal-section {
            margin-bottom: 2rem;
        }

        .legal-section h3 {
            color: var(--text-primary);
            margin: 0 0 1rem 0;
            font-size: 1.25rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .legal-section p {
            color: var(--text-secondary);
            line-height: 1.6;
            margin-bottom: 1rem;
        }

        .disclaimer-list {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .disclaimer-item {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
            transition: all 0.2s ease;
        }

        .disclaimer-item:hover {
            border-color: var(--siemens-petrol, #009999);
            box-shadow: 0 4px 12px rgba(0, 153, 153, 0.1);
        }

        .disclaimer-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .disclaimer-header h4 {
            margin: 0;
            color: var(--text-primary);
            font-size: 1.125rem;
            font-weight: 600;
        }

        .disclaimer-badge {
            background: var(--siemens-orange, #ff6b35);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .disclaimer-details p {
            margin: 0.5rem 0;
            color: var(--text-secondary);
        }

        .disclaimer-details strong {
            color: var(--text-primary);
        }

        .epss-disclaimer {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
        }

        .epss-disclaimer h4 {
            color: var(--text-primary);
            margin: 0 0 1rem 0;
            font-size: 1.125rem;
            font-weight: 600;
        }

        .epss-disclaimer ul {
            margin: 1rem 0;
            padding-left: 1.5rem;
            color: var(--text-secondary);
        }

        .epss-disclaimer li {
            margin-bottom: 0.5rem;
        }

        .liability-disclaimer {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
        }

        .liability-disclaimer p {
            margin-bottom: 1rem;
            color: var(--text-secondary);
        }

        .liability-disclaimer strong {
            color: var(--text-primary);
        }

        .terms-content {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 0.5rem;
            padding: 1.5rem;
        }

        .terms-content ul {
            margin: 1rem 0;
            padding-left: 1.5rem;
            color: var(--text-secondary);
        }

        .terms-content li {
            margin-bottom: 0.5rem;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .modal-content {
                width: 95%;
                margin: 5% auto;
            }
            
            .modal-body {
                padding: 1rem;
            }
            
            .library-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }
            
            .modal-footer {
                flex-direction: column;
            }
        }

        @media (max-width: 768px) {
            .info-grid {
                grid-template-columns: 1fr;
            }
            
            .author-details {
                grid-template-columns: 1fr;
            }
        }
    </style>

    <!-- Profile Dropdown Script -->
    <script src="/assets/js/dashboard-common.js"></script>
    <script>
        // Pass user data to the profile dropdown
        window.userData = {
            name: '<?php echo dave_htmlspecialchars($user['username']); ?>',
            role: '<?php echo dave_htmlspecialchars($user['role']); ?>',
            email: '<?php echo dave_htmlspecialchars($user['email'] ?? 'user@example.com'); ?>'
        };

        // Open Source Declaration Modal Functions
        function showOpenSourceModal() {
            const modal = document.getElementById('openSourceModal');
            modal.style.display = 'block';
            document.body.style.overflow = 'hidden'; // Prevent background scrolling
        }

        function closeOpenSourceModal() {
            const modal = document.getElementById('openSourceModal');
            modal.style.display = 'none';
            document.body.style.overflow = 'auto'; // Restore scrolling
        }

        function printOpenSourceDeclaration() {
            // Create a new window for printing
            const printWindow = window.open('', '_blank');
            const modalContent = document.querySelector('#openSourceModal .modal-content').innerHTML;
            
            printWindow.document.write(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Open Source Declaration - </title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
                        .modal-header { border-bottom: 2px solid #333; padding-bottom: 10px; margin-bottom: 20px; }
                        .modal-header h2 { color: #333; margin: 0; }
                        .opensource-section { margin-bottom: 30px; }
                        .opensource-section h3 { color: #333; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
                        .library-item { border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px; }
                        .library-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
                        .license-badge { background: #009999; color: white; padding: 4px 12px; border-radius: 15px; font-size: 12px; font-weight: bold; }
                        .library-details p { margin: 5px 0; }
                        .disclaimer-item { background: #f9f9f9; padding: 15px; margin-bottom: 15px; border-radius: 5px; }
                        .disclaimer-item h4 { color: #333; margin-top: 0; }
                        @media print { body { margin: 0; } }
                    </style>
                </head>
                <body>
                    ${modalContent}
                </body>
                </html>
            `);
            
            printWindow.document.close();
            printWindow.print();
        }

        // Close modal when clicking outside of it
        window.onclick = function(event) {
            const openSourceModal = document.getElementById('openSourceModal');
            const legalDisclaimersModal = document.getElementById('legalDisclaimersModal');
            
            if (event.target === openSourceModal) {
                closeOpenSourceModal();
            }
            if (event.target === legalDisclaimersModal) {
                closeLegalDisclaimersModal();
            }
        }

        // Close modal with Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeOpenSourceModal();
                closeLegalDisclaimersModal();
            }
        });

        // Legal Disclaimers Modal Functions
        function showLegalDisclaimersModal() {
            const modal = document.getElementById('legalDisclaimersModal');
            modal.style.display = 'block';
            document.body.style.overflow = 'hidden'; // Prevent background scrolling
        }

        function closeLegalDisclaimersModal() {
            const modal = document.getElementById('legalDisclaimersModal');
            modal.style.display = 'none';
            document.body.style.overflow = 'auto'; // Restore scrolling
        }

        function printLegalDisclaimers() {
            // Create a new window for printing
            const printWindow = window.open('', '_blank');
            const modalContent = document.querySelector('#legalDisclaimersModal .modal-content').innerHTML;
            
            printWindow.document.write(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Legal Disclaimers - </title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
                        .modal-header { border-bottom: 2px solid #333; padding-bottom: 10px; margin-bottom: 20px; }
                        .modal-header h2 { color: #333; margin: 0; }
                        .legal-section { margin-bottom: 30px; }
                        .legal-section h3 { color: #333; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
                        .disclaimer-item { border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px; }
                        .disclaimer-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
                        .disclaimer-badge { background: #ff6b35; color: white; padding: 4px 12px; border-radius: 15px; font-size: 12px; font-weight: bold; }
                        .disclaimer-details p { margin: 5px 0; }
                        .epss-disclaimer, .liability-disclaimer, .terms-content { background: #f9f9f9; padding: 15px; margin-bottom: 15px; border-radius: 5px; }
                        .epss-disclaimer h4, .liability-disclaimer strong { color: #333; margin-top: 0; }
                        .epss-disclaimer ul, .terms-content ul { margin: 10px 0; padding-left: 20px; }
                        .epss-disclaimer li, .terms-content li { margin-bottom: 5px; }
                        @media print { body { margin: 0; } }
                    </style>
                </head>
                <body>
                    ${modalContent}
                </body>
                </html>
            `);
            
            printWindow.document.close();
            printWindow.print();
        }
    </script>
</body>
</html>
