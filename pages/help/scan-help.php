<?php
/*
* SPDX-License-Identifier: AGPL-3.0-or-later
* SPDX-FileCopyrightText: Copyright 2026 Siemens Healthineers
*/
/**
 * Scan Help Guide for Device Assessment and Vulnerability Exposure ()
 * Comprehensive Nmap scanning guide for asset discovery and vulnerability assessment
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
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Help Guide - <?php echo _NAME; ?></title>
    <link rel="stylesheet" href="/assets/css/dashboard.css">
    <link rel="stylesheet" href="/assets/css/brand-variables.css">
    <link rel="stylesheet" href="/assets/css/brand-components.css">
    <link rel="stylesheet" href="/assets/css/help.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <?php include __DIR__ . '/../../assets/templates/dashboard-header.php'; ?>

    <main class="main-content">
        <div class="help-content-container">
            <div class="help-page-header">
                <div class="container">
                    <h1><i class="fas fa-search"></i> Scan Help Guide</h1>
                    <p>Comprehensive Nmap scanning guide for asset discovery and vulnerability assessment</p>
                </div>
            </div>

            <div class="help-content">

            <div class="help-content">
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i>
                    <strong>Nmap Scan Guide!</strong> This guide provides comprehensive instructions for creating Nmap scans that are compatible with the Device Assessment and Vulnerability Exposure ().
                </div>

                <h2 id="overview">Overview</h2>
                <p>This guide provides comprehensive instructions for creating Nmap scans that are compatible with the Device Assessment and Vulnerability Exposure (). The scans will be used for asset discovery, vulnerability assessment, and medical device management.</p>

                <h2 id="quick-reference-commands">Quick Reference Commands</h2>
                
                <h3>Basic Network Discovery</h3>
                <pre><code># Discover active hosts on network
nmap -sn -oX network_discovery.xml 192.168.1.0/24

# Discover hosts with hostname resolution
nmap -sn -R -oX network_discovery.xml 192.168.1.0/24</code></pre>

                <h3>Standard Asset Scan</h3>
                <pre><code># Basic asset scan with service detection
nmap -sS -sV -O -A -T4 -p 1-1000 -oX standard_scan.xml &lt;target_range&gt;

# Extended port range scan
nmap -sS -sV -O -A -T4 -p 1-10000 -oX extended_scan.xml &lt;target_range&gt;</code></pre>

                <h3>Comprehensive Security Scan</h3>
                <pre><code># Full security assessment
nmap -sS -sV -O -A -T4 --script vuln,default,auth,discovery -p- --max-retries 3 --max-rtt-timeout 1000ms --script-timeout 300s -oX security_scan.xml &lt;target_range&gt;</code></pre>

                <h3>Medical Device Focused Scan</h3>
                <pre><code># Medical device specific scan
nmap -sS -sV -O -A -T4 --script vuln,default,auth,discovery,medical-device-info -p 1-10000 --max-retries 3 --max-rtt-timeout 1000ms --script-timeout 300s -oX medical_devices.xml &lt;target_range&gt;</code></pre>

                <h2 id="scan-types-and-use-cases">Scan Types and Use Cases</h2>
                
                <h3>1. Network Discovery Scans</h3>
                
                <h4>Purpose</h4>
                <p>Identify active hosts on the network</p>
                
                <h4>Use Case</h4>
                <p>Initial network assessment, asset inventory</p>
                
                <h4>Command</h4>
                <pre><code>nmap -sn -oX network_discovery.xml &lt;target_range&gt;</code></pre>
                
                <h4>Options</h4>
                <ul>
                    <li><code>-sn</code>: Ping scan (no port scan)</li>
                    <li><code>-R</code>: Reverse DNS resolution</li>
                    <li><code>-oX</code>: Output to XML format</li>
                </ul>

                <h3>2. Asset Discovery Scans</h3>
                
                <h4>Purpose</h4>
                <p>Comprehensive asset identification with service detection</p>
                
                <h4>Use Case</h4>
                <p>Asset inventory, service enumeration</p>
                
                <h4>Command</h4>
                <pre><code>nmap -sS -sV -O -A -T4 -p 1-1000 -oX asset_scan.xml &lt;target_range&gt;</code></pre>
                
                <h4>Options</h4>
                <ul>
                    <li><code>-sS</code>: SYN scan (stealth scan)</li>
                    <li><code>-sV</code>: Service version detection</li>
                    <li><code>-O</code>: OS detection</li>
                    <li><code>-A</code>: Aggressive scan (OS detection, version detection, script scanning, and traceroute)</li>
                    <li><code>-T4</code>: Timing template (aggressive)</li>
                </ul>

                <h3>3. Vulnerability Assessment Scans</h3>
                
                <h4>Purpose</h4>
                <p>Identify security vulnerabilities and misconfigurations</p>
                
                <h4>Use Case</h4>
                <p>Security assessment, compliance checking</p>
                
                <h4>Command</h4>
                <pre><code>nmap -sS -sV -O -A -T4 --script vuln,default,auth,discovery -p- --max-retries 3 --max-rtt-timeout 1000ms --script-timeout 300s -oX vulnerability_scan.xml &lt;target_range&gt;</code></pre>
                
                <h4>Options</h4>
                <ul>
                    <li><code>--script vuln</code>: Vulnerability detection scripts</li>
                    <li><code>--script default</code>: Default NSE scripts</li>
                    <li><code>--script auth</code>: Authentication scripts</li>
                    <li><code>--script discovery</code>: Discovery scripts</li>
                    <li><code>-p-</code>: Scan all ports (1-65535)</li>
                </ul>

                <h2 id="medical-device-specific-scans">Medical Device Specific Scans</h2>
                
                <h3>Medical Device Discovery</h3>
                <pre><code># Medical device focused scan
nmap -sS -sV -O -A -T4 --script vuln,default,auth,discovery,medical-device-info -p 1-10000 --max-retries 3 --max-rtt-timeout 1000ms --script-timeout 300s -oX medical_devices.xml &lt;target_range&gt;</code></pre>

                <h3>DICOM Service Detection</h3>
                <pre><code># DICOM service scan
nmap -sS -sV -p 104,2762,11112 -oX dicom_scan.xml &lt;target_range&gt;</code></pre>

                <h3>HL7 Service Detection</h3>
                <pre><code># HL7 service scan
nmap -sS -sV -p 2575,8080,8443 -oX hl7_scan.xml &lt;target_range&gt;</code></pre>

                <h2 id="output-formats-for-dave">Output Formats for </h2>
                
                <h3>XML Format (Recommended)</h3>
                <p> primarily supports XML format for scan results:</p>
                <ul>
                    <li><strong>Standard Nmap XML</strong>: <code>-oX filename.xml</code></li>
                    <li><strong>Structured Data</strong>: Easy parsing and processing</li>
                    <li><strong>Complete Information</strong>: All scan details included</li>
                </ul>

                <h3>Alternative Formats</h3>
                <ul>
                    <li><strong>CSV Format</strong>: <code>-oX filename.csv</code> (limited information)</li>
                    <li><strong>JSON Format</strong>: <code>-oX filename.json</code> (requires conversion)</li>
                </ul>

                <h2 id="recommended-scan-configurations">Recommended Scan Configurations</h2>
                
                <h3>Quick Network Assessment</h3>
                <pre><code>nmap -sn -R -oX quick_network.xml 192.168.1.0/24</code></pre>

                <h3>Standard Asset Inventory</h3>
                <pre><code>nmap -sS -sV -O -A -T4 -p 1-1000 -oX asset_inventory.xml 192.168.1.0/24</code></pre>

                <h3>Comprehensive Security Assessment</h3>
                <pre><code>nmap -sS -sV -O -A -T4 --script vuln,default,auth,discovery -p- --max-retries 3 --max-rtt-timeout 1000ms --script-timeout 300s -oX security_assessment.xml 192.168.1.0/24</code></pre>

                <h3>Medical Device Assessment</h3>
                <pre><code>nmap -sS -sV -O -A -T4 --script vuln,default,auth,discovery,medical-device-info -p 1-10000 --max-retries 3 --max-rtt-timeout 1000ms --script-timeout 300s -oX medical_assessment.xml 192.168.1.0/24</code></pre>

                <h2 id="advanced-options">Advanced Options</h2>
                
                <h3>Timing and Performance</h3>
                <ul>
                    <li><code>-T0</code>: Paranoid (very slow)</li>
                    <li><code>-T1</code>: Sneaky (slow)</li>
                    <li><code>-T2</code>: Polite (slower)</li>
                    <li><code>-T3</code>: Normal (default)</li>
                    <li><code>-T4</code>: Aggressive (faster)</li>
                    <li><code>-T5</code>: Insane (very fast)</li>
                </ul>

                <h3>Port Scanning Options</h3>
                <ul>
                    <li><code>-p 1-1000</code>: Scan ports 1-1000</li>
                    <li><code>-p 1-10000</code>: Scan ports 1-10000</li>
                    <li><code>-p-</code>: Scan all ports (1-65535)</li>
                    <li><code>-p 80,443,8080</code>: Scan specific ports</li>
                </ul>

                <h3>Script Options</h3>
                <ul>
                    <li><code>--script vuln</code>: Vulnerability detection</li>
                    <li><code>--script default</code>: Default NSE scripts</li>
                    <li><code>--script auth</code>: Authentication scripts</li>
                    <li><code>--script discovery</code>: Discovery scripts</li>
                    <li><code>--script medical-device-info</code>: Medical device information</li>
                </ul>

                <h2 id="sample-scan-commands">Sample Scan Commands</h2>
                
                <h3>Basic Network Discovery</h3>
                <pre><code># Discover all hosts on network
nmap -sn -R -oX network_discovery.xml 192.168.1.0/24

# Discover hosts with specific IP range
nmap -sn -R -oX network_discovery.xml 10.0.0.0/8</code></pre>

                <h3>Asset Inventory Scan</h3>
                <pre><code># Standard asset scan
nmap -sS -sV -O -A -T4 -p 1-1000 -oX asset_scan.xml 192.168.1.0/24

# Extended asset scan
nmap -sS -sV -O -A -T4 -p 1-10000 -oX extended_asset_scan.xml 192.168.1.0/24</code></pre>

                <h3>Security Assessment Scan</h3>
                <pre><code># Comprehensive security scan
nmap -sS -sV -O -A -T4 --script vuln,default,auth,discovery -p- --max-retries 3 --max-rtt-timeout 1000ms --script-timeout 300s -oX security_scan.xml 192.168.1.0/24</code></pre>

                <h3>Medical Device Scan</h3>
                <pre><code># Medical device focused scan
nmap -sS -sV -O -A -T4 --script vuln,default,auth,discovery,medical-device-info -p 1-10000 --max-retries 3 --max-rtt-timeout 1000ms --script-timeout 300s -oX medical_devices.xml 192.168.1.0/24</code></pre>

                <h2 id="best-practices-for-dave">Best Practices for </h2>
                
                <h3>Scan Planning</h3>
                <ul>
                    <li><strong>Network Segmentation</strong>: Scan different network segments separately</li>
                    <li><strong>Timing</strong>: Schedule scans during maintenance windows</li>
                    <li><strong>Documentation</strong>: Document scan parameters and results</li>
                    <li><strong>Validation</strong>: Verify scan results before importing</li>
                </ul>

                <h3>Data Quality</h3>
                <ul>
                    <li><strong>Complete Information</strong>: Ensure all required fields are populated</li>
                    <li><strong>Accurate Timestamps</strong>: Use consistent time zones</li>
                    <li><strong>Valid IP Addresses</strong>: Verify IP address ranges</li>
                    <li><strong>Service Detection</strong>: Enable service version detection</li>
                </ul>

                <h3>Security Considerations</h3>
                <ul>
                    <li><strong>Authorization</strong>: Ensure you have permission to scan</li>
                    <li><strong>Network Impact</strong>: Use appropriate timing templates</li>
                    <li><strong>Data Protection</strong>: Secure scan results and data</li>
                    <li><strong>Compliance</strong>: Follow organizational security policies</li>
                </ul>

                <h2 id="troubleshooting">Troubleshooting</h2>
                
                <h3>Common Issues</h3>
                
                <h4>Scan Timeout</h4>
                <ul>
                    <li>Increase timeout values: <code>--max-rtt-timeout 2000ms</code></li>
                    <li>Reduce port range: <code>-p 1-1000</code></li>
                    <li>Use faster timing: <code>-T4</code></li>
                </ul>

                <h4>No Results</h4>
                <ul>
                    <li>Check network connectivity</li>
                    <li>Verify target IP ranges</li>
                    <li>Check firewall settings</li>
                    <li>Use different scan types</li>
                </ul>

                <h4>Import Errors</h4>
                <ul>
                    <li>Verify XML format is valid</li>
                    <li>Check file permissions</li>
                    <li>Ensure file is not corrupted</li>
                    <li>Review  import logs</li>
                </ul>

                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <strong>Scan Help Complete!</strong> This guide provides comprehensive instructions for creating Nmap scans compatible with . For additional support, refer to the user guide or contact technical support.
                </div>

                <div class="help-navigation">
                    <a href="/pages/help/user-guide.php" class="btn btn-secondary">
                        <i class="fas fa-user"></i>
                        User Guide
                    </a>
                    <a href="/pages/help/administrator-guide.php" class="btn btn-primary">
                        <i class="fas fa-cog"></i>
                        Administrator Guide
                    </a>
                </div>
            </div>
                </div>
        </div>
    </main>

    <script>
        // Scan Help JavaScript
        document.addEventListener('DOMContentLoaded', function() {
            // Smooth scrolling for anchor links
            document.querySelectorAll('a[href^="#"]').forEach(function(link) {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {
                        target.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                });
            });

            // Add loading states to buttons
            document.querySelectorAll('.btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    this.classList.add('loading');
                });
            });
        });
    </script>
</body>
</html>
